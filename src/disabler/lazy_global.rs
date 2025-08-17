use std::{
    alloc::{GlobalAlloc, Layout, System},
    mem,
    ops::Deref,
    ptr,
    sync::LazyLock,
};

use windows_sys::Win32::{
    Foundation::GetLastError,
    System::{
        Memory::{CreateFileMappingW, FILE_MAP_ALL_ACCESS, MapViewOfFile, PAGE_READWRITE},
        Threading::{AcquireSRWLockExclusive, ReleaseSRWLockExclusive, SRWLOCK},
    },
};

/// [`LazyLock`] wrapper for process-wide global variables created with [`lazy_global`].
pub struct LazyGlobal<T>(LazyLock<(*const T, usize)>);

/// Defines a process-wide global variable that manages a named file mapping. It is
/// guaranteed to only be assigned once.
///
/// The name of the file mapping is the name of the static variable. In that way,
/// it is globally defined for the entire process. Only ASCII alphanumerics and the
/// underscore are allowed to be used in the name of the identifier.
///
/// # Safety
///
/// Obtaining a pointer to the shared memory is safe, but using it is extremely unsafe.
/// Different modules may have different ideas about the layout of `T`. It is *highly*
/// recommended to use `repr(C)` and types with a stable ABI, as well as verify
/// the size returned by derefencing.
///
/// # Panics
///
/// Dereferencing will panic if the initializer panics, if the identifier contains
/// disallowed characters or if one of the OS routines fails.
macro_rules! lazy_global {
    ($(#[$attr:meta])* $vis:vis static $name:ident: $t:ty = $init:expr;) => {
        $(#[$attr])* $vis static $name: $crate::disabler::lazy_global::LazyGlobal<$t> =
            $crate::disabler::lazy_global::LazyGlobal::<$t>::new(|| {
                $crate::disabler::lazy_global::get_ptr::<$t, _>(stringify!($name), || $init)
            });
    }
}

impl<T> LazyGlobal<T> {
    #[doc(hidden)]
    pub const fn new(f: fn() -> (*const T, usize)) -> Self {
        Self(LazyLock::new(f))
    }
}

impl<T> Deref for LazyGlobal<T> {
    type Target = (*const T, usize);

    #[track_caller]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Process-wide named file mapping.
///
/// `repr(C)` for ABI compatibility. Likewise, instead of storing `T` directly,
/// it stores a pointer to `T` to not invoke immediate UB when the layout of `T`
/// is different between callers and to preserve its natural alignment.
#[repr(C)]
struct LazyGlobalMapping<T> {
    value: *const T,
    size: usize,
    init_lock: SRWLOCK,
    is_poisoned: bool,
}

/// Accesses a process-wide global variable that manages a named file mapping. It is
/// guaranteed to only be assigned once.
///
/// Only ASCII alphanumerics and the underscore are allowed to be used in the name of the
/// identifier.
///
/// # Safety
///
/// Obtaining a pointer to the shared memory is safe, but using it is extremely unsafe.
/// Different modules may have different ideas about the layout of `T`. It is *highly*
/// recommended to use `repr(C)` and types with a stable ABI, as well as verify
/// the size returned by derefencing.
///
/// # Panics
///
/// Will panic if the initializer panics, if the name contains disallowed characters
/// or if one of the OS routines fails.
#[track_caller]
pub fn get_ptr<T, F: FnOnce() -> T>(name: &str, init: F) -> (*const T, usize) {
    unsafe {
        // Filter invalid names and prepend the local (process-wide) namespace prefix.
        if name.chars().any(|c| !c.is_ascii_alphanumeric() && c != '_') {
            panic!("{name} is not a valid file mapping name");
        }

        // Note: backslashes are not permitted after the prefix, but they are already
        // filtered out above.
        let name = format!("Local\\{name}\0").encode_utf16().collect::<Vec<_>>();

        // Create or open the named file mapping backed by the paging file (no file handle).
        let mapping_handle = CreateFileMappingW(
            ptr::null_mut(),
            ptr::null(),
            PAGE_READWRITE,
            0,
            mem::size_of::<LazyGlobalMapping<T>>() as u32,
            name.as_ptr(),
        );

        if mapping_handle.is_null() {
            let last_error = GetLastError();
            panic!("CreateFileMappingW failed with code {last_error:08x}");
        }

        // Map the file mapping memory. It is zero initialized, which is already a valid state for
        // all members of `LazyGlobalMapping` (for `SRWLOCK` see `SRWLOCK_INIT`).
        //
        // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile
        //
        // "The initial contents of the pages in a file mapping object backed by the paging file
        // are 0 (zero)."
        let mapping = MapViewOfFile(
            mapping_handle,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            mem::size_of::<LazyGlobalMapping<T>>(),
        )
        .Value as *mut LazyGlobalMapping<T>;

        if mapping.is_null() {
            let last_error = GetLastError();
            panic!("MapViewOfFile failed with code {last_error:08x}");
        };

        // Get an exclusive lock in case initialization is required.
        AcquireSRWLockExclusive(&raw mut (*mapping).init_lock);

        // RAII guard that releases the lock when it goes out of scope or poisons it in case of
        // a panic.
        struct LockGuard<T>(*mut LazyGlobalMapping<T>);

        impl<T> Drop for LockGuard<T> {
            fn drop(&mut self) {
                unsafe {
                    if std::thread::panicking() {
                        (*self.0).is_poisoned = true;
                    }

                    ReleaseSRWLockExclusive(&raw mut (*self.0).init_lock);
                }
            }
        }

        let _lock_guard = LockGuard(mapping);
        let mapping = &mut *mapping;

        // Check for poisoning (panic while initializing).
        if mapping.is_poisoned {
            panic!("variable initialization failed and the lock is poisoned");
        }

        // Read or initialize the mapping contents. The exclusive lock serializes accesses and
        // initialization.
        if mapping.value.is_null() {
            // *Actual* size of `T`, which may be a ZST.
            let size = mem::size_of::<T>();

            // Allocate at least one byte as per the contract of `GlobalAlloc`.
            let layout = Layout::from_size_align_unchecked(size.max(1), mem::align_of::<T>());
            let value = System.alloc(layout) as *mut T;

            if value.is_null() {
                std::alloc::handle_alloc_error(layout);
            };

            // Populate the value. `init` is only ever called once globally, since a panic poisons
            // the lock.
            value.write(init());

            mapping.value = value;
            mapping.size = size;
        }

        (mapping.value, mapping.size)
    }
}

unsafe impl<T: Send> Send for LazyGlobal<T> {}

unsafe impl<T: Sync> Sync for LazyGlobal<T> {}
