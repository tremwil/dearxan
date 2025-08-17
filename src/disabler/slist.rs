use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::UnsafeCell,
    marker::PhantomData,
    ptr,
};

use windows_sys::Win32::System::{
    Kernel::{SLIST_ENTRY, SLIST_HEADER},
    Threading::{InitializeSListHead, InterlockedFlushSList, InterlockedPushEntrySList},
};

/// Lightweight FFI friendly atomic singly linked list.
///
/// Used together with [`lazy_global`] to guarantee a particular collection layout,
/// whereas using [`Vec`] would not be (say, between Rust versions).
#[repr(C, align(16))]
pub struct SList<T> {
    inner: UnsafeCell<SLIST_HEADER>,
    _marker: PhantomData<T>,
}

#[repr(C, align(16))]
struct SListEntry<T> {
    inner: SLIST_ENTRY,
    value: T,
}

impl<T> SList<T> {
    /// Creates a new list without allocating.
    pub fn new() -> Self {
        let new = Self {
            inner: Default::default(),
            _marker: PhantomData,
        };

        unsafe {
            InitializeSListHead(new.inner.get());
        }

        new
    }

    /// Prepends a new entry with value `value` to the front of the list atomically.
    pub fn push(&self, value: T) {
        unsafe {
            let layout = Layout::new::<SListEntry<T>>();
            let entry = System.alloc(layout) as *mut SListEntry<T>;

            if entry.is_null() {
                std::alloc::handle_alloc_error(layout)
            }

            ptr::write(&raw mut (*entry).value, value);

            InterlockedPushEntrySList(self.inner.get(), &raw mut (*entry).inner);
        }
    }

    /// Atomically takes the contents of the linked list and returns them as a [`Vec`].
    ///
    /// The elements are ordered in FIFO order.
    pub fn flush(&self) -> Vec<T> {
        let mut entries = vec![];

        unsafe {
            let mut next_entry = InterlockedFlushSList(self.inner.get());

            while !next_entry.is_null() {
                let entry = ptr::read(next_entry as *mut SListEntry<T>);
                entries.push(entry.value);

                System.dealloc(next_entry as _, Layout::new::<SListEntry<T>>());

                next_entry = entry.inner.Next;
            }
        }

        // From LIFO to FIFO order:
        entries.reverse();
        entries
    }
}

impl<T> Drop for SList<T> {
    fn drop(&mut self) {
        let _flushed = self.flush();
    }
}

unsafe impl<T: Send> Send for SList<T> {}

unsafe impl<T: Sync> Sync for SList<T> {}
