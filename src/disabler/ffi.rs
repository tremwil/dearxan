#[cfg(feature = "ffi")]
use std::ffi::c_void;
use std::{
    ffi::{c_char, c_int},
    mem, ptr,
};

use crate::disabler::{
    lazy_global::LazyGlobal,
    result::{DearxanResult as Result, Error, Status},
};

/// DearxanResult as seen across FFI boundaries.
///
/// Take utmost care when modifying its layout to maintain ABI compatibility:
/// 1. No fields may be removed.
/// 2. No fields may be reordered.
/// 3. New fields must be added before `_last_for_offsetof`.
///
/// Likewise, don't forget to update the C layout in `include/dearxan.h`.
#[repr(C)]
#[derive(Clone)]
pub struct DearxanResult {
    result_size: usize,
    status: c_int,
    error_msg: *const c_char,
    error_msg_size: usize,
    is_arxan_detected: bool,
    is_executing_entrypoint: bool,
    _last_for_offsetof: c_char,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DearxanStatus {
    Success = 1,
    Error,
    Panic,
}

/// Callback invoked once arxan has been disabled (or if it wasn't detected).
#[cfg(feature = "ffi")]
pub type DearxanUserCallback = extern "C" fn(result: *const DearxanResult, context: *mut c_void);

/// Single function to neuter all of Arxan's checks.
///
/// The callback will be invoked with the true entry point of the program once patching
/// is complete, and a bool indicating whether Arxan was detected. It can be used to initialize
/// hooks/etc.
///
/// Handles SteamStub 3.1 possibly being applied on top of Arxan.
///
/// # Safety
/// This function must be called before the game's entry point runs. It is generally safe to call
/// from within DllMain.
#[cfg(feature = "ffi")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dearxan_neuter_arxan(
    callback: Option<DearxanUserCallback>,
    context: *mut c_void,
) {
    let context_send = context.addr();
    // SAFETY: Send'ness of context is asserted by caller
    unsafe {
        super::neuter_arxan(move |result| {
            if let Some(callback) = callback {
                callback(&DearxanResult::from(result), context_send as *mut c_void);
            }
        })
    };
}

impl DearxanResult {
    const UNPADDED_SIZE: usize = mem::offset_of!(Self, _last_for_offsetof);

    fn new_without_status() -> Self {
        Self {
            result_size: Self::UNPADDED_SIZE,
            status: 0,
            is_arxan_detected: false,
            is_executing_entrypoint: false,
            error_msg: c"".as_ptr(),
            error_msg_size: 0,
            _last_for_offsetof: 0,
        }
    }

    pub(crate) fn new(status: DearxanStatus) -> Self {
        Self {
            status: status.into(),
            ..Self::new_without_status()
        }
    }

    #[track_caller]
    pub(crate) unsafe fn from_global(global: &LazyGlobal<Self>) -> Self {
        let (ptr, global_size) = **global;
        if ptr.is_null() || !ptr.is_aligned() || global_size < mem::size_of::<usize>() {
            panic!("lazy_global variable was incorrectly initialized");
        }

        let result_size = unsafe { ptr::read(&raw const (*ptr).result_size) };
        if global_size < result_size {
            panic!("lazy_global variable self-reported size mismatch");
        }

        let mut result = Self::new_without_status();

        unsafe {
            let result_size = Self::UNPADDED_SIZE.min(result_size);
            ptr::copy_nonoverlapping(ptr as *const u8, &raw mut result as *mut u8, result_size);
            result.result_size = result_size;
        }

        result
    }
}

unsafe impl Send for DearxanResult {}

unsafe impl Sync for DearxanResult {}

impl From<Result> for DearxanResult {
    fn from(result: Result) -> Self {
        match result {
            Ok(status) => Self {
                is_arxan_detected: status.is_arxan_detected,
                is_executing_entrypoint: status.is_executing_entrypoint,
                ..Self::new(DearxanStatus::Success)
            },
            Err(Error::Error(err)) => {
                let msg = {
                    let mut msg = err.to_string();
                    msg.push('\0');
                    msg.leak()
                };

                Self {
                    error_msg: msg.as_ptr() as *const c_char,
                    error_msg_size: msg.len() - 1,
                    ..Self::new(DearxanStatus::Error)
                }
            }
            Err(Error::Panic(mut msg)) => {
                let msg = {
                    msg.push('\0');
                    msg.leak()
                };

                Self {
                    error_msg: msg.as_ptr() as *const c_char,
                    error_msg_size: msg.len() - 1,
                    ..Self::new(DearxanStatus::Panic)
                }
            }
        }
    }
}

impl From<DearxanResult> for Result {
    fn from(result: DearxanResult) -> Self {
        if result.status == DearxanStatus::Success {
            Ok(Status {
                is_arxan_detected: result.is_arxan_detected,
                is_executing_entrypoint: result.is_executing_entrypoint,
            })
        }
        else if result.status == DearxanStatus::Error || result.status == DearxanStatus::Panic {
            let bytes = unsafe {
                std::slice::from_raw_parts(result.error_msg as *const u8, result.error_msg_size)
            };

            Err(match str::from_utf8(bytes) {
                Ok(str) => {
                    if result.status == DearxanStatus::Error {
                        Error::Error(str.into())
                    }
                    else {
                        Error::Panic(str.to_owned())
                    }
                }
                Err(err) => Error::Error(Box::new(err)),
            })
        }
        else {
            Err(Error::Error("result was uninitialized or invalid".into()))
        }
    }
}

impl From<DearxanStatus> for c_int {
    fn from(value: DearxanStatus) -> Self {
        value as c_int
    }
}

impl PartialEq<DearxanStatus> for c_int {
    fn eq(&self, other: &DearxanStatus) -> bool {
        *self == *other as c_int
    }
}

impl PartialEq<c_int> for DearxanStatus {
    fn eq(&self, other: &c_int) -> bool {
        *self as c_int == *other
    }
}
