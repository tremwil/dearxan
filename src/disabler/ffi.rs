use std::ffi::c_void;

/// Callback invoked once arxan has been disabled (or if it wasn't detected).
pub type DearxanUserCallback =
    extern "C" fn(original_entry_point: *const u8, arxan_detected: bool, context: *mut c_void);

/// Single function to neuter all of Arxan's checks.
///
/// The callback will be invoked with the true entry point of the program once patching
/// is complete, and a bool indicating whether Arxan was detected. It can be used to initialize
/// hooks/etc.
///
/// Handles SteamStub 3.1 possibly being applied on top of Arxan.
///
/// # Panics
/// If called more than once.
///
/// # Safety
/// This function must be called before the game's entry point runs. It is generally safe to call
/// from within DllMain.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dearxan_neuter_arxan(callback: Option<DearxanUserCallback>, context: *mut c_void) {
    let context_send = context.addr();
    // SAFETY: Send'ness of context is asserted by caller
    unsafe {
        super::neuter_arxan(move |entry, has_arxan| {
            if let Some(callback) = callback {
                callback(entry, has_arxan, context_send as *mut c_void);
            }
        })
    };
}
