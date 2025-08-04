//! Provides utilities for disabling Arxan in various FromSoftware games.
//!
//! Disablers implement the [`ArxanDisabler`] trait and are prefixed by the game acronym
//! (e.g. [`DSRArxanDisabler`]). Integration with a DLL mod is very simple and only requires
//! an [`ArxanDisabler::disable`] call to be made **before** the game's entry point is called.
//!
//! <div class="warning">
//! Many DLL injectors or mod launchers do not suspend the process upon creation or otherwise
//! provide a method to execute your code before the game's entry point is invoked. If they
//! are used with this module, the game will likely crash.
//! </div>
//!
//! Example usage for Dark Souls Remastered:
//! ```no_run
//! use arxan_disabler::disabler::{ArxanDisabler, DSRArxanDisabler};
//!
//! unsafe fn my_entry_point() {
//!     DSRArxanDisabler::disable(|| {
//!         println!("Arxan disabled!");
//!         // This is a good place to do your hooks.
//!         // Once this callback returns, the game's true entry point
//!         // will be invoked.
//!     });
//! }
//! ```
//!
//! # Debugging
//! If the `disabler-debug` feature is enabled, patched Arxan stubs will log their first
//! execution with the [`log::Level::Trace`] severity.

use std::sync::atomic::{AtomicBool, Ordering};

use call_hook::CallHook;
use closure_ffi::BareFnOnce;
use common::{find_and_patch_stubs, game_code_buffer, game_module, make_module_rwe};
use steamstub::schedule_after_steamstub;

use super::patcher::StubPatchInfo;

mod call_hook;
mod code_buffer;
mod common;
mod steamstub;

pub mod game_specific;
pub use game_specific::*;

/// Implementation of an Arxan disabler for a particular game.
pub trait ArxanDisabler: Default + Send + 'static {
    /// Internal to the disabler implementation.
    ///
    /// Filters patches before they are applied by the default
    /// [`ArxanDisabler::patch_stubs`] implementation.
    ///
    /// The default simply performs all patches.
    #[allow(unused_variables)]
    fn filter_patch(&mut self, hook_address: u64, patch: Option<&StubPatchInfo>) -> bool {
        true
    }

    /// Finds and applies code patches to Arxan stubs.
    ///
    /// Called by the default implementation of [`ArxanDisabler::init_stub_hook`].
    ///
    /// While you can could call this directly at any time after game initialization, it may
    /// lead to data races and crashes. Consider calling [`ArxanDisabler::disable`] before the
    /// entry point runs instead.
    unsafe fn patch_stubs(&mut self) {
        log::debug!("Finding and patching Arxan stubs");
        unsafe {
            find_and_patch_stubs(game_module(), game_code_buffer(), |h, p| {
                self.filter_patch(h, p)
            })
        };
    }

    /// Internal to the disabler implementation.
    ///
    /// Function to hook the Arxan initialization stub with. Takes care of performing all required patches.
    ///
    /// By default, will first run the original initialization stub run to decrypt information.
    /// Then, [`ArxanDisabler::patch_stubs`] will be run to patch Arxan stubs, before running the user-provided
    /// callback that was passed to [`ArxanDisabler::disable`].
    unsafe fn init_stub_hook(
        &mut self,
        original_stub: unsafe extern "C" fn(),
        user_callback: Box<dyn FnOnce() + Send>,
    ) {
        log::debug!("Running Arxan initialization stub");
        unsafe { original_stub() };

        unsafe { self.patch_stubs() };

        log::debug!("Arxan disabled, running user callback");
        user_callback()
    }

    /// Do-it-all function to disable Arxan.
    /// The callback will be triggered once patching is complete, and can be
    /// used to initialize hooks/etc.
    ///
    /// This must be called **exactly once** before the game's entry point runs.
    /// It is generally safe to call from within DllMain.
    ///
    /// The default implementation handles the game module not being RWE yet, and
    /// SteamStub 3.1 possibly being applied on top of Arxan.
    unsafe fn disable<F>(callback: F)
    where
        F: FnOnce() + Send + 'static,
    {
        static CALLED: AtomicBool = AtomicBool::new(false);
        assert!(
            !CALLED.swap(true, Ordering::Relaxed),
            "ArxanDisabler::disable already called once"
        );

        let pe = game_module();

        log::debug!("Making game image RWE");
        unsafe {
            make_module_rwe(pe);
        }

        let user_callback = Box::new(callback);
        let mut instance = Self::default();
        unsafe {
            schedule_after_steamstub(move |arxan_entry| {
                // Arxan entry stubs begin first SUB rsp, 28 (4 bytes)
                let arxan_stub_hook =
                    &*Box::leak(Box::new(CallHook::new((arxan_entry + 4) as *mut u8)));

                let detour = BareFnOnce::new_c_in(
                    move || {
                        log::info!("Removing Arxan stub hook");
                        arxan_stub_hook.unhook();
                        instance.init_stub_hook(arxan_stub_hook.original(), user_callback);
                    },
                    game_code_buffer(),
                );

                log::debug!("Detouring Arxan init stub");
                arxan_stub_hook.hook_with(detour.leak());
            });
        }
    }
}

macro_rules! ffi_impl {
    ($disabler:ty, $ffi_disable:ident) => {
        #[cfg(feature = "ffi")]
        #[no_mangle]
        unsafe extern "C" fn $ffi_disable(
            callback: unsafe extern "C" fn(*mut ::std::ffi::c_void),
            context: *mut ::std::ffi::c_void,
        ) {
            let ptr_addr = context.addr();
            unsafe {
                <$disabler as $crate::disabler::ArxanDisabler>::disable(move || {
                    callback(ptr_addr as *mut ::std::ffi::c_void)
                })
            }
        }
    };
}
pub(crate) use ffi_impl;
