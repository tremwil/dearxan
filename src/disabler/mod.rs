//! Provides utilities for neutering Arxan.
//!
//! <div class="warning">
//!
//! Many DLL injectors or mod launchers do not suspend the process upon creation or otherwise
//! provide a method to execute your code before the game's entry point is invoked. The crate
//! supports these loaders on a best-effort basis, but it is **strongly** recommended to use
//! one that loads mods before the game's entry point runs.
//!
//! </div>
//!
//! Example usage:
//! ```no_run
//! use dearxan::disabler::neuter_arxan;
//!
//! unsafe fn my_entry_point() {
//!     unsafe {
//!         neuter_arxan(|result| {
//!             println!("Arxan disabled!");
//!             // This is a good place to do your hooks.
//!             // Once this callback returns, the game's true entry point
//!             // will be invoked.
//!         });
//!     }
//! }
//! ```
//!
//! # Debugging
//! If the `instrument_stubs` feature is enabled, patched Arxan stubs will log their first
//! execution with the [`log::Level::Trace`] severity.

use std::{
    io::Write,
    sync::{
        Once,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Instant,
};

use call_hook::CallHook;
use closure_ffi::BareFnOnce;
use pelite::pe64::{Pe, PeObject, PeView};
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

use crate::disabler::slist::SList;
use crate::disabler::steamstub::neuter_steamstub;
use crate::disabler::{
    entry_point::wait_for_gs_cookie,
    result::{DearxanResult, Status},
};
use crate::patch::ArxanPatch;
use crate::{
    analysis::entry_point::MsvcEntryPoint,
    disabler::entry_point::{is_created_suspended, process_main_thread},
};

mod call_hook;
mod code_buffer;
mod entry_point;
pub mod ffi;
mod game;
mod lazy_global;
pub mod result;
mod slist;
mod steamstub;
mod util;

use code_buffer::CodeBuffer;
use game::game;
use lazy_global::lazy_global;

/// Single function to neuter all of Arxan's checks.
///
/// The callback will be invoked with a [`DearxanResult`] which contains fields indicating whether
/// Arxan was detected and whether entry point execution is being blocked while the callback is
/// running. Modulo any reported error, it is safe to assume that Arxan has been disabled once it is
/// executed.
///
/// Handles SteamStub 3.1 possibly being applied on top of Arxan.
///
/// # Safety
///
/// This function applies code patches derived from imperfect binary analysis to the program.
/// Although extremely unlikely, it is theoretically possible for code to be falsely identified as
/// an Arxan stub and incorrectly patched, which will lead to all kinds of UB.
///
/// While best-effort synchronization with the entry point is performed when this function is
/// called after it has started executing, it is not perfect and may lead to race conditions.
/// For this reason it is **strongly** recommended to use a mod loader that creates the game process
/// as suspended.
pub unsafe fn neuter_arxan<F>(callback: F)
where
    F: FnOnce(DearxanResult) + Send + 'static,
{
    // Functions are carefully wrapped in `std::panic::catch_unwind` to avoid entry point panics!
    lazy_global! {
        static DEARXAN_NEUTER_ARXAN_RESULT: ffi::DearxanResult = unsafe {
            result::from_maybe_panic(|| neuter_arxan_inner()).into()
        };
    }

    // Backwards compatibility jank -- we should have made `lazy_global`
    // function more like a `LazyLock` whose constructor takes an argument
    static NEEDS_SUSPEND: AtomicBool = AtomicBool::new(false);

    unsafe fn neuter_arxan_inner() -> Result<Status, Box<dyn std::error::Error + Send + Sync>> {
        static CALLED: AtomicBool = AtomicBool::new(false);
        if CALLED.swap(true, Ordering::Relaxed) {
            panic!("neuter_arxan_inner must not be called more than once");
        }

        let _suspend_guard: Option<entry_point::SuspendGuard> = NEEDS_SUSPEND
            .load(Ordering::SeqCst)
            .then(|| unsafe { entry_point::SuspendGuard::suspend_all_threads() });

        let game = game();
        unsafe {
            make_module_rwe(game.pe);
        }

        let analysis_time = Instant::now();
        log::info!("analyzing Arxan stubs");

        let analysis_results = crate::analysis::analyze_all_stubs(game.pe);
        let num_found = analysis_results.len();
        log::info!(
            "analysis completed in {:.3?}. {} stubs found",
            analysis_time.elapsed(),
            num_found
        );

        let good_stubs: Vec<_> = analysis_results
            .into_iter()
            .filter_map(|maybe_stub| maybe_stub.inspect_err(|err| log::error!("{err}")).ok())
            .collect();

        if good_stubs.len() != num_found {
            return Err("failed to generate patches for all stubs".into());
        }

        log::info!("generating patches");
        let patch_gen_time = Instant::now();
        let patches = crate::patch::ArxanPatch::build_from_stubs(
            game.pe,
            Some(game.preferred_base),
            good_stubs.iter(),
        )?;

        log::info!(
            "generated {} patches in {:.3?}",
            patches.len(),
            patch_gen_time.elapsed()
        );

        log::info!("applying patches");
        let patch_apply_time = Instant::now();
        for patch in &patches {
            unsafe {
                apply_patch(patch, &game.hook_buffer);
            }
        }
        log::info!(
            "all patches applied in {:.3?}. Arxan is now neutered",
            patch_apply_time.elapsed()
        );

        Ok(Status {
            is_arxan_detected: true,
            is_executing_entrypoint: true,
        })
    }

    unsafe {
        schedule_after_arxan(move |is_present, is_executing_entrypoint: bool| {
            NEEDS_SUSPEND.store(!is_executing_entrypoint, Ordering::SeqCst);
            let result = if is_present {
                result::from_maybe_panic(|| {
                    ffi::DearxanResult::from_global(&DEARXAN_NEUTER_ARXAN_RESULT).into()
                })
            }
            else {
                Ok(Status {
                    is_arxan_detected: false,
                    is_executing_entrypoint,
                })
            };

            log::debug!("invoking user callback");
            callback(result.map(|s| Status {
                is_executing_entrypoint,
                ..s
            }));
        })
    };
}

/// Schedule a callback to run right after the Arxan entry point stub terminates, in lockstep with
/// the executable's main entry point.
///
/// If Arxan is not present, will try to run the callback after the executable's
/// `__security_init_cookie` has finished running, which is right before the main entry point.
/// This may fail if the executable was built with a non-MSVC CRT, in which case the callback
/// will be run immediately in a separate thread.
///
/// The callback receives the following:
/// - a boolean indicating whether Arxan was detected
/// - a boolean indicating whether execution is blocking the entry point.
///
/// Handles SteamStub 3.1 possibly being applied on top of Arxan.
///
/// # Safety
///
/// This function may apply code and memory patches to the program depending on various checks,
/// such as patching the SteamStub headers if it is present. Although it is extremely unlikely for a
/// patch to be incorrectly applied, this is a fundamentally unsafe operation and may lead to all
/// kinds of UB.
pub unsafe fn schedule_after_arxan<F>(callback: F)
where
    F: FnOnce(bool, bool) + Send + 'static,
{
    #[repr(C)]
    struct Ctx {
        callbacks: SList<unsafe extern "C" fn(bool, bool)>,
        wait_done: AtomicU32,
        is_present: AtomicBool,
    }

    lazy_global! {
        static DEARXAN_SCHEDULED_AFTER_ARXAN: Ctx = {
            unsafe { schedule_after_arxan_inner(); }
            Ctx {
                callbacks: SList::new(),
                wait_done: AtomicU32::new(0),
                is_present: AtomicBool::new(false)
            }
        };
    }
    static CALLBACK_PUSHED: Once = Once::new();

    fn first_callback_flush(is_present: bool, is_blocking: bool) {
        let ctx = unsafe { &*DEARXAN_SCHEDULED_AFTER_ARXAN.0 };

        ctx.is_present.store(false, Ordering::SeqCst);

        let callbacks = ctx.callbacks.flush();
        for callback in callbacks {
            unsafe { callback(is_present, is_blocking) };
        }

        ctx.wait_done.store(1, Ordering::SeqCst);
        atomic_wait::wake_all(&ctx.wait_done);
    }

    unsafe fn schedule_after_arxan_inner() {
        static CALLED: AtomicBool = AtomicBool::new(false);
        if CALLED.swap(true, Ordering::Relaxed) {
            panic!("schedule_after_arxan_inner must not be called more than once");
        }

        unsafe {
            neuter_steamstub(move |result| {
                let Some(msvc_ep) =
                    MsvcEntryPoint::try_from_va(game().pe, result.original_entry_point)
                else {
                    log::warn!(
                        "non-msvc entry point detected. Assuming Arxan was not applied to this binary"
                    );
                    log::warn!("callbacks will *not* be synchronized with the entry point");

                    std::thread::spawn(move || {
                        // Avoid potential race condition where callback is pushed after the flush
                        CALLBACK_PUSHED.wait();
                        first_callback_flush(false, false);
                    });
                    return;
                };

                log::info!("arxan detected: {}", msvc_ep.is_arxan_hooked);
                if !result.blocking_entry_point {
                    log::warn!("schedule_after_arxan run after the process entry point");
                    log::warn!("callbacks will race with game initialization");
                    std::thread::spawn(move || {
                        // This shouldn't panic, as we already know we have a MSVC entry point
                        wait_for_gs_cookie(None).unwrap();

                        log::debug!("arxan entry point finished, flushing callback functions");
                        // Note: No CALLBACK_PUSHED race condition here: `blocking_entry_point` is
                        // false, so the same check after pushing the callback will be true and
                        // another flush will be triggered
                        first_callback_flush(msvc_ep.is_arxan_hooked, false);
                    });
                    return;
                }

                // Call hook `__security_init_cookie`, which is where Arxan inserted its entry stubs
                let security_init_cookie_hook =
                    &*Box::leak(Box::new(CallHook::<unsafe extern "C" fn()>::new(
                        (result.original_entry_point + 4) as *mut u8,
                    )));

                let detour = BareFnOnce::new_c_in(
                    move || {
                        log::debug!("removing __security_init_cookie entry point hook");
                        security_init_cookie_hook.unhook();
                        // TODO: Fully reverse the entry point so this is not necessary
                        log::debug!(
                            "calling __security_init_cookie (will run Arxan initialization routines)"
                        );
                        security_init_cookie_hook.original()();
                        log::debug!("flushing callback functions");

                        first_callback_flush(msvc_ep.is_arxan_hooked, true);
                    },
                    &game().hook_buffer,
                );

                log::debug!("detouring entry point via __security_init_cookie call hook");
                security_init_cookie_hook.hook_with(detour.leak());
            })
        }
    }

    // Only use callbacks here, as older versions of DEARXAN_SCHEDULED_AFTER_ARXAN may not have the
    // is_present and wait_done fields
    let ctx = unsafe { &*DEARXAN_SCHEDULED_AFTER_ARXAN.0 };
    let bare_callback = BareFnOnce::new_c(callback);
    ctx.callbacks.push(bare_callback.leak());
    CALLBACK_PUSHED.call_once(|| {});

    if !process_main_thread().is_none_or(is_created_suspended) {
        if DEARXAN_SCHEDULED_AFTER_ARXAN.1 < size_of::<Ctx>() {
            log::error!(
                "module that initialized the schedule_after_arxan state does not support post-entry-point calls"
            );
            log::error!("the schedule_after_arxan callback might never be run!");
            return;
        }

        log::warn!("schedule_after_arxan run after the process entry point");
        log::warn!("callbacks will race with game initialization");

        std::thread::spawn(|| {
            while ctx.wait_done.load(Ordering::SeqCst) != 1 {
                atomic_wait::wait(&ctx.wait_done, 0);
            }
            log::debug!("flushing callback functions");

            let is_present = ctx.is_present.load(Ordering::SeqCst);
            let callbacks = ctx.callbacks.flush();
            for callback in callbacks {
                unsafe { callback(is_present, false) };
            }
        });
    }
}

unsafe fn apply_patch(patch: &ArxanPatch, code_buf: &CodeBuffer) {
    match patch {
        ArxanPatch::JmpHook { target, pic } => {
            #[cfg(feature = "instrument_stubs")]
            let instrumented: Vec<_> = stub_instrumentation::emit_log_call(*target)
                .unwrap()
                .into_iter()
                .chain(pic.iter().copied())
                .collect();
            #[cfg(feature = "instrument_stubs")]
            let pic = &instrumented;

            let hook = code_buf.write(pic).unwrap().addr() as i64;
            let jmp_immediate: i32 = hook.wrapping_sub(*target as i64 + 5).try_into().unwrap();

            let mut hook_site = unsafe { std::slice::from_raw_parts_mut(*target as *mut u8, 5) };
            hook_site.write_all(&[0xE9]).unwrap();
            hook_site.write_all(&jmp_immediate.to_le_bytes()).unwrap();

            log::trace!("patched arxan stub at {:016x}", *target);
        }
        ArxanPatch::Write { va, bytes } => {
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), *va as *mut u8, bytes.len());
            }
            log::trace!("wrote {} bytes to {va:x}", bytes.len())
        }
    }
}

#[cfg(feature = "instrument_stubs")]
mod stub_instrumentation {
    use std::option::Option::None;
    use std::sync::Mutex;

    use fxhash::FxHashSet;
    use iced_x86::{
        BlockEncoder, BlockEncoderOptions, Code, IcedError, Instruction, InstructionBlock,
        MemoryOperand, Register::*,
    };

    unsafe extern "C" fn log_arxan_stub(hook_addr: u64, rsp: u64) {
        static CALLED_STUBS: Mutex<Option<FxHashSet<u64>>> = Mutex::new(None);
        let mut maybe_map = CALLED_STUBS.lock().unwrap();
        if maybe_map.get_or_insert_default().insert(hook_addr) {
            log::debug!("Stub for {hook_addr:016x} called | RSP = {rsp:016x}");
        }
    }

    pub fn emit_log_call(hook_addr: u64) -> Result<Vec<u8>, IcedError> {
        #[allow(clippy::fn_to_numeric_cast)]
        let log_stub_instructions = [
            Instruction::with2(Code::Mov_r64_rm64, RDX, RSP)?,
            Instruction::with2(Code::And_rm64_imm8, RSP, -0x10i64)?,
            Instruction::with1(Code::Push_rm64, RDX)?,
            Instruction::with2(Code::Sub_rm64_imm8, RSP, 0x28)?,
            Instruction::with2(Code::Mov_r64_imm64, RCX, hook_addr)?,
            Instruction::with2(Code::Mov_r64_imm64, RAX, log_arxan_stub as u64)?,
            Instruction::with1(Code::Call_rm64, RAX)?,
            Instruction::with2(
                Code::Mov_r64_rm64,
                RSP,
                MemoryOperand::with_base_displ(RSP, 0x28),
            )?,
        ];
        let encoded = BlockEncoder::encode(
            64,
            InstructionBlock::new(&log_stub_instructions, 0),
            BlockEncoderOptions::NONE,
        )?;
        Ok(encoded.code_buffer)
    }
}

unsafe fn make_module_rwe(pe: PeView<'_>) {
    log::debug!("setting game executable page protection flags to RWX");

    let base = pe.image().as_ptr().addr();
    for section in pe.section_headers() {
        let rva_range = section.virtual_range();
        let len = (rva_range.end - rva_range.start) as usize;

        let mut protect = Default::default();
        if 0 == unsafe {
            VirtualProtect(
                (base + rva_range.start as usize) as *const _,
                len,
                PAGE_EXECUTE_READWRITE,
                &mut protect,
            )
        } {
            panic!(
                "VirtualProtect failed on address {:x} and length {len}",
                base + rva_range.start as usize
            );
        }
    }
}
