//! Provides utilities for neutering Arxan.
//!
//! <div class="warning">
//! Many DLL injectors or mod launchers do not suspend the process upon creation or otherwise
//! provide a method to execute your code before the game's entry point is invoked. If they
//! are used with this module, the game will likely crash.
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

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use call_hook::CallHook;
use closure_ffi::BareFnOnce;
use pelite::pe64::{Pe, PeObject, PeView};
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

use crate::analysis::is_arxan_hooked_entry_point;
use crate::disabler::result::{DearxanResult, Status};
use crate::disabler::slist::SList;
use crate::disabler::steamstub::schedule_after_steamstub;
use crate::patch::ArxanPatch;

mod call_hook;
mod code_buffer;
pub mod ffi;
mod game;
#[macro_use]
mod lazy_global;
pub mod result;
mod slist;
mod steamstub;

use code_buffer::CodeBuffer;
use game::game;

/// Single function to neuter all of Arxan's checks.
///
/// The callback will be invoked with the true entry point of the program once patching
/// is complete, and a bool indicating whether Arxan was detected. It can be used to initialize
/// hooks/etc.
///
/// Handles SteamStub 3.1 possibly being applied on top of Arxan.
///
/// # Safety
///
/// This function must be called before the game's entry point runs. It is generally safe to call
/// from within DllMain.
pub unsafe fn neuter_arxan<F>(callback: F)
where
    F: FnOnce(DearxanResult) + Send + 'static,
{
    // Functions are carefully wrapped in `std::panic::catch_unwind` to entry point panics!
    lazy_global! {
        static DEARXAN_NEUTER_ARXAN_RESULT: ffi::DearxanResult = unsafe {
            let maybe_panicked = std::panic::catch_unwind(|| match neuter_arxan_inner() {
                Ok(status) => Ok(status),
                Err(err) => result::from_error(err),
            });

            ffi::DearxanResult::from(match maybe_panicked {
                Ok(result) => result,
                Err(payload) => result::from_panic_payload(payload),
            })
        };
    }

    unsafe fn neuter_arxan_inner() -> Result<Status, Box<dyn std::error::Error + Send + Sync>> {
        static CALLED: AtomicBool = AtomicBool::new(false);
        if CALLED.swap(true, Ordering::Relaxed) {
            panic!("neuter_arxan_inner must not be called more than once");
        }

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
            "all patches applied in {:3?}. Arxan is now neutered",
            patch_apply_time.elapsed()
        );
        log::debug!("invoking user callback");

        Ok(Status {
            is_arxan_detected: true,
            is_executing_entrypoint: true,
        })
    }

    unsafe {
        schedule_after_arxan(|is_present, is_executing_entrypoint| {
            let result = if is_present {
                match std::panic::catch_unwind(|| {
                    ffi::DearxanResult::from_global(&DEARXAN_NEUTER_ARXAN_RESULT)
                }) {
                    Ok(result) => result.into(),
                    Err(payload) => result::from_panic_payload(payload),
                }
            }
            else {
                Ok(Status {
                    is_arxan_detected: false,
                    is_executing_entrypoint,
                })
            };

            callback(result);
        });
    }
}

/// Schedule a callback to run after the Arxan entry point stub.
/// It runs immediately if Arxan was not detected.
///
/// The callback receives the following:
/// - a boolean indicating whether Arxan was detected
/// - a boolean indicating whether execution is blocking the entry point.
///
/// Handles SteamStub 3.1 possibly being applied on top of Arxan.
///
/// # Safety
///
/// This function must be called before the game's entry point runs. It is generally safe to call
/// from within DllMain.
pub unsafe fn schedule_after_arxan<F>(callback: F)
where
    F: FnOnce(bool, bool) + Send + 'static,
{
    lazy_global! {
        static DEARXAN_SCHEDULED_AFTER_ARXAN: SList<unsafe extern "C" fn(bool, bool)> = {
            unsafe {
                schedule_after_arxan_inner();
            };
            SList::new()
        };
    }

    unsafe fn schedule_after_arxan_inner() {
        static CALLED: AtomicBool = AtomicBool::new(false);
        if CALLED.swap(true, Ordering::Relaxed) {
            panic!("schedule_after_arxan_inner must not be called more than once");
        }

        unsafe {
            schedule_after_steamstub(move |maybe_arxan_entry, _| {
                if is_arxan_hooked_entry_point(game().pe, maybe_arxan_entry as u64).is_none() {
                    log::info!(
                        "Arxan entry point hook not detected. Assuming Arxan was not applied to this binary"
                    );

                    // Prevent potential initialization deadlock.
                    std::thread::spawn(|| {
                        let callbacks = (*DEARXAN_SCHEDULED_AFTER_ARXAN.0).flush();
                        for callback in callbacks {
                            callback(false, false);
                        }
                    });

                    return;
                };

                // Arxan entry stubs begin first SUB rsp, 28 (4 bytes)
                let entry_stub_hook = &*Box::leak(Box::new(
                    CallHook::<unsafe extern "C" fn()>::new(maybe_arxan_entry.add(4) as *mut u8),
                ));

                let detour = BareFnOnce::new_c_in(
                    move || {
                        log::debug!("removing Arxan entry point hook");
                        entry_stub_hook.unhook();
                        // TODO: Fully reverse the entry point so this is not necessary
                        log::debug!("running Arxan entry point stub");
                        entry_stub_hook.original()();
                        log::debug!("running callback functions");

                        let callbacks = (*DEARXAN_SCHEDULED_AFTER_ARXAN.0).flush();
                        for callback in callbacks {
                            callback(true, true);
                        }
                    },
                    &game().hook_buffer,
                );

                log::debug!("detouring Arxan entry point stub");
                entry_stub_hook.hook_with(detour.leak());
            });
        }
    }

    unsafe {
        let callbacks = &*DEARXAN_SCHEDULED_AFTER_ARXAN.0;
        let bare_callback = BareFnOnce::new_c(callback);
        callbacks.push(bare_callback.leak());
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
