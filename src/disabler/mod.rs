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
//!         neuter_arxan(|original_entry_point, arxan_was_present| {
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
//! If the `disabler-debug` feature is enabled, patched Arxan stubs will log their first
//! execution with the [`log::Level::Trace`] severity.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use call_hook::CallHook;
use closure_ffi::BareFnOnce;
use pelite::pe64::{Pe, PeObject, PeView};
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

use crate::patch::ArxanPatch;

mod call_hook;
mod code_buffer;
mod game;
mod steamstub;

#[cfg(feature = "ffi")]
pub mod ffi;

use code_buffer::CodeBuffer;
use game::game;
pub use steamstub::schedule_after_steamstub;

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
/// <div class="warning">
///
/// Note that this function calls [`schedule_after_steamstub`] and
/// [`schedule_after_arxan`], which can also be called at most once. Hence they are mutually
/// exclusive.
///
/// </div>
///
/// # Safety
/// This function must be called before the game's entry point runs. It is generally safe to call
/// from within DllMain.
pub unsafe fn neuter_arxan<F>(callback: F)
where
    F: FnOnce(*const u8, bool) + Send + 'static,
{
    static CALLED: AtomicBool = AtomicBool::new(false);
    assert!(
        !CALLED.swap(true, Ordering::Relaxed),
        "ArxanDisabler::disable already called once"
    );

    unsafe {
        schedule_after_arxan(|entry_point, is_present| {
            if !is_present {
                callback(entry_point, false);
                return;
            }

            let game = game();
            make_module_rwe(game.pe);

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
                panic!("analysis of some Arxan stubs failed, aborting");
            }

            log::info!("generating patches");
            let patch_gen_time = Instant::now();
            let patches = crate::patch::ArxanPatch::build_from_stubs(
                game.pe,
                Some(game.preferred_base),
                good_stubs.iter(),
            )
            .expect("failed to generate patches for all stubs");

            log::info!(
                "generated {} patches in {:.3?}",
                patches.len(),
                patch_gen_time.elapsed()
            );

            log::info!("applying patches");
            let patch_apply_time = Instant::now();
            for patch in &patches {
                apply_patch(patch, &game.hook_buffer);
            }
            log::info!(
                "all patches applied in {:3?}. Arxan is now neutered",
                patch_apply_time.elapsed()
            );
            log::debug!("invoking user callback");
            callback(entry_point, true);
        });
    }
}

/// Schedule a callback to run after the Arxan entry point stub.
/// It runs immediately if Arxan was not detected.
///
/// The callback receives the following:
/// - a pointer original entry point before Arxan was applied to the executable
/// - a boolean indicating whether Arxan was detected
///
/// Handles SteamStub 3.1 possibly being applied on top of Arxan.
///
/// # Panics
/// If called more than once.
///
/// <div class="warning">
///
/// Note this function calls [`schedule_after_steamstub`] and is called by [`neuter_arxan`],
/// both of which can only be called once. Hence all three are mutually exclusive.
///
/// </div>
///
/// # Safety
/// This function should only be called before the entry point of the game runs.
pub unsafe fn schedule_after_arxan<F>(callback: F)
where
    F: FnOnce(*const u8, bool) + Send + 'static,
{
    static CALLED: AtomicBool = AtomicBool::new(false);
    if CALLED.swap(true, Ordering::Relaxed) {
        panic!("schedule_after_arxan must not be called more than once");
    }

    unsafe {
        schedule_after_steamstub(move |maybe_arxan_entry, _| {
            let Some(game_entry) = is_arxan_entry(maybe_arxan_entry)
            else {
                log::info!(
                    "Arxan entry point hook not detected. Assuming arxan was not applied to this binary"
                );
                callback(maybe_arxan_entry, false);
                return;
            };

            // Arxan entry stubs begin first SUB rsp, 28 (4 bytes)
            let arxan_stub_hook = &*Box::leak(Box::new(CallHook::<unsafe extern "C" fn()>::new(
                maybe_arxan_entry.add(4) as *mut u8,
            )));

            let detour = BareFnOnce::new_c_in(
                move || {
                    log::debug!("removing Arxan entry point hook");
                    arxan_stub_hook.unhook();
                    // TODO: Fully reverse the entry point so this is not necessary
                    log::debug!("running Arxan entry point stub");
                    arxan_stub_hook.original()();
                    log::debug!("running callback function");
                    callback(game_entry, true)
                },
                &game().hook_buffer,
            );

            log::debug!("detouring Arxan entry point stub");
            arxan_stub_hook.hook_with(detour.leak());
        });
    }
}

/// Checks if the given entry point was hooked by Arxan, returning the address of the
/// original entry point if it was.
///
/// # Safety
/// `entry_point` must point to at least 18 bytes of readable memory.
pub unsafe fn is_arxan_entry(entry_point: *const u8) -> Option<*const u8> {
    #[rustfmt::skip]
    let arxan_entry_pattern: &[u8; 18] = &[
        0x48,0x83,0xec,0x28,        // sub rsp, 28
        0xe8,0x00,0x00,0x00,0x00,   // call {arxan entry stub}
        0x48,0x83,0xc4,0x28,        // add rsp, 28
        0xe9,0x00,0x00,0x00,0x00    // jmp {true entry point}
    ];

    // If all non-zero bytes match, consider the entry point hooked by Arxan
    let entry_point_bytes = unsafe { &*(entry_point as *const [u8; 18]) };
    if entry_point_bytes
        .iter()
        .zip(arxan_entry_pattern)
        .all(|(b, pat)| *pat == 0 || b == pat)
    {
        // Calculate the target of the last jmp instruction
        let jmp_imm = i32::from_le_bytes(entry_point_bytes[14..].try_into().unwrap());
        let true_entry =
            entry_point.map_addr(|addr| (addr + 18).wrapping_add_signed(jmp_imm as isize));
        return Some(true_entry);
    }
    None
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
