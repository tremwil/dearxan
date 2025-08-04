//! Provides utilities to hook around SteamStub V3.1 (as versionned by Steamless).
//!
//! SteamStub is used in DS2, DS3 and SDT. We must hook around it to be able to extract
//! the binary's original entry point (which in DS3's case will be the Arxan entry point)
//! to then apply the arxan patches on that one.
//!
//! Detouring SteamStub is fairly straightforward. The structure of a stubbed entry point
//! is as follows:
//!
//! ```x86asm
//! CALL steamstub_entry
//! steamstub_entry:
//! {push general purpose registers}
//! {align RSP}
//! CALL steamstub_main
//! {write RAX to call return address}
//! {pop general purpose registers}
//! RET
//! ```
//!
//! `steamstub_main` performs code integrity checks, so we can't simply hook it.
//! However, we can do the following:
//! 1. Hook at the first CALL
//! 2. Follow `steamstub_entry` until we get to the second call
//! 3. Call it ourselves with the usual MSVC x64 calling convention
//! 4. We now have the original (Arxan) entry point as the return value!
//!
//! Which makes it quite easy to work around.

use std::sync::atomic::{AtomicBool, Ordering};

use closure_ffi::BareFnOnce;
use iced_x86::{Decoder, DecoderOptions, FlowControl};
use pelite::{
    pe::{Pe, PeObject},
    pe64::PeView,
};

use super::{call_hook::CallHook, game_code_buffer, game_module};

/// Takes PE entry point and returns original entry point.
pub type SteamStub31Main = unsafe extern "C" fn(u64) -> u64;

/// Finds the main steamstub 3.1 unpacking function in the PE, if present.
///
/// Returns the address of the call instruction invoking the function, as
/// well as the address of the function itself.
pub fn find_steamstub31_main(pe: PeView<'_>) -> Option<(u64, u64)> {
    const STEAMSTUB_HEADER_SIZE: u32 = 0xF0;
    const EXPECTED_SIGNATURE: u32 = 0xC0DEC0DF;

    let entry_rva = pe.optional_header().AddressOfEntryPoint;
    let base = pe.optional_header().ImageBase;
    let [key, sig] = pe.derva::<[u32; 2]>(entry_rva - STEAMSTUB_HEADER_SIZE as u32).ok()?;
    if key ^ sig != EXPECTED_SIGNATURE {
        return None;
    }

    // Walk through SteamStub context save until we get to the call
    let mut decoder = Decoder::new(64, pe.image(), DecoderOptions::NONE);
    let mut rip = base + entry_rva as u64;
    let mut call_count = 0;
    loop {
        decoder.set_ip(rip);
        decoder.set_position((rip - base) as usize).ok()?;
        let instr = decoder.decode();
        rip = match instr.flow_control() {
            FlowControl::Next => instr.next_ip(),
            FlowControl::UnconditionalBranch => instr.near_branch_target(),
            FlowControl::Call => {
                call_count += 1;
                if call_count == 2 {
                    break Some((instr.ip(), instr.near_branch_target()));
                }
                instr.near_branch_target()
            }
            _ => break None,
        }
    }
}

/// Schedule a callback to run after SteamStub 3.1 finishes unpacking the game.
/// It runs immediately if SteamStub was not detected.
///
/// The callback receives the following:
/// - a pointer original entry point before SteamStub was applied to the executable
/// - a boolean indicating whether SteamStub 3.1 was detected
///
/// # Panics
/// If called more than once.
///
/// <div class="warning">
///
/// Note this function is called by [`schedule_after_arxan`](super::schedule_after_arxan)
/// and [`neuter_arxan`](super::neuter_arxan), both of which can only be called once.
/// Hence all three are mutually exclusive.
///
/// </div>
///
/// # Safety
/// This should only be called before the game's entry point is executed.
pub unsafe fn schedule_after_steamstub(callback: impl FnOnce(*const u8, bool) + Send + 'static) {
    static CALLED: AtomicBool = AtomicBool::new(false);
    if CALLED.swap(true, Ordering::Relaxed) {
        panic!("schedule_after_steamstub must not be called more than once");
    }

    let pe = game_module();
    let base = pe.optional_header().ImageBase;
    let opt_header = pe.optional_header();
    let entry_point = opt_header.ImageBase + opt_header.AddressOfEntryPoint as u64;

    let Some((call_ptr, _)) = find_steamstub31_main(pe)
    else {
        log::debug!("SteamStub not detected, running callback immediately");
        callback(entry_point as *const _, false);
        return;
    };

    log::debug!("SteamStub detected, CALL to unpacking routine: {call_ptr:016x}");
    let call_hook = &*Box::leak(Box::new(unsafe {
        CallHook::<SteamStub31Main>::new(call_ptr as *mut u8)
    }));

    let hook = BareFnOnce::new_c_in(
        move |entry| unsafe {
            call_hook.unhook();

            // SteamStub 3.1 checks the PEB for the IsDebugged flag on startup.
            // We'll need to clear it first.
            log::debug!("setting PEB->BeingDebugged to false");
            let debug_flag = peb_being_debugged_flag();
            let prv_debug_flag = debug_flag.swap(false, Ordering::Relaxed);

            log::debug!("running SteamStub unpacker");
            let original_entry = call_hook.original()(entry);
            log::debug!(
                "entry point before SteamStub: {original_entry:016x} (RVA {:x})",
                original_entry - base
            );

            match debug_flag.compare_exchange(
                false,
                prv_debug_flag,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    log::debug!("set PEB->BeingDebugged back to original value ({prv_debug_flag})")
                }
                Err(new) => log::debug!("PEB->BeingDebugged was changed by foreign code to {new}"),
            };

            callback(original_entry as *const _, true);
            original_entry
        },
        game_code_buffer(),
    );

    unsafe { call_hook.hook_with(hook.leak()) };
}

unsafe fn peb_being_debugged_flag<'a>() -> &'a AtomicBool {
    let ptr: *mut bool;
    unsafe {
        std::arch::asm!(
            "mov {reg}, qword ptr GS:[0x30]",
            "mov {reg}, qword ptr [{reg} + 0x60]",
            "lea {reg} [{reg} + 0x2]",
            reg = out(reg) ptr
        );
        AtomicBool::from_ptr(ptr)
    }
}
