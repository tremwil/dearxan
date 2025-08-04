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

use closure_ffi::BareFnOnce;
use iced_x86::{Decoder, DecoderOptions, FlowControl};
use pelite::{
    pe::{Pe, PeObject},
    pe64::PeView,
};

use crate::disabler::common::clear_being_debugged;

use super::{
    call_hook::CallHook,
    common::{game_code_buffer, game_module},
};

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
    let [key, sig] = pe
        .derva::<[u32; 2]>(entry_rva - STEAMSTUB_HEADER_SIZE as u32)
        .ok()?;
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
/// The callback receives the original entry point before SteamStub was
/// applied to the executable.
///
/// Runs immediately if SteamStub is not detected.
///
/// # Warning
/// This should only be called **once before the entry point of the game runs**.
pub unsafe fn schedule_after_steamstub(callback: impl FnOnce(u64) + Send + 'static) {
    let pe = game_module();
    let base = pe.optional_header().ImageBase;
    let opt_header = pe.optional_header();
    let entry_point = opt_header.ImageBase + opt_header.AddressOfEntryPoint as u64;

    match find_steamstub31_main(pe) {
        None => callback(entry_point),
        Some((call_ptr, _)) => unsafe {
            log::debug!("SteamStub detected, CALL address: {call_ptr:016x}");
            let call_hook = &*Box::leak(Box::new(CallHook::<SteamStub31Main>::new(
                call_ptr as *mut u8,
            )));

            let hook = BareFnOnce::new_c_in(
                move |entry| {
                    call_hook.unhook();

                    // SteamStub 3.1 checks the PEB for the IsDebugged flag on startup.
                    // We'll need to clear it first.
                    clear_being_debugged();
                    log::debug!("Set PEB->BeingDebugged to false");

                    log::debug!("Running SteamStub unpacker");
                    let original_entry = call_hook.original()(entry);
                    log::debug!(
                        "Original entry point: {original_entry:016x} (RVA {:x})",
                        original_entry - base
                    );
                    callback(original_entry);
                    original_entry
                },
                game_code_buffer(),
            );

            call_hook.hook_with(hook.leak());
        },
    };
}
