use pelite::{
    pe::{Pe, PeObject},
    pe64::PeView,
};
use std::{io::Write, sync::LazyLock};
use windows::{
    core::PCSTR,
    Win32::System::{
        LibraryLoader::GetModuleHandleA,
        Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE},
    },
};

use crate::patcher::StubPatchInfo;

use super::code_buffer::CodeBuffer;

pub unsafe fn find_and_patch_stubs(
    pe: PeView<'_>,
    code_buf: &CodeBuffer,
    mut stub_filter: impl FnMut(u64, Option<&StubPatchInfo>) -> bool,
) {
    let base = pe.optional_header().ImageBase;

    // find_arxan_stubs(pe, |hook_addr, patch| {
    //     if !stub_filter(hook_addr, patch.as_ref()) {
    //         return;
    //     }

    //     let encoded = match patch.and_then(|p| p.assemble().ok()) {
    //         Some(p) => p,
    //         None => {
    //             log::warn!(
    //                 "Failed to create patch for stub at {hook_addr:016x} (RVA {:x})",
    //                 hook_addr - base
    //             );
    //             return;
    //         }
    //     };

    //     #[cfg(feature = "disabler-debug")]
    //     let encoded: Vec<_> = disabler_debug::emit_log_call(hook_addr)
    //         .unwrap()
    //         .into_iter()
    //         .chain(encoded)
    //         .collect();

    //     let thunk = code_buf.write(&encoded).unwrap().addr() as i64;
    //     let jmp_immediate: i32 = (thunk - hook_addr as i64 - 5).try_into().unwrap();
    //     let mut to_patch = unsafe { std::slice::from_raw_parts_mut(hook_addr as *mut u8, 5) };
    //     to_patch.write(&[0xE9]).unwrap();
    //     to_patch.write(&jmp_immediate.to_le_bytes()).unwrap();

    //     log::trace!("Patched arxan stub at {:016x}", hook_addr);
    // });
}

#[cfg(feature = "disabler-debug")]
mod disabler_debug {
    use fxhash::FxHashSet;
    use iced_x86::{
        BlockEncoder, BlockEncoderOptions, Code, IcedError, Instruction, InstructionBlock, Register,
    };
    use std::sync::Mutex;

    unsafe extern "C" fn log_arxan_stub(hook_addr: u64, rsp: u64) {
        static CALLED_STUBS: Mutex<Option<FxHashSet<u64>>> = Mutex::new(None);
        let mut maybe_map = CALLED_STUBS.lock().unwrap();
        if maybe_map.get_or_insert_default().insert(hook_addr) {
            log::trace!("Stub for {hook_addr:016x} called | RSP = {rsp:016x}");
        }
    }

    pub fn emit_log_call(hook_addr: u64) -> Result<Vec<u8>, IcedError> {
        let log_stub_instructions = [
            Instruction::with2(Code::Mov_r64_rm64, Register::RSI, Register::RSP)?,
            Instruction::with2(Code::And_rm64_imm8, Register::RSP, -0x10i64)?,
            Instruction::with2(Code::Sub_rm64_imm8, Register::RSP, 0x30)?,
            Instruction::with2(Code::Mov_r64_imm64, Register::RCX, hook_addr)?,
            Instruction::with2(Code::Mov_r64_rm64, Register::RDX, Register::RSI)?,
            Instruction::with2(Code::Mov_r64_imm64, Register::RAX, log_arxan_stub as u64)?,
            Instruction::with1(Code::Call_rm64, Register::RAX)?,
            Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::RSI)?,
        ];
        let encoded = BlockEncoder::encode(
            64,
            InstructionBlock::new(&log_stub_instructions, 0),
            BlockEncoderOptions::NONE,
        )?;
        Ok(encoded.code_buffer)
    }
}

pub fn game_module() -> PeView<'static> {
    static PE: LazyLock<PeView<'static>> = LazyLock::new(|| unsafe {
        let hmod = GetModuleHandleA(PCSTR::null()).unwrap();
        PeView::module(hmod.0 as *const _)
    });
    *PE
}

pub fn game_code_buffer() -> &'static CodeBuffer {
    static BUF: LazyLock<CodeBuffer> = LazyLock::new(|| {
        CodeBuffer::alloc_near(game_module().image(), 0x100_0000, 1 << 31).unwrap()
    });
    &BUF
}

pub unsafe fn make_module_rwe(pe: PeView<'_>) {
    let base = pe.image().as_ptr().addr();
    for section in pe.section_headers() {
        let rva_range = section.virtual_range();
        let len = (rva_range.end - rva_range.start) as usize;

        let mut protect = Default::default();
        unsafe {
            VirtualProtect(
                (base + rva_range.start as usize) as *const _,
                len,
                PAGE_EXECUTE_READWRITE,
                &mut protect,
            )
            .unwrap();
        }
    }
}

/// Sets the BeingDebugged flag in the PEB to false.
pub unsafe fn clear_being_debugged() {
    unsafe {
        std::arch::asm!(
            "mov {reg}, qword ptr GS:[0x30]",
            "mov {reg}, qword ptr [{reg} + 0x60]",
            "mov byte ptr [{reg} + 0x2], 0",
            reg = out(reg) _
        );
    }
}
