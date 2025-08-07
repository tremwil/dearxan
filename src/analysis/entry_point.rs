use iced_x86::{Code, Decoder, DecoderOptions, Register};

use super::ImageView;
use crate::analysis::vm::{MemoryStore, ProgramState, Registers, StepKind};

/// Check if possible entry point `entry_point_va` is hooked by Arxan.
///
/// If true, returns the virtual address of the original entry point and the arxan entry stub,
/// respectively.
pub fn is_arxan_hooked_entry_point(
    image: impl ImageView,
    entry_point_va: u64,
) -> Option<(u64, u64)> {
    // Parse the msvc crt entry point structure

    const EXPECTED_CODES: &[&[Code]] = &[
        &[Code::Sub_rm64_imm8],
        &[Code::Call_rel32_64],
        &[Code::Add_rm64_imm8],
        &[Code::Jmp_rel32_64, Code::Jmp_rel8_64],
    ];

    let mut decoder = Decoder::with_ip(
        64,
        image.read(entry_point_va, 15)?,
        entry_point_va,
        DecoderOptions::NONE,
    );

    let mut security_init_cookie_va = 0;
    let mut scrt_common_main_seh_va = 0;
    for (i, &codes) in EXPECTED_CODES.iter().enumerate() {
        let instr = decoder.decode();
        if !codes.contains(&instr.code()) {
            return None;
        }
        match i {
            1 => security_init_cookie_va = instr.near_branch_target(),
            3 => scrt_common_main_seh_va = instr.near_branch_target(),
            _ => (),
        };
    }

    // Arxan inserts itself in the entry point by hooking `security_init_cookie_va`.
    // Inspect it and try to find a `TEST RSP, 0xF` instruction after a bit

    let state = ProgramState {
        rip: Some(security_init_cookie_va),
        registers: Registers::new([(Register::RSP, 0x10000)]),
        memory: MemoryStore::new(&image),
        user_data: (),
    };

    let mut num_steps = 0;
    state
        .run(|mut step| {
            num_steps += 1;
            // We should get to the TEST RSP, 0xF instruction quite quickly.
            if num_steps > 0x100 {
                return StepKind::Stop(None);
            }

            if step.instruction.code() == Code::Test_rm64_imm32
                && step.instruction.op0_register() == Register::RSP
                && step.instruction.immediate32() == 0xF
            {
                return StepKind::Stop(Some((security_init_cookie_va, scrt_common_main_seh_va)));
            }
            // Don't take any forks
            let _maybe_fork = step.single_step();
            StepKind::Custom(None)
        })
        .flatten()
}
