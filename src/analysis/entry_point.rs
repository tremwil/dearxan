//! Tools for analyzing the entry point of an executable protected by Arxan.

use iced_x86::{Code, Decoder, DecoderOptions, Register};

use super::ImageView;
use crate::analysis::vm::{MemoryStore, ProgramState, Registers, StepKind};

/// Information about the structure of the entry point of an executable compiled with MSVC on which
/// Arxan was possibly applied.
///
/// The first few instructions of a MSVC entry point are as follows:
///
/// ```text
/// sub rsp, 28
/// call __security_init_cookie
/// add rsp, 28
/// call __scrt_common_main_seh
/// ```
///
/// If Arxan was applied to the executable, a sequence of chained Arxan stubs will be inserted at
/// the beginning of `__security_init_cookie`.
pub struct MsvcEntryPoint {
    /// Virtual address of the `__security_init_cookie` function.
    pub security_init_cookie_va: u64,
    /// Virtual address of the `__scrt_common_main_seh` function.
    pub scrt_common_main_seh_va: u64,
    /// If true, the entry point was hooked by Arxan.
    ///
    /// This is done by inserting Arxan stubs at the start of `__security_init_cookie`.
    pub is_arxan_hooked: bool,
}

impl MsvcEntryPoint {
    pub fn try_from_va(image: impl ImageView, entry_point_va: u64) -> Option<Self> {
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

        // Arxan inserts stubs into `security_init_cookie_va`.
        // Inspect it and try to find a `TEST RSP, 0xF` instruction after a bit

        let state = ProgramState {
            rip: Some(security_init_cookie_va),
            registers: Registers::new([(Register::RSP, 0x10000)]),
            memory: MemoryStore::new(&image),
            user_data: (),
        };

        let mut num_steps = 0;
        let is_arxan_hooked = state
            .run(|mut step| {
                num_steps += 1;
                // We should get to the TEST RSP, 0xF instruction quite quickly.
                if num_steps > 0x100 {
                    return StepKind::Stop(false);
                }

                if step.instruction.code() == Code::Test_rm64_imm32
                    && step.instruction.op0_register() == Register::RSP
                    && step.instruction.immediate32() == 0xF
                {
                    return StepKind::Stop(true);
                }
                // Don't take any forks
                let _maybe_fork = step.single_step();
                StepKind::Custom(None)
            })
            .unwrap_or_default();

        Some(Self {
            security_init_cookie_va,
            scrt_common_main_seh_va,
            is_arxan_hooked,
        })
    }
}
