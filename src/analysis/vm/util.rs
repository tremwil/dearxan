//! Utility functions used by the forking emulator.

use iced_x86::{Instruction, Mnemonic, OpAccess, OpKind};

/// Check whether the given instruction mnemonic is a CMOV instruction.
pub fn is_cmov(mnemonic: Mnemonic) -> bool {
    mnemonic >= Mnemonic::Cmova && mnemonic <= Mnemonic::Cmovs
}

/// Debugging helper taking a [`RunStep`](super::RunStep) to create a string showing:
/// - the current branch and fork depth;
/// - the instruction and stack pointer values;
/// - the dissassembly of the current instruction;
/// - all register and memory accesses performed by the current instruction.
pub fn format_step_state<I: super::ImageView, D: Clone>(step: &super::RunStep<'_, I, D>) -> String {
    use std::fmt::Write;

    use iced_x86::{FastFormatter, InstructionInfoFactory};

    let mut formatter = FastFormatter::new();
    let mut instr_factory = InstructionInfoFactory::new();
    let mut step_info = String::new();

    formatter.format(step.instruction, &mut step_info);
    step_info = format!(
        "B{:02} F{:02} {:x} RSP = {:08x}\t{step_info}\n\t",
        step.branch_count,
        step.past_forks.len(),
        step.instruction.ip(),
        step.state.registers.rsp().unwrap_or(0),
    );

    let instr_info = instr_factory.info(&step.instruction);
    for used_reg in instr_info.used_registers() {
        let code = op_access_code(used_reg.access());
        let reg_value = (used_reg.register().is_gpr())
            .then(|| step.state.registers.read_gpr(used_reg.register()))
            .flatten();
        step_info += &format!("[{code}] {:?} = {reg_value:x?}\t", used_reg.register());
    }
    for used_mem in instr_info.used_memory() {
        let code = op_access_code(used_mem.access());
        let Some(va) = used_mem.virtual_address(0, |reg, _, _| step.state.virtual_address_cb(reg))
        else {
            continue;
        };

        let mem_value = (used_mem.memory_size().size() <= 8)
            .then(|| step.state.memory.read_int(va, used_mem.memory_size().size()))
            .flatten();

        step_info
            .write_fmt(format_args!("[{code}] mem[{va:x}] = {:x?}\t", mem_value))
            .unwrap();
    }

    step_info
}

pub(crate) fn op_size(instr: &Instruction, op: u32) -> usize {
    match instr.op_kind(op) {
        OpKind::Register => instr.op_register(op).size(),
        OpKind::Memory => instr.memory_size().size(),
        OpKind::Immediate8 => 1,
        OpKind::Immediate16 | OpKind::Immediate8to16 => 2,
        OpKind::Immediate32 | OpKind::Immediate8to32 => 4,
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => 8,
        _ => unimplemented!(),
    }
}

pub(crate) fn reinterpret_unsigned(val: u64, size_bytes: usize) -> u64 {
    let mask = u64::MAX >> (64 - 8 * size_bytes);
    val & mask
}

pub(crate) fn reinterpret_signed(val: u64, size_bytes: usize) -> i64 {
    let sign_bit = 1u64 << (8 * size_bytes - 1);
    (val | (val & sign_bit).wrapping_neg()) as i64
}

#[allow(dead_code)]
pub(crate) fn op_access_code(op_access: OpAccess) -> &'static str {
    match op_access {
        OpAccess::Read => "R",
        OpAccess::Write => "W",
        OpAccess::CondRead => "R?",
        OpAccess::CondWrite => "W?",
        OpAccess::ReadWrite => "RW",
        OpAccess::ReadCondWrite => "RW?",
        _ => "-",
    }
}
