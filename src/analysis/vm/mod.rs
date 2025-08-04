//! Implements a very basic and lightweight amd64 forking "virtual machine" or "emulator" that can
//! work on partial information and explore multiple program branches.
//!
//! The CPU model is extremely simplified:
//! - All memory is lazily mapped and is both readable and writable.
//! - Only general purpose registers (RAX-R15) are modeled. Segment registers CS, DS, ES and SS are
//!   assumed to be zero.
//! - Instructions can only be read from the *immutable* executable image; self-modifying code is
//!   not supported.
//! - EFLAGS is not modeled; condtional branching/data instructions (such as `CMOVxx`) always fork
//!   the execution of the program into two paths.
//! - Interrupts are not modeled and simply kill the current fork.
//! - A very small subset of instructions are fully modeled: `mov`, `movzx`, `lea`, `xchg`, `add`,
//!   `sub`, `push`, `pop`, `call` and `ret`. Other instructions invalidate the registers and memory
//!   that they would write to according to iced's [`InstructionInfoFactory`] output.
//!
//! Nevertheless, in practice this is sufficient to work through the instruction obfuscations and
//! mutations that Arxan applies to its code.
//!
//! To use the forking emulator, first construct a [`ProgramState`] and then execute all its
//! possible branches via [`ProgramState::run`].

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};

pub mod image;
pub mod memory;
pub mod registers;
pub mod util;

#[doc(inline)]
pub use image::ImageView;
#[doc(inline)]
pub use memory::MemoryStore;
#[doc(inline)]
pub use registers::Registers;

/// The full state of an emulated program.
///
/// This state fetches instructions and static memory from an [`ImageView`] implementation. It also
/// allows attaching extra data to the `user_data` field that can be used for higher-level logic.
#[derive(Debug, Clone)]
pub struct ProgramState<I: ImageView, D: Clone = ()> {
    /// The instruction pointer, if known.
    pub rip: Option<u64>,
    /// The state of general-purpose registers.
    pub registers: Registers,
    /// The state of the virtual memory of the program.
    pub memory: MemoryStore<I>,
    /// An extra field which may be used to attach additional state to the program.
    pub user_data: D,
}

/// Represents a past point in program execution where execution forked in two as a result of a
/// conditional branch/data instruction.
#[derive(Debug)]
pub struct PastFork<I: ImageView, D: Clone = ()> {
    /// The current state of the program (excluding any steps belonging to more recent forks).
    pub state: ProgramState<I, D>,
    /// The index (e.g. time) of the instruction in the execution path since the last the
    /// conditional data/branch instruction.
    pub basic_block_index: usize,
    /// The index of the instruction in the execution path at which this fork was created.
    pub fork_index: usize,
    /// The number of conditional branch/writes that have been encountered on this path since
    /// execution began.
    pub branch_count: usize,
}

/// Stores information about the current step during forking emulation of a [`ProgramState`].
///
/// Much of this state is mutable and can be modified by the callback function given to
/// [`ProgramState::run`].
#[allow(dead_code)]
#[derive(Debug)]
pub struct RunStep<'a, I: ImageView, D: Clone = ()> {
    /// The current instruction being executed.
    pub instruction: &'a mut Instruction,
    /// An [`InstructionInfoFactory`] which can be used to compute register and memory accesses for
    /// the instruction.
    pub info_factory: &'a mut InstructionInfoFactory,
    /// The current state of the program being emulated.
    pub state: &'a mut ProgramState<I, D>,
    /// The past forks created when conditional branch/data instructions were encountered.
    pub past_forks: &'a mut [PastFork<I, D>],
    /// The full execution path (virtual address of instructions) the program took to arrive at its
    /// current state.
    pub execution_path: &'a [u64],
    /// The number of conditional branch/writes that have been encountered on this path since
    /// execution began.
    pub branch_count: usize,
    /// The index of the instruction in the execution path at which this program state was forked
    /// from another. Zero if this is the initial program state.
    pub fork_index: usize,
    /// The index of the last conditional branch/data instruction in the execution path. The
    /// overall execution history after this point is guaranteed to be linear.
    pub basic_block_index: usize,
}

impl<I: ImageView, D: Clone> RunStep<'_, I, D> {
    /// Borrows mutably from self to create an identical [`RunStep`] with a shorter lifetime.
    pub fn reborrow(&mut self) -> RunStep<'_, I, D> {
        RunStep {
            instruction: self.instruction,
            info_factory: self.info_factory,
            state: self.state,
            past_forks: self.past_forks,
            execution_path: self.execution_path,
            branch_count: self.branch_count,
            fork_index: self.fork_index,
            basic_block_index: self.basic_block_index,
        }
    }

    /// Emulate the current instruction, stepping the program forward by one.
    ///
    /// If said instruction performs a conditional write/branch operation,
    pub fn single_step(&mut self) -> Option<ProgramState<I, D>> {
        self.state.single_step(self.instruction, self.info_factory)
    }

    /// Subslice of the execution path starting at the point where this fork was created.
    #[allow(dead_code)] // Public when internal_api is enabled
    pub fn current_fork_path(&self) -> &[u64] {
        &self.execution_path[self.fork_index..]
    }

    /// Subslice of the execution path starting at the last conditional data/branch instruction.
    pub fn basic_block(&self) -> &[u64] {
        &self.execution_path[self.basic_block_index..]
    }

    /// Subslice of the execution path starting at the point where the past `depth` fork was
    /// created.
    ///
    /// If `depth` is zero, this is the same as [`Self::current_fork_path`].
    ///
    /// If `depth` is greater or equal to `self.past_forks.len()`, will return the entire execution
    /// path.
    #[allow(dead_code)] // Public when internal_api is enabled
    pub fn fork_path_since(&self, depth: usize) -> &[u64] {
        let Some(i_tgt_fork) = self.past_forks.len().checked_sub(depth)
        else {
            return self.execution_path;
        };
        let i = self.past_forks.get(i_tgt_fork).map(|f| f.fork_index).unwrap_or(self.fork_index);

        &self.execution_path[i..]
    }
}

/// The kind of action that [`ProgramState::run`] should take to update the current program state.
#[derive(Debug, Clone)]
pub enum StepKind<I: ImageView, D: Clone = (), R = ()> {
    /// Single-step emulation of the current instruction.
    SingleStep,
    /// End execution of the current program state fork.
    ///
    /// Next step, execution of the parent program state will resume.
    StopFork,
    /// Do not emulate the current instruction or update the instruction pointer,
    /// giving `on_step` logic fine-grained control over program state modifications.
    ///
    /// If a new program state is provided, emulation will fork to it, resuming
    /// execution of the current program state once an invalid instruction pointer
    /// is reached or [`StepKind::StopFork`] is received.
    Custom(Option<ProgramState<I, D>>),
    /// Stop emulating all program forks, returning the provided value.
    Stop(R),
}

impl<I: ImageView, D: Clone> ProgramState<I, D> {
    /// Emulate this program state, visiting all possible execution paths.
    ///
    /// The `on_step` callback can be used to inspect and modify the state of the program
    /// as it is executing.
    ///
    /// <div class="warning">
    ///
    /// Note that if there is a loop in the program, this function **will run forever** (until
    /// memory is exhausted) unless `on_step` eventually returns [`StepKind::StopFork`],
    /// [`StepKind::Stop`] or a custom state which is not cyclic.
    ///
    /// </div>
    pub fn run<F, R>(self, mut on_step: F) -> Option<R>
    where
        F: FnMut(RunStep<'_, I, D>) -> StepKind<I, D, R>,
    {
        let mut instruction = Instruction::default();
        let mut info_factory = InstructionInfoFactory::new();
        let mut execution_path: Vec<u64> = Vec::with_capacity(0x1000);

        let mut fork_stack = vec![PastFork {
            basic_block_index: 0,
            fork_index: 0,
            state: self,
            branch_count: 0,
        }];

        while !fork_stack.is_empty() {
            let i_fork = fork_stack.len() - 1;
            let (past_forks, tail) = fork_stack.split_at_mut(i_fork);
            let PastFork {
                state,
                branch_count,
                basic_block_index,
                fork_index,
            } = &mut tail[0];

            let Some((ip, instr_bytes)) =
                state.rip.and_then(|ip| state.memory.image().read(ip, 1).map(|b| (ip, b)))
            else {
                execution_path.truncate(*fork_index);
                fork_stack.pop();
                continue;
            };

            execution_path.push(ip);

            let mut decoder = Decoder::with_ip(64, instr_bytes, ip, DecoderOptions::NONE);
            decoder.decode_out(&mut instruction);
            if instruction.is_invalid() {
                log::debug!("invalid instruction at {ip:x}");
                execution_path.truncate(*fork_index);
                fork_stack.pop();
                continue;
            }

            let run_step = RunStep {
                execution_path: &execution_path,
                instruction: &mut instruction,
                info_factory: &mut info_factory,
                state,
                past_forks,
                branch_count: *branch_count,
                fork_index: *fork_index,
                basic_block_index: *basic_block_index,
            };
            let maybe_fork = match on_step(run_step) {
                StepKind::Stop(ret) => return Some(ret),
                StepKind::StopFork => {
                    execution_path.truncate(*fork_index);
                    fork_stack.pop();
                    continue;
                }
                StepKind::SingleStep => state.single_step(&instruction, &mut info_factory),
                StepKind::Custom(maybe_fork) => maybe_fork,
            };

            if let Some(forked) = maybe_fork {
                // Increment branch count
                *branch_count += 1;
                let branch_count = *branch_count;

                // Set basic block index to next instuction
                *basic_block_index = execution_path.len();

                // Split visited state into shared stack to allow both programs to progress
                // independently
                fork_stack.push(PastFork {
                    fork_index: execution_path.len(),
                    basic_block_index: execution_path.len(),
                    state: forked,
                    branch_count,
                });
            }
        }

        None
    }

    /// Emulate a single instruction, updating the program state accordingly.
    ///
    /// If the instruction results in two possible program states (e.g. conditional branch or CMOV
    /// instructions), returns the other possible state.
    pub fn single_step(
        &mut self,
        instr: &Instruction,
        info_factory: &mut InstructionInfoFactory,
    ) -> Option<ProgramState<I, D>> {
        // Address populated by custom flow control driven by per-mnemonic logic
        let mut flow_override = None;

        match instr.mnemonic() {
            Mnemonic::Mov | Mnemonic::Movzx => {
                let _ = self.set_operand_value(instr, 0, self.get_operand_value(instr, 1));
            }
            Mnemonic::Movsx | Mnemonic::Movsxd => {
                let sign_extended = self
                    .get_operand_value(instr, 1)
                    .map(|arg| util::reinterpret_signed(arg, util::op_size(instr, 0)) as u64);
                let _ = self.set_operand_value(instr, 0, sign_extended);
            }
            Mnemonic::Xchg => self.handle_xchg(instr),
            Mnemonic::Lea => {
                let addr = self.virtual_address(instr, 1);
                let _ = self.set_operand_value(instr, 0, addr);
            }
            Mnemonic::Add => {
                let result = self
                    .get_operand_value(instr, 0)
                    .and_then(|lhs| Some(lhs.wrapping_add(self.get_operand_value(instr, 1)?)));
                let _ = self.set_operand_value(instr, 0, result);
            }
            Mnemonic::Sub => {
                let result = self
                    .get_operand_value(instr, 0)
                    .and_then(|lhs| Some(lhs.wrapping_sub(self.get_operand_value(instr, 1)?)));
                let _ = self.set_operand_value(instr, 0, result);
            }
            Mnemonic::Push => {
                if self.registers.rsp().is_some() {
                    // Careful! To handle the `push rsp` case, we need to resolve the operand before
                    // adjusting rsp
                    let pushed_value = self
                        .get_operand_value(instr, 0)
                        .map(|v| util::reinterpret_signed(v, util::op_size(instr, 0)) as u64);

                    let rsp = self.registers.rsp_mut().as_mut().unwrap();
                    *rsp = rsp.wrapping_add_signed(instr.stack_pointer_increment() as i64);
                    self.memory.write_int(*rsp, pushed_value, 8);
                }
            }
            Mnemonic::Pop => {
                if let Some(rsp) = self.registers.rsp_mut() {
                    let popped_value = self.memory.read_int(*rsp, util::op_size(instr, 0));
                    // Careful! To handle the `pop rsp` case, we need to increment rsp before
                    // writing to the register
                    *rsp = rsp.wrapping_add_signed(instr.stack_pointer_increment() as i64);
                    let _ = self.set_operand_value(instr, 0, popped_value);
                }
            }
            Mnemonic::Call => {
                flow_override = self.get_operand_value(instr, 0);

                self.adjust_rsp(instr.stack_pointer_increment());
                if let Some(rsp) = self.registers.rsp() {
                    self.memory.write_int(rsp, Some(instr.next_ip()), 8);
                }
            }
            Mnemonic::Ret => {
                if let Some(rsp) = self.registers.rsp() {
                    flow_override = self.memory.read_int(rsp, 8);
                }
                self.adjust_rsp(instr.stack_pointer_increment());
            }
            m if util::is_cmov(m) => {
                let original_value = self.get_operand_value(instr, 0);
                let potential_write = self.get_operand_value(instr, 1);

                match (original_value, potential_write) {
                    // Both values are present, so we fork
                    (Some(_), Some(_)) => {
                        self.rip = Some(instr.next_ip());
                        let mut forked = self.clone();
                        let _ = forked.set_operand_value(instr, 0, potential_write);
                        return Some(forked);
                    }
                    // Only new value is present, write it (original path has no extra info)
                    (None, Some(_)) => {
                        let _ = self.set_operand_value(instr, 0, potential_write);
                    }
                    // new value is missing, do nothing (cond path has no extra info)
                    _ => {}
                }
            }
            _ => self.handle_generic(instr, info_factory),
        }

        if flow_override.is_some() {
            self.rip = flow_override;
            return None;
        }
        match instr.flow_control() {
            FlowControl::Next => self.rip = Some(instr.next_ip()),
            FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
                self.rip = self.get_operand_value(instr, 0);
            }
            FlowControl::ConditionalBranch => {
                self.rip = Some(instr.next_ip());
                return Some(Self {
                    rip: Some(instr.near_branch_target()),
                    ..self.clone()
                });
            }
            _ => self.rip = None,
        }

        None
    }

    pub(crate) fn virtual_address_cb(&self, reg: Register) -> Option<u64> {
        match reg {
            Register::CS | Register::DS | Register::ES | Register::SS => Some(0),
            _ if reg.is_gpr() => self.registers.read_gpr(reg),
            _ => None,
        }
    }

    /// Get the virtual address of operand index `op` as it appears in `instr`.
    ///
    /// This has no meaning if the operand is not a memory operand.
    pub fn virtual_address(&self, instr: &Instruction, op: u32) -> Option<u64> {
        instr.virtual_address(op, 0, |reg, _, _| self.virtual_address_cb(reg))
    }

    /// Get the value of `instr`'s operand at index `op`.
    ///
    /// For registers, this is the value of the register.
    ///
    /// For memory operands, this is the value of the referenced memory.
    ///
    /// For branch instructions, this is the branch's target address.
    pub fn get_operand_value(&self, instr: &Instruction, op: u32) -> Option<u64> {
        match instr.op_kind(op) {
            OpKind::Register => {
                let reg = instr.op_register(op);
                if !reg.is_gpr() {
                    return None;
                }
                self.registers.read_gpr(reg)
            }
            OpKind::Memory => {
                let addr = self.virtual_address(instr, op)?;
                self.memory.read_int(addr, instr.memory_size().size())
            }
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Some(instr.near_branch_target())
            }
            _ => instr.try_immediate(op).ok(),
        }
    }

    /// Set the value of `instr`'s operand at index `op`.
    ///
    /// For register operands, this sets the value of the register.
    ///
    /// For memory operands, this writes the value to the referenced memory, ignoring extra bytes.
    ///
    /// Returns a [`Result`] indicating unspecified failure or success.
    ///
    /// # Panics
    /// If the operand is not a register or memory operand.
    pub fn set_operand_value(
        &mut self,
        instr: &Instruction,
        op: u32,
        val: Option<u64>,
    ) -> Result<(), ()> {
        match instr.op_kind(op) {
            OpKind::Register => {
                let reg = instr.op_register(op);
                if !reg.is_gpr() {
                    return Err(());
                }
                self.registers.write_gpr(reg, val)
            }
            OpKind::Memory => {
                let addr = self.virtual_address(instr, op).ok_or(())?;
                self.memory.write_int(addr, val, instr.memory_size().size());
            }
            _ => unimplemented!(),
        }
        Ok(())
    }

    fn adjust_rsp(&mut self, increment: i32) {
        self.registers
            .rsp_mut()
            .as_mut()
            .map(|rsp| *rsp = rsp.wrapping_add_signed(increment as i64));
    }

    fn handle_xchg(&mut self, instr: &Instruction) {
        let mut to_swap = [(None, None); 2];
        for (i, (addr, val)) in to_swap.iter_mut().enumerate() {
            *addr = self.virtual_address(instr, i as u32);
            *val = match instr.op_kind(i as u32) {
                OpKind::Register => self.registers.read_gpr(instr.op_register(i as u32)),
                OpKind::Memory => {
                    addr.and_then(|a| self.memory.read_int(a, instr.memory_size().size()))
                }
                _ => unreachable!(),
            }
        }
        for (i, (addr, _)) in to_swap.iter().enumerate() {
            let other_value = to_swap[1 - i].1;
            match instr.op_kind(i as u32) {
                OpKind::Register => {
                    self.registers.write_gpr(instr.op_register(i as u32), other_value)
                }
                OpKind::Memory => {
                    if let Some(a) = addr {
                        self.memory.write_int(*a, other_value, instr.memory_size().size())
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    fn handle_generic(&mut self, instr: &Instruction, info_factory: &mut InstructionInfoFactory) {
        let used_memory = info_factory.info(instr);

        for mem in used_memory.used_memory() {
            let addr = match mem.virtual_address(0, |reg, _, _| self.virtual_address_cb(reg)) {
                Some(addr) => addr,
                None => continue,
            };
            let access_size = mem.memory_size().size();

            match mem.access() {
                // We are definitely writing to this address. Invalidate the written range.
                OpAccess::Write | OpAccess::ReadWrite => {
                    self.memory.invalidate(addr, access_size);
                }
                // We may be writing to this address. This would normally fork,
                // but the path where we invalidate the memory is worthless as it does
                // not provide any new information, so we don't consider it.
                OpAccess::CondWrite | OpAccess::ReadCondWrite => {}
                _ => {}
            }
        }
        for reg in used_memory.used_registers() {
            // RSP is used implicitly and not present in the rest of the instruction
            if reg.register() == Register::RSP
                && instr.is_stack_instruction()
                && !(0..instr.op_count()).any(|i| instr.op_register(i) == Register::RSP)
                && instr.memory_base() != Register::RSP
                && instr.memory_index() != Register::RSP
            {
                self.adjust_rsp(instr.stack_pointer_increment());
                continue;
            }
            match reg.access() {
                // We are definitely writing to this register. Invalidate it.
                OpAccess::Write | OpAccess::ReadWrite if reg.register().is_gpr() => {
                    self.registers.write_gpr(reg.register(), None);
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use iced_x86::code_asm::*;

    use super::{MemoryStore, ProgramState, Registers, StepKind, image::WithBase};

    #[test]
    fn test_cmov_branching() {
        let mut asm = CodeAssembler::new(64).unwrap();
        asm.mov(ecx, 0x42).unwrap();
        asm.mov(edx, 0x69).unwrap();
        asm.cmove(ecx, edx).unwrap();
        asm.add(ecx, 1).unwrap();
        asm.cmove(edx, ecx).unwrap();
        asm.sub(edx, 4).unwrap();
        asm.ret().unwrap();
        let code = asm.assemble(0).unwrap();
        let image = WithBase::new(&code, 0);

        let state = ProgramState {
            rip: Some(0),
            registers: Registers::default(),
            memory: MemoryStore::new(image),
            user_data: 1u64, // Store the path through cmov branches as a bitmap
        };

        let mut steps = Vec::default();
        state.run(|step| -> StepKind<_, _> {
            steps.push((
                step.instruction.code(),
                step.state.registers.rcx(),
                step.state.registers.rdx(),
            ));
            StepKind::SingleStep
        });

        const EXPECTED: &[(iced_x86::Code, Option<u64>, Option<u64>)] = &[
            (iced_x86::Code::Mov_r32_imm32, None, None),
            (iced_x86::Code::Mov_r32_imm32, Some(0x42), None),
            (iced_x86::Code::Cmove_r32_rm32, Some(0x42), Some(0x69)),
            (iced_x86::Code::Add_rm32_imm8, Some(0x69), Some(0x69)),
            (iced_x86::Code::Cmove_r32_rm32, Some(0x6a), Some(0x69)),
            (iced_x86::Code::Sub_rm32_imm8, Some(0x6a), Some(0x6a)),
            (iced_x86::Code::Retnq, Some(0x6a), Some(0x66)),
            (iced_x86::Code::Sub_rm32_imm8, Some(0x6a), Some(0x69)),
            (iced_x86::Code::Retnq, Some(0x6a), Some(0x65)),
            (iced_x86::Code::Add_rm32_imm8, Some(0x42), Some(0x69)),
            (iced_x86::Code::Cmove_r32_rm32, Some(0x43), Some(0x69)),
            (iced_x86::Code::Sub_rm32_imm8, Some(0x43), Some(0x43)),
            (iced_x86::Code::Retnq, Some(0x43), Some(0x3F)),
            (iced_x86::Code::Sub_rm32_imm8, Some(0x43), Some(0x69)),
            (iced_x86::Code::Retnq, Some(0x43), Some(0x65)),
        ];

        assert_eq!(&steps, EXPECTED)
    }
}
