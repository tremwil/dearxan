use iced_x86::Register;

use crate::analysis::ssa::{
    ir::{
        DefinedVar, IrInstruction, IrRegister, IrStackRef, IrVariable, MemExpr, MovOps, StackRef,
        UsedVars,
    },
    state::{BlockDefs, PropagatedValue},
};

#[derive(Debug, Clone, Default)]
pub struct LiftedBlock {
    pub defs: BlockDefs,
    pub lifted_instructions: Vec<IrInstruction>,
    pub lifted_to_native: Vec<Option<usize>>,
    pub native_instructions: Vec<iced_x86::Instruction>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LifterError {
    UnsupportedInstruction,
    UnsupportedSIBMem,
    UnsupportedOpKind,
    NonStackMemoryAccess,
}

impl LiftedBlock {
    pub fn len(&self) -> usize {
        self.lifted_instructions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lifted_instructions.is_empty()
    }

    pub fn clear(&mut self) {
        self.defs.clear();
        self.lifted_instructions.clear();
        self.lifted_to_native.clear();
        self.native_instructions.clear();
    }

    pub fn lift_instruction(
        &mut self,
        instruction: &iced_x86::Instruction,
    ) -> Result<(), LifterError> {
        use iced_x86::Code;

        fn is_cmov64(instruction: &iced_x86::Instruction) -> bool {
            let c = instruction.code() as usize;
            instruction.op0_register().is_gpr64()
                && c >= Code::Cmovo_r64_rm64 as usize
                && c <= Code::Cmovg_r64_rm64 as usize
        }

        if instruction.mnemonic() == iced_x86::Mnemonic::Nop {
            self.push_lifted_instruction(IrInstruction::Nop);
            self.native_instructions.push(*instruction);
            return Ok(());
        }

        match instruction.code() {
            Code::Mov_r64_imm64 => self.handle_mov_imm(instruction, instruction.immediate64())?,
            Code::Mov_rm64_imm32 => {
                self.handle_mov_imm(instruction, instruction.immediate32to64().cast_unsigned())?
            }
            Code::Mov_r64_rm64 => self.handle_mov_reg(instruction)?,
            Code::Mov_rm64_r64 => self.handle_mov_stack(instruction)?,
            Code::Lea_r64_m => self.handle_lea(instruction)?,
            Code::Pushq_imm8 | Code::Push_imm16 | Code::Pushq_imm32 => {
                self.handle_push_imm(instruction)?
            }
            Code::Push_r64 => self.handle_push_reg(instruction)?,
            Code::Pop_r64 => self.handle_pop_reg(instruction)?,
            Code::Xchg_r64_RAX | Code::Xchg_rm64_r64 => self.handle_xchg(instruction)?,
            Code::Jmp_rel8_64 | Code::Jmp_rel32_64 => self.handle_jmp_rel(instruction)?,
            Code::Jmp_rm64 => self.handle_jmp_rm(instruction)?,
            Code::Retnq => self.handle_ret(instruction)?,
            _ if is_cmov64(instruction) => self.handle_cmov(instruction)?,
            _ => return Err(LifterError::UnsupportedInstruction),
        }

        self.native_instructions.push(*instruction);
        Ok(())
    }

    fn handle_mov_imm(
        &mut self,
        native: &iced_x86::Instruction,
        imm: u64,
    ) -> Result<(), LifterError> {
        self.emit_mov_imm(self.modrm_var(native, 0)?, imm);
        Ok(())
    }

    fn handle_mov_reg(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        self.emit_mov_reg(native.op0_register(), self.modrm_var(native, 1)?);
        Ok(())
    }

    fn handle_mov_stack(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        let IrVariable::Stack(prev_dst) = self.modrm_var(native, 0)?
        else {
            return self.handle_mov_reg(native);
        };
        self.emit_mov_stack(
            prev_dst.id,
            self.defs.registers.current(native.op1_register()),
        );

        Ok(())
    }

    fn handle_lea(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        self.emit_lea(native.op0_register(), self.modrm_mem_expr(native)?);
        Ok(())
    }

    fn handle_push_imm(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        let imm = native.try_immediate(1).unwrap();
        let dst = self.defs.registers.stack_at_rsp(-8).ok_or(LifterError::NonStackMemoryAccess)?;

        self.emit_mov_imm(IrVariable::Stack(dst.into()), imm);

        let new_rsp = MemExpr::RegOffset(self.defs.registers.current(Register::RSP), -8);
        self.emit_lea(Register::RSP, new_rsp);

        Ok(())
    }

    fn handle_push_reg(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        self.emit_mov_stack(
            self.defs.registers.stack_at_rsp(-8).ok_or(LifterError::NonStackMemoryAccess)?,
            self.defs.registers.current(native.op1_register()),
        );

        let new_rsp = MemExpr::RegOffset(self.defs.registers.current(Register::RSP), -8);
        self.emit_lea(Register::RSP, new_rsp);

        Ok(())
    }

    fn handle_pop_reg(&mut self, instruction: &iced_x86::Instruction) -> Result<(), LifterError> {
        let mut stack_ref =
            self.defs.registers.stack_at_rsp(0).ok_or(LifterError::NonStackMemoryAccess)?;

        let new_rsp = MemExpr::RegOffset(self.defs.registers.current(Register::RSP), 8);
        self.emit_lea(Register::RSP, new_rsp);

        // LEA will have pushed a new tag!
        stack_ref.source = self.defs.registers.current(Register::RSP);
        let popped = IrVariable::Stack(stack_ref.into());
        self.emit_mov_reg(instruction.op0_register(), popped);

        Ok(())
    }

    fn handle_xchg(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        let lhs = self.modrm_var(native, 0)?;
        let rhs = self.defs.registers.current(native.op1_register());

        match lhs {
            IrVariable::Register(r) => self.emit_mov_reg(*r, IrVariable::Register(rhs)),
            IrVariable::Stack(s) => self.emit_mov_stack(*s, rhs),
        }
        self.emit_mov_reg(rhs.id, lhs);

        Ok(())
    }

    fn handle_jmp_rel(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        let lifted = IrInstruction::JmpImm(native.near_branch_target());
        self.push_lifted_instruction(lifted);
        Ok(())
    }

    fn handle_jmp_rm(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        let lifted = IrInstruction::Jmp(self.modrm_var(native, 0)?);
        self.push_lifted_instruction(lifted);
        Ok(())
    }

    fn handle_ret(&mut self, _: &iced_x86::Instruction) -> Result<(), LifterError> {
        let mut stack_ref =
            self.defs.registers.stack_at_rsp(0).ok_or(LifterError::NonStackMemoryAccess)?;

        let new_rsp = MemExpr::RegOffset(self.defs.registers.current(Register::RSP), 8);
        self.emit_lea(Register::RSP, new_rsp);

        // LEA will have pushed a new tag!
        stack_ref.source = self.defs.registers.current(Register::RSP);
        let tagged_stack = self.defs.stack.current(stack_ref);

        let jmp = IrInstruction::Jmp(IrVariable::Stack(tagged_stack));
        self.push_lifted_instruction(jmp);

        Ok(())
    }

    fn handle_cmov(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        let cond = native.condition_code();
        let src = self.modrm_var(native, 1)?;
        let prv_dest = self.defs.registers.current(native.op0_register());
        let value = PropagatedValue::phony(
            cond,
            self.defs.propagated_value(src),
            self.defs.registers.propagated_value(prv_dest),
        );

        let dst = self.defs.registers.push_def(prv_dest.id, self.len(), value);
        let lifted = IrInstruction::Cmov { cond, dst, src };
        self.push_lifted_instruction(lifted);
        Ok(())
    }

    fn emit_mov_imm(&mut self, prev_dst: IrVariable, imm: u64) {
        let value = PropagatedValue::Constant(imm);
        let dst = self.defs.push_var(prev_dst, self.len(), value);
        let lifted = IrInstruction::Mov(MovOps::Immediate { dst, imm });
        self.push_lifted_instruction(lifted);
    }

    fn emit_mov_reg(&mut self, dst: Register, src: IrVariable) {
        let value = self.defs.propagated_value(src);
        let dst = self.defs.registers.push_def(dst, self.len(), value);
        let lifted = IrInstruction::Mov(MovOps::Register { dst, src });
        self.push_lifted_instruction(lifted);
    }

    fn emit_mov_stack(&mut self, dst: StackRef, src: IrRegister) {
        let value = self.defs.registers.propagated_value(src);
        let dst = self.defs.stack.push_def(dst, self.len(), value);
        let lifted = IrInstruction::Mov(MovOps::Stack { dst, src });
        self.push_lifted_instruction(lifted);
    }

    fn emit_lea(&mut self, dst: Register, mem: MemExpr) {
        let value = self.defs.mem_expr_value(mem);
        let dst = self.defs.registers.push_def(dst, self.len(), value);
        let lifted = IrInstruction::Lea { dst, mem };
        self.push_lifted_instruction(lifted);
    }

    fn push_lifted_instruction(&mut self, lifted: IrInstruction) {
        for used_var in lifted.used_vars() {
            if let Some(def) = self.defs.def_of_mut(used_var) {
                def.increment_refcount();
            }
        }

        self.lifted_instructions.push(lifted);
        self.lifted_to_native.push(Some(self.native_instructions.len()));
    }

    fn modrm_mem_expr(&self, instruction: &iced_x86::Instruction) -> Result<MemExpr, LifterError> {
        if instruction.is_ip_rel_memory_operand() {
            return Ok(MemExpr::Constant(instruction.memory_displacement64()));
        }
        // Don't support SIB to limit additions to constants
        if instruction.memory_index() != Register::None {
            return Err(LifterError::UnsupportedSIBMem);
        }
        Ok(MemExpr::RegOffset(
            self.defs.registers.current(instruction.memory_base()),
            instruction.memory_displacement64().cast_signed() as i32,
        ))
    }

    fn modrm_var(
        &self,
        instruction: &iced_x86::Instruction,
        op: u32,
    ) -> Result<IrVariable, LifterError> {
        match instruction.op_kind(op) {
            iced_x86::OpKind::Register => {
                Ok(self.defs.registers.current(instruction.op_register(op)).into())
            }
            iced_x86::OpKind::Memory => {
                let MemExpr::RegOffset(reg, offset) = self.modrm_mem_expr(instruction)?
                else {
                    return Err(LifterError::NonStackMemoryAccess);
                };
                let stack_ref = self
                    .defs
                    .registers
                    .stack_at(reg, offset)
                    .ok_or(LifterError::NonStackMemoryAccess)?;
                Ok(self.defs.stack.current(stack_ref).into())
            }
            _ => Err(LifterError::UnsupportedOpKind),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ssa::{lifter::LiftedBlock, test::samples};

    #[test]
    fn lift_arxan_call() -> Result<(), Box<dyn std::error::Error>> {
        let mut block = LiftedBlock::default();
        for instruction in samples::arxan_call() {
            block.lift_instruction(&instruction).unwrap();
        }

        for ir in &block.lifted_instructions {
            println!("{}", ir);
        }

        Ok(())
    }

    #[test]
    fn lift_arxan_cmov() -> Result<(), Box<dyn std::error::Error>> {
        let mut block = LiftedBlock::default();
        for instruction in samples::arxan_cmov() {
            block.lift_instruction(&instruction).unwrap();
        }

        for ir in &block.lifted_instructions {
            println!("{}", ir);
        }

        Ok(())
    }
}
