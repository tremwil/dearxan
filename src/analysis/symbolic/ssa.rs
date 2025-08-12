use fxhash::FxHashMap;
use iced_x86::{ConditionCode, Instruction, Mnemonic, OpKind, Register};
use pelite::pe32::Va;
use rayon::iter::Fold;
use smallvec::SmallVec;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum VarLabel {
    Register(Register),
    Stack(i32), // So the enum fits in 8 bytes
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct SSAVar {
    label: VarLabel,
    generation: Option<u32>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum FoldExpr {
    OffsetFrom(SSAVar, u64),
    Constant(u64),
}

impl FoldExpr {
    fn add(self, imm: u64) -> Self {
        match self {
            Self::OffsetFrom(v, c) => Self::OffsetFrom(v, c.wrapping_add(imm)),
            Self::Constant(c) => Self::Constant(c.wrapping_add(imm)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Operand {
    Var(SSAVar),
    Imm(u64),
}

impl Operand {
    fn folded(&self, fold_var: impl FnOnce(&SSAVar) -> Option<FoldExpr>) -> Option<FoldExpr> {
        match self {
            Self::Imm(imm) => Some(FoldExpr::Constant(*imm)),
            Self::Var(var) => fold_var(var),
        }
    }
}

// Should be enough to deobfuscate arxan
#[derive(Debug, Clone)]
enum IR {
    Nop,
    AddImm {
        lhs: SSAVar,
        rhs: u64,
    },
    Mov {
        lhs: SSAVar,
        rhs: Operand,
    },
    CMov {
        cond: ConditionCode,
        lhs: SSAVar,
        rhs: Operand,
    },
    Jmp(Operand),
    Jcc {
        cond: ConditionCode,
        target: Operand,
    },
}

#[derive(Debug, Clone)]
struct IRRecord {
    ir: IR,
    instruction_index: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
struct SSAGen {
    ir_index: usize,
    folded: Option<FoldExpr>,
}

type GenList = SmallVec<[SSAGen; 8]>;

#[derive(Default, Clone)]
struct Registers {
    regs: [GenList; Self::GPR_COUNT],
}

impl std::fmt::Debug for Registers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Registers");
        for (i, recs) in self.regs.iter().enumerate() {
            if recs.is_empty() {
                continue;
            }
            let reg: Register = (Register::RAX as usize + i).try_into().unwrap();
            s.field(&format!("{:?}", reg), recs);
        }
        s.finish()
    }
}

impl Registers {
    const GPR_COUNT: usize = Register::R15 as usize - Register::RAX as usize + 1;

    fn gpr64(&self, reg: Register) -> &GenList {
        assert!(reg.is_gpr64());
        &self.regs[reg as usize - Register::RAX as usize]
    }

    fn gpr64_mut(&mut self, reg: Register) -> &mut GenList {
        assert!(reg.is_gpr64());
        &mut self.regs[reg as usize - Register::RAX as usize]
    }
}

#[derive(Default, Debug, Clone)]
struct Stack {
    values: FxHashMap<i32, GenList>,
}

#[derive(Default, Debug, Clone)]
struct BlockLifter {
    registers: Registers,
    stack: Stack,
    instructions: Vec<Instruction>,
    ir: Vec<IRRecord>,
}

impl BlockLifter {
    fn latest_var(&self, label: VarLabel) -> SSAVar {
        SSAVar {
            label,
            generation: self
                .gens(label)
                .and_then(|recs| recs.len().checked_sub(1))
                .map(|g| g as u32),
        }
    }

    fn push_gen(&mut self, label: VarLabel, record: SSAGen) -> SSAVar {
        let gens = self.gens_mut(label);
        let var = SSAVar {
            label,
            generation: Some(gens.len() as u32),
        };
        gens.push(record);
        var
    }

    fn gens(&self, label: VarLabel) -> Option<&GenList> {
        match label {
            VarLabel::Register(reg) => Some(self.registers.gpr64(reg)),
            VarLabel::Stack(offset) => self.stack.values.get(&offset),
        }
    }

    fn gens_mut(&mut self, label: VarLabel) -> &mut GenList {
        match label {
            VarLabel::Register(reg) => self.registers.gpr64_mut(reg),
            VarLabel::Stack(offset) => self.stack.values.entry(offset).or_default(),
        }
    }

    fn gen_of(&self, v: &SSAVar) -> Option<&SSAGen> {
        let generation = v.generation? as usize;
        self.gens(v.label).and_then(|recs| recs.get(generation))
    }

    fn gen_of_mut(&mut self, v: &SSAVar) -> Option<&mut SSAGen> {
        let generation = v.generation? as usize;
        self.gens_mut(v.label).get_mut(generation)
    }

    fn virtual_address(&self, instruction: &Instruction) -> Option<FoldExpr> {
        if instruction.is_ip_rel_memory_operand() {
            return Some(FoldExpr::Constant(instruction.memory_displacement64()));
        }

        let base = instruction.memory_base();
        let index = instruction.memory_index();

        let var = self.latest_var(VarLabel::Register(
            if base.is_gpr64() && index == Register::None {
                base
            }
            else if base == Register::None
                && index.is_gpr64()
                && instruction.memory_index_scale() == 1
            {
                index
            }
            else {
                return None;
            },
        ));

        Some(FoldExpr::OffsetFrom(
            var,
            instruction.memory_displacement64(),
        ))
    }

    fn get_write_label(&self, instruction: &Instruction, op: u32) -> Option<VarLabel> {
        match instruction.op_kind(op) {
            OpKind::Register => {
                let reg = instruction.op_register(op);
                if !reg.is_gpr64() {
                    return None;
                }
                Some(VarLabel::Register(reg))
            }
            OpKind::Memory => match self.virtual_address(instruction)? {
                FoldExpr::OffsetFrom(var, offset) => {
                    self.get_stack_label(&var, offset.cast_signed() as i32)
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn get_unfolded_op(&self, instruction: &Instruction, op: u32) -> Option<Operand> {
        match instruction.op_kind(op) {
            OpKind::Register => {
                let reg = instruction.op_register(op);
                if !reg.is_gpr64() {
                    return None;
                }
                Some(Operand::Var(self.latest_var(VarLabel::Register(reg))))
            }
            OpKind::Memory => {
                todo!()
            }
            _ => instruction.try_immediate(op).ok().map(|imm| Operand::Imm(imm)),
        }
    }

    fn get_stack_label(&self, var: &SSAVar, extra_offset: i32) -> Option<VarLabel> {
        let rsp_fold = self.get_fold_expr(var);
        match rsp_fold {
            FoldExpr::OffsetFrom(
                SSAVar {
                    label: VarLabel::Register(Register::RSP),
                    generation: None,
                },
                offset,
            ) => Some(VarLabel::Stack(
                (offset.cast_signed() as i32).checked_add(extra_offset)?,
            )),
            _ => None,
        }
    }

    fn get_rsp_stack_label(&self, extra_offset: i32) -> Option<VarLabel> {
        self.get_stack_label(
            &self.latest_var(VarLabel::Register(Register::RSP)),
            extra_offset,
        )
    }

    fn get_fold_expr(&self, v: &SSAVar) -> FoldExpr {
        self.gen_of(v).and_then(|r| r.folded).unwrap_or(FoldExpr::OffsetFrom(*v, 0))
    }

    fn emit_mov(&mut self, lhs: VarLabel, rhs: Operand) {
        // Don't emit if the mov does nothing
        if let Operand::Var(v) = rhs
            && v.label == lhs
        {
            return;
        }

        let lhs_gen = SSAGen {
            ir_index: self.ir.len(),
            folded: rhs.folded(|v| Some(self.get_fold_expr(v))),
        };
        let lhs_var = self.push_gen(lhs, lhs_gen);
        self.ir.push(IRRecord {
            ir: IR::Mov { lhs: lhs_var, rhs },
            instruction_index: Some(self.instructions.len()),
        });
    }

    fn emit_cmov(&mut self, cond: ConditionCode, lhs: VarLabel, rhs: Operand) {
        // Don't emit if the mov does nothing
        if let Operand::Var(v) = rhs
            && v.label == lhs
        {
            return;
        }

        let lhs_gen = SSAGen {
            ir_index: self.ir.len(),
            folded: None,
        };
        let lhs_var = self.push_gen(lhs, lhs_gen);
        self.ir.push(IRRecord {
            ir: IR::CMov {
                cond,
                lhs: lhs_var,
                rhs,
            },
            instruction_index: Some(self.instructions.len()),
        });
    }

    fn emit_add(&mut self, lhs: VarLabel, rhs: u64) {
        // Don't emit if the add does nothing
        if rhs == 0 {
            return;
        }

        let lhs_gen = SSAGen {
            ir_index: self.ir.len(),
            folded: Some(self.get_fold_expr(&self.latest_var(lhs)).add(rhs)),
        };
        let lhs_var = self.push_gen(lhs, lhs_gen);
        self.ir.push(IRRecord {
            ir: IR::AddImm { lhs: lhs_var, rhs },
            instruction_index: Some(self.instructions.len()),
        });
    }

    fn emit_jmp(&mut self, target: Operand) {
        self.ir.push(IRRecord {
            ir: IR::Jmp(target),
            instruction_index: Some(self.instructions.len()),
        });
    }

    pub fn lift_instruction(&mut self, instruction: &Instruction) -> Option<()> {
        match instruction.mnemonic() {
            Mnemonic::Mov => {
                let lhs = self.get_write_label(instruction, 0)?;
                let rhs = self.get_unfolded_op(instruction, 1)?;
                self.emit_mov(lhs, rhs);
            }
            Mnemonic::Lea => {
                let lhs = self.get_write_label(instruction, 0)?;
                let rhs = self.virtual_address(instruction)?;

                match rhs {
                    FoldExpr::Constant(c) => self.emit_mov(lhs, Operand::Imm(c)),
                    FoldExpr::OffsetFrom(v, c) => {
                        self.emit_mov(lhs, Operand::Var(v));
                        self.emit_add(lhs, c);
                    }
                }
            }
            Mnemonic::Xchg => {
                let lhs = self.get_write_label(instruction, 0)?;
                let rhs = self.get_write_label(instruction, 1)?;

                if lhs != rhs {
                    let lhs_var = Operand::Var(self.latest_var(lhs));
                    let rhs_var = Operand::Var(self.latest_var(rhs));

                    self.emit_mov(lhs, rhs_var);
                    self.emit_mov(rhs, lhs_var);
                }
            }
            Mnemonic::Add | Mnemonic::Sub if instruction.try_immediate(1).is_ok() => {
                let lhs = self.get_write_label(instruction, 0)?;
                let mut rhs = instruction.try_immediate(1).unwrap();

                if instruction.mnemonic() == Mnemonic::Sub {
                    rhs = rhs.wrapping_neg();
                }
                self.emit_add(lhs, rhs);
            }
            Mnemonic::Push => {
                let src = self.get_unfolded_op(instruction, 0)?;
                let stack = self.get_rsp_stack_label(-8)?;

                self.emit_mov(stack, src);
                self.emit_add(VarLabel::Register(Register::RSP), (-8i64).cast_unsigned());
            }
            Mnemonic::Pop => {
                let dest = self.get_write_label(instruction, 0)?;
                let stack = self.latest_var(self.get_rsp_stack_label(0)?);

                self.emit_add(VarLabel::Register(Register::RSP), 8);
                self.emit_mov(dest, Operand::Var(stack));
            }
            Mnemonic::Jmp => {
                let target = self.get_unfolded_op(instruction, 0)?;
                self.emit_jmp(target);
            }
            Mnemonic::Call => {
                let target = self.get_unfolded_op(instruction, 0)?;
                self.emit_add(VarLabel::Register(Register::RSP), (-8i64).cast_unsigned());

                let stack = self.get_rsp_stack_label(0)?;
                self.emit_mov(stack, Operand::Imm(instruction.next_ip()));
                self.emit_jmp(target);
            }
            Mnemonic::Ret => {
                self.emit_add(VarLabel::Register(Register::RSP), 8);
                let stack = self.latest_var(self.get_rsp_stack_label(-8)?);
                self.emit_jmp(Operand::Var(stack));
            }
            m if super::vm::util::is_cmov(m) => {
                let cond = instruction.condition_code();
                let lhs = self.get_write_label(instruction, 0)?;
                let rhs = self.get_unfolded_op(instruction, 1)?;
                self.emit_cmov(cond, lhs, rhs);
            }
            _ => return None,
        }

        self.instructions.push(*instruction);
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::symbolic::ssa::BlockLifter;

    #[test]
    fn lift_moves() -> Result<(), Box<dyn std::error::Error>> {
        use iced_x86::code_asm::*;

        let mut asm = CodeAssembler::new(64)?;
        asm.mov(rdx, rax)?;
        asm.mov(rdx, rbx)?;
        asm.mov(qword_ptr(rsp - 8), rdx)?;
        asm.lea(rsp, qword_ptr(rsp - 8))?;

        let mut lifter = BlockLifter::default();
        for instruction in asm.instructions() {
            lifter.lift_instruction(instruction);
        }

        println!("{:#x?}", lifter);

        Ok(())
    }

    #[test]
    fn lift_arxan_cmov() -> Result<(), Box<dyn std::error::Error>> {
        use iced_x86::code_asm::*;

        let mut asm = CodeAssembler::new(64)?;
        asm.sub(rsp, 8)?;
        asm.push(rdx)?;
        asm.push(rcx)?;
        asm.mov(rcx, 0x1000u64)?;
        asm.mov(rdx, 0x2000u64)?;
        asm.cmove(rcx, rdx)?;
        asm.mov(qword_ptr(rsp + 0x10), rcx)?;
        asm.pop(rcx)?;
        asm.pop(rdx)?;
        asm.ret()?;

        let mut lifter = BlockLifter::default();
        for instruction in asm.instructions() {
            lifter.lift_instruction(instruction).unwrap();
        }

        println!("{:#x?}", lifter);

        Ok(())
    }
}
