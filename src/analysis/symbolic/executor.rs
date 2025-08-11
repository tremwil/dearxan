use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::analysis::{
    ImageView,
    symbolic::{
        expr::{Expr, ExprHeap},
        memory::Memory,
        registers::Registers,
    },
    vm,
};

#[derive(Debug, Clone, Default)]
pub struct SymbolicState<I: ImageView> {
    pub registers: Registers,
    pub memory: Memory<I>,
}

impl<I: ImageView> SymbolicState<I> {
    pub fn new(image: I) -> Self {
        Self {
            registers: Default::default(),
            memory: Memory::new(image),
        }
    }
}

struct StateExecutor<'a, I: ImageView> {
    state: SymbolicState<I>,
    heap: &'a mut ExprHeap,
}

impl<I: ImageView> StateExecutor<'_, I> {
    fn virtual_address(&mut self, instruction: &Instruction) -> Expr {
        if instruction.memory_base() == Register::RIP {
            return Expr::Constant(instruction.memory_displacement64());
        }

        let base_reg = instruction.memory_base();
        if !base_reg.is_gpr64() {
            return Expr::Unknown;
        }
        let base_value = *self.state.registers.gpr64(base_reg);

        let index_reg = instruction.memory_index();
        if index_reg == Register::None {
            self.heap.linear([(base_value, 1)], instruction.memory_displacement64())
        }
        else if index_reg.is_gpr64() {
            let index_value = *self.state.registers.gpr64(index_reg);
            let terms = [
                (base_value, 1),
                (index_value, instruction.memory_index_scale() as u64),
            ];
            self.heap.linear(terms, instruction.memory_displacement64())
        }
        else {
            Expr::Unknown
        }
    }

    fn get_operand_value(&mut self, instruction: &Instruction, op: u32) -> Expr {
        match instruction.op_kind(op) {
            OpKind::Register => {
                let reg = instruction.op_register(op);
                if reg.is_gpr64() { *self.state.registers.gpr64(reg) } else { Expr::Unknown }
            }
            OpKind::Memory => {
                if instruction.memory_size().size() != 8 {
                    return Expr::Unknown;
                }
                let va = self.virtual_address(instruction);
                self.state.memory.read_u64(&va, &mut self.heap)
            }
            _ => instruction
                .try_immediate(op)
                .map(|imm| Expr::Constant(imm))
                .unwrap_or(Expr::Unknown),
        }
    }

    fn set_operand_value(&mut self, instruction: &Instruction, op: u32, value: Expr) {
        match instruction.op_kind(op) {
            OpKind::Register => {
                let full_reg = instruction.op_register(op).full_register();
                if full_reg.is_gpr() {
                    *self.state.registers.gpr64_mut(full_reg) = value;
                }
            }
            OpKind::Memory => {
                if instruction.memory_size().size() == 8 {
                    let va = self.virtual_address(instruction);
                    self.state.memory.write_u64(&va, value, &mut self.heap);
                }
            }
            _ => (),
        }
    }

    fn adjust_rsp(&mut self, instruction: &Instruction) -> Expr {
        let rsp = self.state.registers.rsp_mut();
        *rsp = self.heap.linear(
            [(*rsp, 1)],
            (instruction.stack_pointer_increment() as i64).cast_unsigned(),
        );
        *rsp
    }

    fn execute(&mut self, instruction: &Instruction) -> bool {
        match instruction.mnemonic() {
            Mnemonic::Mov => {
                let moved_val = self.get_operand_value(instruction, 1);
                self.set_operand_value(instruction, 0, moved_val);
            }
            Mnemonic::Xchg => {
                let v1 = self.get_operand_value(instruction, 0);
                let v2 = self.get_operand_value(instruction, 1);

                match (instruction.op0_kind(), instruction.op1_kind()) {
                    (OpKind::Memory, _) => {
                        let va = self.virtual_address(instruction);
                        self.set_operand_value(instruction, 1, v1);
                        self.state.memory.write_u64(&va, v2, &mut self.heap);
                    }
                    (_, OpKind::Memory) => {
                        let va = self.virtual_address(instruction);
                        self.set_operand_value(instruction, 1, v2);
                        self.state.memory.write_u64(&va, v1, &mut self.heap);
                    }
                    _ => {
                        self.set_operand_value(instruction, 0, v2);
                        self.set_operand_value(instruction, 1, v1);
                    }
                };
            }
            Mnemonic::Lea => {
                let va = self.virtual_address(instruction);
                self.set_operand_value(instruction, 0, va);
            }
            Mnemonic::Add => {
                let a = self.get_operand_value(instruction, 0);
                let b = self.get_operand_value(instruction, 1);
                let sum = self.heap.linear([(a, 1), (b, 1)], 0);
                self.set_operand_value(instruction, 0, sum);
            }
            Mnemonic::Sub => {
                let a = self.get_operand_value(instruction, 0);
                let b = self.get_operand_value(instruction, 1);
                let sum = self.heap.linear([(a, 1), (b, (-1i64).cast_unsigned())], 0);
                self.set_operand_value(instruction, 0, sum);
            }
            Mnemonic::Push => {
                let push_val = self.get_operand_value(instruction, 0);
                let new_rsp = self.adjust_rsp(instruction);
                self.state.memory.write_u64(&new_rsp, push_val, &mut self.heap);
            }
            Mnemonic::Pop => {
                let pop_val =
                    self.state.memory.read_u64(self.state.registers.rsp(), &mut self.heap);
                self.adjust_rsp(instruction);
                self.set_operand_value(instruction, 0, pop_val);
            }
            Mnemonic::Call => {
                let call_target = self.get_operand_value(instruction, 0);
                let return_rip = Expr::Constant(instruction.next_ip());
                let new_rsp = self.adjust_rsp(instruction);
                self.state.memory.write_u64(&new_rsp, return_rip, &mut self.heap);
                *self.state.registers.rip_mut() = Some(call_target);
            }
            Mnemonic::Ret => {
                let return_rip =
                    self.state.memory.read_u64(self.state.registers.rsp(), &mut self.heap);
                self.adjust_rsp(instruction);
                *self.state.registers.rip_mut() = Some(return_rip);
            }
            Mnemonic::Jmp => {
                let jmp_target = self.get_operand_value(instruction, 0);
                *self.state.registers.rip_mut() = Some(jmp_target);
            }
            _ if instruction.is_jcc_short_or_near() => {
                let if_true = self.get_operand_value(instruction, 0);
                let if_false = Expr::Constant(instruction.next_ip());
                let ternary = self.heap.ternary(instruction.condition_code(), if_true, if_false);
                *self.state.registers.rip_mut() = Some(ternary);
            }
            m if vm::util::is_cmov(m) => {
                let if_true = self.get_operand_value(instruction, 1);
                let if_false = self.get_operand_value(instruction, 0);
                let ternary = self.heap.ternary(instruction.condition_code(), if_true, if_false);
                self.set_operand_value(instruction, 0, ternary);
            }
            _ => return false,
        }
        true
    }
}
