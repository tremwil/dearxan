use fxhash::FxHashMap;
use iced_x86::{ConditionCode, Instruction, Mnemonic, OpKind, Register};

use crate::analysis::{
    ImageView,
    symbolic::{executor::SymbolicState, registers::Registers},
    util, vm,
};

mod ssa;

mod executor;
mod expr;
mod memory;
mod registers;

use expr::{BoxedExpr, Expr, ExprHeap, ExprId};
use memory::Memory;

pub struct BlockOptimizer<'a, I: ImageView> {
    heap: &'a mut ExprHeap,
    block: Vec<Instruction>,
    states: Vec<SymbolicState<I>>,
}

impl<'a, I: ImageView> BlockOptimizer<'a, I> {
    fn push_repr(&mut self, past: usize, current: usize) -> Option<Instruction> {
        let past = &self.states[past];
        let current = &self.states[current];

        let rsp_plus_8 = self.heap.linear([(*current.registers.rsp(), 1)], 8);

        // if !past
        //     .registers
        //     .gprs_equal_except(&current.registers, [(Register::RSP, rsp_plus_8)])
        // {
        //     return false;
        // }

        todo!();
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::{
        WithBase,
        symbolic::{executor::SymbolicState, expr::ExprHeap},
    };

    #[test]
    fn arxan_cmov() -> Result<(), Box<dyn std::error::Error>> {
        use iced_x86::code_asm::*;

        let mut asm = CodeAssembler::new(64)?;
        asm.sub(rsp, 8)?;
        asm.push(rdx)?;
        asm.push(rcx)?;
        asm.mov(rcx, 0x1000u64)?;
        asm.mov(rdx, 0x2000u64)?;
        asm.cmove(rcx, rdx)?;
        asm.mov(rsp + 0x10, rcx)?;
        asm.pop(rcx)?;
        asm.pop(rdx)?;
        asm.ret()?;

        let image = WithBase::new([], 0);
        let mut sym = SymbolicState::new(image);
        let heap = ExprHeap::new();

        for instruction in asm.instructions() {
            //sym.execute(instruction);
        }

        println!("{sym:#x?}");
        Ok(())
    }

    #[test]
    fn arxan_call() -> Result<(), Box<dyn std::error::Error>> {
        use iced_x86::code_asm::*;

        let mut asm = CodeAssembler::new(64)?;
        asm.lea(rsp, qword_ptr(rsp - 8))?;
        asm.mov(qword_ptr(rsp), rbp)?;
        asm.mov(rbp, 0x10000u64)?;
        asm.xchg(qword_ptr(rsp), rbp)?;

        asm.push(rbp)?;
        asm.mov(rbp, 0x20000u64)?;
        asm.xchg(qword_ptr(rsp), rbp)?;
        asm.ret()?;

        let image = WithBase::new([], 0);
        let mut sym = SymbolicState::new(image);
        for instruction in asm.instructions() {
            //sym.execute(instruction);
        }

        println!("{sym:#x?}");
        Ok(())
    }

    #[test]
    fn mem_identity() -> Result<(), Box<dyn std::error::Error>> {
        use iced_x86::code_asm::*;

        let mut asm = CodeAssembler::new(64)?;
        asm.mov(rdx, qword_ptr(rcx))?;
        asm.mov(qword_ptr(rcx), rdx)?;

        let image = WithBase::new([], 0);
        let mut sym = SymbolicState::new(image);
        for instruction in asm.instructions() {
            //sym.execute(instruction);
        }

        println!("{sym:#x?}");
        Ok(())
    }
}

// 1 mov rax, rbx
//   rax(1) = rbx(0)
//
// 2 add rax, rbx
//   rax(2) = rax(1) + rbx(0), rbx(2) = rbx(0)
//
// 3
//
// 4
