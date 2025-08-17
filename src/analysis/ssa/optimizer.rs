use iced_x86::code_asm::cl;

use crate::analysis::ssa::{
    ir::{IrInstruction, IrVariable, MovOps, StackRef, UsedVars},
    lifter::LiftedBlock,
    state::{DefList, PropagatedValue, VarDef},
};

pub struct BlockOptimizer<'a> {
    block: &'a mut LiftedBlock,
    stack_diff: Option<i32>,
    can_clobber_free_stack: bool,
    dead_index_stack: Vec<usize>,
}

impl<'a> BlockOptimizer<'a> {
    pub fn new(block: &'a mut LiftedBlock) -> Self {
        Self {
            stack_diff: block.defs.registers.stack_at_rsp(0).map(|s| s.offset),
            block,
            can_clobber_free_stack: false,
            dead_index_stack: Vec::new(),
        }
    }

    /// Set the lifted block to be optimized, restting the optimizer state.
    pub fn set_block(&mut self, block: &'a mut LiftedBlock) {
        self.can_clobber_free_stack = false;
        self.dead_index_stack.clear();
        self.stack_diff = block.defs.registers.stack_at_rsp(0).map(|s| s.offset);
        self.block = block;
    }

    fn stack_clobber_limit(&self) -> Option<i32> {
        self.can_clobber_free_stack.then_some(self.stack_diff).flatten()
    }

    fn is_dead(defs: &DefList, var: IrVariable, stack_clobber_limit: Option<i32>) -> bool {
        let Some(def) = defs.get(var.tag())
        else {
            return true;
        };
        if def.refcount() != 0 {
            return false;
        }
        else if var.tag() != defs.latest_tag() {
            return true;
        }
        var.stack()
            .and_then(|s| stack_clobber_limit.map(|d| s.offset < d))
            .unwrap_or(false)
    }

    fn decrement_refcount(&mut self, var: IrVariable) {
        let clobber_limit = self.stack_clobber_limit();
        let defs = self.block.defs.defs_of_mut(var);
        let Some(def) = defs.get_mut(var.tag())
        else {
            return;
        };
        def.decrement_refcount();
        if Self::is_dead(defs, var, clobber_limit) {
            let dead_index = defs.pop_def(var.tag()).ir_index;
            self.dead_index_stack.push(dead_index);
        }
    }

    fn replace_ir(&mut self, index: usize, new: IrInstruction) {
        // increment refcounts for the new instruction
        for var in new.used_vars() {
            if let Some(def) = self.block.defs.def_of_mut(var) {
                def.increment_refcount();
            }
        }
        // decrement refcounts of used vars in old instruction
        let replaced = self.block.lifted_instructions[index];
        for var in replaced.used_vars() {
            self.decrement_refcount(var);
        }
        // replace instruction
        self.block.lifted_instructions[index] = new;
        self.block.lifted_to_native[index] = None;
    }

    fn try_replace_ir(&mut self, index: usize, new: IrInstruction) {
        // get buffer of used vars for old instruction
        let replaced = self.block.lifted_instructions[index];
        let replaced_used_vars = replaced.used_vars_buf();

        // temporarily decrement (but don't mark dead!) old vars
        for &var in replaced_used_vars.iter() {
            if let Some(def) = self.block.defs.def_of_mut(var) {
                def.decrement_refcount();
            }
        }

        // get buffer of used vars for new instruction
        let new_used_vars = new.used_vars_buf();
    }

    pub fn dead_code_pass(&mut self) {
        while let Some(index) = self.dead_index_stack.pop() {
            self.replace_ir(index, IrInstruction::Nop);
        }
    }

    pub fn propagate_copies(&mut self, ir_index: usize) {
        let instr = &self.block.lifted_instructions[ir_index];
        match instr {
            IrInstruction::Jmp(target) => match self.block.defs.propagated_value(*target) {
                PropagatedValue::Constant(c) => self.replace_ir(ir_index, IrInstruction::JmpImm(c)),
                PropagatedValue::PhonyConstant {
                    cond,
                    if_true,
                    if_false,
                } => {
                    self.can_clobber_free_stack = true;
                    self.replace_ir(
                        ir_index,
                        IrInstruction::Jcc {
                            cond,
                            if_true,
                            if_false,
                        },
                    );
                }
                _ => (),
            },
            // IrInstruction::Mov(ops) => match ops {
            //     MovOps::Register { dst, src } => match self.block.defs.propagated_value(*src) {
            //         PropagatedValue::Constant(c) => self.replace_ir(index, IrIns),
            //     },
            // },
            _ => (),
        }
        self.dead_code_pass();
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ssa::{lifter::LiftedBlock, optimizer::BlockOptimizer, test::samples};

    #[test]
    fn optimize_arxan_call() -> Result<(), Box<dyn std::error::Error>> {
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
    fn optimize_arxan_cmov() -> Result<(), Box<dyn std::error::Error>> {
        let mut block = LiftedBlock::default();
        for instruction in samples::arxan_cmov() {
            block.lift_instruction(&instruction).unwrap();
        }

        //let mut opt = BlockOptimizer::new(&mut block);
        //opt.propagate_copies(opt.block.len() - 1);

        for ir in &block.lifted_instructions {
            println!("{}", ir);
        }

        Ok(())
    }
}
