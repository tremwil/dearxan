use crate::analysis::ssa::{
    intrusive_ilist::IndexNode,
    ir::{IrOp, IrVar, LocalVarRef},
    lifter::{LiftedBlock, PropagatedValue},
    stack_vec::StackVec,
};

#[derive(Debug, Clone, Default)]
pub struct BlockOptimizerState {
    dead_stack: Vec<usize>,
}

#[derive(Debug)]
pub struct BlockOptimizer<'a> {
    block: &'a mut LiftedBlock,
    dead_stack: &'a mut Vec<usize>,
    stack_diff: Option<i32>,
    can_clobber_free_stack: bool,
    last_pass_has_changes: bool,
}

impl<'a> BlockOptimizer<'a> {
    pub fn new(state: &'a mut BlockOptimizerState, block: &'a mut LiftedBlock) -> Self {
        state.dead_stack.clear();
        Self {
            stack_diff: block.stack_at_rsp(0).map(|s| s.offset),
            block,
            dead_stack: &mut state.dead_stack,
            can_clobber_free_stack: false,
            last_pass_has_changes: false,
        }
    }

    fn increment_refcounts<'b>(&mut self, vars: impl IntoIterator<Item = &'b IrVar>) {
        for var in vars {
            if let IrVar::Local(local) = var {
                self.block.ops[local.index()].refcount += 1;
            }
        }
    }

    fn decrement_refcounts<'b>(&mut self, vars: impl IntoIterator<Item = &'b IrVar>) {
        for i in vars.into_iter().filter_map(|v| v.local()).map(|v| v.index()) {
            self.block.ops[i].refcount -= 1;
            if self.is_dead(i) {
                self.dead_stack.push(i);
            }
        }
    }

    fn is_dead(&self, index: usize) -> bool {
        let op = &self.block.ops[index];
        if op.refcount != 0 || op.defined_var == LocalVarRef::INVALID {
            return false;
        }
        let defined_var = op.defined_var;
        let native_mapping = self.block.native_vars.var(defined_var.native());
        let latest = native_mapping.latest();

        if IrVar::Local(op.defined_var) != latest {
            return true;
        }

        let clobber_limit = self.can_clobber_free_stack.then_some(self.stack_diff).flatten();
        return native_mapping
            .native_var
            .stack()
            .and_then(|s| clobber_limit.map(|d| s < d))
            .unwrap_or(false);
    }

    pub fn replace_imm_op(&mut self, index: usize, new_op: IrOp) {
        let op_info = &mut self.block.ops[index];

        op_info.op = new_op;
        op_info.value = PropagatedValue::None;
        self.block.native_ops[op_info.native_op_index].modified = true;
        self.last_pass_has_changes = true;

        let old_used_vars = op_info.used_vars.copy();
        op_info.used_vars.clear();

        if new_op == IrOp::Nop {
            let defined_var = op_info.defined_var;
            op_info.defined_var = LocalVarRef::INVALID;
            let mut node = self.block.ops.node_mut(index);
            self.block.native_vars.var_mut(defined_var.native()).def_list.remove(&mut node);
        }
        self.decrement_refcounts(old_used_vars.iter());
    }

    fn try_replace_op_src(&mut self, index: usize, new_op: IrOp, new_src: IrVar) {
        // get buffer of used vars for old instruction
        let op_info = &self.block.ops[index];
        let current_used_vars = op_info.used_vars.copy();

        // Check if the next source assignment is beyong the block
        let next_source_idx = match new_src {
            IrVar::Native(n) => {
                let defs = &self.block.native_vars.var(n).def_list;
                defs.head_index()
            }
            IrVar::Local(l) => self.block.ops.node(l.index()).next_index(),
        };
        if next_source_idx.is_some_and(|i| i.index() > index) {
            return;
        }

        if let IrVar::Local(l) = new_src {
            self.block.ops[l.index()].refcount += 1;
        }
        self.decrement_refcounts(current_used_vars.iter());

        let op_info = &mut self.block.ops[index];
        op_info.op = new_op;
        op_info.value = PropagatedValue::None;
        op_info.used_vars = StackVec::from_elem(new_src);
        self.block.native_ops[op_info.native_op_index].modified = true;
        self.last_pass_has_changes = true;
    }

    pub fn nop_dead_ops(&mut self, index: usize) {
        if self.is_dead(index) {
            self.dead_stack.push(index);
        }
        while let Some(i) = self.dead_stack.pop() {
            self.replace_imm_op(i, IrOp::Nop);
        }
    }

    fn propagate_values(&mut self, index: usize) {
        let op_info = &self.block.ops[index];
        match op_info.op {
            IrOp::Jmp(_) => match op_info.value {
                PropagatedValue::Constant(c) => self.replace_imm_op(index, IrOp::JmpImm(c)),
                PropagatedValue::PhonyConstant(phony) => {
                    self.can_clobber_free_stack = true;
                    self.replace_imm_op(index, IrOp::Jcc(phony));
                }
                _ => (),
            },
            IrOp::Mov { dst, .. } | IrOp::Lea { dst, .. } => match op_info.value {
                PropagatedValue::Constant(imm) => {
                    self.replace_imm_op(index, IrOp::MovImm { dst, imm })
                }
                PropagatedValue::VarOffset(var, offset) => {
                    self.try_replace_op_src(
                        index,
                        IrOp::Lea {
                            dst,
                            base: var,
                            offset,
                        },
                        var,
                    );
                }
                _ => (),
            },
            _ => (),
        };
    }

    pub fn bidirectional_pass(&mut self) -> bool {
        self.last_pass_has_changes = false;
        let indices = 0..self.block.ops.len();
        for i in indices.clone().rev().chain(indices) {
            self.propagate_values(i);
            self.nop_dead_ops(i);
        }
        self.last_pass_has_changes
    }

    pub fn optimize(&mut self) {
        while self.bidirectional_pass() {}
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::ssa::{
        lifter::LiftedBlock,
        optimizer::{BlockOptimizer, BlockOptimizerState},
        test::samples,
    };

    #[test]
    fn optimize_arxan_call() -> Result<(), Box<dyn std::error::Error>> {
        let mut block = LiftedBlock::default();
        for instruction in samples::arxan_call() {
            block.lift_instruction(&instruction).unwrap();
        }

        let mut opt_state = BlockOptimizerState::default();
        let mut opt = BlockOptimizer::new(&mut opt_state, &mut block);
        opt.bidirectional_pass();

        for ir in &block.ops {
            println!("{}", ir.op);
        }

        Ok(())
    }

    #[test]
    fn optimize_arxan_cmov() -> Result<(), Box<dyn std::error::Error>> {
        let mut block = LiftedBlock::default();
        for instruction in samples::arxan_cmov() {
            block.lift_instruction(&instruction).unwrap();
        }

        let mut opt_state = BlockOptimizerState::default();
        let mut opt = BlockOptimizer::new(&mut opt_state, &mut block);
        opt.bidirectional_pass();

        for ir in &block.ops {
            println!("{}", ir.op);
        }

        Ok(())
    }
}
