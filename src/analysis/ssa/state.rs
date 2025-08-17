use fxhash::FxHashMap;
use iced_x86::{ConditionCode, Register};
use smallvec::SmallVec;

use crate::analysis::ssa::ir::{
    self, AssignmentTag, IrInstruction, IrRegister, IrStackRef, IrVariable, MemExpr, StackRef,
};

/// Value propagated through constant/copy propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagatedValue {
    None,
    /// Constant 64-bit integer.
    Constant(u64),
    /// Two possible 64-bit constants depending on the value of a condition
    PhonyConstant {
        cond: iced_x86::ConditionCode,
        if_true: u64,
        if_false: u64,
    },
    /// Signed 32-bit offset to the value of a register.
    RegOffset(IrRegister, i32),
}

impl PropagatedValue {
    pub fn phony(cond: iced_x86::ConditionCode, if_true: Self, if_false: Self) -> Self {
        match (if_true, if_false) {
            (t, f) if t == f => t,
            (PropagatedValue::Constant(t), PropagatedValue::Constant(f)) => {
                PropagatedValue::PhonyConstant {
                    cond,
                    if_true: t,
                    if_false: f,
                }
            }
            _ => PropagatedValue::None,
        }
    }

    /// Add this [`PropagatedValue`] with the given 32-bit signed immediate value.
    pub fn add(self, imm: i32) -> Self {
        let imm_64 = (imm as i64).cast_unsigned();
        match self {
            Self::None => Self::None,
            Self::Constant(c) => Self::Constant(c.wrapping_add(imm_64)),
            Self::RegOffset(r, c) => Self::RegOffset(r, c.wrapping_add(imm)),
            Self::PhonyConstant {
                cond,
                if_true,
                if_false,
            } => Self::PhonyConstant {
                cond,
                if_true: if_true.wrapping_add(imm_64),
                if_false: if_false.wrapping_add(imm_64),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct VarDef {
    refcount: usize,
    pub ir_index: usize,
    pub value: PropagatedValue,
}

impl VarDef {
    pub fn refcount(&self) -> usize {
        self.refcount
    }

    pub fn increment_refcount(&mut self) -> usize {
        self.refcount += 1;
        self.refcount
    }

    pub fn decrement_refcount(&mut self) -> usize {
        self.refcount = self.refcount.checked_sub(1).unwrap();
        self.refcount
    }
}

#[derive(Default, Debug, Clone)]
pub struct DefList {
    var_defs: SmallVec<[VarDef; 4]>,
    latest_tag: AssignmentTag,
}

impl DefList {
    pub fn clear(&mut self) {
        self.var_defs.clear();
    }

    pub fn latest_tag(&self) -> AssignmentTag {
        self.latest_tag
    }

    pub fn push_def(&mut self, ir_index: usize, value: PropagatedValue) -> AssignmentTag {
        self.latest_tag = AssignmentTag::from_index(self.var_defs.len());
        self.var_defs.push(VarDef {
            refcount: 0,
            ir_index,
            value,
        });
        self.latest_tag
    }

    pub fn pop_def(&mut self, tag: AssignmentTag) -> &VarDef {
        let index = tag.as_index().unwrap();
        let def = &self.var_defs[index];
        debug_assert_eq!(def.refcount, 0);

        if self.latest_tag == tag {
            let latest_index = self.var_defs[..index]
                .iter()
                .enumerate()
                .rev()
                .find(|(_, d)| d.refcount != 0)
                .map(|(i, _)| i);

            self.latest_tag = AssignmentTag::from_index_opt(latest_index);
        }

        def
    }

    pub fn get(&self, tag: AssignmentTag) -> Option<&VarDef> {
        tag.as_index().and_then(|i| self.var_defs.get(i))
    }

    pub fn get_mut(&mut self, tag: AssignmentTag) -> Option<&mut VarDef> {
        tag.as_index().and_then(|i| self.var_defs.get_mut(i))
    }
}

#[derive(Default, Clone)]
pub struct RegisterDefs {
    defs: Box<[DefList; Self::GPR64_COUNT]>,
}

impl std::fmt::Debug for RegisterDefs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Registers");
        for (i, defs) in self.defs.iter().enumerate() {
            if defs.var_defs.is_empty() {
                continue;
            }
            let reg: Register = (Register::RAX as usize + i).try_into().unwrap();
            s.field(&format!("{:?}", reg), defs);
        }
        s.finish()
    }
}

impl RegisterDefs {
    const GPR64_COUNT: usize = Register::R15 as usize - Register::RAX as usize + 1;

    pub fn clear(&mut self) {
        self.defs.iter_mut().for_each(|d| d.clear());
    }

    pub fn defs_of(&self, reg: Register) -> &DefList {
        assert!(reg.is_gpr64());
        &self.defs[reg as usize - Register::RAX as usize]
    }

    pub fn defs_of_mut(&mut self, reg: Register) -> &mut DefList {
        assert!(reg.is_gpr64());
        &mut self.defs[reg as usize - Register::RAX as usize]
    }

    pub fn def_of(&self, reg: IrRegister) -> Option<&VarDef> {
        reg.tag.as_index().map(|i| &self.defs_of(reg.id).var_defs[i])
    }

    pub fn def_of_mut(&mut self, reg: IrRegister) -> Option<&mut VarDef> {
        reg.tag.as_index().map(|i| &mut self.defs_of_mut(reg.id).var_defs[i])
    }

    pub fn current(&self, reg: Register) -> IrRegister {
        IrRegister::new(reg, self.defs_of(reg).latest_tag)
    }

    pub fn propagated_value(&self, reg: IrRegister) -> PropagatedValue {
        self.def_of(reg).map_or(PropagatedValue::RegOffset(reg, 0), |d| d.value)
    }

    pub fn push_def(
        &mut self,
        reg: Register,
        ir_index: usize,
        value: PropagatedValue,
    ) -> IrRegister {
        IrRegister::new(reg, self.defs_of_mut(reg).push_def(ir_index, value))
    }

    pub fn stack_at(&self, reg: IrRegister, offset: i32) -> Option<StackRef> {
        let address = self.propagated_value(reg).add(offset);
        if let PropagatedValue::RegOffset(src_reg, offset) = address
            && src_reg == Register::RSP.into()
        {
            Some(StackRef {
                source: reg,
                offset,
            })
        }
        else {
            None
        }
    }

    pub fn stack_at_rsp(&self, offset: i32) -> Option<StackRef> {
        self.stack_at(self.current(Register::RSP), offset)
    }

    pub fn iter(&self) -> impl Iterator<Item = (Register, &DefList)> {
        self.defs.iter().enumerate().map(|(i, g)| (Register::RAX + i as u32, g))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (Register, &mut DefList)> {
        self.defs.iter_mut().enumerate().map(|(i, g)| (Register::RAX + i as u32, g))
    }
}

#[derive(Default, Debug, Clone)]
pub struct StackDefs {
    defs: FxHashMap<i32, DefList>,
}

impl StackDefs {
    pub fn clear(&mut self) {
        self.defs.values_mut().for_each(|d| d.clear());
    }

    pub fn defs_of(&self, stack_offset: i32) -> Option<&DefList> {
        self.defs.get(&stack_offset)
    }

    pub fn defs_of_mut(&mut self, stack_offset: i32) -> &mut DefList {
        self.defs.entry(stack_offset).or_default()
    }

    pub fn def_of(&self, stack_ref: IrStackRef) -> Option<&VarDef> {
        stack_ref
            .tag
            .as_index()
            .and_then(|i| self.defs_of(stack_ref.offset).map(|defs| &defs.var_defs[i]))
    }

    pub fn def_of_mut(&mut self, stack_ref: IrStackRef) -> Option<&mut VarDef> {
        stack_ref
            .tag
            .as_index()
            .map(|i| &mut self.defs_of_mut(stack_ref.offset).var_defs[i])
    }

    pub fn current(&self, stack_ref: StackRef) -> IrStackRef {
        let tag = self.defs_of(stack_ref.offset).map_or(AssignmentTag::NONE, |d| d.latest_tag());
        IrStackRef::new(stack_ref, tag)
    }

    pub fn propagated_value(&self, stack_ref: IrStackRef) -> PropagatedValue {
        self.def_of(stack_ref).map_or(PropagatedValue::None, |d| d.value)
    }

    pub fn push_def(
        &mut self,
        stack_ref: StackRef,
        ir_index: usize,
        value: PropagatedValue,
    ) -> IrStackRef {
        let tag = self.defs_of_mut(stack_ref.offset).push_def(ir_index, value);
        IrStackRef::new(stack_ref, tag)
    }

    pub fn iter(&self) -> impl Iterator<Item = (i32, &DefList)> {
        self.defs.iter().map(|(k, v)| (*k, v))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (i32, &mut DefList)> {
        self.defs.iter_mut().map(|(k, v)| (*k, v))
    }
}

#[derive(Default, Debug, Clone)]
pub struct BlockDefs {
    pub registers: RegisterDefs,
    pub stack: StackDefs,
}

impl BlockDefs {
    pub fn clear(&mut self) {
        self.registers.clear();
        self.stack.clear();
    }

    pub fn def_of(&self, var: IrVariable) -> Option<&VarDef> {
        match var {
            IrVariable::Register(r) => self.registers.def_of(r),
            IrVariable::Stack(s) => self.stack.def_of(s),
        }
    }

    pub fn def_of_mut(&mut self, var: IrVariable) -> Option<&mut VarDef> {
        match var {
            IrVariable::Register(r) => self.registers.def_of_mut(r),
            IrVariable::Stack(s) => self.stack.def_of_mut(s),
        }
    }

    pub fn defs_of(&self, var: IrVariable) -> Option<&DefList> {
        match var {
            IrVariable::Register(r) => Some(self.registers.defs_of(r.id)),
            IrVariable::Stack(s) => self.stack.defs_of(s.offset),
        }
    }

    pub fn defs_of_mut(&mut self, var: IrVariable) -> &mut DefList {
        match var {
            IrVariable::Register(r) => self.registers.defs_of_mut(r.id),
            IrVariable::Stack(s) => self.stack.defs_of_mut(s.offset),
        }
    }

    pub fn propagated_value(&self, var: IrVariable) -> PropagatedValue {
        match var {
            IrVariable::Register(r) => self.registers.propagated_value(r),
            IrVariable::Stack(s) => self.stack.propagated_value(s),
        }
    }

    pub fn push_var(
        &mut self,
        var: IrVariable,
        ir_index: usize,
        value: PropagatedValue,
    ) -> IrVariable {
        match var {
            IrVariable::Register(r) => {
                IrVariable::Register(self.registers.push_def(r.id, ir_index, value))
            }
            IrVariable::Stack(s) => IrVariable::Stack(self.stack.push_def(s.id, ir_index, value)),
        }
    }

    pub fn mem_expr_value(&self, mem: MemExpr) -> PropagatedValue {
        match mem {
            MemExpr::Constant(c) => PropagatedValue::Constant(c),
            MemExpr::RegOffset(reg, offset) => self.registers.propagated_value(reg).add(offset),
        }
    }
}
