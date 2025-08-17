use fxhash::FxHashMap;

use crate::analysis::ssa::stack_vec::StackVec;

/// Reference to a SSA variable defined in a basic block.
///
/// This is the same as the index of the IR instruction that defines the variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocalVarRef(u32);

impl LocalVarRef {
    /// Create a [`LocalVarRef`] from an index.
    pub fn new(index: usize) -> Self {
        Self(index.try_into().unwrap())
    }

    /// Get the index of the IR instruction that defined this variable.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Reference to a native variable (x86 register/stack location).
///
/// The associated [`NativeVarInfo`] can be retrieved via [`NativeVars::var`] and
/// [`NativeVars::var_mut`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeVarRef(u32);

impl NativeVarRef {
    fn new(index: usize) -> Self {
        Self(index.try_into().unwrap())
    }

    /// Get the index of the IR instruction that defined this variable.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// An IR variable referenced by an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrVar {
    /// Reference to a native x86 variable (register/stack) before it was locally assigned.
    Native(NativeVarRef),
    /// Reference to an SSA variable assigned in the basic block.
    Local(LocalVarRef),
}

/// An x86 native variable, i.e. registers/stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeVar {
    /// A 64-bit general-purpose register.
    Register(iced_x86::Register),
    /// A 64-bit stack location, represented as an offset to the original RSP value.
    Stack(i32),
}

/// A "constant" which takes one of two possible values depending on a condition.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PhonyConstant {
    /// The x86 condition code to check for.
    pub cond: iced_x86::ConditionCode,
    /// Value if the condition is true.
    pub if_true: u64,
    /// Value if the condition is false.
    pub if_false: u64,
}

/// An IR operation (instruction).
///
/// This doesn't store all the required information to represent the instruction; for that see
/// [`IrOpInfo`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IrOp {
    /// Do nothing.
    Nop,
    /// Define a new local variable with a constant value.
    MovImm { dst: LocalVarRef, imm: u64 },
    /// Define a new local variable by copying the value of another variable.
    Mov { dst: LocalVarRef, src: IrVar },
    /// Conditionally define a new local variable.
    CMov {
        cond: iced_x86::ConditionCode,
        dst: LocalVarRef,
        src: IrVar,
    },
    /// x86 LEA, but unable to encode an SIB operation.
    Lea {
        dst: LocalVarRef,
        base: IrVar,
        offset: i32,
    },
    /// Unconditional jump to a constant address.
    JmpImm(u64),
    /// Unconditional jump to code pointed to by a variable.
    Jmp(IrVar),
    /// Conditional jump to either of two constant addresses.
    Jcc(PhonyConstant),
}

/// A value propagated through value/copy propagation.
#[derive(Debug, Clone, Copy)]
pub enum PropagatedValue {
    /// Unknown propagated value.
    None,
    /// Known constant.
    Constant(u64),
    /// "Constant" which may take different values depending on a condition.
    PhonyConstant(PhonyConstant),
    /// 32-bit offset from another variable.
    VarOffset(IrVar, i32),
}

#[derive(Debug, Clone)]
pub struct NativeOpInfo {
    ir_op_index: usize,
    modified: bool,
    instruction: iced_x86::Instruction,
}

#[derive(Debug, Clone)]
pub struct IrOpInfo {
    op: IrOp,
    native_op_index: usize,
    defined_native_var: Option<NativeVarRef>,
    refcount: usize,
    used_vars: StackVec<IrVar, 3>,
    value: PropagatedValue,
}

#[derive(Debug, Clone)]
pub struct NativeVarInfo {
    native_var: NativeVar,
    last_def: Option<LocalVarRef>,
    defs: Vec<LocalVarRef>,
}

impl NativeVarInfo {
    pub fn new(var: NativeVar) -> Self {
        Self {
            native_var: var,
            last_def: None,
            defs: Vec::with_capacity(8),
        }
    }
}

/// Maps a [`NativeVar`] to a [`NativeVarInfo`] structure.
#[derive(Debug, Clone)]
pub struct NativeVars {
    vars: Vec<NativeVarInfo>,
    active_var_count: usize,
    stack_map: FxHashMap<i32, NativeVarRef>,
}

impl Default for NativeVars {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeVars {
    const GPR64_COUNT: usize = 16;

    pub fn new() -> Self {
        Self {
            vars: (0..Self::GPR64_COUNT as u32)
                .map(|i| NativeVarInfo::new(NativeVar::Register(iced_x86::Register::RAX + i)))
                .collect(),
            active_var_count: Self::GPR64_COUNT,
            stack_map: Default::default(),
        }
    }

    pub fn clear(&mut self) {
        for i in 0..self.active_var_count {
            self.vars[i].defs.clear();
            self.vars[i].last_def = None;
        }
        self.active_var_count = Self::GPR64_COUNT
    }

    pub fn var(&self, reference: NativeVarRef) -> &NativeVarInfo {
        &self.vars[reference.index()]
    }

    pub fn var_mut(&mut self, reference: NativeVarRef) -> &mut NativeVarInfo {
        &mut self.vars[reference.index()]
    }

    pub fn register_ref(&self, reg: iced_x86::Register) -> NativeVarRef {
        assert!(reg.is_gpr64());
        NativeVarRef(reg as u32 - iced_x86::Register::RAX as u32)
    }

    pub fn register(&self, reg: iced_x86::Register) -> &NativeVarInfo {
        self.var(self.register_ref(reg))
    }

    pub fn register_mut(&mut self, reg: iced_x86::Register) -> &mut NativeVarInfo {
        self.var_mut(self.register_ref(reg))
    }

    pub fn stack_ref(&self, offset: i32) -> Option<NativeVarRef> {
        self.stack_map.get(&offset).copied()
    }

    pub fn stack(&self, offset: i32) -> Option<&NativeVarInfo> {
        self.stack_ref(offset).map(|r| self.var(r))
    }

    pub fn stack_mut(&mut self, offset: i32) -> &mut NativeVarInfo {
        let var_ref = *self.stack_map.entry(offset).or_insert_with(|| {
            let native = NativeVar::Stack(offset);
            if self.active_var_count == self.vars.len() {
                self.vars.push(NativeVarInfo::new(native));
            }
            else {
                self.vars[self.active_var_count].native_var = native;
            }
            let new_ref = NativeVarRef::new(self.active_var_count);
            self.active_var_count += 1;
            new_ref
        });
        self.var_mut(var_ref)
    }

    pub fn native_ref(&self, native: NativeVar) -> Option<NativeVarRef> {
        match native {
            NativeVar::Register(r) => Some(self.register_ref(r)),
            NativeVar::Stack(s) => self.stack_ref(s),
        }
    }

    pub fn native(&self, native: NativeVar) -> Option<&NativeVarInfo> {
        self.native_ref(native).map(|r| self.var(r))
    }

    pub fn native_mut(&mut self, native: NativeVar) -> &mut NativeVarInfo {
        match native {
            NativeVar::Register(r) => self.register_mut(r),
            NativeVar::Stack(s) => self.stack_mut(s),
        }
    }
}

pub struct LiftedBlock {
    ops: Vec<IrOpInfo>,
    native_ops: NativeOpInfo,
    native_vars: NativeVars,
}
