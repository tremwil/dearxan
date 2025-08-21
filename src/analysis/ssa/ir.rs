use crate::analysis::ssa::util::AsFmtSigned;

/// Reference to a SSA variable defined in a basic block.
///
/// This is the same as the index of the IR instruction that defines the variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(align(4))]
pub struct LocalVarRef {
    native: u16,
    index: u16,
}

impl LocalVarRef {
    pub const INVALID: Self = LocalVarRef {
        native: u16::MAX,
        index: u16::MAX,
    };

    /// Create a [`LocalVarRef`] from an index.
    pub fn new(index: usize, native: NativeVarRef) -> Self {
        debug_assert!((index as u64) < (u16::MAX as u64));
        Self {
            native: native.0,
            index: index as u16,
        }
    }

    /// Get the index of the IR instruction that defined this variable.
    pub fn index(self) -> usize {
        self.index as usize
    }

    pub fn native(self) -> NativeVarRef {
        NativeVarRef(self.native)
    }
}

/// Reference to a native variable (x86 register/stack location).
///
/// The associated [`NativeVarInfo`] can be retrieved via [`NativeVars::var`] and
/// [`NativeVars::var_mut`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(align(4))]
pub struct NativeVarRef(u16);

impl NativeVarRef {
    pub const INVALID: Self = NativeVarRef(u16::MAX);

    pub fn new(index: usize) -> Self {
        debug_assert!((index as u64) < (u16::MAX as u64));
        Self(index as u16)
    }

    /// Get the index of the IR instruction that defined this variable.
    pub fn index(self) -> usize {
        self.0 as usize
    }

    pub fn into_local(self, local_index: usize) -> LocalVarRef {
        LocalVarRef::new(local_index, self)
    }
}

/// An IR variable referenced by an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(align(8))]
pub enum IrVar {
    /// Reference to a native x86 variable (register/stack) before it was locally assigned.
    Native(NativeVarRef),
    /// Reference to an SSA variable assigned in the basic block.
    Local(LocalVarRef),
}

impl IrVar {
    pub fn native(self) -> NativeVarRef {
        match self {
            Self::Local(l) => l.native(),
            Self::Native(n) => n,
        }
    }

    pub fn local(self) -> Option<LocalVarRef> {
        match self {
            Self::Local(l) => Some(l),
            Self::Native(_) => None,
        }
    }
}

impl From<LocalVarRef> for IrVar {
    fn from(value: LocalVarRef) -> Self {
        Self::Local(value)
    }
}

impl From<NativeVarRef> for IrVar {
    fn from(value: NativeVarRef) -> Self {
        Self::Native(value)
    }
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

impl PhonyConstant {
    /// Apply a mapping to the `if_true` and `if_false` values of this [`PhonyConstant`].
    pub fn map_fields(self, mut fun: impl FnMut(u64) -> u64) -> Self {
        Self {
            cond: self.cond,
            if_true: fun(self.if_true),
            if_false: fun(self.if_false),
        }
    }
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
    Cmov {
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

impl IrOp {
    pub fn is_native_nop(&self) -> bool {
        match self {
            Self::Nop => true,
            Self::Mov { src, dst }
            | Self::Cmov { src, dst, .. }
            | Self::Lea {
                dst,
                base: src,
                offset: 0,
            } => dst.native() == src.native(),
            _ => false,
        }
    }

    pub fn defined_var(&self) -> Option<LocalVarRef> {
        match self {
            Self::Mov { dst, .. } | Self::Cmov { dst, .. } | Self::Lea { dst, .. } => Some(*dst),
            _ => None,
        }
    }

    pub fn source_var(&self) -> Option<IrVar> {
        match self {
            Self::Mov { src, .. }
            | Self::Cmov { src, .. }
            | Self::Lea { base: src, .. }
            | Self::Jmp(src) => Some(*src),
            _ => None,
        }
    }
}

/* Display impls */

impl std::fmt::Display for LocalVarRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("V{:02}_{:02}", self.native, self.index))
    }
}

impl std::fmt::Display for NativeVarRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("V{:02}", self.0))
    }
}

impl std::fmt::Display for IrVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local(v) => std::fmt::Display::fmt(v, f),
            Self::Native(v) => std::fmt::Display::fmt(v, f),
        }
    }
}

impl std::fmt::Display for PhonyConstant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:?}? {:x} : {:x}",
            self.cond, self.if_true, self.if_false
        ))
    }
}

impl std::fmt::Display for IrOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nop => f.write_str("nop"),
            Self::MovImm { dst, imm } => f.write_fmt(format_args!("mov {dst}, {imm:x}")),
            Self::Mov { dst, src } => f.write_fmt(format_args!("mov {dst}, {src}")),
            Self::Lea { dst, base, offset } => f.write_fmt(format_args!(
                "lea {dst}, [{base}{:x}]",
                offset.format_signed()
            )),
            Self::Cmov { cond, dst, src } => f.write_fmt(format_args!("cmov{cond:?} {dst}, {src}")),
            Self::JmpImm(target) => f.write_fmt(format_args!("jmp {target:x}")),
            Self::Jmp(target) => f.write_fmt(format_args!("jmp {target}")),
            Self::Jcc(phony) => f.write_fmt(format_args!("j{phony}")),
        }
    }
}
