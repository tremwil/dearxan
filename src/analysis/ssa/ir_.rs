use std::convert::identity;

use crate::analysis::ssa::util::{AsFmtSigned, StackVec};

/// A numeric tag tracking the assignment count of a variable in a SSA-form program.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AssignmentTag(u16);

impl Default for AssignmentTag {
    fn default() -> Self {
        AssignmentTag::NONE
    }
}

impl std::fmt::Debug for AssignmentTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_tuple("AssignmentTag");
        if let Some(i) = self.as_index() {
            s.field(&i);
        }
        else {
            s.field(&None::<()>);
        }
        s.finish()
    }
}

impl AssignmentTag {
    /// An emtpy assignment tag, indicating that the referenced value of the variable predates
    /// assignment in the SSA program.
    ///
    /// Variables with this assignment tag are treated as symbolic constants.
    pub const NONE: Self = AssignmentTag(u16::MAX);

    pub(super) const fn from_index(index: usize) -> Self {
        #[cfg(debug_assertions)]
        if index >= Self::NONE.0 as usize {
            panic!("assignment tag overflow");
        }
        Self(index as u16)
    }

    pub(super) const fn from_index_opt(maybe_index: Option<usize>) -> Self {
        match maybe_index {
            None => Self::NONE,
            Some(index) => Self::from_index(index),
        }
    }

    pub const fn increment(self) -> Self {
        #[cfg(debug_assertions)]
        if self.0 == Self::NONE.0 {
            panic!("assignment tag overflow");
        }
        Self(self.0.wrapping_add(1))
    }

    pub const fn decrement(self) -> Self {
        #[cfg(debug_assertions)]
        if self.0 == Self::NONE.0 {
            panic!("assignment tag overflow");
        }
        Self(self.0.wrapping_sub(1)) // allow 0 to become NONE
    }

    pub const fn as_index(self) -> Option<usize> {
        if self.0 == Self::NONE.0 { None } else { Some(self.0 as usize) }
    }
}

/// An identifier representing a program variable paired with a static-single assignment tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tagged<T> {
    /// Unique identifier representing the program variable (register, stack offset, etc.).
    pub id: T,
    /// Tag keeping track of which assignment to the variable we are referring to.
    pub tag: AssignmentTag,
}

impl<T> Tagged<T> {
    pub const fn new(id: T, tag: AssignmentTag) -> Self {
        Self { id, tag }
    }

    pub const fn untagged(id: T) -> Self {
        Self {
            id,
            tag: AssignmentTag::NONE,
        }
    }

    pub fn with_tag(self, tag: AssignmentTag) -> Self {
        Self { tag, ..self }
    }

    pub fn with_inc_tag(self) -> Self {
        Self::new(self.id, self.tag.increment())
    }

    pub fn with_dec_tag(self) -> Self {
        Self::new(self.id, self.tag.decrement())
    }
}

impl<T> From<T> for Tagged<T> {
    fn from(value: T) -> Self {
        Self::untagged(value)
    }
}

impl<T> std::ops::Deref for Tagged<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.id
    }
}

impl<T> std::ops::DerefMut for Tagged<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.id
    }
}

/// A SSA-tagged register.
pub type IrRegister = Tagged<iced_x86::Register>;

/// A non-labeled reference to a 64-bit stack variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackRef {
    /// Byte offset of the stack variable relative to the original value of RSP.
    pub offset: i32,
    /// Register used by the stack expression to refer to this stack variable.
    ///
    /// For example, `RSP1` in `mov [RSP1-8], rax`.
    pub source: IrRegister,
}

/// A SSA-tagged 64-bit stack variable.
pub type IrStackRef = Tagged<StackRef>;

/// An tagged program variable, either stored in a register or on the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrVariable {
    /// Register variable.
    Register(IrRegister),
    /// Stack variable.
    Stack(IrStackRef),
}

impl IrVariable {
    pub fn register(&self) -> Option<IrRegister> {
        match self {
            Self::Register(r) => Some(*r),
            _ => None,
        }
    }

    pub fn stack(&self) -> Option<IrStackRef> {
        match self {
            Self::Stack(s) => Some(*s),
            _ => None,
        }
    }

    pub fn tag(&self) -> AssignmentTag {
        match self {
            Self::Register(r) => r.tag,
            Self::Stack(s) => s.tag,
        }
    }
}

impl From<IrStackRef> for IrVariable {
    fn from(value: IrStackRef) -> Self {
        Self::Stack(value)
    }
}

impl From<&IrStackRef> for IrVariable {
    fn from(value: &IrStackRef) -> Self {
        (*value).into()
    }
}

impl From<IrRegister> for IrVariable {
    fn from(value: IrRegister) -> Self {
        Self::Register(value)
    }
}

impl From<&IrRegister> for IrVariable {
    fn from(value: &IrRegister) -> Self {
        (*value).into()
    }
}

/// Memory access expresion used by IR memory operands.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MemExpr {
    /// A constant address, usually lifted from a RIP-relative expression.
    Constant(u64),
    /// An offset from some register.
    RegOffset(IrRegister, i32),
}

/// Types of destination and source operand pairs allowed by move instructions.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MovOps {
    /// Write an immediate to a register or stack variable.
    Immediate { dst: IrVariable, imm: u64 },
    /// Write a register or stack variable to a register.
    Register { dst: IrRegister, src: IrVariable },
    /// Write a register to a stack variable.
    Stack { dst: IrStackRef, src: IrRegister },
}

/// Static single-assignment intermediate-level representation of an instruction.
///
/// This set was chosen to be as restricted as possible, while being sufficient to handle
/// all types of Arxan obfuscation. To avoid having to deal with register allocation, we also don't
/// want to allow IR representations that can't be re-encoded to x86 without a temporary register.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IrInstruction {
    /// Does nothing.
    ///
    /// Used to replace dead instructions without outright removing them.
    Nop,
    /// Similar to x86's `lea`, but with a more restricted memory expression.
    Lea {
        /// Destination register.
        dst: IrRegister,
        /// Memory expression whose virtual address will be written to the register.
        mem: MemExpr,
    },
    /// Moves a 64-bit value from one variable to another.
    Mov(MovOps),
    /// Conditionally moves a 64-bit value from one variable to another.
    Cmov {
        /// x86 condition code determining whether the move occurs.
        cond: iced_x86::ConditionCode,
        /// The destination register of the conditional move.
        dst: IrRegister,
        /// The source register/stack variable that may be moved.
        src: IrVariable,
    },
    /// Unconditional branch to a fixed address, usually lifted from an IP-relative operand.
    JmpImm(u64),
    /// Unconditional branch to the address stored in a register/stack variable.
    Jmp(IrVariable),
    /// Conditional branch to any of two fixed addresses.
    Jcc {
        /// x86 condition code.
        cond: iced_x86::ConditionCode,
        /// Branch taken if the condition is true.
        if_true: u64,
        /// Branch taken if the condition is false.
        if_false: u64,
    },
}

/// Trait exposing the variable defined by an IR instruction or destination operand.
pub trait DefinedVar {
    fn defined_var(&self) -> Option<IrVariable>;
}

impl DefinedVar for MovOps {
    fn defined_var(&self) -> Option<IrVariable> {
        Some(match self {
            Self::Immediate { dst, .. } => *dst,
            Self::Register { dst, .. } => dst.into(),
            Self::Stack { dst, .. } => dst.into(),
        })
    }
}

impl DefinedVar for IrInstruction {
    fn defined_var(&self) -> Option<IrVariable> {
        match self {
            Self::Lea { dst, .. } => Some(dst.into()),
            Self::Mov(ops) => ops.defined_var(),
            Self::Cmov { dst, .. } => Some(dst.into()),
            _ => None,
        }
    }
}

/// Trait exposing the variables used by an IR instruction or operand type.
pub trait UsedVars {
    /// Buffer type able to hold the used variables in contiguous memory.
    type VarsBuf: AsRef<[IrVariable]> + IntoIterator<Item = IrVariable>;

    /// Collect the variables used by this instruction/operand into a contigous buffer.
    fn used_vars_buf(&self) -> Self::VarsBuf;

    /// Iterate over the variables used by this instruction/operand.
    fn used_vars(&self) -> impl Iterator<Item = IrVariable> {
        self.used_vars_buf().into_iter()
    }
}

impl UsedVars for IrStackRef {
    type VarsBuf = StackVec<IrVariable, 2>;

    fn used_vars_buf(&self) -> Self::VarsBuf {
        StackVec::from_buf([self.into(), self.id.source.into()])
    }
}

impl UsedVars for IrVariable {
    type VarsBuf = StackVec<IrVariable, 2>;

    fn used_vars_buf(&self) -> Self::VarsBuf {
        match self {
            Self::Register(_) => StackVec::from_array([*self]),
            Self::Stack(s) => StackVec::from_array([*self, s.source.into()]),
        }
    }
}

impl UsedVars for MemExpr {
    type VarsBuf = StackVec<IrVariable, 1>;

    fn used_vars_buf(&self) -> Self::VarsBuf {
        match self {
            Self::RegOffset(r, _) => StackVec::from_array([r.into()]),
            _ => StackVec::new(),
        }
    }
}

impl UsedVars for MovOps {
    type VarsBuf = StackVec<IrVariable, 2>;

    fn used_vars_buf(&self) -> Self::VarsBuf {
        match self {
            Self::Immediate {
                dst: IrVariable::Stack(IrStackRef { id, .. }),
                ..
            } => StackVec::from_array([id.source.into()]),
            Self::Immediate { .. } => StackVec::new(),
            Self::Register { src, .. } => src.used_vars_buf(),
            Self::Stack { dst, src } if &dst.source != src => {
                StackVec::from_array([dst.source.into(), src.into()])
            }
            Self::Stack { src, .. } => StackVec::from_array([src.into()]),
        }
    }
}

impl UsedVars for IrInstruction {
    type VarsBuf = StackVec<IrVariable, 3>;

    fn used_vars_buf(&self) -> Self::VarsBuf {
        match self {
            Self::Lea { mem, .. } => mem.used_vars_buf().expand(),
            Self::Mov(ops) => ops.used_vars_buf().expand(),
            Self::Cmov { dst, src, .. } => {
                let mut used = src.used_vars_buf().expand();

                let prev_dst = dst.with_dec_tag();
                let in_src = match src {
                    IrVariable::Register(r) => &prev_dst == r,
                    IrVariable::Stack(s) => prev_dst == s.source,
                };
                if !in_src {
                    used.push(prev_dst.into());
                }
                used
            }
            Self::Jmp(var) => var.used_vars_buf().expand(),
            _ => StackVec::new(),
        }
    }
}

// Display impls to pretty-print SSA IR instructions

impl std::fmt::Display for IrRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.id, f)?;
        if let Some(i) = self.tag.as_index() {
            f.write_fmt(format_args!("_{i}"))?;
        }
        Ok(())
    }
}

impl std::fmt::Display for StackRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Stack[{:x} ({})]",
            self.offset.format_signed(),
            self.source
        ))
    }
}

impl std::fmt::Display for IrStackRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.id, f)?;
        if let Some(i) = self.tag.as_index() {
            f.write_fmt(format_args!("_{i}"))?;
        }
        Ok(())
    }
}

impl std::fmt::Display for IrVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Register(r) => std::fmt::Display::fmt(r, f),
            Self::Stack(s) => std::fmt::Display::fmt(s, f),
        }
    }
}

impl std::fmt::Display for MemExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Constant(c) => f.write_fmt(format_args!("[{c:x}]")),
            Self::RegOffset(r, o) => f.write_fmt(format_args!("[{r} {:x}]", o.format_signed())),
        }
    }
}

impl std::fmt::Display for MovOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Immediate { dst, imm } => {
                f.write_fmt(format_args!("{dst}, {:x}", imm.format_signed()))
            }
            Self::Register { dst, src } => f.write_fmt(format_args!("{dst}, {src}")),
            Self::Stack { dst, src } => f.write_fmt(format_args!("{dst}, {src}")),
        }
    }
}

impl std::fmt::Display for IrInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nop => f.write_str("nop"),
            Self::Mov(ops) => f.write_fmt(format_args!("mov {ops}")),
            Self::Lea { dst, mem } => f.write_fmt(format_args!("lea {dst}, {mem}")),
            Self::Cmov { cond, dst, src } => f.write_fmt(format_args!("cmov{cond:?} {dst}, {src}")),
            Self::JmpImm(imm) => f.write_fmt(format_args!("jmp {imm:x}")),
            Self::Jmp(target) => f.write_fmt(format_args!("jmp {target}")),
            Self::Jcc {
                cond,
                if_true,
                if_false,
            } => f.write_fmt(format_args!("j{cond:?}? {if_true:x} : {if_false:x}")),
        }
    }
}
