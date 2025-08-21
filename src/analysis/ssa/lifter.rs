use std::ops::IndexMut;

use fxhash::FxHashMap;
use iced_x86::Register;

use crate::analysis::ssa::{
    intrusive_ilist::{IListEnds, IListLink, IListNode, IndexNode},
    ir::{IrOp, IrVar, LocalVarRef, NativeVarRef, PhonyConstant},
    stack_vec::StackVec,
};

/// A value propagated through value/copy propagation.
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq)]
pub enum PropagatedValue {
    /// Unknown propagated value.
    #[default]
    None,
    /// Known constant.
    Constant(u64),
    /// "Constant" which may take different values depending on a condition.
    PhonyConstant(PhonyConstant),
    /// 32-bit offset from another variable.
    VarOffset(IrVar, i32),
}

impl PropagatedValue {
    /// Create a [`PropagatedValue::PhonyConstant`] from its parts.
    ///
    /// if `if_true == is_false`, will simply return `if_true` instead.
    pub fn phony(cond: iced_x86::ConditionCode, if_true: Self, if_false: Self) -> Self {
        match (if_true, if_false) {
            (t, f) if t == f => t,
            (PropagatedValue::Constant(t), PropagatedValue::Constant(f)) => {
                PropagatedValue::PhonyConstant(PhonyConstant {
                    cond,
                    if_true: t,
                    if_false: f,
                })
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
            Self::VarOffset(r, c) => Self::VarOffset(r, c.wrapping_add(imm)),
            Self::PhonyConstant(p) => Self::PhonyConstant(p.map_fields(|x| x.wrapping_add(imm_64))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IrOpInfo {
    /// The IR opcode and its operands.
    pub op: IrOp,
    /// Index of the native instruction that was lifted into this IR operation.
    pub native_op_index: usize,
    /// The variable defined by this instruction, or [`LocalVarRef::INVALID`] if not applicable.
    pub defined_var: LocalVarRef,
    /// Number of times the variable defined by this instruction is referenced.
    pub refcount: usize,
    /// Variables read by this IR operation.
    pub used_vars: StackVec<IrVar, 3>,
    /// Propagated value of the defined variable or main operand.
    pub value: PropagatedValue,
    /// Intrusive linked list of definitions for the same variable
    pub defs_link: IListLink,
}

impl IListNode for IrOpInfo {
    fn link(&self) -> &IListLink {
        &self.defs_link
    }

    fn link_mut(&mut self) -> &mut IListLink {
        &mut self.defs_link
    }
}

impl IrOpInfo {
    fn new(op: IrOp) -> Self {
        Self {
            op,
            native_op_index: usize::MAX,
            defined_var: LocalVarRef::INVALID,
            refcount: 0,
            used_vars: StackVec::new(),
            value: Default::default(),
            defs_link: IListLink::default(),
        }
    }

    fn with_defined_var(self, var: LocalVarRef) -> Self {
        Self {
            defined_var: var,
            ..self
        }
    }

    fn with_used_vars(self, vars: impl IntoIterator<Item = IrVar>) -> Self {
        Self {
            used_vars: vars.into_iter().collect(),
            ..self
        }
    }

    fn with_value(self, value: PropagatedValue) -> Self {
        Self { value, ..self }
    }
}

/// Information about a lifted native instruction.
#[derive(Debug, Clone)]
pub struct NativeOpInfo {
    /// Index of the first IR operation making up this instruction
    pub ir_op_index: usize,
    /// Whether any of the IR operations making up this instruction were modified.
    pub modified: bool,
    /// The disassembled native instruction.
    pub instruction: iced_x86::Instruction,
}

/// An x86 native variable, i.e. register/stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeVar {
    /// A 64-bit general-purpose register.
    Register(Register),
    /// A 64-bit stack location, represented as an offset to the original RSP value.
    Stack(i32),
}

impl NativeVar {
    pub fn register(self) -> Option<Register> {
        match self {
            Self::Register(r) => Some(r),
            _ => None,
        }
    }

    pub fn stack(self) -> Option<i32> {
        match self {
            Self::Stack(s) => Some(s),
            _ => None,
        }
    }
}

/// Information about how a native x86 variable (stack/register) maps to an IR variable
#[derive(Debug, Clone)]
pub struct NativeVarMapping {
    /// The x86 native variable, i.e. register/stack.
    pub native_var: NativeVar,
    /// The [`NativeVarRef`] that can be passed to [`NativeVars::var`] to fetch this
    /// [`NativeVarMapping`].
    pub self_ref: NativeVarRef,
    /// Linked list of local SSA variables that map to this native variable
    pub def_list: IListEnds,
}

impl From<&NativeVarMapping> for NativeVarRef {
    fn from(value: &NativeVarMapping) -> Self {
        value.self_ref
    }
}

impl From<&NativeVarMapping> for IrVar {
    fn from(value: &NativeVarMapping) -> Self {
        IrVar::Native(value.self_ref)
    }
}

impl NativeVarMapping {
    /// Create a new native var mapping given the index it will be stored at.
    pub fn new(var: NativeVar, index: usize) -> Self {
        Self {
            native_var: var,
            self_ref: NativeVarRef::new(index),
            def_list: IListEnds::default(),
        }
    }

    pub fn latest(&self) -> IrVar {
        self.def_list.tail_index().map_or(IrVar::Native(self.self_ref), |i| {
            LocalVarRef::new(i.index(), self.self_ref).into()
        })
    }
}

/// Maps a [`NativeVar`] to a [`NativeVarMapping`] structure.
#[derive(Debug, Clone)]
pub struct NativeVars {
    vars: Vec<NativeVarMapping>,
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
                .map(|i| {
                    NativeVarMapping::new(
                        NativeVar::Register(iced_x86::Register::RAX + i),
                        i as usize,
                    )
                })
                .collect(),
            active_var_count: Self::GPR64_COUNT,
            stack_map: Default::default(),
        }
    }

    pub fn clear(&mut self) {
        for i in 0..self.active_var_count {
            self.vars[i].def_list = IListEnds::default();
        }
        self.active_var_count = Self::GPR64_COUNT
    }

    pub fn var(&self, reference: NativeVarRef) -> &NativeVarMapping {
        &self.vars[reference.index()]
    }

    pub fn var_mut(&mut self, reference: NativeVarRef) -> &mut NativeVarMapping {
        &mut self.vars[reference.index()]
    }

    pub fn register_ref(&self, reg: iced_x86::Register) -> NativeVarRef {
        assert!(reg.is_gpr64());
        NativeVarRef::new(reg as usize - iced_x86::Register::RAX as usize)
    }

    pub fn register(&self, reg: iced_x86::Register) -> &NativeVarMapping {
        self.var(self.register_ref(reg))
    }

    pub fn register_mut(&mut self, reg: iced_x86::Register) -> &mut NativeVarMapping {
        self.var_mut(self.register_ref(reg))
    }

    pub fn stack_ref(&self, offset: i32) -> Option<NativeVarRef> {
        self.stack_map.get(&offset).copied()
    }

    pub fn stack(&self, offset: i32) -> Option<&NativeVarMapping> {
        self.stack_ref(offset).map(|r| self.var(r))
    }

    pub fn stack_mut(&mut self, offset: i32) -> &mut NativeVarMapping {
        let var_ref = *self.stack_map.entry(offset).or_insert_with(|| {
            let native = NativeVar::Stack(offset);
            if self.active_var_count == self.vars.len() {
                self.vars.push(NativeVarMapping::new(native, self.active_var_count));
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

    pub fn native(&self, native: NativeVar) -> Option<&NativeVarMapping> {
        self.native_ref(native).map(|r| self.var(r))
    }

    pub fn native_mut(&mut self, native: NativeVar) -> &mut NativeVarMapping {
        match native {
            NativeVar::Register(r) => self.register_mut(r),
            NativeVar::Stack(s) => self.stack_mut(s),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum MemExpr {
    Constant(u64),
    RegOffset(IrVar, i32),
}

/// A stack offset from the initial RSP value along with the source variable the address was read
/// from.
#[derive(Debug, Clone, Copy)]
pub struct StackOffset {
    pub offset: i32,
    pub source: IrVar,
}

#[derive(Debug, Clone, Copy)]
enum SourcedNativeVar {
    Register(Register),
    Stack(StackOffset),
}

impl SourcedNativeVar {
    fn register(reg: Register) -> Self {
        Self::Register(reg)
    }

    fn stack(offset: i32, source: IrVar) -> Self {
        Self::Stack(StackOffset { offset, source })
    }

    fn source(&self) -> Option<IrVar> {
        match self {
            Self::Register(_) => None,
            Self::Stack(so) => Some(so.source),
        }
    }

    fn var(&self) -> NativeVar {
        match self {
            Self::Register(r) => NativeVar::Register(*r),
            Self::Stack(so) => NativeVar::Stack(so.offset),
        }
    }
}

impl From<iced_x86::Register> for SourcedNativeVar {
    fn from(value: iced_x86::Register) -> Self {
        Self::register(value)
    }
}

impl From<StackOffset> for SourcedNativeVar {
    fn from(value: StackOffset) -> Self {
        Self::stack(value.offset, value.source)
    }
}

impl From<SourcedNativeVar> for NativeVar {
    fn from(value: SourcedNativeVar) -> Self {
        value.var()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LifterError {
    UnsupportedInstruction,
    UnsupportedSIBMem,
    UnsupportedOpKind,
    NonStackMemoryAccess,
}

#[derive(Debug, Clone, Default)]
pub struct LiftedBlock {
    pub ops: Vec<IrOpInfo>,
    pub native_ops: Vec<NativeOpInfo>,
    pub native_vars: NativeVars,
}

impl LiftedBlock {
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn clear(&mut self) {
        self.ops.clear();
        self.native_ops.clear();
        self.native_vars.clear();
    }

    pub fn propagated_value(&self, var: IrVar) -> PropagatedValue {
        match var {
            IrVar::Local(v) => self.ops[v.index()].value,
            IrVar::Native(_) => PropagatedValue::VarOffset(var, 0),
        }
    }

    pub fn stack_at(&self, var: IrVar, offset: i32) -> Option<StackOffset> {
        let address = self.propagated_value(var);
        if let PropagatedValue::VarOffset(src_var, src_offset) = address
            && self.native_vars.var(src_var.native()).native_var
                == NativeVar::Register(Register::RSP)
        {
            Some(StackOffset {
                offset: src_offset.checked_add(offset)?,
                source: var,
            })
        }
        else {
            None
        }
    }

    pub fn stack_at_rsp(&self, offset: i32) -> Option<StackOffset> {
        self.stack_at(self.native_vars.register(Register::RSP).latest(), offset)
    }

    pub fn lift_instruction(
        &mut self,
        instruction: &iced_x86::Instruction,
    ) -> Result<(), LifterError> {
        use iced_x86::Code;

        let native_op_info = NativeOpInfo {
            ir_op_index: self.ops.len(),
            modified: false,
            instruction: *instruction,
        };

        fn is_cmov64(instruction: &iced_x86::Instruction) -> bool {
            let c = instruction.code() as usize;
            instruction.op0_register().is_gpr64()
                && c >= Code::Cmovo_r64_rm64 as usize
                && c <= Code::Cmovg_r64_rm64 as usize
        }

        if instruction.mnemonic() == iced_x86::Mnemonic::Nop {
            self.push_lifted_instruction(IrOpInfo::new(IrOp::Nop));
            self.native_ops.push(native_op_info);
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

        self.native_ops.push(native_op_info);
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
        let native_dst = self.modrm_var(native, 0)?;
        let native_src = native.op1_register();
        match native_dst {
            SourcedNativeVar::Register(r) => {
                self.emit_mov_reg(r, SourcedNativeVar::register(native_src))
            }
            SourcedNativeVar::Stack(so) => self.emit_mov_stack(so, native_src),
        };
        Ok(())
    }

    fn handle_lea(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        self.emit_lea(native.op0_register(), self.modrm_mem_expr(native)?);
        Ok(())
    }

    fn handle_push_imm(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        let imm = native.try_immediate(1).unwrap();
        let dst = self.stack_at_rsp(-8).ok_or(LifterError::NonStackMemoryAccess)?;

        self.emit_mov_imm(dst.into(), imm);

        let new_rsp = MemExpr::RegOffset(self.native_vars.register(Register::RSP).latest(), -8);
        self.emit_lea(Register::RSP, new_rsp);

        Ok(())
    }

    fn handle_push_reg(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        self.emit_mov_stack(
            self.stack_at_rsp(-8).ok_or(LifterError::NonStackMemoryAccess)?,
            native.op0_register(),
        );

        let new_rsp = MemExpr::RegOffset(self.native_vars.register(Register::RSP).latest(), -8);
        self.emit_lea(Register::RSP, new_rsp);

        Ok(())
    }

    fn handle_pop_reg(&mut self, instruction: &iced_x86::Instruction) -> Result<(), LifterError> {
        let mut stack_ref = self.stack_at_rsp(0).ok_or(LifterError::NonStackMemoryAccess)?;

        let new_rsp = MemExpr::RegOffset(self.native_vars.register(Register::RSP).latest(), 8);
        self.emit_lea(Register::RSP, new_rsp);

        // LEA will have pushed a new tag!
        stack_ref.source = self.native_vars.register(Register::RSP).latest();
        self.emit_mov_reg(instruction.op0_register(), stack_ref.into());

        Ok(())
    }

    fn handle_xchg(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        let lhs = self.modrm_var(native, 0)?;
        let native_rhs = native.op1_register();
        let prev_lhs = self.native_vars.native_mut(lhs.into()).latest();

        match lhs {
            SourcedNativeVar::Register(r) => {
                self.emit_mov_reg(r, SourcedNativeVar::register(native_rhs))
            }
            SourcedNativeVar::Stack(so) => self.emit_mov_stack(so, native_rhs),
        }

        let dst = self.native_vars.register_ref(native_rhs).into_local(self.ops.len());
        let used = std::iter::once(prev_lhs).chain(lhs.source());
        let lifted = IrOpInfo::new(IrOp::Mov { dst, src: prev_lhs })
            .with_defined_var(dst)
            .with_value(self.propagated_value(prev_lhs))
            .with_used_vars(used);
        self.push_lifted_instruction(lifted);

        Ok(())
    }

    fn handle_jmp_rel(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        let lifted = IrOpInfo::new(IrOp::JmpImm(native.near_branch_target()));
        self.push_lifted_instruction(lifted);
        Ok(())
    }

    fn handle_jmp_rm(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        self.emit_jmp_rm(self.modrm_var(native, 0)?);
        Ok(())
    }

    fn handle_ret(&mut self, _: &iced_x86::Instruction) -> Result<(), LifterError> {
        let mut stack_ref = self.stack_at_rsp(0).ok_or(LifterError::NonStackMemoryAccess)?;

        let new_rsp = MemExpr::RegOffset(self.native_vars.register(Register::RSP).latest(), 8);
        self.emit_lea(Register::RSP, new_rsp);

        // LEA will have pushed a new tag!
        stack_ref.source = self.native_vars.register(Register::RSP).latest();
        self.emit_jmp_rm(stack_ref.into());

        Ok(())
    }

    fn handle_cmov(&mut self, native: &iced_x86::Instruction) -> Result<(), LifterError> {
        let cond = native.condition_code();
        let native_src = self.modrm_var(native, 1)?;
        let src = self.native_vars.native_mut(native_src.into()).latest();
        let native_dst = self.native_vars.register_mut(native.op0_register());
        let prev_dst = native_dst.latest();
        let dst = native_dst.self_ref.into_local(self.ops.len());

        let value = PropagatedValue::phony(
            cond,
            self.propagated_value(prev_dst),
            self.propagated_value(src),
        );
        let used = [prev_dst, src]
            .into_iter()
            .chain(native_src.source().filter(|s| s != &prev_dst));
        let lifted = IrOpInfo::new(IrOp::Cmov { cond, dst, src })
            .with_defined_var(dst)
            .with_value(value)
            .with_used_vars(used);

        self.push_lifted_instruction(lifted);
        Ok(())
    }

    fn emit_mov_imm(&mut self, native_dst: SourcedNativeVar, imm: u64) {
        let value = PropagatedValue::Constant(imm);
        let dst = self
            .native_vars
            .native_mut(native_dst.into())
            .self_ref
            .into_local(self.ops.len());
        let lifted = IrOpInfo::new(IrOp::MovImm { dst, imm })
            .with_defined_var(dst)
            .with_value(value)
            .with_used_vars(native_dst.source());
        self.push_lifted_instruction(lifted);
    }

    fn emit_mov_reg(&mut self, native_dst: Register, native_src: SourcedNativeVar) {
        let src = self.native_vars.native_mut(native_src.into()).latest();
        let dst = self.native_vars.register_ref(native_dst).into_local(self.ops.len());
        let used = std::iter::once(src).chain(native_src.source());
        let lifted = IrOpInfo::new(IrOp::Mov { dst, src })
            .with_defined_var(dst)
            .with_value(self.propagated_value(src))
            .with_used_vars(used);
        self.push_lifted_instruction(lifted);
    }

    fn emit_mov_stack(&mut self, native_dst: StackOffset, native_src: Register) {
        let src = self.native_vars.register_mut(native_src).latest();
        let dst = self
            .native_vars
            .stack_mut(native_dst.offset)
            .self_ref
            .into_local(self.ops.len());
        let used = std::iter::once(src).chain(Some(native_dst.source).filter(|s| s != &src));
        let lifted = IrOpInfo::new(IrOp::Mov { dst, src })
            .with_defined_var(dst)
            .with_value(self.propagated_value(src))
            .with_used_vars(used);
        self.push_lifted_instruction(lifted);
    }

    fn emit_lea(&mut self, native_dst: Register, mem: MemExpr) {
        let (base, offset) = match mem {
            MemExpr::Constant(imm) => {
                return self.emit_mov_imm(SourcedNativeVar::register(native_dst), imm);
            }
            MemExpr::RegOffset(r, o) => (r, o),
        };
        let dst = self.native_vars.register_ref(native_dst).into_local(self.ops.len());
        let lifted = IrOpInfo::new(IrOp::Lea { dst, base, offset })
            .with_defined_var(dst)
            .with_value(self.propagated_value(base).add(offset))
            .with_used_vars([base]);
        self.push_lifted_instruction(lifted);
    }

    fn emit_jmp_rm(&mut self, native_target: SourcedNativeVar) {
        let target = self.native_vars.native_mut(native_target.into()).latest();
        let lifted = IrOpInfo::new(IrOp::Jmp(target))
            .with_value(self.propagated_value(target))
            .with_used_vars(std::iter::once(target).chain(native_target.source()));
        self.push_lifted_instruction(lifted);
    }

    fn push_lifted_instruction(&mut self, mut lifted: IrOpInfo) {
        for &used_var in &lifted.used_vars {
            if let IrVar::Local(local) = used_var {
                self.ops[local.index()].refcount += 1;
            }
        }
        let def = lifted.defined_var;
        lifted.native_op_index = self.native_ops.len();
        self.ops.push(lifted);

        if def != LocalVarRef::INVALID {
            let native_mapping = self.native_vars.var_mut(def.native());
            self.ops.node_mut(def.index()).insert_tail(&mut native_mapping.def_list);
        }
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
            self.native_vars.register(instruction.memory_base()).latest(),
            instruction.memory_displacement64().cast_signed() as i32,
        ))
    }

    fn modrm_var(
        &self,
        instruction: &iced_x86::Instruction,
        op: u32,
    ) -> Result<SourcedNativeVar, LifterError> {
        match instruction.op_kind(op) {
            iced_x86::OpKind::Register => {
                Ok(SourcedNativeVar::register(instruction.op_register(op)))
            }
            iced_x86::OpKind::Memory => {
                let MemExpr::RegOffset(reg, offset) = self.modrm_mem_expr(instruction)?
                else {
                    return Err(LifterError::NonStackMemoryAccess);
                };
                let stack_offset =
                    self.stack_at(reg, offset).ok_or(LifterError::NonStackMemoryAccess)?;
                Ok(stack_offset.into())
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

        for ir in &block.ops {
            println!("{}", ir.op);
        }

        Ok(())
    }

    #[test]
    fn lift_arxan_cmov() -> Result<(), Box<dyn std::error::Error>> {
        let mut block = LiftedBlock::default();
        for instruction in samples::arxan_cmov() {
            block.lift_instruction(&instruction).unwrap();
        }

        for ir in &block.ops {
            println!("{}\t\t{:?}", ir.op, ir.value);
        }

        Ok(())
    }
}
