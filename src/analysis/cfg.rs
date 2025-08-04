//! Implements specialized logic to visit all instructions in an arbitrary Arxan stub, using the
//! forking emulator from the [`vm`](`crate::analysis::vm`) module to work through obfuscated
//! control flow.

use std::collections::hash_map::Entry;

use bitfield_struct::bitfield;
use fxhash::FxHashMap;
use iced_x86::{Code, FlowControl, Register};

use super::vm::{ImageView, ProgramState, RunStep, StepKind, util};

const VOLATILE_REGS: &[Register] = &[
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];

#[bitfield(u64)]
struct CfgInfo {
    #[bits(63)]
    cmov_id: u64,
    unresolved_branch: bool,
}

impl CfgInfo {
    const fn detached() -> Self {
        Self::new().with_cmov_id(u64::MAX >> 1)
    }

    fn detach_cmov_pair(&mut self) {
        self.set_cmov_id(u64::MAX >> 1);
    }

    fn is_prev_of(&self, other: &Self) -> bool {
        self.cmov_id().checked_add(1) == Some(other.cmov_id())
    }

    fn create_pair(&mut self) -> (Self, Self) {
        self.set_cmov_id(self.cmov_id() + 3);
        (
            Self::new().with_cmov_id(self.cmov_id()),
            Self::new().with_cmov_id(self.cmov_id() + 1),
        )
    }
}

#[derive(Clone, Copy)]
pub struct ArxanCfgData<D: Clone> {
    pub inner: D,
    cfg_info: CfgInfo,
}

// Information about a possibly-obfuscated call instruction.
pub struct CallInfo {
    /// The value of RSP after taking the call.
    pub target_rsp: u64,
    /// The value of RSP after returning from the call.
    pub return_rsp: u64,
    /// The call's target function.
    pub target_ip: Option<u64>,
    /// The return address to jump to after returning from the called function.
    pub return_ip: Option<u64>,
}

impl CallInfo {
    /// Attempt to extract call information from the current execution step.
    ///
    /// The instruction trigerring this may not necessarily be a call instruction.
    /// Heuristics regarding the stack and its alignment make detecting calls obfuscated
    /// via jump or return instructions possible.
    pub fn from_step<I: ImageView, D: Clone>(step: &RunStep<I, D>) -> Option<Self> {
        // rsp must be known to analyze calls
        let rsp = step.state.registers.rsp()?;

        match step.instruction.flow_control() {
            // If RSP is call-aligned after a return/indirect branch, assume an obfuscated call.
            FlowControl::Return => {
                let target_rsp =
                    rsp.wrapping_add_signed(step.instruction.stack_pointer_increment() as i64);

                (target_rsp & 0xF == 8).then(|| Self {
                    target_rsp,
                    return_rsp: target_rsp.wrapping_add(8),
                    target_ip: step.state.memory.read_int(rsp, 8),
                    return_ip: step.state.memory.read_int(target_rsp, 8),
                })
            }
            FlowControl::IndirectBranch => (rsp & 0xF == 8).then(|| Self {
                target_rsp: rsp,
                return_rsp: rsp.wrapping_add(8),
                target_ip: step.state.get_operand_value(step.instruction, 0),
                return_ip: step.state.memory.read_int(rsp, 8),
            }),
            FlowControl::Call | FlowControl::IndirectCall => Some(Self {
                target_rsp: rsp
                    .wrapping_add_signed(step.instruction.stack_pointer_increment() as i64),
                return_rsp: rsp,
                target_ip: if step.instruction.flow_control() == FlowControl::IndirectCall {
                    step.state.get_operand_value(step.instruction, 0)
                }
                else {
                    Some(step.instruction.near_branch_target())
                },
                return_ip: Some(step.instruction.next_ip()),
            }),
            _ => None,
        }
    }
}

/// Wrapper around a [`ProgramState`] providing a different [`run`](ArxanCfgVisitor::run) method
/// which attempts to visit all instructions of an Arxan stub.
pub struct ArxanCfgVisitor<I: ImageView, D: Clone>(pub ProgramState<I, D>);

impl<I: ImageView, D: Clone> ArxanCfgVisitor<I, D> {
    // Handles repeat calls and obfuscated calls
    fn handle_call_like<R>(
        step: RunStep<I, ArxanCfgData<D>>,
        visited: &mut FxHashMap<u64, CfgInfo>,
    ) -> StepKind<I, ArxanCfgData<D>, R> {
        let Some(call) = CallInfo::from_step(&step)
        else {
            return StepKind::SingleStep;
        };
        let Some(return_ip) = call.return_ip
        else {
            return StepKind::SingleStep;
        };

        let oob_or_visited = match call.target_ip {
            Some(t) => step.state.memory.image().read(t, 1).is_none() || visited.contains_key(&t),
            None => true,
        };

        // make sure we visit instructions after returning, skip to the return immediately
        // if the target is oob or already visited
        if oob_or_visited {
            log::trace!("skipping detected call at {:x}", step.instruction.ip());
            *step.state.registers.rsp_mut() = Some(call.return_rsp);
            step.state.rip = Some(return_ip);

            // Clear volatile registers, since we don't know what the function did
            for &r in VOLATILE_REGS {
                *step.state.registers.gpr64_mut(r) = None;
            }
            StepKind::Custom(None)
        }
        else {
            StepKind::SingleStep
        }
    }

    /// Visits the control flow graph of the provided [`ProgramState`] while resolving obfuscated
    /// branches and preserving partial register and memory state information along the way.
    ///
    /// The `on_step` function can be used to modify the state of the emulator and/or stop visting
    /// certain branches.
    ///
    /// Unlike [`ProgramState::run`], this function will always halt, usually taking `O(n)`
    /// steps to visit all instructions of the stub. Note that pathological worst cases may take
    /// `O(n^2)` time to halt, but such cases will not be encountered in practice.
    ///
    /// # Requirements
    /// The [`ProgramState`] must be initialized to the `TEST RSP, 0xF` instruction of the Arxan
    /// stub.
    pub fn run<F, R>(self, mut on_step: F) -> Option<R>
    where
        F: FnMut(RunStep<'_, I, ArxanCfgData<D>>) -> StepKind<I, ArxanCfgData<D>, R>,
    {
        // Ignore the RSP-aligning first branch path that doesn't correspond to the
        // actual RSP value
        let ignored_test_rsp_branch = match self.0.registers.rsp() {
            Some(rsp) if rsp % 16 == 0 => 1,
            _ => 0,
        };
        let mut bad_cmp_rax_branch = None;

        let mut is_double_stepping = false;
        let mut info_pair_gen = CfgInfo::new();
        let mut visited: FxHashMap<u64, CfgInfo> = Default::default();
        let init_state = ProgramState {
            rip: self.0.rip,
            registers: self.0.registers,
            memory: self.0.memory,
            user_data: ArxanCfgData {
                inner: self.0.user_data,
                cfg_info: CfgInfo::detached(),
            },
        };
        init_state.run(move |mut step| {
            // Don't execute the incorrect RSP alignment branch
            if (step.branch_count, step.past_forks.len()) == (1, ignored_test_rsp_branch) {
                log::trace!("Ignoring unreachable RSP alignment branch");
                return StepKind::StopFork;
            }

            // Obfuscated stub call routines will first check if we pushed 18 earlier.
            // We need to make sure to take the correct branch here too
            if step.branch_count == 1
                && step.instruction.code() == Code::Cmp_rm64_imm8
                && step.instruction.op0_register() == Register::RAX
                && step.instruction.immediate8() == 0x18
            {
                bad_cmp_rax_branch = Some(2 * ignored_test_rsp_branch);
            }
            if step.branch_count == 2 && Some(step.past_forks.len()) == bad_cmp_rax_branch {
                log::trace!("Ignoring unreachable RSP alignment return fixup branch");
                return StepKind::StopFork;
            }

            // Keep track of visited instructions
            match visited.entry(step.instruction.ip()) {
                Entry::Occupied(mut e) => {
                    let cfg_info = e.get_mut();

                    // Clear the unresolved branch flag if set
                    let mut allow_visited = cfg_info.unresolved_branch();
                    if allow_visited {
                        cfg_info.set_unresolved_branch(false);
                    }

                    // Only double step instructions when:
                    // - instruction immediately follows the latest cmov branch
                    // - no conditional branch instruction has been invoked yet
                    let is_cond = step.instruction.flow_control() == FlowControl::ConditionalBranch;
                    if !is_cond && step.state.user_data.cfg_info.is_prev_of(cfg_info) {
                        // Since we already visited the instruction, don't call the user step
                        // function
                        log::trace!("double stepping");
                        is_double_stepping = true;
                        allow_visited = true;
                    }
                    else if allow_visited && is_double_stepping {
                        log::trace!("double stepping path diverged");
                        is_double_stepping = false;
                        step.state.user_data.cfg_info.detach_cmov_pair();
                    }

                    if !allow_visited {
                        return StepKind::StopFork;
                    }
                }
                Entry::Vacant(e) => {
                    if is_double_stepping {
                        log::trace!("double stepping path diverged");
                        is_double_stepping = false;
                        step.state.user_data.cfg_info.detach_cmov_pair();
                    }
                    e.insert(step.state.user_data.cfg_info);
                }
            };

            // Run the user step function
            // TODO: Don't do this when double stepping, so each instruction is only seen once by
            // the user code
            match on_step(step.reborrow()) {
                StepKind::SingleStep => (),
                handled => return handled,
            }

            // If the instruction is a int 0x2D, skip it instead of stopping
            // Without this, Arxan anti-debug checks will not be fully visited
            if step.instruction.code() == Code::Int_imm8 && step.instruction.immediate8() == 0x2D {
                step.state.rip = Some(step.instruction.next_ip());
                return StepKind::Custom(None);
            }

            // If instruction is a conditional move, fork the cmov path too
            if util::is_cmov(step.instruction.mnemonic()) {
                let maybe_fork = step.single_step().map(|mut fork| {
                    (step.state.user_data.cfg_info, fork.user_data.cfg_info) =
                        info_pair_gen.create_pair();
                    fork
                });
                return StepKind::Custom(maybe_fork);
            }

            match Self::handle_call_like(step.reborrow(), &mut visited) {
                StepKind::SingleStep => (),
                handled => return handled,
            };

            // If we didn't fork and somehow ended up at no rip while single-stepping an indirect
            // branch or return, set the unresolved flag on all instructions in the basic block
            let maybe_fork = step.single_step();
            let indirect = matches!(
                step.instruction.flow_control(),
                FlowControl::IndirectBranch | FlowControl::Return
            );
            if maybe_fork.is_none() && indirect && step.state.rip.is_none() {
                let last_blocks = step.basic_block();

                log::trace!(
                    "Unresolved jump/ret at {:x}, allowing revisits from {:x?}",
                    step.instruction.ip(),
                    last_blocks.first()
                );

                for ip in last_blocks {
                    visited.get_mut(ip).unwrap().set_unresolved_branch(true);
                }
            }

            StepKind::Custom(maybe_fork)
        })
    }
}
