//! Analyze Arxan stubs, attempting to extracting the information about them.

use fxhash::FxBuildHasher;
use iced_x86::{Code, OpKind, Register};
use indexmap::IndexMap;

use super::{
    cfg::{ArxanCfgVisitor, CallInfo},
    encryption::{
        DecryptReader, EncryptedRegion, EncryptedRegionList, rmx_decryptor, tea_decryptor,
    },
    vm::{ImageView, MemoryStore, ProgramState, Registers, RunStep, StepKind},
};
use crate::analysis::encryption::{ArxanDecryptionKind, sub_decryptor};

/// Information about an Arxan return gadget.
///
/// Arxan tries to prevent trivially stopping its stubs from running by simply returning from them
/// by first pushing 3 "bad" addresses to the stack. As the stub routine executes, it will write
/// above its own stack frame to replace these bad addresses with the "true" addresses
/// which allow the stub to return properly.
#[derive(Debug, Clone)]
pub struct ReturnGadget {
    /// The stack offset (relative to the value of RSP during the `test rsp, 0xf` instruction) at
    /// which the return gadget is written.
    pub stack_offset: usize,
    /// The virtual address of the return gadget.
    pub address: u64,
}

/// Information extracted from an analyzed Arxan stub.
#[derive(Debug, Clone)]
pub struct StubInfo {
    /// The virtual address of the stub's `test rsp, 0xf` instruction.
    ///
    /// This particular instruction is useful as it does not typically appear in normal code, since
    /// there are better ways to align the stack. Hence its presence makes it very easy to scan for
    /// Arxan stubs.
    pub test_rsp_va: u64,
    /// The virtual address of the "exit" portion of the stub, responsible for restoring the
    /// execution context.
    pub context_pop_va: u64,
    /// The top-most return gadget.
    ///
    /// Although Arxan pushes 3 "bad" addresses to the stack, one only needs to know the value of
    /// the top one to locate the stub's return address.
    pub return_gadget: Option<ReturnGadget>,
    /// A list of memory regions that are encrypted at rest and get decrypted by the stub.
    ///
    /// The stub may also be an "encryption" stub, in which case the bytes it writes to the region
    /// were randomly generated.
    pub encrypted_regions: Option<EncryptedRegionList>,
}

#[derive(Debug, Clone)]
struct BlockTeaCandidate<'a> {
    tea_block_decrypt: u64,
    ciphertext: &'a [u8],
    key_va: u64,
    key: &'a [u8; 16],
}

#[derive(Debug, Clone)]
struct RegionListInfo {
    tea_block_decrypt: u64,
    region_list_key_va: u64,
    encrypted_regions: Vec<EncryptedRegion>,
}

#[derive(Debug, Clone)]
struct RegionsKeyCandidate<'a> {
    tea_block_decrypt: u64,
    next_lea_test: usize,
    key_va: u64,
    key: &'a [u8; 16],
}

#[derive(Debug, Clone)]
enum TeaEncryptionState<'a> {
    SearchingRegions((Vec<RegionsKeyCandidate<'a>>, Vec<u64>)),
    SearchingCiphertext(RegionListInfo),
    Found(EncryptedRegionList),
}

impl Default for TeaEncryptionState<'_> {
    fn default() -> Self {
        Self::SearchingRegions((Vec::default(), Vec::default()))
    }
}

#[derive(Debug, Clone)]
enum RmxEncryptionState<'a> {
    Searching {
        key: Option<u32>,
        regions: Option<Vec<EncryptedRegion>>,
        ciphertext: Option<&'a [u8]>,
    },
    Found(EncryptedRegionList),
}

impl<'a> RmxEncryptionState<'a> {
    fn update<I: ImageView, D: Clone>(&mut self, step: &RunStep<&'a I, D>) {
        let image = *step.state.memory.image();

        let Self::Searching {
            key,
            regions,
            ciphertext,
        } = self
        else {
            return;
        };

        if key.is_none()
            && matches!(
                step.instruction.code(),
                Code::And_EAX_imm32 | Code::And_rm32_imm8
            )
            && step.instruction.immediate32() == 0x1f
            && let Some(k) = step.state.registers.read_gpr(step.instruction.op0_register())
        {
            log::trace!("found potential rmx key: {:x}", k);
            *key = Some(k as u32);
        }
        if regions.is_none()
            && step.instruction.code() == Code::Movzx_r32_rm8
            && step.instruction.op1_kind() == OpKind::Memory
            && let Some(va) = step.state.virtual_address(step.instruction, 1)
            && let Some(varints) = image.read(va, 2)
        {
            // enforce max length of 256 to avoid false positives
            // let varints = varints.get(..0x100).unwrap_or(varints);
            if let Ok(rlist) = EncryptedRegion::try_from_varints(varints) {
                log::trace!("found rmx region list info: {:x?}", rlist);
                *regions = Some(rlist);
            }
        }
        if ciphertext.is_none()
            && step.instruction.code() == Code::Imul_r32_rm32
            && step.instruction.op0_register() == Register::EDX
            && let Some(rax) = step.state.registers.rax()
        {
            log::trace!("found potential rmx ciphertext va: {:x}", rax);
            *ciphertext = image.read(rax, 4)
        }

        if let Some(key) = *key
            && let Some(ctext) = *ciphertext
            && let Some(regions) = regions.take()
        {
            match EncryptedRegionList::try_new(
                ArxanDecryptionKind::Rmx,
                regions,
                DecryptReader::new(ctext, rmx_decryptor(key)),
            ) {
                Ok(rlist) => *self = Self::Found(rlist),
                Err(e) => log::warn!("error while decrypting rmx regions: {e}"),
            }
        }
    }
}

impl Default for RmxEncryptionState<'_> {
    fn default() -> Self {
        Self::Searching {
            key: None,
            regions: None,
            ciphertext: None,
        }
    }
}

#[derive(Default, Debug, Clone)]
enum SubEncryptionState<'a> {
    #[default]
    SearchingRegions,
    SearchingCtextMov {
        regions: Vec<EncryptedRegion>,
    },
    CheckingNeg {
        regions: Vec<EncryptedRegion>,
        register: Register,
        ctext: &'a [u8],
    },
    CheckingKey {
        regions: Vec<EncryptedRegion>,
        register: Register,
        ctext: &'a [u8],
    },
    Found(EncryptedRegionList),
}

impl<'a> SubEncryptionState<'a> {
    fn update<I: ImageView, D: Clone>(&mut self, step: &RunStep<&'a I, D>) {
        // ignore unconditional non-computed branches
        if step.instruction.is_jmp_short_or_near() {
            return;
        }

        let image = *step.state.memory.image();
        match self {
            Self::SearchingRegions => {
                if step.instruction.code() == Code::Movzx_r32_rm8
                    && step.instruction.op1_kind() == OpKind::Memory
                    && let Some(va) = step.state.virtual_address(step.instruction, 1)
                    && let Some(varints) = image.read(va, 2)
                    && let Ok(regions) = EncryptedRegion::try_from_varints(varints)
                {
                    log::trace!("found sub region list info: {:x?}", regions);
                    *self = Self::SearchingCtextMov { regions };
                }
            }
            Self::SearchingCtextMov { regions } => {
                if step.instruction.code() == Code::Mov_r32_rm32
                    && step.instruction.op1_kind() == OpKind::Memory
                    && let Some(va) = step.state.virtual_address(step.instruction, 1)
                    && let Some(ctext) = image.read(va, 1)
                {
                    log::trace!("found potential sub ciphertext va: {:x}", va);
                    *self = Self::CheckingNeg {
                        regions: std::mem::take(regions),
                        register: step.instruction.op0_register(),
                        ctext,
                    };
                }
            }
            Self::CheckingNeg {
                regions,
                register,
                ctext,
            } => {
                if step.instruction.code() == Code::Neg_rm32
                    && step.instruction.op0_register() == *register
                {
                    *self = Self::CheckingKey {
                        regions: std::mem::take(regions),
                        register: *register,
                        ctext,
                    };
                }
                else {
                    *self = Self::SearchingCtextMov {
                        regions: std::mem::take(regions),
                    };
                }
            }
            Self::CheckingKey {
                regions,
                register,
                ctext,
            } => {
                if step.instruction.code() == Code::Add_r32_rm32
                    && step.instruction.op0_register() == *register
                    && step.instruction.is_ip_rel_memory_operand()
                    && let Some(key) = step.state.get_operand_value(step.instruction, 1)
                {
                    match EncryptedRegionList::try_new(
                        ArxanDecryptionKind::Sub,
                        regions.clone(),
                        DecryptReader::new(ctext, sub_decryptor(key as u32)),
                    ) {
                        Ok(rlist) => {
                            *self = Self::Found(rlist);
                            return;
                        }
                        Err(e) => log::warn!("error while decrypting sub regions: {e}"),
                    }
                }
                *self = Self::SearchingCtextMov {
                    regions: std::mem::take(regions),
                };
            }
            Self::Found(_) => (),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct StubScanState<'a> {
    init_rsp: u64,
    return_gadget: Option<ReturnGadget>,
    context_pop_va: Option<u64>,
    tea_state: TeaEncryptionState<'a>,
    rmx_state: RmxEncryptionState<'a>,
    sub_state: SubEncryptionState<'a>,
    /// Candidate calls to the stub's tea block decrypt function
    tea_candidates: Vec<BlockTeaCandidate<'a>>,
    /// Maps the first 8 bytes of memory at an LEA [rip+...] instruction to its address
    static_lea_lookup: IndexMap<u64, u64, FxBuildHasher>,
}

impl<'a> StubScanState<'a> {
    /// Search for the instruction writing a return gadget.
    /// this is a code pointer written above the stub's stack-saved context
    fn extract_return_gadget<I: ImageView, D: Clone>(
        &self,
        step: &RunStep<I, D>,
    ) -> Option<ReturnGadget> {
        if step.instruction.code() != Code::Mov_rm64_r64
            || step.instruction.op0_kind() != OpKind::Memory
        {
            return None;
        }
        let write_addr = step.state.virtual_address(step.instruction, 0)?;
        let address = step.state.get_operand_value(step.instruction, 1)?;
        let stack_offset = write_addr.checked_sub(self.init_rsp)? as usize;
        (stack_offset < 0x400).then_some(ReturnGadget {
            stack_offset,
            address,
        })
    }

    fn search_region_candidates(&mut self, image: &impl ImageView, new_block_decrypt: Option<u64>) {
        let TeaEncryptionState::SearchingRegions((key_candidates, block_decrypts)) =
            &mut self.tea_state
        else {
            return;
        };
        block_decrypts.extend(new_block_decrypt);

        for key_info in key_candidates {
            // only try a key if the call it was detected from matches one we got full info from
            if !block_decrypts.contains(&key_info.tea_block_decrypt) {
                continue;
            }
            let Some(lea_targets) = self.static_lea_lookup.get_range(key_info.next_lea_test..)
            else {
                continue;
            };

            let candidate_ctexts = lea_targets.values().filter_map(|&va| image.read(va, 8));
            for ctext in candidate_ctexts {
                let stream = DecryptReader::new(ctext, tea_decryptor(key_info.key));
                if let Ok(region_list) = EncryptedRegion::try_from_varints(stream) {
                    self.tea_state = TeaEncryptionState::SearchingCiphertext(RegionListInfo {
                        tea_block_decrypt: key_info.tea_block_decrypt,
                        region_list_key_va: key_info.key_va,
                        encrypted_regions: region_list,
                    });
                    log::trace!("found tea region list info: {:x?}", self.tea_state);

                    self.search_ciphertext_candidates();
                    return;
                }
            }
            key_info.next_lea_test = lea_targets.len();
        }
    }

    fn search_ciphertext_candidates(&mut self) {
        let TeaEncryptionState::SearchingCiphertext(region_list) = &self.tea_state
        else {
            return;
        };

        self.tea_candidates.retain(|c| {
            c.tea_block_decrypt == region_list.tea_block_decrypt
                && c.key_va != region_list.region_list_key_va
        });

        if let Some(ctext_decrypt) = self.tea_candidates.first() {
            let encrypted_regions = EncryptedRegionList::try_new(
                ArxanDecryptionKind::Tea,
                region_list.encrypted_regions.clone(),
                DecryptReader::new(ctext_decrypt.ciphertext, tea_decryptor(ctext_decrypt.key)),
            )
            .unwrap();

            log::trace!(
                "encryption info extracted, regions: {:x?}",
                encrypted_regions.regions
            );

            self.tea_state = TeaEncryptionState::Found(encrypted_regions);
        }
    }

    fn on_tea_info<I: ImageView, D: Clone>(
        &mut self,
        tea_block_decrypt: u64,
        step: &RunStep<&'a I, D>,
    ) -> Option<()> {
        let image = *step.state.memory.image();

        // The second argument of the block decrypt function is the 128-bit key
        let key_va = step.state.registers.rdx()?;
        let key: &'a [u8; 16] =
            image.read(key_va, 16).and_then(|slice| slice[..16].try_into().ok())?;

        log::trace!("possible tea key = {key:02x?} ({key_va:x})");

        if let TeaEncryptionState::SearchingRegions((candidates, _)) = &mut self.tea_state {
            candidates.push(RegionsKeyCandidate {
                tea_block_decrypt,
                next_lea_test: 0,
                key_va,
                key,
            });
            self.search_region_candidates(image, None);
        }

        // The first argument is a pointer to an 8-byte block to decrypt in place
        // we try to match its encyrpted value with a static address using the lea map
        // to extract the full ciphertext
        let ctext_stack_va = step.state.registers.rcx().filter(|&va| va < self.init_rsp)?;
        let ctext_block = step.state.memory.read_int(ctext_stack_va, 8)?;
        let ctext_va = *self.static_lea_lookup.get(&ctext_block)?;
        let ctext_bytes = image.read(ctext_va, 8)?;

        self.tea_candidates.push(BlockTeaCandidate {
            tea_block_decrypt,
            key_va,
            key,
            ciphertext: ctext_bytes,
        });

        log::trace!("possible tea ciphertext at {ctext_va:x}");

        self.search_region_candidates(image, Some(tea_block_decrypt));
        self.search_ciphertext_candidates();
        None
    }

    fn update<I: ImageView, D: Clone>(&mut self, step: &RunStep<&'a I, D>) {
        if self.return_gadget.is_none() {
            self.return_gadget = self.extract_return_gadget(step);
            if let Some(g) = self.return_gadget.as_ref() {
                log::trace!("return gadget found: {g:x?}");
            }
        }

        // update rmx state
        self.rmx_state.update(step);

        // update sub state
        self.sub_state.update(step);

        // Track pointee values for LEA reg, [rip+...] instructions
        if step.instruction.code() == Code::Lea_r64_m
            && step.instruction.memory_base() == Register::RIP
        {
            step.state
                .virtual_address(step.instruction, 1)
                .and_then(|va| step.state.memory.read_int(va, 8).map(|m| (va, m)))
                .inspect(|&(va, mem)| {
                    self.static_lea_lookup.insert(mem, va);
                });
        }

        // Check if this instruction is a call
        let Some(call) = CallInfo::from_step(step)
        else {
            return;
        };

        // The first return we find will point to the context pop part of the stub
        if let Some(ret) = call.return_ip
            && self.context_pop_va.is_none()
        {
            self.context_pop_va = Some(ret);
        }
        // If we know the call target, analyze arguments to try to find the tea block decrypt
        // routine once found, we can use it to find the rest of the tea encryption info
        else if let Some(tgt) = call.target_ip {
            self.on_tea_info(tgt, step);
        }
    }

    fn can_stop(&self) -> bool {
        let has_encrypted_regions = matches!(self.tea_state, TeaEncryptionState::Found(_))
            || matches!(self.rmx_state, RmxEncryptionState::Found(_))
            || matches!(self.sub_state, SubEncryptionState::Found(_));

        self.context_pop_va.is_some() && self.return_gadget.is_some() && has_encrypted_regions
    }
}

/// Error encountered during the analysis of an Arxan stub.
#[derive(Debug, Clone, Copy)]
pub enum StubAnalysisError {
    /// The analyzed code at this address is not an Arxan stub.
    NotAStub(u64),
    /// The address of the context restoration part of the stub at this address was not found.
    ContextPopNotFound(u64),
    /// The maximum number of iterations (second tuple field) has been reached when analyzing the
    /// stub at this address.
    MaxStepsReached(u64, usize),
}

impl std::fmt::Display for StubAnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAStub(addr) => write!(f, "analyzed code at {addr:x} is not an Arxan stub"),

            Self::ContextPopNotFound(addr) => write!(
                f,
                "stub context restoration routine was not found for {addr:x}"
            ),
            Self::MaxStepsReached(addr, steps) => write!(
                f,
                "analysis for {addr:x} did not complete before the maximum number of steps ({steps})"
            ),
        }
    }
}

impl std::error::Error for StubAnalysisError {}

/// Analyzes Arxan stubs, producing [`StubInfo`] on success.
#[derive(Debug, Clone, Copy)]
pub struct StubAnalyzer {
    max_steps: usize,
    init_rsp: u64,
    trace_execution: bool,
}

impl Default for StubAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl StubAnalyzer {
    /// Create a new [`StubAnalyzer`] with the default configuration.
    pub fn new() -> Self {
        Self {
            max_steps: 0x100000,
            init_rsp: 0x10000,
            trace_execution: false,
        }
    }

    /// Set the maximum amount of steps the analyzer can spend visiting the stub's CFG before giving
    /// up.
    ///
    /// The default value is 2^20 which is slightly over a million steps.
    pub fn max_steps(self, max_steps: usize) -> Self {
        Self { max_steps, ..self }
    }

    /// Set the initial value of RSP used to emulate the stub.
    ///
    /// The default value is 0x10000 (2^16).
    pub fn init_rsp(self, init_rsp: u64) -> Self {
        Self { init_rsp, ..self }
    }

    /// Logging the visited stub instructions with trace level as they are emulated.
    pub fn trace_execution(self, trace_execution: bool) -> Self {
        Self {
            trace_execution,
            ..self
        }
    }

    /// Analyze an Arxan stub in the executable image `image` given the virtual address of it's
    /// `test rsp, 0xf` instruction.
    pub fn analyze(
        &self,
        image: &impl ImageView,
        test_rsp_va: u64,
    ) -> Result<StubInfo, StubAnalysisError> {
        let state = ProgramState {
            rip: Some(test_rsp_va),
            registers: Registers::new([(Register::RSP, self.init_rsp)]),
            memory: MemoryStore::new_initialized(image, [(self.init_rsp, 0x10u64.to_le_bytes())]),
            user_data: (),
        };

        let mut step_count = 0;
        let mut scan_state = StubScanState {
            init_rsp: self.init_rsp,
            ..Default::default()
        };

        let halted = ArxanCfgVisitor(state).run(|step| {
            step_count += 1;
            if step_count > self.max_steps {
                return StepKind::Stop(false);
            }

            if self.trace_execution {
                log::trace!("{}", super::vm::util::format_step_state(&step));
            }

            scan_state.update(&step);
            if scan_state.can_stop() {
                return StepKind::Stop(true);
            }

            // If exiting, we know for sure that if there was a return gadget, we saw it
            let exiting_stub = step.state.registers.rsp().is_some_and(|rsp| rsp > self.init_rsp);
            if exiting_stub {
                return StepKind::StopFork;
            }

            StepKind::SingleStep
        });
        if halted == Some(false) {
            return Err(StubAnalysisError::MaxStepsReached(
                test_rsp_va,
                self.max_steps,
            ));
        }
        else if halted.is_none() {
            log::trace!("stub {test_rsp_va:x} required a full visit");
        }

        let context_pop_va = match scan_state.context_pop_va {
            Some(va)
                // Check if first instruction is a JMP REL32 or an add rsp, [rsp+8] instruction 
                if image.read(va, 5).is_some_and(|add_rsp_bytes| {
                    add_rsp_bytes[0] == 0xe9 || &add_rsp_bytes[..5] == b"\x48\x03\x64\x24\x08"
                }) =>
            {
                va
            }
            _ => {
                log::debug!("{test_rsp_va:x} is not in an Arxan stub");
                return Err(StubAnalysisError::NotAStub(test_rsp_va))
            }
        };

        Ok(StubInfo {
            test_rsp_va,
            context_pop_va,
            return_gadget: scan_state.return_gadget,
            encrypted_regions: {
                let tea_regions = match scan_state.tea_state {
                    TeaEncryptionState::SearchingRegions(_) => None,
                    TeaEncryptionState::SearchingCiphertext(list_info) => {
                        log::trace!(
                            "stub {test_rsp_va:x}: likely integrity check routine ({} regions)",
                            list_info.encrypted_regions.len()
                        );
                        None
                    }
                    TeaEncryptionState::Found(region_list) => Some(region_list),
                };
                let rmx_regions = match scan_state.rmx_state {
                    RmxEncryptionState::Found(rlist) => Some(rlist),
                    _ => None,
                };
                let sub_regions = match scan_state.sub_state {
                    SubEncryptionState::Found(rlist) => Some(rlist),
                    _ => None,
                };
                tea_regions.or(rmx_regions).or(sub_regions)
            },
        })
    }
}
