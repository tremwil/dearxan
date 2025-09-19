//! Structs detailing code patches to indivitual Arxan stubs.

use iced_x86::IcedError;

use crate::analysis::{BadRelocsError, ImageView, StubInfo, encryption};

/// An individual patch to the executable image.
#[derive(Debug, Clone)]
pub enum ArxanPatch {
    /// Install a 32-bit jmp hook at virtual address `target` pointing to executable memory where
    /// the position-independent code `pic` has been written.
    JmpHook { target: u64, pic: Vec<u8> },
    /// Write the contents of `bytes` to the virtual address `va`.
    Write { va: u64, bytes: Vec<u8> },
}

/// Opqaue inner type for [`PatchGenError::AssemblerError`].
#[derive(Debug, Clone)]
pub struct AssemblerErrorInner(IcedError);

/// Different ways that generation of an [`ArxanPatch`] can fail.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PatchGenError {
    /// An error occured when assembling machine code for an [`ArxanPatch::JmpHook`].
    AssemblerError(AssemblerErrorInner),
    /// The patch would be writing to memory outside of the executable image.
    OutOfBounds { rva: usize, size: usize },
    /// The executable image's .reloc section is required but could not be read.
    RelocsCorrupted,
}

impl From<IcedError> for PatchGenError {
    fn from(value: IcedError) -> Self {
        Self::AssemblerError(AssemblerErrorInner(value))
    }
}

impl From<BadRelocsError> for PatchGenError {
    fn from(_value: BadRelocsError) -> Self {
        Self::RelocsCorrupted
    }
}

impl std::fmt::Display for PatchGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AssemblerError(AssemblerErrorInner(iced)) => {
                write!(f, "assembly error: {iced}")
            }
            Self::OutOfBounds { rva, size } => {
                write!(
                    f,
                    "write of {size} bytes to RVA 0x{rva:x} is not within the executable image"
                )
            }
            Self::RelocsCorrupted => {
                write!(f, ".relocs section is corrupted and could not be read")
            }
        }
    }
}

impl std::error::Error for PatchGenError {}

impl ArxanPatch {
    /// Generate the required patches to disable Arxan given `analyzed_stubs` extracted from
    /// the executable image `image`, e.g. through
    /// [`analyze_all_stubs`](super::analysis::analyze_all_stubs)
    ///
    /// If `image` was mapped at a different address to its preferred base address,
    /// relocations may need to be applied to some of the patches. In that case `preferred_base`
    /// must be provided.
    pub fn build_from_stubs<
        'a,
        #[cfg(feature = "rayon")] I: ImageView + Sync,
        #[cfg(not(feature = "rayon"))] I: ImageView,
    >(
        image: I,
        preferred_base: Option<u64>,
        analyzed_stubs: impl IntoIterator<Item = &'a StubInfo>,
    ) -> Result<Vec<Self>, PatchGenError> {
        let analyzed_stubs = analyzed_stubs.into_iter();

        let mut hooks = Vec::with_capacity(analyzed_stubs.size_hint().0);
        let mut error = None;
        let final_rlists = encryption::apply_relocs_and_resolve_conflicts(
            analyzed_stubs.filter_map(|si| {
                hooks.push(ArxanPatch::JmpHook {
                    target: si.test_rsp_va,
                    pic: match assemble_stub_patch(si) {
                        Ok(pic) => pic,
                        Err(e) => {
                            error = Some(e);
                            return None;
                        }
                    },
                });
                si.encrypted_regions.as_ref()
            }),
            &image,
            preferred_base,
        )?;
        if let Some(e) = error {
            return Err(e.into());
        }

        let base_va = image.base_va();

        let patches = final_rlists
            .into_iter()
            .flat_map(|rlist| {
                rlist.regions.into_iter().map(move |r| ArxanPatch::Write {
                    va: base_va + r.rva as u64,
                    bytes: rlist.decrypted_stream[r.stream_offset..r.stream_offset + r.size]
                        .to_owned(),
                })
            })
            .chain(hooks)
            .collect();

        Ok(patches)
    }
}

fn assemble_stub_patch(stub: &StubInfo) -> Result<Vec<u8>, IcedError> {
    use iced_x86::{Code, Instruction, MemoryOperand, Register::*};

    let mut instructions = Vec::with_capacity(8);

    // Write a pointer to our own return gadget to the low slot
    if let Some(rg) = &stub.return_gadget {
        let rg_low = MemoryOperand::with_base_displ(RSP, rg.stack_offset as i64 - 16);
        // Will point to the our own return gadget
        let ret_stub_ref = MemoryOperand::with_base_displ(RIP, 1);
        instructions.extend([
            Instruction::with2(Code::Lea_r64_m, RAX, ret_stub_ref)?,
            Instruction::with2(Code::Mov_rm64_r64, rg_low, RAX)?,
        ]);
    }

    // Adjust stack and jump to context restore
    instructions.extend([
        Instruction::with2(Code::Sub_rm64_imm8, RSP, 8)?,
        Instruction::with2(Code::Mov_r64_imm64, RAX, stub.context_pop_va)?,
        Instruction::with1(Code::Jmp_rm64, RAX)?,
    ]);

    // Write our own return gadget -- adds 16 to rsp and jumps to the top one directly
    if let Some(rg) = &stub.return_gadget {
        let mut add_rsp = Instruction::with2(Code::Add_rm64_imm8, RSP, 16)?;
        add_rsp.set_ip(1);

        let mut dq_rg_address = Instruction::with_declare_qword_1(rg.address);
        dq_rg_address.set_ip(2);

        let rg_address_ref = MemoryOperand::with_base_displ(RIP, 2);
        let jmp_rg = Instruction::with1(Code::Jmp_rm64, rg_address_ref)?;

        instructions.extend([add_rsp, jmp_rg, dq_rg_address]);
    }

    let block = iced_x86::InstructionBlock::new(&instructions, 0);
    Ok(iced_x86::BlockEncoder::encode(64, block, iced_x86::BlockEncoderOptions::NONE)?.code_buffer)
}
