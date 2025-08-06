//! Structs detailing code patches to indivitual Arxan stubs.

use fxhash::FxHashMap;
use iced_x86::IcedError;

use crate::analysis::{EncryptedRegionList, ImageView, StubInfo, shannon_entropy};

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
    pub fn build_from_stubs<'a, I: ImageView>(
        image: I,
        preferred_base: Option<u64>,
        analyzed_stubs: impl IntoIterator<Item = &'a StubInfo>,
    ) -> Result<Vec<Self>, PatchGenError> {
        let analyzed_stubs = analyzed_stubs.into_iter();

        let mut decrypt_conflicts: FxHashMap<u32, Vec<&EncryptedRegionList>> = FxHashMap::default();
        let mut patches = Vec::with_capacity(analyzed_stubs.size_hint().0);

        for stub in analyzed_stubs {
            if let Some(rlist) = &stub.encrypted_regions
                && let Some(r) = rlist.regions.first()
            {
                decrypt_conflicts.entry(r.rva).or_default().push(rlist)
            }
            patches.push(ArxanPatch::JmpHook {
                target: stub.test_rsp_va,
                pic: assemble_stub_patch(stub)?,
            })
        }

        let actual_base = image.base_va();
        let mut writes = Vec::with_capacity(decrypt_conflicts.len());

        for conflicts in decrypt_conflicts.values() {
            // Get the region list that doesn't match existing bytes with the lowest Shannon entropy
            let Some(&rlist) = conflicts
                .iter()
                .filter(|rlist| {
                    rlist.regions.first().is_some_and(|r| {
                        image.read(actual_base + r.rva as u64, r.size) != r.decrypted_slice(rlist)
                    })
                })
                .min_by_key(|r| (shannon_entropy(&r.decrypted_stream) * 10e6) as i64)
            else {
                continue;
            };
            // Make sure that all regions in the list are within the image
            if let Some(r) = rlist
                .regions
                .iter()
                .find(|r| image.read(actual_base + r.rva as u64, r.size).is_none())
            {
                return Err(PatchGenError::OutOfBounds {
                    rva: r.rva as usize,
                    size: r.size,
                });
            }
            // Collect all contiguous writes together
            writes.extend(
                rlist
                    .regions
                    .iter()
                    .map(|r| (r.rva, r.decrypted_slice(rlist).unwrap().to_owned())),
            );
        }

        // Handle relocs to decrypted regions, if necessary
        match preferred_base {
            Some(preferred) /* if preferred != actual_base */ => {
                // Use a mergesort like pass to match regions with their relocs
                writes.sort_by_key(|(rva, _)| *rva);

                // Usually, PE relocs are in the right order, but we don't guarantee this
                let mut relocs: Vec<_> =
                    image.relocs64().map_err(|_| PatchGenError::RelocsCorrupted)?.collect();
                relocs.sort();

                let reloc_offset = actual_base.wrapping_sub(preferred);
                let mut i_reloc = relocs.into_iter().peekable();
                for (rva, mut bytes) in writes {
                    while let Some(reloc) = i_reloc.next_if(|r| r + 8 <= rva + bytes.len() as u32) {
                        let Some(offset) = reloc.checked_sub(rva).map(|r| r as usize)
                        else {
                            continue;
                        };
                        let target_bytes = &mut bytes[offset..offset + 8];
                        let target: u64 = bytemuck::pod_read_unaligned(target_bytes);
                        let adjusted = target.wrapping_add(reloc_offset);
                        target_bytes.copy_from_slice(bytemuck::bytes_of(&adjusted));
                        log::trace!("applied reloc at {:x} (in patch at rva {:x})", reloc, rva)
                    }
                    patches.push(ArxanPatch::Write {
                        va: actual_base + rva as u64,
                        bytes,
                    })
                }
            }
            _ => patches.extend(writes.into_iter().map(|(rva, bytes)| ArxanPatch::Write {
                va: actual_base + rva as u64,
                bytes,
            })),
        }

        // Create a write patch for every reloc in the exe
        // TODO: Use a mergesort like algorithm to intersect decrypted regions and relocs

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
