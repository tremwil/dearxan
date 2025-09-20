//! Algorithms and data structures used to deal with Arxan's at-rest encryption of game functions
//! and data.
//!
//! Given a a function or some other not-necessarily-contiguous static data, Arxan may
//! be used to encrypt it at rest to make reverse engineering harder. Such encrypted regions can
//! then be dynamically decrypted whenever the data/code is needed and re-"encrypted" immediately
//! afterwards.
//!
//! The result of this process is the creation of two function-like Arxan stubs: one is called
//! before the code/data needs to be accessed, and the other after to replace it with garbage bytes.
//!
//! There are two types of Arxan encryption: TEA and RMX (rotate-multiply-xor).
//!
//! Stubs of both types first recover a list of (offset, size) pairs, each
//! representing a contiguous region to be decrypted. These pairs are encoded as 7-bit
//! variable-length integers (varints) where the high bit is used as a terminator, and the initial
//! offset is the base of the executable image. A running offset of [`u32::MAX`] indicates the end
//! of the list. TEA stubs encrypt this offset list using TEA with a per-stub hardcoded key.
//!
//!
//! The ciphertext for these regions is stored as a single contiguous blob, encrypted with either
//! TEA or RMX (in both cases using a hardcoded key). After a region is parsed from the varint list,
//! the corresponding ciphertext bytes will be decrypted and copied to it.
//!
//! The "encryption" process is exactly the same, except that the ciphertext used decrypts to random
//! garbage bytes. These bytes seem to be uniformly distributed and can thus be effectively
//! identified by calculating their Shannon entropy. In fact, when an "encryption" stub is
//! instantiated across multiple translation units, different random bytes are used.
//!
//! The static data structures described above are modeled through the [`EncryptedRegion`] and
//! [`EncryptedRegionList`] types.

use std::{
    io::{self, Read},
    marker::PhantomData,
};

use crate::analysis::{ImageView, vm::image::BadRelocsError};

/// Abstraction over a decryption algorithm operating in fixed-size blocks.
pub trait Decryptor {
    /// The cipher's block type (e.g. `[u32; 2]` for TEA).
    type Block: bytemuck::Pod;

    /// Decrypt a single block in place, updating the decryptor's state.
    fn decrypt(&mut self, block: &mut Self::Block);
}

/// [`Decryptor`] wrapper which decrypts an arbitrary [`io::Read`] stream.
pub struct DecryptReader<R: Read, D: Decryptor> {
    reader: R,
    decryptor: D,
    block_buffer: D::Block,
    consumed: usize,
}

impl<R: Read, D: Decryptor> DecryptReader<R, D> {
    const BLOCK_SIZE: usize = size_of::<D::Block>();

    /// Create a [`DecryptReader`] from an [`io::Read`] implementationa and a decryptor.
    pub fn new(reader: R, decryptor: D) -> Self {
        Self {
            reader,
            decryptor,
            block_buffer: bytemuck::Zeroable::zeroed(),
            consumed: size_of::<D::Block>(),
        }
    }
}

impl<R: Read, D: Decryptor> Read for DecryptReader<R, D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.consumed == Self::BLOCK_SIZE {
            self.reader.read_exact(bytemuck::bytes_of_mut(&mut self.block_buffer))?;
            self.decryptor.decrypt(&mut self.block_buffer);
            self.consumed = 0;
        }

        let to_read = (Self::BLOCK_SIZE - self.consumed).min(buf.len());
        buf[..to_read].copy_from_slice(
            &bytemuck::bytes_of(&self.block_buffer)[self.consumed..self.consumed + to_read],
        );
        self.consumed += to_read;
        Ok(to_read)
    }
}

/// wrapper around a block decrypt function that implements [`Decryptor`].
pub struct FnDecryptor<B: bytemuck::Pod, F: FnMut(&mut B)>(F, PhantomData<fn(&mut B)>);

impl<B: bytemuck::Pod, F: FnMut(&mut B)> FnDecryptor<B, F> {
    pub fn new(fun: F) -> Self {
        Self(fun, PhantomData)
    }
}

impl<B: bytemuck::Pod, F: FnMut(&mut B)> Decryptor for FnDecryptor<B, F> {
    type Block = B;

    fn decrypt(&mut self, block: &mut Self::Block) {
        self.0(block)
    }
}

/// Encryption algorithms used by Arxan to obfuscate static data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArxanDecryptionKind {
    /// Standard 32-round TEA.
    Tea,
    /// Custom rotate-multiply-xor algorithm.
    Rmx,
    /// Simple subtraction from a constant.
    Sub,
}

/// 32-round TEA (Tiny Encryption Algorithm) decryptor.
pub fn tea_decryptor(key: &[u8; 16]) -> impl Decryptor<Block = [u32; 2]> {
    let key: [u32; 4] = bytemuck::pod_read_unaligned(key);
    FnDecryptor::new(move |block: &mut [u32; 2]| {
        const NUM_ROUNDS: u32 = 32;
        const DELTA: u32 = 0x9E3779B9;
        let mut sum = 0xC6EF3720;

        fn fiestel_round(b1: u32, b2: &mut u32, k1: u32, k2: u32, sum: u32) {
            let k1_term = (b1 << 4).wrapping_add(k1) ^ b1.wrapping_add(sum);
            let k2_term = (b1 >> 5).wrapping_add(k2);
            *b2 = b2.wrapping_sub(k1_term ^ k2_term);
        }

        for _ in 0..NUM_ROUNDS {
            fiestel_round(block[0], &mut block[1], key[2], key[3], sum);
            fiestel_round(block[1], &mut block[0], key[0], key[1], sum);
            sum = sum.wrapping_sub(DELTA);
        }
    })
}

/// Rotate-multiply-xor decryptor.
///
/// This algorithm seems to have been invented by the Arxan developers. It is reminiscent of ARX
/// ciphers, but uses multiplication. Its cryptographic security seems poor.
pub fn rmx_decryptor(mut key: u32) -> impl Decryptor<Block = u32> {
    let mut key_rot = key & 0x1f;

    FnDecryptor::new(move |block: &mut u32| {
        key = key.rotate_left(key_rot);
        *block = block.wrapping_sub(key.wrapping_mul(key_rot));
        key_rot ^= !*block;
    })
}

/// Subtraction decryptor.
///
/// This is more obfuscation than encryption. Blocks of 4 bytes are subtracted from a constant
/// "key".
pub fn sub_decryptor(key: u32) -> impl Decryptor<Block = u32> {
    FnDecryptor::new(move |block| *block = key.wrapping_sub(*block))
}

/// Try to parse a 32-bit unsigned integer encoded as a varint.
///
/// On success, returns the decoded number.
pub fn try_read_varint(mut reader: impl io::Read) -> io::Result<u32> {
    let mut result = 0u32;
    let mut num_read = 0u32;

    let mut b = 0u8;
    loop {
        reader.read_exact(std::slice::from_mut(&mut b))?;

        result = (b as u32 & 0x7F)
            .checked_shl(7 * num_read)
            .and_then(|s| result.checked_add(s))
            .ok_or(io::ErrorKind::InvalidData)?;

        num_read += 1;

        if b < 0x80 {
            return Ok(result);
        }
    }
}

/// A contiguous region of bytes encrypted by Arxan.
///
/// See the module-level documentation for more information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncryptedRegion {
    /// Offset of the plaintext for this region in the decrypted byte stream.
    pub stream_offset: usize,
    /// The size of the region.
    pub size: usize,
    /// The relative virtual address of the region.
    pub rva: u32,
}

impl EncryptedRegion {
    /// Return the decrypted slice of bytes corresponding to this region, borrowing the bytes
    /// from its parent [`EncryptedRegionList`].
    ///
    /// Will always return [`Some`] if `list` is the actual parent.
    pub fn decrypted_slice<'a>(&self, list: &'a EncryptedRegionList) -> Option<&'a [u8]> {
        list.decrypted_stream.get(self.stream_offset..self.stream_offset + self.size)
    }

    /// Try to extract a list of encrypted regions from a stream of varint-encoded offset size
    /// pairs.
    ///
    /// See the module-level documentation for more information.
    pub fn try_from_varints(mut reader: impl Read) -> io::Result<Vec<Self>> {
        let mut regions = Vec::new();

        let mut rva = 0u32;
        let mut stream_offset = 0usize;

        // as an optimization to cut down the time before an error
        // for false positives, disallow zero offsets/sizes
        loop {
            let offset = try_read_varint(&mut reader)?;
            if offset == 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }

            rva = rva.checked_add(offset).ok_or(io::ErrorKind::InvalidData)?;
            if rva == u32::MAX {
                return Ok(regions);
            }

            let size = try_read_varint(&mut reader)?;
            if size == 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }

            regions.push(Self {
                stream_offset,
                size: size as usize,
                rva,
            });
            rva = rva.checked_add(size).ok_or(io::ErrorKind::InvalidData)?;
            stream_offset += size as usize;
        }
    }

    pub fn intersects(&self, other: &EncryptedRegion) -> bool {
        let end = self.rva as usize + self.size;
        let other_end = other.rva as usize + other.size;

        end.min(other_end) > self.rva.max(other.rva) as usize
    }
}

/// A list of contiguous regions encrypted by Arxan using the same TEA key paired with the decrypted
/// plaintext for said regions.
///
/// See the module-level documentation for more details.
#[derive(Debug, Clone)]
pub struct EncryptedRegionList {
    pub kind: ArxanDecryptionKind,
    pub regions: Vec<EncryptedRegion>,
    pub decrypted_stream: Vec<u8>,
}

impl EncryptedRegionList {
    /// Return the number of encrypted regions in this list.
    ///
    /// Shorthand for `self.regions.len()`.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Return true if this encrypted region list is empty.
    ///
    /// Shorthand for `self.regions.is_empty()`.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    pub fn try_new(
        kind: ArxanDecryptionKind,
        regions: Vec<EncryptedRegion>,
        mut decrypted_stream: impl Read,
    ) -> io::Result<Self> {
        let ctext_len = regions.last().map(|r| r.stream_offset + r.size).unwrap_or(0);

        let mut plaintext = vec![0; ctext_len];
        decrypted_stream.read_exact(&mut plaintext)?;

        Ok(Self {
            kind,
            regions,
            decrypted_stream: plaintext,
        })
    }
}

/// Compute the Shannon entropy of a sequence of bytes.
///
/// This is useful to discriminate between non-random and random data, provided its length is
/// sufficient.
pub fn shannon_entropy(bytes: impl IntoIterator<Item = u8>) -> f64 {
    let mut byte_dist = [0usize; 256];
    let mut len = 0;
    for b in bytes {
        byte_dist[b as usize] += 1;
        len += 1;
    }

    let len_log2 = (len as f64).log2();
    // -sum b/N * log2(b/N) = 1/N sum b(log2 N - log2 b)
    let plogp_sum: f64 = byte_dist
        .into_iter()
        .filter(|&b| b != 0)
        // rust-analyzer reports an error without the type hint (but not rustc)
        .map(|b: usize| (b as f64) * (len_log2 - (b as f64).log2()))
        .sum();

    plogp_sum / (len as f64)
}

/// Apply relocs and resolve conflicts between many [`EncryptedRegionList`].
///
/// Conflict resolution is based on Shannon entropy. The region lists with lowest entropy
/// are assumed to represent decrypted bytes, while any conflicting region is assumed to be
/// "encrypted".
pub fn apply_relocs_and_resolve_conflicts<
    'a,
    #[cfg(feature = "rayon")] I: ImageView + Sync,
    #[cfg(not(feature = "rayon"))] I: ImageView,
>(
    region_lists: impl IntoIterator<Item = &'a EncryptedRegionList>,
    image: I,
    preferred_base: Option<u64>,
) -> Result<Vec<EncryptedRegionList>, BadRelocsError> {
    #[cfg(feature = "rayon")]
    use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};

    let base_va = image.base_va();

    struct ProcessedRegionList {
        rlist: EncryptedRegionList,
        entropy: f64,
        base_entropy: f64,
        eliminated: bool,
    }

    struct ContiguousRegion {
        rlist_index: usize,
        region: EncryptedRegion,
    }

    let sorted_relocs = {
        let mut relocs: Vec<_> = image.relocs64()?.collect();
        relocs.sort();
        relocs
    };

    let region_lists = region_lists.into_iter();
    let mut processed = Vec::with_capacity(region_lists.size_hint().0);
    let mut contiguous_regions = Vec::with_capacity(processed.capacity());

    // Compute the image entropy for each non-empty region list
    for rlist in region_lists.filter(|r| !r.is_empty()) {
        let index = processed.len();
        processed.push(ProcessedRegionList {
            entropy: 0.0,
            base_entropy: 0.0,
            rlist: rlist.clone(),
            eliminated: false,
        });

        contiguous_regions.extend(rlist.regions.iter().map(|r| ContiguousRegion {
            rlist_index: index,
            region: r.clone(),
        }));
    }

    // sort contiguous regions by increasing rva and size
    // will make applying relocs and handling collisions faster
    contiguous_regions.sort_by_key(|r| (r.region.rva, r.region.size));

    // apply relocs using single pass through the sorted relocs array
    // also use relocs to eliminate encrypted regions
    let pref_base = preferred_base.unwrap_or(base_va);
    let base_diff = base_va.wrapping_sub(pref_base);
    let mut crel = sorted_relocs.iter().copied().peekable();

    for r in &contiguous_regions {
        let parent = &mut processed[r.rlist_index];
        if parent.eliminated {
            continue;
        }

        // skip earlier relocs and stop if we exhausted them
        while crel.next_if(|&reloc| reloc < r.region.rva).is_some() {}
        if crel.peek().is_none() {
            break;
        }

        let region_end = r.region.rva + r.region.size as u32;
        for reloc in crel.clone().take_while(|&r| r + 8 <= region_end) {
            let offset = (reloc - r.region.rva) as usize + r.region.stream_offset;
            let reloc_area: &mut [u8; 8] =
                (&mut parent.rlist.decrypted_stream[offset..offset + 8]).try_into().unwrap();

            let relocated = u64::from_le_bytes(*reloc_area).wrapping_add(base_diff);
            if image.read(relocated, 1).is_none() {
                log::trace!("rlist {} eliminated using relocs", r.rlist_index);
                parent.eliminated = true;
                break;
            }

            *reloc_area = relocated.to_le_bytes();
        }
    }

    #[cfg(not(feature = "rayon"))]
    let not_eliminated = processed.iter_mut().filter(|p| !p.eliminated);
    #[cfg(feature = "rayon")]
    let not_eliminated = processed.par_iter_mut().filter(|p| !p.eliminated);

    // now that relocs have been applied, compute entropies on non-eliminated rlists
    // this is worth doing in parallel
    not_eliminated.for_each(|p| {
        let base_bytes_iter = p.rlist.regions.iter().flat_map(|r| {
            image
                .read(base_va + r.rva as u64, r.size)
                .map_or(&[] as &[u8], |s| &s[..r.size])
        });
        p.base_entropy = shannon_entropy(base_bytes_iter.copied());
        p.entropy = shannon_entropy(p.rlist.decrypted_stream.iter().copied());
        p.eliminated = p.entropy >= p.base_entropy;

        if !p.eliminated {
            log::trace!(
                "kind = {:?} rva = {:08x} base_entropy = {:.03} entropy = {:.03} len = {}",
                p.rlist.kind,
                p.rlist.regions[0].rva,
                p.base_entropy,
                p.entropy,
                p.rlist.decrypted_stream.len()
            );
        }
    });

    // use sorted contiguous regions to find intersections between region lists and eliminate
    // conflicting ones with high shannon entropy
    if let Some(i) = contiguous_regions.iter().position(|r| !processed[r.rlist_index].eliminated) {
        let mut best = &contiguous_regions[i];
        for r in contiguous_regions.get(i + 1..).unwrap_or(&[]) {
            let Ok([r_rlist, best_rlist]) =
                processed.get_disjoint_mut([r.rlist_index, best.rlist_index])
            else {
                // if not disjoint then they have the same rlist and don't intersect
                best = r;
                continue;
            };
            if r_rlist.eliminated {
                continue;
            }
            if !best.region.intersects(&r.region) {
                best = r;
                continue;
            }
            if best_rlist.entropy > r_rlist.entropy {
                best_rlist.eliminated = true;
                best = r;
            }
            else {
                r_rlist.eliminated = true;
            }
        }
    };

    Ok(processed
        .into_iter()
        .filter_map(|p| (!p.eliminated).then_some(p.rlist))
        .collect())
}
