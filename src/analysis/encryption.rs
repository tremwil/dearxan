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
//! To achieve this, the stubs first use the
//! [Tiny Encryption Algorithm](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) (TEA)
//! with a per-stub hardcoded key to decrypt a variable-length list of (offset, size) pairs, each
//! representing a contiguous region to be decrypted. These pairs are encoded as 7-bit
//! variable-length integers (varints) where the high bit is used as a terminator, and the initial
//! offset is the base of the executable image. A running offset of [`u32::MAX`] indicates the end
//! of the list.
//!
//! The ciphertext for these regions is stored as a single contiguous blob, encrypted using a
//! different per-stub hardcoded key. After a region is parsed from the varint list, the
//! corresponding ciphertext bytes will be decrypted and copied to it.
//!
//! The "encryption" process is exactly the same, except that the ciphertext used decrypts to random
//! garbage bytes. These bytes seem to be uniformly distributed and can thus be effectively
//! identified by calculating their Shannon entropy. In fact, when an "encryption" stub is
//! instantiated across multiple translation units, different random bytes are used.
//!
//! The static data structures described above are modeled through the [`EncryptedRegion`] and
//! [`EncryptedRegionList`] types.

use std::io::{self, Read};

/// Compute the Shannon entropy of a slice of bytes.
///
/// This is useful to discriminate between non-random and random data, provided its length is
/// sufficient.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut byte_dist = [0usize; 256];
    bytes.iter().for_each(|&b| byte_dist[b as usize] += 1);

    let len_log2 = (bytes.len() as f64).log2();
    // -sum b/N * log2(b/N) = 1/N sum b(log2 N - log2 b)
    let plogp_sum: f64 = byte_dist
        .into_iter()
        .filter_map(|b| (b != 0).then(|| b as f64))
        .map(|b| b * (len_log2 - b.log2()))
        .sum();

    plogp_sum / (bytes.len() as f64)
}

/// Decrypt a single block of 8 bytes that was encrypted using 32-round TEA.
pub fn tea_block_decrypt(block: &mut [u32; 2], key: &[u32; 4]) {
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
}

/// Decrypt a slice that was encrypted using 32-round TEA.
///
/// The length of the slice does not need to be a multiple of 8 (the TEA block size). However, if an
/// incomplete block is present, it will not be decrypted.
pub fn tea_decrypt(bytes: &mut [u8], key: &[u8; 16]) {
    let local_key: [u32; 4] = bytemuck::cast(*key);
    for chunk in bytes.chunks_exact_mut(8) {
        let mut local_block: [u32; 2] = bytemuck::pod_read_unaligned(chunk);
        tea_block_decrypt(&mut local_block, &local_key);
        chunk.copy_from_slice(bytemuck::bytes_of(&local_block));
    }
}

/// Error type which may be raised when reading a 32-bit varint-encoded integer.
pub enum VarintError {
    /// The varint does not fit within an unsigned 32-bit integer.
    Overflow,
    /// No stop bit was read before the end of the byte slice.
    NoStopBit,
}

/// Try to parse a 32-bit unsigned integer encoded as a varint.
///
/// On success, returns both the decoded number and the amount of bytes read.
pub fn try_read_varint(bytes: &[u8]) -> Result<(u32, usize), VarintError> {
    let mut result = 0u32;
    let mut num_read = 0u32;

    for &b in bytes {
        result = (b as u32 & 0x7F)
            .checked_shl(7 * num_read)
            .and_then(|s| result.checked_add(s))
            .ok_or(VarintError::Overflow)?;

        num_read += 1;

        if b < 0x80 {
            return Ok((result, num_read as usize));
        }
    }
    Err(VarintError::NoStopBit)
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
    pub fn decrypted_slice<'a>(&self, list: &'a EncryptedRegionList) -> Option<&'a [u8]> {
        list.decrypted_stream.get(self.stream_offset..self.stream_offset + self.size)
    }

    /// Try to extract a list of encrypted regions from the encrypted varint-encoded offset size
    /// pairs.
    ///
    /// See the module-level documentation for more information.
    pub fn try_decrypt_list(encrypted_varints: &[u8], key: &[u8; 16]) -> Option<Vec<Self>> {
        let mut regions = Vec::new();

        let mut decoded_varints = Vec::new();
        let mut cursor = 0;
        let mut rva = 0u32;
        let mut stream_offset = 0usize;

        let key_local = bytemuck::cast(*key);
        'outer: for block in encrypted_varints.chunks_exact(8) {
            let mut block: [u32; 2] = bytemuck::pod_read_unaligned(block);
            tea_block_decrypt(&mut block, &key_local);
            decoded_varints.extend_from_slice(bytemuck::bytes_of(&block));

            log::trace!("block: {:08x?}", block);

            loop {
                let (offset, offset_size) = match try_read_varint(&decoded_varints[cursor..]) {
                    Ok((o, s)) => (o, s),
                    Err(VarintError::Overflow) => break 'outer,
                    Err(VarintError::NoStopBit) => break,
                };
                if rva.checked_add(offset) == Some(u32::MAX) {
                    return Some(regions);
                }

                let (size, size_size) =
                    match try_read_varint(&decoded_varints[cursor + offset_size..]) {
                        Ok((o, s)) => (o, s),
                        Err(VarintError::Overflow) => break 'outer,
                        Err(VarintError::NoStopBit) => break,
                    };
                cursor += offset_size + size_size;

                rva = rva.checked_add(offset)?;

                regions.push(Self {
                    stream_offset,
                    size: size as usize,
                    rva,
                });

                rva = rva.checked_add(size)?;
                stream_offset += size as usize;
            }
        }

        None
    }
}

/// A list of contiguous regions encrypted by Arxan using the same TEA key paired with the decrypted
/// plaintext for said regions.
///
/// See the module-level documentation for more details.
#[derive(Debug, Clone)]
pub struct EncryptedRegionList {
    pub regions: Vec<EncryptedRegion>,
    pub decrypted_stream: Vec<u8>,
}

impl EncryptedRegionList {
    pub fn try_new(
        regions: Vec<EncryptedRegion>,
        mut ciphertext: impl Read,
        key: &[u8; 16],
    ) -> io::Result<Self> {
        let ctext_len = regions.last().map(|r| r.stream_offset + r.size).unwrap_or(0);

        let mut decrypted_stream = vec![0; ctext_len.next_multiple_of(8)];
        ciphertext.read(&mut decrypted_stream)?;
        tea_decrypt(&mut decrypted_stream, key);
        decrypted_stream.truncate(ctext_len);

        Ok(Self {
            regions,
            decrypted_stream,
        })
    }
}
