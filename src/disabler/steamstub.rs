//! Provides utilities to hook around SteamStub V3.1 (as versionned by Steamless).
//!
//! SteamStub is used in DS2, DS3 and SDT. We must hook around it to be able to extract
//! the binary's original entry point (which in DS3's case will be the Arxan entry point)
//! to then apply the arxan patches on that one.
//!
//! Detouring SteamStub is fairly straightforward. The structure of a stubbed entry point
//! is as follows:
//!
//! ```x86asm
//! CALL steamstub_entry
//! steamstub_entry:
//! {push general purpose registers}
//! {align RSP}
//! CALL steamstub_main
//! {write RAX to call return address}
//! {pop general purpose registers}
//! RET
//! ```
//!
//! `steamstub_main` performs code integrity checks, so we can't simply hook it.
//! However, we can do the following:
//! 1. Hook at the first CALL
//! 2. Follow `steamstub_entry` until we get to the second call
//! 3. Call it ourselves with the usual MSVC x64 calling convention
//! 4. We now have the original (Arxan) entry point as the return value!
//!
//! Which makes it quite easy to work around.

use std::sync::atomic::{AtomicBool, Ordering};

use closure_ffi::BareFnOnce;
use pelite::pe64::{Pe, PeView};

use super::{game::game, util};

#[derive(Default, Debug, Clone, Copy)]
struct SteamDrmHasher {
    hash: u32,
}

impl SteamDrmHasher {
    fn write(&mut self, bytes: &[u8]) {
        const SCRAMBLE: u32 = 0x488781ed;

        for &b in bytes {
            self.hash ^= (b as u32) << 0x18;
            for _ in 0..8 {
                if self.hash & 0x8000_0000 == 0 {
                    self.hash <<= 1;
                }
                else {
                    self.hash = (self.hash << 1) ^ SCRAMBLE;
                }
            }
        }
    }

    fn finish(&self) -> u32 {
        self.hash
    }
}

#[bitfield_struct::bitfield(u32)]
struct SteamDrmFlags {
    _unused_0: bool,
    no_module_verification: bool,
    no_encryption: bool,
    _unused_1: bool,
    no_ownership_check: bool,
    no_debugger_check: bool,
    no_error_dialog: bool,
    #[bits(25)]
    _unused_2: u32,
}

impl SteamDrmFlags {
    pub fn clear_protection_flags(&mut self) {
        self.set_no_module_verification(true);
        self.set_no_ownership_check(true);
        self.set_no_debugger_check(true);
    }
}

/// SteamStub 3.1 header data.
///
/// Derived from atom0s's [Steamless](https://github.com/atom0s/Steamless/blob/master/Steamless.Unpacker.Variant31.x64/Classes/SteamStubHeader.cs)
/// source code, with additional fields reversed.
#[repr(C)]
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
struct SteamStubHeader {
    xor_key: u32,
    signature: u32,
    image_base: u64,
    steamstub_entry_point: u64,
    bind_section_ep_offset: u32,
    steamstub_ep_code_size: u32,
    original_entry_point: u64,
    strings_bind_offset: u32,
    strings_data_size: u32,
    drmp_dll_bind_offset: u32,
    drmp_dll_size: u32,
    steam_app_id: u32,
    drm_flags: SteamDrmFlags,
    bind_section_virtual_size: u32,
    integrity_hash: u32,
    code_section_virtual_address: u64,
    code_section_size: u64,
    aes_key: [u8; 32],
    aes_iv: [u8; 16],
    code_section_bytes: [u8; 16],
    drmp_xtea_key: [u32; 4],
    unk_a8: [u32; 8],
    get_module_handle_a_rva: u64,
    get_module_handle_w_rva: u64,
    load_library_a_rva: u64,
    load_library_w_rva: u64,
    get_proc_address_rva: u64,
}

unsafe impl bytemuck::Zeroable for SteamStubHeader {}
unsafe impl bytemuck::Pod for SteamStubHeader {}
unsafe impl pelite::Pod for SteamStubHeader {}

struct SteamStubContext<'a> {
    header: SteamStubHeader,
    decrypted_drmp_dll: Vec<u8>,
    decrypted_strings: Vec<u8>,
    encrypted_header: &'a SteamStubHeader,
    encrypted_strings: &'a [u8],
    pe: PeView<'a>,
}

impl<'a> SteamStubContext<'a> {
    fn from_pe_inner(
        pe: PeView<'a>,
        encrypted_header: &'a SteamStubHeader,
    ) -> pelite::Result<Self> {
        let mut header = *encrypted_header;
        let strings_table_key = header.decrypt();

        Ok(Self {
            encrypted_strings: header.strings(pe)?,
            decrypted_strings: header.decrypt_strings(pe, strings_table_key)?,
            decrypted_drmp_dll: header.decrypt_drmp_dll(pe)?,
            encrypted_header,
            header,
            pe,
        })
    }

    pub fn from_pe(pe: PeView<'a>) -> Option<pelite::Result<Self>> {
        Some(Self::from_pe_inner(
            pe,
            SteamStubHeader::from_pe_encrypted(pe)?,
        ))
    }

    /// Recompute the steamstub integrity hash.
    pub fn recompute_hash(&mut self) -> pelite::Result<u32> {
        let code_rva = self.pe.optional_header().AddressOfEntryPoint;
        let aligned_ep_code_size = self.header.steamstub_ep_code_size.next_multiple_of(16) as usize;

        let mut hasher = SteamDrmHasher::default();
        self.header.integrity_hash = 0;

        hasher.write(&self.decrypted_strings);
        hasher.write(bytemuck::bytes_of(&self.header));
        hasher.write(self.pe.derva_slice(code_rva, aligned_ep_code_size)?);
        hasher.write(&self.decrypted_drmp_dll);

        self.header.integrity_hash = hasher.finish();
        Ok(self.header.integrity_hash)
    }

    /// Re-encrypt the header and strings table.
    pub fn re_encrypt(&self) -> (SteamStubHeader, Vec<u8>) {
        let mut encrypted = self.header;
        let mut encrypted_strings = self.decrypted_strings.clone();

        let mut key = 0;
        for block in bytemuck::cast_slice_mut(bytemuck::bytes_of_mut(&mut encrypted)) {
            *block ^= key;
            key = *block;
        }
        for block in encrypted_strings.chunks_exact_mut(4) {
            let new_block = bytemuck::pod_read_unaligned::<u32>(block) ^ key;
            block.copy_from_slice(bytemuck::bytes_of(&new_block));
            key = new_block;
        }

        (encrypted, encrypted_strings)
    }
}

impl SteamStubHeader {
    const EXPECTED_SIGNATURE: u32 = 0xC0DEC0DF;

    /// Reads the encrypted SteamStub header from a PE file SteamStub was applied to.
    ///
    /// To decrypt the header, make a copy and call [`Self::decrypt`].
    pub fn from_pe_encrypted(pe: PeView<'_>) -> Option<&Self> {
        const HEADER_SIZE: u32 = size_of::<SteamStubHeader>() as u32;

        let entry_rva = pe.optional_header().AddressOfEntryPoint;
        let encrypted: &Self = pe.derva(entry_rva - HEADER_SIZE).ok()?;
        (encrypted.xor_key ^ encrypted.signature == Self::EXPECTED_SIGNATURE).then_some(encrypted)
    }

    /// Decrypts the header, leaving the original XOR key in place.
    ///
    /// Returns the last 4-byte encrypted block, which is the key to use for
    /// [`Self::decrypt_strings`].
    pub fn decrypt(&mut self) -> u32 {
        let mut key = 0;
        for block in bytemuck::cast_slice_mut(bytemuck::bytes_of_mut(self)) {
            let new_key = *block;
            *block ^= key;
            key = new_key;
        }
        key
    }

    pub fn drmp_dll<'a>(&self, pe: PeView<'a>) -> pelite::Result<&'a [u8]> {
        let entry_rva = pe.optional_header().AddressOfEntryPoint;
        let drmp_dll_rva = entry_rva - self.bind_section_ep_offset + self.drmp_dll_bind_offset;
        pe.derva_slice(drmp_dll_rva, self.drmp_dll_size as usize)
    }

    /// Decrypts the Steam DRMP dll payload.
    ///
    /// This algorithm used here is a [XTEA](https://en.wikipedia.org/wiki/XTEA)
    /// variant augmented with a running XOR key.
    pub fn decrypt_drmp_dll(&self, pe: PeView<'_>) -> pelite::Result<Vec<u8>> {
        let mut drmp_dll = self.drmp_dll(pe)?.to_owned();

        let key = self.drmp_xtea_key;
        let mut xor_key = [0x5555_5555u32; 2];
        for block in drmp_dll.chunks_exact_mut(8) {
            const DELTA: u32 = 0x9E3779B9;
            let mut sum: u32 = DELTA.wrapping_mul(32);

            let [mut v0, mut v1]: [u32; 2] = bytemuck::pod_read_unaligned(block);
            let next_xor_key = [v0, v1];

            for _ in 0..32 {
                let v1_diff = v0.wrapping_add((v0 << 4) ^ (v0 >> 5))
                    ^ sum.wrapping_add(key[(sum as usize >> 11) & 3]);
                v1 = v1.wrapping_sub(v1_diff);

                sum = sum.wrapping_sub(DELTA);

                let v0_diff = v1.wrapping_add((v1 << 4) ^ (v1 >> 5))
                    ^ sum.wrapping_add(key[sum as usize & 3]);
                v0 = v0.wrapping_sub(v0_diff);
            }

            v0 ^= xor_key[0];
            v1 ^= xor_key[1];

            block.copy_from_slice(bytemuck::bytes_of(&[v0, v1]));
            xor_key = next_xor_key;
        }

        Ok(drmp_dll)
    }

    pub fn strings<'a>(&self, pe: PeView<'a>) -> pelite::Result<&'a [u8]> {
        let entry_rva = pe.optional_header().AddressOfEntryPoint;
        let strings_rva = entry_rva - self.bind_section_ep_offset + self.strings_bind_offset;
        let aligned_strings_size = self.strings_data_size.next_multiple_of(16) as usize;
        pe.derva_slice(strings_rva, aligned_strings_size)
    }

    pub fn decrypt_strings(&self, pe: PeView<'_>, mut key: u32) -> pelite::Result<Vec<u8>> {
        let mut strings = self.strings(pe)?.to_owned();

        for block in strings.chunks_exact_mut(4) {
            let next_key: u32 = bytemuck::pod_read_unaligned(block);
            block.copy_from_slice(bytemuck::bytes_of(&(key ^ next_key)));
            key = next_key;
        }

        Ok(strings)
    }
}

/// Schedule a callback to run after SteamStub 3.1 finishes unpacking the game.
/// It runs immediately if SteamStub was not detected.
///
/// The callback receives the following:
/// - a pointer original entry point before SteamStub was applied to the executable
/// - a boolean indicating whether SteamStub 3.1 was detected
///
/// # Panics
/// If called more than once.
///
/// # Safety
/// This should only be called before the game's entry point is executed.
pub unsafe fn schedule_after_steamstub(callback: impl FnOnce(*const u8, bool) + Send + 'static) {
    static CALLED: AtomicBool = AtomicBool::new(false);
    if CALLED.swap(true, Ordering::Relaxed) {
        panic!("schedule_after_steamstub must not be called more than once");
    }

    let game = game();
    let base = game.pe.optional_header().ImageBase;
    let opt_header = game.pe.optional_header();
    let entry_point = opt_header.ImageBase + opt_header.AddressOfEntryPoint as u64;

    let mut steamstub_ctx = match SteamStubContext::from_pe(game.pe) {
        None => {
            log::debug!("SteamStub not detected, running callback immediately");
            callback(entry_point as *const _, false);
            return;
        }
        Some(Ok(ctx)) => ctx,
        Some(Err(err)) => panic!("got pelite error while evaluating steamstub ctx: {err}"),
    };

    log::debug!("SteamStub detected");

    log::debug!(
        "clearing SteamStub protection flags, original values: {:#?}",
        steamstub_ctx.header.drm_flags
    );
    steamstub_ctx.header.drm_flags.clear_protection_flags();

    log::debug!("swapping steamstub header OEP with user callback");

    let original_entry_point = base + steamstub_ctx.header.original_entry_point;

    let bare_callback = BareFnOnce::new_c(move || {
        callback(original_entry_point as *const _, true);
        let ep_call: extern "C" fn() -> u64 = unsafe { std::mem::transmute(original_entry_point) };
        ep_call()
    })
    .leak();

    steamstub_ctx.header.original_entry_point = (bare_callback as usize as u64).wrapping_sub(base);

    steamstub_ctx.recompute_hash().unwrap();
    let (new_header, new_strings) = steamstub_ctx.re_encrypt();

    // writing to immutable refs is bad, but pelite's PeView already borrows all that memory
    // so writing to the game's memory is UB no matter what :)
    unsafe {
        util::with_rwx_ptr(
            steamstub_ctx.encrypted_header as *const _ as *mut SteamStubHeader,
            |p| p.write(new_header),
        );
        util::with_rwx_ptr(steamstub_ctx.encrypted_strings.as_ptr().cast_mut(), |p| {
            std::ptr::copy_nonoverlapping(new_strings.as_ptr(), p, new_strings.len());
        });
    }
}
