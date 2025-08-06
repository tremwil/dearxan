use pelite::pe64::{
    PeObject, PeView,
    image::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64},
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};

use crate::disabler::code_buffer::CodeBuffer;

pub struct CurrentGame {
    pub pe: PeView<'static>,
    pub preferred_base: u64,
    pub hook_buffer: CodeBuffer,
}

#[cfg(target_os = "windows")]
pub fn game() -> &'static CurrentGame {
    use std::{ffi::OsString, io::Read, os::windows::ffi::OsStringExt, sync::LazyLock};

    static GAME: LazyLock<CurrentGame> = LazyLock::new(|| unsafe {
        let handle = GetModuleHandleW(std::ptr::null());
        if handle.is_null() {
            panic!("GetModuleHandleW(NULL) failed");
        }
        let pe = PeView::module(handle as *const _);

        let mut game_path = vec![0u16; 0x1000];
        let path_size = GetModuleFileNameW(handle, game_path.as_mut_ptr(), game_path.len() as u32);
        if path_size == 0 || path_size == game_path.len() as u32 {
            panic!("GetModuleFileNameW failed for game module");
        }
        let game_path = OsString::from_wide(&game_path[..path_size as usize]);
        log::debug!("game path: {:?}", game_path);

        let mut game_file = match std::fs::File::open(&game_path) {
            Err(err) => panic!("failed to read game executable at {game_path:?} due to {err}"),
            Ok(f) => f,
        };
        let mut first_page = [0; 0x1000];
        let _ = game_file.read_exact(&mut first_page).inspect_err(|err| {
            panic!("failed to read first page of game executable {game_path:?} due to {err}")
        });

        let dos_header = first_page.as_ptr().cast::<IMAGE_DOS_HEADER>().read_unaligned();
        let nt_headers = first_page
            .as_ptr()
            .add(dos_header.e_lfanew as usize)
            .cast::<IMAGE_NT_HEADERS64>()
            .read_unaligned();

        let preferred_base = nt_headers.OptionalHeader.ImageBase;
        log::debug!("preferred base address: {preferred_base:x}");

        let hook_buffer = CodeBuffer::alloc_near(pe.image().as_ptr_range(), 0x100_0000, 1 << 31)
            .expect("failed to create hook buffer near the game module");

        CurrentGame {
            pe,
            preferred_base,
            hook_buffer,
        }
    });
    &GAME
}

// Hack to get docs-rs (which runs on linux only) to build the disabler module
#[cfg(not(target_os = "windows"))]
pub fn game() -> &'static CurrentGame {
    unimplemented!("unsupported platform")
}
