use std::{ffi::OsStr, path::PathBuf, sync::LazyLock};

use pelite::pe64::{Pe, PeFile, PeObject, PeView};

// Re-implementation of `PeFile::to_view` as the original is broken
pub fn pe_file_to_view(pe: pelite::pe64::PeFile) -> Vec<u8> {
    let (sizeof_headers, sizeof_image) = {
        let optional_header = pe.optional_header();
        (optional_header.SizeOfHeaders, optional_header.SizeOfImage)
    };

    // Zero fill the underlying image
    let mut vec = vec![0u8; sizeof_image as usize];

    // Start by copying the headers
    let image = pe.image();
    unsafe {
        // Validated by constructor
        let dest_headers = vec.get_unchecked_mut(..sizeof_headers as usize);
        let src_headers = image.get_unchecked(..sizeof_headers as usize);
        dest_headers.copy_from_slice(src_headers);
    }

    // Copy the section file data
    for section in pe.section_headers() {
        let dest = vec.get_mut(
            section.VirtualAddress as usize
                ..u32::wrapping_add(section.VirtualAddress, section.VirtualSize) as usize,
        );
        let src = image.get(
            section.PointerToRawData as usize
                ..u32::wrapping_add(section.PointerToRawData, section.SizeOfRawData) as usize,
        );
        // Skip invalid sections...
        if let (Some(dest), Some(src)) = (dest, src) {
            let write_sz = src.len().min(dest.len());
            dest[..write_sz].copy_from_slice(&src[..write_sz]);
        }
    }

    vec
}

#[derive(Debug, Clone)]
pub struct FsExe {
    pub game: String,
    pub ver: String,
    pub path: PathBuf,
}

impl FsExe {
    pub fn load_64(&self) -> pelite::Result<MappedFsExe> {
        let disk_view = std::fs::read(&self.path).unwrap();
        let pe_file = PeFile::from_bytes(&disk_view)?;
        let mem_view = pe_file_to_view(pe_file);

        Ok(MappedFsExe {
            exe: self.clone(),
            disk_view,
            mem_view,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MappedFsExe {
    exe: FsExe,
    disk_view: Vec<u8>,
    mem_view: Vec<u8>,
}

impl MappedFsExe {
    pub fn exe_info(&self) -> &FsExe {
        &self.exe
    }

    pub fn game(&self) -> &str {
        &self.exe.game
    }

    pub fn ver(&self) -> &str {
        &self.exe.ver
    }

    pub fn pe_file(&self) -> PeFile<'_> {
        PeFile::from_bytes(&self.disk_view).unwrap()
    }

    pub fn pe_view(&self) -> PeView<'_> {
        PeView::from_bytes(&self.mem_view).unwrap()
    }
}

pub struct FsGame {
    pub name: String,
    pub versions: Vec<FsExe>,
}

pub fn fsbins() -> &'static [FsGame] {
    static FS_BINS: LazyLock<Vec<FsGame>> = LazyLock::new(|| {
        let fsbins_root = std::env::var("FSBINS_PATH").expect(
            "This test requires fsbins to be installed and the FSBINS_PATH environment 
            variable to point to its root.",
        );

        std::fs::read_dir(fsbins_root)
            .unwrap()
            .filter_map(|game_folder| {
                let game_folder = game_folder.ok()?;
                let game_name = game_folder.file_name().to_string_lossy().to_string();
                if !game_folder.file_type().ok()?.is_dir() {
                    return None;
                }

                let mut versions: Vec<_> = std::fs::read_dir(game_folder.path())
                    .ok()?
                    .filter_map(|ver_folder| {
                        let ver_folder = ver_folder.ok()?;
                        let ver_name = ver_folder.file_name().to_string_lossy().to_string();
                        if !ver_folder.file_type().ok()?.is_dir() {
                            return None;
                        }

                        let exe = std::fs::read_dir(ver_folder.path())
                            .ok()?
                            .filter_map(|f| f.ok())
                            .find(|f| f.path().extension() == Some(OsStr::new("exe")))?;

                        Some(FsExe {
                            game: game_name.clone(),
                            ver: ver_name.clone(),
                            path: exe.path(),
                        })
                    })
                    .collect();

                if versions.is_empty() {
                    return None;
                }

                // permissive semver sorting: if dot-delimited versions are numbers, compare them as
                // such otherwise compare them as strings
                versions.sort_by(|a, b| {
                    let mut a_split = a.ver.split('.');
                    let mut b_split = b.ver.split('.');
                    for (a_seg, b_seg) in (&mut a_split).zip(&mut b_split) {
                        if let (Ok(a_num), Ok(b_num)) = (
                            usize::from_str_radix(a_seg, 10),
                            usize::from_str_radix(b_seg, 10),
                        ) {
                            return a_num.cmp(&b_num);
                        }
                        return a_seg.cmp(b_seg);
                    }
                    return a_split.cmp(b_split);
                });
                Some(FsGame {
                    name: game_name.to_string(),
                    versions,
                })
            })
            .collect()
    });
    &FS_BINS
}

pub fn latest_fsbins() -> Vec<&'static FsExe> {
    fsbins().iter().map(|g| g.versions.last().unwrap()).collect()
}

pub fn init_log(level: log::LevelFilter) {
    simplelog::SimpleLogger::init(level, simplelog::Config::default()).unwrap();
}
