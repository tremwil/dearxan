use pelite::pe64::{Pe, PeView};

/// Opaque error type returned by [`ImageView::relocs64`] when image relocations cannot be read.
#[derive(Debug, Clone, Copy)]
pub struct BadRelocsError;

impl std::fmt::Display for BadRelocsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("failed to read image relocations")
    }
}

impl std::error::Error for BadRelocsError {}

/// Abstraction over an immutable view of a mapped executable image.
pub trait ImageView: Clone {
    /// The actual base address of the image.
    fn base_va(&self) -> u64;

    /// Iterate over the virtual address and bytes of each section of the image.
    fn sections(&self) -> impl Iterator<Item = (u64, &[u8])>;

    /// Iterate over the RVAs of all 64-bit relative relocations of the image.
    ///
    /// May fail with an opaque error if the relocations section of the image is corrupted.
    fn relocs64(&self) -> Result<impl Iterator<Item = u32>, BadRelocsError>;

    /// Attempt to read at least `min_size` bytes at the virtual address `va`.
    ///
    /// Returns the longest possible contiguous readable slice, and [`None`] if the address is
    /// out-of-bounds or less than `min_size` bytes can be read.
    fn read(&self, va: u64, min_size: usize) -> Option<&[u8]>;
}

impl<I: ImageView> ImageView for &I {
    fn base_va(&self) -> u64 {
        (*self).base_va()
    }

    fn sections(&self) -> impl Iterator<Item = (u64, &[u8])> {
        (*self).sections()
    }

    fn relocs64(&self) -> Result<impl Iterator<Item = u32>, BadRelocsError> {
        (*self).relocs64()
    }

    fn read(&self, va: u64, min_size: usize) -> Option<&[u8]> {
        (*self).read(va, min_size)
    }
}

impl ImageView for PeView<'_> {
    fn base_va(&self) -> u64 {
        Pe::optional_header(*self).ImageBase
    }

    fn sections(&self) -> impl Iterator<Item = (u64, &[u8])> {
        use pelite::pe64::Pe;
        self.section_headers().iter().filter_map(|s| {
            self.get_section_bytes(s)
                .ok()
                .map(|slice| (self.base_va() + s.VirtualAddress as u64, slice))
        })
    }

    #[allow(clippy::filter_map_bool_then)]
    fn relocs64(&self) -> Result<impl Iterator<Item = u32>, BadRelocsError> {
        let maybe_relocs = match self.base_relocs() {
            Ok(relocs) => Some(relocs),
            Err(pelite::Error::Null) => None,
            Err(_) => return Err(BadRelocsError),
        };
        Ok(maybe_relocs
            .into_iter()
            .flat_map(|relocs| relocs.iter_blocks())
            .flat_map(|block| {
                block.words().iter().filter_map(move |w| {
                    // IMAGE_REL_BASED_DIR64 = 10
                    (block.type_of(w) == 10).then(|| block.rva_of(w))
                })
            }))
    }

    fn read(&self, va: u64, min_size: usize) -> Option<&[u8]> {
        pelite::pe64::Pe::read(self, va, min_size, 1).ok()
    }
}

/// Wrapper around an [`AsRef<[u8]>`](AsRef) type which implements [`ImageView`] over a single
/// section.
///
/// The base address of this "image" is arbitrary and can be set during construction with
/// [`WithBase::new`].
#[derive(Debug, Clone, Copy)]
pub struct WithBase<T: AsRef<[u8]> + Clone> {
    bytes: T,
    base: u64,
}

impl<T: AsRef<[u8]> + Clone> WithBase<T> {
    /// Construct a [`WithBase`] from a u8 slice-like type and a base virtual address.
    #[allow(dead_code)] // To be used in tests
    pub fn new(bytes: T, base: u64) -> Self {
        Self { bytes, base }
    }
}

impl<T: AsRef<[u8]> + Clone> ImageView for WithBase<T> {
    fn base_va(&self) -> u64 {
        self.base
    }

    fn sections(&self) -> impl Iterator<Item = (u64, &[u8])> {
        std::iter::once((self.base, self.bytes.as_ref()))
    }

    fn relocs64(&self) -> Result<impl Iterator<Item = u32>, BadRelocsError> {
        Ok(std::iter::empty())
    }

    fn read(&self, va: u64, min_size: usize) -> Option<&[u8]> {
        va.checked_sub(self.base)
            .and_then(|offset| offset.try_into().ok())
            .and_then(|offset| self.bytes.as_ref().get(offset..))
            .and_then(|bytes| (bytes.len() >= min_size).then_some(bytes))
    }
}
