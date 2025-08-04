/// Trait implemented by types representing an immutable view over a mapped executable image.
pub trait ImageView: Clone {
    /// The base address of the image.
    fn base_va(&self) -> u64;

    /// Iterate over the virtual address and bytes of each section of the image.
    fn sections(&self) -> impl Iterator<Item = (u64, &[u8])>;

    /// Attempt to read at least `min_size` bytes at the virtual address `va`.
    ///
    /// Returns the longest possible contiguous readable slice, and [`None`] if the address is
    /// out-of-bounds or less than `min_size` bytes can be read.
    fn read(&self, va: u64, min_size: usize) -> Option<&[u8]>;
}

impl<'a, I: ImageView> ImageView for &'a I {
    fn base_va(&self) -> u64 {
        (*self).base_va()
    }

    fn sections(&self) -> impl Iterator<Item = (u64, &[u8])> {
        (*self).sections()
    }

    fn read(&self, va: u64, min_size: usize) -> Option<&[u8]> {
        (*self).read(va, min_size)
    }
}

impl ImageView for pelite::pe64::PeView<'_> {
    fn base_va(&self) -> u64 {
        pelite::pe64::Pe::optional_header(*self).ImageBase
    }

    fn sections(&self) -> impl Iterator<Item = (u64, &[u8])> {
        use pelite::pe64::Pe;
        self.section_headers().iter().filter_map(|s| {
            self.get_section_bytes(s)
                .ok()
                .map(|slice| (self.base_va() + s.VirtualAddress as u64, slice))
        })
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
    #[allow(dead_code)] // Used in tests
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

    fn read(&self, va: u64, min_size: usize) -> Option<&[u8]> {
        va.checked_sub(self.base)
            .and_then(|offset| offset.try_into().ok())
            .and_then(|offset| self.bytes.as_ref().get(offset..))
            .and_then(|bytes| (bytes.len() >= min_size).then_some(bytes))
    }
}
