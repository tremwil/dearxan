use std::{
    ffi::c_void,
    ops::Range,
    ptr::slice_from_raw_parts_mut,
    sync::atomic::{AtomicPtr, Ordering},
};

use closure_ffi::{JitAlloc, JitAllocError};
use pelite::util::AlignTo;
use windows::Win32::System::{
    Memory::{
        VirtualAlloc, VirtualFree, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE,
        MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    },
    SystemInformation::{GetSystemInfo, SYSTEM_INFO},
};

#[derive(Debug)]
#[repr(align(64))]
pub struct CodeBuffer {
    cursor: AtomicPtr<u8>,
    alloc_base: *mut c_void,
    end: *mut u8,
}

unsafe impl Send for CodeBuffer {}
unsafe impl Sync for CodeBuffer {}

impl CodeBuffer {
    pub fn alloc_near(region: impl IntoUsizeRange, size: usize, max_sep: usize) -> Option<Self> {
        let region = region.into_region();

        // Get allocation granularity (typically 64KB)
        let mut si = SYSTEM_INFO::default();
        unsafe { GetSystemInfo(&mut si) };
        let gran = si.dwAllocationGranularity as usize;

        // compute lowest possible allocation address (note that the first block cannot be allocated)
        let lowest_base = (region.end.saturating_sub(max_sep).max(gran) + gran - 1).align_to(gran);

        // Search free region closest to target module to allocate our hook memory at,
        // starting at lowest possible address that admits a REL32 jmp
        let mut minfo = MEMORY_BASIC_INFORMATION::default();
        let mut query_base = lowest_base;
        while unsafe {
            VirtualQuery(
                Some(query_base as *const _),
                &mut minfo,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) != 0
        } {
            // Compute portion of block that is aligned to allocation boundaries
            let block_start = (minfo.BaseAddress as usize + gran - 1).align_to(gran);
            let block_end = (minfo.BaseAddress as usize + minfo.RegionSize).align_to(gran);
            let block_size = block_end - block_start;

            // block end would be too far from region start
            if (block_size + size).saturating_sub(region.start) > max_sep {
                break;
            }
            // block is not free or not enough space
            else if minfo.State != MEM_FREE || size > block_size {
                query_base = minfo.BaseAddress as usize + minfo.RegionSize;
                continue;
            }

            // Otherwise, block satisfies all requirements
            let alloc_base = unsafe {
                VirtualAlloc(
                    Some(block_start as *const _),
                    size,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            assert!(!alloc_base.is_null(), "VirtualAlloc failed");
            return Some(Self {
                alloc_base,
                cursor: AtomicPtr::new(alloc_base as *mut _),
                end: unsafe { (alloc_base as *mut u8).add(size) },
            });
        }
        None
    }

    pub fn reserve(&self, size: usize) -> Option<*mut [u8]> {
        self.cursor
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                let new_cursor = c.with_addr(c.addr().checked_add(size)?);
                (c < self.end).then_some(new_cursor)
            })
            .ok()
            // SAFETY:
            // - Slice is atomically reserved
            // - VirtualAlloc zero-initializes the bytes
            .map(|c| slice_from_raw_parts_mut(c, size))
    }

    pub fn write(&self, bytes: &[u8]) -> Option<*mut [u8]> {
        self.reserve(bytes.len()).map(|buf| unsafe {
            (buf as *mut u8).copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
            buf
        })
    }
}

impl Drop for CodeBuffer {
    fn drop(&mut self) {
        unsafe { VirtualFree(self.alloc_base, 0, MEM_RELEASE).unwrap() }
    }
}

impl JitAlloc for CodeBuffer {
    fn alloc(&self, size: usize) -> Result<(*const u8, *mut u8), JitAllocError> {
        self.reserve(size)
            .map(|p| (p as *const u8, p as *mut u8))
            .ok_or(JitAllocError)
    }

    // CodeBuffer is a simple arena without the ability to free individual blocks
    #[allow(unused_variables)]
    unsafe fn release(&self, rx_ptr: *const u8) -> Result<(), JitAllocError> {
        Ok(())
    }

    // Not needed on modern AMD64 processors
    #[allow(unused_variables)]
    unsafe fn flush_instruction_cache(&self, rx_ptr: *const u8, size: usize) {}

    // Not needed on Windows
    #[allow(unused_variables)]
    unsafe fn protect_jit_memory(
        &self,
        ptr: *const u8,
        size: usize,
        access: closure_ffi::jit_alloc::ProtectJitAccess,
    ) {
    }
}

pub trait IntoUsizeRange {
    fn into_region(self) -> Range<usize>;
}
impl<T> IntoUsizeRange for *const [T] {
    fn into_region(self) -> Range<usize> {
        self.addr()..(self.addr() + self.len())
    }
}
impl<T> IntoUsizeRange for *mut [T] {
    fn into_region(self) -> Range<usize> {
        self.addr()..(self.addr() + self.len())
    }
}
impl<T> IntoUsizeRange for Range<*const T> {
    fn into_region(self) -> Range<usize> {
        self.start.addr()..self.end.addr()
    }
}
impl<T> IntoUsizeRange for Range<*mut T> {
    fn into_region(self) -> Range<usize> {
        self.start.addr()..self.end.addr()
    }
}
impl<T> IntoUsizeRange for &[T] {
    fn into_region(self) -> Range<usize> {
        self.as_ptr_range().into_region()
    }
}
impl<T> IntoUsizeRange for &mut [T] {
    fn into_region(self) -> Range<usize> {
        self.as_ptr_range().into_region()
    }
}
