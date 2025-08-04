use std::mem::transmute_copy;

use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

pub struct CallHook<F: Copy> {
    imm_ptr: *mut i32,
    original: F,
}

unsafe impl<F: Copy + Send> Send for CallHook<F> {}
unsafe impl<F: Copy + Sync> Sync for CallHook<F> {}

impl<F: Copy> CallHook<F> {
    pub unsafe fn new(call_ptr: *mut u8) -> Self {
        const {
            assert!(
                size_of::<F>() == size_of::<usize>(),
                "Call hook generic parameter must be pointer-sized"
            );
        }

        let imm_ptr = call_ptr.wrapping_add(1) as *mut i32;
        let imm = unsafe { imm_ptr.read_unaligned() };
        let target = (imm_ptr.addr() + 4).wrapping_add_signed(imm as isize);

        Self {
            imm_ptr,
            original: unsafe { transmute_copy(&target) },
        }
    }

    pub fn original(&self) -> F {
        self.original
    }

    pub unsafe fn hook_with(&self, new_target: F) {
        let mut old_protect = Default::default();

        let address: isize = unsafe { transmute_copy(&new_target) };
        let imm: i32 = address.wrapping_sub_unsigned(self.imm_ptr.addr() + 4).try_into().unwrap();

        if unsafe {
            VirtualProtect(
                self.imm_ptr as *const _,
                size_of_val(&imm),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        } == 0
        {
            panic!("VirtualProtect failed to make patch area RWX");
        }

        unsafe { self.imm_ptr.write_unaligned(imm) };

        if unsafe {
            VirtualProtect(
                self.imm_ptr as *const _,
                size_of_val(&imm),
                old_protect,
                &mut old_protect,
            )
        } == 0
        {
            panic!("VirtualProtect failed to restore patch area protection flags");
        }
    }

    pub unsafe fn unhook(&self) {
        unsafe { self.hook_with(self.original) }
    }
}

impl<F: Copy> Drop for CallHook<F> {
    fn drop(&mut self) {
        unsafe { self.unhook() }
    }
}
