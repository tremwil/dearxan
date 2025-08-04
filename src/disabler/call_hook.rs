use std::mem::transmute_copy;

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
        let address: isize = unsafe { transmute_copy(&new_target) };
        let imm: i32 = address
            .wrapping_sub_unsigned(self.imm_ptr.addr() + 4)
            .try_into()
            .unwrap();

        unsafe { self.imm_ptr.write_unaligned(imm) };
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
