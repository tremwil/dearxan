use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

unsafe fn with_rwx_inner<R>(addr: *const (), size: usize, fun: impl FnOnce() -> R) -> R {
    let mut old_protect = Default::default();
    let addr = addr as *const _;

    if unsafe { VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &mut old_protect) } == 0 {
        panic!("VirtualProtect failed to make memory RWX");
    }

    let ret = fun();

    if unsafe { VirtualProtect(addr, size, old_protect, &mut old_protect) } == 0 {
        panic!("VirtualProtect failed to restore memory protection flags");
    }

    ret
}

pub unsafe fn with_rwx_ptr<T: ?Sized, R>(ptr: *mut T, fun: impl FnOnce(*mut T) -> R) -> R {
    let size = std::mem::size_of_val(unsafe { &*ptr });
    unsafe { with_rwx_inner(ptr.cast(), size, || fun(ptr)) }
}
