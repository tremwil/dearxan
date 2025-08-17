use std::{
    mem::{ManuallyDrop, MaybeUninit, needs_drop, transmute, transmute_copy},
    ops::{Deref, DerefMut},
};

pub struct FmtSigned<T: Copy + Into<i128>>(T);

pub trait AsFmtSigned: Copy + Into<i128> {
    fn format_signed(self) -> FmtSigned<Self> {
        FmtSigned(self)
    }
}

impl<T: Copy + Into<i128>> AsFmtSigned for T {}

impl<T: Copy + Into<i128>> std::fmt::Debug for FmtSigned<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let num: i128 = self.0.into();
        if num >= 0 {
            f.write_str("+")?;
            std::fmt::Debug::fmt(&num, f)
        }
        else {
            f.write_str("-")?;
            std::fmt::Debug::fmt(&num.wrapping_neg(), f)
        }
    }
}

impl<T: Copy + Into<i128>> std::fmt::Display for FmtSigned<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let num: i128 = self.0.into();
        if num >= 0 {
            f.write_str("+")?;
            std::fmt::Display::fmt(&num, f)
        }
        else {
            f.write_str("-")?;
            std::fmt::Display::fmt(&num.wrapping_neg(), f)
        }
    }
}

impl<T: Copy + Into<i128>> std::fmt::LowerHex for FmtSigned<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let num: i128 = self.0.into();
        if num >= 0 {
            f.write_str("+")?;
            std::fmt::LowerHex::fmt(&num, f)
        }
        else {
            f.write_str("-")?;
            std::fmt::LowerHex::fmt(&num.wrapping_neg(), f)
        }
    }
}

impl<T: Copy + Into<i128>> std::fmt::UpperHex for FmtSigned<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let num: i128 = self.0.into();
        if num >= 0 {
            f.write_str("+")?;
            std::fmt::UpperHex::fmt(&num, f)
        }
        else {
            f.write_str("-")?;
            std::fmt::UpperHex::fmt(&num.wrapping_neg(), f)
        }
    }
}

/// Dynamic array of up to `N` elements stored on the stack.
pub struct StackVec<T, const N: usize> {
    buf: [MaybeUninit<T>; N],
    len: usize,
}

impl<T, const N: usize> StackVec<T, N> {
    pub const fn new() -> Self {
        Self {
            buf: [const { MaybeUninit::uninit() }; N],
            len: 0,
        }
    }

    pub const fn from_buf(buf: [T; N]) -> Self {
        Self {
            buf: unsafe { transmute_copy(&ManuallyDrop::new(buf)) },
            len: N,
        }
    }

    pub const fn from_array<const M: usize>(array: [T; M]) -> Self {
        const {
            if M > N {
                panic!("StackVec::from_array only accepts a shorter array");
            }
        }
        let mut buf = [const { MaybeUninit::uninit() }; N];
        unsafe {
            std::ptr::copy_nonoverlapping(array.as_ptr(), buf.as_mut_ptr().cast(), M);
        }
        std::mem::forget(array);
        Self { buf, len: M }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub const fn push(&mut self, val: T) {
        if self.len >= N {
            panic!("StackVec max capacity exceeded");
        }
        self.buf[self.len].write(val);
        self.len += 1;
    }

    pub const fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        unsafe { Some(self.buf.as_ptr().add(self.len).read().assume_init()) }
    }

    pub const fn expand<const M: usize>(self) -> StackVec<T, M> {
        const {
            if M < N {
                panic!("StackVec::expand cannot expand into a lower capacity");
            }
        }
        let mut new = StackVec::new();
        unsafe {
            std::ptr::copy_nonoverlapping(self.buf.as_ptr(), new.buf.as_mut_ptr(), self.len);
        }
        new.len = self.len;
        std::mem::forget(self);
        new
    }
}

impl<T, const N: usize> AsRef<[T]> for StackVec<T, N> {
    fn as_ref(&self) -> &[T] {
        unsafe { transmute(self.buf.get_unchecked(..self.len)) }
    }
}

impl<T, const N: usize> AsMut<[T]> for StackVec<T, N> {
    fn as_mut(&mut self) -> &mut [T] {
        unsafe { transmute(self.buf.get_unchecked_mut(..self.len)) }
    }
}

impl<T, const N: usize> Deref for StackVec<T, N> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T, const N: usize> DerefMut for StackVec<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<T, const N: usize> IntoIterator for StackVec<T, N> {
    type Item = T;

    type IntoIter = std::iter::Map<
        std::iter::Take<<[MaybeUninit<T>; N] as IntoIterator>::IntoIter>,
        fn(MaybeUninit<T>) -> T,
    >;

    fn into_iter(self) -> Self::IntoIter {
        let len = self.len;
        let manually_drop = ManuallyDrop::new(self);
        // SAFETY: we only read the first `len` elements of the buffer
        let buf = unsafe { (&manually_drop.buf as *const [MaybeUninit<T>; N]).read() };
        buf.into_iter().take(len).map(|v| unsafe { v.assume_init() })
    }
}

impl<T, const N: usize> Drop for StackVec<T, N> {
    fn drop(&mut self) {
        if needs_drop::<T>() {
            for i in 0..self.len {
                unsafe {
                    self.buf.get_unchecked_mut(i).assume_init_drop();
                }
            }
        }
    }
}
