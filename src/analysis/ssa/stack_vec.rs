use std::{
    mem::{ManuallyDrop, MaybeUninit, needs_drop, transmute, transmute_copy},
    ops::{Deref, DerefMut},
};

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

    pub const unsafe fn from_raw_parts(buf: [MaybeUninit<T>; N], len: usize) -> Self {
        Self { buf, len }
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

    pub const unsafe fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    pub fn extend(&mut self, iter: impl IntoIterator<Item = T>) {
        let mut iter = iter.into_iter();
        let min_size = iter.size_hint().0;

        if self.len().checked_add(min_size).is_none_or(|l| l > N) {
            panic!("StackVec max capacity exceeded")
        }
        for _ in 0..min_size {
            unsafe {
                self.buf.get_unchecked_mut(self.len).write(iter.next().unwrap());
                self.len += 1;
            }
        }

        for elem in iter {
            self.push(elem);
        }
    }

    pub fn clear(&mut self) {
        if needs_drop::<T>() {
            for i in 0..self.len {
                unsafe {
                    self.buf.get_unchecked_mut(i).assume_init_drop();
                }
            }
        }
        self.len = 0;
    }
}

impl<T: Copy, const N: usize> StackVec<T, N> {
    /// Optimized version of [`StackVec::clone`] when `T` is [`Copy`].
    fn copy(&self) -> Self {
        unsafe { Self::from_raw_parts(self.buf, self.len) }
    }
}

impl<T, const N: usize> Drop for StackVec<T, N> {
    fn drop(&mut self) {
        self.clear();
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

impl<T, const N: usize> Default for StackVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone, const N: usize> Clone for StackVec<T, N> {
    fn clone(&self) -> Self {
        let mut cloned = Self::new();
        for i in 0..self.len() {
            cloned.buf[i].write(self[i].clone());
        }
        unsafe {
            cloned.set_len(self.len());
        }
        cloned
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

impl<A, const N: usize> FromIterator<A> for StackVec<A, N> {
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        let mut vec = StackVec::new();
        vec.extend(iter);
        vec
    }
}
