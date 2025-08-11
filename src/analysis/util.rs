pub fn windows_mut<T, const N: usize>(slice: &mut [T], mut fun: impl FnMut([&mut T; N])) {
    fn window_indices<const N: usize>(i: usize) -> [usize; N] {
        let mut w = [i; N];
        for j in 0..N {
            w[j] += j;
        }
        w
    }

    for i in 0..slice.len().saturating_sub(N) {
        // SAFETY: window indices are disjoint
        let window = unsafe { slice.get_disjoint_unchecked_mut(window_indices::<N>(i)) };
        fun(window);
    }
}
