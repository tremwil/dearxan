pub mod cfg;
pub mod encryption;
pub mod stub_info;
pub mod vm;

pub use encryption::{EncryptedRegion, EncryptedRegionList};
pub use stub_info::{ReturnGadget, StubAnalysisError, StubAnalyzer, StubInfo};
pub use vm::ImageView;

fn find_test_rsp_instructions<'a, I: ImageView>(
    image: &'a I,
) -> impl Iterator<Item = u64> + use<'a, I> {
    use memchr::memmem::find_iter;

    const TEST_RSP_15: &[u8] = b"\x48\xf7\xc4\x0f\x00\x00\x00";
    image
        .sections()
        .flat_map(|(va, slice)| find_iter(slice, TEST_RSP_15).map(move |offset| va + offset as u64))
}

/// Analyze all Arxan stubs found in the executable image using the provided [`StubAnalyzer`].
///
/// If you do not need to configure the analyzer, consider using [`analyze_all_stubs`] instead.
pub fn analyze_all_stubs_with<
    #[cfg(feature = "rayon")] I: ImageView + Sync,
    #[cfg(not(feature = "rayon"))] I: ImageView,
>(
    image: I,
    analyzer: StubAnalyzer,
) -> Vec<Result<StubInfo, StubAnalysisError>> {
    let test_rsp_vas: Vec<_> = find_test_rsp_instructions(&image).collect();

    log::debug!("Found {} potential Arxan stubs", test_rsp_vas.len());

    #[cfg(feature = "rayon")]
    return {
        use rayon::iter::{IntoParallelIterator, ParallelIterator};
        test_rsp_vas.into_par_iter().map(|va| analyzer.analyze(&image, va)).collect()
    };
    #[cfg(not(feature = "rayon"))]
    let stub_infos: Vec<_> =
        test_rsp_vas.into_iter().map(|va| analyzer.analyze(&image, va)).collect();
}

/// Analyze all Arxan stubs found in the executable image using a default [`StubAnalyzer`]
///
/// If you need to configure the analyzer, consider using [`analyze_all_stubs_with`] instead.
pub fn analyze_all_stubs<
    #[cfg(feature = "rayon")] I: ImageView + Sync,
    #[cfg(not(feature = "rayon"))] I: ImageView,
>(
    image: I,
) -> Vec<Result<StubInfo, StubAnalysisError>> {
    analyze_all_stubs_with(image, StubAnalyzer::default())
}
