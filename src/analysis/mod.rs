#[cfg(not(feature = "internal_api"))]
mod cfg;
#[cfg(not(feature = "internal_api"))]
mod encryption;
#[cfg(not(feature = "internal_api"))]
mod stub_info;
#[cfg(not(feature = "internal_api"))]
mod vm;

#[cfg(feature = "internal_api")]
pub mod cfg;
#[cfg(feature = "internal_api")]
pub mod encryption;
#[cfg(feature = "internal_api")]
pub mod stub_info;
#[cfg(feature = "internal_api")]
pub mod vm;

#[doc(inline)]
pub use self::{
    encryption::{EncryptedRegion, EncryptedRegionList, shannon_entropy},
    stub_info::{ReturnGadget, StubAnalysisError, StubAnalyzer, StubInfo},
    vm::{ImageView, image::WithBase},
};

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
    #[cfg(feature = "rayon")]
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    let test_rsp_vas: Vec<_> = find_test_rsp_instructions(&image).collect();

    log::debug!("Found {} potential Arxan stubs", test_rsp_vas.len());

    #[cfg(feature = "rayon")]
    let iter = test_rsp_vas.into_par_iter();
    #[cfg(not(feature = "rayon"))]
    let iter = test_rsp_vas.into_iter();

    // Exclude don't report `NotAStub` errors as errors, just filter them out
    iter.filter_map(|va| match analyzer.analyze(&image, va) {
        Err(StubAnalysisError::NotAStub(_)) => None,
        other => Some(other),
    })
    .collect()
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
