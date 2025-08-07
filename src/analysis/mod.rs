mod cfg;
mod encryption;
mod entry_point;
mod stub_info;
mod vm;

/// Internal analysis API.
///
/// # Warning
///
/// <div class="warning">
///
/// Breaking changes to this module are *not* considered as breaking for the purpose of semantic
/// versioning!
///
/// </div>
#[cfg(feature = "internal_api")]
pub mod internal {
    pub mod cfg {
        #[doc(inline)]
        pub use super::super::cfg::*;
    }
    pub mod encryption {
        #[doc(inline)]
        pub use super::super::encryption::*;
    }
    pub mod stub_info {
        #[doc(inline)]
        pub use super::super::stub_info::*;
    }
    pub mod vm {
        #[doc(inline)]
        pub use super::super::vm::*;
    }
}

pub use self::{
    encryption::{EncryptedRegion, EncryptedRegionList, shannon_entropy},
    entry_point::is_arxan_hooked_entry_point,
    stub_info::{ReturnGadget, StubAnalysisError, StubAnalyzer, StubInfo},
    vm::{ImageView, image::WithBase},
};

fn find_test_rsp_instructions<'a, I: ImageView>(image: &'a I) -> Vec<u64> {
    use memchr::memmem::find_iter;
    #[cfg(feature = "rayon")]
    use rayon::iter::{IntoParallelIterator, ParallelBridge, ParallelIterator};

    const TEST_RSP_15: &[u8] = b"\x48\xf7\xc4\x0f\x00\x00\x00";

    let sections = image.sections().collect::<Vec<_>>();

    #[cfg(not(feature = "rayon"))]
    return sections
        .into_iter()
        .flat_map(|(va, slice)| find_iter(slice, TEST_RSP_15).map(move |offset| va + offset as u64))
        .collect();

    #[cfg(feature = "rayon")]
    sections
        .into_par_iter()
        .flat_map(|(va, slice)| {
            find_iter(slice, TEST_RSP_15).map(move |offset| va + offset as u64).par_bridge()
        })
        .collect()
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

    let test_rsp_vas = find_test_rsp_instructions(&image);

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
