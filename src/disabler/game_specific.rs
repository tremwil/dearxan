use crate::patcher::StubPatchInfo;

use super::{ffi_impl, ArxanDisabler};

/// Arxan disabler for Dark Souls Remastered 1.3.1.
///
/// Will *not* work for other versions out of the box, but can be adapted if the
/// omitted patches defined in [`DSRArxanDisabler::filter_patch`] are updated.
#[derive(Default)]
pub struct DSRArxanDisabler;
impl ArxanDisabler for DSRArxanDisabler {
    fn filter_patch(&mut self, hook_address: u64, _: Option<&StubPatchInfo>) -> bool {
        // These two decrypt the game's named property list. If they don't run, things
        // go horribly wrong!
        //
        // there doesn't appear to be any other game data encrypted by Arxan.
        !matches!(hook_address, 0x142FF5D21 | 0x143001ED0)
    }
}

ffi_impl!(DSRArxanDisabler, disable_arxan_dsr);

/// Arxan disabler for Dark Souls II SOTFS.
///
/// Only the latest version (1.03) of SOTFS is actively supported. Compatibility with
/// other versions is highly likely but not guaranteed.
#[derive(Default)]
pub struct DS2ArxanDisabler;

// We don't actually have to do anything special for DS2, it doesn't have any weird encrypted
// data/functions
impl ArxanDisabler for DS2ArxanDisabler {}

ffi_impl!(DS2ArxanDisabler, disable_arxan_ds2);

/// Arxan disabler for Dark Souls III
///
/// Only the latest version (1.03) of SOTFS is actively supported. Compatibility with
/// other versions is highly likely but not guaranteed.
#[derive(Default)]
pub struct DS3ArxanDisabler;

// We don't actually have to do anything special for DS2, it doesn't have any weird encrypted
// data/functions
impl ArxanDisabler for DS3ArxanDisabler {}

ffi_impl!(DSRArxanDisabler, disable_arxan_ds3);
