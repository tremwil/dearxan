#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(unsafe_op_in_unsafe_fn)]
#![doc = include_str!("../README.md")]

// #[cfg(feature = "disabler")]
// pub mod disabler;

pub mod analysis;
pub mod patcher;

#[cfg(test)]
mod test_util;

/// Re-export of the `iced_x86` crate.
pub use iced_x86;
/// Re-export of the `pelite` crate.
pub use pelite;
