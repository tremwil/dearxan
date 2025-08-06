#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(unsafe_op_in_unsafe_fn)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "disabler")]
pub mod disabler;

pub mod analysis;
pub mod patch;

/// Re-export of the `iced_x86` crate.
#[cfg(feature = "internal_api")]
pub use iced_x86;
#[cfg(feature = "internal_api")]
/// Re-export of the `pelite` crate.
pub use pelite;
