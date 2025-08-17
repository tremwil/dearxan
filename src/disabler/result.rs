use std::{any::Any, fmt};

pub type DearxanResult = std::result::Result<Status, Error>;

/// The informational part of a [`DearxanResult`].
#[derive(Clone, Debug)]
pub struct Status {
    pub is_arxan_detected: bool,
    pub is_executing_entrypoint: bool,
}

/// Errors that prevented dearxan from finishing.
///
/// Either a `dyn`[`std::error::Error`] error or a payload panic as a string.
#[derive(Debug)]
pub enum Error {
    Error(Box<dyn std::error::Error + Send + Sync>),
    Panic(String),
}

pub(crate) fn from_error<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
    err: E,
) -> DearxanResult {
    Err(Error::Error(err.into()))
}

pub(crate) fn from_panic_payload(payload: Box<dyn Any + Send + 'static>) -> DearxanResult {
    // As of Rust 2024, library panic payloads are always `&'static str`.
    match payload.downcast::<&'static str>() {
        Ok(panic_msg) => Err(Error::Panic(panic_msg.to_string())),
        Err(_) => Err(Error::Panic(
            "panicked, but failed to retrieve panic message".to_owned(),
        )),
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(err) => err.fmt(f),
            Self::Panic(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {}
