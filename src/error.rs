//! The crate-wide [`Error`] type.

use std::fmt;

/// Errors returned by COSE/CWT operations in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Failed to encode or decode CBOR.
    Cbor(String),
    /// A header, key or claim value was present but had an unexpected CBOR type.
    UnexpectedType(String),
    /// Signature, MAC or decryption verification failed.
    Verify(String),
    /// Any other COSE/CWT protocol error (malformed message, algorithm
    /// mismatch, missing parameter, ...).
    Custom(String),
}

impl Error {
    /// Builds an [`Error::Custom`] from anything that can become a string.
    pub fn custom(msg: impl Into<String>) -> Self {
        Error::Custom(msg.into())
    }

    /// Builds an [`Error::Verify`] from anything that can become a string.
    pub fn verify(msg: impl Into<String>) -> Self {
        Error::Verify(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cbor(msg) => write!(f, "cose: cbor error: {msg}"),
            Error::UnexpectedType(msg) => write!(f, "cose: unexpected type: {msg}"),
            Error::Verify(msg) => write!(f, "cose: verification failed: {msg}"),
            Error::Custom(msg) => write!(f, "cose: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<cbor2::de::Error> for Error {
    fn from(err: cbor2::de::Error) -> Self {
        Error::Cbor(err.to_string())
    }
}

impl From<cbor2::ser::Error> for Error {
    fn from(err: cbor2::ser::Error) -> Self {
        Error::Cbor(err.to_string())
    }
}
