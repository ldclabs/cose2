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
    /// An operation was attempted in an invalid message lifecycle state.
    InvalidState(String),
    /// A declared message, header, or key algorithm did not match the expected algorithm.
    AlgorithmMismatch {
        /// Algorithm declared by the message or key.
        declared: String,
        /// Algorithm expected by the provider.
        expected: String,
    },
    /// A COSE_Key `key_ops` restriction forbids the requested operation.
    KeyOperation(String),
    /// A configured parser or processing resource limit was exceeded.
    LimitExceeded {
        /// Name of the limited resource.
        resource: String,
        /// Configured upper bound.
        limit: usize,
    },
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

    /// Builds an [`Error::InvalidState`].
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Error::InvalidState(msg.into())
    }

    /// Builds an [`Error::KeyOperation`].
    pub fn key_operation(msg: impl Into<String>) -> Self {
        Error::KeyOperation(msg.into())
    }

    /// Builds an [`Error::LimitExceeded`].
    pub fn limit(resource: impl Into<String>, limit: usize) -> Self {
        Error::LimitExceeded {
            resource: resource.into(),
            limit,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cbor(msg) => write!(f, "cose: cbor error: {msg}"),
            Error::UnexpectedType(msg) => write!(f, "cose: unexpected type: {msg}"),
            Error::Verify(msg) => write!(f, "cose: verification failed: {msg}"),
            Error::InvalidState(msg) => write!(f, "cose: invalid state: {msg}"),
            Error::AlgorithmMismatch { declared, expected } => write!(
                f,
                "cose: algorithm mismatch, declared {declared}, expected {expected}"
            ),
            Error::KeyOperation(msg) => write!(f, "cose: key operation denied: {msg}"),
            Error::LimitExceeded { resource, limit } => {
                write!(f, "cose: {resource} limit {limit} exceeded")
            }
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
