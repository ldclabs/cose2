//! `cose2` — CBOR Object Signing and Encryption (COSE, RFC 9052) and CBOR
//! Web Token (CWT, RFC 8392) for Rust, built on [`cbor2`].
//!
//! This crate models COSE structures (messages, headers, keys) and CWT
//! claims, and delegates cryptography to caller-supplied implementations of
//! the [`Signer`], [`Verifier`], [`Macer`] and [`Encryptor`] traits — so it
//! ships no cryptographic dependencies of its own.
//!
//! # Example: COSE_Sign1 round trip
//!
//! ```
//! use cose2::{iana, Sign1Message, Signer, Verifier, Error};
//!
//! // A trivial (insecure) signer/verifier for illustration.
//! struct Demo;
//! impl Signer for Demo {
//!     fn alg(&self) -> i64 { iana::AlgorithmEdDSA }
//!     fn kid(&self) -> &[u8] { b"key-1" }
//!     fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> { Ok(data.to_vec()) }
//! }
//! impl Verifier for Demo {
//!     fn alg(&self) -> i64 { iana::AlgorithmEdDSA }
//!     fn verify(&self, data: &[u8], sig: &[u8]) -> Result<(), Error> {
//!         if sig == data { Ok(()) } else { Err(Error::verify("bad signature")) }
//!     }
//! }
//!
//! let mut msg = Sign1Message::new(Some(b"This is the content".to_vec()));
//! let encoded = msg.sign_and_encode(&Demo, None).unwrap();
//!
//! let verified = Sign1Message::verify_and_decode(&Demo, &encoded, None).unwrap();
//! assert_eq!(verified.payload.as_deref(), Some(&b"This is the content"[..]));
//! ```

#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod iana;

mod error;
mod header;
mod key;
mod label;
mod map;
pub mod tag;
mod traits;
mod util;

mod context;
mod encrypt;
mod encrypt0;
mod mac;
mod mac0;
mod recipient;
mod sign;
mod sign1;

pub mod cwt;

pub use error::Error;
pub use header::Header;
pub use key::{Key, KeySet};
pub use label::Label;
pub use map::CoseMap;
pub use traits::{Encryptor, Macer, Signer, Verifier};

pub use context::{KdfContext, PartyInfo, SuppPubInfo};
pub use encrypt::EncryptMessage;
pub use encrypt0::Encrypt0Message;
pub use mac::MacMessage;
pub use mac0::Mac0Message;
pub use recipient::Recipient;
pub use sign::{SignMessage, Signature};
pub use sign1::Sign1Message;

/// The CBOR value type used for header, key and claim values.
///
/// Re-exported from [`cbor2`].
pub use cbor2::Value;
