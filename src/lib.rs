//! `cose2` — CBOR Object Signing and Encryption (COSE, RFC 9052) and CBOR
//! Web Token (CWT, RFC 8392) for Rust, built on [`cbor2`].
//!
//! This crate models COSE structures (messages, headers, keys) and CWT
//! claims, and delegates cryptography to caller-supplied implementations of
//! the [`Signer`], [`Verifier`], [`Macer`] and [`Encryptor`] traits — so it
//! ships no cryptographic dependencies in its default feature set.
//! Top-level COSE messages use named Rust structs with `#[cbor(array)]` to keep
//! the COSE array wire shape, and encode with their registered CBOR tags
//! through `#[derive(cbor2::Cbor)]`. CWT claims likewise encode with their
//! registered CBOR tag. Decode helpers still accept untagged messages and claim
//! maps for compatibility; use `to_untagged_vec` when a peer expects an
//! untagged wire body.
//! Headers reject malformed `crit` parameters and protected/unprotected bucket
//! label collisions. Critical header parameters (`crit`) that an application
//! must understand are validated structurally on decode; applications that
//! process untrusted input should additionally call
//! [`Header::ensure_crit_understood`] on each protected header to enforce the
//! RFC 9052 §3.1 rule that an unrecognised critical parameter is a fatal error.
//! Header accessors and the message layer read attributes from the protected
//! bucket first and then the unprotected bucket (RFC 9052 §3).
//! Keys enforce required `kty` values and non-empty `COSE_KeySet`s. Recipient
//! structures validate the RFC 9052 shape for known recipient algorithm
//! classes. Content-key distribution itself (key wrap, key transport, ECDH key
//! agreement, and the `Enc_Recipient` / `Mac_Recipient` / `Rec_Recipient`
//! recipient-layer cryptography of RFC 9053) is left to application code: this
//! crate models and validates the recipient structures but does not encrypt or
//! decrypt the content-encryption key.
//! Content encryption follows the AEAD construction of RFC 9052 §5.3; the
//! [`Encryptor`] trait always authenticates the `Enc_structure`, so the AE-only
//! construction of §5.4 (zero-length protected header, no external AAD) is not
//! directly modelled.
//! Encryption accepts either a full `IV`, or a `Partial IV` combined with
//! [`Encryptor::base_iv`], and never generates nonces internally.
//! Optional crypto backends are available behind feature flags; enable
//! `crypto-ring` (or the aggregate `crypto` feature) for a `ring`-based
//! backend, or `crypto-aws-lc-rs` for an [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs)-based
//! one. The two backends expose the same providers; when both are enabled,
//! `crypto-ring` takes precedence. The `crypto-ed25519-dalek` feature adds a
//! standalone Ed25519 [`Signer`]/[`Verifier`] backed by
//! [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) (module
//! `ed25519`), and `crypto-aes-gcm` adds an AES-GCM [`Encryptor`] backed by
//! [`aes-gcm`](https://crates.io/crates/aes-gcm) (module `aes_gcm`).
//!
//! # Example: COSE_Sign1 round trip
//!
//! ```
//! use cose2::{iana, Sign1Message, Signer, Verifier, Error};
//!
//! // A trivial (insecure) signer/verifier for illustration.
//! struct Demo;
//! impl Signer for Demo {
//!     fn alg(&self) -> Option<cose2::Label> { Some(iana::AlgorithmEdDSA.into()) }
//!     fn kid(&self) -> Option<&[u8]> { Some(b"key-1") }
//!     fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> { Ok(data.to_vec()) }
//! }
//! impl Verifier for Demo {
//!     fn alg(&self) -> Option<cose2::Label> { Some(iana::AlgorithmEdDSA.into()) }
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

#[cfg(feature = "crypto-aes-gcm")]
pub mod aes_gcm;
#[cfg(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
pub mod crypto;
pub mod cwt;
#[cfg(feature = "crypto-ed25519-dalek")]
pub mod ed25519;

pub use error::Error;
pub use header::{is_understood_header, Header};
pub use key::{Key, KeySet};
pub use label::Label;
pub use map::CoseMap;
pub use traits::{EncryptionContext, Encryptor, Macer, Signer, Verifier};

pub use context::{KdfContext, PartyInfo, PartyNonce, SuppPubInfo};
pub use encrypt::EncryptMessage;
pub use encrypt0::Encrypt0Message;
pub use mac::MacMessage;
pub use mac0::Mac0Message;
pub use recipient::{Recipient, RecipientAlgorithmClass};
pub use sign::{SignMessage, Signature};
pub use sign1::Sign1Message;

/// The CBOR value type used for header, key and claim values.
///
/// Re-exported from [`cbor2`].
pub use cbor2::Value;
