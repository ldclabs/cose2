//! Pluggable cryptographic interfaces.
//!
//! `cose2` models COSE structures but does not implement cryptography
//! itself. Callers supply signing, verification, MAC and encryption by
//! implementing these traits with the crypto library of their choice.

use crate::{Error, Label};

/// Produces digital signatures for COSE_Sign and COSE_Sign1.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-signature-algorithms>.
pub trait Signer {
    /// The COSE algorithm identifier this signer uses.
    ///
    /// Returning `None` leaves the `alg` header untouched. Returning `Some`
    /// writes the identifier when it is absent, or checks that an existing
    /// protected `alg` value matches. COSE algorithm identifiers are
    /// `int / tstr`, represented by [`Label`].
    fn alg(&self) -> Option<Label> {
        None
    }

    /// The key identifier to write to the unprotected header.
    ///
    /// Returning `None` leaves the `kid` header untouched.
    fn kid(&self) -> Option<&[u8]> {
        None
    }

    /// Computes the signature over `data`.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Verifies digital signatures for COSE_Sign and COSE_Sign1.
pub trait Verifier {
    /// The COSE algorithm identifier this verifier expects, if any.
    fn alg(&self) -> Option<Label> {
        None
    }

    /// The key identifier matched against a message's `kid` header, if any.
    fn kid(&self) -> Option<&[u8]> {
        None
    }

    /// Returns `Ok(())` if `signature` is valid for `data`, otherwise an error.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error>;
}

/// Computes and verifies message authentication codes for COSE_Mac and
/// COSE_Mac0.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-message-authentication-code>.
pub trait Macer {
    /// The COSE algorithm identifier this MACer uses, if any.
    fn alg(&self) -> Option<Label> {
        None
    }

    /// The key identifier to write to the unprotected header, if any.
    fn kid(&self) -> Option<&[u8]> {
        None
    }

    /// Computes the authentication tag over `data`.
    fn mac_create(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Returns `Ok(())` if `tag` is a correct MAC for `data`.
    fn mac_verify(&self, data: &[u8], tag: &[u8]) -> Result<(), Error>;
}

/// Encrypts and decrypts content for COSE_Encrypt and COSE_Encrypt0.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-content-encryption-algorith>.
pub trait Encryptor {
    /// The COSE algorithm identifier this encryptor uses, if any.
    fn alg(&self) -> Option<Label> {
        None
    }

    /// The key identifier to write to the unprotected header, if any.
    fn kid(&self) -> Option<&[u8]> {
        None
    }

    /// The nonce (IV) size, in bytes, this encryptor expects.
    fn nonce_size(&self) -> usize;

    /// The Base IV / Context IV used to derive the nonce when a COSE message
    /// carries `Partial IV` instead of a full `IV`.
    ///
    /// Returning `None` rejects messages that use `Partial IV`. When present,
    /// the slice length must match [`nonce_size`](Self::nonce_size); the
    /// message nonce is the Base IV XORed with the left-padded Partial IV.
    fn base_iv(&self) -> Option<&[u8]> {
        None
    }

    /// Encrypts `plaintext` with `nonce` and additional authenticated data.
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;

    /// Decrypts `ciphertext` with `nonce` and additional authenticated data.
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
}
