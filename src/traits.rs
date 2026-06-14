//! Pluggable cryptographic interfaces.
//!
//! `cose2` models COSE structures but does not implement cryptography
//! itself. Callers supply signing, verification, MAC and encryption by
//! implementing these traits with the crypto library of their choice.

use crate::Error;

/// Produces digital signatures for COSE_Sign and COSE_Sign1.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-signature-algorithms>.
pub trait Signer {
    /// The COSE algorithm identifier this signer uses, or
    /// [`AlgorithmReserved`](crate::iana::AlgorithmReserved) (0) when none
    /// should be written to the protected header.
    fn alg(&self) -> i64 {
        crate::iana::AlgorithmReserved
    }

    /// The key identifier, or an empty slice when none should be written to
    /// the unprotected header.
    fn kid(&self) -> &[u8] {
        &[]
    }

    /// Computes the signature over `data`.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Verifies digital signatures for COSE_Sign and COSE_Sign1.
pub trait Verifier {
    /// The COSE algorithm identifier this verifier expects.
    fn alg(&self) -> i64 {
        crate::iana::AlgorithmReserved
    }

    /// The key identifier matched against a message's `kid` header.
    fn kid(&self) -> &[u8] {
        &[]
    }

    /// Returns `Ok(())` if `signature` is valid for `data`, otherwise an error.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error>;
}

/// Computes and verifies message authentication codes for COSE_Mac and
/// COSE_Mac0.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-message-authentication-code>.
pub trait Macer {
    /// The COSE algorithm identifier this MACer uses.
    fn alg(&self) -> i64 {
        crate::iana::AlgorithmReserved
    }

    /// The key identifier.
    fn kid(&self) -> &[u8] {
        &[]
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
    /// The COSE algorithm identifier this encryptor uses.
    fn alg(&self) -> i64 {
        crate::iana::AlgorithmReserved
    }

    /// The key identifier.
    fn kid(&self) -> &[u8] {
        &[]
    }

    /// The nonce (IV) size, in bytes, this encryptor expects.
    fn nonce_size(&self) -> usize;

    /// Encrypts `plaintext` with `nonce` and additional authenticated data.
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;

    /// Decrypts `ciphertext` with `nonce` and additional authenticated data.
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
}
