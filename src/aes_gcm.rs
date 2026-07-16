//! Optional built-in AES-GCM content encryptor backed by
//! [`aes-gcm`](https://crates.io/crates/aes-gcm).
//!
//! This module is available with the `crypto-aes-gcm` feature. It implements
//! the crate's [`Encryptor`] trait for the COSE AEAD algorithms `A128GCM` and
//! `A256GCM` (RFC 9053 §4.1) using symmetric COSE keys (`kty` = Symmetric).
//! The 96-bit GCM nonce is supplied by the message as a full `IV`, or derived
//! from a `Partial IV` and the configured Base IV.

use std::fmt;

// `aes_gcm` is also the name of this module, so reach the crate through `::`.
use ::aes_gcm::{
    aead::{Aead, Nonce, Payload},
    Aes128Gcm, Aes256Gcm, KeyInit,
};
use zeroize::Zeroizing;

use crate::{iana, Encryptor, Error, Key, Label};

/// The AES-GCM nonce size, in bytes (96 bits, RFC 9053 §4.1).
const NONCE_LEN: usize = 12;

/// A built-in AES-GCM provider for COSE_Encrypt and COSE_Encrypt0 content.
#[derive(Clone)]
pub struct AesGcmEncryptor {
    alg: i64,
    kid: Option<Vec<u8>>,
    cipher: AesGcmCipher,
    // Retained so the symmetric `k` can be re-exported by `to_cose_key`; the
    // cipher does not expose its raw bytes. Zeroized on drop (every clone
    // wipes its own copy).
    raw_key: Zeroizing<Vec<u8>>,
    base_iv: Option<Vec<u8>>,
}

// The variants are boxed because AES-256's key schedule is markedly larger
// than AES-128's, which would otherwise bloat every `AesGcmEncryptor`.
#[derive(Clone)]
enum AesGcmCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl AesGcmEncryptor {
    /// Creates a provider from a COSE AES-GCM algorithm and raw key bytes.
    pub fn new(alg: i64, key: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        let cipher = match alg {
            iana::AlgorithmA128GCM => AesGcmCipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key)
                    .map_err(|_| Error::custom("invalid A128GCM key length"))?,
            )),
            iana::AlgorithmA256GCM => AesGcmCipher::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key)
                    .map_err(|_| Error::custom("invalid A256GCM key length"))?,
            )),
            _ => return Err(unsupported_alg(alg)),
        };
        Ok(Self {
            alg,
            kid,
            cipher,
            raw_key: Zeroizing::new(key.to_vec()),
            base_iv: None,
        })
    }

    /// Creates a provider from a symmetric [`Key`] carrying `alg` and `k`.
    ///
    /// A Base IV (`Base IV`, label 5) on the key is preserved for use with
    /// COSE `Partial IV`.
    pub fn from_cose_key(key: &Key) -> Result<Self, Error> {
        require_kty(key, iana::KeyTypeSymmetric)?;
        let alg = required_alg(key)?;
        let mut encryptor = Self::new(
            alg,
            required_bytes(key, iana::SymmetricKeyParameterK, "k")?,
            key_kid(key)?,
        )?;
        encryptor.base_iv = key.base_iv()?.map(ToOwned::to_owned);
        Ok(encryptor)
    }

    /// Sets the Base IV used with COSE `Partial IV`.
    pub fn with_base_iv(mut self, base_iv: impl Into<Vec<u8>>) -> Self {
        self.base_iv = Some(base_iv.into());
        self
    }

    /// Exports this provider as a symmetric COSE_Key carrying `alg`, `k` and,
    /// when configured, the Base IV.
    ///
    /// The result round-trips through [`AesGcmEncryptor::from_cose_key`].
    /// Note the exported [`Key`] holds an unprotected copy of the secret; it
    /// is the caller's responsibility to handle it carefully.
    pub fn to_cose_key(&self) -> Result<Key, Error> {
        let mut key = Key::new();
        key.set_kty(iana::KeyTypeSymmetric).set_alg(self.alg);
        if let Some(kid) = &self.kid {
            key.set_kid(kid.clone());
        }
        key.insert(iana::SymmetricKeyParameterK, self.raw_key.to_vec());
        if let Some(base_iv) = &self.base_iv {
            key.insert(iana::KeyParameterBaseIV, base_iv.clone());
        }
        Ok(key)
    }

    /// The configured COSE algorithm.
    pub fn algorithm(&self) -> i64 {
        self.alg
    }
}

// Manual `Debug` keeps the raw key material out of formatted output.
impl fmt::Debug for AesGcmEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcmEncryptor")
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .field("base_iv", &self.base_iv)
            .finish_non_exhaustive()
    }
}

impl Encryptor for AesGcmEncryptor {
    fn alg(&self) -> Option<Label> {
        Some(self.alg.into())
    }

    fn kid(&self) -> Option<&[u8]> {
        self.kid.as_deref()
    }

    fn nonce_size(&self) -> usize {
        NONCE_LEN
    }

    fn base_iv(&self) -> Option<&[u8]> {
        self.base_iv.as_deref()
    }

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match &self.cipher {
            AesGcmCipher::Aes128(c) => aead_seal(c.as_ref(), nonce, payload),
            AesGcmCipher::Aes256(c) => aead_seal(c.as_ref(), nonce, payload),
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match &self.cipher {
            AesGcmCipher::Aes128(c) => aead_open(c.as_ref(), nonce, payload),
            AesGcmCipher::Aes256(c) => aead_open(c.as_ref(), nonce, payload),
        }
    }
}

/// Encrypts a payload, checking the nonce is the cipher's expected length.
fn aead_seal<C: Aead>(cipher: &C, nonce: &[u8], payload: Payload) -> Result<Vec<u8>, Error> {
    let nonce =
        Nonce::<C>::try_from(nonce).map_err(|_| Error::custom("invalid AEAD nonce length"))?;
    cipher
        .encrypt(&nonce, payload)
        .map_err(|_| Error::custom("AEAD encryption failed"))
}

/// Decrypts a payload, checking the nonce is the cipher's expected length.
fn aead_open<C: Aead>(cipher: &C, nonce: &[u8], payload: Payload) -> Result<Vec<u8>, Error> {
    let nonce =
        Nonce::<C>::try_from(nonce).map_err(|_| Error::custom("invalid AEAD nonce length"))?;
    cipher
        .decrypt(&nonce, payload)
        .map_err(|_| Error::verify("AEAD authentication failed"))
}

fn required_alg(key: &Key) -> Result<i64, Error> {
    match key.alg()? {
        Some(Label::Int(alg)) => Ok(alg),
        Some(Label::Text(_)) => Err(Error::custom(
            "the built-in AES-GCM backend does not support text-string algorithms",
        )),
        None => Err(Error::custom("COSE_Key is missing alg")),
    }
}

fn require_kty(key: &Key, expected: i64) -> Result<(), Error> {
    match key.kty()? {
        Some(Label::Int(kty)) if kty == expected => Ok(()),
        Some(other) => Err(Error::custom(format!(
            "COSE_Key kty mismatch, expected {}, got {}",
            Label::from(expected),
            other
        ))),
        None => Err(Error::custom("COSE_Key is missing kty")),
    }
}

fn required_bytes<'a>(key: &'a Key, label: i64, name: &str) -> Result<&'a [u8], Error> {
    key.get_bytes(label)?
        .ok_or_else(|| Error::custom(format!("COSE_Key is missing {name}")))
}

fn key_kid(key: &Key) -> Result<Option<Vec<u8>>, Error> {
    Ok(key.kid()?.map(ToOwned::to_owned))
}

fn unsupported_alg(alg: i64) -> Error {
    Error::custom(format!(
        "unsupported AEAD algorithm {} for the built-in AES-GCM backend",
        Label::from(alg)
    ))
}
