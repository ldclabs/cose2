//! Mock cryptographic implementations for tests.
//!
//! These are deterministic toys — not secure — used only to exercise the
//! COSE structure layer.

#![allow(dead_code)]

use cose2::{iana, Encryptor, Error, Label, Macer, Signer, Verifier};

/// A deterministic keyed "tag" over `secret || data`.
pub fn toy_tag(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut acc = [0u8; 8];
    for (i, b) in secret.iter().chain(data).enumerate() {
        acc[i % 8] ^= b.wrapping_add(i as u8);
    }
    acc.to_vec()
}

fn keystream(secret: &[u8], nonce: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let s = if secret.is_empty() {
            0
        } else {
            secret[i % secret.len()]
        };
        let n = if nonce.is_empty() {
            0
        } else {
            nonce[i % nonce.len()]
        };
        out.push(s ^ n ^ (i as u8));
    }
    out
}

/// A toy signer whose "signature" is [`toy_tag`] of `secret || data`.
pub struct MockSigner {
    pub alg: i64,
    pub kid: Vec<u8>,
    pub secret: Vec<u8>,
}

impl MockSigner {
    pub fn new(alg: i64, kid: &[u8]) -> Self {
        MockSigner {
            alg,
            kid: kid.to_vec(),
            secret: b"signer-secret".to_vec(),
        }
    }
}

impl Signer for MockSigner {
    fn alg(&self) -> Option<Label> {
        (self.alg != iana::AlgorithmReserved).then(|| self.alg.into())
    }
    fn kid(&self) -> Option<&[u8]> {
        (!self.kid.is_empty()).then_some(self.kid.as_slice())
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(toy_tag(&self.secret, data))
    }
}

/// A toy verifier; verification succeeds only if the `secret` matches the
/// signer's.
pub struct MockVerifier {
    pub alg: i64,
    pub kid: Vec<u8>,
    pub secret: Vec<u8>,
}

impl MockVerifier {
    pub fn new(alg: i64, kid: &[u8]) -> Self {
        MockVerifier {
            alg,
            kid: kid.to_vec(),
            secret: b"signer-secret".to_vec(),
        }
    }
}

impl Verifier for MockVerifier {
    fn alg(&self) -> Option<Label> {
        (self.alg != iana::AlgorithmReserved).then(|| self.alg.into())
    }
    fn kid(&self) -> Option<&[u8]> {
        (!self.kid.is_empty()).then_some(self.kid.as_slice())
    }
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        if toy_tag(&self.secret, data) == signature {
            Ok(())
        } else {
            Err(Error::verify("signature mismatch"))
        }
    }
}

/// A toy MACer.
pub struct MockMacer {
    pub alg: i64,
    pub kid: Vec<u8>,
    pub secret: Vec<u8>,
}

impl MockMacer {
    pub fn new(alg: i64, kid: &[u8]) -> Self {
        MockMacer {
            alg,
            kid: kid.to_vec(),
            secret: b"mac-secret".to_vec(),
        }
    }
}

impl Macer for MockMacer {
    fn alg(&self) -> Option<Label> {
        (self.alg != iana::AlgorithmReserved).then(|| self.alg.into())
    }
    fn kid(&self) -> Option<&[u8]> {
        (!self.kid.is_empty()).then_some(self.kid.as_slice())
    }
    fn mac_create(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(toy_tag(&self.secret, data))
    }
    fn mac_verify(&self, data: &[u8], tag: &[u8]) -> Result<(), Error> {
        if toy_tag(&self.secret, data) == tag {
            Ok(())
        } else {
            Err(Error::verify("tag mismatch"))
        }
    }
}

/// A reversible AEAD-like toy encryptor: keystream XOR plus an authentication
/// tag over `nonce || aad || plaintext`.
pub struct MockEncryptor {
    pub alg: i64,
    pub kid: Vec<u8>,
    pub nonce_size: usize,
    pub secret: Vec<u8>,
}

impl MockEncryptor {
    pub fn new(alg: i64, kid: &[u8], nonce_size: usize) -> Self {
        MockEncryptor {
            alg,
            kid: kid.to_vec(),
            nonce_size,
            secret: b"enc-secret".to_vec(),
        }
    }

    fn tag_input(nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(nonce);
        v.extend_from_slice(aad);
        v.extend_from_slice(plaintext);
        v
    }
}

impl Encryptor for MockEncryptor {
    fn alg(&self) -> Option<Label> {
        (self.alg != iana::AlgorithmReserved).then(|| self.alg.into())
    }
    fn kid(&self) -> Option<&[u8]> {
        (!self.kid.is_empty()).then_some(self.kid.as_slice())
    }
    fn nonce_size(&self) -> usize {
        self.nonce_size
    }
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let ks = keystream(&self.secret, nonce, plaintext.len());
        let mut out: Vec<u8> = plaintext.iter().zip(&ks).map(|(p, k)| p ^ k).collect();
        out.extend_from_slice(&toy_tag(
            &self.secret,
            &Self::tag_input(nonce, aad, plaintext),
        ));
        Ok(out)
    }
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.len() < 8 {
            return Err(Error::verify("ciphertext too short"));
        }
        let (body, tag) = ciphertext.split_at(ciphertext.len() - 8);
        let ks = keystream(&self.secret, nonce, body.len());
        let plaintext: Vec<u8> = body.iter().zip(&ks).map(|(c, k)| c ^ k).collect();
        if toy_tag(&self.secret, &Self::tag_input(nonce, aad, &plaintext)) != tag {
            return Err(Error::verify("authentication tag mismatch"));
        }
        Ok(plaintext)
    }
}

/// An encryptor returning fixed ciphertext/plaintext, for reproducing RFC
/// test vectors whose ciphertext came from real AEAD.
pub struct FixedEncryptor {
    pub alg: i64,
    pub nonce_size: usize,
    pub ciphertext: Vec<u8>,
    pub plaintext: Vec<u8>,
}

impl Encryptor for FixedEncryptor {
    fn alg(&self) -> Option<Label> {
        (self.alg != iana::AlgorithmReserved).then(|| self.alg.into())
    }
    fn nonce_size(&self) -> usize {
        self.nonce_size
    }
    fn encrypt(&self, _nonce: &[u8], _plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.ciphertext.clone())
    }
    fn decrypt(&self, _nonce: &[u8], _ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.plaintext.clone())
    }
}

/// A signer that always fails, to exercise error propagation.
pub struct FailingSigner;

impl Signer for FailingSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::custom("signing unavailable"))
    }
}

// The "minimal" implementations below implement only the required trait
// methods, relying on the default `alg()`/`kid()` so those defaults are
// exercised.

const MIN_SECRET: &[u8] = b"minimal";

pub struct MinimalSigner;
impl Signer for MinimalSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(toy_tag(MIN_SECRET, data))
    }
}

pub struct MinimalVerifier;
impl Verifier for MinimalVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        if toy_tag(MIN_SECRET, data) == signature {
            Ok(())
        } else {
            Err(Error::verify("mismatch"))
        }
    }
}

pub struct MinimalMacer;
impl Macer for MinimalMacer {
    fn mac_create(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(toy_tag(MIN_SECRET, data))
    }
    fn mac_verify(&self, data: &[u8], tag: &[u8]) -> Result<(), Error> {
        if toy_tag(MIN_SECRET, data) == tag {
            Ok(())
        } else {
            Err(Error::verify("mismatch"))
        }
    }
}

pub struct MinimalEncryptor;
impl Encryptor for MinimalEncryptor {
    fn nonce_size(&self) -> usize {
        4
    }
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = plaintext.to_vec();
        out.extend_from_slice(&toy_tag(MIN_SECRET, &[nonce, aad, plaintext].concat()));
        Ok(out)
    }
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let (pt, tag) = ciphertext.split_at(ciphertext.len() - 8);
        if toy_tag(MIN_SECRET, &[nonce, aad, pt].concat()) != tag {
            return Err(Error::verify("mismatch"));
        }
        Ok(pt.to_vec())
    }
}
