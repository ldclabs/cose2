//! Optional built-in Ed25519 providers backed by
//! [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek).
//!
//! This module is available with the `crypto-ed25519-dalek` feature. It
//! implements the crate's [`Signer`] and [`Verifier`] traits for the COSE
//! `EdDSA` algorithm over the Ed25519 curve (RFC 9053 §2.2), using COSE OKP
//! keys (`kty` = OKP, `crv` = Ed25519).

use ed25519_dalek::{Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

use crate::{iana, Error, Key, Label, Signer, Verifier};

/// A built-in Ed25519 signing provider for COSE_Sign and COSE_Sign1.
#[derive(Clone, Debug)]
pub struct Ed25519Signer {
    kid: Option<Vec<u8>>,
    key: SigningKey,
}

impl Ed25519Signer {
    /// Creates a signer from the 32-byte OKP private seed (`d`).
    pub fn from_secret_key(secret_key: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        let seed: [u8; SECRET_KEY_LENGTH] = secret_key
            .try_into()
            .map_err(|_| Error::custom("Ed25519 private key must be 32 bytes"))?;
        Ok(Self {
            kid,
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Creates a signer from an OKP COSE_Key carrying `crv` = Ed25519 and `d`.
    pub fn from_cose_key(key: &Key) -> Result<Self, Error> {
        require_alg(key)?;
        require_kty(key, iana::KeyTypeOKP)?;
        require_curve(key, iana::EllipticCurveEd25519)?;
        Self::from_secret_key(
            required_bytes(key, iana::OKPKeyParameterD, "d")?,
            key_kid(key)?,
        )
    }

    /// Returns the 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.key.verifying_key().to_bytes()
    }

    /// Exports the *public* COSE_Key for this signer.
    ///
    /// The seed cannot be recovered as a public key, so the result carries only
    /// the public parameter `x` and round-trips through
    /// [`Ed25519Verifier::from_cose_key`].
    pub fn to_cose_key(&self) -> Result<Key, Error> {
        Ok(okp_public_cose_key(
            self.key.verifying_key().as_bytes(),
            self.kid.as_deref(),
        ))
    }

    /// The configured COSE algorithm (always `EdDSA`).
    pub fn algorithm(&self) -> i64 {
        iana::AlgorithmEdDSA
    }
}

impl Signer for Ed25519Signer {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEdDSA.into())
    }

    fn kid(&self) -> Option<&[u8]> {
        self.kid.as_deref()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        // Bring the dalek signing trait into scope for the `sign` method
        // without shadowing the crate's `Signer` at module level.
        use ed25519_dalek::Signer as _;
        Ok(self.key.sign(data).to_bytes().to_vec())
    }
}

/// A built-in Ed25519 verifier for COSE_Sign and COSE_Sign1.
#[derive(Clone, Debug)]
pub struct Ed25519Verifier {
    kid: Option<Vec<u8>>,
    key: VerifyingKey,
}

impl Ed25519Verifier {
    /// Creates a verifier from the 32-byte OKP public key (`x`).
    pub fn from_public_key(public_key: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        let bytes: [u8; PUBLIC_KEY_LENGTH] = public_key
            .try_into()
            .map_err(|_| Error::custom("Ed25519 public key must be 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| Error::custom("invalid Ed25519 public key"))?;
        Ok(Self { kid, key })
    }

    /// Creates a verifier from an OKP COSE_Key carrying `crv` = Ed25519 and `x`.
    pub fn from_cose_key(key: &Key) -> Result<Self, Error> {
        require_alg(key)?;
        require_kty(key, iana::KeyTypeOKP)?;
        require_curve(key, iana::EllipticCurveEd25519)?;
        Self::from_public_key(
            required_bytes(key, iana::OKPKeyParameterX, "x")?,
            key_kid(key)?,
        )
    }

    /// Returns the 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.key.to_bytes()
    }

    /// Exports this verifier as a public COSE_Key.
    ///
    /// The result round-trips through [`Ed25519Verifier::from_cose_key`].
    pub fn to_cose_key(&self) -> Result<Key, Error> {
        Ok(okp_public_cose_key(
            self.key.as_bytes(),
            self.kid.as_deref(),
        ))
    }

    /// The configured COSE algorithm (always `EdDSA`).
    pub fn algorithm(&self) -> i64 {
        iana::AlgorithmEdDSA
    }
}

impl Verifier for Ed25519Verifier {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEdDSA.into())
    }

    fn kid(&self) -> Option<&[u8]> {
        self.kid.as_deref()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        let signature = Signature::from_slice(signature)
            .map_err(|_| Error::verify("invalid Ed25519 signature"))?;
        // `verify_strict` rejects non-canonical encodings and small-order keys.
        self.key
            .verify_strict(data, &signature)
            .map_err(|_| Error::verify("Ed25519 signature mismatch"))
    }
}

/// Builds an Ed25519 OKP public COSE_Key carrying `alg`, `crv`, `x` and an
/// optional `kid`.
fn okp_public_cose_key(x: &[u8], kid: Option<&[u8]>) -> Key {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeOKP).set_alg(iana::AlgorithmEdDSA);
    if let Some(kid) = kid {
        key.set_kid(kid.to_vec());
    }
    key.insert(iana::OKPKeyParameterCrv, iana::EllipticCurveEd25519);
    key.insert(iana::OKPKeyParameterX, x.to_vec());
    key
}

/// Accepts a COSE_Key whose `alg` is absent or exactly `EdDSA`.
fn require_alg(key: &Key) -> Result<(), Error> {
    match key.alg()? {
        None => Ok(()),
        Some(Label::Int(alg)) if alg == iana::AlgorithmEdDSA => Ok(()),
        Some(other) => Err(Error::custom(format!(
            "COSE_Key alg mismatch, expected {}, got {}",
            Label::from(iana::AlgorithmEdDSA),
            other
        ))),
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

fn require_curve(key: &Key, expected: i64) -> Result<(), Error> {
    match key.get_label(iana::OKPKeyParameterCrv)? {
        Some(Label::Int(curve)) if curve == expected => Ok(()),
        Some(other) => Err(Error::custom(format!(
            "COSE_Key curve mismatch, expected {}, got {}",
            Label::from(expected),
            other
        ))),
        None => Err(Error::custom("COSE_Key is missing curve")),
    }
}

fn required_bytes<'a>(key: &'a Key, label: i64, name: &str) -> Result<&'a [u8], Error> {
    key.get_bytes(label)?
        .ok_or_else(|| Error::custom(format!("COSE_Key is missing {name}")))
}

fn key_kid(key: &Key) -> Result<Option<Vec<u8>>, Error> {
    Ok(key.kid()?.map(ToOwned::to_owned))
}
