//! Optional built-in Ed25519 providers backed by
//! [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek).
//!
//! This module is available with the `crypto-ed25519-dalek` feature. It
//! implements the crate's [`Signer`] and [`Verifier`] traits for the fully
//! specified COSE `Ed25519` algorithm and legacy generic `EdDSA` identifier,
//! using COSE OKP keys (`kty` = OKP, `crv` = Ed25519).

use ed25519_dalek::{Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

use crate::{iana, Error, Key, Label, Signer, Verifier};

/// A built-in Ed25519 signing provider for COSE_Sign and COSE_Sign1.
#[derive(Clone, Debug)]
pub struct Ed25519Signer {
    alg: i64,
    kid: Option<Vec<u8>>,
    key: SigningKey,
}

impl Ed25519Signer {
    /// Creates a signer from the 32-byte OKP private seed (`d`).
    pub fn from_secret_key(secret_key: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        Self::from_secret_key_with_alg(iana::AlgorithmEd25519, secret_key, kid)
    }

    /// Creates a signer with the fully specified Ed25519 or legacy EdDSA identifier.
    pub fn from_secret_key_with_alg(
        alg: i64,
        secret_key: &[u8],
        kid: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        require_supported_alg(alg)?;
        let seed: [u8; SECRET_KEY_LENGTH] = secret_key
            .try_into()
            .map_err(|_| Error::custom("Ed25519 private key must be 32 bytes"))?;
        Ok(Self {
            alg,
            kid,
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Creates a signer from an OKP COSE_Key carrying `crv` = Ed25519 and `d`.
    pub fn from_cose_key(key: &Key) -> Result<Self, Error> {
        key.require_any_operation(&[iana::KeyOperationSign], "signing")?;
        let alg = require_alg(key)?;
        key.require_integer_kty(iana::KeyTypeOKP)?;
        key.require_integer_parameter(
            iana::OKPKeyParameterCrv,
            iana::EllipticCurveEd25519,
            "curve",
        )?;
        let signer = Self::from_secret_key_with_alg(
            alg,
            key.required_bytes(iana::OKPKeyParameterD, "d")?,
            key.kid_owned()?,
        )?;
        if let Some(expected) = key.get_bytes(iana::OKPKeyParameterX)? {
            if expected != signer.public_key() {
                return Err(Error::custom(
                    "COSE_Key Ed25519 public key x does not match private key d",
                ));
            }
        }
        Ok(signer)
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
        let mut key = okp_public_cose_key(
            self.alg,
            self.key.verifying_key().as_bytes(),
            self.kid.as_deref(),
        );
        key.set_ops([iana::KeyOperationVerify]);
        Ok(key)
    }

    /// The configured COSE algorithm (`Ed25519` by default).
    pub fn algorithm(&self) -> i64 {
        self.alg
    }
}

impl Signer for Ed25519Signer {
    fn alg(&self) -> Option<Label> {
        Some(self.alg.into())
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
    alg: i64,
    kid: Option<Vec<u8>>,
    key: VerifyingKey,
}

impl Ed25519Verifier {
    /// Creates a verifier from the 32-byte OKP public key (`x`).
    pub fn from_public_key(public_key: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        Self::from_public_key_with_alg(iana::AlgorithmEd25519, public_key, kid)
    }

    /// Creates a verifier with the fully specified Ed25519 or legacy EdDSA identifier.
    pub fn from_public_key_with_alg(
        alg: i64,
        public_key: &[u8],
        kid: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        require_supported_alg(alg)?;
        let bytes: [u8; PUBLIC_KEY_LENGTH] = public_key
            .try_into()
            .map_err(|_| Error::custom("Ed25519 public key must be 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| Error::custom("invalid Ed25519 public key"))?;
        Ok(Self { alg, kid, key })
    }

    /// Creates a verifier from an OKP COSE_Key carrying `crv` = Ed25519 and `x`.
    pub fn from_cose_key(key: &Key) -> Result<Self, Error> {
        key.require_any_operation(&[iana::KeyOperationVerify], "signature verification")?;
        let alg = require_alg(key)?;
        key.require_integer_kty(iana::KeyTypeOKP)?;
        key.require_integer_parameter(
            iana::OKPKeyParameterCrv,
            iana::EllipticCurveEd25519,
            "curve",
        )?;
        Self::from_public_key_with_alg(
            alg,
            key.required_bytes(iana::OKPKeyParameterX, "x")?,
            key.kid_owned()?,
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
        let mut key = okp_public_cose_key(self.alg, self.key.as_bytes(), self.kid.as_deref());
        key.set_ops([iana::KeyOperationVerify]);
        Ok(key)
    }

    /// The configured COSE algorithm (`Ed25519` by default).
    pub fn algorithm(&self) -> i64 {
        self.alg
    }
}

impl Verifier for Ed25519Verifier {
    fn alg(&self) -> Option<Label> {
        Some(self.alg.into())
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
fn okp_public_cose_key(alg: i64, x: &[u8], kid: Option<&[u8]>) -> Key {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeOKP).set_alg(alg);
    if let Some(kid) = kid {
        key.set_kid(kid.to_vec());
    }
    key.insert(iana::OKPKeyParameterCrv, iana::EllipticCurveEd25519);
    key.insert(iana::OKPKeyParameterX, x.to_vec());
    key
}

/// Accepts a COSE_Key whose `alg` is absent, Ed25519, or legacy EdDSA.
fn require_alg(key: &Key) -> Result<i64, Error> {
    match key.alg()? {
        None => Ok(iana::AlgorithmEd25519),
        Some(Label::Int(alg)) if matches!(alg, iana::AlgorithmEd25519 | iana::AlgorithmEdDSA) => {
            Ok(alg)
        }
        Some(other) => Err(Error::custom(format!(
            "COSE_Key alg mismatch, expected {} or {}, got {other}",
            Label::from(iana::AlgorithmEd25519),
            Label::from(iana::AlgorithmEdDSA)
        ))),
    }
}

fn require_supported_alg(alg: i64) -> Result<(), Error> {
    if matches!(alg, iana::AlgorithmEd25519 | iana::AlgorithmEdDSA) {
        Ok(())
    } else {
        Err(Error::custom(format!(
            "unsupported Ed25519 algorithm {}",
            Label::from(alg)
        )))
    }
}
