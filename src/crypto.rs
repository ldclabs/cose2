//! Optional `ring`-based cryptographic providers.
//!
//! This module is available with the `crypto-ring` feature. It implements the
//! crate's pluggable traits for the algorithms that `ring` exposes in COSE
//! wire-compatible form:
//!
//! - signatures: Ed25519, ES256, ES384, RS256/384/512, PS256/384/512
//! - MACs: HMAC 256/64, HMAC 256/256, HMAC 384/384, HMAC 512/512
//! - AEAD content encryption: A128GCM, A256GCM, ChaCha20/Poly1305
//!
//! Algorithms not supported by `ring` are rejected during provider
//! construction.

use std::fmt;

use ring::{
    aead, hmac, rand, rsa, signature,
    signature::{KeyPair, RsaParameters},
};

use crate::{iana, Encryptor, Error, Key, Label, Macer, Signer, Verifier};

/// A `ring` HMAC provider for COSE_Mac and COSE_Mac0.
#[derive(Clone, Debug)]
pub struct RingMacer {
    alg: i64,
    kid: Option<Vec<u8>>,
    key: hmac::Key,
    tag_len: usize,
}

impl RingMacer {
    /// Creates a provider from a COSE HMAC algorithm and raw key bytes.
    pub fn new(alg: i64, key: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        let (algorithm, tag_len) = hmac_algorithm(alg)?;
        Ok(Self {
            alg,
            kid,
            key: hmac::Key::new(algorithm, key),
            tag_len,
        })
    }

    /// Creates a provider from a symmetric [`Key`] carrying `alg` and `k`.
    pub fn from_cose_key(key: &Key) -> Result<Self, Error> {
        require_kty(key, iana::KeyTypeSymmetric)?;
        let alg = required_alg(key)?;
        Self::new(
            alg,
            required_bytes(key, iana::SymmetricKeyParameterK, "k")?,
            key_kid(key)?,
        )
    }

    /// The configured COSE algorithm.
    pub fn algorithm(&self) -> i64 {
        self.alg
    }
}

impl Macer for RingMacer {
    fn alg(&self) -> Option<Label> {
        Some(self.alg.into())
    }

    fn kid(&self) -> Option<&[u8]> {
        self.kid.as_deref()
    }

    fn mac_create(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let tag = hmac::sign(&self.key, data);
        Ok(tag.as_ref()[..self.tag_len].to_vec())
    }

    fn mac_verify(&self, data: &[u8], tag: &[u8]) -> Result<(), Error> {
        if tag.len() != self.tag_len {
            return Err(Error::verify("HMAC tag length mismatch"));
        }
        let expected = hmac::sign(&self.key, data);
        if constant_time_eq(&expected.as_ref()[..self.tag_len], tag) {
            Ok(())
        } else {
            Err(Error::verify("HMAC tag mismatch"))
        }
    }
}

/// A `ring` AEAD provider for COSE_Encrypt and COSE_Encrypt0 content.
#[derive(Clone, Debug)]
pub struct RingEncryptor {
    alg: i64,
    kid: Option<Vec<u8>>,
    key: aead::LessSafeKey,
    base_iv: Option<Vec<u8>>,
}

impl RingEncryptor {
    /// Creates a provider from a COSE AEAD algorithm and raw content-encryption key.
    pub fn new(alg: i64, key: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        let algorithm = aead_algorithm(alg)?;
        let unbound = aead::UnboundKey::new(algorithm, key)
            .map_err(|_| Error::custom("invalid AEAD key length"))?;
        Ok(Self {
            alg,
            kid,
            key: aead::LessSafeKey::new(unbound),
            base_iv: None,
        })
    }

    /// Creates a provider from a symmetric [`Key`] carrying `alg` and `k`.
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

    /// The configured COSE algorithm.
    pub fn algorithm(&self) -> i64 {
        self.alg
    }
}

impl Encryptor for RingEncryptor {
    fn alg(&self) -> Option<Label> {
        Some(self.alg.into())
    }

    fn kid(&self) -> Option<&[u8]> {
        self.kid.as_deref()
    }

    fn nonce_size(&self) -> usize {
        aead::NONCE_LEN
    }

    fn base_iv(&self) -> Option<&[u8]> {
        self.base_iv.as_deref()
    }

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| Error::custom("invalid AEAD nonce length"))?;
        let mut out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut out)
            .map_err(|_| Error::custom("AEAD encryption failed"))?;
        Ok(out)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| Error::custom("invalid AEAD nonce length"))?;
        let mut in_out = ciphertext.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, aead::Aad::from(aad), &mut in_out)
            .map_err(|_| Error::verify("AEAD authentication failed"))?;
        Ok(plaintext.to_vec())
    }
}

/// A `ring` signing provider for COSE_Sign and COSE_Sign1.
#[derive(Debug)]
pub struct RingSigner {
    alg: i64,
    kid: Option<Vec<u8>>,
    key: RingSigningKey,
}

enum RingSigningKey {
    Ed25519(signature::Ed25519KeyPair),
    Ecdsa(signature::EcdsaKeyPair),
    Rsa {
        key_pair: rsa::KeyPair,
        padding: &'static dyn signature::RsaEncoding,
    },
}

impl fmt::Debug for RingSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RingSigningKey::Ed25519(_) => f.write_str("Ed25519"),
            RingSigningKey::Ecdsa(_) => f.write_str("Ecdsa"),
            RingSigningKey::Rsa { .. } => f.write_str("Rsa"),
        }
    }
}

impl RingSigner {
    /// Creates a signer from a COSE_Key.
    pub fn from_cose_key(key: &Key) -> Result<Self, Error> {
        let alg = required_alg(key)?;
        match alg {
            iana::AlgorithmEdDSA => Self::ed25519_from_cose_key(key),
            iana::AlgorithmES256 | iana::AlgorithmES384 => Self::ecdsa_from_cose_key(key, alg),
            iana::AlgorithmRS256
            | iana::AlgorithmRS384
            | iana::AlgorithmRS512
            | iana::AlgorithmPS256
            | iana::AlgorithmPS384
            | iana::AlgorithmPS512 => Self::rsa_from_cose_key(key, alg),
            _ => Err(unsupported_alg("signing", alg)),
        }
    }

    /// Creates an Ed25519 signer from PKCS#8 private-key bytes.
    pub fn ed25519_from_pkcs8(pkcs8: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        let key = signature::Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| Error::custom("invalid Ed25519 PKCS#8 key"))?;
        Ok(Self {
            alg: iana::AlgorithmEdDSA,
            kid,
            key: RingSigningKey::Ed25519(key),
        })
    }

    /// Creates an Ed25519 signer from the COSE OKP private seed and public key.
    pub fn ed25519_from_seed_and_public_key(
        seed: &[u8],
        public_key: &[u8],
        kid: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let key = signature::Ed25519KeyPair::from_seed_and_public_key(seed, public_key)
            .map_err(|_| Error::custom("invalid Ed25519 key material"))?;
        Ok(Self {
            alg: iana::AlgorithmEdDSA,
            kid,
            key: RingSigningKey::Ed25519(key),
        })
    }

    /// Creates an ES256 signer from PKCS#8 private-key bytes.
    pub fn es256_from_pkcs8(pkcs8: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        Self::ecdsa_from_pkcs8(
            iana::AlgorithmES256,
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8,
            kid,
        )
    }

    /// Creates an ES384 signer from PKCS#8 private-key bytes.
    pub fn es384_from_pkcs8(pkcs8: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        Self::ecdsa_from_pkcs8(
            iana::AlgorithmES384,
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            pkcs8,
            kid,
        )
    }

    /// Creates an RSA signer from PKCS#8 private-key bytes.
    pub fn rsa_from_pkcs8(alg: i64, pkcs8: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        let padding = rsa_signing_algorithm(alg)?;
        let key_pair =
            rsa::KeyPair::from_pkcs8(pkcs8).map_err(|_| Error::custom("invalid RSA PKCS#8 key"))?;
        Ok(Self {
            alg,
            kid,
            key: RingSigningKey::Rsa { key_pair, padding },
        })
    }

    /// Creates an RSA signer from a DER-encoded PKCS#1 RSAPrivateKey.
    pub fn rsa_from_der(alg: i64, der: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        let padding = rsa_signing_algorithm(alg)?;
        let key_pair =
            rsa::KeyPair::from_der(der).map_err(|_| Error::custom("invalid RSA DER key"))?;
        Ok(Self {
            alg,
            kid,
            key: RingSigningKey::Rsa { key_pair, padding },
        })
    }

    /// Returns the public key bytes for Ed25519 and ECDSA signers.
    pub fn public_key(&self) -> Option<&[u8]> {
        match &self.key {
            RingSigningKey::Ed25519(key) => Some(key.public_key().as_ref()),
            RingSigningKey::Ecdsa(key) => Some(key.public_key().as_ref()),
            RingSigningKey::Rsa { .. } => None,
        }
    }

    /// The configured COSE algorithm.
    pub fn algorithm(&self) -> i64 {
        self.alg
    }

    fn ed25519_from_cose_key(key: &Key) -> Result<Self, Error> {
        require_kty(key, iana::KeyTypeOKP)?;
        require_curve(key, iana::OKPKeyParameterCrv, iana::EllipticCurveEd25519)?;
        Self::ed25519_from_seed_and_public_key(
            required_bytes(key, iana::OKPKeyParameterD, "d")?,
            required_bytes(key, iana::OKPKeyParameterX, "x")?,
            key_kid(key)?,
        )
    }

    fn ecdsa_from_cose_key(key: &Key, alg: i64) -> Result<Self, Error> {
        require_kty(key, iana::KeyTypeEC2)?;
        let (curve, signing_algorithm) = match alg {
            iana::AlgorithmES256 => (
                iana::EllipticCurveP_256,
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            ),
            iana::AlgorithmES384 => (
                iana::EllipticCurveP_384,
                &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            ),
            _ => return Err(unsupported_alg("ECDSA signing", alg)),
        };
        require_curve(key, iana::EC2KeyParameterCrv, curve)?;
        let kid = key_kid(key)?;
        let public_key = ec2_uncompressed_public_key(key)?;
        let rng = rand::SystemRandom::new();
        let signing_key = signature::EcdsaKeyPair::from_private_key_and_public_key(
            signing_algorithm,
            required_bytes(key, iana::EC2KeyParameterD, "d")?,
            &public_key,
            &rng,
        )
        .map_err(|_| Error::custom("invalid ECDSA key material"))?;
        Ok(Self {
            alg,
            kid,
            key: RingSigningKey::Ecdsa(signing_key),
        })
    }

    fn ecdsa_from_pkcs8(
        alg: i64,
        signing_algorithm: &'static signature::EcdsaSigningAlgorithm,
        pkcs8: &[u8],
        kid: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let rng = rand::SystemRandom::new();
        let key = signature::EcdsaKeyPair::from_pkcs8(signing_algorithm, pkcs8, &rng)
            .map_err(|_| Error::custom("invalid ECDSA PKCS#8 key"))?;
        Ok(Self {
            alg,
            kid,
            key: RingSigningKey::Ecdsa(key),
        })
    }

    fn rsa_from_cose_key(key: &Key, alg: i64) -> Result<Self, Error> {
        require_kty(key, iana::KeyTypeRSA)?;
        let padding = rsa_signing_algorithm(alg)?;
        let components = rsa::KeyPairComponents {
            public_key: rsa::PublicKeyComponents {
                n: required_bytes(key, iana::RSAKeyParameterN, "n")?,
                e: required_bytes(key, iana::RSAKeyParameterE, "e")?,
            },
            d: required_bytes(key, iana::RSAKeyParameterD, "d")?,
            p: required_bytes(key, iana::RSAKeyParameterP, "p")?,
            q: required_bytes(key, iana::RSAKeyParameterQ, "q")?,
            dP: required_bytes(key, iana::RSAKeyParameterDP, "dP")?,
            dQ: required_bytes(key, iana::RSAKeyParameterDQ, "dQ")?,
            qInv: required_bytes(key, iana::RSAKeyParameterQInv, "qInv")?,
        };
        let key_pair = rsa::KeyPair::from_components(&components)
            .map_err(|_| Error::custom("invalid RSA key material"))?;
        Ok(Self {
            alg,
            kid: key_kid(key)?,
            key: RingSigningKey::Rsa { key_pair, padding },
        })
    }
}

impl Signer for RingSigner {
    fn alg(&self) -> Option<Label> {
        Some(self.alg.into())
    }

    fn kid(&self) -> Option<&[u8]> {
        self.kid.as_deref()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.key {
            RingSigningKey::Ed25519(key) => Ok(key.sign(data).as_ref().to_vec()),
            RingSigningKey::Ecdsa(key) => {
                let rng = rand::SystemRandom::new();
                Ok(key
                    .sign(&rng, data)
                    .map_err(|_| Error::custom("ECDSA signing failed"))?
                    .as_ref()
                    .to_vec())
            }
            RingSigningKey::Rsa { key_pair, padding } => {
                let rng = rand::SystemRandom::new();
                let mut signature = vec![0; key_pair.public().modulus_len()];
                key_pair
                    .sign(*padding, &rng, data, &mut signature)
                    .map_err(|_| Error::custom("RSA signing failed"))?;
                Ok(signature)
            }
        }
    }
}

/// A `ring` verifier for COSE_Sign and COSE_Sign1.
#[derive(Clone, Debug)]
pub struct RingVerifier {
    alg: i64,
    kid: Option<Vec<u8>>,
    key: RingVerificationKey,
}

#[derive(Clone, Debug)]
enum RingVerificationKey {
    Ed25519(Vec<u8>),
    Ecdsa(Vec<u8>),
    RsaComponents { n: Vec<u8>, e: Vec<u8> },
    RsaDer(Vec<u8>),
}

impl RingVerifier {
    /// Creates a verifier from a COSE_Key.
    pub fn from_cose_key(key: &Key) -> Result<Self, Error> {
        let alg = required_alg(key)?;
        match alg {
            iana::AlgorithmEdDSA => {
                require_kty(key, iana::KeyTypeOKP)?;
                require_curve(key, iana::OKPKeyParameterCrv, iana::EllipticCurveEd25519)?;
                Self::ed25519(
                    required_bytes(key, iana::OKPKeyParameterX, "x")?,
                    key_kid(key)?,
                )
            }
            iana::AlgorithmES256 | iana::AlgorithmES384 => {
                require_kty(key, iana::KeyTypeEC2)?;
                let expected_curve = if alg == iana::AlgorithmES256 {
                    iana::EllipticCurveP_256
                } else {
                    iana::EllipticCurveP_384
                };
                require_curve(key, iana::EC2KeyParameterCrv, expected_curve)?;
                Self::ecdsa(alg, &ec2_uncompressed_public_key(key)?, key_kid(key)?)
            }
            iana::AlgorithmRS256
            | iana::AlgorithmRS384
            | iana::AlgorithmRS512
            | iana::AlgorithmPS256
            | iana::AlgorithmPS384
            | iana::AlgorithmPS512 => {
                require_kty(key, iana::KeyTypeRSA)?;
                Self::rsa_components(
                    alg,
                    required_bytes(key, iana::RSAKeyParameterN, "n")?,
                    required_bytes(key, iana::RSAKeyParameterE, "e")?,
                    key_kid(key)?,
                )
            }
            _ => Err(unsupported_alg("verification", alg)),
        }
    }

    /// Creates an Ed25519 verifier from the raw public key.
    pub fn ed25519(public_key: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        Ok(Self {
            alg: iana::AlgorithmEdDSA,
            kid,
            key: RingVerificationKey::Ed25519(public_key.to_vec()),
        })
    }

    /// Creates an ECDSA verifier from a COSE algorithm and uncompressed SEC1 public key.
    pub fn ecdsa(alg: i64, public_key: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        ecdsa_verification_algorithm(alg)?;
        Ok(Self {
            alg,
            kid,
            key: RingVerificationKey::Ecdsa(public_key.to_vec()),
        })
    }

    /// Creates an RSA verifier from raw public modulus and exponent bytes.
    pub fn rsa_components(
        alg: i64,
        n: &[u8],
        e: &[u8],
        kid: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        rsa_verification_algorithm(alg)?;
        Ok(Self {
            alg,
            kid,
            key: RingVerificationKey::RsaComponents {
                n: n.to_vec(),
                e: e.to_vec(),
            },
        })
    }

    /// Creates an RSA verifier from a DER-encoded PKCS#1 RSAPublicKey.
    pub fn rsa_der(alg: i64, der: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        rsa_verification_algorithm(alg)?;
        Ok(Self {
            alg,
            kid,
            key: RingVerificationKey::RsaDer(der.to_vec()),
        })
    }

    /// The configured COSE algorithm.
    pub fn algorithm(&self) -> i64 {
        self.alg
    }
}

impl Verifier for RingVerifier {
    fn alg(&self) -> Option<Label> {
        Some(self.alg.into())
    }

    fn kid(&self) -> Option<&[u8]> {
        self.kid.as_deref()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        match &self.key {
            RingVerificationKey::Ed25519(public_key) => {
                signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
                    .verify(data, signature)
                    .map_err(|_| Error::verify("Ed25519 signature mismatch"))
            }
            RingVerificationKey::Ecdsa(public_key) => {
                let algorithm = ecdsa_verification_algorithm(self.alg)?;
                signature::UnparsedPublicKey::new(algorithm, public_key)
                    .verify(data, signature)
                    .map_err(|_| Error::verify("ECDSA signature mismatch"))
            }
            RingVerificationKey::RsaComponents { n, e } => {
                let algorithm = rsa_verification_algorithm(self.alg)?;
                let public_key = signature::RsaPublicKeyComponents { n, e };
                public_key
                    .verify(algorithm, data, signature)
                    .map_err(|_| Error::verify("RSA signature mismatch"))
            }
            RingVerificationKey::RsaDer(der) => {
                let algorithm = rsa_verification_algorithm(self.alg)?;
                signature::UnparsedPublicKey::new(algorithm, der)
                    .verify(data, signature)
                    .map_err(|_| Error::verify("RSA signature mismatch"))
            }
        }
    }
}

fn hmac_algorithm(alg: i64) -> Result<(hmac::Algorithm, usize), Error> {
    match alg {
        iana::AlgorithmHMAC_256_64 => Ok((hmac::HMAC_SHA256, 8)),
        iana::AlgorithmHMAC_256_256 => Ok((hmac::HMAC_SHA256, 32)),
        iana::AlgorithmHMAC_384_384 => Ok((hmac::HMAC_SHA384, 48)),
        iana::AlgorithmHMAC_512_512 => Ok((hmac::HMAC_SHA512, 64)),
        _ => Err(unsupported_alg("HMAC", alg)),
    }
}

fn aead_algorithm(alg: i64) -> Result<&'static aead::Algorithm, Error> {
    match alg {
        iana::AlgorithmA128GCM => Ok(&aead::AES_128_GCM),
        iana::AlgorithmA256GCM => Ok(&aead::AES_256_GCM),
        iana::AlgorithmChaCha20Poly1305 => Ok(&aead::CHACHA20_POLY1305),
        _ => Err(unsupported_alg("AEAD", alg)),
    }
}

fn ecdsa_verification_algorithm(
    alg: i64,
) -> Result<&'static dyn signature::VerificationAlgorithm, Error> {
    match alg {
        iana::AlgorithmES256 => Ok(&signature::ECDSA_P256_SHA256_FIXED),
        iana::AlgorithmES384 => Ok(&signature::ECDSA_P384_SHA384_FIXED),
        _ => Err(unsupported_alg("ECDSA verification", alg)),
    }
}

fn rsa_signing_algorithm(alg: i64) -> Result<&'static dyn signature::RsaEncoding, Error> {
    match alg {
        iana::AlgorithmRS256 => Ok(&signature::RSA_PKCS1_SHA256),
        iana::AlgorithmRS384 => Ok(&signature::RSA_PKCS1_SHA384),
        iana::AlgorithmRS512 => Ok(&signature::RSA_PKCS1_SHA512),
        iana::AlgorithmPS256 => Ok(&signature::RSA_PSS_SHA256),
        iana::AlgorithmPS384 => Ok(&signature::RSA_PSS_SHA384),
        iana::AlgorithmPS512 => Ok(&signature::RSA_PSS_SHA512),
        _ => Err(unsupported_alg("RSA signing", alg)),
    }
}

fn rsa_verification_algorithm(alg: i64) -> Result<&'static RsaParameters, Error> {
    match alg {
        iana::AlgorithmRS256 => Ok(&signature::RSA_PKCS1_2048_8192_SHA256),
        iana::AlgorithmRS384 => Ok(&signature::RSA_PKCS1_2048_8192_SHA384),
        iana::AlgorithmRS512 => Ok(&signature::RSA_PKCS1_2048_8192_SHA512),
        iana::AlgorithmPS256 => Ok(&signature::RSA_PSS_2048_8192_SHA256),
        iana::AlgorithmPS384 => Ok(&signature::RSA_PSS_2048_8192_SHA384),
        iana::AlgorithmPS512 => Ok(&signature::RSA_PSS_2048_8192_SHA512),
        _ => Err(unsupported_alg("RSA verification", alg)),
    }
}

fn required_alg(key: &Key) -> Result<i64, Error> {
    match key.alg()? {
        Some(Label::Int(alg)) => Ok(alg),
        Some(Label::Text(_)) => Err(Error::custom(
            "ring crypto backend does not support private text-string algorithms",
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

fn require_curve(key: &Key, label: i64, expected: i64) -> Result<(), Error> {
    match key.get_label(label)? {
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

fn ec2_uncompressed_public_key(key: &Key) -> Result<Vec<u8>, Error> {
    let x = required_bytes(key, iana::EC2KeyParameterX, "x")?;
    let y = required_bytes(key, iana::EC2KeyParameterY, "y")?;
    let mut out = Vec::with_capacity(1 + x.len() + y.len());
    out.push(0x04);
    out.extend_from_slice(x);
    out.extend_from_slice(y);
    Ok(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn unsupported_alg(operation: &str, alg: i64) -> Error {
    Error::custom(format!(
        "unsupported {operation} algorithm {} for the ring crypto backend",
        Label::from(alg)
    ))
}
