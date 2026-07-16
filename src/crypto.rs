//! Optional built-in cryptographic providers.
//!
//! This module is available with the `crypto-ring` or `crypto-aws-lc-rs`
//! feature. Both back the same providers with an API-compatible backend
//! ([`ring`](https://crates.io/crates/ring) or
//! [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs), respectively); when both
//! features are enabled, `ring` takes precedence. It implements the crate's
//! pluggable traits for the algorithms the backend exposes in COSE
//! wire-compatible form:
//!
//! - signatures: Ed25519, ES256, ES384, RS256/384/512, PS256/384/512
//! - MACs: HMAC 256/64, HMAC 256/256, HMAC 384/384, HMAC 512/512
//! - AEAD content encryption: A128GCM, A256GCM, ChaCha20/Poly1305
//!
//! Algorithms not supported by the backend are rejected during provider
//! construction.

use std::{fmt, sync::Arc};

#[cfg(feature = "crypto-ring")]
use ring as backend;

#[cfg(all(feature = "crypto-aws-lc-rs", not(feature = "crypto-ring")))]
use aws_lc_rs as backend;

use backend::{
    aead, hmac, rand, rsa, signature,
    signature::{KeyPair, RsaParameters},
};

use zeroize::Zeroizing;

use crate::{iana, Encryptor, Error, Key, Label, Macer, Signer, Verifier};

/// A built-in HMAC provider for COSE_Mac and COSE_Mac0.
#[derive(Clone)]
pub struct RingMacer {
    alg: i64,
    kid: Option<Vec<u8>>,
    key: hmac::Key,
    // Retained so the symmetric `k` can be re-exported by `to_cose_key`;
    // `hmac::Key` does not expose its raw bytes. Zeroized on drop (every
    // clone wipes its own copy).
    raw_key: Zeroizing<Vec<u8>>,
    tag_len: usize,
}

// Manual `Debug` keeps the raw key material out of formatted output.
impl fmt::Debug for RingMacer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingMacer")
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .field("tag_len", &self.tag_len)
            .finish_non_exhaustive()
    }
}

impl RingMacer {
    /// Creates a provider from a COSE HMAC algorithm and raw key bytes.
    pub fn new(alg: i64, key: &[u8], kid: Option<Vec<u8>>) -> Result<Self, Error> {
        let (algorithm, tag_len) = hmac_algorithm(alg)?;
        Ok(Self {
            alg,
            kid,
            key: hmac::Key::new(algorithm, key),
            raw_key: Zeroizing::new(key.to_vec()),
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

    /// Exports this provider as a symmetric COSE_Key carrying `alg` and `k`.
    ///
    /// The result round-trips through [`RingMacer::from_cose_key`].
    /// Note the exported [`Key`] holds an unprotected copy of the secret; it
    /// is the caller's responsibility to handle it carefully.
    pub fn to_cose_key(&self) -> Result<Key, Error> {
        Ok(symmetric_cose_key(
            self.alg,
            &self.raw_key,
            self.kid.as_deref(),
            None,
        ))
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

/// A built-in AEAD provider for COSE_Encrypt and COSE_Encrypt0 content.
#[derive(Clone)]
pub struct RingEncryptor {
    alg: i64,
    kid: Option<Vec<u8>>,
    // `Arc` keeps `RingEncryptor: Clone` uniform across backends: `ring`'s
    // `LessSafeKey` is `Clone` but `aws-lc-rs`'s is not.
    key: Arc<aead::LessSafeKey>,
    // Retained so the symmetric `k` can be re-exported by `to_cose_key`;
    // `aead::LessSafeKey` does not expose its raw bytes. Zeroized on drop
    // (every clone wipes its own copy).
    raw_key: Zeroizing<Vec<u8>>,
    base_iv: Option<Vec<u8>>,
}

// Manual `Debug` keeps the raw key material out of formatted output.
impl fmt::Debug for RingEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingEncryptor")
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .field("base_iv", &self.base_iv)
            .finish_non_exhaustive()
    }
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
            key: Arc::new(aead::LessSafeKey::new(unbound)),
            raw_key: Zeroizing::new(key.to_vec()),
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

    /// Exports this provider as a symmetric COSE_Key carrying `alg`, `k` and,
    /// when configured, the Base IV.
    ///
    /// The result round-trips through [`RingEncryptor::from_cose_key`].
    /// Note the exported [`Key`] holds an unprotected copy of the secret; it
    /// is the caller's responsibility to handle it carefully.
    pub fn to_cose_key(&self) -> Result<Key, Error> {
        Ok(symmetric_cose_key(
            self.alg,
            &self.raw_key,
            self.kid.as_deref(),
            self.base_iv.as_deref(),
        ))
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

/// A built-in signing provider for COSE_Sign and COSE_Sign1.
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

    /// Exports the *public* COSE_Key for this signer.
    ///
    /// The backends do not expose the private scalar, so the result carries
    /// only public parameters (`x`, and for EC2 also `y`) and can be consumed
    /// by [`RingVerifier::from_cose_key`]. RSA signers are unsupported because
    /// the backends expose no public modulus for them; use the raw modulus and
    /// exponent with [`RingVerifier::rsa_components`] instead.
    pub fn to_cose_key(&self) -> Result<Key, Error> {
        match &self.key {
            RingSigningKey::Ed25519(key) => Ok(okp_public_cose_key(
                self.alg,
                key.public_key().as_ref(),
                self.kid.as_deref(),
            )),
            RingSigningKey::Ecdsa(key) => {
                ec2_public_cose_key(self.alg, key.public_key().as_ref(), self.kid.as_deref())
            }
            RingSigningKey::Rsa { .. } => Err(Error::custom(
                "cannot export a COSE_Key from an RSA RingSigner: the backend exposes no public key",
            )),
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
        let (curve, signing_algorithm, coordinate_len) = match alg {
            iana::AlgorithmES256 => (
                iana::EllipticCurveP_256,
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                32,
            ),
            iana::AlgorithmES384 => (
                iana::EllipticCurveP_384,
                &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                48,
            ),
            _ => return Err(unsupported_alg("ECDSA signing", alg)),
        };
        require_curve(key, iana::EC2KeyParameterCrv, curve)?;
        let kid = key_kid(key)?;
        let public_key = ec2_uncompressed_public_key(key, coordinate_len)?;
        let d = required_bytes(key, iana::EC2KeyParameterD, "d")?;
        // `ring` requires an RNG argument here; `aws-lc-rs` does not.
        #[cfg(feature = "crypto-ring")]
        let signing_key = signature::EcdsaKeyPair::from_private_key_and_public_key(
            signing_algorithm,
            d,
            &public_key,
            &rand::SystemRandom::new(),
        )
        .map_err(|_| Error::custom("invalid ECDSA key material"))?;
        #[cfg(all(feature = "crypto-aws-lc-rs", not(feature = "crypto-ring")))]
        let signing_key = signature::EcdsaKeyPair::from_private_key_and_public_key(
            signing_algorithm,
            d,
            &public_key,
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
        // `ring` requires an RNG argument here; `aws-lc-rs` does not.
        #[cfg(feature = "crypto-ring")]
        let key = signature::EcdsaKeyPair::from_pkcs8(
            signing_algorithm,
            pkcs8,
            &rand::SystemRandom::new(),
        )
        .map_err(|_| Error::custom("invalid ECDSA PKCS#8 key"))?;
        #[cfg(all(feature = "crypto-aws-lc-rs", not(feature = "crypto-ring")))]
        let key = signature::EcdsaKeyPair::from_pkcs8(signing_algorithm, pkcs8)
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
        // A COSE_Key carries the full RSA CRT parameter set, but the backends
        // disagree on how to ingest it: `ring` offers `from_components` while
        // `aws-lc-rs` only parses DER. Serialize the components into a PKCS#1
        // `RSAPrivateKey` DER, which `RsaKeyPair::from_der` accepts on both.
        let der = rsa_pkcs1_private_key_der(key)?;
        let key_pair =
            rsa::KeyPair::from_der(&der).map_err(|_| Error::custom("invalid RSA key material"))?;
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
                // `ring` deprecates `public_modulus_len()` in favour of
                // `public().modulus_len()`; `aws-lc-rs` exposes only the former.
                #[cfg(feature = "crypto-ring")]
                let sig_len = key_pair.public().modulus_len();
                #[cfg(all(feature = "crypto-aws-lc-rs", not(feature = "crypto-ring")))]
                let sig_len = key_pair.public_modulus_len();
                let mut signature = vec![0; sig_len];
                key_pair
                    .sign(*padding, &rng, data, &mut signature)
                    .map_err(|_| Error::custom("RSA signing failed"))?;
                Ok(signature)
            }
        }
    }
}

/// A built-in verifier for COSE_Sign and COSE_Sign1.
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
                let (expected_curve, coordinate_len) = if alg == iana::AlgorithmES256 {
                    (iana::EllipticCurveP_256, 32)
                } else {
                    (iana::EllipticCurveP_384, 48)
                };
                require_curve(key, iana::EC2KeyParameterCrv, expected_curve)?;
                Self::ecdsa(
                    alg,
                    &ec2_uncompressed_public_key(key, coordinate_len)?,
                    key_kid(key)?,
                )
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

    /// Exports this verifier as a public COSE_Key.
    ///
    /// The result round-trips through [`RingVerifier::from_cose_key`]. RSA
    /// verifiers built from a DER public key have their PKCS#1 `RSAPublicKey`
    /// parsed back into the COSE `n` and `e` parameters.
    pub fn to_cose_key(&self) -> Result<Key, Error> {
        match &self.key {
            RingVerificationKey::Ed25519(public_key) => Ok(okp_public_cose_key(
                self.alg,
                public_key,
                self.kid.as_deref(),
            )),
            RingVerificationKey::Ecdsa(public_key) => {
                ec2_public_cose_key(self.alg, public_key, self.kid.as_deref())
            }
            RingVerificationKey::RsaComponents { n, e } => {
                Ok(rsa_public_cose_key(self.alg, n, e, self.kid.as_deref()))
            }
            RingVerificationKey::RsaDer(der) => {
                let (n, e) = rsa_public_key_from_der(der)?;
                Ok(rsa_public_cose_key(self.alg, &n, &e, self.kid.as_deref()))
            }
        }
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
            "the built-in crypto backend does not support private text-string algorithms",
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

/// Concatenates an EC2 key's `x`/`y` into an uncompressed SEC 1 point.
///
/// Each coordinate must be exactly `coordinate_len` bytes for the curve, so
/// a boundary-shifted `x`/`y` pair cannot pass as an aggregate-length match.
fn ec2_uncompressed_public_key(key: &Key, coordinate_len: usize) -> Result<Vec<u8>, Error> {
    let x = required_bytes(key, iana::EC2KeyParameterX, "x")?;
    let y = required_bytes(key, iana::EC2KeyParameterY, "y")?;
    if x.len() != coordinate_len || y.len() != coordinate_len {
        return Err(Error::custom(format!(
            "EC2 coordinates must be {coordinate_len} bytes, got x = {} and y = {}",
            x.len(),
            y.len()
        )));
    }
    let mut out = Vec::with_capacity(1 + x.len() + y.len());
    out.push(0x04);
    out.extend_from_slice(x);
    out.extend_from_slice(y);
    Ok(out)
}

/// Builds a symmetric COSE_Key (`kty` = Symmetric) carrying `alg`, `k`, an
/// optional `kid` and an optional Base IV.
fn symmetric_cose_key(alg: i64, k: &[u8], kid: Option<&[u8]>, base_iv: Option<&[u8]>) -> Key {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeSymmetric).set_alg(alg);
    if let Some(kid) = kid {
        key.set_kid(kid.to_vec());
    }
    key.insert(iana::SymmetricKeyParameterK, k.to_vec());
    if let Some(base_iv) = base_iv {
        key.insert(iana::KeyParameterBaseIV, base_iv.to_vec());
    }
    key
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

/// Builds an EC2 public COSE_Key from an uncompressed SEC1 point
/// (`0x04 || x || y`), selecting the curve and fixed coordinate length from the
/// ECDSA `alg`.
fn ec2_public_cose_key(alg: i64, point: &[u8], kid: Option<&[u8]>) -> Result<Key, Error> {
    let (curve, coord_len) = match alg {
        iana::AlgorithmES256 => (iana::EllipticCurveP_256, 32),
        iana::AlgorithmES384 => (iana::EllipticCurveP_384, 48),
        _ => return Err(unsupported_alg("ECDSA", alg)),
    };
    // RFC 9053 EC2 keys use fixed-length field-element coordinates, so a valid
    // uncompressed point is exactly `0x04` followed by two `coord_len` halves.
    if point.first() != Some(&0x04) || point.len() != 1 + 2 * coord_len {
        return Err(Error::custom("invalid uncompressed EC public key"));
    }
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeEC2).set_alg(alg);
    if let Some(kid) = kid {
        key.set_kid(kid.to_vec());
    }
    key.insert(iana::EC2KeyParameterCrv, curve);
    key.insert(iana::EC2KeyParameterX, point[1..1 + coord_len].to_vec());
    key.insert(iana::EC2KeyParameterY, point[1 + coord_len..].to_vec());
    Ok(key)
}

/// Builds an RSA public COSE_Key carrying `alg`, `n`, `e` and an optional `kid`.
fn rsa_public_cose_key(alg: i64, n: &[u8], e: &[u8], kid: Option<&[u8]>) -> Key {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeRSA).set_alg(alg);
    if let Some(kid) = kid {
        key.set_kid(kid.to_vec());
    }
    key.insert(iana::RSAKeyParameterN, n.to_vec());
    key.insert(iana::RSAKeyParameterE, e.to_vec());
    key
}

/// Serializes an RSA COSE_Key's CRT components into a PKCS#1 `RSAPrivateKey`
/// DER document (RFC 8017 §A.1.2). Both crypto backends ingest this through
/// `RsaKeyPair::from_der`.
fn rsa_pkcs1_private_key_der(key: &Key) -> Result<Vec<u8>, Error> {
    // Field order is fixed by the ASN.1 `RSAPrivateKey` SEQUENCE.
    let fields = [
        required_bytes(key, iana::RSAKeyParameterN, "n")?,
        required_bytes(key, iana::RSAKeyParameterE, "e")?,
        required_bytes(key, iana::RSAKeyParameterD, "d")?,
        required_bytes(key, iana::RSAKeyParameterP, "p")?,
        required_bytes(key, iana::RSAKeyParameterQ, "q")?,
        required_bytes(key, iana::RSAKeyParameterDP, "dP")?,
        required_bytes(key, iana::RSAKeyParameterDQ, "dQ")?,
        required_bytes(key, iana::RSAKeyParameterQInv, "qInv")?,
    ];

    let mut body = Vec::new();
    der_unsigned_integer(&[0], &mut body); // version: 0 (two-prime)
    for field in fields {
        der_unsigned_integer(field, &mut body);
    }

    let mut der = Vec::with_capacity(body.len() + 4);
    der.push(0x30); // SEQUENCE
    der_length(body.len(), &mut der);
    der.extend_from_slice(&body);
    Ok(der)
}

/// Appends a DER `INTEGER` TLV holding the unsigned big-endian magnitude `value`.
fn der_unsigned_integer(value: &[u8], out: &mut Vec<u8>) {
    // DER integers are minimally encoded: drop leading zero bytes, keeping one.
    let mut magnitude = value;
    while magnitude.len() > 1 && magnitude[0] == 0 {
        magnitude = &magnitude[1..];
    }
    out.push(0x02); // INTEGER
                    // Prepend 0x00 when the high bit is set so the value stays positive.
    if magnitude.first().is_some_and(|&b| b & 0x80 != 0) {
        der_length(magnitude.len() + 1, out);
        out.push(0x00);
    } else {
        der_length(magnitude.len(), out);
    }
    out.extend_from_slice(magnitude);
}

/// Appends DER definite-form length octets for `len`.
fn der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let be = len.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let bytes = &be[first..];
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(bytes);
}

/// Parses a PKCS#1 `RSAPublicKey` DER (RFC 8017 §A.1.1),
/// `SEQUENCE { modulus INTEGER, publicExponent INTEGER }`, returning the
/// unsigned big-endian magnitudes of `n` and `e`.
fn rsa_public_key_from_der(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let invalid = || Error::custom("invalid RSA public key DER");
    let (seq, trailing) = der_take_tlv(der, 0x30).ok_or_else(invalid)?;
    if !trailing.is_empty() {
        return Err(invalid());
    }
    let (n, rest) = der_take_tlv(seq, 0x02).ok_or_else(invalid)?;
    let (e, rest) = der_take_tlv(rest, 0x02).ok_or_else(invalid)?;
    if !rest.is_empty() {
        return Err(invalid());
    }
    Ok((
        der_integer_magnitude(n).to_vec(),
        der_integer_magnitude(e).to_vec(),
    ))
}

/// Reads one DER TLV whose tag must equal `tag`, returning `(contents, rest)`
/// where `rest` is the bytes following the value. Returns `None` on any
/// malformation.
fn der_take_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&first, rest) = input.split_first()?;
    if first != tag {
        return None;
    }
    let (len, rest) = der_read_length(rest)?;
    if rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}

/// Reads DER definite-form length octets, returning `(length, rest)`. Rejects
/// the indefinite form and lengths that would overflow `usize`.
fn der_read_length(input: &[u8]) -> Option<(usize, &[u8])> {
    let (&first, rest) = input.split_first()?;
    if first < 0x80 {
        return Some((first as usize, rest));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > std::mem::size_of::<usize>() || rest.len() < count {
        return None;
    }
    let (bytes, rest) = rest.split_at(count);
    let mut len = 0usize;
    for &b in bytes {
        len = (len << 8) | b as usize;
    }
    Some((len, rest))
}

/// Strips a DER sign byte (a single leading `0x00`) to yield the unsigned
/// big-endian magnitude used by COSE RSA parameters.
fn der_integer_magnitude(bytes: &[u8]) -> &[u8] {
    match bytes.split_first() {
        Some((&0x00, rest)) if !rest.is_empty() => rest,
        _ => bytes,
    }
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
        "unsupported {operation} algorithm {} for the built-in crypto backend",
        Label::from(alg)
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        der_length, der_unsigned_integer, ec2_public_cose_key, rsa_pkcs1_private_key_der,
        rsa_public_key_from_der,
    };
    use crate::{iana, Key};

    #[test]
    fn der_length_uses_minimal_definite_form() {
        let cases: &[(usize, &[u8])] = &[
            (0, &[0x00]),
            (5, &[0x05]),
            (127, &[0x7f]),
            (128, &[0x81, 0x80]),
            (200, &[0x81, 0xc8]),
            (257, &[0x82, 0x01, 0x01]),
        ];
        for (len, expected) in cases {
            let mut out = Vec::new();
            der_length(*len, &mut out);
            assert_eq!(out, *expected, "length {len}");
        }
    }

    #[test]
    fn der_unsigned_integer_is_minimal_and_positive() {
        let cases: &[(&[u8], &[u8])] = &[
            // version 0
            (&[0x00], &[0x02, 0x01, 0x00]),
            // no high bit: encoded verbatim
            (&[0x7f], &[0x02, 0x01, 0x7f]),
            // high bit set: 0x00 prepended to stay positive
            (&[0x80], &[0x02, 0x02, 0x00, 0x80]),
            // redundant leading zeros are stripped to the minimal magnitude
            (&[0x00, 0x00, 0x01], &[0x02, 0x01, 0x01]),
            // stripped down to a single high-bit byte, which is then padded
            (&[0x00, 0xb6], &[0x02, 0x02, 0x00, 0xb6]),
        ];
        for (value, expected) in cases {
            let mut out = Vec::new();
            der_unsigned_integer(value, &mut out);
            assert_eq!(out, *expected, "value {value:02x?}");
        }
    }

    #[test]
    fn rsa_pkcs1_der_wraps_components_in_a_sequence() {
        let mut key = Key::new();
        key.set_kty(iana::KeyTypeRSA);
        for label in [
            iana::RSAKeyParameterN,
            iana::RSAKeyParameterE,
            iana::RSAKeyParameterD,
            iana::RSAKeyParameterP,
            iana::RSAKeyParameterQ,
            iana::RSAKeyParameterDP,
            iana::RSAKeyParameterDQ,
            iana::RSAKeyParameterQInv,
        ] {
            key.insert(label, vec![0x01u8]);
        }

        let der = rsa_pkcs1_private_key_der(&key).unwrap();
        // SEQUENCE { version 0, then the eight single-byte INTEGERs }.
        let mut expected = vec![0x30, 0x1b, 0x02, 0x01, 0x00];
        for _ in 0..8 {
            expected.extend_from_slice(&[0x02, 0x01, 0x01]);
        }
        assert_eq!(der, expected);

        // A missing component is a clear error rather than a malformed DER.
        let mut incomplete = Key::new();
        incomplete.set_kty(iana::KeyTypeRSA);
        incomplete.insert(iana::RSAKeyParameterN, vec![0x01u8]);
        assert!(rsa_pkcs1_private_key_der(&incomplete).is_err());
    }

    #[test]
    fn rsa_public_key_from_der_extracts_minimal_magnitudes() {
        // SEQUENCE { INTEGER 0x00B6 (sign-padded), INTEGER 0x010001 }.
        let der = &[
            0x30, 0x09, // SEQUENCE, length 9
            0x02, 0x02, 0x00, 0xb6, // INTEGER n = 0xB6 with DER sign byte
            0x02, 0x03, 0x01, 0x00, 0x01, // INTEGER e = 65537
        ];
        let (n, e) = rsa_public_key_from_der(der).unwrap();
        // The sign byte is stripped back to the unsigned magnitude.
        assert_eq!(n, vec![0xb6]);
        assert_eq!(e, vec![0x01, 0x00, 0x01]);

        // Trailing garbage, a wrong outer tag and a truncated value are rejected.
        let mut trailing = der.to_vec();
        trailing.push(0x00);
        assert!(rsa_public_key_from_der(&trailing).is_err());
        assert!(rsa_public_key_from_der(&[0x31, 0x00]).is_err());
        assert!(rsa_public_key_from_der(&[0x30, 0x05, 0x02, 0x02, 0x00]).is_err());
    }

    #[test]
    fn ec2_public_cose_key_splits_fixed_length_coordinates() {
        // 0x04 || x(32) || y(32) for a P-256 point.
        let mut point = vec![0x04];
        point.extend_from_slice(&[0xaa; 32]);
        point.extend_from_slice(&[0xbb; 32]);
        let key = ec2_public_cose_key(iana::AlgorithmES256, &point, Some(b"p256")).unwrap();

        assert_eq!(key.kty().unwrap(), Some(iana::KeyTypeEC2.into()));
        assert_eq!(key.alg().unwrap(), Some(iana::AlgorithmES256.into()));
        assert_eq!(key.kid().unwrap(), Some(&b"p256"[..]));
        assert_eq!(
            key.get_label(iana::EC2KeyParameterCrv).unwrap(),
            Some(iana::EllipticCurveP_256.into())
        );
        assert_eq!(
            key.get_bytes(iana::EC2KeyParameterX).unwrap(),
            Some(&[0xaa; 32][..])
        );
        assert_eq!(
            key.get_bytes(iana::EC2KeyParameterY).unwrap(),
            Some(&[0xbb; 32][..])
        );

        // A point whose length does not match the curve is rejected, as is a
        // point without the uncompressed `0x04` prefix or an unknown algorithm.
        assert!(ec2_public_cose_key(iana::AlgorithmES256, &point[..64], None).is_err());
        let mut compressed = point.clone();
        compressed[0] = 0x02;
        assert!(ec2_public_cose_key(iana::AlgorithmES256, &compressed, None).is_err());
        assert!(ec2_public_cose_key(iana::AlgorithmEdDSA, &point, None).is_err());
    }
}
