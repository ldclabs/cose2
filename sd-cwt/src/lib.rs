//! Selective Disclosure CBOR Web Token helpers.
//!
//! This crate implements the SD-CWT disclosure and redaction mechanics from
//! `draft-ietf-spice-sd-cwt-08` on top of [`cose2`]. It deliberately reuses
//! `cose2` for COSE signing, verification and header storage; the APIs here
//! cover SD-CWT-specific header parameters, salted disclosures, redacted claim
//! markers, AEAD-encrypted disclosure wire structures, and restoration of a
//! presented claims set. [`SdCwtValidator`] and
//! [`verify_validate_and_restore_sd_cwt`] enforce draft-08 structure and
//! configurable resource limits.
//!
//! # Security
//!
//! This crate implements only the disclosure/redaction mechanics. Two
//! independent checks remain the application's responsibility:
//!
//! 1. **Issuer signature.** The restore helpers never verify COSE signatures.
//!    A Verifier must decode and verify the signature of the wire bytes it
//!    received (e.g. with [`cose2::Sign1Message::verify_and_decode`]) before
//!    calling any restore helper, and must not reuse a struct it did not
//!    verify itself.
//! 2. **Holder binding.** `sd_claims` lives in the *unprotected* header, so
//!    the issuer's signature does not cover which disclosures are presented.
//!    A presentation is bound to the holder and transaction with a Key
//!    Binding Token (`kcwt`, header parameter 13, [`HEADER_KCWT`]): a CWT
//!    signed with the holder's `cnf` key over the verifier's audience,
//!    `cnonce` and issuance time. This crate does not yet implement KBT
//!    issuance or verification; until the application performs that check, a
//!    captured presentation can be replayed by anyone.

use std::collections::{HashMap, HashSet};

use cbor2::{Simple, Value};
use cose2::{Error, Header, Label};
use sha2::{Digest, Sha256};

/// COSE header parameter `sd_claims`.
pub const HEADER_SD_CLAIMS: i64 = 17;
/// COSE header parameter `sd_alg`.
pub const HEADER_SD_ALG: i64 = 170;
/// COSE header parameter `sd_aead_encrypted_claims`.
pub const HEADER_SD_AEAD_ENCRYPTED_CLAIMS: i64 = 171;
/// COSE header parameter `sd_aead`.
pub const HEADER_SD_AEAD: i64 = 172;
/// COSE header parameter `kcwt` used by Key Binding Tokens.
pub const HEADER_KCWT: i64 = 13;
/// COSE header parameter `CWT_Claims`.
pub const HEADER_CWT_CLAIMS: i64 = 15;
/// COSE header parameter `typ`.
pub const HEADER_TYP: i64 = 16;

/// CoAP content-format number for `application/sd-cwt`.
pub const CONTENT_FORMAT_SD_CWT: i64 = 293;
/// CoAP content-format number for `application/kb+cwt`.
pub const CONTENT_FORMAT_KB_CWT: i64 = 294;

/// SD-CWT `vct` CWT claim key.
pub const CWT_CLAIM_VCT: i64 = 11;
/// SD-CWT `cnonce` CWT claim key.
pub const CWT_CLAIM_CNONCE: i64 = 39;

/// The CBOR simple value used as the `redacted_claim_keys` map key.
pub const REDACTED_CLAIM_KEYS_SIMPLE: u8 = 59;
/// The CBOR tag used for redacted array elements.
pub const REDACTED_ELEMENT_TAG: u64 = 60;
/// The CBOR tag used in pre-issuance maps to mark a key or element for redaction.
pub const TO_BE_REDACTED_TAG: u64 = 58;
/// The CBOR tag used in pre-issuance maps to request decoys.
pub const TO_BE_DECOY_TAG: u64 = 62;

/// The COSE algorithm identifier for SHA-256.
pub const ALG_SHA_256: i64 = cose2::iana::AlgorithmSHA_256;

/// Returns the SD-CWT `redacted_claim_keys` map label, `simple(59)`.
pub fn redacted_claim_keys_label() -> Value {
    Value::Simple(Simple::new(REDACTED_CLAIM_KEYS_SIMPLE).expect("59 is a valid CBOR simple value"))
}

/// Returns true when `value` is the SD-CWT `redacted_claim_keys` map label.
pub fn is_redacted_claim_keys_label(value: &Value) -> bool {
    matches!(
        value,
        Value::Simple(simple) if simple.value() == REDACTED_CLAIM_KEYS_SIMPLE
    )
}

/// Wraps a redacted array-element hash as CBOR tag 60.
pub fn redacted_element(hash: impl Into<Vec<u8>>) -> Value {
    Value::Tag(REDACTED_ELEMENT_TAG, Box::new(Value::Bytes(hash.into())))
}

/// Source of 128-bit salts for issuance helpers.
///
/// The crate does not generate randomness. Issuers pass an implementation that
/// returns one fresh, unpredictable 16-byte salt for each redacted claim,
/// redacted array element, or decoy.
pub trait SaltGenerator {
    /// Returns the next 16-byte salt.
    fn next_salt(&mut self) -> Result<[u8; 16], Error>;
}

impl<F> SaltGenerator for F
where
    F: FnMut() -> [u8; 16],
{
    fn next_salt(&mut self) -> Result<[u8; 16], Error> {
        Ok(self())
    }
}

/// Redaction hash algorithm used for Salted Disclosed Claims.
pub trait RedactionHasher {
    /// Returns the COSE algorithm identifier advertised in `sd_alg`.
    fn algorithm(&self) -> i64;

    /// Computes the digest of one bstr-encoded Salted Disclosed Claim.
    fn digest(&self, data: &[u8]) -> Vec<u8>;
}

/// SHA-256 redaction hasher, the SD-CWT default when `sd_alg` is omitted.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256RedactionHasher;

impl RedactionHasher for Sha256RedactionHasher {
    fn algorithm(&self) -> i64 {
        ALG_SHA_256
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }
}

/// Returns the built-in SHA-256 hasher for `sd_alg = -16` or an omitted `sd_alg`.
pub fn default_hasher_for_sd_alg(alg: Option<i64>) -> Result<Sha256RedactionHasher, Error> {
    match alg {
        None | Some(ALG_SHA_256) => Ok(Sha256RedactionHasher),
        Some(other) => Err(Error::custom(format!(
            "unsupported SD-CWT hash algorithm {other}"
        ))),
    }
}

/// Reads the `sd_alg` protected header parameter.
pub fn sd_alg(protected: &Header) -> Result<Option<i64>, Error> {
    protected.get_i64(HEADER_SD_ALG)
}

/// Sets the `sd_alg` protected header parameter.
pub fn set_sd_alg(protected: &mut Header, alg: i64) -> &mut Header {
    protected.insert(HEADER_SD_ALG, alg);
    protected
}

/// Sets the SD-CWT content type (`typ`) header to `application/sd-cwt` (293).
pub fn set_sd_cwt_typ(protected: &mut Header) -> &mut Header {
    protected.insert(HEADER_TYP, CONTENT_FORMAT_SD_CWT);
    protected
}

/// Sets the Key Binding Token content type (`typ`) header to `application/kb+cwt` (294).
pub fn set_kb_cwt_typ(protected: &mut Header) -> &mut Header {
    protected.insert(HEADER_TYP, CONTENT_FORMAT_KB_CWT);
    protected
}

/// Reads the `sd_aead` protected header parameter.
pub fn sd_aead(protected: &Header) -> Result<Option<u16>, Error> {
    match protected.get_i64(HEADER_SD_AEAD)? {
        None => Ok(None),
        Some(value) => u16::try_from(value)
            .map(Some)
            .map_err(|_| Error::UnexpectedType("sd_aead must be a uint .size 2".into())),
    }
}

/// Sets the `sd_aead` protected header parameter.
pub fn set_sd_aead(protected: &mut Header, alg: u16) -> &mut Header {
    protected.insert(HEADER_SD_AEAD, i64::from(alg));
    protected
}

/// A decoded Salted Disclosed Claim entry.
#[derive(Clone, Debug, PartialEq)]
pub enum DisclosureKind {
    /// A redacted map claim: `[salt, claim value, claim key]`.
    Claim {
        /// The 16-byte salt.
        salt: Vec<u8>,
        /// The disclosed claim key.
        key: Label,
        /// The disclosed claim value.
        value: Value,
    },
    /// A redacted array element: `[salt, claim value]`.
    Element {
        /// The 16-byte salt.
        salt: Vec<u8>,
        /// The disclosed element value.
        value: Value,
    },
    /// A decoy entry: `[salt]`.
    Decoy {
        /// The 16-byte salt.
        salt: Vec<u8>,
    },
}

/// One Salted Disclosed Claim plus the exact bstr-encoded bytes used for hashing.
#[derive(Clone, Debug, PartialEq)]
pub struct Disclosure {
    kind: DisclosureKind,
    encoded: Vec<u8>,
}

impl Disclosure {
    /// Builds a redacted map-claim disclosure.
    pub fn claim(
        salt: impl Into<Vec<u8>>,
        key: impl Into<Label>,
        value: impl Into<Value>,
    ) -> Result<Self, Error> {
        Self::from_kind(DisclosureKind::Claim {
            salt: salt.into(),
            key: key.into(),
            value: value.into(),
        })
    }

    /// Builds a redacted array-element disclosure.
    pub fn element(salt: impl Into<Vec<u8>>, value: impl Into<Value>) -> Result<Self, Error> {
        Self::from_kind(DisclosureKind::Element {
            salt: salt.into(),
            value: value.into(),
        })
    }

    /// Builds a decoy disclosure.
    pub fn decoy(salt: impl Into<Vec<u8>>) -> Result<Self, Error> {
        Self::from_kind(DisclosureKind::Decoy { salt: salt.into() })
    }

    /// Decodes and validates one bstr-encoded Salted Disclosed Claim.
    pub fn from_encoded(encoded: impl Into<Vec<u8>>) -> Result<Self, Error> {
        Self::from_encoded_with_limits(encoded, ProcessingLimits::default())
    }

    /// Decodes one disclosure with explicit resource limits.
    pub fn from_encoded_with_limits(
        encoded: impl Into<Vec<u8>>,
        limits: ProcessingLimits,
    ) -> Result<Self, Error> {
        let encoded = encoded.into();
        if encoded.len() > limits.max_disclosure_bytes {
            return Err(Error::limit(
                "SD-CWT disclosure bytes",
                limits.max_disclosure_bytes,
            ));
        }
        cose2::validate_cbor(
            &encoded,
            cose2::CborLimits {
                max_depth: limits.max_depth,
                max_items: limits.max_items,
                require_definite: true,
            },
        )?;
        let value: Value = cbor2::from_slice(&encoded)?;
        let kind = decode_disclosure_value(value)?;
        validate_disclosure_kind(&kind)?;
        validate_disclosure_value(&kind, limits)?;
        Ok(Self { kind, encoded })
    }

    /// Returns the decoded disclosure kind.
    pub fn kind(&self) -> &DisclosureKind {
        &self.kind
    }

    /// Returns the exact bstr-encoded Salted Disclosed Claim bytes.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Computes this disclosure's Redacted Claim Hash.
    pub fn redacted_hash(&self, hasher: &dyn RedactionHasher) -> Vec<u8> {
        hasher.digest(&self.encoded)
    }

    /// Encodes the decoded disclosure value canonically.
    pub fn to_canonical_vec(&self) -> Result<Vec<u8>, Error> {
        Ok(cbor2::to_canonical_vec(&self.to_value())?)
    }

    /// Converts this disclosure to its decoded CBOR value.
    pub fn to_value(&self) -> Value {
        kind_to_value(&self.kind)
    }

    fn from_kind(kind: DisclosureKind) -> Result<Self, Error> {
        validate_disclosure_kind(&kind)?;
        validate_disclosure_value(&kind, ProcessingLimits::default())?;
        let encoded = cbor2::to_canonical_vec(&kind_to_value(&kind))?;
        Ok(Self { kind, encoded })
    }

    fn item_count(&self) -> Result<usize, Error> {
        let fixed = match &self.kind {
            DisclosureKind::Decoy { .. } => 2,
            DisclosureKind::Element { .. } => 2,
            DisclosureKind::Claim { .. } => 3,
        };
        let value = match &self.kind {
            DisclosureKind::Claim { value, .. } | DisclosureKind::Element { value, .. } => {
                Some(value)
            }
            DisclosureKind::Decoy { .. } => None,
        };
        value.map_or(Ok(fixed), |value| {
            fixed
                .checked_add(value_item_count(value)?)
                .ok_or_else(|| Error::custom("SD-CWT item count overflow"))
        })
    }
}

/// A collection of Salted Disclosed Claims.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DisclosureSet {
    disclosures: Vec<Disclosure>,
}

impl DisclosureSet {
    /// Creates an empty disclosure set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a disclosure set from an iterator.
    pub fn from_disclosures<I>(disclosures: I) -> Self
    where
        I: IntoIterator<Item = Disclosure>,
    {
        Self {
            disclosures: disclosures.into_iter().collect(),
        }
    }

    /// Decodes the `sd_claims` unprotected header parameter.
    pub fn from_unprotected(header: &Header) -> Result<Self, Error> {
        disclosures_from_unprotected(header).map(Self::from_disclosures)
    }

    /// Returns the disclosures.
    pub fn as_slice(&self) -> &[Disclosure] {
        &self.disclosures
    }

    /// Appends a disclosure.
    pub fn push(&mut self, disclosure: Disclosure) {
        self.disclosures.push(disclosure);
    }

    /// Returns true when there are no disclosures.
    pub fn is_empty(&self) -> bool {
        self.disclosures.is_empty()
    }

    /// Returns the number of disclosures.
    pub fn len(&self) -> usize {
        self.disclosures.len()
    }

    /// Writes this set to the `sd_claims` unprotected header parameter.
    ///
    /// Per the draft, an empty disclosure set omits `sd_claims`.
    pub fn write_unprotected(&self, header: &mut Header) {
        set_disclosures(header, &self.disclosures);
    }
}

impl IntoIterator for DisclosureSet {
    type Item = Disclosure;
    type IntoIter = std::vec::IntoIter<Disclosure>;

    fn into_iter(self) -> Self::IntoIter {
        self.disclosures.into_iter()
    }
}

impl<'a> IntoIterator for &'a DisclosureSet {
    type Item = &'a Disclosure;
    type IntoIter = std::slice::Iter<'a, Disclosure>;

    fn into_iter(self) -> Self::IntoIter {
        self.disclosures.iter()
    }
}

/// Reads `sd_claims` from an unprotected header.
pub fn disclosures_from_unprotected(header: &Header) -> Result<Vec<Disclosure>, Error> {
    disclosures_from_unprotected_with_limits(header, ProcessingLimits::default())
}

/// Reads `sd_claims` while enforcing explicit resource limits.
pub fn disclosures_from_unprotected_with_limits(
    header: &Header,
    limits: ProcessingLimits,
) -> Result<Vec<Disclosure>, Error> {
    let Some(value) = header.get(HEADER_SD_CLAIMS) else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = value else {
        return Err(Error::UnexpectedType("sd_claims must be an array".into()));
    };
    if items.is_empty() {
        return Err(Error::custom(
            "sd_claims must be omitted instead of containing an empty array",
        ));
    }
    if items.len() > limits.max_disclosures {
        return Err(Error::limit("SD-CWT disclosure", limits.max_disclosures));
    }
    let envelope_items = items
        .len()
        .checked_add(1)
        .ok_or_else(|| Error::custom("SD-CWT item count overflow"))?;
    if envelope_items > limits.max_items {
        return Err(Error::limit("SD-CWT disclosure values", limits.max_items));
    }

    let mut disclosures = Vec::with_capacity(items.len());
    let mut salts = HashSet::with_capacity(items.len());
    let mut total_bytes = 0usize;
    let mut remaining_items = limits.max_items - envelope_items;
    for item in items {
        let Value::Bytes(encoded) = item else {
            return Err(Error::UnexpectedType(
                "sd_claims entries must be byte strings".into(),
            ));
        };
        total_bytes = total_bytes
            .checked_add(encoded.len())
            .ok_or_else(|| Error::custom("SD-CWT disclosure size overflow"))?;
        if total_bytes > limits.max_disclosure_bytes {
            return Err(Error::limit(
                "SD-CWT disclosure bytes",
                limits.max_disclosure_bytes,
            ));
        }
        let mut disclosure_limits = limits;
        disclosure_limits.max_items = remaining_items;
        let disclosure = Disclosure::from_encoded_with_limits(encoded.clone(), disclosure_limits)?;
        let salt = match disclosure.kind() {
            DisclosureKind::Claim { salt, .. }
            | DisclosureKind::Element { salt, .. }
            | DisclosureKind::Decoy { salt } => salt,
        };
        if !salts.insert(salt.clone()) {
            return Err(Error::verify("duplicate SD-CWT disclosure salt"));
        }
        remaining_items = remaining_items
            .checked_sub(disclosure.item_count()?)
            .ok_or_else(|| Error::limit("SD-CWT disclosure values", limits.max_items))?;
        disclosures.push(disclosure);
    }
    Ok(disclosures)
}

/// Writes `sd_claims` to an unprotected header, omitting the parameter when empty.
pub fn set_disclosures(header: &mut Header, disclosures: &[Disclosure]) {
    if disclosures.is_empty() {
        header.remove(HEADER_SD_CLAIMS);
        return;
    }

    let values = disclosures
        .iter()
        .map(|disclosure| Value::Bytes(disclosure.encoded().to_vec()))
        .collect::<Vec<_>>();
    header.insert(HEADER_SD_CLAIMS, Value::Array(values));
}

/// AEAD encrypted disclosure key context.
#[derive(Clone, Debug, PartialEq)]
pub enum AeadKeyContext {
    /// Unsigned integer key context.
    Uint(u64),
    /// Text key context.
    Text(String),
    /// COSE key thumbprint key context.
    Thumbprint(Vec<u8>),
}

/// One `sd_aead_encrypted_claims` entry.
#[derive(Clone, Debug, PartialEq)]
pub struct AeadEncryptedDisclosure {
    /// Nonce of N_MIN octets for the selected AEAD.
    pub nonce: Vec<u8>,
    /// Ciphertext output for one bstr-encoded Salted Disclosed Claim.
    pub ciphertext: Vec<u8>,
    /// AEAD authentication tag.
    pub tag: Vec<u8>,
    /// Optional context used by profiles to select the correct AEAD key.
    pub key_context: Option<AeadKeyContext>,
}

impl AeadEncryptedDisclosure {
    /// Converts this encrypted disclosure to its CBOR array value.
    pub fn to_value(&self) -> Value {
        let mut values = vec![
            Value::Bytes(self.nonce.clone()),
            Value::Bytes(self.ciphertext.clone()),
            Value::Bytes(self.tag.clone()),
        ];
        if let Some(context) = &self.key_context {
            values.push(match context {
                AeadKeyContext::Uint(value) => Value::from(*value),
                AeadKeyContext::Text(value) => Value::Text(value.clone()),
                AeadKeyContext::Thumbprint(value) => Value::Bytes(value.clone()),
            });
        }
        Value::Array(values)
    }

    /// Decodes one encrypted disclosure from its CBOR array value.
    pub fn from_value(value: &Value) -> Result<Self, Error> {
        let Value::Array(items) = value else {
            return Err(Error::UnexpectedType(
                "AEAD encrypted disclosure must be an array".into(),
            ));
        };
        if !(3..=4).contains(&items.len()) {
            return Err(Error::custom(
                "AEAD encrypted disclosure must have 3 or 4 elements",
            ));
        }

        let nonce = expect_bytes(&items[0], "AEAD nonce")?.to_vec();
        let ciphertext = expect_bytes(&items[1], "AEAD ciphertext")?.to_vec();
        let tag = expect_bytes(&items[2], "AEAD tag")?.to_vec();
        if nonce.is_empty() {
            return Err(Error::custom("AEAD disclosure nonce must not be empty"));
        }
        if ciphertext.is_empty() {
            return Err(Error::custom(
                "AEAD disclosure ciphertext must not be empty",
            ));
        }
        if tag.len() < 16 {
            return Err(Error::custom(
                "AEAD disclosure authentication tag must be at least 16 bytes",
            ));
        }
        let key_context = if items.len() == 4 {
            Some(match &items[3] {
                Value::Integer(value) => {
                    let value = u64::try_from(*value).map_err(|_| {
                        Error::UnexpectedType("AEAD key context uint out of range".into())
                    })?;
                    AeadKeyContext::Uint(value)
                }
                Value::Text(value) => AeadKeyContext::Text(value.clone()),
                Value::Bytes(value) => AeadKeyContext::Thumbprint(value.clone()),
                _ => {
                    return Err(Error::UnexpectedType(
                        "AEAD key context must be uint, text, or bytes".into(),
                    ));
                }
            })
        } else {
            None
        };

        Ok(Self {
            nonce,
            ciphertext,
            tag,
            key_context,
        })
    }
}

/// Reads `sd_aead_encrypted_claims` from an unprotected header.
pub fn aead_encrypted_disclosures_from_unprotected(
    header: &Header,
) -> Result<Vec<AeadEncryptedDisclosure>, Error> {
    aead_encrypted_disclosures_from_unprotected_with_limits(header, ProcessingLimits::default())
}

/// Reads encrypted disclosures while enforcing explicit resource limits.
pub fn aead_encrypted_disclosures_from_unprotected_with_limits(
    header: &Header,
    limits: ProcessingLimits,
) -> Result<Vec<AeadEncryptedDisclosure>, Error> {
    let Some(value) = header.get(HEADER_SD_AEAD_ENCRYPTED_CLAIMS) else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = value else {
        return Err(Error::UnexpectedType(
            "sd_aead_encrypted_claims must be an array".into(),
        ));
    };
    if items.is_empty() {
        return Err(Error::custom(
            "sd_aead_encrypted_claims must be omitted instead of containing an empty array",
        ));
    }
    if items.len() > limits.max_disclosures {
        return Err(Error::limit(
            "SD-CWT encrypted disclosure",
            limits.max_disclosures,
        ));
    }
    if items.len() > limits.max_container_entries {
        return Err(Error::limit(
            "SD-CWT encrypted disclosure container entry",
            limits.max_container_entries,
        ));
    }
    let item_count = items.iter().try_fold(1usize, |count, value| {
        count
            .checked_add(value_item_count(value)?)
            .ok_or_else(|| Error::custom("encrypted disclosure item count overflow"))
    })?;
    if item_count > limits.max_items {
        return Err(Error::limit(
            "SD-CWT encrypted disclosure item",
            limits.max_items,
        ));
    }
    let disclosures = items
        .iter()
        .map(AeadEncryptedDisclosure::from_value)
        .collect::<Result<Vec<_>, _>>()?;
    let mut nonces = HashSet::with_capacity(disclosures.len());
    if disclosures
        .iter()
        .any(|disclosure| !nonces.insert(disclosure.nonce.clone()))
    {
        return Err(Error::verify(
            "duplicate nonce in SD-CWT encrypted disclosures",
        ));
    }
    let total_bytes = disclosures.iter().try_fold(0usize, |total, disclosure| {
        total
            .checked_add(disclosure.nonce.len())
            .and_then(|total| total.checked_add(disclosure.ciphertext.len()))
            .and_then(|total| total.checked_add(disclosure.tag.len()))
            .and_then(|total| {
                let context_len = match &disclosure.key_context {
                    Some(AeadKeyContext::Text(value)) => value.len(),
                    Some(AeadKeyContext::Thumbprint(value)) => value.len(),
                    Some(AeadKeyContext::Uint(_)) | None => 0,
                };
                total.checked_add(context_len)
            })
            .ok_or_else(|| Error::custom("encrypted disclosure size overflow"))
    })?;
    if total_bytes > limits.max_disclosure_bytes {
        return Err(Error::limit(
            "SD-CWT encrypted disclosure bytes",
            limits.max_disclosure_bytes,
        ));
    }
    Ok(disclosures)
}

/// Writes `sd_aead_encrypted_claims` to an unprotected header.
pub fn set_aead_encrypted_disclosures(
    header: &mut Header,
    disclosures: &[AeadEncryptedDisclosure],
) {
    if disclosures.is_empty() {
        header.remove(HEADER_SD_AEAD_ENCRYPTED_CLAIMS);
        return;
    }

    header.insert(
        HEADER_SD_AEAD_ENCRYPTED_CLAIMS,
        Value::Array(
            disclosures
                .iter()
                .map(AeadEncryptedDisclosure::to_value)
                .collect(),
        ),
    );
}

/// Result of converting a pre-issued claims value into an issued SD-CWT value.
#[derive(Clone, Debug, PartialEq)]
pub struct IssueResult {
    /// The issued value with tag 58/62 requests replaced by redacted hashes.
    pub value: Value,
    /// The Salted Disclosed Claims created while issuing.
    pub disclosures: DisclosureSet,
}

/// Resource limits applied while issuing or restoring SD-CWT claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessingLimits {
    /// Maximum nesting assembled across the payload and disclosures.
    pub max_depth: usize,
    /// Maximum number of values visited during one operation.
    pub max_items: usize,
    /// Maximum number of disclosures accepted in one operation.
    pub max_disclosures: usize,
    /// Maximum combined encoded disclosure size.
    pub max_disclosure_bytes: usize,
    /// Maximum entries in any one map or array.
    pub max_container_entries: usize,
    /// Maximum encoded SD-CWT or payload size accepted by high-level APIs.
    pub max_input_bytes: usize,
}

impl Default for ProcessingLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_items: 100_000,
            max_disclosures: 4_096,
            max_disclosure_bytes: 4 * 1024 * 1024,
            max_container_entries: 16_384,
            max_input_bytes: 8 * 1024 * 1024,
        }
    }
}

struct TraversalBudget {
    limits: ProcessingLimits,
    visited: usize,
}

impl TraversalBudget {
    fn new(limits: ProcessingLimits) -> Self {
        Self { limits, visited: 0 }
    }

    fn enter(&mut self, depth: usize) -> Result<(), Error> {
        if depth > self.limits.max_depth {
            return Err(Error::limit("SD-CWT nesting", self.limits.max_depth));
        }
        self.consume(1)
    }

    fn consume(&mut self, count: usize) -> Result<(), Error> {
        self.visited = self
            .visited
            .checked_add(count)
            .ok_or_else(|| Error::custom("SD-CWT item count overflow"))?;
        if self.visited > self.limits.max_items {
            return Err(Error::limit("SD-CWT item", self.limits.max_items));
        }
        Ok(())
    }

    fn container(&self, len: usize) -> Result<(), Error> {
        if len > self.limits.max_container_entries {
            Err(Error::limit(
                "SD-CWT container entry",
                self.limits.max_container_entries,
            ))
        } else {
            Ok(())
        }
    }
}

/// Converts a pre-issued claims value containing tag 58/62 requests into an issued value.
///
/// Tag 58 around a map key redacts that key/value pair. Tag 58 around an
/// array element redacts that element. Tag 62 inserts a decoy redaction at
/// that map or array position; the tag payload must be a positive integer
/// that is unique within the SD-CWT being issued.
pub fn issue_from_preissuance(
    value: Value,
    salts: &mut dyn SaltGenerator,
    hasher: &dyn RedactionHasher,
) -> Result<IssueResult, Error> {
    issue_from_preissuance_with_limits(value, salts, hasher, ProcessingLimits::default())
}

/// Converts pre-issuance claims while enforcing caller-selected limits.
pub fn issue_from_preissuance_with_limits(
    value: Value,
    salts: &mut dyn SaltGenerator,
    hasher: &dyn RedactionHasher,
    limits: ProcessingLimits,
) -> Result<IssueResult, Error> {
    if !matches!(value, Value::Map(_)) {
        return Err(Error::UnexpectedType(
            "pre-issuance SD-CWT claims must be a map".into(),
        ));
    }
    let mut context = IssueContext {
        salts,
        hasher,
        decoy_ids: HashSet::new(),
        salts_used: HashSet::new(),
        digests_used: HashSet::new(),
        disclosures: Vec::new(),
        disclosure_bytes: 0,
        budget: TraversalBudget::new(limits),
    };
    let value = issue_value(value, &mut context, 0)?;
    Ok(IssueResult {
        value,
        disclosures: DisclosureSet::from_disclosures(context.disclosures),
    })
}

/// Controls how unmatched Redacted Claim Hashes are handled during restoration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreMode {
    /// Holder validation: every redaction must have a matching disclosure.
    Holder,
    /// Verifier validation: undisclosed redactions and decoys are removed.
    Verifier,
}

/// Result of restoring disclosed SD-CWT claims.
#[derive(Clone, Debug, PartialEq)]
pub struct RestoreReport {
    /// The restored payload claims value.
    pub value: Value,
    /// Restored claims from the protected `CWT_Claims` header, when present.
    pub protected_claims: Option<Value>,
    /// Number of map claims or array elements restored from disclosures.
    pub disclosed: usize,
    /// Number of matching decoy redactions removed.
    pub decoys: usize,
    /// Number of redactions removed because no disclosure was presented.
    pub removed_redactions: usize,
}

#[derive(Default)]
struct RestoreStats {
    disclosed: usize,
    decoys: usize,
    removed_redactions: usize,
}

/// Restores a claims value using Holder validation rules.
pub fn restore_for_holder<I>(
    value: Value,
    disclosures: I,
    hasher: &dyn RedactionHasher,
) -> Result<RestoreReport, Error>
where
    I: IntoIterator<Item = Disclosure>,
{
    restore(value, disclosures, hasher, RestoreMode::Holder)
}

/// Restores a claims value using Verifier validation rules.
pub fn restore_for_verifier<I>(
    value: Value,
    disclosures: I,
    hasher: &dyn RedactionHasher,
) -> Result<RestoreReport, Error>
where
    I: IntoIterator<Item = Disclosure>,
{
    restore(value, disclosures, hasher, RestoreMode::Verifier)
}

/// Restores a claims value using the selected validation mode.
pub fn restore<I>(
    value: Value,
    disclosures: I,
    hasher: &dyn RedactionHasher,
    mode: RestoreMode,
) -> Result<RestoreReport, Error>
where
    I: IntoIterator<Item = Disclosure>,
{
    restore_with_limits(
        value,
        disclosures,
        hasher,
        mode,
        ProcessingLimits::default(),
    )
}

/// Restores claims while enforcing caller-selected resource limits.
pub fn restore_with_limits<I>(
    value: Value,
    disclosures: I,
    hasher: &dyn RedactionHasher,
    mode: RestoreMode,
    limits: ProcessingLimits,
) -> Result<RestoreReport, Error>
where
    I: IntoIterator<Item = Disclosure>,
{
    restore_with_protected_claims(value, None, disclosures, hasher, mode, limits, false)
}

fn restore_with_protected_claims<I>(
    value: Value,
    protected_claims: Option<Value>,
    disclosures: I,
    hasher: &dyn RedactionHasher,
    mode: RestoreMode,
    limits: ProcessingLimits,
    validate_claims: bool,
) -> Result<RestoreReport, Error>
where
    I: IntoIterator<Item = Disclosure>,
{
    let mut stats = RestoreStats::default();
    let mut budget = TraversalBudget::new(limits);
    let mut pending = DisclosureMap::new(disclosures, hasher, &mut budget)?;
    pending.validate_claims = validate_claims;
    let mut protected_claims = protected_claims
        .map(|claims| restore_value(claims, &mut pending, mode, &mut stats, &mut budget, 0))
        .transpose()?;
    let mut value = restore_value(value, &mut pending, mode, &mut stats, &mut budget, 0)?;
    if !pending.is_empty() {
        return Err(Error::verify(
            "sd_claims contains a disclosure without a matching redacted claim",
        ));
    }
    if validate_claims {
        let Value::Map(entries) = &value else {
            unreachable!("the structural validator requires a claims map");
        };
        // Preserve undisclosed markers until comparison: removing them first
        // loses the distinction between absent and still-hidden fields.
        validate_matching_claims(&claim_maps(entries, protected_claims.as_ref()))?;
        remove_undisclosed_redactions(&mut value);
        if let Some(claims) = &mut protected_claims {
            remove_undisclosed_redactions(claims);
        }
    }
    Ok(RestoreReport {
        value,
        protected_claims,
        disclosed: stats.disclosed,
        decoys: stats.decoys,
        removed_redactions: stats.removed_redactions,
    })
}

/// Decodes a COSE payload as CBOR and restores it using disclosures in the message header.
///
/// This helper supports the SD-CWT default hash algorithm, SHA-256. Use
/// [`restore_payload_with_disclosures`] when a profile uses another hash.
///
/// # Security
///
/// This helper does **not** verify the COSE signature or holder binding.
/// Pass only messages whose signature was verified from the received wire
/// bytes, and check holder binding (KBT) separately — see the crate-level
/// Security notes.
pub fn restore_payload_from_message(
    message: &cose2::Sign1Message,
    mode: RestoreMode,
) -> Result<RestoreReport, Error> {
    let hasher = default_hasher_for_sd_alg(sd_alg(&message.protected)?)?;
    let disclosures = disclosures_from_unprotected(&message.unprotected)?;
    restore_payload_with_disclosures(message, disclosures, &hasher, mode)
}

/// Decodes a COSE payload as CBOR and restores it with caller-supplied disclosures.
///
/// # Security
///
/// This helper does **not** verify the COSE signature or holder binding —
/// see the crate-level Security notes.
pub fn restore_payload_with_disclosures<I>(
    message: &cose2::Sign1Message,
    disclosures: I,
    hasher: &dyn RedactionHasher,
    mode: RestoreMode,
) -> Result<RestoreReport, Error>
where
    I: IntoIterator<Item = Disclosure>,
{
    restore_payload_with_disclosures_and_limits(
        message,
        disclosures,
        hasher,
        mode,
        ProcessingLimits::default(),
    )
}

/// Decodes and restores an SD-CWT payload and protected `CWT_Claims` map with
/// explicit resource limits.
pub fn restore_payload_with_disclosures_and_limits<I>(
    message: &cose2::Sign1Message,
    disclosures: I,
    hasher: &dyn RedactionHasher,
    mode: RestoreMode,
    limits: ProcessingLimits,
) -> Result<RestoreReport, Error>
where
    I: IntoIterator<Item = Disclosure>,
{
    ensure_message_protected_state(message)?;
    let payload = message
        .payload
        .as_deref()
        .ok_or_else(|| Error::custom("SD-CWT message must carry an embedded payload"))?;
    if payload.len() > limits.max_input_bytes {
        return Err(Error::limit("SD-CWT payload bytes", limits.max_input_bytes));
    }
    cose2::validate_cbor(
        payload,
        cose2::CborLimits {
            max_depth: limits.max_depth,
            max_items: limits.max_items,
            require_definite: true,
        },
    )?;
    let value: Value = cbor2::from_slice(payload)?;
    if !matches!(value, Value::Map(_)) {
        return Err(Error::UnexpectedType(
            "SD-CWT payload must be a claims map".into(),
        ));
    }
    restore_with_protected_claims(
        value,
        protected_cwt_claims(message)?,
        disclosures,
        hasher,
        mode,
        limits,
        false,
    )
}

/// Verifies a definite-length SD-CWT COSE_Sign1, validates its protected
/// envelope headers, and returns the decoded message.
pub fn verify_and_decode_sd_cwt(
    verifier: &dyn cose2::Verifier,
    data: &[u8],
    external_aad: Option<&[u8]>,
    limits: ProcessingLimits,
) -> Result<cose2::Sign1Message, Error> {
    if data.len() > limits.max_input_bytes {
        return Err(Error::limit("SD-CWT input bytes", limits.max_input_bytes));
    }
    cose2::validate_cbor(
        data,
        cose2::CborLimits {
            max_depth: limits.max_depth,
            max_items: limits.max_items,
            require_definite: true,
        },
    )?;
    let message = cose2::Sign1Message::from_slice(data)?;
    validate_sd_headers(&message, limits)?;
    let verifier = SdCriticalVerifier::new(verifier);
    message.verify(&verifier, external_aad)?;
    Ok(message)
}

struct SdCriticalVerifier<'a> {
    inner: &'a dyn cose2::Verifier,
    understood: Vec<Label>,
}

impl<'a> SdCriticalVerifier<'a> {
    fn new(inner: &'a dyn cose2::Verifier) -> Self {
        let mut understood = inner.understood_critical_headers().to_vec();
        for label in [HEADER_CWT_CLAIMS, HEADER_TYP, HEADER_SD_ALG, HEADER_SD_AEAD] {
            let label = Label::from(label);
            if !understood.contains(&label) {
                understood.push(label);
            }
        }
        Self { inner, understood }
    }
}

impl cose2::Verifier for SdCriticalVerifier<'_> {
    fn alg(&self) -> Option<Label> {
        self.inner.alg()
    }

    fn kid(&self) -> Option<&[u8]> {
        self.inner.kid()
    }

    fn understood_critical_headers(&self) -> &[Label] {
        &self.understood
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        self.inner.verify(data, signature)
    }
}

/// Options for full SD-CWT structural validation and restoration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SdCwtValidationOptions {
    /// Allow a protected certificate header to identify the issuer when `iss`
    /// is absent. The caller is responsible for validating that certificate.
    pub issuer_identified_by_protected_header: bool,
    /// Optional profile nonce-size constraint, applied in addition to the
    /// selected AEAD algorithm's required `N_MIN` size.
    pub aead_nonce_size: Option<usize>,
    /// Resource limits for parsing and restoration.
    pub limits: ProcessingLimits,
}

/// Validates the draft-08 SD-CWT structure and restores its disclosed claims.
#[derive(Clone, Copy, Debug)]
pub struct SdCwtValidator {
    options: SdCwtValidationOptions,
}

impl SdCwtValidator {
    /// Creates an SD-CWT validator.
    pub fn new(options: SdCwtValidationOptions) -> Self {
        Self { options }
    }

    /// Validates headers, required claims, dates and disclosure rules, then restores.
    ///
    /// `message` must be the result of verifying the received wire bytes. Use
    /// [`verify_validate_and_restore_sd_cwt`] for the combined safe path.
    pub fn validate_and_restore(
        &self,
        message: &cose2::Sign1Message,
        mode: RestoreMode,
    ) -> Result<RestoreReport, Error> {
        ensure_message_protected_state(message)?;
        validate_sd_headers(message, self.options.limits)?;
        let protected_claims = protected_cwt_claims(message)?;
        let disclosures =
            disclosures_from_unprotected_with_limits(&message.unprotected, self.options.limits)?;
        let encrypted = aead_encrypted_disclosures_from_unprotected_with_limits(
            &message.unprotected,
            self.options.limits,
        )?;
        let aead_algorithm = sd_aead(&message.protected)?.unwrap_or(1);
        validate_aead_disclosure_dimensions(
            &encrypted,
            aead_algorithm,
            self.options.aead_nonce_size,
        )?;

        let payload = message
            .payload
            .as_deref()
            .ok_or_else(|| Error::custom("SD-CWT message must carry an embedded payload"))?;
        if payload.len() > self.options.limits.max_input_bytes {
            return Err(Error::limit(
                "SD-CWT payload bytes",
                self.options.limits.max_input_bytes,
            ));
        }
        cose2::validate_cbor(
            payload,
            cose2::CborLimits {
                max_depth: self.options.limits.max_depth,
                max_items: self.options.limits.max_items,
                require_definite: true,
            },
        )?;
        let value: Value = cbor2::from_slice(payload)?;
        let Value::Map(entries) = &value else {
            return Err(Error::UnexpectedType(
                "SD-CWT payload must be a claims map".into(),
            ));
        };
        let maps = claim_maps(entries, protected_claims.as_ref());
        validate_registered_claim_types(&maps)?;
        validate_required_claims(
            &maps,
            self.options.issuer_identified_by_protected_header,
            true,
        )?;
        validate_time_relationships(&maps)?;

        let hasher = default_hasher_for_sd_alg(sd_alg(&message.protected)?)?;
        let report = restore_with_protected_claims(
            value,
            protected_claims,
            disclosures,
            &hasher,
            mode,
            self.options.limits,
            true,
        )?;
        let Value::Map(entries) = &report.value else {
            unreachable!();
        };
        let restored_maps = claim_maps(entries, report.protected_claims.as_ref());
        validate_registered_claim_types(&restored_maps)?;
        validate_time_relationships(&restored_maps)?;
        if mode == RestoreMode::Holder {
            validate_required_claims(
                &restored_maps,
                self.options.issuer_identified_by_protected_header,
                false,
            )?;
        }
        Ok(report)
    }
}

fn ensure_message_protected_state(message: &cose2::Sign1Message) -> Result<(), Error> {
    let current = message.protected.to_vec()?;
    if current == message.protected_raw()
        || (message.protected.is_empty() && message.protected_raw().is_empty())
    {
        return Ok(());
    }
    let authenticated = if message.protected_raw().is_empty() {
        Header::new()
    } else {
        Header::from_slice(message.protected_raw())?
    };
    if authenticated.to_vec()? != current {
        return Err(Error::invalid_state(
            "SD-CWT protected header differs from authenticated bytes",
        ));
    }
    Ok(())
}

impl Default for SdCwtValidator {
    fn default() -> Self {
        Self::new(SdCwtValidationOptions::default())
    }
}

/// Verifies the issuer signature, validates draft-08 structure and restores
/// disclosures in one operation.
pub fn verify_validate_and_restore_sd_cwt(
    verifier: &dyn cose2::Verifier,
    data: &[u8],
    external_aad: Option<&[u8]>,
    mode: RestoreMode,
    options: SdCwtValidationOptions,
) -> Result<(cose2::Sign1Message, RestoreReport), Error> {
    let message = verify_and_decode_sd_cwt(verifier, data, external_aad, options.limits)?;
    let report = SdCwtValidator::new(options).validate_and_restore(&message, mode)?;
    Ok((message, report))
}

fn validate_sd_headers(
    message: &cose2::Sign1Message,
    limits: ProcessingLimits,
) -> Result<(), Error> {
    // The protected map is CBOR embedded inside a byte string. Validating the
    // outer message cannot inspect its encoding or apply these limits to it.
    if !message.protected_raw().is_empty() {
        cose2::validate_cbor(
            message.protected_raw(),
            cose2::CborLimits {
                max_depth: limits.max_depth,
                max_items: limits.max_items,
                require_definite: true,
            },
        )?;
    }
    for label in [HEADER_SD_CLAIMS, HEADER_SD_AEAD_ENCRYPTED_CLAIMS] {
        if message.protected.contains_key(label) {
            return Err(Error::custom(format!(
                "SD-CWT header {label} must be unprotected"
            )));
        }
    }
    for label in [HEADER_CWT_CLAIMS, HEADER_TYP, HEADER_SD_ALG, HEADER_SD_AEAD] {
        if message.unprotected.contains_key(label) {
            return Err(Error::custom(format!(
                "SD-CWT header {label} must be protected"
            )));
        }
    }
    match message.protected.get(HEADER_TYP) {
        Some(Value::Integer(value))
            if i64::try_from(*value).ok() == Some(CONTENT_FORMAT_SD_CWT) => {}
        Some(Value::Text(value)) if is_sd_cwt_content_type(value) => {}
        _ => {
            return Err(Error::custom(
                "SD-CWT protected typ must be 293, application/sd-cwt, or a +sd-cwt media type",
            ))
        }
    }
    let _ = sd_alg(&message.protected)?;
    if let Some(algorithm) = sd_aead(&message.protected)? {
        validate_sd_aead_algorithm(algorithm)?;
    }
    let algorithm = message
        .protected
        .alg()?
        .ok_or_else(|| Error::custom("SD-CWT protected header is missing alg"))?;
    let Label::Int(algorithm) = algorithm else {
        return Err(Error::custom(
            "SD-CWT signature algorithm must be a registered integer",
        ));
    };
    if !is_fully_specified_signature_algorithm(algorithm) {
        return Err(Error::custom(format!(
            "SD-CWT algorithm {algorithm} is not a recognized fully specified asymmetric signature algorithm"
        )));
    }
    if let Some(claims) = protected_cwt_claims_ref(message)? {
        validate_issued_value(claims, &mut TraversalBudget::new(limits), 0)?;
    }
    validate_safe_headers(message, limits)
}

fn is_sd_cwt_content_type(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    if value == "application/sd-cwt" {
        return true;
    }
    let Some((type_name, subtype)) = value.split_once('/') else {
        return false;
    };
    is_media_type_token(type_name)
        && is_media_type_token(subtype)
        && !subtype.starts_with('+')
        && subtype.ends_with("+sd-cwt")
}

fn is_media_type_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                )
        })
}

fn is_fully_specified_signature_algorithm(algorithm: i64) -> bool {
    matches!(
        algorithm,
        cose2::iana::AlgorithmESB512
            | cose2::iana::AlgorithmESB384
            | cose2::iana::AlgorithmESB320
            | cose2::iana::AlgorithmESB256
            | cose2::iana::AlgorithmWalnutDSA
            | cose2::iana::AlgorithmRS512
            | cose2::iana::AlgorithmRS384
            | cose2::iana::AlgorithmRS256
            | cose2::iana::AlgorithmEd448
            | cose2::iana::AlgorithmESP512
            | cose2::iana::AlgorithmESP384
            | cose2::iana::AlgorithmML_DSA_87
            | cose2::iana::AlgorithmML_DSA_65
            | cose2::iana::AlgorithmML_DSA_44
            | cose2::iana::AlgorithmES256K
            | cose2::iana::AlgorithmHSS_LMS
            | cose2::iana::AlgorithmPS512
            | cose2::iana::AlgorithmPS384
            | cose2::iana::AlgorithmPS256
            | cose2::iana::AlgorithmEd25519
            | cose2::iana::AlgorithmESP256
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SdAeadDimensions {
    nonce_size: usize,
    tag_sizes: &'static [usize],
}

fn sd_aead_dimensions(algorithm: u16) -> Result<SdAeadDimensions, Error> {
    // draft-ietf-spice-sd-cwt-08 requires an N_MIN-sized nonce. The values
    // below come from each algorithm's defining entry in the IANA AEAD
    // Algorithms registry; tag sizes are restricted to at least 16 bytes by
    // the draft, with AEGIS-X further restricted to its 256-bit variant.
    const TAG_128: &[usize] = &[16];
    const TAG_128_OR_256: &[usize] = &[16, 32];
    const TAG_256: &[usize] = &[32];

    let (nonce_size, tag_sizes) = match algorithm {
        1 | 2 => (12, TAG_128),
        15..=17 | 20 | 23 | 26 => (1, TAG_128),
        29..=31 => (12, TAG_128),
        32 => (16, TAG_128_OR_256),
        33 => (32, TAG_128_OR_256),
        34 | 35 => (16, TAG_256),
        36 | 37 => (32, TAG_256),
        38 | 39 => (24, TAG_128),
        _ => {
            return Err(Error::custom(format!(
                "AEAD algorithm {algorithm} is not permitted for SD-CWT encrypted disclosures"
            )))
        }
    };
    Ok(SdAeadDimensions {
        nonce_size,
        tag_sizes,
    })
}

fn validate_sd_aead_algorithm(algorithm: u16) -> Result<(), Error> {
    sd_aead_dimensions(algorithm).map(|_| ())
}

fn validate_aead_disclosure_dimensions(
    encrypted: &[AeadEncryptedDisclosure],
    algorithm: u16,
    profile_nonce_size: Option<usize>,
) -> Result<(), Error> {
    let dimensions = sd_aead_dimensions(algorithm)?;
    for entry in encrypted {
        let actual_nonce_size = entry.nonce.len();
        if actual_nonce_size != dimensions.nonce_size {
            return Err(Error::custom(format!(
                "AEAD algorithm {algorithm} disclosure nonce size mismatch, expected {}, got {actual_nonce_size}",
                dimensions.nonce_size
            )));
        }
        if let Some(expected) = profile_nonce_size {
            if actual_nonce_size != expected {
                return Err(Error::custom(format!(
                    "AEAD disclosure nonce size does not satisfy the profile, expected {expected}, got {actual_nonce_size}"
                )));
            }
        }
        if !dimensions.tag_sizes.contains(&entry.tag.len()) {
            let expected = dimensions
                .tag_sizes
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(" or ");
            return Err(Error::custom(format!(
                "AEAD algorithm {algorithm} disclosure tag size mismatch, expected {expected} bytes, got {}",
                entry.tag.len()
            )));
        }
    }
    Ok(())
}

fn validate_safe_headers(
    message: &cose2::Sign1Message,
    limits: ProcessingLimits,
) -> Result<(), Error> {
    let mut budget = TraversalBudget::new(limits);
    for (header, skip_cwt_claims) in [(&message.protected, true), (&message.unprotected, false)] {
        budget.enter(0)?;
        budget.container(header.len())?;
        for (label, value) in header.iter() {
            budget.enter(1)?;
            validate_text_label(label)?;
            if skip_cwt_claims && *label == Label::Int(HEADER_CWT_CLAIMS) {
                continue;
            }
            validate_safe_value(value, &mut budget, 1)?;
        }
    }
    Ok(())
}

fn validate_safe_value(
    value: &Value,
    budget: &mut TraversalBudget,
    depth: usize,
) -> Result<(), Error> {
    budget.enter(depth)?;
    match value {
        Value::Array(items) => {
            budget.container(items.len())?;
            for item in items {
                validate_safe_value(item, budget, depth + 1)?;
            }
        }
        Value::Map(entries) => {
            budget.container(entries.len())?;
            let mut keys = HashSet::with_capacity(entries.len());
            for (key, value) in entries {
                budget.enter(depth + 1)?;
                let key = safe_map_key(key)?;
                if !keys.insert(key) {
                    return Err(Error::verify("duplicate safe-map key"));
                }
                validate_safe_value(value, budget, depth + 1)?;
            }
        }
        Value::Tag(tag, _)
            if matches!(
                *tag,
                TO_BE_REDACTED_TAG | REDACTED_ELEMENT_TAG | TO_BE_DECOY_TAG
            ) =>
        {
            return Err(Error::UnexpectedType(format!(
                "SD-CWT reserved tag {tag} is not permitted in this header value"
            )));
        }
        Value::Tag(_, inner) => validate_safe_value(inner, budget, depth + 1)?,
        Value::Simple(simple) if simple.value() == REDACTED_CLAIM_KEYS_SIMPLE => {
            return Err(Error::UnexpectedType(
                "simple(59) is not permitted in this header value".into(),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn validate_disclosure_value(
    disclosure: &DisclosureKind,
    limits: ProcessingLimits,
) -> Result<(), Error> {
    let (value, fixed_items) = match disclosure {
        DisclosureKind::Claim { value, .. } => (value, 3),
        DisclosureKind::Element { value, .. } => (value, 2),
        DisclosureKind::Decoy { .. } => return Ok(()),
    };
    let mut budget = TraversalBudget::new(limits);
    budget.consume(fixed_items)?;
    validate_issued_value(value, &mut budget, 0)
}

fn validate_issued_value(
    value: &Value,
    budget: &mut TraversalBudget,
    depth: usize,
) -> Result<(), Error> {
    budget.enter(depth)?;
    match value {
        Value::Map(entries) => {
            budget.container(entries.len())?;
            let mut keys = HashSet::with_capacity(entries.len());
            for (key, value) in entries {
                budget.enter(depth + 1)?;
                let canonical = cbor2::to_canonical_vec(key)?;
                if !keys.insert(canonical) {
                    return Err(Error::verify("duplicate issued SD-CWT map key"));
                }
                if is_redacted_claim_keys_label(key) {
                    let Value::Array(hashes) = value else {
                        return Err(Error::UnexpectedType(
                            "redacted_claim_keys value must be an array".into(),
                        ));
                    };
                    budget.enter(depth + 1)?;
                    budget.container(hashes.len())?;
                    for hash in hashes {
                        budget.enter(depth + 2)?;
                        expect_bytes(hash, "redacted_claim_keys entry")?;
                    }
                } else {
                    label_from_value(key).map_err(|_| {
                        Error::UnexpectedType(
                            "issued SD-CWT map keys must be integers or text".into(),
                        )
                    })?;
                    validate_issued_value(value, budget, depth + 1)?;
                }
            }
        }
        Value::Array(items) => {
            budget.container(items.len())?;
            for item in items {
                if let Value::Tag(REDACTED_ELEMENT_TAG, inner) = item {
                    budget.enter(depth + 1)?;
                    budget.enter(depth + 2)?;
                    expect_bytes(inner, "redacted array element hash")?;
                } else {
                    validate_issued_value(item, budget, depth + 1)?;
                }
            }
        }
        Value::Tag(tag, _)
            if matches!(
                *tag,
                TO_BE_REDACTED_TAG | REDACTED_ELEMENT_TAG | TO_BE_DECOY_TAG
            ) =>
        {
            return Err(Error::UnexpectedType(format!(
                "SD-CWT tag {tag} is not valid in this value position"
            )));
        }
        Value::Tag(_, inner) => validate_issued_value(inner, budget, depth + 1)?,
        Value::Simple(simple) if simple.value() == REDACTED_CLAIM_KEYS_SIMPLE => {
            return Err(Error::UnexpectedType(
                "simple(59) is only valid as a redacted_claim_keys map key".into(),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn validate_text_label(label: &Label) -> Result<(), Error> {
    if matches!(label, Label::Text(value) if !(1..=255).contains(&value.len())) {
        Err(Error::UnexpectedType(
            "SD-CWT text map keys must contain 1 to 255 octets".into(),
        ))
    } else {
        Ok(())
    }
}

fn safe_map_key(value: &Value) -> Result<Vec<u8>, Error> {
    match value {
        Value::Integer(_) => {}
        Value::Text(value) if (1..=255).contains(&value.len()) => {}
        Value::Text(_) => {
            return Err(Error::UnexpectedType(
                "SD-CWT text map keys must contain 1 to 255 octets".into(),
            ));
        }
        _ => {
            return Err(Error::UnexpectedType(
                "SD-CWT safe-map keys must be integers or text strings".into(),
            ));
        }
    }
    Ok(cbor2::to_canonical_vec(value)?)
}

fn protected_cwt_claims(message: &cose2::Sign1Message) -> Result<Option<Value>, Error> {
    Ok(protected_cwt_claims_ref(message)?.cloned())
}

fn protected_cwt_claims_ref(message: &cose2::Sign1Message) -> Result<Option<&Value>, Error> {
    match message.protected.get(HEADER_CWT_CLAIMS) {
        None => Ok(None),
        Some(value @ Value::Map(_)) => Ok(Some(value)),
        Some(_) => Err(Error::UnexpectedType(
            "protected CWT_Claims header must contain a claims map".into(),
        )),
    }
}

fn map_value(entries: &[(Value, Value)], label: i64) -> Option<&Value> {
    entries.iter().find_map(|(key, value)| {
        matches!(key, Value::Integer(key) if i64::try_from(*key).ok() == Some(label))
            .then_some(value)
    })
}

fn claim_maps<'a>(
    payload: &'a [(Value, Value)],
    protected_claims: Option<&'a Value>,
) -> Vec<&'a [(Value, Value)]> {
    let mut maps = vec![payload];
    if let Some(Value::Map(entries)) = protected_claims {
        maps.push(entries);
    }
    maps
}

fn claim_value<'a>(maps: &[&'a [(Value, Value)]], label: i64) -> Option<&'a Value> {
    maps.iter().find_map(|entries| map_value(entries, label))
}

fn validate_matching_claims(maps: &[&[(Value, Value)]]) -> Result<(), Error> {
    let mut seen = HashMap::<Vec<u8>, (usize, &Value)>::new();
    for (map_index, entries) in maps.iter().enumerate() {
        for (key, value) in *entries {
            if is_redacted_claim_keys_label(key) {
                continue;
            }
            let key_bytes = safe_map_key(key)?;
            if let Some((previous_map, previous)) = seen.insert(key_bytes, (map_index, value)) {
                if previous_map == map_index {
                    return Err(Error::verify(format!("duplicate SD-CWT claim key {key}")));
                }
                if !claim_values_match(previous, value)? {
                    return Err(Error::verify(format!(
                        "CWT_Claims header and payload disagree for claim {key}"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Compares the visible parts of restored claims. Unmatched hashes conceal
/// values (or decoys), so their bytes are not evidence of a value mismatch.
fn claim_values_match(left: &Value, right: &Value) -> Result<bool, Error> {
    match (left, right) {
        (Value::Map(left), Value::Map(right)) => {
            let left_hidden = left
                .iter()
                .any(|(key, _)| is_redacted_claim_keys_label(key));
            let right_hidden = right
                .iter()
                .any(|(key, _)| is_redacted_claim_keys_label(key));
            let mut right_values = right
                .iter()
                .filter(|(key, _)| !is_redacted_claim_keys_label(key))
                .map(|(key, value)| Ok((label_from_value(key)?, value)))
                .collect::<Result<HashMap<_, _>, Error>>()?;
            for (key, value) in left {
                if is_redacted_claim_keys_label(key) {
                    continue;
                }
                match right_values.remove(&label_from_value(key)?) {
                    Some(other) if !claim_values_match(value, other)? => return Ok(false),
                    None if !right_hidden => return Ok(false),
                    _ => {}
                }
            }
            Ok(left_hidden || right_values.is_empty())
        }
        (Value::Array(left), Value::Array(right)) => {
            let left_known = left.iter().filter(|v| !is_redacted_element(v)).count();
            let right_known = right.iter().filter(|v| !is_redacted_element(v)).count();
            if left_known > right.len() || right_known > left.len() {
                return Ok(false);
            }
            if left_known == left.len() && right_known == right.len() {
                for (left, right) in left.iter().zip(right) {
                    if !claim_values_match(left, right)? {
                        return Ok(false);
                    }
                }
            } else {
                // An undisclosed element may be a decoy, so middle positions
                // cannot be aligned yet. Known prefixes and suffixes can.
                for (left, right) in left
                    .iter()
                    .take_while(|v| !is_redacted_element(v))
                    .zip(right.iter().take_while(|v| !is_redacted_element(v)))
                    .chain(
                        left.iter()
                            .rev()
                            .take_while(|v| !is_redacted_element(v))
                            .zip(right.iter().rev().take_while(|v| !is_redacted_element(v))),
                    )
                {
                    if !claim_values_match(left, right)? {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        }
        (Value::Tag(left_tag, left), Value::Tag(right_tag, right)) if left_tag == right_tag => {
            claim_values_match(left, right)
        }
        _ => Ok(cbor2::to_canonical_vec(left)? == cbor2::to_canonical_vec(right)?),
    }
}

fn is_redacted_element(value: &Value) -> bool {
    matches!(value, Value::Tag(REDACTED_ELEMENT_TAG, _))
}

fn remove_undisclosed_redactions(value: &mut Value) {
    match value {
        Value::Map(entries) => entries.retain_mut(|(key, value)| {
            if is_redacted_claim_keys_label(key) {
                return false;
            }
            remove_undisclosed_redactions(value);
            true
        }),
        Value::Array(items) => items.retain_mut(|value| {
            if is_redacted_element(value) {
                return false;
            }
            remove_undisclosed_redactions(value);
            true
        }),
        Value::Tag(_, value) => remove_undisclosed_redactions(value),
        _ => {}
    }
}

fn validate_registered_claim_types(maps: &[&[(Value, Value)]]) -> Result<(), Error> {
    for (label, name) in [
        (cose2::iana::CWTClaimIss, "iss"),
        (cose2::iana::CWTClaimSub, "sub"),
        (cose2::iana::CWTClaimAud, "aud"),
    ] {
        if claim_value(maps, label).is_some_and(|value| !matches!(value, Value::Text(_))) {
            return Err(Error::UnexpectedType(format!(
                "SD-CWT {name} must be a text string"
            )));
        }
    }
    for (label, name) in [
        (cose2::iana::CWTClaimExp, "exp"),
        (cose2::iana::CWTClaimNbf, "nbf"),
        (cose2::iana::CWTClaimIat, "iat"),
    ] {
        if let Some(value) = claim_value(maps, label) {
            DateValue::from_value(value, name)?;
        }
    }
    if claim_value(maps, cose2::iana::CWTClaimCti)
        .is_some_and(|value| !matches!(value, Value::Bytes(_)))
    {
        return Err(Error::UnexpectedType(
            "SD-CWT cti must be a byte string".into(),
        ));
    }
    if claim_value(maps, cose2::iana::CWTClaimCnf)
        .is_some_and(|value| !matches!(value, Value::Map(_)))
    {
        return Err(Error::UnexpectedType("SD-CWT cnf must be a map".into()));
    }
    if claim_value(maps, CWT_CLAIM_CNONCE).is_some_and(|value| !matches!(value, Value::Bytes(_))) {
        return Err(Error::UnexpectedType(
            "SD-CWT cnonce must be a byte string".into(),
        ));
    }
    if let Some(value) = claim_value(maps, CWT_CLAIM_VCT) {
        match value {
            Value::Text(_) => {}
            Value::Integer(value) if u16::try_from(*value).is_ok() => {}
            _ => {
                return Err(Error::UnexpectedType(
                    "SD-CWT vct must be a text string or uint16".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_required_claims(
    maps: &[&[(Value, Value)]],
    issuer_from_header: bool,
    allow_redacted_subject: bool,
) -> Result<(), Error> {
    if !issuer_from_header {
        match claim_value(maps, cose2::iana::CWTClaimIss) {
            Some(Value::Text(_)) => {}
            Some(_) => return Err(Error::UnexpectedType("SD-CWT iss must be text".into())),
            None => return Err(Error::custom("SD-CWT is missing required iss claim")),
        }
    }
    match claim_value(maps, cose2::iana::CWTClaimCnf) {
        Some(Value::Map(_)) => {}
        Some(_) => return Err(Error::UnexpectedType("SD-CWT cnf must be a map".into())),
        None => return Err(Error::custom("SD-CWT is missing required cnf claim")),
    }
    if !matches!(
        claim_value(maps, cose2::iana::CWTClaimSub),
        Some(Value::Text(_))
    ) {
        let has_redacted_root_claim = maps.iter().any(|entries| {
            entries.iter().any(|(key, value)| {
                is_redacted_claim_keys_label(key)
                    && matches!(value, Value::Array(hashes) if !hashes.is_empty())
            })
        });
        if !allow_redacted_subject || !has_redacted_root_claim {
            return Err(Error::custom(
                "SD-CWT is missing required disclosed or redacted sub claim",
            ));
        }
    }
    Ok(())
}

fn validate_root_disclosure_key(key: &Label) -> Result<(), Error> {
    const NEVER_REDACTED: &[i64] = &[1, 3, 4, 5, 6, 7, 8, 39];
    if matches!(key, Label::Int(key) if NEVER_REDACTED.contains(key)) {
        return Err(Error::custom(format!(
            "SD-CWT claim {key} must not be redacted"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum DateValue {
    Integer(i128),
    Float(f64),
}

impl DateValue {
    fn from_value(value: &Value, name: &str) -> Result<Self, Error> {
        match value {
            Value::Integer(value) => Ok(Self::Integer(i128::from(*value))),
            Value::Float(value) if value.is_finite() && value.abs() <= 9_007_199_254_740_992.0 => {
                Ok(Self::Float(*value))
            }
            Value::Float(_) => Err(Error::UnexpectedType(format!(
                "{name} must be a finite float in the inclusive range [-2^53, 2^53]"
            ))),
            _ => Err(Error::UnexpectedType(format!("{name} must be numeric"))),
        }
    }

    fn compare(self, other: Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (Self::Integer(left), Self::Integer(right)) => left.partial_cmp(&right),
            (Self::Integer(left), Self::Float(right)) => {
                compare_f64_to_i128(right, left).map(std::cmp::Ordering::reverse)
            }
            (Self::Float(left), Self::Integer(right)) => compare_f64_to_i128(left, right),
            (Self::Float(left), Self::Float(right)) => left.partial_cmp(&right),
        }
    }
}

fn compare_f64_to_i128(value: f64, other: i128) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;

    if !value.is_finite() {
        return None;
    }
    if value >= i128::MAX as f64 {
        return Some(Ordering::Greater);
    }
    if value < i128::MIN as f64 {
        return Some(Ordering::Less);
    }
    let truncated = value as i128;
    match truncated.cmp(&other) {
        Ordering::Equal if value == truncated as f64 => Some(Ordering::Equal),
        Ordering::Equal if value.is_sign_negative() => Some(Ordering::Less),
        Ordering::Equal => Some(Ordering::Greater),
        ordering => Some(ordering),
    }
}

fn validate_time_relationships(maps: &[&[(Value, Value)]]) -> Result<(), Error> {
    let exp = claim_value(maps, 4)
        .map(|value| DateValue::from_value(value, "exp"))
        .transpose()?;
    let nbf = claim_value(maps, 5)
        .map(|value| DateValue::from_value(value, "nbf"))
        .transpose()?;
    let iat = claim_value(maps, 6)
        .map(|value| DateValue::from_value(value, "iat"))
        .transpose()?;
    if let (Some(nbf), Some(iat)) = (nbf, iat) {
        if nbf.compare(iat) == Some(std::cmp::Ordering::Greater) {
            return Err(Error::custom("SD-CWT requires nbf <= iat"));
        }
    }
    if let (Some(nbf), Some(exp)) = (nbf, exp) {
        if nbf.compare(exp) != Some(std::cmp::Ordering::Less) {
            return Err(Error::custom("SD-CWT requires nbf < exp"));
        }
    }
    if let (Some(iat), Some(exp)) = (iat, exp) {
        if iat.compare(exp) != Some(std::cmp::Ordering::Less) {
            return Err(Error::custom("SD-CWT requires iat < exp"));
        }
    }
    Ok(())
}

struct DisclosureMap {
    entries: HashMap<Vec<u8>, Disclosure>,
    // Only the structural validator applies registered-claim policy and
    // retains unmatched markers until duplicate claims have been compared.
    validate_claims: bool,
}

impl DisclosureMap {
    fn new<I>(
        disclosures: I,
        hasher: &dyn RedactionHasher,
        budget: &mut TraversalBudget,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = Disclosure>,
    {
        let mut entries = HashMap::new();
        let mut salts = HashSet::new();
        let mut total_bytes = 0usize;
        for (index, disclosure) in disclosures.into_iter().enumerate() {
            if index >= budget.limits.max_disclosures {
                return Err(Error::limit(
                    "SD-CWT disclosure",
                    budget.limits.max_disclosures,
                ));
            }
            total_bytes = total_bytes
                .checked_add(disclosure.encoded().len())
                .ok_or_else(|| Error::custom("SD-CWT disclosure size overflow"))?;
            if total_bytes > budget.limits.max_disclosure_bytes {
                return Err(Error::limit(
                    "SD-CWT disclosure bytes",
                    budget.limits.max_disclosure_bytes,
                ));
            }
            budget.consume(disclosure.item_count()?)?;
            let hash = disclosure.redacted_hash(hasher);
            let entry = match entries.entry(hash) {
                std::collections::hash_map::Entry::Occupied(_) => {
                    return Err(Error::verify("duplicate SD-CWT disclosure digest"));
                }
                std::collections::hash_map::Entry::Vacant(entry) => entry,
            };
            let salt = match disclosure.kind() {
                DisclosureKind::Claim { salt, .. }
                | DisclosureKind::Element { salt, .. }
                | DisclosureKind::Decoy { salt } => salt,
            };
            if !salts.insert(salt.clone()) {
                return Err(Error::verify("duplicate SD-CWT disclosure salt"));
            }
            entry.insert(disclosure);
        }
        Ok(Self {
            entries,
            validate_claims: false,
        })
    }

    fn remove(&mut self, hash: &[u8]) -> Option<Disclosure> {
        self.entries.remove(hash)
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

struct IssueContext<'a> {
    salts: &'a mut dyn SaltGenerator,
    hasher: &'a dyn RedactionHasher,
    decoy_ids: HashSet<u64>,
    salts_used: HashSet<[u8; 16]>,
    digests_used: HashSet<Vec<u8>>,
    disclosures: Vec<Disclosure>,
    disclosure_bytes: usize,
    budget: TraversalBudget,
}

impl IssueContext<'_> {
    fn next_salt(&mut self) -> Result<[u8; 16], Error> {
        let salt = self.salts.next_salt()?;
        if !self.salts_used.insert(salt) {
            return Err(Error::custom("SaltGenerator returned a duplicate salt"));
        }
        Ok(salt)
    }

    fn add_disclosure(&mut self, disclosure: Disclosure) -> Result<Vec<u8>, Error> {
        if self.disclosures.len() >= self.budget.limits.max_disclosures {
            return Err(Error::limit(
                "SD-CWT disclosure",
                self.budget.limits.max_disclosures,
            ));
        }
        self.disclosure_bytes = self
            .disclosure_bytes
            .checked_add(disclosure.encoded().len())
            .ok_or_else(|| Error::custom("SD-CWT disclosure size overflow"))?;
        if self.disclosure_bytes > self.budget.limits.max_disclosure_bytes {
            return Err(Error::limit(
                "SD-CWT disclosure bytes",
                self.budget.limits.max_disclosure_bytes,
            ));
        }
        let digest = disclosure.redacted_hash(self.hasher);
        if !self.digests_used.insert(digest.clone()) {
            return Err(Error::verify(
                "redaction hash collision while issuing SD-CWT disclosures",
            ));
        }
        self.disclosures.push(disclosure);
        Ok(digest)
    }
}

fn issue_value(value: Value, context: &mut IssueContext<'_>, depth: usize) -> Result<Value, Error> {
    context.budget.enter(depth)?;
    match value {
        Value::Map(entries) => issue_map(entries, context, depth),
        Value::Array(items) => issue_array(items, context, depth),
        Value::Tag(tag, _)
            if matches!(
                tag,
                TO_BE_REDACTED_TAG | TO_BE_DECOY_TAG | REDACTED_ELEMENT_TAG
            ) =>
        {
            Err(Error::custom(format!(
                "SD-CWT tag {tag} is not valid in this value position"
            )))
        }
        Value::Tag(tag, inner) => Ok(Value::Tag(
            tag,
            Box::new(issue_value(*inner, context, depth + 1)?),
        )),
        Value::Simple(simple) if simple.value() == REDACTED_CLAIM_KEYS_SIMPLE => Err(
            Error::custom("pre-issuance value must not contain simple(59) redaction labels"),
        ),
        other => Ok(other),
    }
}

fn issue_map(
    entries: Vec<(Value, Value)>,
    context: &mut IssueContext<'_>,
    depth: usize,
) -> Result<Value, Error> {
    context.budget.container(entries.len())?;
    let mut output = Vec::with_capacity(entries.len());
    let mut normalized_keys = HashSet::<Vec<u8>>::with_capacity(entries.len());
    let mut redacted_hashes = Vec::<Value>::new();

    for (key, value) in entries {
        context.budget.enter(depth + 1)?;
        match key {
            Value::Tag(tag, inner) if tag == TO_BE_REDACTED_TAG => {
                context.budget.enter(depth + 2)?;
                let claim_key = label_from_value(&inner)?;
                let normalized_key = Value::from(claim_key.clone());
                insert_normalized_key(&mut normalized_keys, &normalized_key)?;

                let issued_value = issue_value(value, context, depth + 1)?;
                let disclosure = Disclosure::claim(context.next_salt()?, claim_key, issued_value)?;
                redacted_hashes.push(Value::Bytes(context.add_disclosure(disclosure)?));
            }
            Value::Tag(tag, inner) if tag == TO_BE_DECOY_TAG => {
                context.budget.enter(depth + 2)?;
                let decoy_key = Value::Tag(tag, inner.clone());
                insert_normalized_key(&mut normalized_keys, &decoy_key)?;
                record_decoy_id(&inner, context)?;
                if !matches!(value, Value::Null) {
                    return Err(Error::custom(
                        "map decoy tag 62 entries must have a null value",
                    ));
                }
                context.budget.enter(depth + 1)?;
                let disclosure = Disclosure::decoy(context.next_salt()?)?;
                redacted_hashes.push(Value::Bytes(context.add_disclosure(disclosure)?));
            }
            key if is_redacted_claim_keys_label(&key) => {
                return Err(Error::custom(
                    "pre-issuance map must not already contain simple(59)",
                ));
            }
            key => {
                ensure_preissuance_key(&key)?;
                insert_normalized_key(&mut normalized_keys, &key)?;
                output.push((key, issue_value(value, context, depth + 1)?));
            }
        }
    }

    if !redacted_hashes.is_empty() {
        output.push((redacted_claim_keys_label(), Value::Array(redacted_hashes)));
    }

    Ok(Value::Map(output))
}

fn issue_array(
    items: Vec<Value>,
    context: &mut IssueContext<'_>,
    depth: usize,
) -> Result<Value, Error> {
    context.budget.container(items.len())?;
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Tag(tag, inner) if tag == TO_BE_REDACTED_TAG => {
                context.budget.enter(depth + 1)?;
                let issued = issue_value(*inner, context, depth + 2)?;
                let disclosure = Disclosure::element(context.next_salt()?, issued)?;
                let hash = context.add_disclosure(disclosure)?;
                output.push(redacted_element(hash));
            }
            Value::Tag(tag, inner) if tag == TO_BE_DECOY_TAG => {
                context.budget.enter(depth + 1)?;
                context.budget.enter(depth + 2)?;
                record_decoy_id(&inner, context)?;
                let disclosure = Disclosure::decoy(context.next_salt()?)?;
                let hash = context.add_disclosure(disclosure)?;
                output.push(redacted_element(hash));
            }
            item => output.push(issue_value(item, context, depth + 1)?),
        }
    }
    Ok(Value::Array(output))
}

fn record_decoy_id(value: &Value, context: &mut IssueContext<'_>) -> Result<(), Error> {
    let Value::Integer(id) = value else {
        return Err(Error::UnexpectedType(
            "tag 62 decoy payload must be a positive integer".into(),
        ));
    };
    let id = u64::try_from(*id).map_err(|_| {
        Error::UnexpectedType("tag 62 decoy payload must be a positive integer".into())
    })?;
    if id == 0 {
        return Err(Error::UnexpectedType(
            "tag 62 decoy payload must be greater than zero".into(),
        ));
    }
    if !context.decoy_ids.insert(id) {
        return Err(Error::verify("duplicate tag 62 decoy identifier"));
    }
    Ok(())
}

fn ensure_preissuance_key(key: &Value) -> Result<(), Error> {
    label_from_value(key).map(|_| ())
}

fn insert_normalized_key(keys: &mut HashSet<Vec<u8>>, key: &Value) -> Result<(), Error> {
    let encoded = cbor2::to_canonical_vec(key)?;
    if !keys.insert(encoded) {
        return Err(Error::verify(format!(
            "duplicate pre-issuance map key {key}"
        )));
    }
    Ok(())
}

fn restore_value(
    value: Value,
    pending: &mut DisclosureMap,
    mode: RestoreMode,
    stats: &mut RestoreStats,
    budget: &mut TraversalBudget,
    depth: usize,
) -> Result<Value, Error> {
    budget.enter(depth)?;
    match value {
        Value::Map(entries) => restore_map(entries, pending, mode, stats, budget, depth),
        Value::Array(items) => restore_array(items, pending, mode, stats, budget, depth),
        Value::Tag(tag, _)
            if matches!(
                tag,
                REDACTED_ELEMENT_TAG | TO_BE_REDACTED_TAG | TO_BE_DECOY_TAG
            ) =>
        {
            Err(Error::UnexpectedType(format!(
                "SD-CWT tag {tag} is not valid in this value position"
            )))
        }
        Value::Tag(tag, inner) => Ok(Value::Tag(
            tag,
            Box::new(restore_value(
                *inner,
                pending,
                mode,
                stats,
                budget,
                depth + 1,
            )?),
        )),
        Value::Simple(simple) if simple.value() == REDACTED_CLAIM_KEYS_SIMPLE => {
            Err(Error::UnexpectedType(
                "simple(59) is only valid as a redacted_claim_keys map key".into(),
            ))
        }
        other => Ok(other),
    }
}

fn restore_map(
    entries: Vec<(Value, Value)>,
    pending: &mut DisclosureMap,
    mode: RestoreMode,
    stats: &mut RestoreStats,
    budget: &mut TraversalBudget,
    depth: usize,
) -> Result<Value, Error> {
    budget.container(entries.len())?;
    let mut output = Vec::with_capacity(entries.len());
    let mut output_keys = HashSet::<Label>::with_capacity(entries.len());
    let mut redacted_hashes = Vec::new();
    let mut saw_redacted_keys = false;

    for (key, value) in entries {
        budget.enter(depth + 1)?;
        if is_redacted_claim_keys_label(&key) {
            if saw_redacted_keys {
                return Err(Error::verify("duplicate redacted_claim_keys entry"));
            }
            saw_redacted_keys = true;
            let Value::Array(hashes) = value else {
                return Err(Error::UnexpectedType(
                    "redacted_claim_keys value must be an array".into(),
                ));
            };
            budget.enter(depth + 1)?;
            budget.container(hashes.len())?;
            for hash in hashes {
                budget.enter(depth + 2)?;
                redacted_hashes.push(expect_owned_bytes(
                    hash,
                    "redacted_claim_keys entries must be byte strings",
                )?);
            }
            continue;
        }

        let label = label_from_value(&key).map_err(|_| {
            Error::UnexpectedType("issued SD-CWT map keys must be integers or text".into())
        })?;
        if !output_keys.insert(label) {
            return Err(Error::verify(format!("duplicate claim key {key}")));
        }
        let value = restore_value(value, pending, mode, stats, budget, depth + 1)?;
        output.push((key, value));
    }

    let mut undisclosed_hashes = Vec::new();
    for hash in redacted_hashes {
        match pending.remove(&hash) {
            Some(disclosure) => match disclosure.kind {
                DisclosureKind::Claim { key, value, .. } => {
                    if pending.validate_claims && depth == 0 {
                        validate_root_disclosure_key(&key)?;
                    }
                    if !output_keys.insert(key.clone()) {
                        return Err(Error::verify(format!("duplicate claim key {key}")));
                    }
                    let value = restore_value(value, pending, mode, stats, budget, depth + 1)?;
                    output.push((Value::from(key), value));
                    stats.disclosed += 1;
                }
                DisclosureKind::Decoy { .. } => {
                    stats.decoys += 1;
                }
                DisclosureKind::Element { .. } => {
                    return Err(Error::verify(
                        "array-element disclosure matched a redacted map claim",
                    ));
                }
            },
            None if mode == RestoreMode::Verifier => {
                stats.removed_redactions += 1;
                if pending.validate_claims {
                    undisclosed_hashes.push(Value::Bytes(hash));
                }
            }
            None => {
                return Err(Error::verify(
                    "holder validation found redacted map claim without disclosure",
                ));
            }
        }
    }

    if !undisclosed_hashes.is_empty() {
        output.push((
            redacted_claim_keys_label(),
            Value::Array(undisclosed_hashes),
        ));
    }

    Ok(Value::Map(output))
}

fn restore_array(
    items: Vec<Value>,
    pending: &mut DisclosureMap,
    mode: RestoreMode,
    stats: &mut RestoreStats,
    budget: &mut TraversalBudget,
    depth: usize,
) -> Result<Value, Error> {
    budget.container(items.len())?;
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Tag(tag, inner) if tag == REDACTED_ELEMENT_TAG => {
                budget.enter(depth + 1)?;
                budget.enter(depth + 2)?;
                let hash = expect_bytes(&inner, "redacted array element hash")?.to_vec();
                match pending.remove(&hash) {
                    Some(disclosure) => match disclosure.kind {
                        DisclosureKind::Element { value, .. } => {
                            output.push(restore_value(
                                value,
                                pending,
                                mode,
                                stats,
                                budget,
                                depth + 1,
                            )?);
                            stats.disclosed += 1;
                        }
                        DisclosureKind::Decoy { .. } => {
                            stats.decoys += 1;
                        }
                        DisclosureKind::Claim { .. } => {
                            return Err(Error::verify(
                                "map-claim disclosure matched a redacted array element",
                            ));
                        }
                    },
                    None if mode == RestoreMode::Verifier => {
                        stats.removed_redactions += 1;
                        if pending.validate_claims {
                            output.push(redacted_element(hash));
                        }
                    }
                    None => {
                        return Err(Error::verify(
                            "holder validation found redacted array element without disclosure",
                        ));
                    }
                }
            }
            other => output.push(restore_value(
                other,
                pending,
                mode,
                stats,
                budget,
                depth + 1,
            )?),
        }
    }
    Ok(Value::Array(output))
}

fn kind_to_value(kind: &DisclosureKind) -> Value {
    match kind {
        DisclosureKind::Claim { salt, key, value } => Value::Array(vec![
            Value::Bytes(salt.clone()),
            value.clone(),
            Value::from(key.clone()),
        ]),
        DisclosureKind::Element { salt, value } => {
            Value::Array(vec![Value::Bytes(salt.clone()), value.clone()])
        }
        DisclosureKind::Decoy { salt } => Value::Array(vec![Value::Bytes(salt.clone())]),
    }
}

fn decode_disclosure_value(value: Value) -> Result<DisclosureKind, Error> {
    let Value::Array(mut items) = value else {
        return Err(Error::UnexpectedType(
            "Salted Disclosed Claim must be an array".into(),
        ));
    };

    match items.len() {
        1 => {
            let salt = expect_owned_bytes(items.remove(0), "disclosure salt must be bytes")?;
            Ok(DisclosureKind::Decoy { salt })
        }
        2 => {
            let value = items.pop().expect("len checked");
            let salt = expect_owned_bytes(items.remove(0), "disclosure salt must be bytes")?;
            Ok(DisclosureKind::Element { salt, value })
        }
        3 => {
            let key_value = items.pop().expect("len checked");
            let value = items.pop().expect("len checked");
            let salt = expect_owned_bytes(items.remove(0), "disclosure salt must be bytes")?;
            let key = label_from_value(&key_value)?;
            Ok(DisclosureKind::Claim { salt, key, value })
        }
        _ => Err(Error::UnexpectedType(
            "Salted Disclosed Claim must have 1, 2, or 3 elements".into(),
        )),
    }
}

fn validate_disclosure_kind(kind: &DisclosureKind) -> Result<(), Error> {
    let salt = match kind {
        DisclosureKind::Claim { salt, .. }
        | DisclosureKind::Element { salt, .. }
        | DisclosureKind::Decoy { salt } => salt,
    };
    if salt.len() != 16 {
        return Err(Error::UnexpectedType(
            "Salted Disclosed Claim salt must be 16 bytes".into(),
        ));
    }
    if let DisclosureKind::Claim { key, .. } = kind {
        validate_text_label(key)?;
    }
    Ok(())
}

fn label_from_value(value: &Value) -> Result<Label, Error> {
    match value {
        Value::Integer(value) => i64::try_from(*value)
            .map(Label::Int)
            .map_err(|_| Error::UnexpectedType("claim key integer out of range".into())),
        Value::Text(value) if (1..=255).contains(&value.len()) => Ok(Label::Text(value.clone())),
        Value::Text(_) => Err(Error::UnexpectedType(
            "SD-CWT text claim keys must contain 1 to 255 octets".into(),
        )),
        _ => Err(Error::UnexpectedType(
            "disclosed claim key must be an integer or text string".into(),
        )),
    }
}

fn expect_bytes<'a>(value: &'a Value, name: &str) -> Result<&'a [u8], Error> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(Error::UnexpectedType(format!("{name} must be bytes"))),
    }
}

fn expect_owned_bytes(value: Value, name: &str) -> Result<Vec<u8>, Error> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(Error::UnexpectedType(name.into())),
    }
}

fn value_item_count(value: &Value) -> Result<usize, Error> {
    let mut count = 0usize;
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        count = count
            .checked_add(1)
            .ok_or_else(|| Error::custom("SD-CWT item count overflow"))?;
        match value {
            Value::Array(items) => pending.extend(items),
            Value::Map(entries) => {
                for (key, value) in entries {
                    pending.push(key);
                    pending.push(value);
                }
            }
            Value::Tag(_, value) => pending.push(value),
            _ => {}
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cose2::Sign1Message;

    fn salt(byte: u8) -> Vec<u8> {
        vec![byte; 16]
    }

    fn hash(disclosure: &Disclosure) -> Vec<u8> {
        disclosure.redacted_hash(&Sha256RedactionHasher)
    }

    fn salt_source() -> impl FnMut() -> [u8; 16] {
        let mut next = 1u8;
        move || {
            let salt = [next; 16];
            next += 1;
            salt
        }
    }

    #[test]
    fn simple_label_and_tagged_array_element_have_expected_wire_shape() {
        assert_eq!(
            cbor2::to_vec(&redacted_claim_keys_label()).unwrap(),
            vec![0xf8, 0x3b]
        );

        let tagged = redacted_element(vec![0xab; 32]);
        let encoded = cbor2::to_vec(&tagged).unwrap();
        assert_eq!(encoded[0], 0xd8);
        assert_eq!(encoded[1], REDACTED_ELEMENT_TAG as u8);
        assert_eq!(encoded[2], 0x58);
        assert_eq!(encoded[3], 32);
    }

    #[test]
    fn disclosure_round_trips_and_hashes_encoded_bytes() {
        let disclosure = Disclosure::claim(salt(1), 2, "Alice").unwrap();
        let encoded = disclosure.encoded().to_vec();

        let decoded = Disclosure::from_encoded(encoded.clone()).unwrap();
        assert_eq!(decoded.kind(), disclosure.kind());
        assert_eq!(decoded.encoded(), encoded.as_slice());
        assert_eq!(
            decoded.redacted_hash(&Sha256RedactionHasher),
            hash(&disclosure)
        );

        match decoded.kind() {
            DisclosureKind::Claim { salt, key, value } => {
                assert_eq!(salt, &vec![1; 16]);
                assert_eq!(key, &Label::Int(2));
                assert_eq!(value, &Value::Text("Alice".into()));
            }
            _ => panic!("expected claim disclosure"),
        }
    }

    #[test]
    fn sd_claims_header_helpers_omit_empty_and_decode_entries() {
        let disclosure = Disclosure::element(salt(2), 42).unwrap();
        let mut header = Header::new();

        set_disclosures(&mut header, &[]);
        assert!(!header.contains_key(HEADER_SD_CLAIMS));

        set_disclosures(&mut header, std::slice::from_ref(&disclosure));
        let decoded = disclosures_from_unprotected(&header).unwrap();
        assert_eq!(decoded, vec![disclosure]);

        DisclosureSet::new().write_unprotected(&mut header);
        assert!(!header.contains_key(HEADER_SD_CLAIMS));
    }

    #[test]
    fn restores_redacted_map_claim_for_holder() {
        let disclosure = Disclosure::claim(salt(3), 2, "holder").unwrap();
        let payload = Value::Map(vec![
            (Value::from(1), Value::from("issuer")),
            (
                redacted_claim_keys_label(),
                Value::Array(vec![Value::Bytes(hash(&disclosure))]),
            ),
        ]);

        let report = restore_for_holder(payload, vec![disclosure], &Sha256RedactionHasher).unwrap();

        assert_eq!(report.disclosed, 1);
        assert_eq!(
            report.value,
            Value::Map(vec![
                (Value::from(1), Value::from("issuer")),
                (Value::from(2), Value::from("holder")),
            ])
        );
    }

    #[test]
    fn verifier_removes_undisclosed_map_claims_and_array_elements() {
        let disclosed = Disclosure::element(salt(4), "visible").unwrap();
        let payload = Value::Map(vec![
            (
                redacted_claim_keys_label(),
                Value::Array(vec![Value::Bytes(vec![0xaa; 32])]),
            ),
            (
                Value::from("items"),
                Value::Array(vec![
                    redacted_element(hash(&disclosed)),
                    redacted_element(vec![0xbb; 32]),
                    Value::from("plain"),
                ]),
            ),
        ]);

        let report =
            restore_for_verifier(payload, vec![disclosed], &Sha256RedactionHasher).unwrap();
        assert_eq!(report.disclosed, 1);
        assert_eq!(report.removed_redactions, 2);
        assert_eq!(
            report.value,
            Value::Map(vec![(
                Value::from("items"),
                Value::Array(vec![Value::from("visible"), Value::from("plain")]),
            )])
        );
    }

    #[test]
    fn holder_rejects_undisclosed_redaction() {
        let payload = Value::Map(vec![(
            redacted_claim_keys_label(),
            Value::Array(vec![Value::Bytes(vec![0xaa; 32])]),
        )]);

        assert!(restore_for_holder(payload, Vec::new(), &Sha256RedactionHasher).is_err());
    }

    #[test]
    fn nested_disclosures_are_matched_in_any_order() {
        let child = Disclosure::claim(salt(5), "country", "FR").unwrap();
        let parent_value = Value::Map(vec![(
            redacted_claim_keys_label(),
            Value::Array(vec![Value::Bytes(hash(&child))]),
        )]);
        let parent = Disclosure::claim(salt(6), "address", parent_value).unwrap();
        let payload = Value::Map(vec![(
            redacted_claim_keys_label(),
            Value::Array(vec![Value::Bytes(hash(&parent))]),
        )]);

        let report =
            restore_for_holder(payload, vec![child, parent], &Sha256RedactionHasher).unwrap();

        assert_eq!(report.disclosed, 2);
        assert_eq!(
            report.value,
            Value::Map(vec![(
                Value::from("address"),
                Value::Map(vec![(Value::from("country"), Value::from("FR"))]),
            )])
        );
    }

    #[test]
    fn extraneous_disclosure_is_rejected_in_both_modes() {
        // A disclosure whose digest matches no redacted digest in the signed
        // payload must fail: otherwise a holder or MITM could inject
        // unrelated claims into a presentation.
        let matched = Disclosure::claim(salt(20), 2, "ok").unwrap();
        let extraneous = Disclosure::claim(salt(21), "email", "eve@example.com").unwrap();
        let payload = Value::Map(vec![(
            redacted_claim_keys_label(),
            Value::Array(vec![Value::Bytes(hash(&matched))]),
        )]);

        for mode in [RestoreMode::Holder, RestoreMode::Verifier] {
            let err = restore(
                payload.clone(),
                vec![matched.clone(), extraneous.clone()],
                &Sha256RedactionHasher,
                mode,
            )
            .unwrap_err();
            assert!(format!("{err}").contains("without a matching redacted claim"));
        }
    }

    #[test]
    fn duplicate_disclosure_digests_are_rejected() {
        let disclosure = Disclosure::claim(salt(22), 2, "dup").unwrap();
        let payload = Value::Map(vec![(
            redacted_claim_keys_label(),
            Value::Array(vec![Value::Bytes(hash(&disclosure))]),
        )]);

        let err = restore_for_verifier(
            payload,
            vec![disclosure.clone(), disclosure],
            &Sha256RedactionHasher,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("duplicate SD-CWT disclosure digest"));
    }

    #[test]
    fn holder_rejects_undisclosed_array_element_redaction() {
        let payload = Value::Array(vec![redacted_element(vec![0xcc; 32]), Value::from("kept")]);
        let err = restore_for_holder(payload, Vec::new(), &Sha256RedactionHasher).unwrap_err();
        assert!(format!("{err}").contains("redacted array element without disclosure"));
    }

    #[test]
    fn duplicate_disclosed_key_is_invalid() {
        let disclosure = Disclosure::claim(salt(7), 1, "redacted").unwrap();
        let payload = Value::Map(vec![
            (Value::from(1), Value::from("plain")),
            (
                redacted_claim_keys_label(),
                Value::Array(vec![Value::Bytes(hash(&disclosure))]),
            ),
        ]);

        assert!(restore_for_verifier(payload, vec![disclosure], &Sha256RedactionHasher).is_err());
    }

    #[test]
    fn decoys_are_removed_when_their_digest_is_present() {
        let decoy = Disclosure::decoy(salt(8)).unwrap();
        let payload = Value::Array(vec![redacted_element(hash(&decoy)), Value::from("kept")]);

        let report = restore_for_verifier(payload, vec![decoy], &Sha256RedactionHasher).unwrap();
        assert_eq!(report.decoys, 1);
        assert_eq!(report.value, Value::Array(vec![Value::from("kept")]));
    }

    #[test]
    fn aead_encrypted_disclosures_header_round_trips() {
        let encrypted = AeadEncryptedDisclosure {
            nonce: vec![1, 2, 3],
            ciphertext: vec![4, 5],
            tag: vec![6; 16],
            key_context: Some(AeadKeyContext::Text("key-a".into())),
        };
        let mut header = Header::new();
        set_aead_encrypted_disclosures(&mut header, std::slice::from_ref(&encrypted));

        assert_eq!(
            aead_encrypted_disclosures_from_unprotected(&header).unwrap(),
            vec![encrypted]
        );
    }

    #[test]
    fn issue_from_preissuance_redacts_map_keys_and_array_elements() {
        let preissued = Value::Map(vec![
            (Value::from(1), Value::from("issuer")),
            (
                Value::Tag(TO_BE_REDACTED_TAG, Box::new(Value::from("name"))),
                Value::from("Alice"),
            ),
            (
                Value::from("countries"),
                Value::Array(vec![
                    Value::Tag(TO_BE_REDACTED_TAG, Box::new(Value::from("de"))),
                    Value::from("fr"),
                ]),
            ),
        ]);
        let mut salts = salt_source();

        let issued = issue_from_preissuance(preissued, &mut salts, &Sha256RedactionHasher).unwrap();

        assert_eq!(issued.disclosures.len(), 2);
        let restored =
            restore_for_holder(issued.value, issued.disclosures, &Sha256RedactionHasher).unwrap();
        assert_eq!(
            restored.value,
            Value::Map(vec![
                (Value::from(1), Value::from("issuer")),
                (
                    Value::from("countries"),
                    Value::Array(vec![Value::from("de"), Value::from("fr")]),
                ),
                (Value::from("name"), Value::from("Alice")),
            ])
        );
    }

    #[test]
    fn issue_from_preissuance_inserts_and_restores_decoys() {
        let preissued = Value::Map(vec![
            (
                Value::Tag(TO_BE_DECOY_TAG, Box::new(Value::from(1))),
                Value::Null,
            ),
            (
                Value::from("items"),
                Value::Array(vec![Value::Tag(TO_BE_DECOY_TAG, Box::new(Value::from(2)))]),
            ),
        ]);
        let mut salts = salt_source();

        let issued = issue_from_preissuance(preissued, &mut salts, &Sha256RedactionHasher).unwrap();

        assert_eq!(issued.disclosures.len(), 2);
        let restored =
            restore_for_verifier(issued.value, issued.disclosures, &Sha256RedactionHasher).unwrap();
        assert_eq!(restored.decoys, 2);
        assert_eq!(
            restored.value,
            Value::Map(vec![(Value::from("items"), Value::Array(vec![]))])
        );
    }

    #[test]
    fn issue_from_preissuance_rejects_duplicate_normalized_keys_and_decoy_ids() {
        let duplicate_key = Value::Map(vec![
            (Value::from("name"), Value::from("plain")),
            (
                Value::Tag(TO_BE_REDACTED_TAG, Box::new(Value::from("name"))),
                Value::from("redacted"),
            ),
        ]);
        let duplicate_decoy = Value::Array(vec![
            Value::Tag(TO_BE_DECOY_TAG, Box::new(Value::from(1))),
            Value::Tag(TO_BE_DECOY_TAG, Box::new(Value::from(1))),
        ]);
        let mut salts = salt_source();
        assert!(issue_from_preissuance(duplicate_key, &mut salts, &Sha256RedactionHasher).is_err());

        let mut salts = salt_source();
        assert!(
            issue_from_preissuance(duplicate_decoy, &mut salts, &Sha256RedactionHasher).is_err()
        );
    }

    #[test]
    fn restore_payload_from_message_uses_headers() {
        let disclosure = Disclosure::claim(salt(9), "name", "Alice").unwrap();
        let payload = Value::Map(vec![(
            redacted_claim_keys_label(),
            Value::Array(vec![Value::Bytes(hash(&disclosure))]),
        )]);
        let mut message = Sign1Message::new(Some(cbor2::to_vec(&payload).unwrap()));
        set_disclosures(&mut message.unprotected, std::slice::from_ref(&disclosure));

        let report = restore_payload_from_message(&message, RestoreMode::Holder).unwrap();
        assert_eq!(
            report.value,
            Value::Map(vec![(Value::from("name"), Value::from("Alice"),)])
        );
    }
}
