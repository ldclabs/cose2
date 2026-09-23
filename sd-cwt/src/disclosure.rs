//! Salted disclosures, redaction hashing and plaintext disclosure headers.

use crate::validation::{definite_cbor_limits, validate_disclosure_value, validate_text_label};
use crate::{
    expect_owned_bytes, label_from_value, value_item_count, ProcessingLimits, ALG_SHA_256,
    HEADER_SD_CLAIMS,
};
use cbor2::Value;
use cose2::{Error, Header, Label};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

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
    pub(super) kind: DisclosureKind,
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
        cose2::validate_cbor(&encoded, definite_cbor_limits(limits))?;
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
        encode_kind(&self.kind)
    }

    /// Converts this disclosure to its decoded CBOR value.
    pub fn to_value(&self) -> Value {
        kind_to_value(&self.kind)
    }

    fn from_kind(kind: DisclosureKind) -> Result<Self, Error> {
        Self::from_kind_with_limits(kind, ProcessingLimits::default())
    }

    /// Validates and canonically encodes a new disclosure under `limits`.
    pub(super) fn from_kind_with_limits(
        kind: DisclosureKind,
        limits: ProcessingLimits,
    ) -> Result<Self, Error> {
        validate_disclosure_kind(&kind)?;
        validate_disclosure_value(&kind, limits)?;
        let encoded = encode_kind(&kind)?;
        Ok(Self { kind, encoded })
    }

    /// Returns the salt, which construction and decoding validate as 16 bytes.
    pub(super) fn salt(&self) -> [u8; 16] {
        let (DisclosureKind::Claim { salt, .. }
        | DisclosureKind::Element { salt, .. }
        | DisclosureKind::Decoy { salt }) = &self.kind;
        salt.as_slice()
            .try_into()
            .expect("disclosure salts are validated to 16 bytes")
    }

    pub(super) fn item_count(&self) -> Result<usize, Error> {
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
    let mut salts = HashSet::<[u8; 16]>::with_capacity(items.len());
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
        if !salts.insert(disclosure.salt()) {
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

/// Encodes a disclosure array canonically without first cloning its value.
fn encode_kind(kind: &DisclosureKind) -> Result<Vec<u8>, Error> {
    let encoded = match kind {
        DisclosureKind::Claim { salt, key, value } => {
            cbor2::to_canonical_vec(&(Value::Bytes(salt.clone()), value, key))
        }
        DisclosureKind::Element { salt, value } => {
            cbor2::to_canonical_vec(&(Value::Bytes(salt.clone()), value))
        }
        DisclosureKind::Decoy { salt } => cbor2::to_canonical_vec(&[Value::Bytes(salt.clone())]),
    };
    Ok(encoded?)
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
