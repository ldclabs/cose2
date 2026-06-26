//! Selective Disclosure CBOR Web Token helpers.
//!
//! This crate implements the SD-CWT disclosure and redaction mechanics from
//! `draft-ietf-spice-sd-cwt-08` on top of [`cose2`]. It deliberately reuses
//! `cose2` for COSE signing, verification and header storage; the APIs here
//! cover SD-CWT-specific header parameters, salted disclosures, redacted claim
//! markers, AEAD-encrypted disclosure wire structures, and restoration of a
//! presented claims set.

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
    fn algorithm(&self) -> Label;

    /// Computes the digest of one bstr-encoded Salted Disclosed Claim.
    fn digest(&self, data: &[u8]) -> Vec<u8>;
}

/// SHA-256 redaction hasher, the SD-CWT default when `sd_alg` is omitted.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256RedactionHasher;

impl RedactionHasher for Sha256RedactionHasher {
    fn algorithm(&self) -> Label {
        Label::Int(ALG_SHA_256)
    }

    fn digest(&self, data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }
}

/// Returns the built-in SHA-256 hasher for `sd_alg = -16` or an omitted `sd_alg`.
pub fn default_hasher_for_sd_alg(alg: Option<Label>) -> Result<Sha256RedactionHasher, Error> {
    match alg {
        None | Some(Label::Int(ALG_SHA_256)) => Ok(Sha256RedactionHasher),
        Some(other) => Err(Error::custom(format!(
            "unsupported SD-CWT hash algorithm {other}"
        ))),
    }
}

/// Reads the `sd_alg` protected header parameter.
pub fn sd_alg(protected: &Header) -> Result<Option<Label>, Error> {
    protected.get_label(HEADER_SD_ALG)
}

/// Sets the `sd_alg` protected header parameter.
pub fn set_sd_alg(protected: &mut Header, alg: impl Into<Label>) -> &mut Header {
    protected.insert(HEADER_SD_ALG, Value::from(alg.into()));
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
        let encoded = encoded.into();
        let value: Value = cbor2::from_slice(&encoded)?;
        let kind = decode_disclosure_value(value)?;
        validate_disclosure_kind(&kind)?;
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
        match &self.kind {
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

    fn from_kind(kind: DisclosureKind) -> Result<Self, Error> {
        validate_disclosure_kind(&kind)?;
        let encoded = cbor2::to_canonical_vec(&kind_to_value(&kind))?;
        Ok(Self { kind, encoded })
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
    let Some(value) = header.get(HEADER_SD_CLAIMS) else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = value else {
        return Err(Error::UnexpectedType("sd_claims must be an array".into()));
    };

    let mut disclosures = Vec::with_capacity(items.len());
    for item in items {
        let Value::Bytes(encoded) = item else {
            return Err(Error::UnexpectedType(
                "sd_claims entries must be byte strings".into(),
            ));
        };
        disclosures.push(Disclosure::from_encoded(encoded.clone())?);
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
    let Some(value) = header.get(HEADER_SD_AEAD_ENCRYPTED_CLAIMS) else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = value else {
        return Err(Error::UnexpectedType(
            "sd_aead_encrypted_claims must be an array".into(),
        ));
    };
    items
        .iter()
        .map(AeadEncryptedDisclosure::from_value)
        .collect()
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
    let mut context = IssueContext {
        salts,
        hasher,
        decoy_ids: HashSet::new(),
        disclosures: Vec::new(),
    };
    let value = issue_value(value, &mut context)?;
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
    /// The restored claims value.
    pub value: Value,
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
    let mut pending = DisclosureMap::new(disclosures, hasher)?;
    let mut stats = RestoreStats::default();
    let value = restore_value(value, &mut pending, mode, &mut stats)?;
    if !pending.is_empty() {
        return Err(Error::verify(
            "sd_claims contains a disclosure without a matching redacted claim",
        ));
    }
    Ok(RestoreReport {
        value,
        disclosed: stats.disclosed,
        decoys: stats.decoys,
        removed_redactions: stats.removed_redactions,
    })
}

/// Decodes a COSE payload as CBOR and restores it using disclosures in the message header.
///
/// This helper supports the SD-CWT default hash algorithm, SHA-256. Use
/// [`restore_payload_with_disclosures`] when a profile uses another hash.
pub fn restore_payload_from_message(
    message: &cose2::Sign1Message,
    mode: RestoreMode,
) -> Result<RestoreReport, Error> {
    let hasher = default_hasher_for_sd_alg(sd_alg(&message.protected)?)?;
    let disclosures = disclosures_from_unprotected(&message.unprotected)?;
    restore_payload_with_disclosures(message, disclosures, &hasher, mode)
}

/// Decodes a COSE payload as CBOR and restores it with caller-supplied disclosures.
pub fn restore_payload_with_disclosures<I>(
    message: &cose2::Sign1Message,
    disclosures: I,
    hasher: &dyn RedactionHasher,
    mode: RestoreMode,
) -> Result<RestoreReport, Error>
where
    I: IntoIterator<Item = Disclosure>,
{
    let payload = message
        .payload
        .as_deref()
        .ok_or_else(|| Error::custom("SD-CWT message must carry an embedded payload"))?;
    let value: Value = cbor2::from_slice(payload)?;
    restore(value, disclosures, hasher, mode)
}

struct DisclosureMap {
    entries: HashMap<Vec<u8>, Disclosure>,
}

impl DisclosureMap {
    fn new<I>(disclosures: I, hasher: &dyn RedactionHasher) -> Result<Self, Error>
    where
        I: IntoIterator<Item = Disclosure>,
    {
        let mut entries = HashMap::new();
        for disclosure in disclosures {
            let hash = disclosure.redacted_hash(hasher);
            if entries.insert(hash, disclosure).is_some() {
                return Err(Error::verify("duplicate SD-CWT disclosure digest"));
            }
        }
        Ok(Self { entries })
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
    disclosures: Vec<Disclosure>,
}

fn issue_value(value: Value, context: &mut IssueContext<'_>) -> Result<Value, Error> {
    match value {
        Value::Map(entries) => issue_map(entries, context),
        Value::Array(items) => issue_array(items, context),
        Value::Tag(tag, inner) if tag == TO_BE_REDACTED_TAG => {
            let issued = issue_value(*inner, context)?;
            let disclosure = Disclosure::element(context.salts.next_salt()?, issued)?;
            let hash = disclosure.redacted_hash(context.hasher);
            context.disclosures.push(disclosure);
            Ok(redacted_element(hash))
        }
        Value::Tag(tag, inner) if tag == TO_BE_DECOY_TAG => {
            record_decoy_id(&inner, context)?;
            let disclosure = Disclosure::decoy(context.salts.next_salt()?)?;
            let hash = disclosure.redacted_hash(context.hasher);
            context.disclosures.push(disclosure);
            Ok(redacted_element(hash))
        }
        Value::Tag(tag, _) if tag == REDACTED_ELEMENT_TAG => Err(Error::custom(
            "pre-issuance value must not already contain redacted element tag 60",
        )),
        Value::Tag(tag, inner) => Ok(Value::Tag(tag, Box::new(issue_value(*inner, context)?))),
        Value::Simple(simple) if simple.value() == REDACTED_CLAIM_KEYS_SIMPLE => Err(
            Error::custom("pre-issuance value must not contain simple(59) redaction labels"),
        ),
        other => Ok(other),
    }
}

fn issue_map(entries: Vec<(Value, Value)>, context: &mut IssueContext<'_>) -> Result<Value, Error> {
    let mut output = Vec::with_capacity(entries.len());
    let mut normalized_keys = Vec::<Value>::new();
    let mut redacted_hashes = Vec::<Value>::new();

    for (key, value) in entries {
        match key {
            Value::Tag(tag, inner) if tag == TO_BE_REDACTED_TAG => {
                let claim_key = label_from_value(&inner)?;
                let normalized_key = Value::from(claim_key.clone());
                reject_duplicate_raw_key(&normalized_keys, &normalized_key)?;
                normalized_keys.push(normalized_key);

                let issued_value = issue_value(value, context)?;
                let disclosure =
                    Disclosure::claim(context.salts.next_salt()?, claim_key, issued_value)?;
                redacted_hashes.push(Value::Bytes(disclosure.redacted_hash(context.hasher)));
                context.disclosures.push(disclosure);
            }
            Value::Tag(tag, inner) if tag == TO_BE_DECOY_TAG => {
                record_decoy_id(&inner, context)?;
                if !matches!(value, Value::Null) {
                    return Err(Error::custom(
                        "map decoy tag 62 entries must have a null value",
                    ));
                }
                let disclosure = Disclosure::decoy(context.salts.next_salt()?)?;
                redacted_hashes.push(Value::Bytes(disclosure.redacted_hash(context.hasher)));
                context.disclosures.push(disclosure);
            }
            key if is_redacted_claim_keys_label(&key) => {
                return Err(Error::custom(
                    "pre-issuance map must not already contain simple(59)",
                ));
            }
            key => {
                ensure_preissuance_key(&key)?;
                reject_duplicate_raw_key(&normalized_keys, &key)?;
                normalized_keys.push(key.clone());
                output.push((key, issue_value(value, context)?));
            }
        }
    }

    if !redacted_hashes.is_empty() {
        output.push((redacted_claim_keys_label(), Value::Array(redacted_hashes)));
    }

    Ok(Value::Map(output))
}

fn issue_array(items: Vec<Value>, context: &mut IssueContext<'_>) -> Result<Value, Error> {
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Tag(tag, inner) if tag == TO_BE_REDACTED_TAG => {
                let issued = issue_value(*inner, context)?;
                let disclosure = Disclosure::element(context.salts.next_salt()?, issued)?;
                let hash = disclosure.redacted_hash(context.hasher);
                output.push(redacted_element(hash));
                context.disclosures.push(disclosure);
            }
            Value::Tag(tag, inner) if tag == TO_BE_DECOY_TAG => {
                record_decoy_id(&inner, context)?;
                let disclosure = Disclosure::decoy(context.salts.next_salt()?)?;
                let hash = disclosure.redacted_hash(context.hasher);
                output.push(redacted_element(hash));
                context.disclosures.push(disclosure);
            }
            item => output.push(issue_value(item, context)?),
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
    match key {
        Value::Integer(_) | Value::Text(_) => Ok(()),
        _ => Err(Error::UnexpectedType(
            "pre-issuance map keys must be int, text, tag 58, or tag 62".into(),
        )),
    }
}

fn reject_duplicate_raw_key(keys: &[Value], key: &Value) -> Result<(), Error> {
    if keys.iter().any(|existing| existing == key) {
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
) -> Result<Value, Error> {
    match value {
        Value::Map(entries) => restore_map(entries, pending, mode, stats),
        Value::Array(items) => restore_array(items, pending, mode, stats),
        Value::Tag(tag, inner) if tag == REDACTED_ELEMENT_TAG => {
            let hash = expect_bytes(&inner, "redacted array element hash")?;
            match pending.remove(hash) {
                Some(disclosure) => restore_element_disclosure(disclosure, pending, mode, stats),
                None if mode == RestoreMode::Verifier => {
                    stats.removed_redactions += 1;
                    Ok(Value::Null)
                }
                None => Err(Error::verify(
                    "holder validation found redacted array element without disclosure",
                )),
            }
        }
        Value::Tag(tag, inner) => Ok(Value::Tag(
            tag,
            Box::new(restore_value(*inner, pending, mode, stats)?),
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
) -> Result<Value, Error> {
    let mut output = Vec::with_capacity(entries.len());
    let mut redacted_hashes = Vec::new();
    let mut saw_redacted_keys = false;

    for (key, value) in entries {
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
            for hash in hashes {
                redacted_hashes.push(expect_owned_bytes(
                    hash,
                    "redacted_claim_keys entries must be byte strings",
                )?);
            }
            continue;
        }

        reject_duplicate_key(&output, &key)?;
        let value = restore_value(value, pending, mode, stats)?;
        output.push((key, value));
    }

    for hash in redacted_hashes {
        match pending.remove(&hash) {
            Some(disclosure) => match disclosure.kind {
                DisclosureKind::Claim { key, value, .. } => {
                    let key = Value::from(key);
                    reject_duplicate_key(&output, &key)?;
                    let value = restore_value(value, pending, mode, stats)?;
                    output.push((key, value));
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
            }
            None => {
                return Err(Error::verify(
                    "holder validation found redacted map claim without disclosure",
                ));
            }
        }
    }

    Ok(Value::Map(output))
}

fn restore_array(
    items: Vec<Value>,
    pending: &mut DisclosureMap,
    mode: RestoreMode,
    stats: &mut RestoreStats,
) -> Result<Value, Error> {
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Tag(tag, inner) if tag == REDACTED_ELEMENT_TAG => {
                let hash = expect_bytes(&inner, "redacted array element hash")?.to_vec();
                match pending.remove(&hash) {
                    Some(disclosure) => match disclosure.kind {
                        DisclosureKind::Element { value, .. } => {
                            output.push(restore_value(value, pending, mode, stats)?);
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
                    }
                    None => {
                        return Err(Error::verify(
                            "holder validation found redacted array element without disclosure",
                        ));
                    }
                }
            }
            other => output.push(restore_value(other, pending, mode, stats)?),
        }
    }
    Ok(Value::Array(output))
}

fn restore_element_disclosure(
    disclosure: Disclosure,
    pending: &mut DisclosureMap,
    mode: RestoreMode,
    stats: &mut RestoreStats,
) -> Result<Value, Error> {
    match disclosure.kind {
        DisclosureKind::Element { value, .. } => {
            stats.disclosed += 1;
            restore_value(value, pending, mode, stats)
        }
        DisclosureKind::Decoy { .. } => {
            stats.decoys += 1;
            Ok(Value::Null)
        }
        DisclosureKind::Claim { .. } => Err(Error::verify(
            "map-claim disclosure matched a redacted array element",
        )),
    }
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
    Ok(())
}

fn label_from_value(value: &Value) -> Result<Label, Error> {
    match value {
        Value::Integer(value) => i64::try_from(*value)
            .map(Label::Int)
            .map_err(|_| Error::UnexpectedType("claim key integer out of range".into())),
        Value::Text(value) => Ok(Label::Text(value.clone())),
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

fn reject_duplicate_key(entries: &[(Value, Value)], key: &Value) -> Result<(), Error> {
    if entries.iter().any(|(existing, _)| existing == key) {
        return Err(Error::verify(format!("duplicate claim key {key}")));
    }
    Ok(())
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
