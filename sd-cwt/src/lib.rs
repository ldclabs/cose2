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

use std::collections::HashSet;

use cbor2::{Simple, Value};
use cose2::{Error, Header, Label};

mod disclosure;
mod issuance;
mod restore;
mod validation;

pub use disclosure::{
    default_hasher_for_sd_alg, disclosures_from_unprotected,
    disclosures_from_unprotected_with_limits, set_disclosures, Disclosure, DisclosureKind,
    DisclosureSet, RedactionHasher, Sha256RedactionHasher,
};
pub use issuance::{
    issue_from_preissuance, issue_from_preissuance_with_limits, IssueResult, SaltGenerator,
};
pub use restore::{
    restore, restore_for_holder, restore_for_verifier, restore_payload_from_message,
    restore_payload_with_disclosures, restore_payload_with_disclosures_and_limits,
    restore_with_limits, RestoreMode, RestoreReport,
};
pub use validation::{
    verify_and_decode_sd_cwt, verify_validate_and_restore_sd_cwt, SdCwtValidationOptions,
    SdCwtValidator,
};

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
        .any(|disclosure| !nonces.insert(disclosure.nonce.as_slice()))
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
mod tests;
