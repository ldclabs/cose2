//! Disclosure matching, bounded restoration and removal of undisclosed claims.

use crate::validation::{
    claim_maps, ensure_message_protected_state, protected_cwt_claims,
    remove_undisclosed_redactions, validate_matching_claims, validate_root_disclosure_key,
};
use crate::{
    default_hasher_for_sd_alg, disclosures_from_unprotected, expect_bytes, expect_owned_bytes,
    is_redacted_claim_keys_label, label_from_value, redacted_claim_keys_label, redacted_element,
    sd_alg, Disclosure, DisclosureKind, ProcessingLimits, RedactionHasher, TraversalBudget,
    REDACTED_CLAIM_KEYS_SIMPLE, REDACTED_ELEMENT_TAG, TO_BE_DECOY_TAG, TO_BE_REDACTED_TAG,
};
use cbor2::Value;
use cose2::{Error, Label};
use std::collections::{HashMap, HashSet};

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

pub(super) fn restore_with_protected_claims<I>(
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
