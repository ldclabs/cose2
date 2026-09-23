//! Conversion of pre-issuance redaction and decoy requests.

use crate::{
    is_redacted_claim_keys_label, label_from_value, redacted_claim_keys_label, redacted_element,
    Disclosure, DisclosureSet, ProcessingLimits, RedactionHasher, TraversalBudget,
    REDACTED_CLAIM_KEYS_SIMPLE, REDACTED_ELEMENT_TAG, TO_BE_DECOY_TAG, TO_BE_REDACTED_TAG,
};
use cbor2::Value;
use cose2::Error;
use std::collections::HashSet;

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
