//! SD-CWT envelope and claims policy, including the combined verification API.

use crate::restore::restore_with_protected_claims;
use crate::{
    aead_encrypted_disclosures_from_unprotected_with_limits, default_hasher_for_sd_alg,
    disclosures_from_unprotected_with_limits, expect_bytes, is_redacted_claim_keys_label,
    label_from_value, sd_aead, sd_alg, AeadEncryptedDisclosure, DisclosureKind, ProcessingLimits,
    RestoreMode, RestoreReport, TraversalBudget, CONTENT_FORMAT_SD_CWT, CWT_CLAIM_CNONCE,
    CWT_CLAIM_VCT, HEADER_CWT_CLAIMS, HEADER_SD_AEAD, HEADER_SD_AEAD_ENCRYPTED_CLAIMS,
    HEADER_SD_ALG, HEADER_SD_CLAIMS, HEADER_TYP, REDACTED_CLAIM_KEYS_SIMPLE, REDACTED_ELEMENT_TAG,
    TO_BE_DECOY_TAG, TO_BE_REDACTED_TAG,
};
use cbor2::Value;
use cose2::{cwt::NumericDate, Error, Label};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

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
    let message = cose2::Sign1Message::from_slice_with_limits(data, definite_cbor_limits(limits))?;
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
        message.validate_headers()?;
        validate_sd_headers(message, self.options.limits)?;
        self.restore_validated_headers(message, mode)
    }

    /// Validates claims and disclosures of a message whose SD-CWT headers
    /// were already validated.
    fn restore_validated_headers(
        &self,
        message: &cose2::Sign1Message,
        mode: RestoreMode,
    ) -> Result<RestoreReport, Error> {
        let protected_claims = protected_cwt_claims(message)?;
        let disclosures =
            disclosures_from_unprotected_with_limits(&message.unprotected, self.options.limits)?;
        // The plaintext reader has already bounded both totals.
        let mut encrypted_limits = self.options.limits;
        encrypted_limits.max_disclosures -= disclosures.len();
        for disclosure in &disclosures {
            encrypted_limits.max_disclosure_bytes -= disclosure.encoded().len();
        }
        let encrypted = aead_encrypted_disclosures_from_unprotected_with_limits(
            &message.unprotected,
            encrypted_limits,
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
        cose2::validate_cbor(payload, definite_cbor_limits(self.options.limits))?;
        let value: Value = cbor2::from_slice(payload)?;
        if !matches!(value, Value::Map(_)) {
            return Err(Error::UnexpectedType(
                "SD-CWT payload must be a claims map".into(),
            ));
        }

        let hasher = default_hasher_for_sd_alg(sd_alg(&message.protected)?)?;
        let mut report = restore_with_protected_claims(
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
        let mut maps = vec![entries.as_slice()];
        if let Some(Value::Map(header)) = &report.protected_claims {
            validate_matching_claims(entries, header, self.options.limits)?;
            maps.push(header);
        }
        // A remaining root hash can still hide sub. After all root hashes
        // have been matched, both modes can determine whether sub is absent.
        validate_registered_claim_types(&maps)?;
        validate_required_claims(
            &maps,
            self.options.issuer_identified_by_protected_header,
            mode == RestoreMode::Verifier,
        )?;
        validate_time_relationships(&maps)?;
        if report.removed_redactions > 0 {
            remove_undisclosed_redactions(&mut report.value);
            if let Some(header) = &mut report.protected_claims {
                remove_undisclosed_redactions(header);
            }
        }
        Ok(report)
    }
}

/// Strict CBOR limits for SD-CWT inputs, which must use definite lengths.
pub(super) fn definite_cbor_limits(limits: ProcessingLimits) -> cose2::CborLimits {
    cose2::CborLimits {
        max_depth: limits.max_depth,
        max_items: limits.max_items,
        require_definite: true,
    }
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
    // `verify_and_decode_sd_cwt` validated the SD-CWT headers of this message.
    let report = SdCwtValidator::new(options).restore_validated_headers(&message, mode)?;
    Ok((message, report))
}

pub(super) fn validate_protected_encoding(
    message: &cose2::Sign1Message,
    limits: ProcessingLimits,
) -> Result<(), Error> {
    // The protected map is CBOR embedded inside a byte string. Validating the
    // outer message cannot inspect its encoding or apply these limits to it.
    if !message.protected_raw().is_empty() {
        cose2::validate_cbor(message.protected_raw(), definite_cbor_limits(limits))?;
    }
    Ok(())
}

fn validate_sd_headers(
    message: &cose2::Sign1Message,
    limits: ProcessingLimits,
) -> Result<(), Error> {
    validate_protected_encoding(message, limits)?;
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
    if value.eq_ignore_ascii_case("application/sd-cwt") {
        return true;
    }
    let Some((type_name, subtype)) = value.split_once('/') else {
        return false;
    };
    is_media_type_token(type_name)
        && is_media_type_token(subtype)
        && subtype
            .rsplit_once('+')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("sd-cwt"))
}

fn is_media_type_token(value: &str) -> bool {
    value.len() <= 127
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
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

pub(super) fn validate_confirmation_key(
    value: &Value,
    budget: &mut TraversalBudget,
    depth: usize,
) -> Result<(), Error> {
    if !matches!(value, Value::Map(_)) {
        return Err(Error::UnexpectedType("SD-CWT cnf must be a map".into()));
    }
    validate_safe_value(value, budget, depth)
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
                "SD-CWT reserved tag {tag} is not permitted in a safe value"
            )));
        }
        Value::Tag(_, inner) => validate_safe_value(inner, budget, depth + 1)?,
        Value::Simple(simple) if simple.value() == REDACTED_CLAIM_KEYS_SIMPLE => {
            return Err(Error::UnexpectedType(
                "simple(59) is not permitted in an SD-CWT safe value".into(),
            ));
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn validate_disclosure_value(
    disclosure: &DisclosureKind,
    limits: ProcessingLimits,
) -> Result<(), Error> {
    let (arity, value) = match disclosure {
        DisclosureKind::Claim { value, .. } => (3, Some(value)),
        DisclosureKind::Element { value, .. } => (2, Some(value)),
        DisclosureKind::Decoy { .. } => (1, None),
    };
    let mut budget = TraversalBudget::new(limits);
    budget.enter(0)?;
    budget.container(arity)?;
    budget.enter(1)?; // salt
    if arity == 3 {
        budget.enter(1)?; // claim key
    }
    if let Some(value) = value {
        validate_issued_value(value, &mut budget, 1)?;
    }
    Ok(())
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
            let mut saw_markers = false;
            for (key, value) in entries {
                budget.enter(depth + 1)?;
                if is_redacted_claim_keys_label(key) {
                    if saw_markers {
                        return Err(Error::verify("duplicate issued SD-CWT map key"));
                    }
                    saw_markers = true;
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
                    if !keys.insert(label_from_value(key)?) {
                        return Err(Error::verify("duplicate issued SD-CWT map key"));
                    }
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

pub(super) fn validate_text_label(label: &Label) -> Result<(), Error> {
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

pub(super) fn protected_cwt_claims(message: &cose2::Sign1Message) -> Result<Option<Value>, Error> {
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

fn claim_value<'a>(maps: &[&'a [(Value, Value)]], label: i64) -> Option<&'a Value> {
    maps.iter().find_map(|entries| map_value(entries, label))
}

fn visible_map(entries: &[(Value, Value)]) -> Result<HashMap<Label, &Value>, Error> {
    entries
        .iter()
        .filter(|(key, _)| !is_redacted_claim_keys_label(key))
        .map(|(key, value)| Ok((label_from_value(key)?, value)))
        .collect()
}

fn validate_matching_claims(
    payload: &[(Value, Value)],
    header: &[(Value, Value)],
    limits: ProcessingLimits,
) -> Result<(), Error> {
    // Restoration has already rejected duplicate keys within each map.
    let mut budget = TraversalBudget::new(limits);
    let header = visible_map(header)?;
    for (key, value) in payload {
        if is_redacted_claim_keys_label(key) {
            continue;
        }
        if let Some(other) = header.get(&label_from_value(key)?) {
            if !claim_values_match(value, other, &mut budget)? {
                return Err(Error::verify(format!(
                    "CWT_Claims header and payload disagree for claim {key}"
                )));
            }
        }
    }
    Ok(())
}

/// Compares the visible parts of restored claims. Unmatched hashes conceal
/// values (or decoys), so their bytes are not evidence of a value mismatch.
fn claim_values_match(
    left: &Value,
    right: &Value,
    budget: &mut TraversalBudget,
) -> Result<bool, Error> {
    budget.consume(1)?;
    match (left, right) {
        (Value::Map(left), Value::Map(right)) => {
            budget.consume(left.len())?;
            budget.consume(right.len())?;
            let hidden_count = |entries: &[(Value, Value)]| {
                entries
                    .iter()
                    .find_map(|(key, value)| match value {
                        Value::Array(hashes) if is_redacted_claim_keys_label(key) => {
                            Some(hashes.len())
                        }
                        _ => None,
                    })
                    .unwrap_or(0)
            };
            let mut right_hidden = hidden_count(right);
            let mut right_values = visible_map(right)?;
            for (key, value) in left {
                if is_redacted_claim_keys_label(key) {
                    continue;
                }
                match right_values.remove(&label_from_value(key)?) {
                    Some(other) if !claim_values_match(value, other, budget)? => return Ok(false),
                    None if right_hidden == 0 => return Ok(false),
                    None => right_hidden -= 1,
                    _ => {}
                }
            }
            Ok(right_values.len() <= hidden_count(left))
        }
        (Value::Array(left), Value::Array(right)) => arrays_match(left, right, budget),
        (Value::Bytes(_), Value::Bytes(_))
        | (Value::Text(_), Value::Text(_))
        | (Value::Integer(_), Value::Integer(_)) => Ok(left == right),
        (Value::Tag(left_tag, left), Value::Tag(right_tag, right)) => {
            if left_tag != right_tag {
                return Ok(false);
            }
            claim_values_match(left, right, budget)
        }
        // Different shapes cannot match. Avoid encoding large values at each
        // possible alignment in a partially disclosed array.
        (Value::Map(_) | Value::Array(_) | Value::Bytes(_) | Value::Text(_), _)
        | (_, Value::Map(_) | Value::Array(_) | Value::Bytes(_) | Value::Text(_)) => Ok(false),
        _ => Ok(cbor2::to_canonical_vec(left)? == cbor2::to_canonical_vec(right)?),
    }
}

fn arrays_match(
    mut left: &[Value],
    mut right: &[Value],
    budget: &mut TraversalBudget,
) -> Result<bool, Error> {
    budget.consume(left.len())?;
    budget.consume(right.len())?;
    // Compare the positions fixed by visible prefixes and suffixes first.
    while let ([a, a_rest @ ..], [b, b_rest @ ..]) = (left, right) {
        if is_redacted_element(a) || is_redacted_element(b) {
            break;
        }
        if !claim_values_match(a, b, budget)? {
            return Ok(false);
        }
        (left, right) = (a_rest, b_rest);
    }
    while let ([a_rest @ .., a], [b_rest @ .., b]) = (left, right) {
        if is_redacted_element(a) || is_redacted_element(b) {
            break;
        }
        if !claim_values_match(a, b, budget)? {
            return Ok(false);
        }
        (left, right) = (a_rest, b_rest);
    }

    let left_visible = left.iter().filter(|v| !is_redacted_element(v)).count();
    let right_visible = right.iter().filter(|v| !is_redacted_element(v)).count();
    if left_visible > right.len() || right_visible > left.len() {
        return Ok(false);
    }
    if left_visible == 0 || right_visible == 0 {
        return Ok(true);
    }
    if left_visible == right.len() || right_visible == left.len() {
        // Every slot on one side has a fixed counterpart on the other.
        let (visible, fixed) = if left_visible == right.len() {
            (left, right)
        } else {
            (right, left)
        };
        for (value, slot) in visible
            .iter()
            .filter(|v| !is_redacted_element(v))
            .zip(fixed)
        {
            if !is_redacted_element(slot) && !claim_values_match(value, slot, budget)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }

    // reachable[j] means the processed prefixes can describe the same array.
    // A hidden slot may be skipped as a decoy, or paired with exactly one slot.
    // Keep one row and charge its cells to the shared budget before visiting it.
    let (rows, cols) = if left.len() >= right.len() {
        (left, right)
    } else {
        (right, left)
    };
    let mut reachable = vec![false; cols.len() + 1];
    reachable[0] = true;
    for (j, col) in cols.iter().enumerate() {
        reachable[j + 1] = reachable[j] && is_redacted_element(col);
    }
    for row in rows {
        budget.consume(cols.len())?;
        let hidden = is_redacted_element(row);
        let mut diagonal = reachable[0];
        reachable[0] &= hidden;
        for (j, col) in cols.iter().enumerate() {
            let above = reachable[j + 1];
            let col_hidden = is_redacted_element(col);
            reachable[j + 1] = (hidden && above)
                || (col_hidden && reachable[j])
                || (diagonal && (hidden || col_hidden || claim_values_match(row, col, budget)?));
            diagonal = above;
        }
    }
    Ok(reachable[cols.len()])
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
            date_value(value, name)?;
        }
    }
    if claim_value(maps, cose2::iana::CWTClaimCti)
        .is_some_and(|value| !matches!(value, Value::Bytes(_)))
    {
        return Err(Error::UnexpectedType(
            "SD-CWT cti must be a byte string".into(),
        ));
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
    if claim_value(maps, cose2::iana::CWTClaimCnf).is_none() {
        return Err(Error::custom("SD-CWT is missing required cnf claim"));
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

pub(super) fn validate_root_disclosure_key(key: &Label) -> Result<(), Error> {
    const NEVER_REDACTED: &[i64] = &[1, 3, 4, 5, 6, 7, 8, 39];
    if matches!(key, Label::Int(key) if NEVER_REDACTED.contains(key)) {
        return Err(Error::custom(format!(
            "SD-CWT claim {key} must not be redacted"
        )));
    }
    Ok(())
}

/// Reads an SD-CWT date, whose floating-point form is limited to [-2^53, 2^53].
fn date_value(value: &Value, name: &str) -> Result<NumericDate, Error> {
    match value {
        Value::Integer(value) => Ok(NumericDate::Integer(i128::from(*value))),
        Value::Float(value) if value.is_finite() && value.abs() <= 9_007_199_254_740_992.0 => {
            Ok(NumericDate::Float(*value))
        }
        Value::Float(_) => Err(Error::UnexpectedType(format!(
            "{name} must be a finite float in the inclusive range [-2^53, 2^53]"
        ))),
        _ => Err(Error::UnexpectedType(format!("{name} must be numeric"))),
    }
}

fn validate_time_relationships(maps: &[&[(Value, Value)]]) -> Result<(), Error> {
    let exp = claim_value(maps, 4)
        .map(|value| date_value(value, "exp"))
        .transpose()?;
    let nbf = claim_value(maps, 5)
        .map(|value| date_value(value, "nbf"))
        .transpose()?;
    let iat = claim_value(maps, 6)
        .map(|value| date_value(value, "iat"))
        .transpose()?;
    if let (Some(nbf), Some(iat)) = (nbf, iat) {
        if nbf.compare(iat) == Some(Ordering::Greater) {
            return Err(Error::custom("SD-CWT requires nbf <= iat"));
        }
    }
    if let (Some(nbf), Some(exp)) = (nbf, exp) {
        if nbf.compare(exp) != Some(Ordering::Less) {
            return Err(Error::custom("SD-CWT requires nbf < exp"));
        }
    }
    if let (Some(iat), Some(exp)) = (iat, exp) {
        if iat.compare(exp) != Some(Ordering::Less) {
            return Err(Error::custom("SD-CWT requires iat < exp"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod array_tests {
    use super::*;

    #[test]
    fn alignment_agrees_with_all_short_concrete_expansions() {
        let mut cases = Vec::new();
        for len in 0..=3 {
            for mut code in 0..3usize.pow(len) {
                let mut pattern = Vec::new();
                let mut expansions = vec![Vec::new()];
                for _ in 0..len {
                    let symbol = (code % 3) as u8;
                    code /= 3;
                    if symbol < 2 {
                        pattern.push(Value::from(symbol));
                        for word in &mut expansions {
                            word.push(symbol);
                        }
                    } else {
                        pattern.push(crate::redacted_element(vec![0; 32]));
                        let shorter = expansions.clone(); // the slot is a decoy
                        for word in shorter {
                            for value in [0, 1] {
                                let mut disclosed = word.clone();
                                disclosed.push(value);
                                expansions.push(disclosed);
                            }
                        }
                    }
                }
                cases.push((pattern, expansions));
            }
        }
        for (left, left_words) in &cases {
            for (right, right_words) in &cases {
                let expected = left_words.iter().any(|w| right_words.contains(w));
                let mut budget = TraversalBudget::new(ProcessingLimits::default());
                assert_eq!(
                    arrays_match(left, right, &mut budget).unwrap(),
                    expected,
                    "{left:?}, {right:?}"
                );
            }
        }
    }
}
