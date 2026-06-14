//! Internal helpers shared by the message modules.

use crate::{Error, Header, Label, Value};

/// Maps payload bytes to the CBOR value used in the `*_structure` to be
/// signed or MACed.
pub(crate) fn payload_value(payload: &[u8]) -> Value {
    Value::Bytes(payload.to_vec())
}

/// Returns an embedded payload, or an error that points callers at the
/// detached-payload API.
pub(crate) fn require_embedded_payload<'a>(
    payload: &'a Option<Vec<u8>>,
    operation: &str,
) -> Result<&'a [u8], Error> {
    payload.as_deref().ok_or_else(|| {
        Error::Custom(format!(
            "{operation} requires an embedded payload; use the detached-payload API"
        ))
    })
}

/// Returns plaintext for encryption, requiring callers to make empty
/// plaintext explicit as `Some(Vec::new())`.
pub(crate) fn require_plaintext<'a>(
    payload: &'a Option<Vec<u8>>,
    operation: &str,
) -> Result<&'a [u8], Error> {
    payload.as_deref().ok_or_else(|| {
        Error::Custom(format!(
            "{operation} requires a plaintext payload; use Some(Vec::new()) for empty plaintext"
        ))
    })
}

/// Serializes a fixed COSE `*_structure` array to its canonical CBOR bytes.
pub(crate) fn encode_structure(parts: Vec<Value>) -> Result<Vec<u8>, Error> {
    Ok(cbor2::to_canonical_vec(&Value::Array(parts))?)
}

/// On the signing/encrypting/MACing side: writes `alg` into the protected
/// header if absent, or checks it matches when already present.
///
pub(crate) fn ensure_protected_alg(
    protected: &mut Header,
    alg: Option<Label>,
) -> Result<(), Error> {
    let Some(alg) = alg else {
        return Ok(());
    };
    match protected.alg()? {
        Some(existing) if existing != alg => Err(Error::Custom(format!(
            "algorithm mismatch, header has {existing}, crypto provider has {alg}"
        ))),
        Some(_) => Ok(()),
        None => {
            protected.set_alg(alg);
            Ok(())
        }
    }
}

/// On the verifying/decrypting side: checks the protected header's `alg`
/// matches the verifier's algorithm, when both are present.
pub(crate) fn check_protected_alg(protected: &Header, alg: Option<Label>) -> Result<(), Error> {
    if let Some(expected) = alg {
        if let Some(existing) = protected.alg()? {
            if existing != expected {
                return Err(Error::Custom(format!(
                    "algorithm mismatch, header has {existing}, verifier has {expected}"
                )));
            }
        }
    }
    Ok(())
}

/// Checks whether a verifier key identifier matches a message key identifier.
pub(crate) fn kid_matches(message_kid: Option<&[u8]>, verifier_kid: Option<&[u8]>) -> bool {
    match (message_kid, verifier_kid) {
        (Some(message_kid), Some(verifier_kid)) => message_kid == verifier_kid,
        (None, None) => true,
        _ => false,
    }
}

/// Writes `kid` into the unprotected header if absent.
pub(crate) fn ensure_unprotected_kid(unprotected: &mut Header, kid: Option<&[u8]>) {
    if let Some(kid) = kid {
        if !unprotected.contains_key(crate::iana::HeaderParameterKid) {
            unprotected.set_kid(kid.to_vec());
        }
    }
}
