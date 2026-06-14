//! Internal helpers shared by the message modules.

use crate::{iana, Error, Header, Value};

/// Maps an optional payload to the CBOR value used in messages and in the
/// `*_structure` to be signed/MACed: present bytes become a byte string,
/// an absent payload becomes `null`.
pub(crate) fn payload_value(payload: &Option<Vec<u8>>) -> Value {
    match payload {
        Some(bytes) => Value::Bytes(bytes.clone()),
        None => Value::Null,
    }
}

/// Serializes a fixed COSE `*_structure` array to its canonical CBOR bytes.
///
/// The structure is a small array of byte/text values, which always
/// serializes, so this is infallible.
pub(crate) fn encode_structure(parts: Vec<Value>) -> Vec<u8> {
    cbor2::to_canonical_vec(&Value::Array(parts)).unwrap_or_default()
}

/// On the signing/encrypting/MACing side: writes `alg` into the protected
/// header if absent, or checks it matches when already present.
///
/// A zero `alg` (`AlgorithmReserved`) means "no algorithm" and is skipped.
pub(crate) fn ensure_protected_alg(protected: &mut Header, alg: i64) -> Result<(), Error> {
    if alg == iana::AlgorithmReserved {
        return Ok(());
    }
    match protected.get_i64(iana::HeaderParameterAlg)? {
        Some(existing) if existing != alg => Err(Error::Custom(format!(
            "algorithm mismatch, header has {existing}, signer has {alg}"
        ))),
        Some(_) => Ok(()),
        None => {
            protected.insert(iana::HeaderParameterAlg, alg);
            Ok(())
        }
    }
}

/// On the verifying/decrypting side: checks the protected header's `alg`
/// matches the verifier's algorithm, when both are present.
pub(crate) fn check_protected_alg(protected: &Header, alg: i64) -> Result<(), Error> {
    if alg == iana::AlgorithmReserved {
        return Ok(());
    }
    if let Some(existing) = protected.get_i64(iana::HeaderParameterAlg)? {
        if existing != alg {
            return Err(Error::Custom(format!(
                "algorithm mismatch, header has {existing}, verifier has {alg}"
            )));
        }
    }
    Ok(())
}

/// Writes `kid` into the unprotected header if absent and non-empty.
pub(crate) fn ensure_unprotected_kid(unprotected: &mut Header, kid: &[u8]) {
    if !kid.is_empty() && !unprotected.contains_key(iana::HeaderParameterKid) {
        unprotected.insert(iana::HeaderParameterKid, kid.to_vec());
    }
}
