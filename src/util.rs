//! Internal helpers shared by the message modules.

use crate::{Error, Header, Label};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum OperationState {
    #[default]
    New,
    Prepared,
    Complete,
}

impl OperationState {
    pub(crate) fn initialized(self) -> bool {
        self != Self::New
    }

    pub(crate) fn complete(self) -> bool {
        self == Self::Complete
    }
}

#[cfg(any(
    feature = "crypto-ring",
    feature = "crypto-aws-lc-rs",
    feature = "crypto-aes-gcm"
))]
pub(crate) fn key_ops_allow(ops: &Option<Vec<Label>>, allowed: &[i64]) -> bool {
    ops.as_ref().is_none_or(|ops| {
        ops.iter()
            .any(|op| matches!(op, Label::Int(value) if allowed.contains(value)))
    })
}

#[cfg(any(
    feature = "crypto-ring",
    feature = "crypto-aws-lc-rs",
    feature = "crypto-aes-gcm"
))]
pub(crate) fn require_key_ops(
    ops: &Option<Vec<Label>>,
    allowed: &[i64],
    operation: &str,
) -> Result<(), Error> {
    if key_ops_allow(ops, allowed) {
        Ok(())
    } else {
        Err(Error::key_operation(format!(
            "COSE_Key key_ops does not permit {operation}"
        )))
    }
}

#[cfg(any(
    feature = "crypto-ring",
    feature = "crypto-aws-lc-rs",
    feature = "crypto-aes-gcm"
))]
pub(crate) fn set_key_ops(key: &mut crate::Key, ops: &Option<Vec<Label>>) {
    if let Some(ops) = ops {
        key.set_ops(ops.clone());
    }
}

/// Maps payload bytes to the CBOR value used in the `*_structure` to be
/// signed or MACed.
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
pub(crate) fn encode_structure<T: serde::Serialize>(parts: &T) -> Result<Vec<u8>, Error> {
    // Every authenticated structure is a fixed array of text and byte strings;
    // the normal encoder already emits their unique preferred form. Avoid the
    // canonical encoder here because it first materializes a dynamic Value and
    // would copy large payloads an extra time merely to sort maps that cannot
    // occur in these structures.
    Ok(cbor2::to_vec(parts)?)
}

/// Streams a borrowed wire body into an exactly sized buffer that starts with
/// `prefix` (a COSE tag prefix from [`tag`](crate::tag), or empty for untagged
/// output).
///
/// Message modules pre-encode map-containing fragments with [`canonical_raw`]
/// so the ordinary streaming encoder still produces canonical output without
/// copying large payload or ciphertext byte strings through a dynamic value.
pub(crate) fn encode_prefixed<T: serde::Serialize>(
    prefix: &[u8],
    body: &T,
) -> Result<Vec<u8>, Error> {
    let body_len = usize::try_from(cbor2::serialized_size(body)?)
        .map_err(|_| Error::custom("encoded CBOR size does not fit usize"))?;
    let capacity = prefix
        .len()
        .checked_add(body_len)
        .ok_or_else(|| Error::custom("encoded CBOR size overflow"))?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(prefix);
    cbor2::to_writer(body, &mut out)?;
    Ok(out)
}

/// Canonically encodes a map-containing fragment for zero-copy splicing into
/// an otherwise streaming CBOR message.
pub(crate) fn canonical_raw<T: serde::Serialize>(value: &T) -> Result<cbor2::RawValue, Error> {
    Ok(cbor2::RawValue::new(cbor2::to_canonical_vec(value)?)?)
}

/// On the signing/encrypting/MACing side: writes `alg` into the protected
/// header if absent, or checks it matches when already present.
///
pub(crate) fn ensure_protected_alg(
    protected: &mut Header,
    unprotected: &mut Header,
    alg: Option<Label>,
) -> Result<(), Error> {
    let Some(alg) = alg else {
        return Ok(());
    };
    match protected.alg()? {
        Some(existing) if existing != alg => Err(Error::AlgorithmMismatch {
            declared: existing.to_string(),
            expected: alg.to_string(),
        }),
        Some(_) => Ok(()),
        None => {
            if let Some(existing) = unprotected.alg()? {
                if existing != alg {
                    return Err(Error::AlgorithmMismatch {
                        declared: existing.to_string(),
                        expected: alg.to_string(),
                    });
                }
                unprotected.remove(crate::iana::HeaderParameterAlg);
            }
            protected.set_alg(alg);
            Ok(())
        }
    }
}

/// On the verifying/decrypting side: checks the protected header's `alg`
/// matches the verifier's algorithm, when both are present.
pub(crate) fn check_protected_alg(
    protected: &Header,
    unprotected: &Header,
    alg: Option<Label>,
) -> Result<(), Error> {
    if let Some(expected) = alg {
        let existing = match protected.alg()? {
            Some(existing) => Some(existing),
            None => unprotected.alg()?,
        };
        if let Some(existing) = existing {
            if existing != expected {
                return Err(Error::AlgorithmMismatch {
                    declared: existing.to_string(),
                    expected: expected.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Checks whether a verifier key identifier matches a message key identifier.
pub(crate) fn kid_match_rank(
    message_kid: Option<&[u8]>,
    verifier_kid: Option<&[u8]>,
) -> Option<u8> {
    match (message_kid, verifier_kid) {
        (Some(message_kid), Some(verifier_kid)) if message_kid == verifier_kid => Some(0),
        (Some(_), Some(_)) => None,
        _ => Some(1),
    }
}

/// Writes `kid` into the unprotected header if absent.
pub(crate) fn ensure_unprotected_kid(
    protected: &Header,
    unprotected: &mut Header,
    kid: Option<&[u8]>,
) -> Result<(), Error> {
    if let Some(kid) = kid {
        if protected.kid()?.is_none() && !unprotected.contains_key(crate::iana::HeaderParameterKid)
        {
            unprotected.set_kid(kid.to_vec());
        }
    }
    Ok(())
}

/// Looks a byte-string header parameter up in the protected bucket first, then
/// the unprotected bucket (RFC 9052 §3: protected attributes take precedence).
pub(crate) fn header_bytes<'a>(
    protected: &'a Header,
    unprotected: &'a Header,
    label: i64,
) -> Result<Option<&'a [u8]>, Error> {
    match protected.get_bytes(label)? {
        Some(value) => Ok(Some(value)),
        None => unprotected.get_bytes(label),
    }
}

/// Returns the actual AEAD nonce from either a full `IV` or a `Partial IV`,
/// using explicit external-crypto parameters instead of an `Encryptor`.
pub(crate) fn nonce_from_header_values(
    protected: &Header,
    unprotected: &Header,
    nonce_size: usize,
    base_iv: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let iv = header_bytes(protected, unprotected, crate::iana::HeaderParameterIV)?;
    let partial_iv = header_bytes(
        protected,
        unprotected,
        crate::iana::HeaderParameterPartialIV,
    )?;
    if iv.is_some() && partial_iv.is_some() {
        return Err(Error::Custom(
            "IV and Partial IV must not both be present".into(),
        ));
    }

    if let Some(iv) = iv {
        if iv.len() != nonce_size {
            return Err(Error::Custom(format!(
                "IV size mismatch, expected {}, got {}",
                nonce_size,
                iv.len()
            )));
        }
        return Ok(iv.to_vec());
    }

    let Some(partial_iv) = partial_iv else {
        return Err(Error::Custom(
            "missing IV or Partial IV in unprotected header".into(),
        ));
    };
    let base_iv = base_iv.ok_or_else(|| Error::Custom("Partial IV requires a Base IV".into()))?;
    if base_iv.len() != nonce_size {
        return Err(Error::Custom(format!(
            "Base IV size mismatch, expected {}, got {}",
            nonce_size,
            base_iv.len()
        )));
    }
    if partial_iv.len() > nonce_size {
        return Err(Error::Custom(format!(
            "Partial IV size mismatch, expected at most {}, got {}",
            nonce_size,
            partial_iv.len()
        )));
    }

    let mut nonce = vec![0; nonce_size];
    nonce[nonce_size - partial_iv.len()..].copy_from_slice(partial_iv);
    for (byte, base) in nonce.iter_mut().zip(base_iv) {
        *byte ^= *base;
    }
    Ok(nonce)
}
