//! COSE_Sign1: signing with one signer (RFC 9052 §4.2).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected, validate_header_buckets},
    iana, tag, util, Error, Header, Label, Signer, Verifier,
};

/// The on-the-wire COSE_Sign1 array: `[protected, unprotected, payload, signature]`.
// Private wire types are decoded only after `tag::message_body` validates
// their exact field kinds. Decode byte strings directly into their final buffers.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(tag = 18, array)]
struct Sign1Wire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    unprotected: Header,
    #[serde(with = "serde_bytes")]
    payload: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

/// A COSE_Sign1 message.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-signer>.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sign1Message {
    /// Protected header parameters (e.g. `alg`), authenticated by the signature.
    pub protected: Header,
    /// Unprotected header parameters (e.g. `kid`).
    pub unprotected: Header,
    /// The payload, or `None` when detached.
    pub payload: Option<Vec<u8>>,
    signature: Vec<u8>,
    protected_raw: Vec<u8>,
    state: util::OperationState,
}

impl Sign1Message {
    /// Creates a new, unsigned message with the given payload.
    pub fn new(payload: Option<Vec<u8>>) -> Self {
        Sign1Message {
            payload,
            ..Default::default()
        }
    }

    /// Encodes the `Sig_structure` to be signed (RFC 9052 §4.4).
    ///
    /// This is the low-level helper for applications that sign outside the
    /// synchronous [`Signer`] trait, such as remote KMS or other async signing
    /// services. New messages should usually call
    /// [`prepare_signature`](Self::prepare_signature) or
    /// [`prepare_detached_signature`](Self::prepare_detached_signature) so the
    /// protected header bytes stored in the message match the bytes being
    /// signed.
    pub fn to_be_signed(
        protected_raw: &[u8],
        external_aad: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        util::encode_structure(&(
            "Signature1",
            serde_bytes::Bytes::new(protected_raw),
            serde_bytes::Bytes::new(external_aad),
            serde_bytes::Bytes::new(payload),
        ))
    }

    /// Prepares this embedded-payload message for an external signature.
    ///
    /// The returned bytes are the `Sig_structure` that must be signed. After an
    /// async or remote signer returns the signature bytes, call
    /// [`set_signature`](Self::set_signature) and then [`to_vec`](Self::to_vec).
    /// Passing `None` for `external_aad` is the same as an empty byte string.
    pub fn prepare_signature(
        &mut self,
        alg: Option<Label>,
        kid: Option<&[u8]>,
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.prepare_signature_headers(alg, kid)?;
        let payload =
            util::require_embedded_payload(&self.payload, "Sign1Message::prepare_signature")?;
        Self::to_be_signed(&self.protected_raw, external_aad.unwrap_or(&[]), payload)
    }

    /// Prepares this detached-payload message for an external signature.
    ///
    /// The returned bytes are the `Sig_structure` that must be signed. The
    /// message's on-the-wire payload is set to `nil`; `detached_payload` is used
    /// only in the `Sig_structure`.
    pub fn prepare_detached_signature(
        &mut self,
        alg: Option<Label>,
        kid: Option<&[u8]>,
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.prepare_signature_headers(alg, kid)?;
        let tbs = Self::to_be_signed(
            &self.protected_raw,
            external_aad.unwrap_or(&[]),
            detached_payload,
        )?;
        self.payload = None;
        Ok(tbs)
    }

    fn prepare_signature_headers(
        &mut self,
        alg: Option<Label>,
        kid: Option<&[u8]>,
    ) -> Result<(), Error> {
        util::ensure_protected_alg(&mut self.protected, &mut self.unprotected, alg)?;
        util::ensure_unprotected_kid(&self.protected, &mut self.unprotected, kid)?;
        validate_header_buckets(&self.protected, &self.unprotected)?;
        let protected_raw = encode_protected(&self.protected)?;
        self.protected_raw = protected_raw;
        self.state = util::OperationState::Prepared;
        self.signature.clear();
        Ok(())
    }

    /// Stores externally produced signature bytes on this message.
    ///
    /// This completes the two-step external signing flow started by
    /// [`prepare_signature`](Self::prepare_signature) or
    /// [`prepare_detached_signature`](Self::prepare_detached_signature). If no
    /// protected bytes were prepared yet, this method serializes the current
    /// protected header canonically, which is valid for newly built messages.
    pub fn set_signature(&mut self, signature: impl Into<Vec<u8>>) -> Result<(), Error> {
        validate_header_buckets(&self.protected, &self.unprotected)?;
        if !self.state.initialized() {
            self.protected_raw = encode_protected(&self.protected)?;
        }
        crate::header::validate_protected_state(&self.protected, &self.protected_raw)?;
        self.signature = signature.into();
        self.state = util::OperationState::Complete;
        Ok(())
    }

    /// Signs the message with `signer`, filling in `alg`/`kid` headers as needed.
    pub fn sign(&mut self, signer: &dyn Signer, external_aad: Option<&[u8]>) -> Result<(), Error> {
        self.prepare_signature_headers(signer.alg(), signer.kid())?;
        let payload = util::require_embedded_payload(&self.payload, "Sign1Message::sign")?;
        let tbs = Self::to_be_signed(&self.protected_raw, external_aad.unwrap_or(&[]), payload)?;
        let signature = signer.sign(&tbs)?;
        self.set_signature(signature)
    }

    /// Signs a detached payload.
    ///
    /// The message's on-the-wire payload is set to `nil`; `detached_payload`
    /// is used only in the `Sig_structure`.
    pub fn sign_detached(
        &mut self,
        signer: &dyn Signer,
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.prepare_signature_headers(signer.alg(), signer.kid())?;
        let tbs = Self::to_be_signed(
            &self.protected_raw,
            external_aad.unwrap_or(&[]),
            detached_payload,
        )?;
        let signature = signer.sign(&tbs)?;
        self.set_signature(signature)?;
        self.payload = None;
        Ok(())
    }

    /// Signs and encodes the message, returning the tagged COSE_Sign1 bytes.
    pub fn sign_and_encode(
        &mut self,
        signer: &dyn Signer,
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.sign(signer, external_aad)?;
        self.to_vec()
    }

    /// Signs a detached payload and encodes the message.
    pub fn sign_detached_and_encode(
        &mut self,
        signer: &dyn Signer,
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.sign_detached(signer, detached_payload, external_aad)?;
        self.to_vec()
    }

    /// Encodes a signed message to tagged COSE_Sign1 bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        self.encode(tag::SIGN1_PREFIX)
    }

    /// Encodes this tagged COSE_Sign1 as a CWT (`61(18(...))`).
    pub fn to_cwt_vec(&self) -> Result<Vec<u8>, Error> {
        self.encode(tag::CWT_SIGN1_PREFIX)
    }

    /// Encodes a signed message to canonical COSE_Sign1 bytes without the CBOR tag.
    pub fn to_untagged_vec(&self) -> Result<Vec<u8>, Error> {
        self.encode(&[])
    }

    /// Serializes the wire array borrowing this message's buffers.
    fn encode(&self, prefix: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.state.complete() {
            return Err(Error::InvalidState(
                "Sign1Message must be signed before encoding".into(),
            ));
        }
        validate_header_buckets(&self.protected, &self.unprotected)?;
        crate::header::validate_protected_state(&self.protected, &self.protected_raw)?;
        let unprotected = util::canonical_raw(&self.unprotected)?;
        util::encode_prefixed(
            prefix,
            &(
                serde_bytes::Bytes::new(&self.protected_raw),
                &unprotected,
                self.payload.as_deref().map(serde_bytes::Bytes::new),
                serde_bytes::Bytes::new(&self.signature),
            ),
        )
    }

    /// Decodes a COSE_Sign1 message (tagged or untagged) without verifying it.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::message_body(data, Self::TAG)?;
        let wire: Sign1Wire = cbor2::from_slice(body)?;
        let protected = decode_protected(&wire.protected)?;
        validate_header_buckets(&protected, &wire.unprotected)?;
        Ok(Sign1Message {
            protected,
            unprotected: wire.unprotected,
            payload: wire.payload,
            signature: wire.signature,
            protected_raw: wire.protected,
            state: util::OperationState::Complete,
        })
    }

    /// Verifies the signature with `verifier`.
    ///
    /// Call after [`Sign1Message::from_slice`]; `external_aad` must match the
    /// value used when signing.
    pub fn verify(
        &self,
        verifier: &dyn Verifier,
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        if !self.state.complete() {
            return Err(Error::InvalidState(
                "Sign1Message must be decoded before verifying".into(),
            ));
        }
        let payload = util::require_embedded_payload(&self.payload, "Sign1Message::verify")?;
        self.verify_payload(verifier, payload, external_aad.unwrap_or(&[]))
    }

    /// Verifies the signature over a detached payload.
    pub fn verify_detached(
        &self,
        verifier: &dyn Verifier,
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        if !self.state.complete() {
            return Err(Error::InvalidState(
                "Sign1Message must be decoded before verifying".into(),
            ));
        }
        if self.payload.is_some() {
            return Err(Error::Custom(
                "Sign1Message carries an embedded payload; use verify".into(),
            ));
        }
        self.verify_payload(verifier, detached_payload, external_aad.unwrap_or(&[]))
    }

    fn verify_payload(
        &self,
        verifier: &dyn Verifier,
        payload: &[u8],
        external_aad: &[u8],
    ) -> Result<(), Error> {
        validate_header_buckets(&self.protected, &self.unprotected)?;
        crate::header::validate_protected_state(&self.protected, &self.protected_raw)?;
        self.protected
            .ensure_crit_understood(verifier.understood_critical_headers())?;
        util::check_protected_alg(&self.protected, &self.unprotected, verifier.alg())?;
        let tbs = Self::to_be_signed(&self.protected_raw, external_aad, payload)?;
        verifier.verify(&tbs, &self.signature)
    }

    /// Decodes and verifies a COSE_Sign1 message in one step.
    pub fn verify_and_decode(
        verifier: &dyn Verifier,
        data: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let msg = Self::from_slice(data)?;
        msg.verify(verifier, external_aad)?;
        Ok(msg)
    }

    /// Decodes and verifies a detached-payload COSE_Sign1 message in one step.
    pub fn verify_detached_and_decode(
        verifier: &dyn Verifier,
        data: &[u8],
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let msg = Self::from_slice(data)?;
        msg.verify_detached(verifier, detached_payload, external_aad)?;
        Ok(msg)
    }

    /// Returns the signature bytes (empty until signed/decoded).
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the protected-header bytes used in the signature structure.
    pub fn protected_raw(&self) -> &[u8] {
        &self.protected_raw
    }

    /// Re-exports the on-the-wire CBOR tag for COSE_Sign1.
    pub const TAG: u64 = iana::CBORTagCOSESign1;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_cbor_shape<T: cbor2::Cbor>(tag: Option<u64>, array: bool) {
        assert_eq!(T::TAG, tag);
        assert_eq!(T::ARRAY, array);
    }

    #[test]
    fn wire_metadata_declares_tagged_array_shape() {
        assert_cbor_shape::<Sign1Wire>(Some(iana::CBORTagCOSESign1), true);
    }
}
