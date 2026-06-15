//! COSE_Sign: signing with one or more signers (RFC 9052 §4.1).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected, validate_header_buckets},
    iana, tag, util, Error, Header, Label, Signer, Value, Verifier,
};

/// The on-the-wire COSE_Signature array: `[protected, unprotected, signature]`.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(array)]
struct SignatureWire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    unprotected: Header,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

/// The on-the-wire COSE_Sign array: `[protected, unprotected, payload, signatures]`.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(tag = 98, array)]
struct SignWire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    unprotected: Header,
    #[serde(with = "serde_bytes")]
    payload: Option<Vec<u8>>,
    signatures: Vec<SignatureWire>,
}

/// A COSE_Signature inside a [`SignMessage`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Signature {
    /// Protected header parameters of this signature (e.g. `alg`).
    pub protected: Header,
    /// Unprotected header parameters of this signature (e.g. `kid`).
    pub unprotected: Header,
    signature: Vec<u8>,
    protected_raw: Vec<u8>,
}

impl Signature {
    /// Creates an unsigned COSE_Signature with empty header buckets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an unsigned COSE_Signature with optional `alg` and `kid`.
    pub fn with_alg_kid(alg: Option<Label>, kid: Option<&[u8]>) -> Self {
        let mut signature = Self::new();
        if let Some(alg) = alg {
            signature.protected.set_alg(alg);
        }
        if let Some(kid) = kid {
            signature.unprotected.set_kid(kid.to_vec());
        }
        signature
    }

    /// Returns the signature's `kid`, read from the protected header first and
    /// then the unprotected header (RFC 9052 §3).
    fn kid(&self) -> Result<Option<&[u8]>, Error> {
        match self.protected.kid()? {
            Some(kid) => Ok(Some(kid)),
            None => self.unprotected.kid(),
        }
    }

    /// Returns the raw signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the protected-header bytes used in this signature structure.
    pub fn protected_raw(&self) -> &[u8] {
        &self.protected_raw
    }

    /// Stores externally produced signature bytes on this signature.
    ///
    /// If no protected bytes were prepared yet, this method serializes the
    /// current protected header canonically, which is valid for newly built
    /// signatures.
    pub fn set_signature(&mut self, signature: impl Into<Vec<u8>>) -> Result<(), Error> {
        validate_header_buckets(&self.protected, &self.unprotected)?;
        if self.protected_raw.is_empty() && !self.protected.is_empty() {
            self.protected_raw = encode_protected(&self.protected)?;
        }
        self.signature = signature.into();
        Ok(())
    }
}

/// A COSE_Sign message (one or more signers).
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-or-more-si>.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SignMessage {
    /// Body protected header parameters.
    pub protected: Header,
    /// Body unprotected header parameters.
    pub unprotected: Header,
    /// The payload, or `None` when detached.
    pub payload: Option<Vec<u8>>,
    /// The signatures.
    pub signatures: Vec<Signature>,
    protected_raw: Vec<u8>,
    signed: bool,
}

impl SignMessage {
    /// Creates a new, unsigned message with the given payload.
    pub fn new(payload: Option<Vec<u8>>) -> Self {
        SignMessage {
            payload,
            ..Default::default()
        }
    }

    /// Encodes the `Sig_structure` to be signed by one signer (RFC 9052 §4.4).
    ///
    /// This is the low-level helper for external or async signing code. New
    /// messages should usually call [`prepare_signatures`](Self::prepare_signatures)
    /// or [`prepare_detached_signatures`](Self::prepare_detached_signatures) so
    /// the body and per-signature protected bytes stored in the message match
    /// the bytes being signed.
    pub fn to_be_signed(
        body_protected: &[u8],
        sign_protected: &[u8],
        external_aad: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        util::encode_structure(vec![
            Value::from("Signature"),
            Value::Bytes(body_protected.to_vec()),
            Value::Bytes(sign_protected.to_vec()),
            Value::Bytes(external_aad.to_vec()),
            util::payload_value(payload),
        ])
    }

    /// Prepares this embedded-payload message for external signatures.
    ///
    /// `signatures` provides the per-signature protected and unprotected header
    /// buckets. The returned vector has the same order and contains the
    /// `Sig_structure` bytes each external signer must sign. After async or
    /// remote signers return signature bytes, call
    /// [`set_signatures`](Self::set_signatures) and then [`to_vec`](Self::to_vec).
    pub fn prepare_signatures(
        &mut self,
        signatures: Vec<Signature>,
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let payload =
            util::require_embedded_payload(&self.payload, "SignMessage::prepare_signatures")?
                .to_vec();
        self.prepare_signature_payload(signatures, &payload, external_aad.unwrap_or(&[]))
    }

    /// Prepares this detached-payload message for external signatures.
    ///
    /// The message's on-the-wire payload is set to `nil`; `detached_payload` is
    /// used only in each `Sig_structure`.
    pub fn prepare_detached_signatures(
        &mut self,
        signatures: Vec<Signature>,
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let to_be_signed = self.prepare_signature_payload(
            signatures,
            detached_payload,
            external_aad.unwrap_or(&[]),
        )?;
        self.payload = None;
        Ok(to_be_signed)
    }

    fn prepare_signature_payload(
        &mut self,
        mut signatures: Vec<Signature>,
        payload: &[u8],
        external_aad: &[u8],
    ) -> Result<Vec<Vec<u8>>, Error> {
        if signatures.is_empty() {
            return Err(Error::Custom(
                "SignMessage requires at least one signature".into(),
            ));
        }
        validate_header_buckets(&self.protected, &self.unprotected)?;
        let protected_raw = encode_protected(&self.protected)?;
        let mut to_be_signed = Vec::with_capacity(signatures.len());

        for signature in &mut signatures {
            validate_header_buckets(&signature.protected, &signature.unprotected)?;
            let sign_protected_raw = encode_protected(&signature.protected)?;
            let tbs =
                Self::to_be_signed(&protected_raw, &sign_protected_raw, external_aad, payload)?;
            signature.protected_raw = sign_protected_raw;
            signature.signature.clear();
            to_be_signed.push(tbs);
        }

        self.protected_raw = protected_raw;
        self.signatures = signatures;
        self.signed = false;
        Ok(to_be_signed)
    }

    /// Stores externally produced signature bytes on this message.
    ///
    /// The number and order must match the signatures passed to
    /// [`prepare_signatures`](Self::prepare_signatures) or
    /// [`prepare_detached_signatures`](Self::prepare_detached_signatures).
    pub fn set_signatures<I, S>(&mut self, signatures: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<Vec<u8>>,
    {
        let signatures = signatures.into_iter().map(Into::into).collect::<Vec<_>>();
        if signatures.is_empty() {
            return Err(Error::Custom(
                "SignMessage requires at least one signature".into(),
            ));
        }
        if signatures.len() != self.signatures.len() {
            return Err(Error::Custom(format!(
                "signature count mismatch, message has {}, got {}",
                self.signatures.len(),
                signatures.len()
            )));
        }
        validate_header_buckets(&self.protected, &self.unprotected)?;
        if self.protected_raw.is_empty() && !self.protected.is_empty() {
            self.protected_raw = encode_protected(&self.protected)?;
        }
        for (slot, signature) in self.signatures.iter_mut().zip(signatures) {
            slot.set_signature(signature)?;
        }
        self.signed = true;
        Ok(())
    }

    /// Signs the message with each signer, producing one [`Signature`] per signer.
    pub fn sign(
        &mut self,
        signers: &[&dyn Signer],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        let payload = util::require_embedded_payload(&self.payload, "SignMessage::sign")?.to_vec();
        self.sign_payload(signers, &payload, external_aad.unwrap_or(&[]))
    }

    /// Signs a detached payload with each signer.
    ///
    /// The message's on-the-wire payload is set to `nil`; `detached_payload`
    /// is used only in each `Sig_structure`.
    pub fn sign_detached(
        &mut self,
        signers: &[&dyn Signer],
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.sign_payload(signers, detached_payload, external_aad.unwrap_or(&[]))?;
        self.payload = None;
        Ok(())
    }

    fn sign_payload(
        &mut self,
        signers: &[&dyn Signer],
        payload: &[u8],
        external_aad: &[u8],
    ) -> Result<(), Error> {
        if signers.is_empty() {
            return Err(Error::Custom(
                "SignMessage requires at least one signer".into(),
            ));
        }
        let signature_headers = signers
            .iter()
            .map(|signer| Signature::with_alg_kid(signer.alg(), signer.kid()))
            .collect::<Vec<_>>();
        let to_be_signed =
            self.prepare_signature_payload(signature_headers, payload, external_aad)?;
        let signatures = signers
            .iter()
            .zip(&to_be_signed)
            .map(|(signer, tbs)| signer.sign(tbs))
            .collect::<Result<Vec<_>, _>>()?;
        self.set_signatures(signatures)
    }

    /// Signs and encodes the message to tagged COSE_Sign bytes.
    pub fn sign_and_encode(
        &mut self,
        signers: &[&dyn Signer],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.sign(signers, external_aad)?;
        self.to_vec()
    }

    /// Signs a detached payload and encodes the message to tagged COSE_Sign bytes.
    pub fn sign_detached_and_encode(
        &mut self,
        signers: &[&dyn Signer],
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.sign_detached(signers, detached_payload, external_aad)?;
        self.to_vec()
    }

    /// Encodes a signed message to tagged COSE_Sign bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        if !self.signed {
            return Err(Error::Custom(
                "SignMessage must be signed before encoding".into(),
            ));
        }
        if self.signatures.is_empty() {
            return Err(Error::Custom("SignMessage has no signatures".into()));
        }
        validate_header_buckets(&self.protected, &self.unprotected)?;
        for sig in &self.signatures {
            validate_header_buckets(&sig.protected, &sig.unprotected)?;
        }
        let signatures = self
            .signatures
            .iter()
            .map(|s| SignatureWire {
                protected: s.protected_raw.clone(),
                unprotected: s.unprotected.clone(),
                signature: s.signature.clone(),
            })
            .collect();
        let wire = SignWire {
            protected: self.protected_raw.clone(),
            unprotected: self.unprotected.clone(),
            payload: self.payload.clone(),
            signatures,
        };
        Ok(cbor2::to_canonical_vec(&wire)?)
    }

    /// Decodes a COSE_Sign message (tagged or untagged) without verifying it.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::strip_message_wrappers(data);
        if !body.starts_with(tag::SIGN_PREFIX) && tag::starts_with_cbor_tag(body) {
            return Err(Error::Custom("unexpected CBOR tag for COSE_Sign".into()));
        }
        let wire: SignWire = cbor2::from_slice(body)?;
        if wire.signatures.is_empty() {
            return Err(Error::Custom("SignMessage has no signatures".into()));
        }
        let protected = decode_protected(&wire.protected)?;
        validate_header_buckets(&protected, &wire.unprotected)?;
        let mut signatures = Vec::with_capacity(wire.signatures.len());
        for sw in wire.signatures {
            let sig_protected = decode_protected(&sw.protected)?;
            validate_header_buckets(&sig_protected, &sw.unprotected)?;
            signatures.push(Signature {
                protected: sig_protected,
                unprotected: sw.unprotected,
                signature: sw.signature,
                protected_raw: sw.protected,
            });
        }
        Ok(SignMessage {
            protected,
            unprotected: wire.unprotected,
            payload: wire.payload,
            signatures,
            protected_raw: wire.protected,
            signed: true,
        })
    }

    /// Verifies every signature: each must match exactly one of the
    /// `verifiers` (by `kid`) and validate.
    pub fn verify(
        &self,
        verifiers: &[&dyn Verifier],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        let payload = util::require_embedded_payload(&self.payload, "SignMessage::verify")?;
        self.verify_payload(verifiers, payload, external_aad.unwrap_or(&[]))
    }

    /// Verifies every signature over a detached payload.
    pub fn verify_detached(
        &self,
        verifiers: &[&dyn Verifier],
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        if self.payload.is_some() {
            return Err(Error::Custom(
                "SignMessage carries an embedded payload; use verify".into(),
            ));
        }
        self.verify_payload(verifiers, detached_payload, external_aad.unwrap_or(&[]))
    }

    fn verify_payload(
        &self,
        verifiers: &[&dyn Verifier],
        payload: &[u8],
        external_aad: &[u8],
    ) -> Result<(), Error> {
        if !self.signed {
            return Err(Error::Custom(
                "SignMessage must be decoded before verifying".into(),
            ));
        }
        if verifiers.is_empty() {
            return Err(Error::Custom(
                "SignMessage requires at least one verifier".into(),
            ));
        }
        if self.signatures.is_empty() {
            return Err(Error::Custom("SignMessage has no signatures".into()));
        }

        for sig in &self.signatures {
            let kid = sig.kid()?;
            let tbs = Self::to_be_signed(
                &self.protected_raw,
                &sig.protected_raw,
                external_aad,
                payload,
            )?;
            let mut matched_kid = false;
            let mut last_error = None;
            for verifier in verifiers.iter().filter(|v| util::kid_matches(kid, v.kid())) {
                matched_kid = true;
                if let Err(err) = util::check_protected_alg(&sig.protected, verifier.alg()) {
                    last_error = Some(err);
                    continue;
                }
                match verifier.verify(&tbs, &sig.signature) {
                    Ok(()) => {
                        last_error = None;
                        break;
                    }
                    Err(err) => last_error = Some(err),
                }
            }
            if let Some(err) = last_error {
                return Err(err);
            }
            if !matched_kid {
                return Err(Error::verify("no verifier for signature kid"));
            }
        }
        Ok(())
    }

    /// Decodes and verifies a COSE_Sign message in one step.
    pub fn verify_and_decode(
        verifiers: &[&dyn Verifier],
        data: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let msg = Self::from_slice(data)?;
        msg.verify(verifiers, external_aad)?;
        Ok(msg)
    }

    /// Decodes and verifies a detached-payload COSE_Sign message in one step.
    pub fn verify_detached_and_decode(
        verifiers: &[&dyn Verifier],
        data: &[u8],
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let msg = Self::from_slice(data)?;
        msg.verify_detached(verifiers, detached_payload, external_aad)?;
        Ok(msg)
    }

    /// Returns the body protected-header bytes used in signature structures.
    pub fn protected_raw(&self) -> &[u8] {
        &self.protected_raw
    }

    /// The on-the-wire CBOR tag for COSE_Sign.
    pub const TAG: u64 = iana::CBORTagCOSESign;
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
        assert_cbor_shape::<SignatureWire>(None, true);
        assert_cbor_shape::<SignWire>(Some(iana::CBORTagCOSESign), true);
    }
}
