//! COSE_Sign: signing with one or more signers (RFC 9052 §4.1).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected},
    iana, tag, util, Error, Header, Signer, Value, Verifier,
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

/// Untagged COSE_Sign, accepted for compatibility with untagged transports.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(array)]
struct SignBareWire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    unprotected: Header,
    #[serde(with = "serde_bytes")]
    payload: Option<Vec<u8>>,
    signatures: Vec<SignatureWire>,
}

impl From<SignBareWire> for SignWire {
    fn from(value: SignBareWire) -> Self {
        SignWire {
            protected: value.protected,
            unprotected: value.unprotected,
            payload: value.payload,
            signatures: value.signatures,
        }
    }
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
    /// Returns the `kid` from the signature's unprotected header, if any.
    fn kid(&self) -> Result<Option<&[u8]>, Error> {
        self.unprotected.kid()
    }

    /// Returns the raw signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the protected-header bytes used in this signature structure.
    pub fn protected_raw(&self) -> &[u8] {
        &self.protected_raw
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

    /// The `Sig_structure` to be signed by one signer (RFC 9052 §4.4).
    fn to_be_signed(
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
        let protected_raw = encode_protected(&self.protected)?;
        let mut signatures = Vec::with_capacity(signers.len());

        for signer in signers {
            let mut protected = Header::new();
            if let Some(alg) = signer.alg() {
                protected.set_alg(alg);
            }
            let mut unprotected = Header::new();
            util::ensure_unprotected_kid(&mut unprotected, signer.kid());

            let sign_protected_raw = encode_protected(&protected)?;
            let tbs =
                Self::to_be_signed(&protected_raw, &sign_protected_raw, external_aad, payload)?;
            let signature = signer.sign(&tbs)?;
            signatures.push(Signature {
                protected,
                unprotected,
                signature,
                protected_raw: sign_protected_raw,
            });
        }
        self.protected_raw = protected_raw;
        self.signatures = signatures;
        self.signed = true;
        Ok(())
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
        let wire: SignWire = if body.starts_with(tag::SIGN_PREFIX) {
            cbor2::from_slice(body)?
        } else if tag::starts_with_cbor_tag(body) {
            return Err(Error::Custom("unexpected CBOR tag for COSE_Sign".into()));
        } else {
            cbor2::from_slice::<SignBareWire>(body)?.into()
        };
        if wire.signatures.is_empty() {
            return Err(Error::Custom("SignMessage has no signatures".into()));
        }
        let protected = decode_protected(&wire.protected)?;
        let mut signatures = Vec::with_capacity(wire.signatures.len());
        for sw in wire.signatures {
            let sig_protected = decode_protected(&sw.protected)?;
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
            let verifier = verifiers
                .iter()
                .find(|v| util::kid_matches(kid, v.kid()))
                .ok_or_else(|| Error::verify("no verifier for signature kid"))?;
            util::check_protected_alg(&sig.protected, verifier.alg())?;
            let tbs = Self::to_be_signed(
                &self.protected_raw,
                &sig.protected_raw,
                external_aad,
                payload,
            )?;
            verifier.verify(&tbs, &sig.signature)?;
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
        assert_cbor_shape::<SignBareWire>(None, true);
    }
}
