//! COSE_Sign1: signing with one signer (RFC 9052 §4.2).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected},
    iana, tag, util, Error, Header, Signer, Value, Verifier,
};

/// The on-the-wire COSE_Sign1 array: `[protected, unprotected, payload, signature]`.
#[derive(Clone, Debug, PartialEq, Cbor)]
struct Sign1Wire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    Header,
    #[serde(with = "serde_bytes")] Option<Vec<u8>>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

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
    signed: bool,
}

impl Sign1Message {
    /// Creates a new, unsigned message with the given payload.
    pub fn new(payload: Option<Vec<u8>>) -> Self {
        Sign1Message {
            payload,
            ..Default::default()
        }
    }

    /// The `Sig_structure` to be signed (RFC 9052 §4.4).
    fn to_be_signed(
        protected_raw: &[u8],
        external_aad: &[u8],
        payload: &Option<Vec<u8>>,
    ) -> Vec<u8> {
        util::encode_structure(vec![
            Value::from("Signature1"),
            Value::Bytes(protected_raw.to_vec()),
            Value::Bytes(external_aad.to_vec()),
            util::payload_value(payload),
        ])
    }

    /// Signs the message with `signer`, filling in `alg`/`kid` headers as needed.
    pub fn sign(&mut self, signer: &dyn Signer, external_aad: Option<&[u8]>) -> Result<(), Error> {
        util::ensure_protected_alg(&mut self.protected, signer.alg())?;
        util::ensure_unprotected_kid(&mut self.unprotected, signer.kid());

        self.protected_raw = encode_protected(&self.protected);
        let tbs = Self::to_be_signed(
            &self.protected_raw,
            external_aad.unwrap_or(&[]),
            &self.payload,
        );
        self.signature = signer.sign(&tbs)?;
        self.signed = true;
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

    /// Encodes a signed message to tagged COSE_Sign1 bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        if !self.signed {
            return Err(Error::Custom(
                "Sign1Message must be signed before encoding".into(),
            ));
        }
        let wire = Sign1Wire(
            self.protected_raw.clone(),
            self.unprotected.clone(),
            self.payload.clone(),
            self.signature.clone(),
        );
        Ok(tag::with_tag(
            tag::SIGN1_PREFIX,
            &cbor2::to_canonical_vec(&wire)?,
        ))
    }

    /// Decodes a COSE_Sign1 message (tagged or untagged) without verifying it.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::untag(data, tag::SIGN1_PREFIX);
        let wire: Sign1Wire = cbor2::from_slice(body)?;
        let protected = decode_protected(&wire.0)?;
        Ok(Sign1Message {
            protected,
            unprotected: wire.1,
            payload: wire.2,
            signature: wire.3,
            protected_raw: wire.0,
            signed: true,
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
        if !self.signed {
            return Err(Error::Custom(
                "Sign1Message must be decoded before verifying".into(),
            ));
        }
        util::check_protected_alg(&self.protected, verifier.alg())?;
        let tbs = Self::to_be_signed(
            &self.protected_raw,
            external_aad.unwrap_or(&[]),
            &self.payload,
        );
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

    /// Returns the signature bytes (empty until signed/decoded).
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Re-exports the on-the-wire CBOR tag for COSE_Sign1.
    pub const TAG: u64 = iana::CBORTagCOSESign1;
}
