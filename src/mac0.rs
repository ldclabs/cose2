//! COSE_Mac0: MAC without recipients (RFC 9052 §6.2).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected},
    iana, tag, util, Error, Header, Macer, Value,
};

/// The on-the-wire COSE_Mac0 array: `[protected, unprotected, payload, tag]`.
#[derive(Clone, Debug, PartialEq, Cbor)]
struct Mac0Wire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    Header,
    #[serde(with = "serde_bytes")] Option<Vec<u8>>,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

/// A COSE_Mac0 message.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-maced-messages-with-implici>.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Mac0Message {
    /// Protected header parameters (e.g. `alg`), authenticated by the tag.
    pub protected: Header,
    /// Unprotected header parameters (e.g. `kid`).
    pub unprotected: Header,
    /// The payload, or `None` when detached.
    pub payload: Option<Vec<u8>>,
    tag: Vec<u8>,
    protected_raw: Vec<u8>,
    computed: bool,
}

impl Mac0Message {
    /// Creates a new message with the given payload.
    pub fn new(payload: Option<Vec<u8>>) -> Self {
        Mac0Message {
            payload,
            ..Default::default()
        }
    }

    /// The `MAC_structure` to be authenticated (RFC 9052 §6.3).
    fn to_be_maced(
        protected_raw: &[u8],
        external_aad: &[u8],
        payload: &Option<Vec<u8>>,
    ) -> Vec<u8> {
        util::encode_structure(vec![
            Value::from("MAC0"),
            Value::Bytes(protected_raw.to_vec()),
            Value::Bytes(external_aad.to_vec()),
            util::payload_value(payload),
        ])
    }

    /// Computes the authentication tag with `macer`.
    pub fn compute(&mut self, macer: &dyn Macer, external_aad: Option<&[u8]>) -> Result<(), Error> {
        util::ensure_protected_alg(&mut self.protected, macer.alg())?;
        util::ensure_unprotected_kid(&mut self.unprotected, macer.kid());

        self.protected_raw = encode_protected(&self.protected);
        let tbm = Self::to_be_maced(
            &self.protected_raw,
            external_aad.unwrap_or(&[]),
            &self.payload,
        );
        self.tag = macer.mac_create(&tbm)?;
        self.computed = true;
        Ok(())
    }

    /// Computes the tag and encodes the message to tagged COSE_Mac0 bytes.
    pub fn compute_and_encode(
        &mut self,
        macer: &dyn Macer,
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.compute(macer, external_aad)?;
        self.to_vec()
    }

    /// Encodes a computed message to tagged COSE_Mac0 bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        if !self.computed {
            return Err(Error::Custom(
                "Mac0Message must be computed before encoding".into(),
            ));
        }
        let wire = Mac0Wire(
            self.protected_raw.clone(),
            self.unprotected.clone(),
            self.payload.clone(),
            self.tag.clone(),
        );
        Ok(tag::with_tag(
            tag::MAC0_PREFIX,
            &cbor2::to_canonical_vec(&wire)?,
        ))
    }

    /// Decodes a COSE_Mac0 message (tagged or untagged) without verifying it.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::untag(data, tag::MAC0_PREFIX);
        let wire: Mac0Wire = cbor2::from_slice(body)?;
        let protected = decode_protected(&wire.0)?;
        Ok(Mac0Message {
            protected,
            unprotected: wire.1,
            payload: wire.2,
            tag: wire.3,
            protected_raw: wire.0,
            computed: true,
        })
    }

    /// Verifies the authentication tag with `macer`.
    pub fn verify(&self, macer: &dyn Macer, external_aad: Option<&[u8]>) -> Result<(), Error> {
        if !self.computed {
            return Err(Error::Custom(
                "Mac0Message must be decoded before verifying".into(),
            ));
        }
        util::check_protected_alg(&self.protected, macer.alg())?;
        let tbm = Self::to_be_maced(
            &self.protected_raw,
            external_aad.unwrap_or(&[]),
            &self.payload,
        );
        macer.mac_verify(&tbm, &self.tag)
    }

    /// Decodes and verifies a COSE_Mac0 message in one step.
    pub fn verify_and_decode(
        macer: &dyn Macer,
        data: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let msg = Self::from_slice(data)?;
        msg.verify(macer, external_aad)?;
        Ok(msg)
    }

    /// Returns the authentication tag (empty until computed/decoded).
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// The on-the-wire CBOR tag for COSE_Mac0.
    pub const TAG: u64 = iana::CBORTagCOSEMac0;
}
