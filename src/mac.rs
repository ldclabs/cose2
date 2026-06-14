//! COSE_Mac: MACed message with recipients (RFC 9052 §6.1).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected},
    iana, tag, util, Error, Header, Macer, Recipient, Value,
};

/// The on-the-wire COSE_Mac array: `[protected, unprotected, payload, tag, recipients]`.
#[derive(Clone, Debug, PartialEq, Cbor)]
struct MacWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    Header,
    #[serde(with = "serde_bytes")] Option<Vec<u8>>,
    #[serde(with = "serde_bytes")] Vec<u8>,
    Vec<Recipient>,
);

/// A COSE_Mac message (MAC with one or more recipients).
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-maced-message-with-recipien>.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MacMessage {
    /// Protected header parameters (e.g. `alg`).
    pub protected: Header,
    /// Unprotected header parameters.
    pub unprotected: Header,
    /// The payload, or `None` when detached.
    pub payload: Option<Vec<u8>>,
    /// The recipients that can recover the MAC key.
    pub recipients: Vec<Recipient>,
    tag: Vec<u8>,
    protected_raw: Vec<u8>,
    computed: bool,
}

impl MacMessage {
    /// Creates a new message with the given payload.
    pub fn new(payload: Option<Vec<u8>>) -> Self {
        MacMessage {
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
            Value::from("MAC"),
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

    /// Computes the tag and encodes the message to tagged COSE_Mac bytes.
    pub fn compute_and_encode(
        &mut self,
        macer: &dyn Macer,
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.compute(macer, external_aad)?;
        self.to_vec()
    }

    /// Encodes a computed message to tagged COSE_Mac bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        if !self.computed {
            return Err(Error::Custom(
                "MacMessage must be computed before encoding".into(),
            ));
        }
        if self.recipients.is_empty() {
            return Err(Error::Custom("MacMessage has no recipients".into()));
        }
        let wire = MacWire(
            self.protected_raw.clone(),
            self.unprotected.clone(),
            self.payload.clone(),
            self.tag.clone(),
            self.recipients.clone(),
        );
        Ok(tag::with_tag(
            tag::MAC_PREFIX,
            &cbor2::to_canonical_vec(&wire)?,
        ))
    }

    /// Decodes a COSE_Mac message (tagged or untagged) without verifying it.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::untag(data, tag::MAC_PREFIX);
        let wire: MacWire = cbor2::from_slice(body)?;
        if wire.4.is_empty() {
            return Err(Error::Custom("MacMessage has no recipients".into()));
        }
        let protected = decode_protected(&wire.0)?;
        Ok(MacMessage {
            protected,
            unprotected: wire.1,
            payload: wire.2,
            recipients: wire.4,
            tag: wire.3,
            protected_raw: wire.0,
            computed: true,
        })
    }

    /// Verifies the authentication tag with `macer`.
    pub fn verify(&self, macer: &dyn Macer, external_aad: Option<&[u8]>) -> Result<(), Error> {
        if !self.computed {
            return Err(Error::Custom(
                "MacMessage must be decoded before verifying".into(),
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

    /// Decodes and verifies a COSE_Mac message in one step.
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

    /// The on-the-wire CBOR tag for COSE_Mac.
    pub const TAG: u64 = iana::CBORTagCOSEMac;
}
