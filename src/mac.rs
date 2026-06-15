//! COSE_Mac: MACed message with recipients (RFC 9052 §6.1).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected, validate_header_buckets},
    iana,
    recipient::validate_recipient_list,
    tag, util, Error, Header, Label, Macer, Recipient, Value,
};

/// The on-the-wire COSE_Mac array: `[protected, unprotected, payload, tag, recipients]`.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(tag = 97, array)]
struct MacWire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    unprotected: Header,
    #[serde(with = "serde_bytes")]
    payload: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    tag: Vec<u8>,
    recipients: Vec<Recipient>,
}

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

    /// Encodes the `MAC_structure` to be authenticated (RFC 9052 §6.3).
    ///
    /// This is the low-level helper for external or async MAC code. New
    /// messages should usually call [`prepare_tag`](Self::prepare_tag) or
    /// [`prepare_detached_tag`](Self::prepare_detached_tag) so the protected
    /// header bytes stored in the message match the bytes being MACed.
    pub fn to_be_maced(
        protected_raw: &[u8],
        external_aad: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        util::encode_structure(vec![
            Value::from("MAC"),
            Value::Bytes(protected_raw.to_vec()),
            Value::Bytes(external_aad.to_vec()),
            util::payload_value(payload),
        ])
    }

    /// Prepares this embedded-payload message for an externally produced tag.
    ///
    /// The returned bytes are the `MAC_structure` that must be MACed. After an
    /// async or remote MAC service returns the tag bytes, call
    /// [`set_tag`](Self::set_tag) and then [`to_vec`](Self::to_vec).
    pub fn prepare_tag(
        &mut self,
        alg: Option<Label>,
        kid: Option<&[u8]>,
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let payload =
            util::require_embedded_payload(&self.payload, "MacMessage::prepare_tag")?.to_vec();
        self.prepare_tag_payload(alg, kid, &payload, external_aad.unwrap_or(&[]))
    }

    /// Prepares this detached-payload message for an externally produced tag.
    ///
    /// The message's on-the-wire payload is set to `nil`; `detached_payload` is
    /// used only in the `MAC_structure`.
    pub fn prepare_detached_tag(
        &mut self,
        alg: Option<Label>,
        kid: Option<&[u8]>,
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let tbm =
            self.prepare_tag_payload(alg, kid, detached_payload, external_aad.unwrap_or(&[]))?;
        self.payload = None;
        Ok(tbm)
    }

    fn prepare_tag_payload(
        &mut self,
        alg: Option<Label>,
        kid: Option<&[u8]>,
        payload: &[u8],
        external_aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if self.recipients.is_empty() {
            return Err(Error::Custom("MacMessage has no recipients".into()));
        }
        validate_recipient_list(&self.recipients)?;
        util::ensure_protected_alg(&mut self.protected, alg)?;
        util::ensure_unprotected_kid(&mut self.unprotected, kid);
        validate_header_buckets(&self.protected, &self.unprotected)?;

        let protected_raw = encode_protected(&self.protected)?;
        let tbm = Self::to_be_maced(&protected_raw, external_aad, payload)?;
        self.protected_raw = protected_raw;
        self.tag.clear();
        self.computed = false;
        Ok(tbm)
    }

    /// Stores externally produced tag bytes on this message.
    pub fn set_tag(&mut self, tag: impl Into<Vec<u8>>) -> Result<(), Error> {
        if self.recipients.is_empty() {
            return Err(Error::Custom("MacMessage has no recipients".into()));
        }
        validate_recipient_list(&self.recipients)?;
        validate_header_buckets(&self.protected, &self.unprotected)?;
        if self.protected_raw.is_empty() && !self.protected.is_empty() {
            self.protected_raw = encode_protected(&self.protected)?;
        }
        self.tag = tag.into();
        self.computed = true;
        Ok(())
    }

    /// Computes the authentication tag with `macer`.
    pub fn compute(&mut self, macer: &dyn Macer, external_aad: Option<&[u8]>) -> Result<(), Error> {
        let payload =
            util::require_embedded_payload(&self.payload, "MacMessage::compute")?.to_vec();
        self.compute_payload(macer, &payload, external_aad.unwrap_or(&[]))
    }

    /// Computes the authentication tag over a detached payload.
    ///
    /// The message's on-the-wire payload is set to `nil`; `detached_payload`
    /// is used only in the `MAC_structure`.
    pub fn compute_detached(
        &mut self,
        macer: &dyn Macer,
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.compute_payload(macer, detached_payload, external_aad.unwrap_or(&[]))?;
        self.payload = None;
        Ok(())
    }

    fn compute_payload(
        &mut self,
        macer: &dyn Macer,
        payload: &[u8],
        external_aad: &[u8],
    ) -> Result<(), Error> {
        let tbm = self.prepare_tag_payload(macer.alg(), macer.kid(), payload, external_aad)?;
        let tag = macer.mac_create(&tbm)?;
        self.set_tag(tag)
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

    /// Computes a detached-payload tag and encodes the message to tagged COSE_Mac bytes.
    pub fn compute_detached_and_encode(
        &mut self,
        macer: &dyn Macer,
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.compute_detached(macer, detached_payload, external_aad)?;
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
        validate_recipient_list(&self.recipients)?;
        validate_header_buckets(&self.protected, &self.unprotected)?;
        let wire = MacWire {
            protected: self.protected_raw.clone(),
            unprotected: self.unprotected.clone(),
            payload: self.payload.clone(),
            tag: self.tag.clone(),
            recipients: self.recipients.clone(),
        };
        Ok(cbor2::to_canonical_vec(&wire)?)
    }

    /// Decodes a COSE_Mac message (tagged or untagged) without verifying it.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::strip_message_wrappers(data);
        if !body.starts_with(tag::MAC_PREFIX) && tag::starts_with_cbor_tag(body) {
            return Err(Error::Custom("unexpected CBOR tag for COSE_Mac".into()));
        }
        let wire: MacWire = cbor2::from_slice(body)?;
        if wire.recipients.is_empty() {
            return Err(Error::Custom("MacMessage has no recipients".into()));
        }
        validate_recipient_list(&wire.recipients)?;
        let protected = decode_protected(&wire.protected)?;
        validate_header_buckets(&protected, &wire.unprotected)?;
        Ok(MacMessage {
            protected,
            unprotected: wire.unprotected,
            payload: wire.payload,
            recipients: wire.recipients,
            tag: wire.tag,
            protected_raw: wire.protected,
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
        let payload = util::require_embedded_payload(&self.payload, "MacMessage::verify")?;
        self.verify_payload(macer, payload, external_aad.unwrap_or(&[]))
    }

    /// Verifies the authentication tag over a detached payload.
    pub fn verify_detached(
        &self,
        macer: &dyn Macer,
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        if !self.computed {
            return Err(Error::Custom(
                "MacMessage must be decoded before verifying".into(),
            ));
        }
        if self.payload.is_some() {
            return Err(Error::Custom(
                "MacMessage carries an embedded payload; use verify".into(),
            ));
        }
        self.verify_payload(macer, detached_payload, external_aad.unwrap_or(&[]))
    }

    fn verify_payload(
        &self,
        macer: &dyn Macer,
        payload: &[u8],
        external_aad: &[u8],
    ) -> Result<(), Error> {
        util::check_protected_alg(&self.protected, macer.alg())?;
        let tbm = Self::to_be_maced(&self.protected_raw, external_aad, payload)?;
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

    /// Decodes and verifies a detached-payload COSE_Mac message in one step.
    pub fn verify_detached_and_decode(
        macer: &dyn Macer,
        data: &[u8],
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let msg = Self::from_slice(data)?;
        msg.verify_detached(macer, detached_payload, external_aad)?;
        Ok(msg)
    }

    /// Returns the authentication tag (empty until computed/decoded).
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Returns the protected-header bytes used in the MAC structure.
    pub fn protected_raw(&self) -> &[u8] {
        &self.protected_raw
    }

    /// The on-the-wire CBOR tag for COSE_Mac.
    pub const TAG: u64 = iana::CBORTagCOSEMac;
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
        assert_cbor_shape::<MacWire>(Some(iana::CBORTagCOSEMac), true);
    }
}
