//! COSE_Mac0: MAC without recipients (RFC 9052 §6.2).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected, validate_header_buckets},
    iana, tag, util, Error, Header, Macer, Value,
};

/// The on-the-wire COSE_Mac0 array: `[protected, unprotected, payload, tag]`.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(tag = 17, array)]
struct Mac0Wire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    unprotected: Header,
    #[serde(with = "serde_bytes")]
    payload: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    tag: Vec<u8>,
}

/// Untagged COSE_Mac0, accepted for compatibility with untagged transports.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(array)]
struct Mac0BareWire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    unprotected: Header,
    #[serde(with = "serde_bytes")]
    payload: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    tag: Vec<u8>,
}

impl From<Mac0BareWire> for Mac0Wire {
    fn from(value: Mac0BareWire) -> Self {
        Mac0Wire {
            protected: value.protected,
            unprotected: value.unprotected,
            payload: value.payload,
            tag: value.tag,
        }
    }
}

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
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        util::encode_structure(vec![
            Value::from("MAC0"),
            Value::Bytes(protected_raw.to_vec()),
            Value::Bytes(external_aad.to_vec()),
            util::payload_value(payload),
        ])
    }

    /// Computes the authentication tag with `macer`.
    pub fn compute(&mut self, macer: &dyn Macer, external_aad: Option<&[u8]>) -> Result<(), Error> {
        let payload =
            util::require_embedded_payload(&self.payload, "Mac0Message::compute")?.to_vec();
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
        util::ensure_protected_alg(&mut self.protected, macer.alg())?;
        util::ensure_unprotected_kid(&mut self.unprotected, macer.kid());
        validate_header_buckets(&self.protected, &self.unprotected)?;

        self.protected_raw = encode_protected(&self.protected)?;
        let tbm = Self::to_be_maced(&self.protected_raw, external_aad, payload)?;
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

    /// Computes a detached-payload tag and encodes the message.
    pub fn compute_detached_and_encode(
        &mut self,
        macer: &dyn Macer,
        detached_payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.compute_detached(macer, detached_payload, external_aad)?;
        self.to_vec()
    }

    /// Encodes a computed message to tagged COSE_Mac0 bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        if !self.computed {
            return Err(Error::Custom(
                "Mac0Message must be computed before encoding".into(),
            ));
        }
        validate_header_buckets(&self.protected, &self.unprotected)?;
        let wire = Mac0Wire {
            protected: self.protected_raw.clone(),
            unprotected: self.unprotected.clone(),
            payload: self.payload.clone(),
            tag: self.tag.clone(),
        };
        Ok(cbor2::to_canonical_vec(&wire)?)
    }

    /// Decodes a COSE_Mac0 message (tagged or untagged) without verifying it.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::strip_message_wrappers(data);
        let wire: Mac0Wire = if body.starts_with(tag::MAC0_PREFIX) {
            cbor2::from_slice(body)?
        } else if tag::starts_with_cbor_tag(body) {
            return Err(Error::Custom("unexpected CBOR tag for COSE_Mac0".into()));
        } else {
            cbor2::from_slice::<Mac0BareWire>(body)?.into()
        };
        let protected = decode_protected(&wire.protected)?;
        validate_header_buckets(&protected, &wire.unprotected)?;
        Ok(Mac0Message {
            protected,
            unprotected: wire.unprotected,
            payload: wire.payload,
            tag: wire.tag,
            protected_raw: wire.protected,
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
        let payload = util::require_embedded_payload(&self.payload, "Mac0Message::verify")?;
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
                "Mac0Message must be decoded before verifying".into(),
            ));
        }
        if self.payload.is_some() {
            return Err(Error::Custom(
                "Mac0Message carries an embedded payload; use verify".into(),
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

    /// Decodes and verifies a detached-payload COSE_Mac0 message in one step.
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

    /// The on-the-wire CBOR tag for COSE_Mac0.
    pub const TAG: u64 = iana::CBORTagCOSEMac0;
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
        assert_cbor_shape::<Mac0Wire>(Some(iana::CBORTagCOSEMac0), true);
        assert_cbor_shape::<Mac0BareWire>(None, true);
    }
}
