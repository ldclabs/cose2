//! COSE headers.

use crate::{CoseMap, Error};

/// A COSE `Generic_Headers` map (RFC 9052 §3).
///
/// Both protected and unprotected headers are represented as a
/// [`CoseMap`]. Use the [`iana`](crate::iana) header-parameter constants as
/// labels, e.g. [`iana::HeaderParameterAlg`](crate::iana::HeaderParameterAlg).
pub type Header = CoseMap;

/// Encodes a header as the `protected` byte string used inside COSE messages.
///
/// Per RFC 9052, an empty protected header is encoded as a zero-length byte
/// string rather than as the encoding of an empty map. A `CoseMap` of CBOR
/// values always serializes, so this is infallible.
pub(crate) fn encode_protected(header: &Header) -> Vec<u8> {
    if header.is_empty() {
        Vec::new()
    } else {
        cbor2::to_canonical_vec(header).unwrap_or_default()
    }
}

/// Decodes the `protected` byte string of a COSE message into a [`Header`].
///
/// A zero-length byte string decodes to an empty header.
pub(crate) fn decode_protected(data: &[u8]) -> Result<Header, Error> {
    if data.is_empty() {
        Ok(Header::new())
    } else {
        Header::from_slice(data)
    }
}
