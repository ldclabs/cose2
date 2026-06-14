//! COSE headers.

use std::collections::btree_map;
use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{iana, CoseMap, Error, Label, Value};

/// A COSE `Headers` / `Generic_Headers` map (RFC 9052 §3).
///
/// The underlying representation is a [`CoseMap`], with header-specific
/// accessors for common parameters. It dereferences to `CoseMap` so custom
/// header parameters can still be inserted with raw labels and values.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Header(CoseMap);

impl Header {
    /// Creates an empty header map.
    pub fn new() -> Self {
        Header(CoseMap::new())
    }

    /// Decodes a header map from CBOR bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        Ok(Header(CoseMap::from_slice(data)?))
    }

    /// Encodes the header map to canonical CBOR bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        self.0.to_vec()
    }

    /// Returns a reference to the underlying map.
    pub fn as_map(&self) -> &CoseMap {
        &self.0
    }

    /// Returns a mutable reference to the underlying map.
    pub fn as_mut_map(&mut self) -> &mut CoseMap {
        &mut self.0
    }

    /// Consumes the header and returns the underlying map.
    pub fn into_map(self) -> CoseMap {
        self.0
    }

    /// Iterates over the `(label, value)` entries in label order.
    pub fn iter(&self) -> btree_map::Iter<'_, Label, Value> {
        self.0.iter()
    }

    /// Returns the algorithm identifier (`alg`, label 1), if present.
    ///
    /// COSE algorithm identifiers are `int / tstr`; this crate represents
    /// that shape with [`Label`].
    pub fn alg(&self) -> Result<Option<Label>, Error> {
        self.0.get_label(iana::HeaderParameterAlg)
    }

    /// Sets the algorithm identifier (`alg`, label 1).
    pub fn set_alg(&mut self, alg: impl Into<Label>) -> &mut Self {
        self.0
            .insert(iana::HeaderParameterAlg, Value::from(alg.into()));
        self
    }

    /// Returns the key identifier (`kid`, label 4), if present.
    pub fn kid(&self) -> Result<Option<&[u8]>, Error> {
        self.0.get_bytes(iana::HeaderParameterKid)
    }

    /// Sets the key identifier (`kid`, label 4).
    pub fn set_kid(&mut self, kid: impl Into<Vec<u8>>) -> &mut Self {
        self.0.insert(iana::HeaderParameterKid, kid.into());
        self
    }

    /// Returns the full initialization vector (`iv`, label 5), if present.
    pub fn iv(&self) -> Result<Option<&[u8]>, Error> {
        self.0.get_bytes(iana::HeaderParameterIV)
    }

    /// Sets the full initialization vector (`iv`, label 5).
    pub fn set_iv(&mut self, iv: impl Into<Vec<u8>>) -> &mut Self {
        self.0.insert(iana::HeaderParameterIV, iv.into());
        self
    }

    /// Returns the partial initialization vector (`Partial IV`, label 6), if present.
    pub fn partial_iv(&self) -> Result<Option<&[u8]>, Error> {
        self.0.get_bytes(iana::HeaderParameterPartialIV)
    }

    /// Sets the partial initialization vector (`Partial IV`, label 6).
    pub fn set_partial_iv(&mut self, partial_iv: impl Into<Vec<u8>>) -> &mut Self {
        self.0
            .insert(iana::HeaderParameterPartialIV, partial_iv.into());
        self
    }
}

impl From<CoseMap> for Header {
    fn from(value: CoseMap) -> Self {
        Header(value)
    }
}

impl From<Header> for CoseMap {
    fn from(value: Header) -> Self {
        value.0
    }
}

impl FromIterator<(Label, Value)> for Header {
    fn from_iter<T: IntoIterator<Item = (Label, Value)>>(iter: T) -> Self {
        Header(CoseMap::from_iter(iter))
    }
}

impl Deref for Header {
    type Target = CoseMap;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Header {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize for Header {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Header {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        CoseMap::deserialize(deserializer).map(Header)
    }
}

/// Encodes a header as the `protected` byte string used inside COSE messages.
///
/// Per RFC 9052, an empty protected header is encoded as a zero-length byte
/// string rather than as the encoding of an empty map.
pub(crate) fn encode_protected(header: &Header) -> Result<Vec<u8>, Error> {
    if header.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(cbor2::to_canonical_vec(header)?)
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
