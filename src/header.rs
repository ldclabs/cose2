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

    /// Returns the content type (`content type`, label 3), if present.
    ///
    /// The value is `tstr / uint` (RFC 9052 §3.1); this crate represents that
    /// shape with [`Label`].
    pub fn content_type(&self) -> Result<Option<Label>, Error> {
        self.0.get_label(iana::HeaderParameterContentType)
    }

    /// Sets the content type (`content type`, label 3).
    pub fn set_content_type(&mut self, content_type: impl Into<Label>) -> &mut Self {
        self.0.insert(
            iana::HeaderParameterContentType,
            Value::from(content_type.into()),
        );
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

    /// Returns the critical protected header labels (`crit`, label 2), if present.
    pub fn crit(&self) -> Result<Option<Vec<Label>>, Error> {
        labels_from_value(self.0.get(iana::HeaderParameterCrit))
    }

    /// Sets the critical protected header labels (`crit`, label 2).
    pub fn set_crit<I, L>(&mut self, labels: I) -> &mut Self
    where
        I: IntoIterator<Item = L>,
        L: Into<Label>,
    {
        let labels = labels
            .into_iter()
            .map(|label| Value::from(label.into()))
            .collect::<Vec<_>>();
        self.0.insert(iana::HeaderParameterCrit, labels);
        self
    }

    /// Enforces RFC 9052 §3.1 critical-header processing: every label listed in
    /// `crit` must be understood, otherwise processing the message is a fatal
    /// error.
    ///
    /// A label is considered understood when it is one of the common header
    /// parameters this crate models natively (see [`is_understood_header`]) or
    /// when the caller lists it in `understood`. Applications that process
    /// untrusted messages SHOULD call this on the protected header of each
    /// layer (and each `COSE_Signature`) after decoding, passing the
    /// application-specific labels they are able to process.
    ///
    /// Returns `Ok(())` when there is no `crit` parameter or when every listed
    /// label is understood.
    pub fn ensure_crit_understood(&self, understood: &[Label]) -> Result<(), Error> {
        let Some(crit) = self.crit()? else {
            return Ok(());
        };
        for label in crit {
            if is_understood_header(&label) || understood.contains(&label) {
                continue;
            }
            return Err(Error::Custom(format!(
                "unsupported critical header parameter {label}"
            )));
        }
        Ok(())
    }
}

/// Returns `true` when `label` is a common header parameter this crate models
/// natively and therefore always understands (RFC 9052 §3.1: "Header
/// parameters defined in [RFC 9052] do not need to be included [in `crit`]").
pub fn is_understood_header(label: &Label) -> bool {
    matches!(
        label,
        Label::Int(
            iana::HeaderParameterAlg
                | iana::HeaderParameterCrit
                | iana::HeaderParameterContentType
                | iana::HeaderParameterKid
                | iana::HeaderParameterIV
                | iana::HeaderParameterPartialIV
        )
    )
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

/// Validates the RFC 9052 rules that require both header buckets.
pub(crate) fn validate_header_buckets(
    protected: &Header,
    unprotected: &Header,
) -> Result<(), Error> {
    for (label, _) in protected.iter() {
        if unprotected.contains_key(label.clone()) {
            return Err(Error::Custom(format!(
                "header label {label} appears in both protected and unprotected buckets"
            )));
        }
    }

    if unprotected.contains_key(iana::HeaderParameterCrit) {
        return Err(Error::Custom(
            "crit header parameter must be protected".into(),
        ));
    }

    if let Some(crit) = protected.crit()? {
        if crit.is_empty() {
            return Err(Error::Custom(
                "crit header parameter must not be empty".into(),
            ));
        }
        for label in crit {
            if !protected.contains_key(label.clone()) {
                return Err(Error::Custom(format!(
                    "crit references absent protected header label {label}"
                )));
            }
        }
    }

    Ok(())
}

fn labels_from_value(value: Option<&Value>) -> Result<Option<Vec<Label>>, Error> {
    let Some(Value::Array(values)) = value else {
        return match value {
            None => Ok(None),
            Some(_) => Err(Error::UnexpectedType(
                "crit must be an array of labels".into(),
            )),
        };
    };

    let mut labels = Vec::with_capacity(values.len());
    for value in values {
        labels.push(label_from_value(value)?);
    }
    Ok(Some(labels))
}

fn label_from_value(value: &Value) -> Result<Label, Error> {
    match value {
        Value::Integer(i) => i64::try_from(*i)
            .map(Label::Int)
            .map_err(|_| Error::UnexpectedType("integer label out of range".into())),
        Value::Text(s) => Ok(Label::Text(s.clone())),
        _ => Err(Error::UnexpectedType(
            "expected an integer or text string label".into(),
        )),
    }
}
