//! [`CoseMap`]: the ordered integer/text-keyed map underlying COSE headers,
//! keys and CWT claims.

use std::collections::{btree_map, BTreeMap};

use serde::{
    de::{MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{Error, Label, Value};

/// A map from [`Label`] to [`Value`], the common representation of COSE
/// header, key and CWT-claim maps (RFC 9052 / RFC 8392).
///
/// Keys are kept sorted by [`Label`]. Serializing a `CoseMap` produces a CBOR
/// map; [`CoseMap::to_vec`] uses canonical (deterministic) encoding so the
/// bytes are reproducible.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseMap(BTreeMap<Label, Value>);

impl CoseMap {
    /// Creates an empty map.
    pub fn new() -> Self {
        CoseMap(BTreeMap::new())
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the map has no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns `true` if the map contains the given label.
    pub fn contains_key(&self, key: impl Into<Label>) -> bool {
        self.0.contains_key(&key.into())
    }

    /// Returns the raw [`Value`] for a label, if present.
    pub fn get(&self, key: impl Into<Label>) -> Option<&Value> {
        self.0.get(&key.into())
    }

    /// Inserts a value, returning the previous value for the label if any.
    pub fn insert(&mut self, key: impl Into<Label>, value: impl Into<Value>) -> Option<Value> {
        self.0.insert(key.into(), value.into())
    }

    /// Removes and returns the value for a label, if present.
    pub fn remove(&mut self, key: impl Into<Label>) -> Option<Value> {
        self.0.remove(&key.into())
    }

    /// Iterates over the `(label, value)` entries in label order.
    pub fn iter(&self) -> btree_map::Iter<'_, Label, Value> {
        self.0.iter()
    }

    /// Returns the value for a label as an `i64`.
    ///
    /// Returns `Ok(None)` when the label is absent and an
    /// [`Error::UnexpectedType`] when the value is not an in-range integer.
    pub fn get_i64(&self, key: impl Into<Label>) -> Result<Option<i64>, Error> {
        match self.0.get(&key.into()) {
            None => Ok(None),
            Some(Value::Integer(i)) => i64::try_from(*i)
                .map(Some)
                .map_err(|_| Error::UnexpectedType("integer out of i64 range".into())),
            Some(_) => Err(Error::UnexpectedType("expected an integer".into())),
        }
    }

    /// Returns the value for a label as a byte string.
    pub fn get_bytes(&self, key: impl Into<Label>) -> Result<Option<&[u8]>, Error> {
        match self.0.get(&key.into()) {
            None => Ok(None),
            Some(Value::Bytes(b)) => Ok(Some(b)),
            Some(_) => Err(Error::UnexpectedType("expected a byte string".into())),
        }
    }

    /// Returns the value for a label as a text string.
    pub fn get_text(&self, key: impl Into<Label>) -> Result<Option<&str>, Error> {
        match self.0.get(&key.into()) {
            None => Ok(None),
            Some(Value::Text(s)) => Ok(Some(s)),
            Some(_) => Err(Error::UnexpectedType("expected a text string".into())),
        }
    }

    /// Returns the value for a label as an `int / tstr` COSE identifier.
    pub fn get_label(&self, key: impl Into<Label>) -> Result<Option<Label>, Error> {
        match self.0.get(&key.into()) {
            None => Ok(None),
            Some(Value::Integer(i)) => i64::try_from(*i)
                .map(Label::Int)
                .map(Some)
                .map_err(|_| Error::UnexpectedType("integer out of i64 range".into())),
            Some(Value::Text(s)) => Ok(Some(Label::Text(s.clone()))),
            Some(_) => Err(Error::UnexpectedType(
                "expected an integer or text string".into(),
            )),
        }
    }

    /// Returns the value for a label as a boolean.
    pub fn get_bool(&self, key: impl Into<Label>) -> Result<Option<bool>, Error> {
        match self.0.get(&key.into()) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(Error::UnexpectedType("expected a boolean".into())),
        }
    }

    /// Returns the value for a label as a CBOR array.
    pub fn get_array(&self, key: impl Into<Label>) -> Result<Option<&[Value]>, Error> {
        match self.0.get(&key.into()) {
            None => Ok(None),
            Some(Value::Array(a)) => Ok(Some(a)),
            Some(_) => Err(Error::UnexpectedType("expected an array".into())),
        }
    }

    /// Decodes a `CoseMap` from CBOR bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        Ok(cbor2::from_slice(data)?)
    }

    /// Encodes the map to canonical (deterministic) CBOR bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        Ok(cbor2::to_canonical_vec(self)?)
    }
}

impl FromIterator<(Label, Value)> for CoseMap {
    fn from_iter<T: IntoIterator<Item = (Label, Value)>>(iter: T) -> Self {
        CoseMap(BTreeMap::from_iter(iter))
    }
}

impl<'a> IntoIterator for &'a CoseMap {
    type Item = (&'a Label, &'a Value);
    type IntoIter = btree_map::Iter<'a, Label, Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for CoseMap {
    type Item = (Label, Value);
    type IntoIter = btree_map::IntoIter<Label, Value>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Serialize for CoseMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for CoseMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MapVisitor;

        impl<'de> Visitor<'de> for MapVisitor {
            type Value = CoseMap;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a COSE map keyed by integers or text strings")
            }

            fn visit_map<A>(self, mut access: A) -> Result<CoseMap, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<Label, Value>()? {
                    if map.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate COSE map label"));
                    }
                }
                Ok(CoseMap(map))
            }
        }

        deserializer.deserialize_map(MapVisitor)
    }
}
