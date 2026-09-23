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
        crate::strict::validate_map(data)?;
        let map = cbor2::from_slice::<BTreeMap<Label, Value>>(data)?;
        Ok(CoseMap(map))
    }

    /// Encodes the map to canonical (deterministic) CBOR bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        // Produces exactly `cbor2::to_canonical_vec(self)`. That function first
        // copies the whole map into a dynamic `Value`, which dominates the cost
        // for large headers such as SD-CWT disclosure lists. Only the entry
        // order and values containing maps, NaNs or bignums need normalizing;
        // the ordinary encoder already writes every other value canonically.
        let mut keys = Vec::new();
        let mut entries = Vec::with_capacity(self.0.len());
        for (label, value) in &self.0 {
            let start = keys.len();
            match label {
                Label::Int(value) if *value >= 0 => write_head(&mut keys, 0, value.unsigned_abs()),
                Label::Int(value) => write_head(&mut keys, 1, (-1 - *value).unsigned_abs()),
                Label::Text(text) => {
                    write_head(&mut keys, 3, text.len() as u64);
                    keys.extend_from_slice(text.as_bytes());
                }
            }
            entries.push((start..keys.len(), value));
        }
        entries.sort_unstable_by(|(a, _), (b, _)| keys[a.clone()].cmp(&keys[b.clone()]));

        let mut out = Vec::new();
        write_head(&mut out, 5, self.0.len() as u64);
        for (key, value) in entries {
            out.extend_from_slice(&keys[key]);
            if needs_canonicalization(value, cbor2::de::DEFAULT_RECURSION_LIMIT) {
                out.extend_from_slice(&cbor2::to_canonical_vec(value)?);
            } else {
                cbor2::to_writer(value, &mut out)?;
            }
        }
        Ok(out)
    }

    /// Deserializes a map whose encoding a strict pass already checked for
    /// duplicate keys at every depth, skipping the second strict pass.
    pub(crate) fn deserialize_checked<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        BTreeMap::<Label, Value>::deserialize(deserializer).map(CoseMap)
    }
}

/// Writes a CBOR head in its preferred (shortest) form.
fn write_head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let major = major << 5;
    if argument < 24 {
        out.push(major | argument as u8);
    } else if argument <= 0xff {
        out.extend_from_slice(&[major | 24, argument as u8]);
    } else if argument <= 0xffff {
        out.push(major | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= 0xffff_ffff {
        out.push(major | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

/// Returns whether deterministic encoding of `value` can differ from its
/// ordinary encoding: maps need sorting, NaNs and bignums normalizing.
/// Values nested beyond `depth` defer to the deterministic encoder.
fn needs_canonicalization(value: &Value, depth: usize) -> bool {
    if depth == 0 {
        return true;
    }
    match value {
        Value::Map(_) | Value::Tag(2 | 3, _) => true,
        Value::Float(value) => value.is_nan(),
        Value::Tag(_, inner) => needs_canonicalization(inner, depth - 1),
        Value::Array(items) => items
            .iter()
            .any(|item| needs_canonicalization(item, depth - 1)),
        _ => false,
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

        if deserializer.is_human_readable() {
            deserializer.deserialize_map(MapVisitor)
        } else {
            let raw = cbor2::RawValue::deserialize(deserializer)?;
            crate::strict::validate_map(raw.as_bytes()).map_err(serde::de::Error::custom)?;
            let map = cbor2::from_slice::<BTreeMap<Label, Value>>(raw.as_bytes())
                .map_err(serde::de::Error::custom)?;
            Ok(CoseMap(map))
        }
    }
}
