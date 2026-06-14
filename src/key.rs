//! COSE_Key objects and key sets (RFC 9052 §7).

use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{iana, CoseMap, Error};

/// A COSE_Key object: a [`CoseMap`] with key-specific accessors.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-key-objects>.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Key(pub CoseMap);

impl Key {
    /// Creates an empty key.
    pub fn new() -> Self {
        Key(CoseMap::new())
    }

    /// Decodes a key from CBOR bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        Ok(Key(CoseMap::from_slice(data)?))
    }

    /// Encodes the key to canonical CBOR bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        self.0.to_vec()
    }

    /// Returns the key type (`kty`, label 1).
    pub fn kty(&self) -> Result<Option<i64>, Error> {
        self.0.get_i64(iana::KeyParameterKty)
    }

    /// Sets the key type.
    pub fn set_kty(&mut self, kty: i64) -> &mut Self {
        self.0.insert(iana::KeyParameterKty, kty);
        self
    }

    /// Returns the key identifier (`kid`, label 2).
    pub fn kid(&self) -> Result<Option<&[u8]>, Error> {
        self.0.get_bytes(iana::KeyParameterKid)
    }

    /// Sets the key identifier.
    pub fn set_kid(&mut self, kid: impl Into<Vec<u8>>) -> &mut Self {
        self.0.insert(iana::KeyParameterKid, kid.into());
        self
    }

    /// Returns the algorithm (`alg`, label 3).
    pub fn alg(&self) -> Result<Option<i64>, Error> {
        self.0.get_i64(iana::KeyParameterAlg)
    }

    /// Sets the algorithm.
    pub fn set_alg(&mut self, alg: i64) -> &mut Self {
        self.0.insert(iana::KeyParameterAlg, alg);
        self
    }

    /// Returns the key operations (`key_ops`, label 4) as a list of integers.
    pub fn ops(&self) -> Result<Option<Vec<i64>>, Error> {
        match self.0.get_array(iana::KeyParameterKeyOps)? {
            None => Ok(None),
            Some(values) => {
                let mut ops = Vec::with_capacity(values.len());
                for v in values {
                    match v {
                        crate::Value::Integer(i) => ops.push(i64::try_from(*i).map_err(|_| {
                            Error::UnexpectedType("key_ops integer out of range".into())
                        })?),
                        _ => {
                            return Err(Error::UnexpectedType(
                                "key_ops must be an array of integers".into(),
                            ))
                        }
                    }
                }
                Ok(Some(ops))
            }
        }
    }

    /// Sets the key operations.
    pub fn set_ops(&mut self, ops: &[i64]) -> &mut Self {
        let values: Vec<crate::Value> = ops.iter().map(|&op| crate::Value::from(op)).collect();
        self.0.insert(iana::KeyParameterKeyOps, values);
        self
    }

    /// Returns the base IV (`Base IV`, label 5).
    pub fn base_iv(&self) -> Result<Option<&[u8]>, Error> {
        self.0.get_bytes(iana::KeyParameterBaseIV)
    }
}

impl Deref for Key {
    type Target = CoseMap;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Key {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        CoseMap::deserialize(deserializer).map(Key)
    }
}

/// A set of [`Key`] objects (a COSE_KeySet, encoded as a CBOR array).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeySet(pub Vec<Key>);

impl KeySet {
    /// Creates an empty key set.
    pub fn new() -> Self {
        KeySet(Vec::new())
    }

    /// Decodes a key set from CBOR bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        Ok(cbor2::from_slice(data)?)
    }

    /// Encodes the key set to canonical CBOR bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        Ok(cbor2::to_canonical_vec(self)?)
    }

    /// Returns the first key whose `kid` matches, if any.
    pub fn lookup(&self, kid: &[u8]) -> Option<&Key> {
        self.0
            .iter()
            .find(|k| matches!(k.kid(), Ok(Some(id)) if id == kid))
    }
}

impl Deref for KeySet {
    type Target = Vec<Key>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for KeySet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
