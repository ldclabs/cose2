//! COSE_Key objects and key sets (RFC 9052 §7).

use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{iana, CoseMap, Error, Label, Value};

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
        let key = Key(CoseMap::from_slice(data)?);
        key.validate()?;
        Ok(key)
    }

    /// Encodes the key to canonical CBOR bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        self.0.to_vec()
    }

    /// Returns the key type (`kty`, label 1).
    pub fn kty(&self) -> Result<Option<Label>, Error> {
        self.0.get_label(iana::KeyParameterKty)
    }

    /// Sets the key type.
    pub fn set_kty(&mut self, kty: impl Into<Label>) -> &mut Self {
        self.0.insert(iana::KeyParameterKty, kty.into());
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
    pub fn alg(&self) -> Result<Option<Label>, Error> {
        self.0.get_label(iana::KeyParameterAlg)
    }

    /// Sets the algorithm.
    pub fn set_alg(&mut self, alg: impl Into<Label>) -> &mut Self {
        self.0.insert(iana::KeyParameterAlg, alg.into());
        self
    }

    /// Returns the key operations (`key_ops`, label 4) as a list of labels.
    pub fn ops(&self) -> Result<Option<Vec<Label>>, Error> {
        match self.0.get_array(iana::KeyParameterKeyOps)? {
            None => Ok(None),
            Some(values) => {
                let mut ops = Vec::with_capacity(values.len());
                for v in values {
                    match v {
                        Value::Integer(i) => {
                            ops.push(Label::Int(i64::try_from(*i).map_err(|_| {
                                Error::UnexpectedType("key_ops integer out of range".into())
                            })?))
                        }
                        Value::Text(s) => ops.push(Label::Text(s.clone())),
                        _ => {
                            return Err(Error::UnexpectedType(
                                "key_ops must be an array of integer or text labels".into(),
                            ))
                        }
                    }
                }
                Ok(Some(ops))
            }
        }
    }

    /// Returns whether `key_ops` permits at least one registered operation.
    /// An absent `key_ops` parameter imposes no restriction.
    pub fn allows_any_operation(&self, operations: &[i64]) -> Result<bool, Error> {
        if operations.is_empty() {
            return Ok(false);
        }
        let Some(configured) = self.ops()? else {
            return Ok(true);
        };
        Ok(configured
            .iter()
            .any(|operation| matches!(operation, Label::Int(value) if operations.contains(value))))
    }

    /// Requires `key_ops`, when present, to permit one of `operations`.
    #[cfg(any(
        feature = "crypto-ring",
        feature = "crypto-aws-lc-rs",
        feature = "crypto-ed25519-dalek"
    ))]
    pub(crate) fn require_any_operation(
        &self,
        operations: &[i64],
        operation_name: &str,
    ) -> Result<(), Error> {
        if self.allows_any_operation(operations)? {
            Ok(())
        } else {
            Err(Error::KeyOperation(format!(
                "COSE_Key key_ops does not permit {operation_name}"
            )))
        }
    }

    #[cfg(any(
        feature = "crypto-ring",
        feature = "crypto-aws-lc-rs",
        feature = "crypto-aes-gcm"
    ))]
    pub(crate) fn required_integer_alg(&self, provider: &str) -> Result<i64, Error> {
        match self.alg()? {
            Some(Label::Int(alg)) => Ok(alg),
            Some(Label::Text(_)) => Err(Error::custom(format!(
                "the built-in {provider} does not support text-string algorithms"
            ))),
            None => Err(Error::custom("COSE_Key is missing alg")),
        }
    }

    #[cfg(any(
        feature = "crypto-ring",
        feature = "crypto-aws-lc-rs",
        feature = "crypto-ed25519-dalek",
        feature = "crypto-aes-gcm"
    ))]
    pub(crate) fn require_integer_kty(&self, expected: i64) -> Result<(), Error> {
        match self.kty()? {
            Some(Label::Int(kty)) if kty == expected => Ok(()),
            Some(other) => Err(Error::custom(format!(
                "COSE_Key kty mismatch, expected {}, got {other}",
                Label::from(expected)
            ))),
            None => Err(Error::custom("COSE_Key is missing kty")),
        }
    }

    #[cfg(any(
        feature = "crypto-ring",
        feature = "crypto-aws-lc-rs",
        feature = "crypto-ed25519-dalek"
    ))]
    pub(crate) fn require_integer_parameter(
        &self,
        label: i64,
        expected: i64,
        name: &str,
    ) -> Result<(), Error> {
        match self.get_label(label)? {
            Some(Label::Int(value)) if value == expected => Ok(()),
            Some(other) => Err(Error::custom(format!(
                "COSE_Key {name} mismatch, expected {}, got {other}",
                Label::from(expected)
            ))),
            None => Err(Error::custom(format!("COSE_Key is missing {name}"))),
        }
    }

    #[cfg(any(
        feature = "crypto-ring",
        feature = "crypto-aws-lc-rs",
        feature = "crypto-ed25519-dalek",
        feature = "crypto-aes-gcm"
    ))]
    pub(crate) fn required_bytes(&self, label: i64, name: &str) -> Result<&[u8], Error> {
        self.get_bytes(label)?
            .ok_or_else(|| Error::custom(format!("COSE_Key is missing {name}")))
    }

    #[cfg(any(
        feature = "crypto-ring",
        feature = "crypto-aws-lc-rs",
        feature = "crypto-ed25519-dalek",
        feature = "crypto-aes-gcm"
    ))]
    pub(crate) fn kid_owned(&self) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.kid()?.map(ToOwned::to_owned))
    }

    /// Sets the key operations.
    pub fn set_ops<I, L>(&mut self, ops: I) -> &mut Self
    where
        I: IntoIterator<Item = L>,
        L: Into<Label>,
    {
        let values: Vec<Value> = ops.into_iter().map(|op| Value::from(op.into())).collect();
        self.0.insert(iana::KeyParameterKeyOps, values);
        self
    }

    /// Returns the base IV (`Base IV`, label 5).
    pub fn base_iv(&self) -> Result<Option<&[u8]>, Error> {
        self.0.get_bytes(iana::KeyParameterBaseIV)
    }

    /// Checks RFC 9052 key-object invariants enforced by this crate.
    pub fn validate(&self) -> Result<(), Error> {
        if self.kty()?.is_none() {
            return Err(Error::Custom("COSE_Key is missing required kty".into()));
        }
        let _ = self.alg()?;
        let _ = self.ops()?;
        let _ = self.kid()?;
        let _ = self.base_iv()?;
        Ok(())
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
        self.validate().map_err(serde::ser::Error::custom)?;
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = Key(CoseMap::deserialize(deserializer)?);
        key.validate().map_err(serde::de::Error::custom)?;
        Ok(key)
    }
}

impl TryFrom<Value> for Key {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let bytes = cbor2::to_canonical_vec(&value)?;
        let key = Key(CoseMap::from_slice(&bytes)?);
        key.validate()?;
        Ok(key)
    }
}

/// A set of [`Key`] objects (a COSE_KeySet, encoded as a CBOR array).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KeySet(pub Vec<Key>);

impl KeySet {
    /// Creates an empty key set.
    pub fn new() -> Self {
        KeySet(Vec::new())
    }

    /// Decodes a key set from CBOR bytes.
    ///
    /// Entries are processed independently as required by RFC 9052: malformed
    /// or unsupported entries are ignored, while valid keys remain available.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let members = crate::strict::independently_validated_array_members(data)?;
        let keys = members
            .into_iter()
            .filter_map(|member| Key::from_slice(member).ok())
            .collect();
        let key_set = KeySet(keys);
        key_set.validate()?;
        Ok(key_set)
    }

    /// Compatibility alias for the RFC-compliant [`KeySet::from_slice`].
    pub fn from_slice_lenient(data: &[u8]) -> Result<Self, Error> {
        Self::from_slice(data)
    }

    /// Decodes a key set and rejects the entire set if any entry is malformed.
    pub fn from_slice_strict(data: &[u8]) -> Result<Self, Error> {
        crate::strict::validate_array(data)?;
        let keys = cbor2::from_slice::<Vec<Key>>(data)?;
        let key_set = KeySet(keys);
        key_set.validate()?;
        Ok(key_set)
    }

    /// Encodes the key set to canonical CBOR bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        Ok(cbor2::to_canonical_vec(self)?)
    }

    /// Returns all keys whose `kid` matches.
    pub fn lookup<'a>(&'a self, kid: &'a [u8]) -> impl Iterator<Item = &'a Key> + 'a {
        self.0
            .iter()
            .filter(move |k| matches!(k.kid(), Ok(Some(id)) if id == kid))
    }

    /// Checks RFC 9052 key-set invariants enforced by this crate.
    pub fn validate(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            return Err(Error::Custom(
                "COSE_KeySet must contain at least one key".into(),
            ));
        }
        for key in &self.0 {
            key.validate()?;
        }
        Ok(())
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

impl Serialize for KeySet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeySet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let key_set = KeySet(Vec::<Key>::deserialize(deserializer)?);
            key_set.validate().map_err(serde::de::Error::custom)?;
            Ok(key_set)
        } else {
            let raw = cbor2::RawValue::deserialize(deserializer)?;
            KeySet::from_slice(raw.as_bytes()).map_err(serde::de::Error::custom)
        }
    }
}
