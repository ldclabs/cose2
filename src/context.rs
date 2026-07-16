//! COSE_KDF_Context and its sub-structures (RFC 9053 §5.2).

use cbor2::Cbor;
use serde::{
    de::{Error as DeError, IgnoredAny, SeqAccess, Visitor},
    ser::{Error as _, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{
    header::{decode_protected, encode_protected},
    Error, Header, Label,
};

/// A `PartyInfo` nonce: `bstr / int` (RFC 9053 §5.2, where the field is
/// `bstr / int / nil`; absence is modeled with `Option`).
///
/// Integer nonces are modeled as `i64`; a CBOR integer outside that range
/// is rejected during decode with an "out of range" error.
#[derive(Clone, Debug, PartialEq)]
pub enum PartyNonce {
    /// A byte-string nonce.
    Bytes(Vec<u8>),
    /// An integer nonce.
    Int(i64),
}

impl From<Vec<u8>> for PartyNonce {
    fn from(value: Vec<u8>) -> Self {
        PartyNonce::Bytes(value)
    }
}

impl From<&[u8]> for PartyNonce {
    fn from(value: &[u8]) -> Self {
        PartyNonce::Bytes(value.to_vec())
    }
}

impl From<i64> for PartyNonce {
    fn from(value: i64) -> Self {
        PartyNonce::Int(value)
    }
}

impl Serialize for PartyNonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            PartyNonce::Bytes(b) => serializer.serialize_bytes(b),
            PartyNonce::Int(i) => serializer.serialize_i64(*i),
        }
    }
}

impl<'de> Deserialize<'de> for PartyNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NonceVisitor;

        impl Visitor<'_> for NonceVisitor {
            type Value = PartyNonce;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a byte string or integer PartyInfo nonce")
            }

            fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<PartyNonce, E> {
                Ok(PartyNonce::Bytes(v.to_vec()))
            }

            fn visit_byte_buf<E: DeError>(self, v: Vec<u8>) -> Result<PartyNonce, E> {
                Ok(PartyNonce::Bytes(v))
            }

            fn visit_i64<E: DeError>(self, v: i64) -> Result<PartyNonce, E> {
                Ok(PartyNonce::Int(v))
            }

            fn visit_u64<E: DeError>(self, v: u64) -> Result<PartyNonce, E> {
                i64::try_from(v)
                    .map(PartyNonce::Int)
                    .map_err(|_| E::custom("integer nonce out of range"))
            }

            fn visit_i128<E: DeError>(self, v: i128) -> Result<PartyNonce, E> {
                i64::try_from(v)
                    .map(PartyNonce::Int)
                    .map_err(|_| E::custom("integer nonce out of range"))
            }

            fn visit_u128<E: DeError>(self, v: u128) -> Result<PartyNonce, E> {
                i64::try_from(v)
                    .map(PartyNonce::Int)
                    .map_err(|_| E::custom("integer nonce out of range"))
            }
        }

        deserializer.deserialize_any(NonceVisitor)
    }
}

/// A `PartyInfo` array `[identity, nonce, other]` (RFC 9053 §5.2).
///
/// `identity` and `other` are byte strings or `null`; `nonce` is a byte
/// string, an integer, or `null`.
#[derive(Clone, Debug, Default, PartialEq, Cbor)]
#[cbor(array)]
pub struct PartyInfo {
    /// Party identity information.
    #[serde(with = "serde_bytes")]
    pub identity: Option<Vec<u8>>,
    /// Party-provided nonce.
    pub nonce: Option<PartyNonce>,
    /// Other party-provided information.
    #[serde(with = "serde_bytes")]
    pub other: Option<Vec<u8>>,
}

/// A `SuppPubInfo` structure: `[keyDataLength, protected, ?other]`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SuppPubInfo {
    /// Length of the derived key material, in bits.
    pub key_data_length: u64,
    /// The protected header of the enclosing structure.
    pub protected: Header,
    /// Optional other supplemental public information.
    pub other: Option<Vec<u8>>,
}

impl Serialize for SuppPubInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let protected_raw = encode_protected(&self.protected).map_err(S::Error::custom)?;
        let len = if self.other.is_some() { 3 } else { 2 };
        let mut seq = serializer.serialize_seq(Some(len))?;
        seq.serialize_element(&self.key_data_length)?;
        seq.serialize_element(serde_bytes::Bytes::new(&protected_raw))?;
        if let Some(other) = &self.other {
            seq.serialize_element(serde_bytes::Bytes::new(other))?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for SuppPubInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SuppPubInfoVisitor;

        impl<'de> Visitor<'de> for SuppPubInfoVisitor {
            type Value = SuppPubInfo;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a SuppPubInfo array of 2 or 3 elements")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<SuppPubInfo, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let key_data_length: u64 = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing keyDataLength"))?;
                let protected_raw: serde_bytes::ByteBuf = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing protected header"))?;
                let other = seq.next_element::<serde_bytes::ByteBuf>()?;
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::invalid_length(4, &self));
                }
                let protected = decode_protected(&protected_raw).map_err(A::Error::custom)?;
                Ok(SuppPubInfo {
                    key_data_length,
                    protected,
                    other: other.map(|o| o.into_vec()),
                })
            }
        }

        deserializer.deserialize_seq(SuppPubInfoVisitor)
    }
}

/// A COSE_KDF_Context structure (RFC 9053 §5.2):
/// `[AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo, ?SuppPrivInfo]`.
#[derive(Clone, Debug, PartialEq)]
pub struct KdfContext {
    /// Identifier of the algorithm the derived key is used with
    /// (`int / tstr`, RFC 9053 §5.2).
    pub algorithm_id: Label,
    /// Information about party U.
    pub party_u_info: PartyInfo,
    /// Information about party V.
    pub party_v_info: PartyInfo,
    /// Supplemental public information.
    pub supp_pub_info: SuppPubInfo,
    /// Optional supplemental private information.
    pub supp_priv_info: Option<Vec<u8>>,
}

impl KdfContext {
    /// Decodes a context from CBOR bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        Ok(cbor2::from_slice(data)?)
    }

    /// Encodes the context to canonical CBOR bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        Ok(cbor2::to_canonical_vec(self)?)
    }
}

impl Serialize for KdfContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let len = if self.supp_priv_info.is_some() { 5 } else { 4 };
        let mut seq = serializer.serialize_seq(Some(len))?;
        seq.serialize_element(&self.algorithm_id)?;
        seq.serialize_element(&self.party_u_info)?;
        seq.serialize_element(&self.party_v_info)?;
        seq.serialize_element(&self.supp_pub_info)?;
        if let Some(priv_info) = &self.supp_priv_info {
            seq.serialize_element(serde_bytes::Bytes::new(priv_info))?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for KdfContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KdfContextVisitor;

        impl<'de> Visitor<'de> for KdfContextVisitor {
            type Value = KdfContext;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a COSE_KDF_Context array of 4 or 5 elements")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<KdfContext, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let algorithm_id: Label = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing AlgorithmID"))?;
                let party_u_info: PartyInfo = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing PartyUInfo"))?;
                let party_v_info: PartyInfo = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing PartyVInfo"))?;
                let supp_pub_info: SuppPubInfo = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing SuppPubInfo"))?;
                let supp_priv_info = seq.next_element::<serde_bytes::ByteBuf>()?;
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::invalid_length(6, &self));
                }
                Ok(KdfContext {
                    algorithm_id,
                    party_u_info,
                    party_v_info,
                    supp_pub_info,
                    supp_priv_info: supp_priv_info.map(|p| p.into_vec()),
                })
            }
        }

        deserializer.deserialize_seq(KdfContextVisitor)
    }
}
