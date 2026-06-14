//! COSE_recipient (RFC 9052 §5.1).

use serde::{
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
    ser::{Error as _, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{
    header::{decode_protected, encode_protected},
    Error, Header,
};

/// A COSE_recipient structure.
///
/// Encoded as `[protected, unprotected, ciphertext]`, or
/// `[protected, unprotected, ciphertext, [+recipient]]` when it carries
/// nested recipients.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Recipient {
    /// Protected header parameters.
    pub protected: Header,
    /// Unprotected header parameters.
    pub unprotected: Header,
    /// The encrypted key (or `None`/empty when absent).
    pub ciphertext: Option<Vec<u8>>,
    /// Nested recipients (the second layer of recipient information).
    pub recipients: Vec<Recipient>,
}

impl Recipient {
    /// Creates an empty recipient.
    pub fn new() -> Self {
        Recipient::default()
    }

    /// Decodes a recipient from CBOR bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        Ok(cbor2::from_slice(data)?)
    }

    /// Encodes the recipient to canonical CBOR bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        Ok(cbor2::to_canonical_vec(self)?)
    }
}

impl Serialize for Recipient {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let protected_raw = encode_protected(&self.protected).map_err(S::Error::custom)?;
        let len = if self.recipients.is_empty() { 3 } else { 4 };
        let mut seq = serializer.serialize_seq(Some(len))?;
        seq.serialize_element(serde_bytes::Bytes::new(&protected_raw))?;
        seq.serialize_element(&self.unprotected)?;
        match &self.ciphertext {
            Some(c) => seq.serialize_element(&Some(serde_bytes::Bytes::new(c)))?,
            None => seq.serialize_element(&Option::<&serde_bytes::Bytes>::None)?,
        }
        if !self.recipients.is_empty() {
            seq.serialize_element(&self.recipients)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Recipient {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RecipientVisitor;

        impl<'de> Visitor<'de> for RecipientVisitor {
            type Value = Recipient;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a COSE_recipient array of 3 or 4 elements")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Recipient, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let protected_raw: serde_bytes::ByteBuf = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing protected header"))?;
                let unprotected: Header = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing unprotected header"))?;
                let ciphertext: Option<serde_bytes::ByteBuf> = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing ciphertext"))?;
                let recipients = seq.next_element::<Vec<Recipient>>()?.unwrap_or_default();
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::invalid_length(5, &self));
                }

                let protected = decode_protected(&protected_raw).map_err(A::Error::custom)?;
                Ok(Recipient {
                    protected,
                    unprotected,
                    ciphertext: ciphertext.map(|c| c.into_vec()),
                    recipients,
                })
            }
        }

        deserializer.deserialize_seq(RecipientVisitor)
    }
}
