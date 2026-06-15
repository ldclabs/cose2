//! COSE_recipient (RFC 9052 §5.1).

use serde::{
    de::{Error as _, IgnoredAny, SeqAccess, Visitor},
    ser::{Error as _, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{
    header::{decode_protected, encode_protected, validate_header_buckets},
    iana, Error, Header, Label,
};

/// The recipient algorithm class implied by a registered COSE algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecipientAlgorithmClass {
    /// Direct encryption or direct key derivation.
    Direct,
    /// AES Key Wrap.
    KeyWrap,
    /// Public-key transport.
    KeyTransport,
    /// Direct ECDH key agreement.
    DirectKeyAgreement,
    /// ECDH key agreement followed by key wrap.
    KeyAgreementWithKeyWrap,
}

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
        self.validate()?;
        Ok(cbor2::to_canonical_vec(self)?)
    }

    /// Returns the recipient algorithm from protected or unprotected headers.
    pub fn alg(&self) -> Result<Option<Label>, Error> {
        match self.protected.alg()? {
            Some(alg) => Ok(Some(alg)),
            None => self.unprotected.alg(),
        }
    }

    /// Returns the registered recipient algorithm class, if this crate knows it.
    pub fn algorithm_class(&self) -> Result<Option<RecipientAlgorithmClass>, Error> {
        Ok(self.alg()?.as_ref().and_then(classify_recipient_algorithm))
    }

    /// Validates RFC 9052 recipient-layer structural requirements.
    pub fn validate(&self) -> Result<(), Error> {
        validate_header_buckets(&self.protected, &self.unprotected)?;
        let alg = self
            .alg()?
            .ok_or_else(|| Error::Custom("COSE_recipient is missing alg".into()))?;

        match classify_recipient_algorithm(&alg) {
            Some(RecipientAlgorithmClass::Direct) => {
                if !matches!(self.ciphertext.as_deref(), Some([])) {
                    return Err(Error::Custom(
                        "direct COSE_recipient requires zero-length ciphertext".into(),
                    ));
                }
                if !self.recipients.is_empty() {
                    return Err(Error::Custom(
                        "direct COSE_recipient must not contain nested recipients".into(),
                    ));
                }
            }
            Some(RecipientAlgorithmClass::KeyWrap) => {
                if !self.protected.is_empty() {
                    return Err(Error::Custom(
                        "key-wrap COSE_recipient requires empty protected headers".into(),
                    ));
                }
                if self.unprotected.alg()?.is_none() {
                    return Err(Error::Custom(
                        "key-wrap COSE_recipient requires alg in unprotected headers".into(),
                    ));
                }
                if self.ciphertext.is_none() {
                    return Err(Error::Custom(
                        "key-wrap COSE_recipient requires encrypted key ciphertext".into(),
                    ));
                }
            }
            Some(RecipientAlgorithmClass::KeyTransport) => {
                if !self.protected.is_empty() {
                    return Err(Error::Custom(
                        "key-transport COSE_recipient requires empty protected headers".into(),
                    ));
                }
                if self.unprotected.alg()?.is_none() {
                    return Err(Error::Custom(
                        "key-transport COSE_recipient requires alg in unprotected headers".into(),
                    ));
                }
                if self.ciphertext.is_none() {
                    return Err(Error::Custom(
                        "key-transport COSE_recipient requires encrypted key ciphertext".into(),
                    ));
                }
                if !self.recipients.is_empty() {
                    return Err(Error::Custom(
                        "key-transport COSE_recipient must not contain nested recipients".into(),
                    ));
                }
            }
            Some(RecipientAlgorithmClass::DirectKeyAgreement) => {
                if !matches!(self.ciphertext.as_deref(), Some([])) {
                    return Err(Error::Custom(
                        "direct key-agreement COSE_recipient requires zero-length ciphertext"
                            .into(),
                    ));
                }
                if !self.recipients.is_empty() {
                    return Err(Error::Custom(
                        "direct key-agreement COSE_recipient must not contain nested recipients"
                            .into(),
                    ));
                }
            }
            Some(RecipientAlgorithmClass::KeyAgreementWithKeyWrap) if self.ciphertext.is_none() => {
                return Err(Error::Custom(
                    "key-agreement-with-key-wrap COSE_recipient requires encrypted key ciphertext"
                        .into(),
                ));
            }
            Some(RecipientAlgorithmClass::KeyAgreementWithKeyWrap) => {}
            None => {}
        }

        validate_recipient_list(&self.recipients)?;
        Ok(())
    }
}

pub(crate) fn validate_recipient_list(recipients: &[Recipient]) -> Result<(), Error> {
    for recipient in recipients {
        recipient.validate()?;
    }

    if recipients.len() <= 1 {
        return Ok(());
    }

    for recipient in recipients {
        match recipient.algorithm_class()? {
            Some(RecipientAlgorithmClass::Direct) => {
                return Err(Error::Custom(
                    "direct COSE_recipient must be the only recipient in its layer".into(),
                ));
            }
            Some(RecipientAlgorithmClass::DirectKeyAgreement) => {
                return Err(Error::Custom(
                    "direct key-agreement COSE_recipient must be the only recipient in its layer"
                        .into(),
                ));
            }
            Some(_) | None => {}
        }
    }

    Ok(())
}

impl Serialize for Recipient {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(S::Error::custom)?;
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
                validate_header_buckets(&protected, &unprotected).map_err(A::Error::custom)?;
                let recipient = Recipient {
                    protected,
                    unprotected,
                    ciphertext: ciphertext.map(|c| c.into_vec()),
                    recipients,
                };
                recipient.validate().map_err(A::Error::custom)?;
                Ok(recipient)
            }
        }

        deserializer.deserialize_seq(RecipientVisitor)
    }
}

fn classify_recipient_algorithm(alg: &Label) -> Option<RecipientAlgorithmClass> {
    let Label::Int(alg) = alg else {
        return None;
    };
    match *alg {
        iana::AlgorithmDirect
        | iana::AlgorithmDirect_HKDF_SHA_256
        | iana::AlgorithmDirect_HKDF_SHA_512
        | iana::AlgorithmDirect_HKDF_AES_128
        | iana::AlgorithmDirect_HKDF_AES_256 => Some(RecipientAlgorithmClass::Direct),
        iana::AlgorithmA128KW | iana::AlgorithmA192KW | iana::AlgorithmA256KW => {
            Some(RecipientAlgorithmClass::KeyWrap)
        }
        iana::AlgorithmRSAES_OAEP_RFC_8017_default
        | iana::AlgorithmRSAES_OAEP_SHA_256
        | iana::AlgorithmRSAES_OAEP_SHA_512 => Some(RecipientAlgorithmClass::KeyTransport),
        iana::AlgorithmECDH_ES_HKDF_256
        | iana::AlgorithmECDH_ES_HKDF_512
        | iana::AlgorithmECDH_SS_HKDF_256
        | iana::AlgorithmECDH_SS_HKDF_512 => Some(RecipientAlgorithmClass::DirectKeyAgreement),
        iana::AlgorithmECDH_ES_A128KW
        | iana::AlgorithmECDH_ES_A192KW
        | iana::AlgorithmECDH_ES_A256KW
        | iana::AlgorithmECDH_SS_A128KW
        | iana::AlgorithmECDH_SS_A192KW
        | iana::AlgorithmECDH_SS_A256KW => Some(RecipientAlgorithmClass::KeyAgreementWithKeyWrap),
        _ => None,
    }
}
