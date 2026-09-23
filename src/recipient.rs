//! COSE_recipient (RFC 9052 §5.1).

use std::borrow::Cow;

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
    /// Direct use of a content-encryption key.
    Direct,
    /// Direct shared secret followed by a KDF.
    DirectKeyDerivation,
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
#[derive(Clone, Debug, Default)]
pub struct Recipient {
    /// Protected header parameters.
    pub protected: Header,
    /// Unprotected header parameters.
    pub unprotected: Header,
    /// The encrypted key (or `None`/empty when absent).
    pub ciphertext: Option<Vec<u8>>,
    /// Nested recipients (the second layer of recipient information).
    pub recipients: Vec<Recipient>,
    protected_raw: Option<Vec<u8>>,
}

impl PartialEq for Recipient {
    fn eq(&self, other: &Self) -> bool {
        self.protected == other.protected
            && self.unprotected == other.unprotected
            && self.ciphertext == other.ciphertext
            && self.recipients == other.recipients
    }
}

impl Recipient {
    /// Creates an empty recipient.
    pub fn new() -> Self {
        Recipient::default()
    }

    /// Decodes a recipient from CBOR bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        crate::strict::validate_array(data)?;
        let recipient: Recipient = cbor2::from_slice(data)?;
        recipient.validate()?;
        Ok(recipient)
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

    /// Returns the decoded protected-header bytes, when this recipient came
    /// from the wire. Newly built recipients return `None`.
    pub fn protected_raw(&self) -> Option<&[u8]> {
        self.protected_raw.as_deref()
    }

    fn header_value(&self, label: i64) -> Option<&crate::Value> {
        self.protected
            .get(label)
            .or_else(|| self.unprotected.get(label))
    }

    fn has_zero_length_protected_field(&self) -> bool {
        self.protected.is_empty()
    }

    fn require_salt_or_party_u_nonce(&self, algorithm: &str) -> Result<(), Error> {
        let salt = self.header_value(iana::HeaderAlgorithmParameterSalt);
        let nonce = self.header_value(iana::HeaderAlgorithmParameterPartyUNonce);
        if salt.is_some_and(|value| !matches!(value, crate::Value::Bytes(_))) {
            return Err(Error::UnexpectedType(
                "recipient salt must be a byte string".into(),
            ));
        }
        if nonce.is_some_and(|value| {
            !matches!(value, crate::Value::Bytes(_) | crate::Value::Integer(_))
        }) {
            return Err(Error::UnexpectedType(
                "recipient PartyU nonce must be a byte string or integer".into(),
            ));
        }
        let has_unique_input = matches!(salt, Some(crate::Value::Bytes(value)) if !value.is_empty())
            || matches!(nonce, Some(crate::Value::Bytes(value)) if !value.is_empty())
            || matches!(nonce, Some(crate::Value::Integer(_)));
        if !has_unique_input {
            return Err(Error::Custom(format!(
                "{algorithm} requires a non-empty salt or PartyU nonce"
            )));
        }
        Ok(())
    }

    fn require_sender_key(&self, ephemeral: bool, algorithm: i64) -> Result<(), Error> {
        if ephemeral {
            let value = self
                .header_value(iana::HeaderAlgorithmParameterEphemeralKey)
                .ok_or_else(|| {
                    Error::Custom("ECDH-ES recipient is missing ephemeral key".into())
                })?;
            let key = crate::Key::try_from(value.clone())?;
            validate_ecdh_public_key(&key, algorithm)?;
        } else {
            let static_key = self.header_value(iana::HeaderAlgorithmParameterStaticKey);
            let static_id = self.header_value(iana::HeaderAlgorithmParameterStaticKeyId);
            if static_key.is_none() && static_id.is_none() {
                return Err(Error::Custom(
                    "ECDH-SS recipient is missing static key or static key id".into(),
                ));
            }
            if let Some(value) = static_key {
                let key = crate::Key::try_from(value.clone())?;
                validate_ecdh_public_key(&key, algorithm)?;
            }
            if static_id.is_some_and(|value| !matches!(value, crate::Value::Bytes(_))) {
                return Err(Error::UnexpectedType(
                    "recipient static key id must be a byte string".into(),
                ));
            }
            self.require_salt_or_party_u_nonce("ECDH-SS recipient")?;
        }
        Ok(())
    }

    /// Validates RFC 9052 recipient-layer structural requirements.
    pub fn validate(&self) -> Result<(), Error> {
        self.validate_at_depth(0)
    }

    fn validate_at_depth(&self, depth: usize) -> Result<(), Error> {
        if depth > MAX_RECIPIENT_DEPTH {
            return Err(Error::limit("COSE recipient nesting", MAX_RECIPIENT_DEPTH));
        }
        self.validate_local()?;
        for recipient in &self.recipients {
            recipient.validate_at_depth(depth + 1)?;
        }
        Ok(())
    }

    fn validate_local(&self) -> Result<(), Error> {
        validate_header_buckets(&self.protected, &self.unprotected)?;
        if let Some(raw) = &self.protected_raw {
            crate::header::validate_protected_state(&self.protected, raw)?;
        }
        let alg = self
            .alg()?
            .ok_or_else(|| Error::Custom("COSE_recipient is missing alg".into()))?;

        match classify_recipient_algorithm(&alg) {
            Some(RecipientAlgorithmClass::Direct) => {
                if !self.has_zero_length_protected_field() {
                    return Err(Error::Custom(
                        "direct COSE_recipient requires a zero-length protected field".into(),
                    ));
                }
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
            Some(RecipientAlgorithmClass::DirectKeyDerivation) => {
                if !matches!(self.ciphertext.as_deref(), Some([])) {
                    return Err(Error::Custom(
                        "direct KDF COSE_recipient requires zero-length ciphertext".into(),
                    ));
                }
                if !self.recipients.is_empty() {
                    return Err(Error::Custom(
                        "direct KDF COSE_recipient must not contain nested recipients".into(),
                    ));
                }
                self.require_salt_or_party_u_nonce("direct KDF recipient")?;
            }
            Some(RecipientAlgorithmClass::KeyWrap) => {
                if !self.has_zero_length_protected_field() {
                    return Err(Error::Custom(
                        "key-wrap COSE_recipient requires empty protected headers".into(),
                    ));
                }
                if self.unprotected.alg()?.is_none() {
                    return Err(Error::Custom(
                        "key-wrap COSE_recipient requires alg in unprotected headers".into(),
                    ));
                }
                if self.ciphertext.as_ref().is_none_or(Vec::is_empty) {
                    return Err(Error::Custom(
                        "key-wrap COSE_recipient requires encrypted key ciphertext".into(),
                    ));
                }
            }
            Some(RecipientAlgorithmClass::KeyTransport) => {
                if !self.has_zero_length_protected_field() {
                    return Err(Error::Custom(
                        "key-transport COSE_recipient requires empty protected headers".into(),
                    ));
                }
                if self.unprotected.alg()?.is_none() {
                    return Err(Error::Custom(
                        "key-transport COSE_recipient requires alg in unprotected headers".into(),
                    ));
                }
                if self.ciphertext.as_ref().is_none_or(Vec::is_empty) {
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
                let Label::Int(alg) = alg else {
                    unreachable!();
                };
                self.require_sender_key(
                    matches!(
                        alg,
                        iana::AlgorithmECDH_ES_HKDF_256 | iana::AlgorithmECDH_ES_HKDF_512
                    ),
                    alg,
                )?;
            }
            Some(RecipientAlgorithmClass::KeyAgreementWithKeyWrap)
                if self.ciphertext.as_ref().is_none_or(Vec::is_empty) =>
            {
                return Err(Error::Custom(
                    "key-agreement-with-key-wrap COSE_recipient requires encrypted key ciphertext"
                        .into(),
                ));
            }
            Some(RecipientAlgorithmClass::KeyAgreementWithKeyWrap) => {
                let Label::Int(alg) = alg else {
                    unreachable!();
                };
                self.require_sender_key(
                    matches!(
                        alg,
                        iana::AlgorithmECDH_ES_A128KW
                            | iana::AlgorithmECDH_ES_A192KW
                            | iana::AlgorithmECDH_ES_A256KW
                    ),
                    alg,
                )?;
            }
            None => {}
        }

        validate_recipient_layer_rules(&self.recipients)
    }
}

fn validate_ecdh_public_key(key: &crate::Key, algorithm: i64) -> Result<(), Error> {
    if let Some(key_algorithm) = key.alg()? {
        if key_algorithm != Label::Int(algorithm) {
            return Err(Error::AlgorithmMismatch {
                declared: key_algorithm.to_string(),
                expected: Label::Int(algorithm).to_string(),
            });
        }
    }
    if key.ops()?.is_some_and(|operations| !operations.is_empty()) {
        return Err(Error::KeyOperation(
            "an ECDH sender public key must have absent or empty key_ops".into(),
        ));
    }

    let key_type = match key.kty()? {
        Some(Label::Int(key_type)) => key_type,
        Some(other) => {
            return Err(Error::custom(format!(
                "ECDH sender key must use EC2 or OKP, got {other}"
            )));
        }
        None => return Err(Error::custom("ECDH sender key is missing kty")),
    };
    let (curve, x_label, private_label) = match key_type {
        iana::KeyTypeEC2 => (
            ecdh_curve(key, iana::EC2KeyParameterCrv)?,
            iana::EC2KeyParameterX,
            iana::EC2KeyParameterD,
        ),
        iana::KeyTypeOKP => (
            ecdh_curve(key, iana::OKPKeyParameterCrv)?,
            iana::OKPKeyParameterX,
            iana::OKPKeyParameterD,
        ),
        _ => {
            return Err(Error::custom(format!(
                "ECDH sender key must use EC2 or OKP, got {}",
                Label::Int(key_type)
            )));
        }
    };
    if key.contains_key(private_label) {
        return Err(Error::custom(
            "ECDH sender key header parameter must not contain private key material",
        ));
    }

    let expected_length = match (key_type, curve) {
        (iana::KeyTypeEC2, iana::EllipticCurveP_256) => 32,
        (iana::KeyTypeEC2, iana::EllipticCurveP_384) => 48,
        (iana::KeyTypeEC2, iana::EllipticCurveP_521) => 66,
        (iana::KeyTypeOKP, iana::EllipticCurveX25519) => 32,
        (iana::KeyTypeOKP, iana::EllipticCurveX448) => 56,
        _ => {
            return Err(Error::custom(
                "ECDH sender key has a curve incompatible with its key type",
            ));
        }
    };
    let x = key
        .get_bytes(x_label)?
        .ok_or_else(|| Error::custom("ECDH sender public key is missing x"))?;
    if x.len() != expected_length {
        return Err(Error::custom(format!(
            "ECDH sender public key x must be {expected_length} bytes"
        )));
    }
    if key_type == iana::KeyTypeEC2 {
        match key.get(iana::EC2KeyParameterY) {
            Some(crate::Value::Bytes(y)) if y.len() == expected_length => {}
            Some(crate::Value::Bool(_)) => {}
            Some(_) => {
                return Err(Error::UnexpectedType(format!(
                    "ECDH EC2 public key y must be {expected_length} bytes or a sign bit"
                )));
            }
            None => return Err(Error::custom("ECDH EC2 sender public key is missing y")),
        }
    }
    Ok(())
}

fn ecdh_curve(key: &crate::Key, label: i64) -> Result<i64, Error> {
    match key.get_label(label)? {
        Some(Label::Int(curve)) => Ok(curve),
        Some(Label::Text(_)) => Err(Error::UnexpectedType(
            "ECDH sender key curve must be a registered integer".into(),
        )),
        None => Err(Error::custom("ECDH sender key is missing curve")),
    }
}

const MAX_RECIPIENT_DEPTH: usize = 128;

/// Fully validates a message's recipient list, which must not be empty.
pub(crate) fn validate_message_recipients(
    recipients: &[Recipient],
    message: &str,
) -> Result<(), Error> {
    require_recipients(recipients, message)?;
    for recipient in recipients {
        recipient.validate_at_depth(0)?;
    }
    validate_recipient_layer_rules(recipients)
}

/// Validates a decoded message's recipient list. `Recipient`'s deserializer
/// already validated every recipient and nested layer, and the strict message
/// pass bounded their nesting, so only the top layer's rules remain.
pub(crate) fn validate_decoded_recipients(
    recipients: &[Recipient],
    message: &str,
) -> Result<(), Error> {
    require_recipients(recipients, message)?;
    validate_recipient_layer_rules(recipients)
}

fn require_recipients(recipients: &[Recipient], message: &str) -> Result<(), Error> {
    if recipients.is_empty() {
        Err(Error::Custom(format!("{message} has no recipients")))
    } else {
        Ok(())
    }
}

fn validate_recipient_layer_rules(recipients: &[Recipient]) -> Result<(), Error> {
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
            Some(RecipientAlgorithmClass::DirectKeyDerivation) => {
                return Err(Error::Custom(
                    "direct KDF COSE_recipient must be the only recipient in its layer".into(),
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
        self.validate_local().map_err(S::Error::custom)?;
        let protected_raw: Cow<'_, [u8]> = match &self.protected_raw {
            Some(raw) => {
                crate::header::validate_protected_state(&self.protected, raw)
                    .map_err(S::Error::custom)?;
                Cow::Borrowed(raw)
            }
            None => Cow::Owned(encode_protected(&self.protected).map_err(S::Error::custom)?),
        };
        let len = if self.recipients.is_empty() { 3 } else { 4 };
        let mut seq = serializer.serialize_seq(Some(len))?;
        seq.serialize_element(serde_bytes::Bytes::new(protected_raw.as_ref()))?;
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
                let protected_raw: crate::strict::StrictBytes = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing protected header"))?;
                let unprotected: Header = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing unprotected header"))?;
                let ciphertext: crate::strict::StrictOptionalBytes = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing ciphertext"))?;
                let recipients = seq.next_element::<Vec<Recipient>>()?;
                if recipients.as_ref().is_some_and(Vec::is_empty) {
                    return Err(A::Error::custom(
                        "nested recipients array must not be empty when present",
                    ));
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::invalid_length(5, &self));
                }

                let protected = decode_protected(&protected_raw.0).map_err(A::Error::custom)?;
                validate_header_buckets(&protected, &unprotected).map_err(A::Error::custom)?;
                let recipient = Recipient {
                    protected,
                    unprotected,
                    ciphertext: ciphertext.0,
                    recipients: recipients.unwrap_or_default(),
                    protected_raw: Some(protected_raw.0),
                };
                recipient.validate_local().map_err(A::Error::custom)?;
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
        iana::AlgorithmDirect => Some(RecipientAlgorithmClass::Direct),
        iana::AlgorithmDirect_HKDF_SHA_256
        | iana::AlgorithmDirect_HKDF_SHA_512
        | iana::AlgorithmDirect_HKDF_AES_128
        | iana::AlgorithmDirect_HKDF_AES_256 => Some(RecipientAlgorithmClass::DirectKeyDerivation),
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
