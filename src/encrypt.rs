//! COSE_Encrypt: encryption with recipients (RFC 9052 §5.1).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected},
    iana, tag, util, Encryptor, Error, Header, Recipient, Value,
};

/// The on-the-wire COSE_Encrypt array: `[protected, unprotected, ciphertext, recipients]`.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(tag = 96, array)]
struct EncryptWire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    unprotected: Header,
    #[serde(with = "serde_bytes")]
    ciphertext: Option<Vec<u8>>,
    recipients: Vec<Recipient>,
}

/// Untagged COSE_Encrypt, accepted for compatibility with untagged transports.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(array)]
struct EncryptBareWire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    unprotected: Header,
    #[serde(with = "serde_bytes")]
    ciphertext: Option<Vec<u8>>,
    recipients: Vec<Recipient>,
}

impl From<EncryptBareWire> for EncryptWire {
    fn from(value: EncryptBareWire) -> Self {
        EncryptWire {
            protected: value.protected,
            unprotected: value.unprotected,
            ciphertext: value.ciphertext,
            recipients: value.recipients,
        }
    }
}

/// A COSE_Encrypt message (encryption with one or more recipients).
///
/// As with [`Encrypt0Message`](crate::Encrypt0Message), the full IV must be
/// present in the unprotected header before encrypting.
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-enveloped-cose-structure>.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EncryptMessage {
    /// Protected header parameters (e.g. `alg`).
    pub protected: Header,
    /// Unprotected header parameters (e.g. `iv`).
    pub unprotected: Header,
    /// The plaintext payload (set after a successful [`decrypt`](Self::decrypt)).
    pub payload: Option<Vec<u8>>,
    /// The recipients that can recover the content-encryption key.
    pub recipients: Vec<Recipient>,
    ciphertext: Vec<u8>,
    protected_raw: Vec<u8>,
    encrypted: bool,
}

impl EncryptMessage {
    /// Creates a new message with the given plaintext payload.
    pub fn new(payload: Option<Vec<u8>>) -> Self {
        EncryptMessage {
            payload,
            ..Default::default()
        }
    }

    /// The `Enc_structure` (additional authenticated data, RFC 9052 §5.3).
    fn to_be_encrypted(protected_raw: &[u8], external_aad: &[u8]) -> Result<Vec<u8>, Error> {
        util::encode_structure(vec![
            Value::from("Encrypt"),
            Value::Bytes(protected_raw.to_vec()),
            Value::Bytes(external_aad.to_vec()),
        ])
    }

    fn iv(&self, encryptor: &dyn Encryptor) -> Result<Vec<u8>, Error> {
        let iv = self
            .unprotected
            .get_bytes(iana::HeaderParameterIV)?
            .ok_or_else(|| Error::Custom("missing IV in unprotected header".into()))?;
        if iv.len() != encryptor.nonce_size() {
            return Err(Error::Custom(format!(
                "IV size mismatch, expected {}, got {}",
                encryptor.nonce_size(),
                iv.len()
            )));
        }
        Ok(iv.to_vec())
    }

    /// Encrypts the payload with `encryptor`.
    pub fn encrypt(
        &mut self,
        encryptor: &dyn Encryptor,
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        if self.recipients.is_empty() {
            return Err(Error::Custom("EncryptMessage has no recipients".into()));
        }
        util::ensure_protected_alg(&mut self.protected, encryptor.alg())?;
        util::ensure_unprotected_kid(&mut self.unprotected, encryptor.kid());

        let iv = self.iv(encryptor)?;
        self.protected_raw = encode_protected(&self.protected)?;
        let aad = Self::to_be_encrypted(&self.protected_raw, external_aad.unwrap_or(&[]))?;
        let plaintext = util::require_plaintext(&self.payload, "EncryptMessage::encrypt")?.to_vec();
        self.ciphertext = encryptor.encrypt(&iv, &plaintext, &aad)?;
        self.encrypted = true;
        Ok(())
    }

    /// Encrypts and encodes the message to tagged COSE_Encrypt bytes.
    pub fn encrypt_and_encode(
        &mut self,
        encryptor: &dyn Encryptor,
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.encrypt(encryptor, external_aad)?;
        self.to_vec()
    }

    /// Encodes an encrypted message to tagged COSE_Encrypt bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        if !self.encrypted {
            return Err(Error::Custom(
                "EncryptMessage must be encrypted before encoding".into(),
            ));
        }
        if self.recipients.is_empty() {
            return Err(Error::Custom("EncryptMessage has no recipients".into()));
        }
        let wire = EncryptWire {
            protected: self.protected_raw.clone(),
            unprotected: self.unprotected.clone(),
            ciphertext: Some(self.ciphertext.clone()),
            recipients: self.recipients.clone(),
        };
        Ok(cbor2::to_canonical_vec(&wire)?)
    }

    /// Decodes a COSE_Encrypt message (tagged or untagged) without decrypting.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::strip_message_wrappers(data);
        let wire: EncryptWire = if body.starts_with(tag::ENCRYPT_PREFIX) {
            cbor2::from_slice(body)?
        } else if tag::starts_with_cbor_tag(body) {
            return Err(Error::Custom("unexpected CBOR tag for COSE_Encrypt".into()));
        } else {
            cbor2::from_slice::<EncryptBareWire>(body)?.into()
        };
        if wire.recipients.is_empty() {
            return Err(Error::Custom("EncryptMessage has no recipients".into()));
        }
        let protected = decode_protected(&wire.protected)?;
        let ciphertext = wire
            .ciphertext
            .ok_or_else(|| Error::Custom("COSE_Encrypt has no ciphertext".into()))?;
        Ok(EncryptMessage {
            protected,
            unprotected: wire.unprotected,
            payload: None,
            recipients: wire.recipients,
            ciphertext,
            protected_raw: wire.protected,
            encrypted: true,
        })
    }

    /// Decrypts the ciphertext with `encryptor`, storing the result in
    /// [`payload`](Self::payload).
    pub fn decrypt(
        &mut self,
        encryptor: &dyn Encryptor,
        external_aad: Option<&[u8]>,
    ) -> Result<&[u8], Error> {
        if !self.encrypted {
            return Err(Error::Custom(
                "EncryptMessage must be decoded before decrypting".into(),
            ));
        }
        util::check_protected_alg(&self.protected, encryptor.alg())?;
        let iv = self.iv(encryptor)?;
        let aad = Self::to_be_encrypted(&self.protected_raw, external_aad.unwrap_or(&[]))?;
        let plaintext = encryptor.decrypt(&iv, &self.ciphertext, &aad)?;
        self.payload = Some(plaintext);
        Ok(self.payload.as_deref().unwrap())
    }

    /// Decodes and decrypts a COSE_Encrypt message in one step.
    pub fn decrypt_and_decode(
        encryptor: &dyn Encryptor,
        data: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let mut msg = Self::from_slice(data)?;
        msg.decrypt(encryptor, external_aad)?;
        Ok(msg)
    }

    /// Returns the raw ciphertext (empty until encrypted/decoded).
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The on-the-wire CBOR tag for COSE_Encrypt.
    pub const TAG: u64 = iana::CBORTagCOSEEncrypt;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_cbor_shape<T: cbor2::Cbor>(tag: Option<u64>, array: bool) {
        assert_eq!(T::TAG, tag);
        assert_eq!(T::ARRAY, array);
    }

    #[test]
    fn wire_metadata_declares_tagged_array_shape() {
        assert_cbor_shape::<EncryptWire>(Some(iana::CBORTagCOSEEncrypt), true);
        assert_cbor_shape::<EncryptBareWire>(None, true);
    }
}
