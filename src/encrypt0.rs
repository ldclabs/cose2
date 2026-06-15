//! COSE_Encrypt0: single-recipient encryption (RFC 9052 §5.2).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected, validate_header_buckets},
    iana, tag, util, Encryptor, Error, Header, Value,
};

/// The on-the-wire COSE_Encrypt0 array: `[protected, unprotected, ciphertext]`.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(tag = 16, array)]
struct Encrypt0Wire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    unprotected: Header,
    #[serde(with = "serde_bytes")]
    ciphertext: Option<Vec<u8>>,
}

/// Untagged COSE_Encrypt0, accepted for compatibility with untagged transports.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(array)]
struct Encrypt0BareWire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    unprotected: Header,
    #[serde(with = "serde_bytes")]
    ciphertext: Option<Vec<u8>>,
}

impl From<Encrypt0BareWire> for Encrypt0Wire {
    fn from(value: Encrypt0BareWire) -> Self {
        Encrypt0Wire {
            protected: value.protected,
            unprotected: value.unprotected,
            ciphertext: value.ciphertext,
        }
    }
}

/// A COSE_Encrypt0 message.
///
/// A full `IV` or a `Partial IV` plus [`Encryptor::base_iv`] must be present
/// before encrypting; this crate does not generate IVs (it has no RNG
/// dependency).
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-single-recipient-encrypted>.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Encrypt0Message {
    /// Protected header parameters (e.g. `alg`).
    pub protected: Header,
    /// Unprotected header parameters (e.g. `iv`, `kid`).
    pub unprotected: Header,
    /// The plaintext payload (set after a successful [`decrypt`](Self::decrypt)).
    pub payload: Option<Vec<u8>>,
    ciphertext: Vec<u8>,
    ciphertext_detached: bool,
    protected_raw: Vec<u8>,
    encrypted: bool,
}

impl Encrypt0Message {
    /// Creates a new message with the given plaintext payload.
    pub fn new(payload: Option<Vec<u8>>) -> Self {
        Encrypt0Message {
            payload,
            ..Default::default()
        }
    }

    /// The `Enc_structure` (additional authenticated data, RFC 9052 §5.3).
    fn to_be_encrypted(protected_raw: &[u8], external_aad: &[u8]) -> Result<Vec<u8>, Error> {
        util::encode_structure(vec![
            Value::from("Encrypt0"),
            Value::Bytes(protected_raw.to_vec()),
            Value::Bytes(external_aad.to_vec()),
        ])
    }

    /// Encrypts the payload with `encryptor`.
    pub fn encrypt(
        &mut self,
        encryptor: &dyn Encryptor,
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        util::ensure_protected_alg(&mut self.protected, encryptor.alg())?;
        util::ensure_unprotected_kid(&mut self.unprotected, encryptor.kid());
        validate_header_buckets(&self.protected, &self.unprotected)?;

        let iv = util::nonce_from_headers(&self.protected, &self.unprotected, encryptor)?;
        self.protected_raw = encode_protected(&self.protected)?;
        let aad = Self::to_be_encrypted(&self.protected_raw, external_aad.unwrap_or(&[]))?;
        let plaintext =
            util::require_plaintext(&self.payload, "Encrypt0Message::encrypt")?.to_vec();
        self.ciphertext = encryptor.encrypt(&iv, &plaintext, &aad)?;
        self.ciphertext_detached = false;
        self.encrypted = true;
        Ok(())
    }

    /// Encrypts the payload and marks the ciphertext as detached.
    ///
    /// The returned ciphertext must be transported separately; the encoded
    /// COSE_Encrypt0 message will carry `nil` in the ciphertext field.
    pub fn encrypt_detached(
        &mut self,
        encryptor: &dyn Encryptor,
        external_aad: Option<&[u8]>,
    ) -> Result<&[u8], Error> {
        self.encrypt(encryptor, external_aad)?;
        self.ciphertext_detached = true;
        Ok(&self.ciphertext)
    }

    /// Encrypts and encodes the message to tagged COSE_Encrypt0 bytes.
    pub fn encrypt_and_encode(
        &mut self,
        encryptor: &dyn Encryptor,
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.encrypt(encryptor, external_aad)?;
        self.to_vec()
    }

    /// Encrypts with detached ciphertext and returns `(message, ciphertext)`.
    pub fn encrypt_detached_and_encode(
        &mut self,
        encryptor: &dyn Encryptor,
        external_aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.encrypt_detached(encryptor, external_aad)?;
        let ciphertext = self.ciphertext.clone();
        Ok((self.to_vec()?, ciphertext))
    }

    /// Encodes an encrypted message to tagged COSE_Encrypt0 bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        if !self.encrypted {
            return Err(Error::Custom(
                "Encrypt0Message must be encrypted before encoding".into(),
            ));
        }
        validate_header_buckets(&self.protected, &self.unprotected)?;
        let ciphertext = if self.ciphertext_detached {
            None
        } else {
            Some(self.ciphertext.clone())
        };
        let wire = Encrypt0Wire {
            protected: self.protected_raw.clone(),
            unprotected: self.unprotected.clone(),
            ciphertext,
        };
        Ok(cbor2::to_canonical_vec(&wire)?)
    }

    /// Decodes a COSE_Encrypt0 message (tagged or untagged) without decrypting.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::strip_message_wrappers(data);
        let wire: Encrypt0Wire = if body.starts_with(tag::ENCRYPT0_PREFIX) {
            cbor2::from_slice(body)?
        } else if tag::starts_with_cbor_tag(body) {
            return Err(Error::Custom(
                "unexpected CBOR tag for COSE_Encrypt0".into(),
            ));
        } else {
            cbor2::from_slice::<Encrypt0BareWire>(body)?.into()
        };
        let protected = decode_protected(&wire.protected)?;
        validate_header_buckets(&protected, &wire.unprotected)?;
        let (ciphertext, ciphertext_detached) = match wire.ciphertext {
            Some(ciphertext) => (ciphertext, false),
            None => (Vec::new(), true),
        };
        Ok(Encrypt0Message {
            protected,
            unprotected: wire.unprotected,
            payload: None,
            ciphertext,
            ciphertext_detached,
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
                "Encrypt0Message must be decoded before decrypting".into(),
            ));
        }
        if self.ciphertext_detached {
            return Err(Error::Custom(
                "Encrypt0Message has detached ciphertext; use decrypt_detached".into(),
            ));
        }
        self.decrypt_ciphertext(encryptor, self.ciphertext.clone(), external_aad)
    }

    /// Decrypts a detached ciphertext for a decoded COSE_Encrypt0 message.
    pub fn decrypt_detached(
        &mut self,
        encryptor: &dyn Encryptor,
        detached_ciphertext: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<&[u8], Error> {
        if !self.encrypted {
            return Err(Error::Custom(
                "Encrypt0Message must be decoded before decrypting".into(),
            ));
        }
        if !self.ciphertext_detached {
            return Err(Error::Custom(
                "Encrypt0Message carries embedded ciphertext; use decrypt".into(),
            ));
        }
        self.decrypt_ciphertext(encryptor, detached_ciphertext.to_vec(), external_aad)
    }

    fn decrypt_ciphertext(
        &mut self,
        encryptor: &dyn Encryptor,
        ciphertext: Vec<u8>,
        external_aad: Option<&[u8]>,
    ) -> Result<&[u8], Error> {
        util::check_protected_alg(&self.protected, encryptor.alg())?;
        let iv = util::nonce_from_headers(&self.protected, &self.unprotected, encryptor)?;
        let aad = Self::to_be_encrypted(&self.protected_raw, external_aad.unwrap_or(&[]))?;
        let plaintext = encryptor.decrypt(&iv, &ciphertext, &aad)?;
        self.ciphertext = ciphertext;
        self.payload = Some(plaintext);
        Ok(self.payload.as_deref().unwrap())
    }

    /// Decodes and decrypts a COSE_Encrypt0 message in one step.
    pub fn decrypt_and_decode(
        encryptor: &dyn Encryptor,
        data: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let mut msg = Self::from_slice(data)?;
        msg.decrypt(encryptor, external_aad)?;
        Ok(msg)
    }

    /// Decodes and decrypts a detached-ciphertext COSE_Encrypt0 message.
    pub fn decrypt_detached_and_decode(
        encryptor: &dyn Encryptor,
        data: &[u8],
        detached_ciphertext: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let mut msg = Self::from_slice(data)?;
        msg.decrypt_detached(encryptor, detached_ciphertext, external_aad)?;
        Ok(msg)
    }

    /// Returns the raw ciphertext (empty until encrypted/decoded).
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns true when the message carries `nil` in the ciphertext field.
    pub fn is_ciphertext_detached(&self) -> bool {
        self.ciphertext_detached
    }

    /// The on-the-wire CBOR tag for COSE_Encrypt0.
    pub const TAG: u64 = iana::CBORTagCOSEEncrypt0;
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
        assert_cbor_shape::<Encrypt0Wire>(Some(iana::CBORTagCOSEEncrypt0), true);
        assert_cbor_shape::<Encrypt0BareWire>(None, true);
    }
}
