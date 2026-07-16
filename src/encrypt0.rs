//! COSE_Encrypt0: single-recipient encryption (RFC 9052 §5.2).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected, validate_header_buckets},
    iana, tag, util, EncryptionContext, Encryptor, Error, Header, Label, Value,
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

    /// Encodes the `Enc_structure` (additional authenticated data, RFC 9052 §5.3).
    ///
    /// This is the low-level helper for external or async AEAD code. New
    /// messages should usually call [`prepare_encryption`](Self::prepare_encryption)
    /// so the protected header bytes stored in the message match the AAD.
    pub fn to_be_encrypted(protected_raw: &[u8], external_aad: &[u8]) -> Result<Vec<u8>, Error> {
        util::encode_structure(vec![
            Value::from("Encrypt0"),
            Value::Bytes(protected_raw.to_vec()),
            Value::Bytes(external_aad.to_vec()),
        ])
    }

    /// Prepares this message for external encryption.
    ///
    /// The returned context contains the nonce and encoded `Enc_structure` AAD
    /// to pass to async or remote AEAD code together with
    /// [`payload`](Self::payload). After encryption returns ciphertext bytes,
    /// call [`set_ciphertext`](Self::set_ciphertext) and then
    /// [`to_vec`](Self::to_vec). Passing `None` for `external_aad` is the same
    /// as an empty byte string.
    pub fn prepare_encryption(
        &mut self,
        alg: Option<Label>,
        kid: Option<&[u8]>,
        nonce_size: usize,
        base_iv: Option<&[u8]>,
        external_aad: Option<&[u8]>,
    ) -> Result<EncryptionContext, Error> {
        util::ensure_protected_alg(&mut self.protected, alg)?;
        util::ensure_unprotected_kid(&mut self.unprotected, kid);
        validate_header_buckets(&self.protected, &self.unprotected)?;
        util::require_plaintext(&self.payload, "Encrypt0Message::prepare_encryption")?;

        let nonce = util::nonce_from_header_values(
            &self.protected,
            &self.unprotected,
            nonce_size,
            base_iv,
        )?;
        let protected_raw = encode_protected(&self.protected)?;
        let aad = Self::to_be_encrypted(&protected_raw, external_aad.unwrap_or(&[]))?;
        self.protected_raw = protected_raw;
        self.ciphertext.clear();
        self.ciphertext_detached = false;
        self.encrypted = false;
        Ok(EncryptionContext { nonce, aad })
    }

    /// Prepares this decoded message for external decryption.
    ///
    /// The returned context contains the nonce and encoded `Enc_structure` AAD
    /// to pass to async or remote AEAD code together with
    /// [`ciphertext`](Self::ciphertext), or with the detached ciphertext when
    /// [`is_ciphertext_detached`](Self::is_ciphertext_detached) is true.
    pub fn prepare_decryption(
        &self,
        alg: Option<Label>,
        nonce_size: usize,
        base_iv: Option<&[u8]>,
        external_aad: Option<&[u8]>,
    ) -> Result<EncryptionContext, Error> {
        if !self.encrypted {
            return Err(Error::Custom(
                "Encrypt0Message must be decoded before decrypting".into(),
            ));
        }
        util::check_protected_alg(&self.protected, alg)?;
        let nonce = util::nonce_from_header_values(
            &self.protected,
            &self.unprotected,
            nonce_size,
            base_iv,
        )?;
        let aad = Self::to_be_encrypted(&self.protected_raw, external_aad.unwrap_or(&[]))?;
        Ok(EncryptionContext { nonce, aad })
    }

    /// Stores externally produced ciphertext bytes on this message.
    ///
    /// When `detached` is true, the encoded COSE_Encrypt0 message carries `nil`
    /// in the ciphertext field and the returned/stored ciphertext must be
    /// transported out of band.
    pub fn set_ciphertext(
        &mut self,
        ciphertext: impl Into<Vec<u8>>,
        detached: bool,
    ) -> Result<(), Error> {
        validate_header_buckets(&self.protected, &self.unprotected)?;
        if self.protected_raw.is_empty() && !self.protected.is_empty() {
            self.protected_raw = encode_protected(&self.protected)?;
        }
        self.ciphertext = ciphertext.into();
        self.ciphertext_detached = detached;
        self.encrypted = true;
        Ok(())
    }

    /// Encrypts the payload with `encryptor`.
    pub fn encrypt(
        &mut self,
        encryptor: &dyn Encryptor,
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        let context = self.prepare_encryption(
            encryptor.alg(),
            encryptor.kid(),
            encryptor.nonce_size(),
            encryptor.base_iv(),
            external_aad,
        )?;
        let plaintext =
            util::require_plaintext(&self.payload, "Encrypt0Message::encrypt")?.to_vec();
        let ciphertext = encryptor.encrypt(&context.nonce, &plaintext, &context.aad)?;
        self.set_ciphertext(ciphertext, false)
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
        self.encode(tag::ENCRYPT0_PREFIX)
    }

    /// Encodes an encrypted message to canonical COSE_Encrypt0 bytes without the CBOR tag.
    pub fn to_untagged_vec(&self) -> Result<Vec<u8>, Error> {
        self.encode(&[])
    }

    /// Serializes the wire array borrowing this message's buffers.
    fn encode(&self, prefix: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.encrypted {
            return Err(Error::Custom(
                "Encrypt0Message must be encrypted before encoding".into(),
            ));
        }
        validate_header_buckets(&self.protected, &self.unprotected)?;
        let ciphertext = if self.ciphertext_detached {
            None
        } else {
            Some(serde_bytes::Bytes::new(&self.ciphertext))
        };
        util::encode_prefixed(
            prefix,
            &(
                serde_bytes::Bytes::new(&self.protected_raw),
                &self.unprotected,
                ciphertext,
            ),
        )
    }

    /// Decodes a COSE_Encrypt0 message (tagged or untagged) without decrypting.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::strip_message_wrappers(data);
        if !body.starts_with(tag::ENCRYPT0_PREFIX) && tag::starts_with_cbor_tag(body) {
            return Err(Error::Custom(
                "unexpected CBOR tag for COSE_Encrypt0".into(),
            ));
        }
        let wire: Encrypt0Wire = cbor2::from_slice(body)?;
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
        let context = self.prepare_decryption(
            encryptor.alg(),
            encryptor.nonce_size(),
            encryptor.base_iv(),
            external_aad,
        )?;
        let plaintext = encryptor.decrypt(&context.nonce, &ciphertext, &context.aad)?;
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

    /// Returns the protected-header bytes used in the encryption AAD.
    pub fn protected_raw(&self) -> &[u8] {
        &self.protected_raw
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
    }
}
