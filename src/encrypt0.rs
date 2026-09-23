//! COSE_Encrypt0: single-recipient encryption (RFC 9052 §5.2).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, validate_header_buckets, validate_layer},
    iana, tag, util, EncryptionContext, Encryptor, Error, Header, Label,
};

/// The on-the-wire COSE_Encrypt0 array: `[protected, unprotected, ciphertext]`.
// Private wire types are decoded only after `tag::message_body` validates
// their exact field kinds and rejects duplicate map keys. Decode byte strings
// directly into their final buffers and header maps without a second pass.
#[derive(Clone, Debug, PartialEq, Cbor)]
#[cbor(tag = 16, array)]
struct Encrypt0Wire {
    #[serde(with = "serde_bytes")]
    protected: Vec<u8>,
    #[serde(deserialize_with = "crate::header::deserialize_checked")]
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
    state: util::OperationState,
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
        util::encode_structure(&(
            "Encrypt0",
            serde_bytes::Bytes::new(protected_raw),
            serde_bytes::Bytes::new(external_aad),
        ))
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
        let protected_raw =
            util::prepare_headers(&mut self.protected, &mut self.unprotected, alg, kid)?;
        util::require_plaintext(&self.payload, "Encrypt0Message::prepare_encryption")?;

        let nonce = util::nonce_from_header_values(
            &self.protected,
            &self.unprotected,
            nonce_size,
            base_iv,
        )?;
        let aad = Self::to_be_encrypted(&protected_raw, external_aad.unwrap_or(&[]))?;
        self.protected_raw = protected_raw;
        self.state = util::OperationState::Prepared;
        self.ciphertext.clear();
        self.ciphertext_detached = false;
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
        self.prepare_decryption_with_crit(alg, nonce_size, base_iv, external_aad, &[])
    }

    /// Prepares external decryption while accepting application critical headers.
    pub fn prepare_decryption_with_crit(
        &self,
        alg: Option<Label>,
        nonce_size: usize,
        base_iv: Option<&[u8]>,
        external_aad: Option<&[u8]>,
        understood_critical_headers: &[Label],
    ) -> Result<EncryptionContext, Error> {
        self.state
            .require_complete("Encrypt0Message must be decoded before decrypting")?;
        validate_layer(&self.protected, &self.unprotected, &self.protected_raw)?;
        self.protected
            .ensure_crit_understood(understood_critical_headers)?;
        util::check_protected_alg(&self.protected, &self.unprotected, alg)?;
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
        util::sync_protected_raw(
            &self.protected,
            &self.unprotected,
            &mut self.protected_raw,
            self.state,
        )?;
        self.ciphertext = ciphertext.into();
        self.ciphertext_detached = detached;
        self.state = util::OperationState::Complete;
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
        let plaintext = util::require_plaintext(&self.payload, "Encrypt0Message::encrypt")?;
        // The headers were validated and encoded by `prepare_encryption`.
        self.ciphertext = encryptor.encrypt(&context.nonce, plaintext, &context.aad)?;
        self.state = util::OperationState::Complete;
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
    ///
    /// The ciphertext buffer is moved into the return value to avoid a full
    /// duplicate allocation; [`ciphertext`](Self::ciphertext) is empty afterward.
    pub fn encrypt_detached_and_encode(
        &mut self,
        encryptor: &dyn Encryptor,
        external_aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.encrypt_detached(encryptor, external_aad)?;
        let encoded = self.to_vec()?;
        let ciphertext = std::mem::take(&mut self.ciphertext);
        Ok((encoded, ciphertext))
    }

    /// Encodes an encrypted message to tagged COSE_Encrypt0 bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        self.encode(tag::ENCRYPT0_PREFIX)
    }

    /// Encodes this tagged COSE_Encrypt0 as a CWT (`61(16(...))`).
    pub fn to_cwt_vec(&self) -> Result<Vec<u8>, Error> {
        self.encode(tag::CWT_ENCRYPT0_PREFIX)
    }

    /// Encodes an encrypted message to canonical COSE_Encrypt0 bytes without the CBOR tag.
    pub fn to_untagged_vec(&self) -> Result<Vec<u8>, Error> {
        self.encode(&[])
    }

    /// Serializes the wire array borrowing this message's buffers.
    fn encode(&self, prefix: &[u8]) -> Result<Vec<u8>, Error> {
        self.state
            .require_complete("Encrypt0Message must be encrypted before encoding")?;
        validate_layer(&self.protected, &self.unprotected, &self.protected_raw)?;
        let ciphertext = if self.ciphertext_detached {
            None
        } else {
            Some(serde_bytes::Bytes::new(&self.ciphertext))
        };
        let unprotected = util::header_raw(&self.unprotected)?;
        util::encode_prefixed(
            prefix,
            &(
                serde_bytes::Bytes::new(&self.protected_raw),
                &unprotected,
                ciphertext,
            ),
        )
    }

    /// Decodes a COSE_Encrypt0 message (tagged or untagged) without decrypting.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::message_body(data, Self::TAG)?;
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
            state: util::OperationState::Complete,
        })
    }

    /// Decrypts the ciphertext with `encryptor`, storing the result in
    /// [`payload`](Self::payload).
    pub fn decrypt(
        &mut self,
        encryptor: &dyn Encryptor,
        external_aad: Option<&[u8]>,
    ) -> Result<&[u8], Error> {
        self.state
            .require_complete("Encrypt0Message must be decoded before decrypting")?;
        if self.ciphertext_detached {
            return Err(Error::Custom(
                "Encrypt0Message has detached ciphertext; use decrypt_detached".into(),
            ));
        }
        let context = self.prepare_decryption_with_crit(
            encryptor.alg(),
            encryptor.nonce_size(),
            encryptor.base_iv(),
            external_aad,
            encryptor.understood_critical_headers(),
        )?;
        let plaintext = encryptor.decrypt(&context.nonce, &self.ciphertext, &context.aad)?;
        self.payload = Some(plaintext);
        Ok(self.payload.as_deref().expect("payload was just set"))
    }

    /// Decrypts a detached ciphertext for a decoded COSE_Encrypt0 message.
    pub fn decrypt_detached(
        &mut self,
        encryptor: &dyn Encryptor,
        detached_ciphertext: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<&[u8], Error> {
        self.state
            .require_complete("Encrypt0Message must be decoded before decrypting")?;
        if !self.ciphertext_detached {
            return Err(Error::Custom(
                "Encrypt0Message carries embedded ciphertext; use decrypt".into(),
            ));
        }
        let context = self.prepare_decryption_with_crit(
            encryptor.alg(),
            encryptor.nonce_size(),
            encryptor.base_iv(),
            external_aad,
            encryptor.understood_critical_headers(),
        )?;
        let plaintext = encryptor.decrypt(&context.nonce, detached_ciphertext, &context.aad)?;
        self.ciphertext.clear();
        self.ciphertext.extend_from_slice(detached_ciphertext);
        self.payload = Some(plaintext);
        Ok(self.payload.as_deref().expect("payload was just set"))
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
