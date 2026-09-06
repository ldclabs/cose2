//! Legacy RFC 8152 full countersignatures (header parameter label 7).

use crate::{
    header::{decode_protected, encode_protected, validate_header_buckets},
    util, Error, Header, Label, Signer, Value, Verifier,
};

/// A full legacy RFC 8152 `COSE_Countersignature`.
///
/// The wire structure is identical to `COSE_Signature`:
/// `[protected, unprotected, signature]`. RFC 9338 deprecates creation of this
/// form in favor of countersignature V2, but requires new implementations to
/// support its verification for compatibility.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CounterSignature {
    /// Protected countersigner header parameters.
    pub protected: Header,
    /// Unprotected countersigner header parameters.
    pub unprotected: Header,
    signature: Vec<u8>,
    protected_raw: Vec<u8>,
    state: util::OperationState,
}

impl CounterSignature {
    /// Creates an unsigned full countersignature with empty header buckets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Encodes the legacy `Sig_structure` used by RFC 8152 countersignatures.
    pub fn to_be_signed(
        body_protected: &[u8],
        sign_protected: &[u8],
        external_aad: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        util::encode_structure(&(
            "CounterSignature",
            serde_bytes::Bytes::new(body_protected),
            serde_bytes::Bytes::new(sign_protected),
            serde_bytes::Bytes::new(external_aad),
            serde_bytes::Bytes::new(payload),
        ))
    }

    /// Prepares the bytes for an external or asynchronous countersigner.
    pub fn prepare_signature(
        &mut self,
        alg: Option<Label>,
        kid: Option<&[u8]>,
        body_protected: &[u8],
        payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        util::ensure_protected_alg(&mut self.protected, &mut self.unprotected, alg)?;
        util::ensure_unprotected_kid(&self.protected, &mut self.unprotected, kid)?;
        validate_header_buckets(&self.protected, &self.unprotected)?;
        self.protected_raw = encode_protected(&self.protected)?;
        self.signature.clear();
        self.state = util::OperationState::Prepared;
        Self::to_be_signed(
            body_protected,
            &self.protected_raw,
            external_aad.unwrap_or(&[]),
            payload,
        )
    }

    /// Stores an externally produced countersignature value.
    pub fn set_signature(&mut self, signature: impl Into<Vec<u8>>) -> Result<(), Error> {
        validate_header_buckets(&self.protected, &self.unprotected)?;
        if !self.state.initialized() {
            self.protected_raw = encode_protected(&self.protected)?;
        }
        crate::header::validate_protected_state(&self.protected, &self.protected_raw)?;
        self.signature = signature.into();
        self.state = util::OperationState::Complete;
        Ok(())
    }

    /// Creates a legacy countersignature over a target structure's protected
    /// bytes and body field.
    pub fn sign(
        &mut self,
        signer: &dyn Signer,
        body_protected: &[u8],
        payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        let to_be_signed = self.prepare_signature(
            signer.alg(),
            signer.kid(),
            body_protected,
            payload,
            external_aad,
        )?;
        self.set_signature(signer.sign(&to_be_signed)?)
    }

    /// Verifies this legacy countersignature over a target structure's
    /// protected bytes and body field.
    ///
    /// `payload` is the third field of the target COSE array: the payload for
    /// message structures, ciphertext for encryption structures, or signature
    /// bytes when the target is a `COSE_Signature`.
    pub fn verify(
        &self,
        verifier: &dyn Verifier,
        body_protected: &[u8],
        payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        if !self.state.complete() {
            return Err(Error::invalid_state(
                "CounterSignature must be signed or decoded before verifying",
            ));
        }
        validate_header_buckets(&self.protected, &self.unprotected)?;
        crate::header::validate_protected_state(&self.protected, &self.protected_raw)?;
        self.protected
            .ensure_crit_understood(verifier.understood_critical_headers())?;
        util::check_protected_alg(&self.protected, &self.unprotected, verifier.alg())?;
        let to_be_signed = Self::to_be_signed(
            body_protected,
            &self.protected_raw,
            external_aad.unwrap_or(&[]),
            payload,
        )?;
        verifier.verify(&to_be_signed, &self.signature)
    }

    /// Returns the countersignature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the exact protected-header bytes captured from the wire or
    /// prepared for signing.
    pub fn protected_raw(&self) -> &[u8] {
        &self.protected_raw
    }

    /// Decodes one full countersignature from its header value.
    pub fn from_value(value: &Value) -> Result<Self, Error> {
        let Value::Array(items) = value else {
            return Err(Error::UnexpectedType(
                "COSE_Countersignature must be an array".into(),
            ));
        };
        if items.len() != 3 {
            return Err(Error::UnexpectedType(
                "COSE_Countersignature must contain 3 elements".into(),
            ));
        }
        let Value::Bytes(protected_raw) = &items[0] else {
            return Err(Error::UnexpectedType(
                "countersignature protected header must be a byte string".into(),
            ));
        };
        if !matches!(items[1], Value::Map(_)) {
            return Err(Error::UnexpectedType(
                "countersignature unprotected header must be a map".into(),
            ));
        }
        let Value::Bytes(signature) = &items[2] else {
            return Err(Error::UnexpectedType(
                "countersignature value must be a byte string".into(),
            ));
        };

        let protected = decode_protected(protected_raw)?;
        let unprotected = Header::from_slice(&cbor2::to_canonical_vec(&items[1])?)?;
        validate_header_buckets(&protected, &unprotected)?;
        Ok(Self {
            protected,
            unprotected,
            signature: signature.clone(),
            protected_raw: protected_raw.clone(),
            state: util::OperationState::Complete,
        })
    }

    /// Converts this countersignature to its header value.
    pub fn to_value(&self) -> Result<Value, Error> {
        if !self.state.complete() {
            return Err(Error::invalid_state(
                "CounterSignature must be signed before encoding",
            ));
        }
        validate_header_buckets(&self.protected, &self.unprotected)?;
        crate::header::validate_protected_state(&self.protected, &self.protected_raw)?;
        let unprotected = Value::Map(
            self.unprotected
                .iter()
                .map(|(label, value)| (Value::from(label.clone()), value.clone()))
                .collect(),
        );
        Ok(Value::Array(vec![
            Value::Bytes(self.protected_raw.clone()),
            unprotected,
            Value::Bytes(self.signature.clone()),
        ]))
    }
}

pub(crate) fn counter_signatures_from_value(value: &Value) -> Result<Vec<CounterSignature>, Error> {
    let Value::Array(items) = value else {
        return Err(Error::UnexpectedType(
            "counter signature header must contain a COSE_Countersignature or non-empty array of them"
                .into(),
        ));
    };
    if items.is_empty() {
        return Err(Error::UnexpectedType(
            "counter signature array must not be empty".into(),
        ));
    }

    if matches!(items.first(), Some(Value::Bytes(_))) {
        return CounterSignature::from_value(value).map(|signature| vec![signature]);
    }
    items.iter().map(CounterSignature::from_value).collect()
}
