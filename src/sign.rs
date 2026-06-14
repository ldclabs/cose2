//! COSE_Sign: signing with one or more signers (RFC 9052 §4.1).

use cbor2::Cbor;

use crate::{
    header::{decode_protected, encode_protected},
    iana, tag, util, Error, Header, Signer, Value, Verifier,
};

/// The on-the-wire COSE_Signature array: `[protected, unprotected, signature]`.
#[derive(Clone, Debug, PartialEq, Cbor)]
struct SignatureWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    Header,
    #[serde(with = "serde_bytes")] Vec<u8>,
);

/// The on-the-wire COSE_Sign array: `[protected, unprotected, payload, signatures]`.
#[derive(Clone, Debug, PartialEq, Cbor)]
struct SignWire(
    #[serde(with = "serde_bytes")] Vec<u8>,
    Header,
    #[serde(with = "serde_bytes")] Option<Vec<u8>>,
    Vec<SignatureWire>,
);

/// A COSE_Signature inside a [`SignMessage`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Signature {
    /// Protected header parameters of this signature (e.g. `alg`).
    pub protected: Header,
    /// Unprotected header parameters of this signature (e.g. `kid`).
    pub unprotected: Header,
    signature: Vec<u8>,
    protected_raw: Vec<u8>,
}

impl Signature {
    /// Returns the `kid` from the signature's unprotected header, if any.
    fn kid(&self) -> &[u8] {
        match self.unprotected.get_bytes(iana::HeaderParameterKid) {
            Ok(Some(kid)) => kid,
            _ => &[],
        }
    }

    /// Returns the raw signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// A COSE_Sign message (one or more signers).
///
/// Reference: <https://datatracker.ietf.org/doc/html/rfc9052#name-signing-with-one-or-more-si>.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SignMessage {
    /// Body protected header parameters.
    pub protected: Header,
    /// Body unprotected header parameters.
    pub unprotected: Header,
    /// The payload, or `None` when detached.
    pub payload: Option<Vec<u8>>,
    /// The signatures.
    pub signatures: Vec<Signature>,
    protected_raw: Vec<u8>,
    signed: bool,
}

impl SignMessage {
    /// Creates a new, unsigned message with the given payload.
    pub fn new(payload: Option<Vec<u8>>) -> Self {
        SignMessage {
            payload,
            ..Default::default()
        }
    }

    /// The `Sig_structure` to be signed by one signer (RFC 9052 §4.4).
    fn to_be_signed(
        body_protected: &[u8],
        sign_protected: &[u8],
        external_aad: &[u8],
        payload: &Option<Vec<u8>>,
    ) -> Vec<u8> {
        util::encode_structure(vec![
            Value::from("Signature"),
            Value::Bytes(body_protected.to_vec()),
            Value::Bytes(sign_protected.to_vec()),
            Value::Bytes(external_aad.to_vec()),
            util::payload_value(payload),
        ])
    }

    /// Signs the message with each signer, producing one [`Signature`] per signer.
    pub fn sign(
        &mut self,
        signers: &[&dyn Signer],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        if signers.is_empty() {
            return Err(Error::Custom(
                "SignMessage requires at least one signer".into(),
            ));
        }
        let aad = external_aad.unwrap_or(&[]);
        self.protected_raw = encode_protected(&self.protected);
        self.signatures.clear();

        for signer in signers {
            let mut protected = Header::new();
            if signer.alg() != iana::AlgorithmReserved {
                protected.insert(iana::HeaderParameterAlg, signer.alg());
            }
            let mut unprotected = Header::new();
            util::ensure_unprotected_kid(&mut unprotected, signer.kid());

            let protected_raw = encode_protected(&protected);
            let tbs = Self::to_be_signed(&self.protected_raw, &protected_raw, aad, &self.payload);
            let signature = signer.sign(&tbs)?;
            self.signatures.push(Signature {
                protected,
                unprotected,
                signature,
                protected_raw,
            });
        }
        self.signed = true;
        Ok(())
    }

    /// Signs and encodes the message to tagged COSE_Sign bytes.
    pub fn sign_and_encode(
        &mut self,
        signers: &[&dyn Signer],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.sign(signers, external_aad)?;
        self.to_vec()
    }

    /// Encodes a signed message to tagged COSE_Sign bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        if !self.signed {
            return Err(Error::Custom(
                "SignMessage must be signed before encoding".into(),
            ));
        }
        if self.signatures.is_empty() {
            return Err(Error::Custom("SignMessage has no signatures".into()));
        }
        let signatures = self
            .signatures
            .iter()
            .map(|s| {
                SignatureWire(
                    s.protected_raw.clone(),
                    s.unprotected.clone(),
                    s.signature.clone(),
                )
            })
            .collect();
        let wire = SignWire(
            self.protected_raw.clone(),
            self.unprotected.clone(),
            self.payload.clone(),
            signatures,
        );
        Ok(tag::with_tag(
            tag::SIGN_PREFIX,
            &cbor2::to_canonical_vec(&wire)?,
        ))
    }

    /// Decodes a COSE_Sign message (tagged or untagged) without verifying it.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let body = tag::untag(data, tag::SIGN_PREFIX);
        let wire: SignWire = cbor2::from_slice(body)?;
        if wire.3.is_empty() {
            return Err(Error::Custom("SignMessage has no signatures".into()));
        }
        let protected = decode_protected(&wire.0)?;
        let mut signatures = Vec::with_capacity(wire.3.len());
        for sw in wire.3 {
            let sig_protected = decode_protected(&sw.0)?;
            signatures.push(Signature {
                protected: sig_protected,
                unprotected: sw.1,
                signature: sw.2,
                protected_raw: sw.0,
            });
        }
        Ok(SignMessage {
            protected,
            unprotected: wire.1,
            payload: wire.2,
            signatures,
            protected_raw: wire.0,
            signed: true,
        })
    }

    /// Verifies every signature: each must match exactly one of the
    /// `verifiers` (by `kid`) and validate.
    pub fn verify(
        &self,
        verifiers: &[&dyn Verifier],
        external_aad: Option<&[u8]>,
    ) -> Result<(), Error> {
        if !self.signed {
            return Err(Error::Custom(
                "SignMessage must be decoded before verifying".into(),
            ));
        }
        if verifiers.is_empty() {
            return Err(Error::Custom(
                "SignMessage requires at least one verifier".into(),
            ));
        }
        if self.signatures.is_empty() {
            return Err(Error::Custom("SignMessage has no signatures".into()));
        }
        let aad = external_aad.unwrap_or(&[]);

        for sig in &self.signatures {
            let kid = sig.kid();
            let verifier = verifiers
                .iter()
                .find(|v| v.kid() == kid)
                .ok_or_else(|| Error::verify("no verifier for signature kid"))?;
            util::check_protected_alg(&sig.protected, verifier.alg())?;
            let tbs =
                Self::to_be_signed(&self.protected_raw, &sig.protected_raw, aad, &self.payload);
            verifier.verify(&tbs, &sig.signature)?;
        }
        Ok(())
    }

    /// Decodes and verifies a COSE_Sign message in one step.
    pub fn verify_and_decode(
        verifiers: &[&dyn Verifier],
        data: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let msg = Self::from_slice(data)?;
        msg.verify(verifiers, external_aad)?;
        Ok(msg)
    }

    /// The on-the-wire CBOR tag for COSE_Sign.
    pub const TAG: u64 = iana::CBORTagCOSESign;
}
