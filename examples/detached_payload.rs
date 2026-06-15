use cose2::{iana, Error, Label, Sign1Message, Signer, Verifier};

fn toy_tag(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 16];
    for (i, byte) in secret.iter().chain(data).enumerate() {
        out[i % out.len()] ^= byte.wrapping_add(i as u8);
    }
    out.to_vec()
}

struct ToySigner;

impl Signer for ToySigner {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEdDSA.into())
    }

    fn kid(&self) -> Option<&[u8]> {
        Some(b"detached-demo")
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(toy_tag(b"detached secret", data))
    }
}

struct ToyVerifier;

impl Verifier for ToyVerifier {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEdDSA.into())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        if toy_tag(b"detached secret", data) == signature {
            Ok(())
        } else {
            Err(Error::verify("detached signature mismatch"))
        }
    }
}

fn main() -> Result<(), Error> {
    let payload = b"large payload transported outside the COSE message";
    let external_aad = b"download metadata";

    let mut msg = Sign1Message::new(None);
    let encoded = msg.sign_detached_and_encode(&ToySigner, payload, Some(external_aad))?;

    let verified = Sign1Message::verify_detached_and_decode(
        &ToyVerifier,
        &encoded,
        payload,
        Some(external_aad),
    )?;
    assert!(verified.payload.is_none());
    assert!(Sign1Message::verify_detached_and_decode(
        &ToyVerifier,
        &encoded,
        b"tampered payload",
        Some(external_aad)
    )
    .is_err());

    println!("detached COSE_Sign1 bytes: {}", encoded.len());
    Ok(())
}
