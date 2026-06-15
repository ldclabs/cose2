use cose2::{iana, Error, Label, Sign1Message, Signer, Verifier};

fn toy_tag(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 16];
    for (i, byte) in secret.iter().chain(data).enumerate() {
        out[i % out.len()] ^= byte.wrapping_add(i as u8);
    }
    out.to_vec()
}

struct ToySigner {
    kid: Vec<u8>,
    secret: Vec<u8>,
}

impl Signer for ToySigner {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEdDSA.into())
    }

    fn kid(&self) -> Option<&[u8]> {
        Some(&self.kid)
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(toy_tag(&self.secret, data))
    }
}

struct ToyVerifier {
    secret: Vec<u8>,
}

impl Verifier for ToyVerifier {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEdDSA.into())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        if toy_tag(&self.secret, data) == signature {
            Ok(())
        } else {
            Err(Error::verify("signature mismatch"))
        }
    }
}

fn main() -> Result<(), Error> {
    // This toy provider demonstrates the trait boundary only. Use a real
    // cryptographic implementation in production.
    let signer = ToySigner {
        kid: b"toy-key-1".to_vec(),
        secret: b"demo signing secret".to_vec(),
    };
    let verifier = ToyVerifier {
        secret: b"demo signing secret".to_vec(),
    };

    let external_aad = b"application context";
    let mut msg = Sign1Message::new(Some(b"hello from cose2".to_vec()));
    let encoded = msg.sign_and_encode(&signer, Some(external_aad))?;

    let verified = Sign1Message::verify_and_decode(&verifier, &encoded, Some(external_aad))?;
    assert_eq!(verified.payload.as_deref(), Some(&b"hello from cose2"[..]));
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, Some(b"wrong aad")).is_err());

    println!("COSE_Sign1 bytes: {}", encoded.len());
    Ok(())
}
