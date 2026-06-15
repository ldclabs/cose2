use cose2::{
    cwt::{Claims, Validator, ValidatorOptions},
    iana, Error, Label, Sign1Message, Signer, Verifier,
};

fn toy_tag(secret: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 16];
    for (i, byte) in secret.iter().chain(data).enumerate() {
        out[i % out.len()] ^= byte.wrapping_add(i as u8);
    }
    out.to_vec()
}

struct Issuer;

impl Signer for Issuer {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEdDSA.into())
    }

    fn kid(&self) -> Option<&[u8]> {
        Some(b"issuer-2026")
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(toy_tag(b"issuer secret", data))
    }
}

struct AudienceVerifier;

impl Verifier for AudienceVerifier {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEdDSA.into())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        if toy_tag(b"issuer secret", data) == signature {
            Ok(())
        } else {
            Err(Error::verify("CWT signature mismatch"))
        }
    }
}

fn main() -> Result<(), Error> {
    let claims = Claims {
        issuer: Some("issuer.example".into()),
        subject: Some("device-123".into()),
        audience: Some("api.example".into()),
        expiration: Some(1_700_000_600),
        not_before: Some(1_700_000_000),
        issued_at: Some(1_700_000_000),
        cwt_id: Some(b"token-1".to_vec()),
        ..Default::default()
    };

    let mut msg = Sign1Message::new(Some(claims.to_vec()?));
    let encoded = msg.sign_and_encode(&Issuer, None)?;

    let verified = Sign1Message::verify_and_decode(&AudienceVerifier, &encoded, None)?;
    let decoded = Claims::from_slice(verified.payload.as_deref().expect("embedded CWT claims"))?;

    let validator = Validator::new(ValidatorOptions {
        expected_issuer: Some("issuer.example".into()),
        expected_audience: Some("api.example".into()),
        fixed_now: Some(1_700_000_300),
        ..Default::default()
    })?;
    validator.validate(&decoded)?;

    println!("signed CWT bytes: {}", encoded.len());
    Ok(())
}
