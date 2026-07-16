use cbor2::Value;
use cose2::{iana, Error, Label, Sign1Message, Signer, Verifier};
use sd_cwt::{
    issue_from_preissuance, restore_payload_from_message, set_disclosures, set_sd_alg,
    set_sd_cwt_typ, RedactionHasher, RestoreMode, Sha256RedactionHasher, TO_BE_DECOY_TAG,
    TO_BE_REDACTED_TAG,
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
        Some(b"issuer-key-1")
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(toy_tag(b"issuer signing secret", data))
    }
}

struct IssuerVerifier;

impl Verifier for IssuerVerifier {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEdDSA.into())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        if toy_tag(b"issuer signing secret", data) == signature {
            Ok(())
        } else {
            Err(Error::verify("SD-CWT issuer signature mismatch"))
        }
    }
}

fn deterministic_demo_salts() -> impl FnMut() -> [u8; 16] {
    let mut next = 1u8;
    move || {
        let salt = [next; 16];
        next = next.wrapping_add(1);
        salt
    }
}

fn main() -> Result<(), Error> {
    // Start from a pre-issued claim set. Tag 58 asks the issuer to redact a
    // map key/value pair or an array element. Tag 62 asks for a decoy digest.
    let preissued_claims = Value::Map(vec![
        (Value::from(1), Value::from("https://issuer.example")),
        (Value::from(8), Value::Map(vec![])), // cnf; fill with a real COSE key in production.
        (
            Value::Tag(TO_BE_REDACTED_TAG, Box::new(Value::from("name"))),
            Value::from("Alice Example"),
        ),
        (
            Value::from("roles"),
            Value::Array(vec![
                Value::Tag(TO_BE_REDACTED_TAG, Box::new(Value::from("admin"))),
                Value::from("user"),
            ]),
        ),
        (
            Value::Tag(TO_BE_DECOY_TAG, Box::new(Value::from(1))),
            Value::Null,
        ),
    ]);

    // The library never generates randomness. Issuers provide fresh 16-byte
    // salts. This deterministic generator is for a reproducible example only.
    let mut salts = deterministic_demo_salts();
    let issued = issue_from_preissuance(preissued_claims, &mut salts, &Sha256RedactionHasher)?;

    // Sign the issued SD-CWT as a COSE_Sign1 message. The payload contains the
    // redacted claims; sd_claims carries all disclosures for the Holder.
    let mut sd_cwt = Sign1Message::new(Some(cbor2::to_vec(&issued.value)?));
    set_sd_cwt_typ(&mut sd_cwt.protected);
    set_sd_alg(&mut sd_cwt.protected, Sha256RedactionHasher.algorithm());
    set_disclosures(&mut sd_cwt.unprotected, issued.disclosures.as_slice());
    let encoded = sd_cwt.sign_and_encode(&Issuer, None)?;

    // Holder receives every disclosure at issuance, so Holder validation uses
    // the strict one-to-one rule: every redaction must have a disclosure.
    let holder_sd_cwt = Sign1Message::verify_and_decode(&IssuerVerifier, &encoded, None)?;
    let holder_claims = restore_payload_from_message(&holder_sd_cwt, RestoreMode::Holder)?;
    println!("holder disclosed claims: {}", holder_claims.disclosed);

    // During presentation, the Holder can disclose a subset.
    let mut presented = holder_sd_cwt.clone();
    let selected = issued.disclosures.as_slice()[0].clone();
    set_disclosures(&mut presented.unprotected, std::slice::from_ref(&selected));
    let presented_bytes = presented.to_vec()?;

    // Verifier side. Two checks are mandatory before trusting anything:
    //
    // 1. Verify the issuer signature over the wire bytes actually received —
    //    never reuse a struct verified elsewhere.
    // 2. Verify holder binding: `sd_claims` sits in the *unprotected* header,
    //    so without a Key Binding Token (kcwt, header 13) signed with the
    //    holder's `cnf` key over this verifier's audience and cnonce, a
    //    captured presentation can be replayed by anyone. The sd-cwt crate
    //    does not implement KBT verification; production verifiers must do it
    //    (this toy example skips it).
    let verified = Sign1Message::verify_and_decode(&IssuerVerifier, &presented_bytes, None)?;
    let verifier_claims = restore_payload_from_message(&verified, RestoreMode::Verifier)?;
    println!(
        "verifier disclosed claims: {}, removed redactions: {}",
        verifier_claims.disclosed, verifier_claims.removed_redactions
    );

    Ok(())
}
