use cose2::{
    crypto::{RingSigner, RingVerifier},
    iana, Error, Key, Sign1Message,
};
use ring::{signature, signature::KeyPair};

fn main() -> Result<(), Error> {
    // Fixed demo key material keeps this example reproducible. Generate and
    // store real keys outside this program for production use.
    let seed = [7u8; 32];
    let pair = signature::Ed25519KeyPair::from_seed_unchecked(&seed)
        .expect("static Ed25519 demo seed is valid");

    let mut key = Key::new();
    key.set_kty(iana::KeyTypeOKP)
        .set_alg(iana::AlgorithmEdDSA)
        .set_kid(b"ed25519-demo".to_vec());
    key.insert(iana::OKPKeyParameterCrv, iana::EllipticCurveEd25519);
    key.insert(iana::OKPKeyParameterX, pair.public_key().as_ref().to_vec());
    key.insert(iana::OKPKeyParameterD, seed.to_vec());

    let signer = RingSigner::from_cose_key(&key)?;
    let verifier = RingVerifier::from_cose_key(&key)?;

    let external_aad = b"sign1-ring context";
    let mut msg = Sign1Message::new(Some(b"real ring-backed signature".to_vec()));
    let encoded = msg.sign_and_encode(&signer, Some(external_aad))?;

    let decoded = Sign1Message::verify_and_decode(&verifier, &encoded, Some(external_aad))?;
    assert_eq!(
        decoded.payload.as_deref(),
        Some(&b"real ring-backed signature"[..])
    );
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, Some(b"wrong aad")).is_err());

    println!("ring COSE_Sign1 bytes: {}", encoded.len());
    Ok(())
}
