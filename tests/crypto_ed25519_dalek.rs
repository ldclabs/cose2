// Coverage for the `crypto-ed25519-dalek` backend.
#![cfg(feature = "crypto-ed25519-dalek")]

use cose2::{
    ed25519::{Ed25519Signer, Ed25519Verifier},
    iana, Key, Sign1Message, Verifier,
};

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// RFC 8032 §7.1 Test 1: the canonical Ed25519 public key and the signature
/// over the empty message. Verifying it confirms the provider is wire-exact.
#[test]
fn ed25519_dalek_verifies_rfc8032_test1_vector() {
    const PUB: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                       5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    let verifier = Ed25519Verifier::from_public_key(&hx(PUB), Some(b"rfc8032-1".to_vec())).unwrap();
    assert_eq!(verifier.algorithm(), iana::AlgorithmEdDSA);
    assert!(verifier.verify(b"", &hx(SIG)).is_ok());

    // A flipped signature byte and a wrong-length signature are both rejected.
    let mut bad = hx(SIG);
    bad[0] ^= 0x01;
    assert!(verifier.verify(b"", &bad).is_err());
    assert!(verifier.verify(b"", &hx(SIG)[..63]).is_err());
}

#[test]
fn ed25519_dalek_signs_and_verifies_sign1() {
    let signer = Ed25519Signer::from_secret_key(&[9u8; 32], Some(b"ed-1".to_vec())).unwrap();
    // The verifier is rebuilt from the signer's exported public COSE_Key.
    let verifier = Ed25519Verifier::from_cose_key(&signer.to_cose_key().unwrap()).unwrap();

    let mut msg = Sign1Message::new(Some(b"hello ed25519".to_vec()));
    let encoded = msg.sign_and_encode(&signer, Some(b"aad")).unwrap();
    assert_eq!(msg.signature().len(), 64);

    let decoded = Sign1Message::verify_and_decode(&verifier, &encoded, Some(b"aad")).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"hello ed25519"[..]));
    // The wrong AAD and a tampered message both fail verification.
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, Some(b"wrong")).is_err());
    let mut tampered = encoded.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(Sign1Message::verify_and_decode(&verifier, &tampered, None).is_err());
}

#[test]
fn ed25519_dalek_cose_key_round_trips() {
    // A self-consistent private OKP key: derive `x` from the seed `d`.
    let seed = [7u8; 32];
    let signer = Ed25519Signer::from_secret_key(&seed, None).unwrap();
    let public = signer.public_key();

    let mut priv_key = Key::new();
    priv_key
        .set_kty(iana::KeyTypeOKP)
        .set_alg(iana::AlgorithmEdDSA)
        .set_kid(b"okp-1".to_vec());
    priv_key.insert(iana::OKPKeyParameterCrv, iana::EllipticCurveEd25519);
    priv_key.insert(iana::OKPKeyParameterX, public.to_vec());
    priv_key.insert(iana::OKPKeyParameterD, seed.to_vec());

    // Signer from the private key exports a public-only COSE_Key.
    let signer = Ed25519Signer::from_cose_key(&priv_key).unwrap();
    let exported = signer.to_cose_key().unwrap();
    assert!(exported
        .get_bytes(iana::OKPKeyParameterD)
        .unwrap()
        .is_none());
    assert_eq!(exported.kid().unwrap(), Some(&b"okp-1"[..]));
    assert_eq!(
        exported.get_bytes(iana::OKPKeyParameterX).unwrap(),
        Some(&public[..])
    );

    // The verifier re-exports the identical public COSE_Key.
    let verifier = Ed25519Verifier::from_cose_key(&priv_key).unwrap();
    assert_eq!(verifier.to_cose_key().unwrap(), exported);
    assert_eq!(verifier.public_key(), public);

    // A message signed by the signer verifies under the round-tripped verifier.
    let mut msg = Sign1Message::new(Some(b"round trip".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());
}

#[test]
fn ed25519_dalek_rejects_malformed_keys() {
    // Wrong key lengths.
    assert!(Ed25519Signer::from_secret_key(&[0u8; 31], None).is_err());
    assert!(Ed25519Verifier::from_public_key(&[0u8; 33], None).is_err());

    // Mismatched kty, curve and alg are all rejected by `from_cose_key`.
    let base = |mutate: &dyn Fn(&mut Key)| {
        let mut key = Key::new();
        key.set_kty(iana::KeyTypeOKP).set_alg(iana::AlgorithmEdDSA);
        key.insert(iana::OKPKeyParameterCrv, iana::EllipticCurveEd25519);
        key.insert(iana::OKPKeyParameterX, vec![0x11u8; 32]);
        mutate(&mut key);
        key
    };

    assert!(Ed25519Verifier::from_cose_key(&base(&|_| {})).is_ok());
    assert!(Ed25519Verifier::from_cose_key(&base(&|k| {
        k.set_kty(iana::KeyTypeEC2);
    }))
    .is_err());
    assert!(Ed25519Verifier::from_cose_key(&base(&|k| {
        k.insert(iana::OKPKeyParameterCrv, iana::EllipticCurveX25519);
    }))
    .is_err());
    assert!(Ed25519Verifier::from_cose_key(&base(&|k| {
        k.set_alg(iana::AlgorithmES256);
    }))
    .is_err());
    // A signer needs the private `d`, which the public key above lacks.
    assert!(Ed25519Signer::from_cose_key(&base(&|_| {})).is_err());
}
