// Round-trip coverage for the `crypto-aws-lc-rs` backend.
//
// Gated on `aws-lc-rs` being the *active* backend (i.e. `crypto-ring` off), so
// these tests exercise the `aws-lc-rs`-specific arms in `src/crypto.rs` that the
// `--all-features` build (where `crypto-ring` wins) never compiles.
#![cfg(all(feature = "crypto-aws-lc-rs", not(feature = "crypto-ring")))]

use aws_lc_rs::{rand::SystemRandom, signature};
use cose2::{
    crypto::{RingEncryptor, RingMacer, RingSigner, RingVerifier},
    iana, Encrypt0Message, Key, Mac0Message, Sign1Message,
};

// A static P-256 key (SEC1 uncompressed public point `04 || x || y`).
const P256_D: &str = "6f4d2ccef998b4b30eb0ea78b7d3a530d9e72f20d8af35d4ac817f6113e7ebe2";
const P256_PUB: &str = "042b21f7145b474ee8013cebdbf3d548ee18e8657a2d5233b2f3c9a3acac3d015a3\
     b08c616a394514a5ae50927ed8e9758f82738b9d5d55f798f3ccdb9996797a1";

// A static RSA-2048 key: PKCS#8 private key plus its raw public components.
const RSA_PKCS8: &str = "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201000282010100b6c35fa8a4f01b77b3da6e070d0c0100b71d69fac1ccc5134862c2e24e0214b29f9335b28bfc958e9dba4f5fae39e5bda549d3ef3df469eeb5b383829e6fc26fd9e30510822cc225569a7e921d15dce61e376b6110aba71514955843467f09d9906ac7b0e225d71bf821aa692fbd4dd1f64cefa88c5c67b461f0b625820a3ac593a3dc875a51781b3633cc2107f3108b1e162861cf77a7078cab5e1f049a66a785d2d2d1a53803a83c8fca2b172802af52ab114718e389a5d184649fc6d7c2eadc182cafbcf4e9751c4bb63d8203286692c8ce5d63d25f06caaf28edb31f1cdd4c0eea5e6a01fee742e101478c3afc546e422757914876387d0166f183a1ccad02030100010282010002af6bfaaea5b4133610c69edfb34cc01270aee53d95811f5c4e67f79dd6cc300dac5c54b68ad29c1c50f48e986dd38acde0998374a779f75eccaae915e3d8ac983c0c8fb33b87b7ea85ed94bf000dbbb83755a27428bfe20081eb3a2a9e17d0db03a50542322855705e2a428194c1f40caede195dc42d664a2db21dd129ce503aadaa10eb1b273a5246f3b747057170c44802b967938c5b6c5bd396d6d9691d4ce282e0b525ab28099f13b294a6c1aff74bebe343c1a8de77c5d46abda2fec6b0fe91ecd12e6ca3aa29f552c8ffad6281c283e6361932f8301ac97ce9a1794c4c174b0375e1aeb637da0970490fffa6c654e31fe58edee55bdaf35332b363df02818100def81e0b796390b8971706cf55dd3f8f0b9fea15ec2b01e228b4d21fa21dc138c5a067744349dce3481ffa4e805d5e0140eac79fb415ddeb9241445d5a071ea6e037a83aad1ea5f84bbfbc53ee15aa2a0038f5d84f6df8708eead127e5134f6847ffce6ca510aecb8ca66dee5d334cb2c5a1f0376f63a4ab9aa33f58a41e10ef02818100d1d67bad4f6066fada8a3a87d0c97873111cac25aee23605cd3b56f0b9b416a2688317a3ab94affad9ed228e771e08cc54319a58df5c2ab9255e23f67aec3c2160549d6610c1a7594b5e9f8f7886f4345870313b3ffdb4c7e0877d19999f1553e465b32074ccc8f83a8fa0bdf2192d197ce6c2b549547e53c35d9a030d5a442302818050b945af63c85f49e531a9fe8098b47d267943f7a1e4442f4c0b83137ecf04f877dc45f83ab0502f5d1a6eb5e3156a864ba9749266519061cc36a2f8a53274af77f7ce8947ca13ce9c261399d355b6a0b429eb1fe049f12b5722be8c920bf6b0cb785a94cd0208369b7a59cc75a3affdfd3d4ec9d32321281bb944a2e3f01ab302818009edc92a5930298f4319f94d05df1298f73d5113f36376c4ed821a4a07af72c6ba85417018254ff261af6bcc2becbae3d83404a6a1e2fd8e872b1e2e82807d13e337fdbe9f9a5a2dca782eba9e2c5c8fc1838580d5354f018a293f0d200cbbf89d3d06adc9790b255bb802161ac7802fcd8e29b66442e03b5c6a28686e904fdb0281801562d916f03b38267ae6dea182084b92261fc064af390d996a6291137c50205715e7dd8433cdefe320231a983db9bda0141e8141262bf7ee2cca3150aa09ccc243711834c2589e8f5c5640796480472eb48811129904b3cc5b8f3d427a372ef6c890fa6218c82904f7684f68be808da223431febb899bc7e1ff1ec76a717a953";
const RSA_N: &str = "b6c35fa8a4f01b77b3da6e070d0c0100b71d69fac1ccc5134862c2e24e0214b29f9335b28bfc958e9dba4f5fae39e5bda549d3ef3df469eeb5b383829e6fc26fd9e30510822cc225569a7e921d15dce61e376b6110aba71514955843467f09d9906ac7b0e225d71bf821aa692fbd4dd1f64cefa88c5c67b461f0b625820a3ac593a3dc875a51781b3633cc2107f3108b1e162861cf77a7078cab5e1f049a66a785d2d2d1a53803a83c8fca2b172802af52ab114718e389a5d184649fc6d7c2eadc182cafbcf4e9751c4bb63d8203286692c8ce5d63d25f06caaf28edb31f1cdd4c0eea5e6a01fee742e101478c3afc546e422757914876387d0166f183a1ccad";
const RSA_E: &str = "010001";
const RSA_D: &str = "02af6bfaaea5b4133610c69edfb34cc01270aee53d95811f5c4e67f79dd6cc300dac5c54b68ad29c1c50f48e986dd38acde0998374a779f75eccaae915e3d8ac983c0c8fb33b87b7ea85ed94bf000dbbb83755a27428bfe20081eb3a2a9e17d0db03a50542322855705e2a428194c1f40caede195dc42d664a2db21dd129ce503aadaa10eb1b273a5246f3b747057170c44802b967938c5b6c5bd396d6d9691d4ce282e0b525ab28099f13b294a6c1aff74bebe343c1a8de77c5d46abda2fec6b0fe91ecd12e6ca3aa29f552c8ffad6281c283e6361932f8301ac97ce9a1794c4c174b0375e1aeb637da0970490fffa6c654e31fe58edee55bdaf35332b363df";
const RSA_P: &str = "def81e0b796390b8971706cf55dd3f8f0b9fea15ec2b01e228b4d21fa21dc138c5a067744349dce3481ffa4e805d5e0140eac79fb415ddeb9241445d5a071ea6e037a83aad1ea5f84bbfbc53ee15aa2a0038f5d84f6df8708eead127e5134f6847ffce6ca510aecb8ca66dee5d334cb2c5a1f0376f63a4ab9aa33f58a41e10ef";
const RSA_Q: &str = "d1d67bad4f6066fada8a3a87d0c97873111cac25aee23605cd3b56f0b9b416a2688317a3ab94affad9ed228e771e08cc54319a58df5c2ab9255e23f67aec3c2160549d6610c1a7594b5e9f8f7886f4345870313b3ffdb4c7e0877d19999f1553e465b32074ccc8f83a8fa0bdf2192d197ce6c2b549547e53c35d9a030d5a4423";
const RSA_DP: &str = "50b945af63c85f49e531a9fe8098b47d267943f7a1e4442f4c0b83137ecf04f877dc45f83ab0502f5d1a6eb5e3156a864ba9749266519061cc36a2f8a53274af77f7ce8947ca13ce9c261399d355b6a0b429eb1fe049f12b5722be8c920bf6b0cb785a94cd0208369b7a59cc75a3affdfd3d4ec9d32321281bb944a2e3f01ab3";
const RSA_DQ: &str = "09edc92a5930298f4319f94d05df1298f73d5113f36376c4ed821a4a07af72c6ba85417018254ff261af6bcc2becbae3d83404a6a1e2fd8e872b1e2e82807d13e337fdbe9f9a5a2dca782eba9e2c5c8fc1838580d5354f018a293f0d200cbbf89d3d06adc9790b255bb802161ac7802fcd8e29b66442e03b5c6a28686e904fdb";
const RSA_QINV: &str = "1562d916f03b38267ae6dea182084b92261fc064af390d996a6291137c50205715e7dd8433cdefe320231a983db9bda0141e8141262bf7ee2cca3150aa09ccc243711834c2589e8f5c5640796480472eb48811129904b3cc5b8f3d427a372ef6c890fa6218c82904f7684f68be808da223431febb899bc7e1ff1ec76a717a953";

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s.split_whitespace().collect::<String>()).unwrap()
}

fn rsa_cose_key(alg: i64) -> Key {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeRSA)
        .set_alg(alg)
        .set_kid(b"rsa-1".to_vec());
    key.insert(iana::RSAKeyParameterN, hx(RSA_N));
    key.insert(iana::RSAKeyParameterE, hx(RSA_E));
    key.insert(iana::RSAKeyParameterD, hx(RSA_D));
    key.insert(iana::RSAKeyParameterP, hx(RSA_P));
    key.insert(iana::RSAKeyParameterQ, hx(RSA_Q));
    key.insert(iana::RSAKeyParameterDP, hx(RSA_DP));
    key.insert(iana::RSAKeyParameterDQ, hx(RSA_DQ));
    key.insert(iana::RSAKeyParameterQInv, hx(RSA_QINV));
    key
}

fn symmetric_key(alg: i64, key_bytes: Vec<u8>) -> Key {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeSymmetric)
        .set_alg(alg)
        .set_kid(b"sym-1".to_vec());
    key.insert(iana::SymmetricKeyParameterK, key_bytes);
    key
}

#[test]
fn aws_lc_rs_ed25519_pkcs8_signs_and_verifies_sign1() {
    let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let signer = RingSigner::ed25519_from_pkcs8(pkcs8.as_ref(), Some(b"ed-1".to_vec())).unwrap();
    let verifier =
        RingVerifier::ed25519(signer.public_key().unwrap(), Some(b"ed-1".to_vec())).unwrap();

    let mut msg = Sign1Message::new(Some(b"aws-lc-rs eddsa".to_vec()));
    let encoded = msg.sign_and_encode(&signer, Some(b"aad")).unwrap();

    let decoded = Sign1Message::verify_and_decode(&verifier, &encoded, Some(b"aad")).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"aws-lc-rs eddsa"[..]));
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, Some(b"nope")).is_err());
}

/// Exercises the `aws-lc-rs` arm of `ecdsa_from_pkcs8` (no RNG argument).
#[test]
fn aws_lc_rs_es256_pkcs8_signs_and_verifies_sign1() {
    let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &SystemRandom::new(),
    )
    .unwrap();
    let signer = RingSigner::es256_from_pkcs8(pkcs8.as_ref(), None).unwrap();
    let verifier =
        RingVerifier::ecdsa(iana::AlgorithmES256, signer.public_key().unwrap(), None).unwrap();

    let mut msg = Sign1Message::new(Some(b"ecdsa payload".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert_eq!(msg.signature().len(), 64);

    let decoded = Sign1Message::verify_and_decode(&verifier, &encoded, None).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"ecdsa payload"[..]));
}

/// Exercises the `aws-lc-rs` arm of `ecdsa_from_cose_key`
/// (`from_private_key_and_public_key`, no RNG argument).
#[test]
fn aws_lc_rs_es256_from_cose_key_signs_and_verifies_sign1() {
    let pub_key = hx(P256_PUB);
    let (x, y) = pub_key[1..].split_at(32);

    let mut key = Key::new();
    key.set_kty(iana::KeyTypeEC2)
        .set_alg(iana::AlgorithmES256)
        .set_kid(b"p256-1".to_vec());
    key.insert(iana::EC2KeyParameterCrv, iana::EllipticCurveP_256);
    key.insert(iana::EC2KeyParameterX, x.to_vec());
    key.insert(iana::EC2KeyParameterY, y.to_vec());
    key.insert(iana::EC2KeyParameterD, hx(P256_D));

    let signer = RingSigner::from_cose_key(&key).unwrap();
    let verifier = RingVerifier::from_cose_key(&key).unwrap();

    let mut msg = Sign1Message::new(Some(b"cose ec2 key".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();

    let decoded = Sign1Message::verify_and_decode(&verifier, &encoded, None).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"cose ec2 key"[..]));
}

/// Exercises the RSA signing path (`public_modulus_len`) and component-based
/// verification. Building an RSA *signer* from raw COSE_Key components is not
/// supported by `aws-lc-rs`, so a PKCS#8 key is used instead.
#[test]
fn aws_lc_rs_rsa_pkcs8_signs_and_component_verifier_checks_sign1() {
    let signer = RingSigner::rsa_from_pkcs8(iana::AlgorithmRS256, &hx(RSA_PKCS8), None).unwrap();
    let verifier =
        RingVerifier::rsa_components(iana::AlgorithmRS256, &hx(RSA_N), &hx(RSA_E), None).unwrap();

    let mut msg = Sign1Message::new(Some(b"rsa payload".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert_eq!(msg.signature().len(), 256);

    let decoded = Sign1Message::verify_and_decode(&verifier, &encoded, None).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"rsa payload"[..]));
}

/// Building an RSA signer from a COSE_Key's raw CRT components: `aws-lc-rs` has
/// no `from_components`, so the provider serializes them into PKCS#1 DER and
/// parses that. Every registered padding must round-trip.
#[test]
fn aws_lc_rs_rsa_from_cose_key_signs_and_verifies_every_padding() {
    for alg in [
        iana::AlgorithmRS256,
        iana::AlgorithmRS384,
        iana::AlgorithmRS512,
        iana::AlgorithmPS256,
        iana::AlgorithmPS384,
        iana::AlgorithmPS512,
    ] {
        let key = rsa_cose_key(alg);
        let signer = RingSigner::from_cose_key(&key).unwrap();
        let verifier = RingVerifier::from_cose_key(&key).unwrap();

        let mut msg = Sign1Message::new(Some(b"rsa cose key".to_vec()));
        let encoded = msg.sign_and_encode(&signer, None).unwrap();
        assert_eq!(msg.signature().len(), 256, "alg {alg}");

        let decoded = Sign1Message::verify_and_decode(&verifier, &encoded, None).unwrap();
        assert_eq!(
            decoded.payload.as_deref(),
            Some(&b"rsa cose key"[..]),
            "alg {alg}"
        );
    }
}

#[test]
fn aws_lc_rs_hmac_from_cose_key_computes_truncated_mac0_tag() {
    let key = symmetric_key(iana::AlgorithmHMAC_256_64, vec![0x11; 32]);
    let macer = RingMacer::from_cose_key(&key).unwrap();

    let mut msg = Mac0Message::new(Some(b"authenticated".to_vec()));
    let encoded = msg.compute_and_encode(&macer, None).unwrap();
    assert_eq!(msg.tag().len(), 8);

    assert!(Mac0Message::verify_and_decode(&macer, &encoded, None).is_ok());
    assert!(Mac0Message::verify_and_decode(&macer, &encoded, Some(b"aad")).is_err());
}

/// Exercises the `Arc`-wrapped `LessSafeKey`: the clone must decrypt what the
/// original sealed, proving `RingEncryptor: Clone` works on `aws-lc-rs`.
#[test]
fn aws_lc_rs_aead_provider_clone_round_trips_encrypt0() {
    let key = symmetric_key(iana::AlgorithmA256GCM, vec![0x22; 32]);
    let encryptor = RingEncryptor::from_cose_key(&key).unwrap();

    let mut msg = Encrypt0Message::new(Some(b"secret".to_vec()));
    msg.unprotected.set_iv(vec![0xaau8; 12]);
    let encoded = msg.encrypt_and_encode(&encryptor, Some(b"aad")).unwrap();
    assert!(!msg.ciphertext().is_empty());

    let decryptor = encryptor.clone();
    let decoded = Encrypt0Message::decrypt_and_decode(&decryptor, &encoded, Some(b"aad")).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"secret"[..]));
    assert!(Encrypt0Message::decrypt_and_decode(&decryptor, &encoded, Some(b"x")).is_err());
}

#[test]
fn aws_lc_rs_backend_rejects_unsupported_algorithms() {
    assert!(RingEncryptor::new(iana::AlgorithmA192GCM, &[0u8; 24], None).is_err());
    assert!(RingMacer::new(iana::AlgorithmAES_MAC_128_64, &[0u8; 16], None).is_err());
    assert!(RingVerifier::ecdsa(iana::AlgorithmES512, &[0u8; 133], None).is_err());
}

// The RSA-2048 public key as a PKCS#1 `RSAPublicKey` DER (`SEQUENCE { n, e }`).
const RSA_PKCS1_PUB: &str = "3082010a0282010100b6c35fa8a4f01b77b3da6e070d0c0100b71d69fac1ccc5134862c2e24e0214b29f9335b28bfc958e9dba4f5fae39e5bda549d3ef3df469eeb5b383829e6fc26fd9e30510822cc225569a7e921d15dce61e376b6110aba71514955843467f09d9906ac7b0e225d71bf821aa692fbd4dd1f64cefa88c5c67b461f0b625820a3ac593a3dc875a51781b3633cc2107f3108b1e162861cf77a7078cab5e1f049a66a785d2d2d1a53803a83c8fca2b172802af52ab114718e389a5d184649fc6d7c2eadc182cafbcf4e9751c4bb63d8203286692c8ce5d63d25f06caaf28edb31f1cdd4c0eea5e6a01fee742e101478c3afc546e422757914876387d0166f183a1ccad0203010001";

#[test]
fn aws_lc_rs_symmetric_providers_export_cose_keys() {
    // HMAC: exporting reproduces the symmetric COSE_Key it was built from.
    let mac_key = symmetric_key(iana::AlgorithmHMAC_256_256, vec![0x11; 32]);
    let macer = RingMacer::from_cose_key(&mac_key).unwrap();
    assert_eq!(macer.to_cose_key().unwrap(), mac_key);

    // AEAD: the Base IV is carried across the round trip too.
    let mut enc_key = symmetric_key(iana::AlgorithmA128GCM, vec![0x22; 16]);
    enc_key.insert(iana::KeyParameterBaseIV, vec![0xaau8; 12]);
    let encryptor = RingEncryptor::from_cose_key(&enc_key).unwrap();
    assert_eq!(encryptor.to_cose_key().unwrap(), enc_key);
}

#[test]
fn aws_lc_rs_signer_and_verifier_export_public_cose_keys() {
    // Ed25519: verify with a verifier rebuilt from the signer's exported key.
    let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let signer = RingSigner::ed25519_from_pkcs8(pkcs8.as_ref(), Some(b"ed-1".to_vec())).unwrap();
    let public = signer.to_cose_key().unwrap();
    assert!(public.get_bytes(iana::OKPKeyParameterD).unwrap().is_none());
    assert_eq!(public.kid().unwrap(), Some(&b"ed-1"[..]));

    let mut msg = Sign1Message::new(Some(b"ed25519 export".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    let verifier = RingVerifier::from_cose_key(&public).unwrap();
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());
    assert_eq!(verifier.to_cose_key().unwrap(), public);

    // ES256 from a COSE_Key: the exported public key still verifies.
    let pub_key = hx(P256_PUB);
    let (x, y) = pub_key[1..].split_at(32);
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeEC2)
        .set_alg(iana::AlgorithmES256)
        .set_kid(b"p256-1".to_vec());
    key.insert(iana::EC2KeyParameterCrv, iana::EllipticCurveP_256);
    key.insert(iana::EC2KeyParameterX, x.to_vec());
    key.insert(iana::EC2KeyParameterY, y.to_vec());
    key.insert(iana::EC2KeyParameterD, hx(P256_D));

    let signer = RingSigner::from_cose_key(&key).unwrap();
    let exported = signer.to_cose_key().unwrap();
    assert!(exported
        .get_bytes(iana::EC2KeyParameterD)
        .unwrap()
        .is_none());
    let mut msg = Sign1Message::new(Some(b"es256 export".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    let verifier = RingVerifier::from_cose_key(&exported).unwrap();
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());
}

#[test]
fn aws_lc_rs_rsa_verifier_exports_n_and_e() {
    // From explicit components: exporting reproduces n and e verbatim.
    let from_components =
        RingVerifier::rsa_components(iana::AlgorithmRS256, &hx(RSA_N), &hx(RSA_E), None).unwrap();
    let exported = from_components.to_cose_key().unwrap();
    assert_eq!(
        exported.get_bytes(iana::RSAKeyParameterN).unwrap(),
        Some(&hx(RSA_N)[..])
    );
    assert_eq!(
        exported.get_bytes(iana::RSAKeyParameterE).unwrap(),
        Some(&hx(RSA_E)[..])
    );

    // From a DER public key: the PKCS#1 RSAPublicKey is parsed back to n and e.
    let from_der = RingVerifier::rsa_der(iana::AlgorithmRS256, &hx(RSA_PKCS1_PUB), None).unwrap();
    let exported = from_der.to_cose_key().unwrap();
    assert_eq!(
        exported.get_bytes(iana::RSAKeyParameterN).unwrap(),
        Some(&hx(RSA_N)[..])
    );
    assert_eq!(
        exported.get_bytes(iana::RSAKeyParameterE).unwrap(),
        Some(&hx(RSA_E)[..])
    );

    // An RSA signer exposes no public modulus, so it cannot export a COSE_Key.
    let signer = RingSigner::rsa_from_pkcs8(iana::AlgorithmRS256, &hx(RSA_PKCS8), None).unwrap();
    assert!(signer.to_cose_key().is_err());
}
