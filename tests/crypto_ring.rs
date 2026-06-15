#![cfg(feature = "crypto-ring")]

use cose2::{
    crypto::{RingEncryptor, RingMacer, RingSigner, RingVerifier},
    iana, Encrypt0Message, Encryptor, Key, Mac0Message, Macer, Sign1Message,
};
use ring::{rand::SystemRandom, signature, signature::KeyPair};

fn symmetric_key(alg: i64, key_bytes: Vec<u8>) -> Key {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeSymmetric)
        .set_alg(alg)
        .set_kid(b"sym-1".to_vec());
    key.insert(iana::SymmetricKeyParameterK, key_bytes);
    key
}

#[test]
fn ring_ed25519_from_cose_key_signs_and_verifies_sign1() {
    let seed = [7u8; 32];
    let pair = signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();

    let mut key = Key::new();
    key.set_kty(iana::KeyTypeOKP)
        .set_alg(iana::AlgorithmEdDSA)
        .set_kid(b"ed25519-1".to_vec());
    key.insert(iana::OKPKeyParameterCrv, iana::EllipticCurveEd25519);
    key.insert(iana::OKPKeyParameterX, pair.public_key().as_ref().to_vec());
    key.insert(iana::OKPKeyParameterD, seed.to_vec());

    let signer = RingSigner::from_cose_key(&key).unwrap();
    let verifier = RingVerifier::from_cose_key(&key).unwrap();

    let mut msg = Sign1Message::new(Some(b"hello cose".to_vec()));
    let encoded = msg.sign_and_encode(&signer, Some(b"aad")).unwrap();
    assert!(!msg.signature().is_empty());

    let decoded = Sign1Message::verify_and_decode(&verifier, &encoded, Some(b"aad")).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"hello cose"[..]));
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, Some(b"wrong")).is_err());
}

#[test]
fn ring_es256_pkcs8_signs_and_verifies_sign1() {
    let rng = SystemRandom::new();
    let pkcs8 =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
    let signer = RingSigner::es256_from_pkcs8(pkcs8.as_ref(), Some(b"p256-1".to_vec())).unwrap();
    let public_key = signer.public_key().unwrap().to_vec();
    let verifier =
        RingVerifier::ecdsa(iana::AlgorithmES256, &public_key, Some(b"p256-1".to_vec())).unwrap();

    let mut msg = Sign1Message::new(Some(b"ecdsa payload".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert_eq!(msg.signature().len(), 64);

    let decoded = Sign1Message::verify_and_decode(&verifier, &encoded, None).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"ecdsa payload"[..]));
}

#[test]
fn ring_hmac_from_cose_key_computes_truncated_mac0_tag() {
    let key = symmetric_key(iana::AlgorithmHMAC_256_64, vec![0x11; 32]);
    let macer = RingMacer::from_cose_key(&key).unwrap();

    let mut msg = Mac0Message::new(Some(b"authenticated".to_vec()));
    let encoded = msg.compute_and_encode(&macer, None).unwrap();
    assert_eq!(msg.tag().len(), 8);

    assert!(Mac0Message::verify_and_decode(&macer, &encoded, None).is_ok());
    assert!(Mac0Message::verify_and_decode(&macer, &encoded, Some(b"aad")).is_err());
}

#[test]
fn ring_aead_from_cose_key_encrypts_with_partial_iv() {
    let mut key = symmetric_key(iana::AlgorithmA128GCM, vec![0x22; 16]);
    key.insert(iana::KeyParameterBaseIV, vec![0xaau8; 12]);
    let encryptor = RingEncryptor::from_cose_key(&key).unwrap();

    let mut msg = Encrypt0Message::new(Some(b"secret".to_vec()));
    msg.unprotected.set_partial_iv(vec![0x01, 0x02]);
    let encoded = msg.encrypt_and_encode(&encryptor, Some(b"aad")).unwrap();
    assert!(!msg.ciphertext().is_empty());

    let decoded = Encrypt0Message::decrypt_and_decode(&encryptor, &encoded, Some(b"aad")).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"secret"[..]));
    assert!(Encrypt0Message::decrypt_and_decode(&encryptor, &encoded, Some(b"wrong")).is_err());
}

/// RFC 9052 Appendix C.2.1 "Single ECDSA Signature".
///
/// Decoding the RFC's own COSE_Sign1 bytes and verifying its real ECDSA-P256
/// signature with the matching C.7.1 public key (kid "11") confirms that this
/// crate's `Sig_structure` construction is byte-exact: ECDSA verification only
/// succeeds if the ToBeSigned bytes match those the RFC signed.
#[test]
fn ring_verifies_rfc9052_c2_1_sign1_vector() {
    // The complete tagged COSE_Sign1 message from Appendix C.2.1.
    let message = hex::decode(
        "d28443a10126a10442313154546869732069732074686520636f6e74656e742e\
         58408eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0\
         117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345ca\
         cb36",
    )
    .unwrap();

    // The P-256 public key with kid "11" from Appendix C.7.1.
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeEC2)
        .set_alg(iana::AlgorithmES256)
        .set_kid(b"11".to_vec());
    key.insert(iana::EC2KeyParameterCrv, iana::EllipticCurveP_256);
    key.insert(
        iana::EC2KeyParameterX,
        hex::decode("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff").unwrap(),
    );
    key.insert(
        iana::EC2KeyParameterY,
        hex::decode("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e").unwrap(),
    );
    let verifier = RingVerifier::from_cose_key(&key).unwrap();

    let decoded = Sign1Message::verify_and_decode(&verifier, &message, None).unwrap();
    assert_eq!(
        decoded.payload.as_deref(),
        Some(&b"This is the content."[..])
    );
    assert_eq!(decoded.protected.alg().unwrap().unwrap().as_int(), Some(-7));
    assert_eq!(decoded.unprotected.kid().unwrap(), Some(&b"11"[..]));

    // Tampering with the payload breaks verification.
    let mut tampered = message.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(Sign1Message::verify_and_decode(&verifier, &tampered, None).is_err());
}

#[test]
fn ring_backend_rejects_unsupported_algorithms() {
    assert!(RingEncryptor::new(iana::AlgorithmA192GCM, &[0u8; 24], None).is_err());
    assert!(RingMacer::new(iana::AlgorithmAES_MAC_128_64, &[0u8; 16], None).is_err());
    assert!(RingVerifier::ecdsa(iana::AlgorithmES512, &[0u8; 133], None).is_err());
}

// ----------------------------------------------------------------------------
// Backend coverage: ECDSA P-384, RSA (all paddings), extra HMAC/AEAD, and the
// error paths of the ring providers.
// ----------------------------------------------------------------------------

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

// A static, throwaway RSA-2048 key in every form the backend accepts.
const RSA_PKCS8: &str = "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201000282010100b6c35fa8a4f01b77b3da6e070d0c0100b71d69fac1ccc5134862c2e24e0214b29f9335b28bfc958e9dba4f5fae39e5bda549d3ef3df469eeb5b383829e6fc26fd9e30510822cc225569a7e921d15dce61e376b6110aba71514955843467f09d9906ac7b0e225d71bf821aa692fbd4dd1f64cefa88c5c67b461f0b625820a3ac593a3dc875a51781b3633cc2107f3108b1e162861cf77a7078cab5e1f049a66a785d2d2d1a53803a83c8fca2b172802af52ab114718e389a5d184649fc6d7c2eadc182cafbcf4e9751c4bb63d8203286692c8ce5d63d25f06caaf28edb31f1cdd4c0eea5e6a01fee742e101478c3afc546e422757914876387d0166f183a1ccad02030100010282010002af6bfaaea5b4133610c69edfb34cc01270aee53d95811f5c4e67f79dd6cc300dac5c54b68ad29c1c50f48e986dd38acde0998374a779f75eccaae915e3d8ac983c0c8fb33b87b7ea85ed94bf000dbbb83755a27428bfe20081eb3a2a9e17d0db03a50542322855705e2a428194c1f40caede195dc42d664a2db21dd129ce503aadaa10eb1b273a5246f3b747057170c44802b967938c5b6c5bd396d6d9691d4ce282e0b525ab28099f13b294a6c1aff74bebe343c1a8de77c5d46abda2fec6b0fe91ecd12e6ca3aa29f552c8ffad6281c283e6361932f8301ac97ce9a1794c4c174b0375e1aeb637da0970490fffa6c654e31fe58edee55bdaf35332b363df02818100def81e0b796390b8971706cf55dd3f8f0b9fea15ec2b01e228b4d21fa21dc138c5a067744349dce3481ffa4e805d5e0140eac79fb415ddeb9241445d5a071ea6e037a83aad1ea5f84bbfbc53ee15aa2a0038f5d84f6df8708eead127e5134f6847ffce6ca510aecb8ca66dee5d334cb2c5a1f0376f63a4ab9aa33f58a41e10ef02818100d1d67bad4f6066fada8a3a87d0c97873111cac25aee23605cd3b56f0b9b416a2688317a3ab94affad9ed228e771e08cc54319a58df5c2ab9255e23f67aec3c2160549d6610c1a7594b5e9f8f7886f4345870313b3ffdb4c7e0877d19999f1553e465b32074ccc8f83a8fa0bdf2192d197ce6c2b549547e53c35d9a030d5a442302818050b945af63c85f49e531a9fe8098b47d267943f7a1e4442f4c0b83137ecf04f877dc45f83ab0502f5d1a6eb5e3156a864ba9749266519061cc36a2f8a53274af77f7ce8947ca13ce9c261399d355b6a0b429eb1fe049f12b5722be8c920bf6b0cb785a94cd0208369b7a59cc75a3affdfd3d4ec9d32321281bb944a2e3f01ab302818009edc92a5930298f4319f94d05df1298f73d5113f36376c4ed821a4a07af72c6ba85417018254ff261af6bcc2becbae3d83404a6a1e2fd8e872b1e2e82807d13e337fdbe9f9a5a2dca782eba9e2c5c8fc1838580d5354f018a293f0d200cbbf89d3d06adc9790b255bb802161ac7802fcd8e29b66442e03b5c6a28686e904fdb0281801562d916f03b38267ae6dea182084b92261fc064af390d996a6291137c50205715e7dd8433cdefe320231a983db9bda0141e8141262bf7ee2cca3150aa09ccc243711834c2589e8f5c5640796480472eb48811129904b3cc5b8f3d427a372ef6c890fa6218c82904f7684f68be808da223431febb899bc7e1ff1ec76a717a953";
const RSA_PKCS1_PRIV: &str = "308204a20201000282010100b6c35fa8a4f01b77b3da6e070d0c0100b71d69fac1ccc5134862c2e24e0214b29f9335b28bfc958e9dba4f5fae39e5bda549d3ef3df469eeb5b383829e6fc26fd9e30510822cc225569a7e921d15dce61e376b6110aba71514955843467f09d9906ac7b0e225d71bf821aa692fbd4dd1f64cefa88c5c67b461f0b625820a3ac593a3dc875a51781b3633cc2107f3108b1e162861cf77a7078cab5e1f049a66a785d2d2d1a53803a83c8fca2b172802af52ab114718e389a5d184649fc6d7c2eadc182cafbcf4e9751c4bb63d8203286692c8ce5d63d25f06caaf28edb31f1cdd4c0eea5e6a01fee742e101478c3afc546e422757914876387d0166f183a1ccad02030100010282010002af6bfaaea5b4133610c69edfb34cc01270aee53d95811f5c4e67f79dd6cc300dac5c54b68ad29c1c50f48e986dd38acde0998374a779f75eccaae915e3d8ac983c0c8fb33b87b7ea85ed94bf000dbbb83755a27428bfe20081eb3a2a9e17d0db03a50542322855705e2a428194c1f40caede195dc42d664a2db21dd129ce503aadaa10eb1b273a5246f3b747057170c44802b967938c5b6c5bd396d6d9691d4ce282e0b525ab28099f13b294a6c1aff74bebe343c1a8de77c5d46abda2fec6b0fe91ecd12e6ca3aa29f552c8ffad6281c283e6361932f8301ac97ce9a1794c4c174b0375e1aeb637da0970490fffa6c654e31fe58edee55bdaf35332b363df02818100def81e0b796390b8971706cf55dd3f8f0b9fea15ec2b01e228b4d21fa21dc138c5a067744349dce3481ffa4e805d5e0140eac79fb415ddeb9241445d5a071ea6e037a83aad1ea5f84bbfbc53ee15aa2a0038f5d84f6df8708eead127e5134f6847ffce6ca510aecb8ca66dee5d334cb2c5a1f0376f63a4ab9aa33f58a41e10ef02818100d1d67bad4f6066fada8a3a87d0c97873111cac25aee23605cd3b56f0b9b416a2688317a3ab94affad9ed228e771e08cc54319a58df5c2ab9255e23f67aec3c2160549d6610c1a7594b5e9f8f7886f4345870313b3ffdb4c7e0877d19999f1553e465b32074ccc8f83a8fa0bdf2192d197ce6c2b549547e53c35d9a030d5a442302818050b945af63c85f49e531a9fe8098b47d267943f7a1e4442f4c0b83137ecf04f877dc45f83ab0502f5d1a6eb5e3156a864ba9749266519061cc36a2f8a53274af77f7ce8947ca13ce9c261399d355b6a0b429eb1fe049f12b5722be8c920bf6b0cb785a94cd0208369b7a59cc75a3affdfd3d4ec9d32321281bb944a2e3f01ab302818009edc92a5930298f4319f94d05df1298f73d5113f36376c4ed821a4a07af72c6ba85417018254ff261af6bcc2becbae3d83404a6a1e2fd8e872b1e2e82807d13e337fdbe9f9a5a2dca782eba9e2c5c8fc1838580d5354f018a293f0d200cbbf89d3d06adc9790b255bb802161ac7802fcd8e29b66442e03b5c6a28686e904fdb0281801562d916f03b38267ae6dea182084b92261fc064af390d996a6291137c50205715e7dd8433cdefe320231a983db9bda0141e8141262bf7ee2cca3150aa09ccc243711834c2589e8f5c5640796480472eb48811129904b3cc5b8f3d427a372ef6c890fa6218c82904f7684f68be808da223431febb899bc7e1ff1ec76a717a953";
const RSA_PKCS1_PUB: &str = "3082010a0282010100b6c35fa8a4f01b77b3da6e070d0c0100b71d69fac1ccc5134862c2e24e0214b29f9335b28bfc958e9dba4f5fae39e5bda549d3ef3df469eeb5b383829e6fc26fd9e30510822cc225569a7e921d15dce61e376b6110aba71514955843467f09d9906ac7b0e225d71bf821aa692fbd4dd1f64cefa88c5c67b461f0b625820a3ac593a3dc875a51781b3633cc2107f3108b1e162861cf77a7078cab5e1f049a66a785d2d2d1a53803a83c8fca2b172802af52ab114718e389a5d184649fc6d7c2eadc182cafbcf4e9751c4bb63d8203286692c8ce5d63d25f06caaf28edb31f1cdd4c0eea5e6a01fee742e101478c3afc546e422757914876387d0166f183a1ccad0203010001";
const RSA_N: &str = "b6c35fa8a4f01b77b3da6e070d0c0100b71d69fac1ccc5134862c2e24e0214b29f9335b28bfc958e9dba4f5fae39e5bda549d3ef3df469eeb5b383829e6fc26fd9e30510822cc225569a7e921d15dce61e376b6110aba71514955843467f09d9906ac7b0e225d71bf821aa692fbd4dd1f64cefa88c5c67b461f0b625820a3ac593a3dc875a51781b3633cc2107f3108b1e162861cf77a7078cab5e1f049a66a785d2d2d1a53803a83c8fca2b172802af52ab114718e389a5d184649fc6d7c2eadc182cafbcf4e9751c4bb63d8203286692c8ce5d63d25f06caaf28edb31f1cdd4c0eea5e6a01fee742e101478c3afc546e422757914876387d0166f183a1ccad";
const RSA_E: &str = "010001";
const RSA_D: &str = "02af6bfaaea5b4133610c69edfb34cc01270aee53d95811f5c4e67f79dd6cc300dac5c54b68ad29c1c50f48e986dd38acde0998374a779f75eccaae915e3d8ac983c0c8fb33b87b7ea85ed94bf000dbbb83755a27428bfe20081eb3a2a9e17d0db03a50542322855705e2a428194c1f40caede195dc42d664a2db21dd129ce503aadaa10eb1b273a5246f3b747057170c44802b967938c5b6c5bd396d6d9691d4ce282e0b525ab28099f13b294a6c1aff74bebe343c1a8de77c5d46abda2fec6b0fe91ecd12e6ca3aa29f552c8ffad6281c283e6361932f8301ac97ce9a1794c4c174b0375e1aeb637da0970490fffa6c654e31fe58edee55bdaf35332b363df";
const RSA_P: &str = "def81e0b796390b8971706cf55dd3f8f0b9fea15ec2b01e228b4d21fa21dc138c5a067744349dce3481ffa4e805d5e0140eac79fb415ddeb9241445d5a071ea6e037a83aad1ea5f84bbfbc53ee15aa2a0038f5d84f6df8708eead127e5134f6847ffce6ca510aecb8ca66dee5d334cb2c5a1f0376f63a4ab9aa33f58a41e10ef";
const RSA_Q: &str = "d1d67bad4f6066fada8a3a87d0c97873111cac25aee23605cd3b56f0b9b416a2688317a3ab94affad9ed228e771e08cc54319a58df5c2ab9255e23f67aec3c2160549d6610c1a7594b5e9f8f7886f4345870313b3ffdb4c7e0877d19999f1553e465b32074ccc8f83a8fa0bdf2192d197ce6c2b549547e53c35d9a030d5a4423";
const RSA_DP: &str = "50b945af63c85f49e531a9fe8098b47d267943f7a1e4442f4c0b83137ecf04f877dc45f83ab0502f5d1a6eb5e3156a864ba9749266519061cc36a2f8a53274af77f7ce8947ca13ce9c261399d355b6a0b429eb1fe049f12b5722be8c920bf6b0cb785a94cd0208369b7a59cc75a3affdfd3d4ec9d32321281bb944a2e3f01ab3";
const RSA_DQ: &str = "09edc92a5930298f4319f94d05df1298f73d5113f36376c4ed821a4a07af72c6ba85417018254ff261af6bcc2becbae3d83404a6a1e2fd8e872b1e2e82807d13e337fdbe9f9a5a2dca782eba9e2c5c8fc1838580d5354f018a293f0d200cbbf89d3d06adc9790b255bb802161ac7802fcd8e29b66442e03b5c6a28686e904fdb";
const RSA_QINV: &str = "1562d916f03b38267ae6dea182084b92261fc064af390d996a6291137c50205715e7dd8433cdefe320231a983db9bda0141e8141262bf7ee2cca3150aa09ccc243711834c2589e8f5c5640796480472eb48811129904b3cc5b8f3d427a372ef6c890fa6218c82904f7684f68be808da223431febb899bc7e1ff1ec76a717a953";

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

#[test]
fn ring_es256_from_cose_key_signs_and_verifies() {
    // The P-256 private key with kid "11" (RFC 9052 Appendix C.7.2).
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeEC2)
        .set_alg(iana::AlgorithmES256)
        .set_kid(b"11".to_vec());
    key.insert(iana::EC2KeyParameterCrv, iana::EllipticCurveP_256);
    key.insert(
        iana::EC2KeyParameterX,
        hx("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"),
    );
    key.insert(
        iana::EC2KeyParameterY,
        hx("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"),
    );
    key.insert(
        iana::EC2KeyParameterD,
        hx("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3"),
    );

    let signer = RingSigner::from_cose_key(&key).unwrap();
    let verifier = RingVerifier::from_cose_key(&key).unwrap();
    assert_eq!(signer.algorithm(), iana::AlgorithmES256);
    assert_eq!(signer.public_key().unwrap().len(), 65);

    let mut msg = Sign1Message::new(Some(b"p256 cose".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());
}

#[test]
fn ring_es384_pkcs8_and_cose_key_round_trip() {
    // ES384 via PKCS#8 (signer) verified with a raw uncompressed public key.
    let rng = SystemRandom::new();
    let pkcs8 =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, &rng)
            .unwrap();
    let signer = RingSigner::es384_from_pkcs8(pkcs8.as_ref(), None).unwrap();
    let verifier =
        RingVerifier::ecdsa(iana::AlgorithmES384, signer.public_key().unwrap(), None).unwrap();
    let mut msg = Sign1Message::new(Some(b"es384".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert_eq!(msg.signature().len(), 96);
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());

    // ES384 via COSE_Key (exercises the P-384 arm of ecdsa_from_cose_key).
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeEC2).set_alg(iana::AlgorithmES384);
    key.insert(iana::EC2KeyParameterCrv, iana::EllipticCurveP_384);
    key.insert(iana::EC2KeyParameterX, hx("ec09668cc67445a486e667700671435dabb16367da1ea132f595d6b73061bc2b16d2632abeea310b8b78a7d140e6ffb4"));
    key.insert(iana::EC2KeyParameterY, hx("87cf05d0c44edb7117357d205e0f577f7268ccc33a070a46021b0a763d03e05e7258a9f5849bffc302d7644d596b83dd"));
    key.insert(iana::EC2KeyParameterD, hx("4d44045827ec786aed2c827cc994f59d653a8bc221cb540b65b58264d405d6a33b8ea1e7ec2116e3d8aeba415c83dad1"));
    let signer = RingSigner::from_cose_key(&key).unwrap();
    let verifier = RingVerifier::from_cose_key(&key).unwrap();
    let mut msg = Sign1Message::new(Some(b"es384 cose".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());
}

#[test]
fn ring_rsa_pkcs8_der_and_cose_key_round_trips() {
    let payload = b"rsa payload".to_vec();

    // rsa_from_pkcs8 (signer) verified by rsa_der (PKCS#1 public DER).
    let signer = RingSigner::rsa_from_pkcs8(iana::AlgorithmRS256, &hx(RSA_PKCS8), None).unwrap();
    assert_eq!(signer.algorithm(), iana::AlgorithmRS256);
    assert!(signer.public_key().is_none());
    let verifier = RingVerifier::rsa_der(iana::AlgorithmRS256, &hx(RSA_PKCS1_PUB), None).unwrap();
    let mut msg = Sign1Message::new(Some(payload.clone()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert_eq!(msg.signature().len(), 256);
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());

    // rsa_from_der (signer) verified by rsa_components (n, e).
    let signer = RingSigner::rsa_from_der(iana::AlgorithmRS256, &hx(RSA_PKCS1_PRIV), None).unwrap();
    let verifier =
        RingVerifier::rsa_components(iana::AlgorithmRS256, &hx(RSA_N), &hx(RSA_E), None).unwrap();
    assert_eq!(verifier.algorithm(), iana::AlgorithmRS256);
    let mut msg = Sign1Message::new(Some(payload.clone()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());

    // rsa_from_cose_key (signer) verified by RingVerifier::from_cose_key.
    let key = rsa_cose_key(iana::AlgorithmRS256);
    let signer = RingSigner::from_cose_key(&key).unwrap();
    let verifier = RingVerifier::from_cose_key(&key).unwrap();
    let mut msg = Sign1Message::new(Some(payload));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());
}

#[test]
fn ring_rsa_every_padding_round_trips() {
    for alg in [
        iana::AlgorithmRS256,
        iana::AlgorithmRS384,
        iana::AlgorithmRS512,
        iana::AlgorithmPS256,
        iana::AlgorithmPS384,
        iana::AlgorithmPS512,
    ] {
        let signer = RingSigner::rsa_from_pkcs8(alg, &hx(RSA_PKCS8), None).unwrap();
        let verifier = RingVerifier::rsa_components(alg, &hx(RSA_N), &hx(RSA_E), None).unwrap();
        let mut msg = Sign1Message::new(Some(b"x".to_vec()));
        let encoded = msg.sign_and_encode(&signer, None).unwrap();
        assert!(
            Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok(),
            "alg {alg} failed to round-trip"
        );
    }
}

#[test]
fn ring_hmac_all_sizes_and_aead_variants() {
    for (alg, len) in [
        (iana::AlgorithmHMAC_256_256, 32usize),
        (iana::AlgorithmHMAC_384_384, 48),
        (iana::AlgorithmHMAC_512_512, 64),
    ] {
        let macer = RingMacer::new(alg, &[0x33; 64], Some(b"m".to_vec())).unwrap();
        assert_eq!(macer.algorithm(), alg);
        let mut msg = Mac0Message::new(Some(b"data".to_vec()));
        let encoded = msg.compute_and_encode(&macer, None).unwrap();
        assert_eq!(msg.tag().len(), len);
        assert!(Mac0Message::verify_and_decode(&macer, &encoded, None).is_ok());
    }

    for (alg, key_len) in [
        (iana::AlgorithmA256GCM, 32usize),
        (iana::AlgorithmChaCha20Poly1305, 32),
    ] {
        let enc = RingEncryptor::new(alg, &vec![0x44; key_len], None).unwrap();
        assert_eq!(enc.algorithm(), alg);
        assert_eq!(enc.nonce_size(), 12);
        let mut msg = Encrypt0Message::new(Some(b"secret".to_vec()));
        msg.unprotected.set_iv(vec![0x55; 12]);
        let encoded = msg.encrypt_and_encode(&enc, None).unwrap();
        let decoded = Encrypt0Message::decrypt_and_decode(&enc, &encoded, None).unwrap();
        assert_eq!(decoded.payload.as_deref(), Some(&b"secret"[..]));
    }
}

#[test]
fn ring_encryptor_base_iv_and_debug() {
    let enc = RingEncryptor::new(iana::AlgorithmA128GCM, &[0u8; 16], None)
        .unwrap()
        .with_base_iv(vec![0xaa; 12]);
    assert_eq!(enc.base_iv(), Some(&[0xaa; 12][..]));

    // Debug impls for the signing-key variants.
    let ed = RingSigner::ed25519_from_pkcs8(
        signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref(),
        None,
    )
    .unwrap();
    assert!(format!("{ed:?}").contains("Ed25519"));
    let rsa = RingSigner::rsa_from_pkcs8(iana::AlgorithmRS256, &hx(RSA_PKCS8), None).unwrap();
    assert!(format!("{rsa:?}").contains("Rsa"));
}

#[test]
fn ring_provider_error_paths() {
    // HMAC tag length mismatch on verify.
    let macer = RingMacer::new(iana::AlgorithmHMAC_256_256, b"k", None).unwrap();
    assert!(macer.mac_verify(b"data", b"short").is_err());

    // Unsupported algorithms across every helper.
    assert!(RingMacer::new(iana::AlgorithmES256, b"k", None).is_err());
    assert!(RingSigner::rsa_from_pkcs8(iana::AlgorithmES256, &hx(RSA_PKCS8), None).is_err());
    assert!(
        RingVerifier::rsa_components(iana::AlgorithmES256, &hx(RSA_N), &hx(RSA_E), None).is_err()
    );
    assert!(RingVerifier::rsa_der(iana::AlgorithmES256, &hx(RSA_PKCS1_PUB), None).is_err());

    // from_cose_key validation failures.
    let mut wrong_kty = rsa_cose_key(iana::AlgorithmRS256);
    wrong_kty.set_kty(iana::KeyTypeEC2);
    assert!(RingSigner::from_cose_key(&wrong_kty).is_err());

    let mut no_alg = Key::new();
    no_alg.set_kty(iana::KeyTypeOKP);
    assert!(RingSigner::from_cose_key(&no_alg).is_err());

    let mut text_alg = Key::new();
    text_alg.set_kty(iana::KeyTypeOKP).set_alg("EdDSA");
    assert!(RingSigner::from_cose_key(&text_alg).is_err());

    let mut missing_curve = Key::new();
    missing_curve
        .set_kty(iana::KeyTypeOKP)
        .set_alg(iana::AlgorithmEdDSA);
    assert!(RingSigner::from_cose_key(&missing_curve).is_err());

    let mut wrong_curve = Key::new();
    wrong_curve
        .set_kty(iana::KeyTypeEC2)
        .set_alg(iana::AlgorithmES256);
    wrong_curve.insert(iana::EC2KeyParameterCrv, iana::EllipticCurveP_384);
    wrong_curve.insert(iana::EC2KeyParameterX, vec![0u8; 32]);
    wrong_curve.insert(iana::EC2KeyParameterY, vec![0u8; 32]);
    wrong_curve.insert(iana::EC2KeyParameterD, vec![0u8; 32]);
    assert!(RingSigner::from_cose_key(&wrong_curve).is_err());

    // Missing required key bytes (no `k`).
    let mut no_k = Key::new();
    no_k.set_kty(iana::KeyTypeSymmetric)
        .set_alg(iana::AlgorithmHMAC_256_256);
    assert!(RingMacer::from_cose_key(&no_k).is_err());

    // Verifier from_cose_key unsupported algorithm.
    let mut unsupported = Key::new();
    unsupported
        .set_kty(iana::KeyTypeEC2)
        .set_alg(iana::AlgorithmES512);
    assert!(RingVerifier::from_cose_key(&unsupported).is_err());
}

#[test]
fn ring_accessor_and_debug_and_error_paths() {
    use cose2::{Signer, Verifier};

    // Ed25519 signer public_key() arm + Debug for an ECDSA signing key.
    let ed = RingSigner::ed25519_from_pkcs8(
        signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref(),
        Some(b"ed".to_vec()),
    )
    .unwrap();
    assert_eq!(ed.public_key().unwrap().len(), 32);
    assert_eq!(ed.kid(), Some(&b"ed"[..]));

    let rng = SystemRandom::new();
    let pkcs8 =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
    let ecdsa = RingSigner::es256_from_pkcs8(pkcs8.as_ref(), None).unwrap();
    assert!(format!("{ecdsa:?}").contains("Ecdsa"));

    // Verifier kid() accessor.
    let verifier = RingVerifier::ecdsa(
        iana::AlgorithmES256,
        ecdsa.public_key().unwrap(),
        Some(b"v".to_vec()),
    )
    .unwrap();
    assert_eq!(verifier.kid(), Some(&b"v"[..]));
    assert_eq!(Verifier::alg(&verifier), Some(iana::AlgorithmES256.into()));

    // from_cose_key signing with an algorithm the backend does not sign with.
    let mut content_alg = Key::new();
    content_alg
        .set_kty(iana::KeyTypeSymmetric)
        .set_alg(iana::AlgorithmA128GCM);
    assert!(RingSigner::from_cose_key(&content_alg).is_err());

    // require_kty against a key that is missing kty entirely.
    let mut no_kty = Key(cose2::CoseMap::new());
    no_kty.set_alg(iana::AlgorithmHMAC_256_256);
    assert!(RingMacer::from_cose_key(&no_kty).is_err());
}
