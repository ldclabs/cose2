// Coverage for the `crypto-aes-gcm` backend.
#![cfg(feature = "crypto-aes-gcm")]

use cose2::{aes_gcm::AesGcmEncryptor, iana, Encrypt0Message, Encryptor, Key};

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

// The canonical GCM specification test vectors (McGrew & Viega, "The
// Galois/Counter Mode of Operation"), which share plaintext, nonce and AAD.
const IV: &str = "cafebabefacedbaddecaf888";
const PLAIN: &str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721\
                     c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
const AAD: &str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

/// GCM spec Test Case 4 (AES-128-GCM): proves the provider is wire-exact,
/// including the postfix authentication tag.
#[test]
fn aes_gcm_128_matches_gcm_spec_test_case_4() {
    let key = hx("feffe9928665731c6d6a8f9467308308");
    let ct = hx(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
    );
    let tag = hx("5bc94fbc3221a5db94fae95ae7121a47");

    let enc = AesGcmEncryptor::new(iana::AlgorithmA128GCM, &key, None).unwrap();
    assert_eq!(enc.nonce_size(), 12);

    let sealed = enc.encrypt(&hx(IV), &hx(PLAIN), &hx(AAD)).unwrap();
    assert_eq!(sealed, [ct.clone(), tag].concat());

    // Round-trips, and both a wrong AAD and a tampered tag are rejected.
    assert_eq!(enc.decrypt(&hx(IV), &sealed, &hx(AAD)).unwrap(), hx(PLAIN));
    assert!(enc.decrypt(&hx(IV), &sealed, b"wrong aad").is_err());
    let mut tampered = sealed.clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert!(enc.decrypt(&hx(IV), &tampered, &hx(AAD)).is_err());
}

/// GCM spec Test Case 16 (AES-256-GCM).
#[test]
fn aes_gcm_256_matches_gcm_spec_test_case_16() {
    let key = hx("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let ct = hx(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                 8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
    );
    let tag = hx("76fc6ece0f4e1768cddf8853bb2d551b");

    let enc = AesGcmEncryptor::new(iana::AlgorithmA256GCM, &key, None).unwrap();
    let sealed = enc.encrypt(&hx(IV), &hx(PLAIN), &hx(AAD)).unwrap();
    assert_eq!(sealed, [ct, tag].concat());
    assert_eq!(enc.decrypt(&hx(IV), &sealed, &hx(AAD)).unwrap(), hx(PLAIN));
}

#[test]
fn aes_gcm_from_cose_key_round_trips() {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeSymmetric)
        .set_alg(iana::AlgorithmA256GCM)
        .set_kid(b"sym-1".to_vec());
    key.insert(iana::SymmetricKeyParameterK, vec![0x11u8; 32]);
    key.insert(iana::KeyParameterBaseIV, vec![0xaau8; 12]);

    let enc = AesGcmEncryptor::from_cose_key(&key).unwrap();
    assert_eq!(enc.algorithm(), iana::AlgorithmA256GCM);
    assert_eq!(enc.base_iv(), Some(&[0xaau8; 12][..]));
    // Exporting reproduces the symmetric COSE_Key, Base IV included.
    assert_eq!(enc.to_cose_key().unwrap(), key);

    // The retained raw key stays out of the redacted Debug output.
    assert!(!format!("{enc:?}").contains("raw_key"));
}

#[test]
fn aes_gcm_encrypt0_with_partial_iv() {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeSymmetric)
        .set_alg(iana::AlgorithmA128GCM);
    key.insert(iana::SymmetricKeyParameterK, vec![0x22u8; 16]);
    key.insert(iana::KeyParameterBaseIV, vec![0xaau8; 12]);
    let encryptor = AesGcmEncryptor::from_cose_key(&key).unwrap();

    let mut msg = Encrypt0Message::new(Some(b"secret".to_vec()));
    msg.unprotected.set_partial_iv(vec![0x01, 0x02]);
    let encoded = msg.encrypt_and_encode(&encryptor, Some(b"aad")).unwrap();
    assert!(!msg.ciphertext().is_empty());

    let decoded = Encrypt0Message::decrypt_and_decode(&encryptor, &encoded, Some(b"aad")).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"secret"[..]));
    assert!(Encrypt0Message::decrypt_and_decode(&encryptor, &encoded, Some(b"nope")).is_err());
}

#[test]
fn aes_gcm_rejects_unsupported_and_malformed() {
    // A192GCM is not offered by this backend, matching the `ring` backend.
    assert!(AesGcmEncryptor::new(iana::AlgorithmA192GCM, &[0u8; 24], None).is_err());
    // Wrong key length for the selected algorithm.
    assert!(AesGcmEncryptor::new(iana::AlgorithmA128GCM, &[0u8; 24], None).is_err());
    assert!(AesGcmEncryptor::new(iana::AlgorithmA256GCM, &[0u8; 16], None).is_err());

    // A non-symmetric key type is rejected by `from_cose_key`.
    let mut ec = Key::new();
    ec.set_kty(iana::KeyTypeEC2).set_alg(iana::AlgorithmA128GCM);
    assert!(AesGcmEncryptor::from_cose_key(&ec).is_err());

    // A wrong-length nonce fails encryption cleanly rather than panicking.
    let enc = AesGcmEncryptor::new(iana::AlgorithmA128GCM, &[0u8; 16], None).unwrap();
    assert!(enc.encrypt(&[0u8; 8], b"data", b"").is_err());
}
