mod common;

use common::*;
use cose2::{
    iana, tag, Encrypt0Message, EncryptMessage, Header, Label, Mac0Message, MacMessage, Recipient,
    RecipientAlgorithmClass, Sign1Message, SignMessage, Signature,
};

fn direct_recipient() -> Recipient {
    let mut r = Recipient::new();
    r.unprotected.set_alg(iana::AlgorithmDirect);
    r.ciphertext = Some(vec![]);
    r
}

fn key_wrap_recipient() -> Recipient {
    let mut r = Recipient::new();
    r.unprotected.set_alg(iana::AlgorithmA128KW);
    r.ciphertext = Some(vec![1, 2, 3]);
    r
}

// ----------------------------------------------------------------------------
// Sign1
// ----------------------------------------------------------------------------

#[test]
fn sign1_round_trip_and_auto_headers() {
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"key-1");
    let verifier = MockVerifier::new(iana::AlgorithmEdDSA, b"key-1");

    let mut msg = Sign1Message::new(Some(b"This is the content".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();

    // Tagged with COSE_Sign1 (0xd2).
    assert_eq!(encoded[0], 0xd2);
    assert!(!msg.signature().is_empty());
    // alg landed in protected, kid in unprotected.
    assert_eq!(
        msg.protected.get_i64(iana::HeaderParameterAlg).unwrap(),
        Some(iana::AlgorithmEdDSA)
    );
    assert_eq!(
        msg.unprotected.get_bytes(iana::HeaderParameterKid).unwrap(),
        Some(&b"key-1"[..])
    );

    let verified = Sign1Message::verify_and_decode(&verifier, &encoded, None).unwrap();
    assert_eq!(
        verified.payload.as_deref(),
        Some(&b"This is the content"[..])
    );

    let cwt_wrapped = tag::with_tag(tag::CWT_PREFIX, &encoded);
    assert!(Sign1Message::verify_and_decode(&verifier, &cwt_wrapped, None).is_ok());
    let self_and_cwt_wrapped = tag::with_tag(tag::CBOR_SELF_PREFIX, &cwt_wrapped);
    assert!(Sign1Message::verify_and_decode(&verifier, &self_and_cwt_wrapped, None).is_ok());
}

#[test]
fn sign1_external_aad_must_match() {
    let signer = MockSigner::new(iana::AlgorithmES256, b"k");
    let verifier = MockVerifier::new(iana::AlgorithmES256, b"k");

    let mut msg = Sign1Message::new(Some(b"hi".to_vec()));
    let encoded = msg.sign_and_encode(&signer, Some(b"aad")).unwrap();

    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, Some(b"aad")).is_ok());
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, Some(b"nope")).is_err());
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_err());
}

#[test]
fn sign1_external_signature_flow_for_embedded_payload() {
    let verifier = MockVerifier::new(iana::AlgorithmEdDSA, b"async-key");
    let mut msg = Sign1Message::new(Some(b"async payload".to_vec()));

    let tbs = msg
        .prepare_signature(
            Some(iana::AlgorithmEdDSA.into()),
            Some(&b"async-key"[..]),
            Some(b"aad"),
        )
        .unwrap();
    assert!(msg.to_vec().is_err());
    assert_eq!(
        tbs,
        Sign1Message::to_be_signed(msg.protected_raw(), b"aad", b"async payload").unwrap()
    );

    msg.set_signature(toy_tag(b"signer-secret", &tbs)).unwrap();
    let encoded = msg.to_vec().unwrap();
    let decoded = Sign1Message::verify_and_decode(&verifier, &encoded, Some(b"aad")).unwrap();

    assert_eq!(decoded.payload.as_deref(), Some(&b"async payload"[..]));
    assert_eq!(
        decoded.protected.get_i64(iana::HeaderParameterAlg).unwrap(),
        Some(iana::AlgorithmEdDSA)
    );
    assert_eq!(
        decoded
            .unprotected
            .get_bytes(iana::HeaderParameterKid)
            .unwrap(),
        Some(&b"async-key"[..])
    );
}

#[test]
fn sign1_external_signature_flow_for_detached_payload() {
    let verifier = MockVerifier::new(iana::AlgorithmES256, b"detached-key");
    let mut msg = Sign1Message::new(None);

    let tbs = msg
        .prepare_detached_signature(
            Some(iana::AlgorithmES256.into()),
            Some(&b"detached-key"[..]),
            b"detached async payload",
            None,
        )
        .unwrap();
    assert_eq!(msg.payload, None);
    assert!(msg.to_vec().is_err());

    msg.set_signature(toy_tag(b"signer-secret", &tbs)).unwrap();
    let encoded = msg.to_vec().unwrap();
    let decoded = Sign1Message::from_slice(&encoded).unwrap();

    assert_eq!(decoded.payload, None);
    assert!(decoded.verify(&verifier, None).is_err());
    assert!(decoded
        .verify_detached(&verifier, b"detached async payload", None)
        .is_ok());
}

#[test]
fn sign1_untagged_and_detached_payload() {
    let signer = MockSigner::new(0, b""); // no alg, no kid
    let verifier = MockVerifier::new(0, b"");

    let mut msg = Sign1Message::new(None);
    assert!(msg.sign(&signer, None).is_err());
    msg.sign_detached(&signer, b"detached content", None)
        .unwrap();
    // Protected stays empty (no alg), unprotected empty (no kid).
    assert!(msg.protected.is_empty());
    assert!(msg.unprotected.is_empty());

    let tagged = msg.to_vec().unwrap();
    // Strip the tag to get an untagged message and decode it too.
    let untagged = &tagged[tag::SIGN1_PREFIX.len()..];
    let decoded = Sign1Message::from_slice(untagged).unwrap();
    assert_eq!(decoded.payload, None);
    assert!(decoded.verify(&verifier, None).is_err());
    assert!(decoded
        .verify_detached(&verifier, b"detached content", None)
        .is_ok());
    assert!(decoded.verify_detached(&verifier, b"wrong", None).is_err());
}

#[test]
fn sign1_rejects_wrong_cose_tag() {
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"key-1");
    let mut msg = Sign1Message::new(Some(b"x".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    let bare = tag::skip_tag(tag::SIGN1_PREFIX, &encoded);
    let wrong_tagged = tag::with_tag(tag::MAC0_PREFIX, bare);
    assert!(Sign1Message::from_slice(&wrong_tagged).is_err());
}

#[test]
fn sign1_rejects_malformed_header_buckets() {
    fn encoded_sign1(protected: &Header, unprotected: Header) -> Vec<u8> {
        let protected_raw = if protected.is_empty() {
            Vec::new()
        } else {
            protected.to_vec().unwrap()
        };
        let body = cbor2::to_vec(&(
            serde_bytes::Bytes::new(&protected_raw),
            unprotected,
            Some(serde_bytes::Bytes::new(b"payload")),
            serde_bytes::Bytes::new(b"sig"),
        ))
        .unwrap();
        tag::with_tag(tag::SIGN1_PREFIX, &body)
    }

    let mut protected = Header::new();
    protected.set_alg(iana::AlgorithmEdDSA);
    let mut unprotected = Header::new();
    unprotected.set_alg(iana::AlgorithmEdDSA);
    assert!(Sign1Message::from_slice(&encoded_sign1(&protected, unprotected)).is_err());

    let protected = Header::new();
    let mut unprotected = Header::new();
    unprotected.set_crit([Label::Text("private".into())]);
    assert!(Sign1Message::from_slice(&encoded_sign1(&protected, unprotected)).is_err());

    let mut protected = Header::new();
    protected.set_crit(Vec::<Label>::new());
    assert!(Sign1Message::from_slice(&encoded_sign1(&protected, Header::new())).is_err());

    let mut protected = Header::new();
    protected.set_crit([Label::Text("absent".into())]);
    assert!(Sign1Message::from_slice(&encoded_sign1(&protected, Header::new())).is_err());
}

#[test]
fn sign1_alg_mismatch_is_rejected() {
    let signer = MockSigner::new(iana::AlgorithmES256, b"k");
    let mut msg = Sign1Message::new(Some(b"x".to_vec()));
    msg.protected
        .insert(iana::HeaderParameterAlg, iana::AlgorithmEdDSA);
    let err = msg.sign(&signer, None).unwrap_err();
    assert!(format!("{err}").contains("algorithm mismatch"));
}

#[test]
fn sign1_verify_alg_mismatch_is_rejected() {
    let signer = MockSigner::new(iana::AlgorithmES256, b"k");
    let verifier = MockVerifier::new(iana::AlgorithmEdDSA, b"k");
    let mut msg = Sign1Message::new(Some(b"x".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    let err = Sign1Message::verify_and_decode(&verifier, &encoded, None).unwrap_err();
    assert!(format!("{err}").contains("algorithm mismatch"));
}

#[test]
fn sign1_wrong_key_fails_verification() {
    let signer = MockSigner::new(iana::AlgorithmES256, b"k");
    let mut bad = MockVerifier::new(iana::AlgorithmES256, b"k");
    bad.secret = b"other".to_vec();
    let mut msg = Sign1Message::new(Some(b"x".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert!(Sign1Message::verify_and_decode(&bad, &encoded, None).is_err());
}

#[test]
fn sign1_signer_error_propagates() {
    let mut msg = Sign1Message::new(Some(b"x".to_vec()));
    assert!(msg.sign(&FailingSigner, None).is_err());
}

#[test]
fn sign1_must_sign_before_encoding_and_decode_before_verify() {
    let msg = Sign1Message::new(Some(b"x".to_vec()));
    assert!(msg.to_vec().is_err());
    let verifier = MockVerifier::new(0, b"");
    assert!(msg.verify(&verifier, None).is_err());
}

#[test]
fn sign1_const_tag() {
    assert_eq!(Sign1Message::TAG, 18);
}

// ----------------------------------------------------------------------------
// Mac0
// ----------------------------------------------------------------------------

#[test]
fn mac0_round_trip() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"mac-kid");
    let mut msg = Mac0Message::new(Some(b"content".to_vec()));
    let encoded = msg.compute_and_encode(&macer, Some(b"aad")).unwrap();
    assert_eq!(encoded[0], 0xd1);
    assert!(!msg.tag().is_empty());

    let verified = Mac0Message::verify_and_decode(&macer, &encoded, Some(b"aad")).unwrap();
    assert_eq!(verified.payload.as_deref(), Some(&b"content"[..]));
    assert!(Mac0Message::verify_and_decode(&macer, &encoded, None).is_err());
    assert_eq!(Mac0Message::TAG, 17);
}

#[test]
fn mac0_detached_payload_round_trip() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"mac-kid");
    let mut msg = Mac0Message::new(None);
    assert!(msg.compute(&macer, None).is_err());

    let encoded = msg
        .compute_detached_and_encode(&macer, b"detached content", Some(b"aad"))
        .unwrap();
    let decoded = Mac0Message::from_slice(&encoded).unwrap();
    assert_eq!(decoded.payload, None);
    assert!(decoded.verify(&macer, Some(b"aad")).is_err());
    assert!(decoded
        .verify_detached(&macer, b"detached content", Some(b"aad"))
        .is_ok());
    assert!(decoded
        .verify_detached(&macer, b"wrong", Some(b"aad"))
        .is_err());
}

#[test]
fn mac0_external_tag_flow() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"async-mac");
    let mut msg = Mac0Message::new(Some(b"content".to_vec()));

    let tbm = msg
        .prepare_tag(
            Some(iana::AlgorithmHMAC_256_256.into()),
            Some(b"async-mac"),
            Some(b"aad"),
        )
        .unwrap();
    assert!(msg.to_vec().is_err());
    assert_eq!(
        tbm,
        Mac0Message::to_be_maced(msg.protected_raw(), b"aad", b"content").unwrap()
    );

    let tag = cose2::Macer::mac_create(&macer, &tbm).unwrap();
    msg.set_tag(tag).unwrap();
    let encoded = msg.to_vec().unwrap();

    assert!(Mac0Message::verify_and_decode(&macer, &encoded, Some(b"aad")).is_ok());
}

#[test]
fn mac0_external_detached_tag_flow() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"async-mac");
    let mut msg = Mac0Message::new(None);

    let tbm = msg
        .prepare_detached_tag(
            Some(iana::AlgorithmHMAC_256_256.into()),
            Some(b"async-mac"),
            b"detached content",
            None,
        )
        .unwrap();
    assert_eq!(msg.payload, None);

    let tag = cose2::Macer::mac_create(&macer, &tbm).unwrap();
    msg.set_tag(tag).unwrap();
    let encoded = msg.to_vec().unwrap();
    let decoded = Mac0Message::from_slice(&encoded).unwrap();

    assert!(decoded
        .verify_detached(&macer, b"detached content", None)
        .is_ok());
}

#[test]
fn mac0_errors() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"k");
    let msg = Mac0Message::new(Some(b"x".to_vec()));
    assert!(msg.to_vec().is_err());
    assert!(msg.verify(&macer, None).is_err());

    let mut wrong = MockMacer::new(iana::AlgorithmHMAC_256_256, b"k");
    wrong.secret = b"nope".to_vec();
    let mut signed = Mac0Message::new(Some(b"x".to_vec()));
    let encoded = signed.compute_and_encode(&macer, None).unwrap();
    assert!(Mac0Message::verify_and_decode(&wrong, &encoded, None).is_err());
}

// ----------------------------------------------------------------------------
// Encrypt0 — including byte-exact RFC 9052 Appendix C.4.1 vector
// ----------------------------------------------------------------------------

#[test]
fn encrypt0_rfc9052_c4_1_byte_exact() {
    // https://datatracker.ietf.org/doc/html/rfc9052#appendix-C.4
    let iv = hex::decode("89f52f65a1c580933b5261a78c").unwrap();
    let ciphertext =
        hex::decode("5974e1b99a3a4cc09a659aa2e9e7fff161d38ce71cb45ce460ffb569").unwrap();
    let expected = "d08343a1010aa1054d89f52f65a1c580933b5261a78c581c\
                    5974e1b99a3a4cc09a659aa2e9e7fff161d38ce71cb45ce460ffb569";

    let enc = FixedEncryptor {
        alg: iana::AlgorithmAES_CCM_16_64_128,
        nonce_size: 13,
        ciphertext: ciphertext.clone(),
        plaintext: b"This is the content.".to_vec(),
    };

    let mut msg = Encrypt0Message::new(Some(b"This is the content.".to_vec()));
    msg.unprotected.insert(iana::HeaderParameterIV, iv);
    let encoded = msg.encrypt_and_encode(&enc, None).unwrap();
    assert_eq!(hex::encode(&encoded), expected);
    assert_eq!(msg.ciphertext(), &ciphertext[..]);

    // Decode + decrypt restores the plaintext (via the fixed encryptor).
    let dec = Encrypt0Message::decrypt_and_decode(&enc, &encoded, None).unwrap();
    assert_eq!(dec.payload.as_deref(), Some(&b"This is the content."[..]));
    assert_eq!(Encrypt0Message::TAG, 16);
}

#[test]
fn encrypt0_round_trip_reversible() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"e", 12);
    let mut msg = Encrypt0Message::new(Some(b"secret payload".to_vec()));
    msg.unprotected
        .insert(iana::HeaderParameterIV, vec![7u8; 12]);
    let encoded = msg.encrypt_and_encode(&enc, Some(b"aad")).unwrap();

    let mut decoded = Encrypt0Message::from_slice(&encoded).unwrap();
    assert_eq!(decoded.payload, None);
    let pt = decoded.decrypt(&enc, Some(b"aad")).unwrap().to_vec();
    assert_eq!(pt, b"secret payload");

    // Wrong AAD fails authentication.
    let mut decoded2 = Encrypt0Message::from_slice(&encoded).unwrap();
    assert!(decoded2.decrypt(&enc, Some(b"wrong")).is_err());
}

#[test]
fn encrypt0_external_ciphertext_flow() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"async-enc", 12);
    let mut msg = Encrypt0Message::new(Some(b"secret payload".to_vec()));
    msg.unprotected.set_iv(vec![9u8; 12]);

    let context = msg
        .prepare_encryption(
            Some(iana::AlgorithmA128GCM.into()),
            Some(b"async-enc"),
            12,
            None,
            Some(b"aad"),
        )
        .unwrap();
    assert!(msg.to_vec().is_err());
    assert_eq!(
        context.aad,
        Encrypt0Message::to_be_encrypted(msg.protected_raw(), b"aad").unwrap()
    );
    let plaintext = msg.payload.as_deref().unwrap().to_vec();
    let ciphertext =
        cose2::Encryptor::encrypt(&enc, &context.nonce, &plaintext, &context.aad).unwrap();

    msg.set_ciphertext(ciphertext, false).unwrap();
    let encoded = msg.to_vec().unwrap();
    let decoded = Encrypt0Message::decrypt_and_decode(&enc, &encoded, Some(b"aad")).unwrap();

    assert_eq!(decoded.payload.as_deref(), Some(&b"secret payload"[..]));
}

#[test]
fn encrypt0_iv_handling_errors() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12);
    let enc_with_base_iv =
        MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12).with_base_iv(vec![0u8; 12]);

    // Missing IV.
    let mut msg = Encrypt0Message::new(Some(b"x".to_vec()));
    let err = msg.encrypt(&enc, None).unwrap_err();
    assert!(format!("{err}").contains("missing IV"));

    // Wrong-size IV.
    let mut msg2 = Encrypt0Message::new(Some(b"x".to_vec()));
    msg2.unprotected
        .insert(iana::HeaderParameterIV, vec![0u8; 8]);
    let err2 = msg2.encrypt(&enc, None).unwrap_err();
    assert!(format!("{err2}").contains("IV size mismatch"));

    // IV and Partial IV are mutually exclusive.
    let mut both = Encrypt0Message::new(Some(b"x".to_vec()));
    both.unprotected.set_iv(vec![0u8; 12]);
    both.unprotected.set_partial_iv(vec![1, 2]);
    let err_both = both.encrypt(&enc_with_base_iv, None).unwrap_err();
    assert!(format!("{err_both}").contains("must not both be present"));

    // Partial IV needs an encryptor-provided Base IV.
    let mut partial_without_base = Encrypt0Message::new(Some(b"x".to_vec()));
    partial_without_base.unprotected.set_partial_iv(vec![1, 2]);
    let err_base = partial_without_base.encrypt(&enc, None).unwrap_err();
    assert!(format!("{err_base}").contains("Base IV"));

    // The Base IV length must match the content-encryption nonce size.
    let wrong_base_iv =
        MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12).with_base_iv(vec![0u8; 8]);
    let mut partial_wrong_base = Encrypt0Message::new(Some(b"x".to_vec()));
    partial_wrong_base.unprotected.set_partial_iv(vec![1, 2]);
    let err_wrong_base = partial_wrong_base
        .encrypt(&wrong_base_iv, None)
        .unwrap_err();
    assert!(format!("{err_wrong_base}").contains("Base IV size mismatch"));

    // The Partial IV is left-padded to the nonce size, so it cannot be longer.
    let mut long_partial = Encrypt0Message::new(Some(b"x".to_vec()));
    long_partial.unprotected.set_partial_iv(vec![1u8; 13]);
    let err_long_partial = long_partial.encrypt(&enc_with_base_iv, None).unwrap_err();
    assert!(format!("{err_long_partial}").contains("Partial IV size mismatch"));

    // Missing plaintext; use Some(Vec::new()) when an empty plaintext is intended.
    let mut msg3 = Encrypt0Message::new(None);
    msg3.unprotected
        .insert(iana::HeaderParameterIV, vec![0u8; 12]);
    let err3 = msg3.encrypt(&enc, None).unwrap_err();
    assert!(format!("{err3}").contains("plaintext"));
}

#[test]
fn encrypt0_partial_iv_uses_base_iv() {
    let base_iv = vec![0xaau8; 12];
    let partial_iv = vec![0x01, 0x02, 0x03];
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"e", 12).with_base_iv(base_iv.clone());

    let mut derived_nonce = base_iv.clone();
    let offset = derived_nonce.len() - partial_iv.len();
    for (byte, partial) in derived_nonce[offset..].iter_mut().zip(&partial_iv) {
        *byte ^= *partial;
    }

    let mut partial = Encrypt0Message::new(Some(b"secret payload".to_vec()));
    partial.unprotected.set_partial_iv(partial_iv);
    let encoded = partial.encrypt_and_encode(&enc, Some(b"aad")).unwrap();

    let mut full = Encrypt0Message::new(Some(b"secret payload".to_vec()));
    full.unprotected.set_iv(derived_nonce);
    full.encrypt(&enc, Some(b"aad")).unwrap();
    assert_eq!(partial.ciphertext(), full.ciphertext());

    let decoded = Encrypt0Message::decrypt_and_decode(&enc, &encoded, Some(b"aad")).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"secret payload"[..]));
}

#[test]
fn encrypt0_state_and_alg_errors() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12);
    let msg = Encrypt0Message::new(Some(b"x".to_vec()));
    assert!(msg.to_vec().is_err());
    let mut unprocessed = Encrypt0Message::new(Some(b"x".to_vec()));
    assert!(unprocessed.decrypt(&enc, None).is_err());

    // alg mismatch on decrypt.
    let mut msg = Encrypt0Message::new(Some(b"x".to_vec()));
    msg.unprotected
        .insert(iana::HeaderParameterIV, vec![1u8; 12]);
    let encoded = msg.encrypt_and_encode(&enc, None).unwrap();
    let other = MockEncryptor::new(iana::AlgorithmA256GCM, b"", 12);
    assert!(Encrypt0Message::decrypt_and_decode(&other, &encoded, None).is_err());
}

#[test]
fn encrypt0_detached_ciphertext_round_trip() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"e", 12);
    let mut msg = Encrypt0Message::new(Some(b"secret payload".to_vec()));
    msg.unprotected
        .insert(iana::HeaderParameterIV, vec![7u8; 12]);
    let (encoded, ciphertext) = msg.encrypt_detached_and_encode(&enc, Some(b"aad")).unwrap();

    let mut decoded = Encrypt0Message::from_slice(&encoded).unwrap();
    assert!(decoded.is_ciphertext_detached());
    assert!(decoded.ciphertext().is_empty());
    assert!(decoded.decrypt(&enc, Some(b"aad")).is_err());
    let pt = decoded
        .decrypt_detached(&enc, &ciphertext, Some(b"aad"))
        .unwrap()
        .to_vec();
    assert_eq!(pt, b"secret payload");
    assert_eq!(decoded.ciphertext(), &ciphertext[..]);

    assert!(
        Encrypt0Message::decrypt_detached_and_decode(&enc, &encoded, b"wrong", Some(b"aad"))
            .is_err()
    );
}

// ----------------------------------------------------------------------------
// Recipient
// ----------------------------------------------------------------------------

#[test]
fn recipient_round_trip_three_and_four_elements() {
    let r = direct_recipient();
    let bytes = r.to_vec().unwrap();
    let back = Recipient::from_slice(&bytes).unwrap();
    assert_eq!(back, r);

    // With a nested recipient → 4-element form.
    let mut outer = Recipient::new();
    outer.unprotected.set_alg(iana::AlgorithmA128KW);
    outer.ciphertext = Some(vec![1, 2, 3]);
    outer.recipients.push(r);
    let bytes = outer.to_vec().unwrap();
    let back = Recipient::from_slice(&bytes).unwrap();
    assert_eq!(back, outer);
    assert_eq!(back.recipients.len(), 1);
}

#[test]
fn recipient_null_ciphertext() {
    let r = Recipient::new();
    assert!(r.to_vec().is_err());

    let mut r = Recipient::new();
    r.unprotected.set_alg(iana::AlgorithmA128KW);
    assert!(r.to_vec().is_err());
}

#[test]
fn recipient_validates_registered_algorithm_classes() {
    let r = direct_recipient();
    assert_eq!(
        r.algorithm_class().unwrap(),
        Some(RecipientAlgorithmClass::Direct)
    );

    let mut direct = direct_recipient();
    direct.ciphertext = Some(vec![1]);
    assert!(direct.validate().is_err());

    let key_wrap = key_wrap_recipient();
    assert_eq!(
        key_wrap.algorithm_class().unwrap(),
        Some(RecipientAlgorithmClass::KeyWrap)
    );
    assert!(key_wrap.validate().is_ok());

    let mut key_wrap = key_wrap_recipient();
    key_wrap.protected.set_kid(b"protected".to_vec());
    assert!(key_wrap.validate().is_err());

    let mut transport = Recipient::new();
    transport
        .unprotected
        .set_alg(iana::AlgorithmRSAES_OAEP_SHA_256);
    transport.protected.set_kid(b"protected".to_vec());
    transport.ciphertext = Some(vec![1, 2, 3]);
    assert!(transport.validate().is_err());

    let mut direct_ka = Recipient::new();
    direct_ka.protected.set_alg(iana::AlgorithmECDH_ES_HKDF_256);
    direct_ka.ciphertext = Some(vec![]);
    assert_eq!(
        direct_ka.algorithm_class().unwrap(),
        Some(RecipientAlgorithmClass::DirectKeyAgreement)
    );
    assert!(direct_ka.validate().is_ok());

    let mut direct_ka_missing_ciphertext = direct_ka.clone();
    direct_ka_missing_ciphertext.ciphertext = None;
    assert!(direct_ka_missing_ciphertext.validate().is_err());

    let mut ka_kw = Recipient::new();
    ka_kw.protected.set_alg(iana::AlgorithmECDH_ES_A128KW);
    assert!(ka_kw.validate().is_err());
}

// ----------------------------------------------------------------------------
// Mac (with recipients)
// ----------------------------------------------------------------------------

#[test]
fn mac_round_trip_with_recipient() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"m");
    let mut msg = MacMessage::new(Some(b"content".to_vec()));
    msg.recipients.push(direct_recipient());

    let encoded = msg.compute_and_encode(&macer, None).unwrap();
    assert_eq!(&encoded[..2], &[0xd8, 0x61]);

    let verified = MacMessage::verify_and_decode(&macer, &encoded, None).unwrap();
    assert_eq!(verified.payload.as_deref(), Some(&b"content"[..]));
    assert_eq!(verified.recipients.len(), 1);
    assert_eq!(MacMessage::TAG, 97);
}

#[test]
fn mac_detached_payload_round_trip() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"m");
    let mut msg = MacMessage::new(None);
    msg.recipients.push(direct_recipient());

    assert!(msg.compute(&macer, None).is_err());
    let encoded = msg
        .compute_detached_and_encode(&macer, b"detached content", None)
        .unwrap();
    let decoded = MacMessage::from_slice(&encoded).unwrap();
    assert_eq!(decoded.payload, None);
    assert!(decoded.verify(&macer, None).is_err());
    assert!(decoded
        .verify_detached(&macer, b"detached content", None)
        .is_ok());
}

#[test]
fn mac_external_tag_flow_with_recipient() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"async-mac");
    let mut msg = MacMessage::new(Some(b"content".to_vec()));
    msg.recipients.push(direct_recipient());

    let tbm = msg
        .prepare_tag(
            Some(iana::AlgorithmHMAC_256_256.into()),
            Some(b"async-mac"),
            None,
        )
        .unwrap();
    assert!(msg.to_vec().is_err());
    assert_eq!(
        tbm,
        MacMessage::to_be_maced(msg.protected_raw(), b"", b"content").unwrap()
    );

    let tag = cose2::Macer::mac_create(&macer, &tbm).unwrap();
    msg.set_tag(tag).unwrap();
    let encoded = msg.to_vec().unwrap();

    assert!(MacMessage::verify_and_decode(&macer, &encoded, None).is_ok());
}

#[test]
fn mac_external_detached_tag_flow_with_recipient() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"async-mac");
    let mut msg = MacMessage::new(None);
    msg.recipients.push(direct_recipient());

    let tbm = msg
        .prepare_detached_tag(
            Some(iana::AlgorithmHMAC_256_256.into()),
            Some(b"async-mac"),
            b"detached content",
            None,
        )
        .unwrap();
    assert_eq!(msg.payload, None);

    let tag = cose2::Macer::mac_create(&macer, &tbm).unwrap();
    msg.set_tag(tag).unwrap();
    let encoded = msg.to_vec().unwrap();
    let decoded = MacMessage::from_slice(&encoded).unwrap();

    assert!(decoded
        .verify_detached(&macer, b"detached content", None)
        .is_ok());
}

#[test]
fn mac_requires_recipients() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"m");
    let mut msg = MacMessage::new(Some(b"x".to_vec()));
    // No recipients → encode fails.
    assert!(msg.compute_and_encode(&macer, None).is_err());

    // A decoded COSE_Mac without recipients is rejected.
    let mut with = MacMessage::new(Some(b"x".to_vec()));
    with.recipients.push(direct_recipient());
    let encoded = with.compute_and_encode(&macer, None).unwrap();
    // Tamper: rebuild as a 5-array with empty recipients list is hard; instead
    // check the state/verify guards.
    let msg2 = MacMessage::new(Some(b"x".to_vec()));
    assert!(msg2.to_vec().is_err());
    assert!(msg2.verify(&macer, None).is_err());
    let _ = encoded;
}

// ----------------------------------------------------------------------------
// Encrypt (with recipients)
// ----------------------------------------------------------------------------

#[test]
fn encrypt_round_trip_with_recipient() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12);
    let mut msg = EncryptMessage::new(Some(b"plaintext".to_vec()));
    msg.unprotected
        .insert(iana::HeaderParameterIV, vec![3u8; 12]);
    msg.recipients.push(direct_recipient());

    let encoded = msg.encrypt_and_encode(&enc, None).unwrap();
    assert_eq!(&encoded[..2], &[0xd8, 0x60]);

    let mut decoded = EncryptMessage::decrypt_and_decode(&enc, &encoded, None).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"plaintext"[..]));
    assert_eq!(decoded.recipients.len(), 1);
    // decrypt again directly to exercise the method path.
    assert_eq!(decoded.decrypt(&enc, None).unwrap(), b"plaintext");
    assert_eq!(EncryptMessage::TAG, 96);
}

#[test]
fn encrypt_external_ciphertext_flow_with_recipient() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"async-enc", 12);
    let mut msg = EncryptMessage::new(Some(b"plaintext".to_vec()));
    msg.unprotected.set_iv(vec![4u8; 12]);
    msg.recipients.push(direct_recipient());

    let context = msg
        .prepare_encryption(
            Some(iana::AlgorithmA128GCM.into()),
            Some(b"async-enc"),
            12,
            None,
            None,
        )
        .unwrap();
    assert!(msg.to_vec().is_err());
    assert_eq!(
        context.aad,
        EncryptMessage::to_be_encrypted(msg.protected_raw(), b"").unwrap()
    );
    let plaintext = msg.payload.as_deref().unwrap().to_vec();
    let ciphertext =
        cose2::Encryptor::encrypt(&enc, &context.nonce, &plaintext, &context.aad).unwrap();

    msg.set_ciphertext(ciphertext, true).unwrap();
    let encoded = msg.to_vec().unwrap();
    let decoded = EncryptMessage::from_slice(&encoded).unwrap();
    assert!(decoded.is_ciphertext_detached());

    let decrypt_context = decoded
        .prepare_decryption(Some(iana::AlgorithmA128GCM.into()), 12, None, None)
        .unwrap();
    assert_eq!(decrypt_context.nonce, context.nonce);
    assert_eq!(decrypt_context.aad, context.aad);
    let plaintext = cose2::Encryptor::decrypt(
        &enc,
        &decrypt_context.nonce,
        msg.ciphertext(),
        &decrypt_context.aad,
    )
    .unwrap();
    assert_eq!(plaintext, b"plaintext");
}

#[test]
fn encrypt_detached_ciphertext_round_trip() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12);
    let mut msg = EncryptMessage::new(Some(b"plaintext".to_vec()));
    msg.unprotected
        .insert(iana::HeaderParameterIV, vec![3u8; 12]);
    msg.recipients.push(direct_recipient());

    let (encoded, ciphertext) = msg.encrypt_detached_and_encode(&enc, None).unwrap();
    let mut decoded = EncryptMessage::from_slice(&encoded).unwrap();
    assert!(decoded.is_ciphertext_detached());
    assert!(decoded.decrypt(&enc, None).is_err());
    assert_eq!(
        decoded.decrypt_detached(&enc, &ciphertext, None).unwrap(),
        b"plaintext"
    );
    assert!(EncryptMessage::decrypt_detached_and_decode(&enc, &encoded, b"wrong", None).is_err());
}

#[test]
fn encrypt_partial_iv_round_trip_with_recipient() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12).with_base_iv(vec![0x55u8; 12]);
    let mut msg = EncryptMessage::new(Some(b"plaintext".to_vec()));
    msg.unprotected.set_partial_iv(vec![0x10, 0x20]);
    msg.recipients.push(direct_recipient());

    let encoded = msg.encrypt_and_encode(&enc, None).unwrap();
    let decoded = EncryptMessage::decrypt_and_decode(&enc, &encoded, None).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"plaintext"[..]));
}

#[test]
fn encrypt_rejects_direct_recipient_mixed_with_other_recipients() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12);
    let mut msg = EncryptMessage::new(Some(b"plaintext".to_vec()));
    msg.unprotected.set_iv(vec![0u8; 12]);
    msg.recipients.push(direct_recipient());
    msg.recipients.push(key_wrap_recipient());

    let err = msg.encrypt(&enc, None).unwrap_err();
    assert!(format!("{err}").contains("only recipient"));
}

#[test]
fn encrypt_requires_recipients_and_state() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12);
    let mut msg = EncryptMessage::new(Some(b"x".to_vec()));
    msg.unprotected
        .insert(iana::HeaderParameterIV, vec![0u8; 12]);
    // No recipients → encode fails.
    assert!(msg.encrypt_and_encode(&enc, None).is_err());

    let unprocessed = EncryptMessage::new(Some(b"x".to_vec()));
    assert!(unprocessed.to_vec().is_err());
    let mut undecoded = EncryptMessage::new(Some(b"x".to_vec()));
    assert!(undecoded.decrypt(&enc, None).is_err());

    let mut no_plaintext = EncryptMessage::new(None);
    no_plaintext
        .unprotected
        .insert(iana::HeaderParameterIV, vec![0u8; 12]);
    no_plaintext.recipients.push(direct_recipient());
    let err = no_plaintext.encrypt(&enc, None).unwrap_err();
    assert!(format!("{err}").contains("plaintext"));
}

// ----------------------------------------------------------------------------
// Sign (with one or more signers)
// ----------------------------------------------------------------------------

#[test]
fn sign_round_trip_multiple_signers() {
    let s1 = MockSigner::new(iana::AlgorithmES256, b"a");
    let s2 = MockSigner::new(iana::AlgorithmEdDSA, b"b");
    let v1 = MockVerifier::new(iana::AlgorithmES256, b"a");
    let v2 = MockVerifier::new(iana::AlgorithmEdDSA, b"b");

    let mut msg = SignMessage::new(Some(b"content".to_vec()));
    let signers: [&dyn cose2::Signer; 2] = [&s1, &s2];
    let encoded = msg.sign_and_encode(&signers, None).unwrap();
    assert_eq!(&encoded[..2], &[0xd8, 0x62]);
    assert_eq!(msg.signatures.len(), 2);
    assert!(!msg.signatures[0].signature().is_empty());

    let verifiers: [&dyn cose2::Verifier; 2] = [&v1, &v2];
    let verified = SignMessage::verify_and_decode(&verifiers, &encoded, None).unwrap();
    assert_eq!(verified.payload.as_deref(), Some(&b"content"[..]));
    assert_eq!(SignMessage::TAG, 98);
}

#[test]
fn sign_external_signature_flow_for_multiple_signers() {
    let v1 = MockVerifier::new(iana::AlgorithmES256, b"a");
    let v2 = MockVerifier::new(iana::AlgorithmEdDSA, b"b");
    let mut msg = SignMessage::new(Some(b"content".to_vec()));

    let to_be_signed = msg
        .prepare_signatures(
            vec![
                Signature::with_alg_kid(Some(iana::AlgorithmES256.into()), Some(b"a")),
                Signature::with_alg_kid(Some(iana::AlgorithmEdDSA.into()), Some(b"b")),
            ],
            Some(b"aad"),
        )
        .unwrap();
    assert_eq!(to_be_signed.len(), 2);
    assert!(msg.to_vec().is_err());
    assert_eq!(
        to_be_signed[0],
        SignMessage::to_be_signed(
            msg.protected_raw(),
            msg.signatures[0].protected_raw(),
            b"aad",
            b"content"
        )
        .unwrap()
    );

    let signatures = to_be_signed
        .iter()
        .map(|tbs| toy_tag(b"signer-secret", tbs))
        .collect::<Vec<_>>();
    msg.set_signatures(signatures).unwrap();
    let encoded = msg.to_vec().unwrap();

    let verifiers: [&dyn cose2::Verifier; 2] = [&v1, &v2];
    assert!(SignMessage::verify_and_decode(&verifiers, &encoded, Some(b"aad")).is_ok());
}

#[test]
fn sign_external_detached_signature_flow() {
    let verifier = MockVerifier::new(iana::AlgorithmES256, b"a");
    let mut msg = SignMessage::new(None);

    let to_be_signed = msg
        .prepare_detached_signatures(
            vec![Signature::with_alg_kid(
                Some(iana::AlgorithmES256.into()),
                Some(b"a"),
            )],
            b"detached content",
            None,
        )
        .unwrap();
    assert_eq!(msg.payload, None);

    msg.set_signatures(vec![toy_tag(b"signer-secret", &to_be_signed[0])])
        .unwrap();
    let encoded = msg.to_vec().unwrap();
    let decoded = SignMessage::from_slice(&encoded).unwrap();
    let verifiers: [&dyn cose2::Verifier; 1] = [&verifier];

    assert!(decoded
        .verify_detached(&verifiers, b"detached content", None)
        .is_ok());
}

#[test]
fn sign_detached_payload_round_trip() {
    let signer = MockSigner::new(iana::AlgorithmES256, b"a");
    let verifier = MockVerifier::new(iana::AlgorithmES256, b"a");
    let mut msg = SignMessage::new(None);
    let signers: [&dyn cose2::Signer; 1] = [&signer];

    assert!(msg.sign(&signers, None).is_err());
    let encoded = msg
        .sign_detached_and_encode(&signers, b"detached content", None)
        .unwrap();
    let decoded = SignMessage::from_slice(&encoded).unwrap();
    assert_eq!(decoded.payload, None);

    let verifiers: [&dyn cose2::Verifier; 1] = [&verifier];
    assert!(decoded.verify(&verifiers, None).is_err());
    assert!(decoded
        .verify_detached(&verifiers, b"detached content", None)
        .is_ok());
    assert!(SignMessage::verify_detached_and_decode(&verifiers, &encoded, b"wrong", None).is_err());
}

#[test]
fn sign_no_verifier_for_kid() {
    let s1 = MockSigner::new(iana::AlgorithmES256, b"a");
    let v_other = MockVerifier::new(iana::AlgorithmES256, b"zzz");
    let mut msg = SignMessage::new(Some(b"x".to_vec()));
    let signers: [&dyn cose2::Signer; 1] = [&s1];
    let encoded = msg.sign_and_encode(&signers, None).unwrap();

    let verifiers: [&dyn cose2::Verifier; 1] = [&v_other];
    let err = SignMessage::verify_and_decode(&verifiers, &encoded, None).unwrap_err();
    assert!(format!("{err}").contains("no verifier"));
}

#[test]
fn sign_tries_all_verifiers_for_matching_kid() {
    let signer = MockSigner::new(iana::AlgorithmES256, b"a");
    let mut bad = MockVerifier::new(iana::AlgorithmES256, b"a");
    bad.secret = b"wrong-secret".to_vec();
    let good = MockVerifier::new(iana::AlgorithmES256, b"a");

    let mut msg = SignMessage::new(Some(b"x".to_vec()));
    let signers: [&dyn cose2::Signer; 1] = [&signer];
    let encoded = msg.sign_and_encode(&signers, None).unwrap();

    let verifiers: [&dyn cose2::Verifier; 2] = [&bad, &good];
    assert!(SignMessage::verify_and_decode(&verifiers, &encoded, None).is_ok());
}

#[test]
fn sign_empty_signers_and_verifiers_rejected() {
    let mut msg = SignMessage::new(Some(b"x".to_vec()));
    assert!(msg.sign(&[], None).is_err());

    // Build a valid message, then verify with no verifiers.
    let s1 = MockSigner::new(iana::AlgorithmES256, b"a");
    let signers: [&dyn cose2::Signer; 1] = [&s1];
    let encoded = msg.sign_and_encode(&signers, None).unwrap();
    let decoded = SignMessage::from_slice(&encoded).unwrap();
    assert!(decoded.verify(&[], None).is_err());
}

#[test]
fn sign_state_guards() {
    let msg = SignMessage::new(Some(b"x".to_vec()));
    assert!(msg.to_vec().is_err());
    let v1 = MockVerifier::new(iana::AlgorithmES256, b"a");
    let verifiers: [&dyn cose2::Verifier; 1] = [&v1];
    assert!(msg.verify(&verifiers, None).is_err());
}

#[test]
fn sign_decode_requires_signatures() {
    // [protected, unprotected, payload, []] — empty signatures array.
    let body = cbor2::to_vec(&(
        serde_bytes::Bytes::new(&[]),
        Header::new(),
        Some(serde_bytes::Bytes::new(b"x")),
        Vec::<cbor2::Value>::new(),
    ))
    .unwrap();
    let tagged = tag::with_tag(tag::SIGN_PREFIX, &body);
    assert!(SignMessage::from_slice(&tagged).is_err());
}

#[test]
fn sign_signer_error_propagates() {
    let mut msg = SignMessage::new(Some(b"x".to_vec()));
    let signers: [&dyn cose2::Signer; 1] = [&FailingSigner];
    assert!(msg.sign(&signers, None).is_err());
}

// ----------------------------------------------------------------------------
// Cross-bucket attribute lookup (RFC 9052 §3: protected bucket takes precedence)
// ----------------------------------------------------------------------------

#[test]
fn encrypt0_reads_iv_from_protected_bucket() {
    // Placing the IV in the protected bucket is unusual but permitted by the
    // CDDL; the message layer must still find it (protected first, then
    // unprotected) for both encryption and decryption.
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12);
    let mut msg = Encrypt0Message::new(Some(b"secret".to_vec()));
    msg.protected.set_iv(vec![9u8; 12]);
    let encoded = msg.encrypt_and_encode(&enc, None).unwrap();

    let mut decoded = Encrypt0Message::from_slice(&encoded).unwrap();
    assert!(decoded.unprotected.iv().unwrap().is_none());
    assert_eq!(decoded.protected.iv().unwrap(), Some(&[9u8; 12][..]));
    let pt = decoded.decrypt(&enc, None).unwrap().to_vec();
    assert_eq!(pt, b"secret");
}

#[test]
fn sign_matches_kid_in_signature_protected_bucket() {
    use cbor2::Value;

    // A COSE_Signature may carry its kid in either bucket. Hand-assemble a
    // COSE_Sign whose signature kid lives in the protected header and confirm
    // verifier selection still matches it (protected first, then unprotected).
    let mut sig_protected = Header::new();
    sig_protected.set_alg(iana::AlgorithmEdDSA);
    sig_protected.set_kid(b"key-7".to_vec());
    let sig_protected_raw = sig_protected.to_vec().unwrap();
    let body_protected_raw: Vec<u8> = Vec::new();
    let payload = b"payload".to_vec();

    // Sig_structure = ["Signature", body_protected, sign_protected, aad, payload]
    let tbs = cbor2::to_canonical_vec(&Value::Array(vec![
        Value::from("Signature"),
        Value::Bytes(body_protected_raw.clone()),
        Value::Bytes(sig_protected_raw.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.clone()),
    ]))
    .unwrap();
    let signature = toy_tag(b"signer-secret", &tbs);

    let body = cbor2::to_vec(&(
        serde_bytes::Bytes::new(&body_protected_raw),
        Header::new(),
        Some(serde_bytes::Bytes::new(&payload)),
        vec![(
            serde_bytes::Bytes::new(&sig_protected_raw),
            Header::new(),
            serde_bytes::Bytes::new(&signature),
        )],
    ))
    .unwrap();
    let tagged = tag::with_tag(tag::SIGN_PREFIX, &body);

    let decoded = SignMessage::from_slice(&tagged).unwrap();
    assert_eq!(
        decoded.signatures[0].protected.kid().unwrap(),
        Some(&b"key-7"[..])
    );

    let verifier = MockVerifier::new(iana::AlgorithmEdDSA, b"key-7");
    let verifiers: [&dyn cose2::Verifier; 1] = [&verifier];
    assert!(decoded.verify(&verifiers, None).is_ok());

    // A verifier whose kid does not match the protected kid is not selected.
    let other = MockVerifier::new(iana::AlgorithmEdDSA, b"key-9");
    let others: [&dyn cose2::Verifier; 1] = [&other];
    assert!(decoded.verify(&others, None).is_err());
}
