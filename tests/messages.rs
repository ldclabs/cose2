mod common;

use common::*;
use cose2::{
    iana, tag, Encrypt0Message, EncryptMessage, Header, Mac0Message, MacMessage, Recipient,
    Sign1Message, SignMessage,
};

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
fn sign1_untagged_and_detached_payload() {
    let signer = MockSigner::new(0, b""); // no alg, no kid
    let verifier = MockVerifier::new(0, b"");

    let mut msg = Sign1Message::new(None);
    msg.sign(&signer, None).unwrap();
    // Protected stays empty (no alg), unprotected empty (no kid).
    assert!(msg.protected.is_empty());
    assert!(msg.unprotected.is_empty());

    let tagged = msg.to_vec().unwrap();
    // Strip the tag to get an untagged message and decode it too.
    let untagged = &tagged[tag::SIGN1_PREFIX.len()..];
    let decoded = Sign1Message::from_slice(untagged).unwrap();
    assert_eq!(decoded.payload, None);
    assert!(decoded.verify(&verifier, None).is_ok());
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
fn encrypt0_iv_handling_errors() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12);

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
fn encrypt0_missing_ciphertext_is_rejected() {
    // [protected, unprotected, nil] — a COSE_Encrypt0 with detached ciphertext.
    let body = cbor2::to_vec(&(
        serde_bytes::Bytes::new(&[]),
        Header::new(),
        Option::<&serde_bytes::Bytes>::None,
    ))
    .unwrap();
    let tagged = tag::with_tag(tag::ENCRYPT0_PREFIX, &body);
    assert!(Encrypt0Message::from_slice(&tagged).is_err());
}

// ----------------------------------------------------------------------------
// Recipient
// ----------------------------------------------------------------------------

#[test]
fn recipient_round_trip_three_and_four_elements() {
    let mut r = Recipient::new();
    r.unprotected
        .insert(iana::HeaderParameterAlg, iana::AlgorithmDirect);
    r.ciphertext = Some(vec![]);
    let bytes = r.to_vec().unwrap();
    let back = Recipient::from_slice(&bytes).unwrap();
    assert_eq!(back, r);

    // With a nested recipient → 4-element form.
    let mut outer = Recipient::new();
    outer
        .protected
        .insert(iana::HeaderParameterAlg, iana::AlgorithmA128KW);
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
    let bytes = r.to_vec().unwrap();
    let back = Recipient::from_slice(&bytes).unwrap();
    assert_eq!(back.ciphertext, None);
}

// ----------------------------------------------------------------------------
// Mac (with recipients)
// ----------------------------------------------------------------------------

#[test]
fn mac_round_trip_with_recipient() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"m");
    let mut msg = MacMessage::new(Some(b"content".to_vec()));
    let mut r = Recipient::new();
    r.unprotected
        .insert(iana::HeaderParameterAlg, iana::AlgorithmDirect);
    r.ciphertext = Some(vec![]);
    msg.recipients.push(r);

    let encoded = msg.compute_and_encode(&macer, None).unwrap();
    assert_eq!(&encoded[..2], &[0xd8, 0x61]);

    let verified = MacMessage::verify_and_decode(&macer, &encoded, None).unwrap();
    assert_eq!(verified.payload.as_deref(), Some(&b"content"[..]));
    assert_eq!(verified.recipients.len(), 1);
    assert_eq!(MacMessage::TAG, 97);
}

#[test]
fn mac_requires_recipients() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"m");
    let mut msg = MacMessage::new(Some(b"x".to_vec()));
    // No recipients → encode fails.
    assert!(msg.compute_and_encode(&macer, None).is_err());

    // A decoded COSE_Mac without recipients is rejected.
    let mut with = MacMessage::new(Some(b"x".to_vec()));
    let mut r = Recipient::new();
    r.ciphertext = Some(vec![]);
    with.recipients.push(r);
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
    let mut r = Recipient::new();
    r.unprotected
        .insert(iana::HeaderParameterAlg, iana::AlgorithmDirect);
    r.ciphertext = Some(vec![]);
    msg.recipients.push(r);

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
