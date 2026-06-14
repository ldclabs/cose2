//! Targeted tests filling coverage gaps: trait defaults, decode error paths,
//! visitor `expecting` messages and defensive branches reachable via the
//! public API.

mod common;

use common::*;
use cose2::{
    cwt::{Claims, Validator, ValidatorOptions},
    iana, tag, CoseMap, Encrypt0Message, EncryptMessage, Header, KdfContext, Key, Label,
    Mac0Message, MacMessage, Recipient, Sign1Message, SignMessage, SuppPubInfo, Value,
};

// ----------------------------------------------------------------------------
// Trait default methods (alg/kid) via minimal implementations
// ----------------------------------------------------------------------------

#[test]
fn minimal_sign_uses_trait_defaults() {
    // SignMessage exercises Verifier::kid() (lookup) and Verifier::alg().
    let mut msg = SignMessage::new(Some(b"x".to_vec()));
    let signers: [&dyn cose2::Signer; 1] = [&MinimalSigner];
    let encoded = msg.sign_and_encode(&signers, None).unwrap();
    // No alg/kid headers were added (signer used defaults).
    assert!(msg.signatures[0].protected.is_empty());
    assert!(msg.signatures[0].unprotected.is_empty());

    let verifiers: [&dyn cose2::Verifier; 1] = [&MinimalVerifier];
    assert!(SignMessage::verify_and_decode(&verifiers, &encoded, None).is_ok());

    // Sign1 exercises Verifier::alg() default too.
    let mut s1 = Sign1Message::new(Some(b"y".to_vec()));
    let enc = s1.sign_and_encode(&MinimalSigner, None).unwrap();
    assert!(Sign1Message::verify_and_decode(&MinimalVerifier, &enc, None).is_ok());
}

#[test]
fn minimal_mac_and_encrypt_use_trait_defaults() {
    let mut mac = Mac0Message::new(Some(b"x".to_vec()));
    let enc = mac.compute_and_encode(&MinimalMacer, None).unwrap();
    assert!(Mac0Message::verify_and_decode(&MinimalMacer, &enc, None).is_ok());

    let mut e = Encrypt0Message::new(Some(b"hello".to_vec()));
    e.unprotected
        .insert(iana::HeaderParameterIV, vec![1u8, 2, 3, 4]);
    let encoded = e.encrypt_and_encode(&MinimalEncryptor, None).unwrap();
    let dec = Encrypt0Message::decrypt_and_decode(&MinimalEncryptor, &encoded, None).unwrap();
    assert_eq!(dec.payload.as_deref(), Some(&b"hello"[..]));
}

// ----------------------------------------------------------------------------
// `alg` already present and matching (the Some(_) => Ok branch)
// ----------------------------------------------------------------------------

#[test]
fn sign1_alg_already_present_and_matching() {
    let signer = MockSigner::new(iana::AlgorithmES256, b"k");
    let verifier = MockVerifier::new(iana::AlgorithmES256, b"k");
    let mut msg = Sign1Message::new(Some(b"x".to_vec()));
    msg.protected
        .insert(iana::HeaderParameterAlg, iana::AlgorithmES256);
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());
}

// ----------------------------------------------------------------------------
// Label::visit_string via an indefinite-length text string
// ----------------------------------------------------------------------------

#[test]
fn label_visit_string_from_indefinite_text() {
    // 0x7f .. 0xff is an indefinite-length text string, decoded into an owned
    // String (visit_string).
    let indef = [0x7f, 0x61, 0x61, 0xff];
    let label: Label = cbor2::from_slice(&indef).unwrap();
    assert_eq!(label, Label::Text("a".into()));
}

// ----------------------------------------------------------------------------
// CoseMap: duplicate keys (the dedup branch) and `expecting` (wrong type)
// ----------------------------------------------------------------------------

#[test]
fn cosemap_duplicate_key_detected_by_visitor() {
    // {1: 1, 1: 2} — a well-formed map with a repeated key.
    let dup = [0xa2u8, 0x01, 0x01, 0x01, 0x02];
    let err = CoseMap::from_slice(&dup).unwrap_err();
    assert!(format!("{err}").contains("duplicate"));
}

#[test]
fn cosemap_expecting_on_wrong_type() {
    // An integer is not a map.
    assert!(CoseMap::from_slice(&[0x01]).is_err());
}

// ----------------------------------------------------------------------------
// Key::ops with an out-of-range integer
// ----------------------------------------------------------------------------

#[test]
fn key_ops_integer_out_of_range() {
    let mut key = Key::new();
    key.insert(iana::KeyParameterKeyOps, vec![Value::from(u64::MAX)]);
    assert!(key.ops().is_err());
}

// ----------------------------------------------------------------------------
// Recipient / SuppPubInfo / KdfContext: `expecting` and decode_protected errors
// ----------------------------------------------------------------------------

#[test]
fn recipient_expecting_on_wrong_type() {
    assert!(Recipient::from_slice(&[0x01]).is_err());
}

#[test]
fn recipient_invalid_protected_bytes() {
    // [h'ff', {}, h''] — protected is not valid CBOR, so decode_protected fails.
    let body = cbor2::to_vec(&(
        serde_bytes::Bytes::new(&[0xff]),
        Header::new(),
        Some(serde_bytes::Bytes::new(&[])),
    ))
    .unwrap();
    assert!(Recipient::from_slice(&body).is_err());
}

#[test]
fn supp_pub_info_expecting_on_wrong_type() {
    assert!(cbor2::from_slice::<SuppPubInfo>(&[0x01]).is_err());
}

#[test]
fn supp_pub_info_invalid_protected_bytes() {
    // [128, h'ff'] — protected is invalid CBOR.
    let body = cbor2::to_vec(&(128u64, serde_bytes::Bytes::new(&[0xff]))).unwrap();
    assert!(cbor2::from_slice::<SuppPubInfo>(&body).is_err());
}

#[test]
fn kdf_context_expecting_on_wrong_type() {
    assert!(KdfContext::from_slice(&[0x01]).is_err());
}

// ----------------------------------------------------------------------------
// Encrypt (with recipients): IV size mismatch, decode without recipients,
// ciphertext accessor
// ----------------------------------------------------------------------------

#[test]
fn encrypt_iv_size_mismatch() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12);
    let mut msg = EncryptMessage::new(Some(b"x".to_vec()));
    msg.unprotected
        .insert(iana::HeaderParameterIV, vec![0u8; 4]); // wrong size
    let mut r = Recipient::new();
    r.ciphertext = Some(vec![]);
    msg.recipients.push(r);
    assert!(msg.encrypt(&enc, None).is_err());
}

#[test]
fn encrypt_decode_without_recipients_or_ciphertext() {
    // [protected, unprotected, ciphertext, []] — empty recipients.
    let no_recip = cbor2::to_vec(&(
        serde_bytes::Bytes::new(&[]),
        Header::new(),
        Some(serde_bytes::Bytes::new(b"ct")),
        Vec::<Value>::new(),
    ))
    .unwrap();
    let tagged = tag::with_tag(tag::ENCRYPT_PREFIX, &no_recip);
    assert!(EncryptMessage::from_slice(&tagged).is_err());

    // [protected, unprotected, nil, [recipient]] — detached ciphertext.
    let recip = Recipient {
        ciphertext: Some(vec![]),
        ..Default::default()
    };
    let no_ct = cbor2::to_canonical_vec(&(
        serde_bytes::Bytes::new(&[]),
        Header::new(),
        Option::<&serde_bytes::Bytes>::None,
        vec![recip],
    ))
    .unwrap();
    let tagged = tag::with_tag(tag::ENCRYPT_PREFIX, &no_ct);
    assert!(EncryptMessage::from_slice(&tagged).is_err());
}

#[test]
fn encrypt_ciphertext_accessor() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12);
    let mut msg = EncryptMessage::new(Some(b"data".to_vec()));
    msg.unprotected
        .insert(iana::HeaderParameterIV, vec![5u8; 12]);
    let mut r = Recipient::new();
    r.ciphertext = Some(vec![]);
    msg.recipients.push(r);
    msg.encrypt(&enc, None).unwrap();
    assert!(!msg.ciphertext().is_empty());
}

// ----------------------------------------------------------------------------
// Mac (with recipients): decode without recipients, tag accessor
// ----------------------------------------------------------------------------

#[test]
fn mac_decode_without_recipients() {
    // [protected, unprotected, payload, tag, []] — empty recipients.
    let body = cbor2::to_vec(&(
        serde_bytes::Bytes::new(&[]),
        Header::new(),
        Some(serde_bytes::Bytes::new(b"p")),
        serde_bytes::Bytes::new(b"t"),
        Vec::<Value>::new(),
    ))
    .unwrap();
    let tagged = tag::with_tag(tag::MAC_PREFIX, &body);
    assert!(MacMessage::from_slice(&tagged).is_err());
}

#[test]
fn mac_tag_accessor() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"m");
    let mut msg = MacMessage::new(Some(b"x".to_vec()));
    let mut r = Recipient::new();
    r.ciphertext = Some(vec![]);
    msg.recipients.push(r);
    msg.compute(&macer, None).unwrap();
    assert!(!msg.tag().is_empty());
}

// ----------------------------------------------------------------------------
// Sign: empty-signatures branches via clearing the public field
// ----------------------------------------------------------------------------

#[test]
fn sign_cleared_signatures_branches() {
    let s1 = MockSigner::new(iana::AlgorithmES256, b"a");
    let v1 = MockVerifier::new(iana::AlgorithmES256, b"a");
    let mut msg = SignMessage::new(Some(b"x".to_vec()));
    let signers: [&dyn cose2::Signer; 1] = [&s1];
    let encoded = msg.sign_and_encode(&signers, None).unwrap();

    let mut decoded = SignMessage::from_slice(&encoded).unwrap();
    decoded.signatures.clear();
    assert!(decoded.to_vec().is_err());
    let verifiers: [&dyn cose2::Verifier; 1] = [&v1];
    assert!(decoded.verify(&verifiers, None).is_err());
}

// ----------------------------------------------------------------------------
// CWT: iat present and valid with `expect_issued_in_the_past`
// ----------------------------------------------------------------------------

#[test]
fn validator_iat_in_past_is_accepted() {
    let v = Validator::new(ValidatorOptions {
        expect_issued_in_the_past: true,
        clock_skew_secs: 0,
        fixed_now: Some(1_000),
        ..Default::default()
    })
    .unwrap();
    let claims = Claims {
        expiration: Some(2_000),
        issued_at: Some(900), // in the past → reaches the post-check path
        ..Default::default()
    };
    assert!(v.validate(&claims).is_ok());

    // expect_issued_in_the_past with no iat: the inner `if let` falls through.
    let no_iat = Claims {
        expiration: Some(2_000),
        ..Default::default()
    };
    assert!(v.validate(&no_iat).is_ok());
}

#[test]
fn verify_with_alg_but_no_alg_in_protected() {
    // Signer adds no alg (alg = 0) → protected has no alg. The verifier still
    // declares an alg, so check_protected_alg takes the "no header alg" path.
    let signer = MockSigner::new(0, b"k");
    let verifier = MockVerifier::new(iana::AlgorithmES256, b"k");
    let mut msg = Sign1Message::new(Some(b"x".to_vec()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();
    assert!(msg.protected.is_empty());
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());
}

// ----------------------------------------------------------------------------
// Visitor `expecting()` messages, driven by a wrong-typed serde deserializer
// ----------------------------------------------------------------------------

#[test]
fn recipient_missing_elements() {
    // array(0): missing protected.
    assert!(Recipient::from_slice(&[0x80]).is_err());
    // array(1) [h'']: missing unprotected.
    assert!(Recipient::from_slice(&[0x81, 0x40]).is_err());
    // array(2) [h'', {}]: missing ciphertext.
    assert!(Recipient::from_slice(&[0x82, 0x40, 0xa0]).is_err());
}

#[test]
fn supp_pub_info_missing_elements() {
    // array(0): missing keyDataLength.
    assert!(cbor2::from_slice::<SuppPubInfo>(&[0x80]).is_err());
    // array(1) [128]: missing protected.
    assert!(cbor2::from_slice::<SuppPubInfo>(&[0x81, 0x18, 0x80]).is_err());
}

#[test]
fn kdf_context_missing_elements() {
    use cose2::PartyInfo;
    // array(1): missing PartyUInfo.
    let b = cbor2::to_vec(&(1i64,)).unwrap();
    assert!(KdfContext::from_slice(&b).is_err());
    // array(2): missing PartyVInfo.
    let b = cbor2::to_vec(&(1i64, PartyInfo::default())).unwrap();
    assert!(KdfContext::from_slice(&b).is_err());
    // array(3): missing SuppPubInfo.
    let b = cbor2::to_vec(&(1i64, PartyInfo::default(), PartyInfo::default())).unwrap();
    assert!(KdfContext::from_slice(&b).is_err());
}

#[test]
fn encrypt_missing_iv() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"", 12);
    let mut msg = EncryptMessage::new(Some(b"x".to_vec()));
    let mut r = Recipient::new();
    r.ciphertext = Some(vec![]);
    msg.recipients.push(r);
    assert!(msg.encrypt(&enc, None).is_err());
}

#[test]
fn visitor_expecting_messages() {
    use serde::de::value::{Error as VErr, I32Deserializer};
    use serde::de::IntoDeserializer;
    use serde::Deserialize;

    // Each of these calls `deserialize_map`/`deserialize_seq` on an integer
    // deserializer, which routes to the visitor's default `visit_i32`, which
    // formats the error using `expecting()`.
    let de: I32Deserializer<VErr> = 7i32.into_deserializer();
    assert!(CoseMap::deserialize(de).is_err());

    let de: I32Deserializer<VErr> = 7i32.into_deserializer();
    assert!(Recipient::deserialize(de).is_err());

    let de: I32Deserializer<VErr> = 7i32.into_deserializer();
    assert!(SuppPubInfo::deserialize(de).is_err());

    let de: I32Deserializer<VErr> = 7i32.into_deserializer();
    assert!(KdfContext::deserialize(de).is_err());
}
