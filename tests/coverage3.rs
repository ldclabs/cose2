//! Third coverage batch: header/key conversions and value-error paths, message
//! state guards, wrong-tag rejections, and recipient edge serialization.

mod common;

use common::*;
use cose2::{
    iana, CoseMap, Encrypt0Message, EncryptMessage, Header, Key, Label, Mac0Message, MacMessage,
    Recipient, Sign1Message, SignMessage, Value,
};

fn key_wrap_recipient() -> Recipient {
    let mut r = Recipient::new();
    r.unprotected.set_alg(iana::AlgorithmA128KW);
    r.ciphertext = Some(vec![1, 2, 3, 4]);
    r
}

fn iv_encryptor() -> MockEncryptor {
    MockEncryptor::new(iana::AlgorithmA128GCM, b"k", 12)
}

#[test]
fn header_conversions_and_crit_value_errors() {
    // CoseMap <-> Header conversions and FromIterator.
    let mut header = Header::new();
    header.set_kid(b"k".to_vec());
    let map: CoseMap = header.clone().into();
    assert_eq!(map.len(), 1);
    let from_iter: Header = [(Label::Int(4), Value::from("x"))].into_iter().collect();
    assert!(from_iter.kid().is_err() || from_iter.contains_key(4));

    // crit present but not an array.
    let mut bad = Header::new();
    bad.insert(iana::HeaderParameterCrit, 5i64);
    assert!(bad.crit().is_err());

    // crit array containing a non-label (boolean).
    let mut bad2 = Header::new();
    bad2.insert(iana::HeaderParameterCrit, vec![Value::Bool(true)]);
    assert!(bad2.crit().is_err());
}

#[test]
fn key_ops_non_label_and_deserialize() {
    // key_ops with a byte-string element is rejected.
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeSymmetric);
    key.insert(iana::KeyParameterKeyOps, vec![Value::Bytes(vec![1, 2])]);
    assert!(key.ops().is_err());

    // Key's serde Deserialize impl (distinct from from_slice).
    let mut valid = Key::new();
    valid
        .set_kty(iana::KeyTypeEC2)
        .set_alg(iana::AlgorithmES256);
    let bytes = valid.to_vec().unwrap();
    let back: Key = cbor2::from_slice(&bytes).unwrap();
    assert_eq!(back.kty().unwrap(), Some(Label::Int(iana::KeyTypeEC2)));
    // A map without kty fails to deserialize.
    let no_kty = CoseMap::from_iter([(Label::Int(3), Value::from(1i64))]);
    assert!(cbor2::from_slice::<Key>(&no_kty.to_vec().unwrap()).is_err());
}

#[test]
fn sign_kid_present_but_verifier_has_none() {
    // kid_matches mismatch arm: message signature has a kid, verifier does not.
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"k");
    let signers: [&dyn cose2::Signer; 1] = [&signer];
    let mut msg = SignMessage::new(Some(b"p".to_vec()));
    let encoded = msg.sign_and_encode(&signers, None).unwrap();
    let decoded = SignMessage::from_slice(&encoded).unwrap();

    let no_kid = MockVerifier::new(iana::AlgorithmEdDSA, b""); // kid() -> None
    let verifiers: [&dyn cose2::Verifier; 1] = [&no_kid];
    assert!(decoded.verify(&verifiers, None).is_err());
}

#[test]
fn message_state_guards() {
    let enc = iv_encryptor();
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"k");
    let verifier = MockVerifier::new(iana::AlgorithmEdDSA, b"k");

    // Detached/verify before encode/decode.
    let mut e0 = Encrypt0Message::new(Some(b"x".to_vec()));
    assert!(e0.decrypt_detached(&enc, b"c", None).is_err());
    let mut em = EncryptMessage::new(Some(b"x".to_vec()));
    assert!(em.decrypt_detached(&enc, b"c", None).is_err());
    assert!(Mac0Message::new(None)
        .verify_detached(&macer, b"x", None)
        .is_err());
    assert!(MacMessage::new(None)
        .verify_detached(&macer, b"x", None)
        .is_err());
    assert!(Sign1Message::new(None)
        .verify_detached(&verifier, b"x", None)
        .is_err());

    // EncryptMessage::to_vec with the recipient list cleared after encrypting.
    let mut msg = EncryptMessage::new(Some(b"p".to_vec()));
    msg.recipients.push(key_wrap_recipient());
    msg.unprotected.set_iv(vec![1u8; 12]);
    msg.encrypt(&enc, None).unwrap();
    msg.recipients.clear();
    assert!(msg.to_vec().is_err());

    // A decoded, embedded EncryptMessage rejects decrypt_detached.
    let mut whole = EncryptMessage::new(Some(b"p".to_vec()));
    whole.recipients.push(key_wrap_recipient());
    whole.unprotected.set_iv(vec![2u8; 12]);
    let bytes = whole.encrypt_and_encode(&enc, None).unwrap();
    let mut decoded = EncryptMessage::from_slice(&bytes).unwrap();
    assert!(decoded.decrypt_detached(&enc, b"c", None).is_err());

    // A computed, embedded Mac/Mac0 rejects verify_detached.
    let mut mac = MacMessage::new(Some(b"p".to_vec()));
    mac.recipients.push(key_wrap_recipient());
    let mac_bytes = mac.compute_and_encode(&macer, None).unwrap();
    let mac_decoded = MacMessage::from_slice(&mac_bytes).unwrap();
    assert!(mac_decoded.verify_detached(&macer, b"p", None).is_err());

    // MacMessage::to_vec with the recipient list cleared after computing.
    mac.recipients.clear();
    assert!(mac.to_vec().is_err());
}

#[test]
fn decode_rejects_wrong_tags_for_each_type() {
    // A COSE_Mac0 (tag 0xd1) fed to decoders that expect other tags.
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"k");
    let mut m0 = Mac0Message::new(Some(b"p".to_vec()));
    let m0_bytes = m0.compute_and_encode(&macer, None).unwrap();

    assert!(Encrypt0Message::from_slice(&m0_bytes).is_err());
    assert!(MacMessage::from_slice(&m0_bytes).is_err());
    assert!(SignMessage::from_slice(&m0_bytes).is_err());
    assert!(EncryptMessage::from_slice(&m0_bytes).is_err());
}

#[test]
fn recipient_unknown_int_alg_and_none_ciphertext_serialize() {
    // An unknown integer algorithm classifies as None and validates.
    let mut unknown = Recipient::new();
    unknown.unprotected.set_alg(9999i64);
    unknown.ciphertext = None;
    assert!(unknown.algorithm_class().unwrap().is_none());
    assert!(unknown.validate().is_ok());
    // Serializing it exercises the nil-ciphertext arm.
    let bytes = unknown.to_vec().unwrap();
    let back = Recipient::from_slice(&bytes).unwrap();
    assert!(back.ciphertext.is_none());
}
