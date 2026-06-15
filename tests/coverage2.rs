//! Second coverage batch: untagged decode (BareWire paths), detached one-step
//! APIs, recipient validation branches, and small accessor/From paths.

mod common;

use common::*;
use cose2::{
    iana, tag, Encrypt0Message, EncryptMessage, Header, Label, Mac0Message, MacMessage, Recipient,
    Sign1Message, SignMessage, Value,
};

fn key_wrap_recipient() -> Recipient {
    let mut r = Recipient::new();
    r.unprotected.set_alg(iana::AlgorithmA128KW);
    r.ciphertext = Some(vec![1, 2, 3, 4]);
    r
}

// ----------------------------------------------------------------------------
// Untagged decode exercises the `From<*BareWire>` conversions.
// ----------------------------------------------------------------------------

#[test]
fn untagged_decode_round_trips_every_message() {
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"k");
    let signers: [&dyn cose2::Signer; 1] = [&signer];
    let verifier = MockVerifier::new(iana::AlgorithmEdDSA, b"k");
    let verifiers: [&dyn cose2::Verifier; 1] = [&verifier];
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"k");
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"k", 12);

    // COSE_Sign (tag 98, 2-byte prefix).
    let mut sign = SignMessage::new(Some(b"p".to_vec()));
    let tagged = sign.sign_and_encode(&signers, None).unwrap();
    let untagged = &tagged[tag::SIGN_PREFIX.len()..];
    let decoded = SignMessage::from_slice(untagged).unwrap();
    assert!(decoded.verify(&verifiers, None).is_ok());

    // COSE_Mac (tag 97).
    let mut mac = MacMessage::new(Some(b"p".to_vec()));
    mac.recipients.push(key_wrap_recipient());
    let tagged = mac.compute_and_encode(&macer, None).unwrap();
    let decoded = MacMessage::from_slice(&tagged[tag::MAC_PREFIX.len()..]).unwrap();
    assert!(decoded.verify(&macer, None).is_ok());

    // COSE_Mac0 (tag 17, 1-byte prefix).
    let mut mac0 = Mac0Message::new(Some(b"p".to_vec()));
    let tagged = mac0.compute_and_encode(&macer, None).unwrap();
    let decoded = Mac0Message::from_slice(&tagged[tag::MAC0_PREFIX.len()..]).unwrap();
    assert!(decoded.verify(&macer, None).is_ok());

    // COSE_Encrypt (tag 96).
    let mut encm = EncryptMessage::new(Some(b"p".to_vec()));
    encm.recipients.push(key_wrap_recipient());
    encm.unprotected.set_iv(vec![1u8; 12]);
    let tagged = encm.encrypt_and_encode(&enc, None).unwrap();
    let mut decoded = EncryptMessage::from_slice(&tagged[tag::ENCRYPT_PREFIX.len()..]).unwrap();
    assert!(decoded.decrypt(&enc, None).is_ok());

    // COSE_Encrypt0 (tag 16).
    let mut enc0 = Encrypt0Message::new(Some(b"p".to_vec()));
    enc0.unprotected.set_iv(vec![1u8; 12]);
    let tagged = enc0.encrypt_and_encode(&enc, None).unwrap();
    let mut decoded = Encrypt0Message::from_slice(&tagged[tag::ENCRYPT0_PREFIX.len()..]).unwrap();
    assert!(decoded.decrypt(&enc, None).is_ok());
}

#[test]
fn decode_rejects_wrong_cose_tags() {
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"k");
    let signers: [&dyn cose2::Signer; 1] = [&signer];
    let mut sign = SignMessage::new(Some(b"p".to_vec()));
    let sign_bytes = sign.sign_and_encode(&signers, None).unwrap();

    // A COSE_Sign (tag 98) fed to other decoders must be rejected.
    assert!(MacMessage::from_slice(&sign_bytes).is_err());
    assert!(EncryptMessage::from_slice(&sign_bytes).is_err());

    let mut enc0 = Encrypt0Message::new(Some(b"p".to_vec()));
    enc0.unprotected.set_iv(vec![1u8; 12]);
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"k", 12);
    let e0 = enc0.encrypt_and_encode(&enc, None).unwrap();
    assert!(Mac0Message::from_slice(&e0).is_err());
}

// ----------------------------------------------------------------------------
// Detached one-step APIs and their guard branches.
// ----------------------------------------------------------------------------

#[test]
fn sign1_detached_one_step_and_guards() {
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"k");
    let verifier = MockVerifier::new(iana::AlgorithmEdDSA, b"k");
    let mut msg = Sign1Message::new(None);
    let encoded = msg
        .sign_detached_and_encode(&signer, b"detached", Some(b"aad"))
        .unwrap();
    assert!(!msg.protected_raw().is_empty());

    let decoded =
        Sign1Message::verify_detached_and_decode(&verifier, &encoded, b"detached", Some(b"aad"))
            .unwrap();
    assert!(decoded.payload.is_none());

    // verify_detached on an embedded-payload message is rejected.
    let mut embedded = Sign1Message::new(Some(b"p".to_vec()));
    let enc2 = embedded.sign_and_encode(&signer, None).unwrap();
    let dec2 = Sign1Message::from_slice(&enc2).unwrap();
    assert!(dec2.verify_detached(&verifier, b"p", None).is_err());
}

#[test]
fn sign_detached_one_step() {
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"k");
    let signers: [&dyn cose2::Signer; 1] = [&signer];
    let verifier = MockVerifier::new(iana::AlgorithmEdDSA, b"k");
    let verifiers: [&dyn cose2::Verifier; 1] = [&verifier];

    let mut msg = SignMessage::new(None);
    let encoded = msg
        .sign_detached_and_encode(&signers, b"detached", None)
        .unwrap();
    // The body protected header is empty; the signer's alg sits in the
    // per-signature protected header instead.
    assert!(msg.protected_raw().is_empty());
    let decoded =
        SignMessage::verify_detached_and_decode(&verifiers, &encoded, b"detached", None).unwrap();
    assert!(!decoded.signatures[0].protected_raw().is_empty());

    // verify_detached rejects an embedded-payload message.
    let mut embedded = SignMessage::new(Some(b"p".to_vec()));
    let enc2 = embedded.sign_and_encode(&signers, None).unwrap();
    let dec2 = SignMessage::from_slice(&enc2).unwrap();
    assert!(dec2.verify_detached(&verifiers, b"p", None).is_err());
}

#[test]
fn mac_and_mac0_detached_one_step() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"k");

    let mut mac = MacMessage::new(None);
    mac.recipients.push(key_wrap_recipient());
    let encoded = mac
        .compute_detached_and_encode(&macer, b"detached", None)
        .unwrap();
    assert!(!mac.protected_raw().is_empty());
    let decoded =
        MacMessage::verify_detached_and_decode(&macer, &encoded, b"detached", None).unwrap();
    assert!(!decoded.tag().is_empty());

    let mut mac0 = Mac0Message::new(None);
    let encoded = mac0
        .compute_detached_and_encode(&macer, b"detached", None)
        .unwrap();
    assert!(!mac0.protected_raw().is_empty());
    let decoded =
        Mac0Message::verify_detached_and_decode(&macer, &encoded, b"detached", None).unwrap();
    assert!(decoded.payload.is_none());

    // verify_detached rejects an embedded-payload Mac0.
    let mut embedded = Mac0Message::new(Some(b"p".to_vec()));
    let enc2 = embedded.compute_and_encode(&macer, None).unwrap();
    let dec2 = Mac0Message::from_slice(&enc2).unwrap();
    assert!(dec2.verify_detached(&macer, b"p", None).is_err());
}

#[test]
fn encrypt_detached_ciphertext_one_step_and_guards() {
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"k", 12);

    // Encrypt0 detached ciphertext.
    let mut enc0 = Encrypt0Message::new(Some(b"secret".to_vec()));
    enc0.unprotected.set_iv(vec![3u8; 12]);
    let (msg_bytes, ciphertext) = enc0.encrypt_detached_and_encode(&enc, None).unwrap();
    assert!(enc0.is_ciphertext_detached());
    let decoded =
        Encrypt0Message::decrypt_detached_and_decode(&enc, &msg_bytes, &ciphertext, None).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"secret"[..]));

    // Guards: decrypt() on a detached message, decrypt_detached() on embedded.
    let mut detached = Encrypt0Message::from_slice(&msg_bytes).unwrap();
    assert!(detached.decrypt(&enc, None).is_err());
    let mut embedded = Encrypt0Message::new(Some(b"x".to_vec()));
    embedded.unprotected.set_iv(vec![3u8; 12]);
    let emb_bytes = embedded.encrypt_and_encode(&enc, None).unwrap();
    let mut emb = Encrypt0Message::from_slice(&emb_bytes).unwrap();
    assert!(emb.decrypt_detached(&enc, &ciphertext, None).is_err());

    // EncryptMessage detached ciphertext.
    let mut encm = EncryptMessage::new(Some(b"secret".to_vec()));
    encm.recipients.push(key_wrap_recipient());
    encm.unprotected.set_iv(vec![4u8; 12]);
    let (msg_bytes, ciphertext) = encm.encrypt_detached_and_encode(&enc, None).unwrap();
    assert!(encm.is_ciphertext_detached());
    assert!(!encm.ciphertext().is_empty());
    let decoded =
        EncryptMessage::decrypt_detached_and_decode(&enc, &msg_bytes, &ciphertext, None).unwrap();
    assert_eq!(decoded.payload.as_deref(), Some(&b"secret"[..]));
    let mut detached = EncryptMessage::from_slice(&msg_bytes).unwrap();
    assert!(detached.decrypt(&enc, None).is_err());
}

// ----------------------------------------------------------------------------
// SignMessage verify branch coverage: matching kid but wrong alg, then retry.
// ----------------------------------------------------------------------------

#[test]
fn sign_verify_skips_alg_mismatch_then_succeeds() {
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"shared");
    let signers: [&dyn cose2::Signer; 1] = [&signer];
    let mut msg = SignMessage::new(Some(b"p".to_vec()));
    let encoded = msg.sign_and_encode(&signers, None).unwrap();
    let decoded = SignMessage::from_slice(&encoded).unwrap();

    // First verifier shares the kid but declares the wrong alg (skipped), the
    // second matches and validates.
    let wrong_alg = MockVerifier::new(iana::AlgorithmES256, b"shared");
    let right = MockVerifier::new(iana::AlgorithmEdDSA, b"shared");
    let verifiers: [&dyn cose2::Verifier; 2] = [&wrong_alg, &right];
    assert!(decoded.verify(&verifiers, None).is_ok());
}

// ----------------------------------------------------------------------------
// Recipient validation branches.
// ----------------------------------------------------------------------------

#[test]
fn recipient_validate_all_error_branches() {
    // Direct must not carry nested recipients.
    let mut direct = Recipient::new();
    direct.unprotected.set_alg(iana::AlgorithmDirect);
    direct.ciphertext = Some(vec![]);
    direct.recipients.push({
        let mut r = Recipient::new();
        r.unprotected.set_alg(iana::AlgorithmDirect);
        r.ciphertext = Some(vec![]);
        r
    });
    assert!(direct.validate().is_err());

    // Key-transport: valid, then each structural failure.
    let mut transport = Recipient::new();
    transport
        .unprotected
        .set_alg(iana::AlgorithmRSAES_OAEP_SHA_256);
    transport.ciphertext = Some(vec![9, 9, 9]);
    assert!(transport.validate().is_ok());

    let mut bad_protected = transport.clone();
    bad_protected.protected.set_kid(b"x".to_vec());
    assert!(bad_protected.validate().is_err()); // protected must be empty

    let mut no_ct = transport.clone();
    no_ct.ciphertext = None;
    assert!(no_ct.validate().is_err()); // requires ciphertext

    let mut nested = transport.clone();
    nested.recipients.push(key_wrap_recipient());
    assert!(nested.validate().is_err()); // no nested recipients

    // Direct key agreement must not carry nested recipients.
    let mut direct_ka = Recipient::new();
    direct_ka.protected.set_alg(iana::AlgorithmECDH_ES_HKDF_256);
    direct_ka.ciphertext = Some(vec![]);
    direct_ka.recipients.push(key_wrap_recipient());
    assert!(direct_ka.validate().is_err());

    // Key-agreement-with-key-wrap: valid (ciphertext present) and invalid.
    let mut ka_kw = Recipient::new();
    ka_kw.protected.set_alg(iana::AlgorithmECDH_ES_A128KW);
    ka_kw.ciphertext = Some(vec![7, 7]);
    assert!(ka_kw.validate().is_ok());
    let mut ka_kw_bad = ka_kw.clone();
    ka_kw_bad.ciphertext = None;
    assert!(ka_kw_bad.validate().is_err());

    // Unknown algorithm class is accepted structurally (None arm).
    let mut unknown = Recipient::new();
    unknown.unprotected.set_alg("application-specific");
    unknown.ciphertext = Some(vec![1]);
    assert!(unknown.validate().is_ok());
    assert!(unknown.algorithm_class().unwrap().is_none());
}

#[test]
fn recipient_list_layer_rules() {
    // Two key-wrap recipients in a layer is fine.
    let list = vec![key_wrap_recipient(), key_wrap_recipient()];
    let mut msg = EncryptMessage::new(Some(b"p".to_vec()));
    msg.recipients = list;
    msg.unprotected.set_iv(vec![1u8; 12]);
    let enc = MockEncryptor::new(iana::AlgorithmA128GCM, b"k", 12);
    assert!(msg.encrypt(&enc, None).is_ok());

    // A direct-key-agreement recipient cannot share its layer.
    let mut direct_ka = Recipient::new();
    direct_ka.protected.set_alg(iana::AlgorithmECDH_ES_HKDF_256);
    direct_ka.ciphertext = Some(vec![]);
    let mut bad = EncryptMessage::new(Some(b"p".to_vec()));
    bad.recipients = vec![direct_ka, key_wrap_recipient()];
    bad.unprotected.set_iv(vec![1u8; 12]);
    assert!(bad.encrypt(&enc, None).is_err());
}

#[test]
fn recipient_serialize_validates() {
    // Serializing a recipient with no alg fails validation.
    assert!(cbor2::to_vec(&Recipient::new()).is_err());
}

// ----------------------------------------------------------------------------
// Small accessor / conversion paths.
// ----------------------------------------------------------------------------

#[test]
fn header_as_map_and_label_value_conversions() {
    let mut header = Header::new();
    header.set_kid(b"k".to_vec());
    assert_eq!(header.as_map().len(), 1);
    header.as_mut_map().insert(99, 1i64);
    assert_eq!(header.as_map().len(), 2);

    // From<&Label> for Value.
    let label = Label::Text("x".into());
    assert_eq!(Value::from(&label), Value::from("x"));
    let int_label = Label::Int(5);
    assert_eq!(Value::from(&int_label), Value::from(5i64));
}

#[test]
fn trait_default_base_iv_rejects_partial_iv() {
    // MinimalEncryptor does not override base_iv(), so a Partial IV is rejected.
    let mut msg = Encrypt0Message::new(Some(b"x".to_vec()));
    msg.unprotected.set_partial_iv(vec![1, 2]);
    assert!(msg.encrypt(&MinimalEncryptor, None).is_err());
}
