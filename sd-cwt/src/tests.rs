use super::*;
use cose2::Sign1Message;

fn salt(byte: u8) -> Vec<u8> {
    vec![byte; 16]
}

fn hash(disclosure: &Disclosure) -> Vec<u8> {
    disclosure.redacted_hash(&Sha256RedactionHasher)
}

fn salt_source() -> impl FnMut() -> [u8; 16] {
    let mut next = 1u8;
    move || {
        let salt = [next; 16];
        next += 1;
        salt
    }
}

#[test]
fn simple_label_and_tagged_array_element_have_expected_wire_shape() {
    assert_eq!(
        cbor2::to_vec(&redacted_claim_keys_label()).unwrap(),
        vec![0xf8, 0x3b]
    );

    let tagged = redacted_element(vec![0xab; 32]);
    let encoded = cbor2::to_vec(&tagged).unwrap();
    assert_eq!(encoded[0], 0xd8);
    assert_eq!(encoded[1], REDACTED_ELEMENT_TAG as u8);
    assert_eq!(encoded[2], 0x58);
    assert_eq!(encoded[3], 32);
}

#[test]
fn disclosure_round_trips_and_hashes_encoded_bytes() {
    let disclosure = Disclosure::claim(salt(1), 2, "Alice").unwrap();
    let encoded = disclosure.encoded().to_vec();

    let decoded = Disclosure::from_encoded(encoded.clone()).unwrap();
    assert_eq!(decoded.kind(), disclosure.kind());
    assert_eq!(decoded.encoded(), encoded.as_slice());
    assert_eq!(
        decoded.redacted_hash(&Sha256RedactionHasher),
        hash(&disclosure)
    );

    match decoded.kind() {
        DisclosureKind::Claim { salt, key, value } => {
            assert_eq!(salt, &vec![1; 16]);
            assert_eq!(key, &Label::Int(2));
            assert_eq!(value, &Value::Text("Alice".into()));
        }
        _ => panic!("expected claim disclosure"),
    }
}

#[test]
fn sd_claims_header_helpers_omit_empty_and_decode_entries() {
    let disclosure = Disclosure::element(salt(2), 42).unwrap();
    let mut header = Header::new();

    set_disclosures(&mut header, &[]);
    assert!(!header.contains_key(HEADER_SD_CLAIMS));

    set_disclosures(&mut header, std::slice::from_ref(&disclosure));
    let decoded = disclosures_from_unprotected(&header).unwrap();
    assert_eq!(decoded, vec![disclosure]);

    DisclosureSet::new().write_unprotected(&mut header);
    assert!(!header.contains_key(HEADER_SD_CLAIMS));
}

#[test]
fn restores_redacted_map_claim_for_holder() {
    let disclosure = Disclosure::claim(salt(3), 2, "holder").unwrap();
    let payload = Value::Map(vec![
        (Value::from(1), Value::from("issuer")),
        (
            redacted_claim_keys_label(),
            Value::Array(vec![Value::Bytes(hash(&disclosure))]),
        ),
    ]);

    let report = restore_for_holder(payload, vec![disclosure], &Sha256RedactionHasher).unwrap();

    assert_eq!(report.disclosed, 1);
    assert_eq!(
        report.value,
        Value::Map(vec![
            (Value::from(1), Value::from("issuer")),
            (Value::from(2), Value::from("holder")),
        ])
    );
}

#[test]
fn verifier_removes_undisclosed_map_claims_and_array_elements() {
    let disclosed = Disclosure::element(salt(4), "visible").unwrap();
    let payload = Value::Map(vec![
        (
            redacted_claim_keys_label(),
            Value::Array(vec![Value::Bytes(vec![0xaa; 32])]),
        ),
        (
            Value::from("items"),
            Value::Array(vec![
                redacted_element(hash(&disclosed)),
                redacted_element(vec![0xbb; 32]),
                Value::from("plain"),
            ]),
        ),
    ]);

    let report = restore_for_verifier(payload, vec![disclosed], &Sha256RedactionHasher).unwrap();
    assert_eq!(report.disclosed, 1);
    assert_eq!(report.removed_redactions, 2);
    assert_eq!(
        report.value,
        Value::Map(vec![(
            Value::from("items"),
            Value::Array(vec![Value::from("visible"), Value::from("plain")]),
        )])
    );
}

#[test]
fn holder_rejects_undisclosed_redaction() {
    let payload = Value::Map(vec![(
        redacted_claim_keys_label(),
        Value::Array(vec![Value::Bytes(vec![0xaa; 32])]),
    )]);

    assert!(restore_for_holder(payload, Vec::new(), &Sha256RedactionHasher).is_err());
}

#[test]
fn nested_disclosures_are_matched_in_any_order() {
    let child = Disclosure::claim(salt(5), "country", "FR").unwrap();
    let parent_value = Value::Map(vec![(
        redacted_claim_keys_label(),
        Value::Array(vec![Value::Bytes(hash(&child))]),
    )]);
    let parent = Disclosure::claim(salt(6), "address", parent_value).unwrap();
    let payload = Value::Map(vec![(
        redacted_claim_keys_label(),
        Value::Array(vec![Value::Bytes(hash(&parent))]),
    )]);

    let report = restore_for_holder(payload, vec![child, parent], &Sha256RedactionHasher).unwrap();

    assert_eq!(report.disclosed, 2);
    assert_eq!(
        report.value,
        Value::Map(vec![(
            Value::from("address"),
            Value::Map(vec![(Value::from("country"), Value::from("FR"))]),
        )])
    );
}

#[test]
fn extraneous_disclosure_is_rejected_in_both_modes() {
    // A disclosure whose digest matches no redacted digest in the signed
    // payload must fail: otherwise a holder or MITM could inject
    // unrelated claims into a presentation.
    let matched = Disclosure::claim(salt(20), 2, "ok").unwrap();
    let extraneous = Disclosure::claim(salt(21), "email", "eve@example.com").unwrap();
    let payload = Value::Map(vec![(
        redacted_claim_keys_label(),
        Value::Array(vec![Value::Bytes(hash(&matched))]),
    )]);

    for mode in [RestoreMode::Holder, RestoreMode::Verifier] {
        let err = restore(
            payload.clone(),
            vec![matched.clone(), extraneous.clone()],
            &Sha256RedactionHasher,
            mode,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("without a matching redacted claim"));
    }
}

#[test]
fn duplicate_disclosure_digests_are_rejected() {
    let disclosure = Disclosure::claim(salt(22), 2, "dup").unwrap();
    let payload = Value::Map(vec![(
        redacted_claim_keys_label(),
        Value::Array(vec![Value::Bytes(hash(&disclosure))]),
    )]);

    let err = restore_for_verifier(
        payload,
        vec![disclosure.clone(), disclosure],
        &Sha256RedactionHasher,
    )
    .unwrap_err();
    assert!(format!("{err}").contains("duplicate SD-CWT disclosure digest"));
}

#[test]
fn holder_rejects_undisclosed_array_element_redaction() {
    let payload = Value::Array(vec![redacted_element(vec![0xcc; 32]), Value::from("kept")]);
    let err = restore_for_holder(payload, Vec::new(), &Sha256RedactionHasher).unwrap_err();
    assert!(format!("{err}").contains("redacted array element without disclosure"));
}

#[test]
fn duplicate_disclosed_key_is_invalid() {
    let disclosure = Disclosure::claim(salt(7), 1, "redacted").unwrap();
    let payload = Value::Map(vec![
        (Value::from(1), Value::from("plain")),
        (
            redacted_claim_keys_label(),
            Value::Array(vec![Value::Bytes(hash(&disclosure))]),
        ),
    ]);

    assert!(restore_for_verifier(payload, vec![disclosure], &Sha256RedactionHasher).is_err());
}

#[test]
fn decoys_are_removed_when_their_digest_is_present() {
    let decoy = Disclosure::decoy(salt(8)).unwrap();
    let payload = Value::Array(vec![redacted_element(hash(&decoy)), Value::from("kept")]);

    let report = restore_for_verifier(payload, vec![decoy], &Sha256RedactionHasher).unwrap();
    assert_eq!(report.decoys, 1);
    assert_eq!(report.value, Value::Array(vec![Value::from("kept")]));
}

#[test]
fn aead_encrypted_disclosures_header_round_trips() {
    let encrypted = AeadEncryptedDisclosure {
        nonce: vec![1, 2, 3],
        ciphertext: vec![4, 5],
        tag: vec![6; 16],
        key_context: Some(AeadKeyContext::Text("key-a".into())),
    };
    let mut header = Header::new();
    set_aead_encrypted_disclosures(&mut header, std::slice::from_ref(&encrypted));

    assert_eq!(
        aead_encrypted_disclosures_from_unprotected(&header).unwrap(),
        vec![encrypted]
    );
}

#[test]
fn issue_from_preissuance_redacts_map_keys_and_array_elements() {
    let preissued = Value::Map(vec![
        (Value::from(1), Value::from("issuer")),
        (
            Value::Tag(TO_BE_REDACTED_TAG, Box::new(Value::from("name"))),
            Value::from("Alice"),
        ),
        (
            Value::from("countries"),
            Value::Array(vec![
                Value::Tag(TO_BE_REDACTED_TAG, Box::new(Value::from("de"))),
                Value::from("fr"),
            ]),
        ),
    ]);
    let mut salts = salt_source();

    let issued = issue_from_preissuance(preissued, &mut salts, &Sha256RedactionHasher).unwrap();

    assert_eq!(issued.disclosures.len(), 2);
    let restored =
        restore_for_holder(issued.value, issued.disclosures, &Sha256RedactionHasher).unwrap();
    assert_eq!(
        restored.value,
        Value::Map(vec![
            (Value::from(1), Value::from("issuer")),
            (
                Value::from("countries"),
                Value::Array(vec![Value::from("de"), Value::from("fr")]),
            ),
            (Value::from("name"), Value::from("Alice")),
        ])
    );
}

#[test]
fn issue_from_preissuance_inserts_and_restores_decoys() {
    let preissued = Value::Map(vec![
        (
            Value::Tag(TO_BE_DECOY_TAG, Box::new(Value::from(1))),
            Value::Null,
        ),
        (
            Value::from("items"),
            Value::Array(vec![Value::Tag(TO_BE_DECOY_TAG, Box::new(Value::from(2)))]),
        ),
    ]);
    let mut salts = salt_source();

    let issued = issue_from_preissuance(preissued, &mut salts, &Sha256RedactionHasher).unwrap();

    assert_eq!(issued.disclosures.len(), 2);
    let restored =
        restore_for_verifier(issued.value, issued.disclosures, &Sha256RedactionHasher).unwrap();
    assert_eq!(restored.decoys, 2);
    assert_eq!(
        restored.value,
        Value::Map(vec![(Value::from("items"), Value::Array(vec![]))])
    );
}

#[test]
fn issue_from_preissuance_rejects_duplicate_normalized_keys_and_decoy_ids() {
    let duplicate_key = Value::Map(vec![
        (Value::from("name"), Value::from("plain")),
        (
            Value::Tag(TO_BE_REDACTED_TAG, Box::new(Value::from("name"))),
            Value::from("redacted"),
        ),
    ]);
    let duplicate_decoy = Value::Array(vec![
        Value::Tag(TO_BE_DECOY_TAG, Box::new(Value::from(1))),
        Value::Tag(TO_BE_DECOY_TAG, Box::new(Value::from(1))),
    ]);
    let mut salts = salt_source();
    assert!(issue_from_preissuance(duplicate_key, &mut salts, &Sha256RedactionHasher).is_err());

    let mut salts = salt_source();
    assert!(issue_from_preissuance(duplicate_decoy, &mut salts, &Sha256RedactionHasher).is_err());
}

#[test]
fn restore_payload_from_message_uses_headers() {
    let disclosure = Disclosure::claim(salt(9), "name", "Alice").unwrap();
    let payload = Value::Map(vec![(
        redacted_claim_keys_label(),
        Value::Array(vec![Value::Bytes(hash(&disclosure))]),
    )]);
    let mut message = Sign1Message::new(Some(cbor2::to_vec(&payload).unwrap()));
    set_disclosures(&mut message.unprotected, std::slice::from_ref(&disclosure));

    let report = restore_payload_from_message(&message, RestoreMode::Holder).unwrap();
    assert_eq!(
        report.value,
        Value::Map(vec![(Value::from("name"), Value::from("Alice"),)])
    );
}
