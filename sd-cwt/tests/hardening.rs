use cbor2::Value;
use cose2::{iana, Error, Label, Sign1Message, Signer, Verifier};
use sd_cwt::{
    aead_encrypted_disclosures_from_unprotected, disclosures_from_unprotected,
    disclosures_from_unprotected_with_limits, issue_from_preissuance, redacted_claim_keys_label,
    redacted_element, restore_for_verifier, set_aead_encrypted_disclosures, set_disclosures,
    set_sd_aead, set_sd_alg, set_sd_cwt_typ, verify_and_decode_sd_cwt,
    verify_validate_and_restore_sd_cwt, AeadEncryptedDisclosure, Disclosure, ProcessingLimits,
    RedactionHasher, RestoreMode, SdCwtValidationOptions, SdCwtValidator, Sha256RedactionHasher,
    HEADER_CWT_CLAIMS, HEADER_SD_AEAD_ENCRYPTED_CLAIMS, HEADER_SD_CLAIMS, HEADER_TYP,
    TO_BE_REDACTED_TAG,
};

struct Toy;
struct GenericToy;

fn tag(data: &[u8]) -> Vec<u8> {
    let mut output = [0u8; 16];
    for (index, byte) in data.iter().enumerate() {
        output[index % output.len()] ^= byte.wrapping_add(index as u8);
    }
    output.to_vec()
}

impl Signer for Toy {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEd25519.into())
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(tag(data))
    }
}

impl Verifier for Toy {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEd25519.into())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        if tag(data) == signature {
            Ok(())
        } else {
            Err(Error::verify("signature mismatch"))
        }
    }
}

impl Signer for GenericToy {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEdDSA.into())
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(tag(data))
    }
}

impl Verifier for GenericToy {
    fn alg(&self) -> Option<Label> {
        Some(iana::AlgorithmEdDSA.into())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        Toy.verify(data, signature)
    }
}

fn valid_claims() -> Value {
    Value::Map(vec![
        (Value::from(1), Value::from("issuer")),
        (Value::from(2), Value::from("subject")),
        (Value::from(5), Value::from(100)),
        (Value::from(6), Value::from(200)),
        (Value::from(4), Value::from(300)),
        (Value::from(8), Value::Map(vec![])),
    ])
}

fn message(payload: Value) -> Sign1Message {
    let mut message = Sign1Message::new(Some(cbor2::to_vec(&payload).unwrap()));
    set_sd_cwt_typ(&mut message.protected);
    set_sd_alg(&mut message.protected, Sha256RedactionHasher.algorithm());
    message.protected.set_alg(iana::AlgorithmEd25519);
    message
}

fn verified_message(payload: Value) -> Sign1Message {
    let mut message = message(payload);
    let encoded = message.sign_and_encode(&Toy, None).unwrap();
    Sign1Message::verify_and_decode(&Toy, &encoded, None).unwrap()
}

#[test]
fn disclosure_and_message_reject_indefinite_length_cbor() {
    let canonical = Disclosure::element(vec![1u8; 16], "value").unwrap();
    let mut indefinite = canonical.encoded().to_vec();
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    assert!(Disclosure::from_encoded(indefinite).is_err());

    let mut message = message(valid_claims());
    let mut encoded = message.sign_and_encode(&Toy, None).unwrap();
    assert_eq!(encoded[0], cose2::tag::SIGN1_PREFIX[0]);
    encoded[1] = 0x9f;
    encoded.push(0xff);
    assert!(verify_and_decode_sd_cwt(&Toy, &encoded, None, ProcessingLimits::default()).is_err());
}

#[test]
fn present_empty_disclosure_headers_are_invalid() {
    let mut header = cose2::Header::new();
    header.insert(HEADER_SD_CLAIMS, Value::Array(vec![]));
    assert!(disclosures_from_unprotected(&header).is_err());
    header.insert(HEADER_SD_AEAD_ENCRYPTED_CLAIMS, Value::Array(vec![]));
    assert!(aead_encrypted_disclosures_from_unprotected(&header).is_err());

    let encrypted = AeadEncryptedDisclosure {
        nonce: vec![1u8; 12],
        ciphertext: vec![2u8],
        tag: vec![3u8; 16],
        key_context: None,
    };
    set_aead_encrypted_disclosures(&mut header, &[encrypted.clone(), encrypted]);
    assert!(aead_encrypted_disclosures_from_unprotected(&header).is_err());
}

#[test]
fn disclosure_chain_hits_limit_without_overflowing_stack() {
    let mut value = Value::from("leaf");
    let mut disclosures = Vec::new();
    for index in 0..200u64 {
        let mut salt = [0u8; 16];
        salt[..8].copy_from_slice(&index.to_le_bytes());
        let disclosure = Disclosure::element(salt.to_vec(), Value::Array(vec![value])).unwrap();
        value = redacted_element(disclosure.redacted_hash(&Sha256RedactionHasher));
        disclosures.push(disclosure);
    }
    let error = restore_for_verifier(
        Value::Array(vec![value]),
        disclosures,
        &Sha256RedactionHasher,
    )
    .unwrap_err();
    assert!(matches!(error, Error::LimitExceeded { .. }));
}

#[test]
fn validator_accepts_valid_structure_and_rejects_generic_algorithm() {
    let validator = SdCwtValidator::default();
    let valid = verified_message(valid_claims());
    let report = validator
        .validate_and_restore(&valid, RestoreMode::Holder)
        .unwrap();
    assert_eq!(report.value, valid_claims());

    let mut generic = message(valid_claims());
    generic.protected.set_alg(iana::AlgorithmEdDSA);
    let encoded = generic.sign_and_encode(&GenericToy, None).unwrap();
    let generic = Sign1Message::verify_and_decode(&GenericToy, &encoded, None).unwrap();
    let error = validator
        .validate_and_restore(&generic, RestoreMode::Holder)
        .unwrap_err();
    assert!(error.to_string().contains("fully specified"));
}

#[test]
fn validator_rejects_never_redacted_claim_and_bad_dates() {
    let disclosure = Disclosure::claim(vec![9u8; 16], 1, "hidden issuer").unwrap();
    let hash = disclosure.redacted_hash(&Sha256RedactionHasher);
    let Value::Map(mut entries) = valid_claims() else {
        unreachable!();
    };
    entries.push((
        redacted_claim_keys_label(),
        Value::Array(vec![Value::Bytes(hash)]),
    ));
    let mut issued_message = message(Value::Map(entries));
    set_disclosures(&mut issued_message.unprotected, &[disclosure]);
    let encoded = issued_message.sign_and_encode(&Toy, None).unwrap();
    let issued_message = Sign1Message::verify_and_decode(&Toy, &encoded, None).unwrap();
    assert!(SdCwtValidator::default()
        .validate_and_restore(&issued_message, RestoreMode::Holder)
        .is_err());

    let Value::Map(mut dates) = valid_claims() else {
        unreachable!();
    };
    for (key, value) in &mut dates {
        if *key == Value::from(5) {
            *value = Value::from(400);
        }
    }
    assert!(SdCwtValidator::new(SdCwtValidationOptions::default())
        .validate_and_restore(&verified_message(Value::Map(dates)), RestoreMode::Holder)
        .is_err());
}

#[test]
fn issued_maps_reject_non_label_keys_and_reserved_tags() {
    let invalid_key = Value::Map(vec![(Value::Bool(false), Value::from("value"))]);
    assert!(restore_for_verifier(invalid_key, [], &Sha256RedactionHasher).is_err());

    let reserved_tag = Value::Map(vec![(
        Value::from("value"),
        Value::Tag(58, Box::new(Value::from("invalid"))),
    )]);
    assert!(restore_for_verifier(reserved_tag, [], &Sha256RedactionHasher).is_err());
}

#[test]
fn protected_cwt_claims_are_restored_and_cross_checked() {
    let disclosure = Disclosure::claim(vec![10u8; 16], "department", "engineering").unwrap();
    let header_claims = Value::Map(vec![(
        redacted_claim_keys_label(),
        Value::Array(vec![Value::Bytes(
            disclosure.redacted_hash(&Sha256RedactionHasher),
        )]),
    )]);
    let mut issued_message = message(valid_claims());
    issued_message
        .protected
        .insert(HEADER_CWT_CLAIMS, header_claims);
    set_disclosures(&mut issued_message.unprotected, &[disclosure]);
    let encoded = issued_message.sign_and_encode(&Toy, None).unwrap();
    let decoded = Sign1Message::verify_and_decode(&Toy, &encoded, None).unwrap();
    let report = SdCwtValidator::default()
        .validate_and_restore(&decoded, RestoreMode::Holder)
        .unwrap();
    let Some(Value::Map(restored)) = report.protected_claims else {
        panic!("expected restored CWT_Claims header");
    };
    assert!(restored.contains(&(Value::from("department"), Value::from("engineering"))));

    let mut mismatch = message(valid_claims());
    mismatch.protected.insert(
        HEADER_CWT_CLAIMS,
        Value::Map(vec![(Value::from(1), Value::from("different issuer"))]),
    );
    let encoded = mismatch.sign_and_encode(&Toy, None).unwrap();
    let decoded = Sign1Message::verify_and_decode(&Toy, &encoded, None).unwrap();
    assert!(SdCwtValidator::default()
        .validate_and_restore(&decoded, RestoreMode::Holder)
        .unwrap_err()
        .to_string()
        .contains("disagree"));
}

#[test]
fn profile_content_type_and_sd_critical_headers_are_processed() {
    let mut message = message(valid_claims());
    message
        .protected
        .insert(HEADER_TYP, "application/example+sd-cwt");
    message
        .protected
        .insert(HEADER_CWT_CLAIMS, Value::Map(vec![]));
    message
        .protected
        .set_crit([HEADER_TYP, sd_cwt::HEADER_SD_ALG, HEADER_CWT_CLAIMS]);
    let encoded = message.sign_and_encode(&Toy, None).unwrap();

    assert!(Sign1Message::verify_and_decode(&Toy, &encoded, None).is_err());
    assert!(verify_validate_and_restore_sd_cwt(
        &Toy,
        &encoded,
        None,
        RestoreMode::Holder,
        SdCwtValidationOptions::default(),
    )
    .is_ok());
}

#[test]
fn validator_rejects_wrong_algorithm_unsafe_headers_and_weak_aead() {
    let mut nonsignature = message(valid_claims());
    nonsignature.protected.set_alg(iana::AlgorithmA128GCM);
    nonsignature.set_signature(vec![0u8; 16]).unwrap();
    let decoded = Sign1Message::from_slice(&nonsignature.to_vec().unwrap()).unwrap();
    assert!(SdCwtValidator::default()
        .validate_and_restore(&decoded, RestoreMode::Holder)
        .is_err());

    let mut unsafe_header = message(valid_claims());
    unsafe_header.protected.insert(
        99,
        Value::Map(vec![(Value::Bool(false), Value::from("invalid key"))]),
    );
    let encoded = unsafe_header.sign_and_encode(&Toy, None).unwrap();
    let decoded = Sign1Message::verify_and_decode(&Toy, &encoded, None).unwrap();
    assert!(SdCwtValidator::default()
        .validate_and_restore(&decoded, RestoreMode::Holder)
        .is_err());

    let mut weak_aead = message(valid_claims());
    set_sd_aead(&mut weak_aead.protected, 5);
    let encoded = weak_aead.sign_and_encode(&Toy, None).unwrap();
    let decoded = Sign1Message::verify_and_decode(&Toy, &encoded, None).unwrap();
    assert!(SdCwtValidator::default()
        .validate_and_restore(&decoded, RestoreMode::Holder)
        .is_err());

    let mut short_aegis_x_tag = message(valid_claims());
    set_sd_aead(&mut short_aegis_x_tag.protected, 34);
    set_aead_encrypted_disclosures(
        &mut short_aegis_x_tag.unprotected,
        &[AeadEncryptedDisclosure {
            nonce: vec![1u8; 16],
            ciphertext: vec![2u8],
            tag: vec![3u8; 16],
            key_context: None,
        }],
    );
    let encoded = short_aegis_x_tag.sign_and_encode(&Toy, None).unwrap();
    let decoded = Sign1Message::verify_and_decode(&Toy, &encoded, None).unwrap();
    assert!(SdCwtValidator::default()
        .validate_and_restore(&decoded, RestoreMode::Holder)
        .unwrap_err()
        .to_string()
        .contains("expected 32 bytes"));
}

#[test]
fn validator_enforces_algorithm_aead_nonce_and_tag_sizes() {
    let build = |algorithm: Option<u16>, nonce_size: usize, tag_size: usize| {
        let mut message = message(valid_claims());
        if let Some(algorithm) = algorithm {
            set_sd_aead(&mut message.protected, algorithm);
        }
        set_aead_encrypted_disclosures(
            &mut message.unprotected,
            &[AeadEncryptedDisclosure {
                nonce: vec![1u8; nonce_size],
                ciphertext: vec![2u8],
                tag: vec![3u8; tag_size],
                key_context: None,
            }],
        );
        let encoded = message.sign_and_encode(&Toy, None).unwrap();
        Sign1Message::verify_and_decode(&Toy, &encoded, None).unwrap()
    };

    let validator = SdCwtValidator::default();
    let bad_nonce = build(None, 1, 16);
    assert!(validator
        .validate_and_restore(&bad_nonce, RestoreMode::Holder)
        .unwrap_err()
        .to_string()
        .contains("expected 12"));

    let bad_tag = build(None, 12, 32);
    assert!(validator
        .validate_and_restore(&bad_tag, RestoreMode::Holder)
        .unwrap_err()
        .to_string()
        .contains("expected 16 bytes"));

    let profile = SdCwtValidator::new(SdCwtValidationOptions {
        aead_nonce_size: Some(24),
        ..SdCwtValidationOptions::default()
    });
    assert!(profile
        .validate_and_restore(&build(None, 12, 16), RestoreMode::Holder)
        .unwrap_err()
        .to_string()
        .contains("does not satisfy the profile"));

    for (algorithm, nonce_size, tag_size) in [
        (1, 12, 16),
        (2, 12, 16),
        (15, 1, 16),
        (16, 1, 16),
        (17, 1, 16),
        (20, 1, 16),
        (23, 1, 16),
        (26, 1, 16),
        (29, 12, 16),
        (30, 12, 16),
        (31, 12, 16),
        (32, 16, 16),
        (33, 32, 32),
        (34, 16, 32),
        (35, 16, 32),
        (36, 32, 32),
        (37, 32, 32),
        (38, 24, 16),
        (39, 24, 16),
    ] {
        let message = build(Some(algorithm), nonce_size, tag_size);
        validator
            .validate_and_restore(&message, RestoreMode::Holder)
            .unwrap();
    }
}

#[test]
fn salts_are_unique_and_disclosure_item_budget_is_aggregate() {
    let first = Disclosure::claim(vec![7u8; 16], "a", 1).unwrap();
    let second = Disclosure::element(vec![7u8; 16], 2).unwrap();
    let mut header = cose2::Header::new();
    set_disclosures(&mut header, &[first, second]);
    assert!(disclosures_from_unprotected(&header).is_err());

    let preissued = Value::Map(vec![
        (
            Value::Tag(TO_BE_REDACTED_TAG, Box::new(Value::from("a"))),
            Value::from(1),
        ),
        (
            Value::Tag(TO_BE_REDACTED_TAG, Box::new(Value::from("b"))),
            Value::from(2),
        ),
    ]);
    let mut repeated_salt = || [9u8; 16];
    assert!(issue_from_preissuance(
        preissued.clone(),
        &mut repeated_salt,
        &Sha256RedactionHasher
    )
    .is_err());

    struct CollisionHasher;
    impl RedactionHasher for CollisionHasher {
        fn algorithm(&self) -> i64 {
            iana::AlgorithmSHA_256
        }

        fn digest(&self, _data: &[u8]) -> Vec<u8> {
            vec![0u8; 32]
        }
    }
    let mut counter = 0u8;
    let mut unique_salts = move || {
        counter += 1;
        [counter; 16]
    };
    assert!(issue_from_preissuance(preissued, &mut unique_salts, &CollisionHasher).is_err());

    let mut header = cose2::Header::new();
    let disclosures = [
        Disclosure::element(vec![1u8; 16], 1).unwrap(),
        Disclosure::element(vec![2u8; 16], 2).unwrap(),
    ];
    set_disclosures(&mut header, &disclosures);
    let limits = ProcessingLimits {
        max_items: 8,
        ..ProcessingLimits::default()
    };
    assert!(disclosures_from_unprotected_with_limits(&header, limits).is_err());
    let limits = ProcessingLimits {
        max_items: 9,
        ..limits
    };
    assert_eq!(
        disclosures_from_unprotected_with_limits(&header, limits)
            .unwrap()
            .len(),
        2
    );
}
