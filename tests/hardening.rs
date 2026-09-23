mod common;

use cbor2::Value;
use common::{toy_tag, MockSigner, MockVerifier};
use cose2::{
    cwt::{Audience, Claims, ClaimsMap, NumericDate, Validator, ValidatorOptions},
    iana, tag, CoseMap, Header, Key, KeySet, Label, PartyInfo, Recipient, Sign1Message,
    SuppPubInfo, Verifier,
};

#[test]
fn message_decoder_enforces_wire_types_and_semantic_tags() {
    let array_as_payload = cbor2::to_vec(&Value::Array(vec![
        Value::Bytes(vec![]),
        Value::Map(vec![]),
        Value::Array(vec![Value::from(97)]),
        Value::Bytes(vec![]),
    ]))
    .unwrap();
    assert!(Sign1Message::from_slice(&array_as_payload).is_err());

    let tagged_bstr = cbor2::to_vec(&Value::Array(vec![
        Value::Tag(100, Box::new(Value::Bytes(vec![]))),
        Value::Map(vec![]),
        Value::Bytes(vec![]),
        Value::Bytes(vec![]),
    ]))
    .unwrap();
    assert!(Sign1Message::from_slice(&tagged_bstr).is_err());

    let body = [0x84, 0x40, 0xa0, 0x40, 0x40];
    let nonpreferred_tag = [0xd8, 0x12, 0x84, 0x40, 0xa0, 0x40, 0x40];
    assert!(Sign1Message::from_slice(&nonpreferred_tag).is_ok());

    let mut invalid_cwt = tag::CWT_PREFIX.to_vec();
    invalid_cwt.extend_from_slice(&body);
    assert!(Sign1Message::from_slice(&invalid_cwt).is_err());
}

#[test]
fn nested_duplicate_map_keys_are_rejected() {
    // [h'', {100: {1: 1, 1: 2}}, h'', h'']
    let input = [
        0x84, 0x40, 0xa1, 0x18, 0x64, 0xa2, 0x01, 0x01, 0x01, 0x02, 0x40, 0x40,
    ];
    assert!(Sign1Message::from_slice(&input).is_err());
}

#[test]
fn duplicate_map_keys_are_detected_across_encodings_of_one_key() {
    // {1: 1, 1: 2}, the second key with a non-preferred argument.
    assert!(CoseMap::from_slice(&[0xa2, 0x01, 0x01, 0x18, 0x01, 0x02]).is_err());
    // {"a": 1, (_ "a"): 2}
    let indefinite_text = [0xa2, 0x61, b'a', 0x01, 0x7f, 0x61, b'a', 0xff, 0x02];
    assert!(CoseMap::from_slice(&indefinite_text).is_err());
    // {h'00': 1, h'00': 2}, the second length with a non-preferred argument.
    assert!(CoseMap::from_slice(&[0xa2, 0x41, 0x00, 0x01, 0x58, 0x01, 0x00, 0x02]).is_err());
    // A text key that is not valid UTF-8 is still rejected.
    assert!(CoseMap::from_slice(&[0xa1, 0x61, 0xff, 0x01]).is_err());
    // Distinct keys sharing an encoding prefix remain distinct: {1: 1, 24: 2}.
    assert_eq!(
        CoseMap::from_slice(&[0xa2, 0x01, 0x01, 0x18, 0x18, 0x02])
            .unwrap()
            .len(),
        2
    );

    // Message decoding reads header maps after one strict pass over the
    // message, which must still reject a duplicate unprotected key:
    // [h'', {4: h'01', 4: h'02'}, h'', h'']
    let input = [
        0x84, 0x40, 0xa2, 0x04, 0x41, 0x01, 0x04, 0x41, 0x02, 0x40, 0x40,
    ];
    assert!(Sign1Message::from_slice(&input).is_err());
}

#[test]
fn map_encoding_matches_cbor2_deterministic_encoding() {
    let mut map = CoseMap::new();
    for key in [
        0i64,
        1,
        23,
        24,
        100,
        255,
        256,
        65_536,
        -1,
        -24,
        -25,
        -256,
        -257,
        i64::MIN,
        i64::MAX,
    ] {
        map.insert(key, key);
    }
    map.insert(
        "z",
        Value::Map(vec![
            (Value::from("bb"), Value::from(1)),
            (Value::from("a"), Value::Float(f64::NAN)),
        ]),
    );
    map.insert(
        "aa",
        Value::Array(vec![
            Value::Tag(2, Box::new(Value::Bytes(vec![0, 0, 1]))),
            Value::Float(-0.0),
            Value::Float(1.5),
            Value::Float(1e300),
        ]),
    );
    map.insert(
        "",
        Value::Tag(
            1,
            Box::new(Value::Map(vec![
                (Value::from(2), Value::Null),
                (Value::from(1), Value::Bool(true)),
            ])),
        ),
    );
    map.insert("nan", Value::Float(f64::NAN));
    map.insert("bytes", vec![7u8; 300]);
    map.insert("text", "t".repeat(70_000));

    assert_eq!(
        map.to_vec().unwrap(),
        cbor2::to_canonical_vec(&map).unwrap()
    );
    assert_eq!(
        CoseMap::new().to_vec().unwrap(),
        cbor2::to_canonical_vec(&CoseMap::new()).unwrap()
    );
}

#[test]
fn kdf_structures_do_not_coerce_integer_arrays_to_bytes() {
    let party = cbor2::to_vec(&Value::Array(vec![
        Value::Array(vec![Value::from(1)]),
        Value::Null,
        Value::Null,
    ]))
    .unwrap();
    assert!(cbor2::from_slice::<PartyInfo>(&party).is_err());

    let supplemental =
        cbor2::to_vec(&Value::Array(vec![Value::from(128), Value::Array(vec![])])).unwrap();
    assert!(cbor2::from_slice::<SuppPubInfo>(&supplemental).is_err());
}

#[test]
fn changing_protected_header_invalidates_authenticated_state() {
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"key");
    let verifier = MockVerifier::new(iana::AlgorithmEdDSA, b"key");
    let mut message = Sign1Message::new(Some(b"payload".to_vec()));
    message.protected.insert("scope", "read");
    message.sign(&signer, None).unwrap();
    message.protected.insert("scope", "admin");
    assert!(message.verify(&verifier, None).is_err());
    assert!(message.to_vec().is_err());

    let mut nan = Sign1Message::new(Some(b"payload".to_vec()));
    nan.protected.insert("number", Value::Float(f64::NAN));
    let encoded = nan.sign_and_encode(&signer, None).unwrap();
    assert!(Sign1Message::verify_and_decode(&verifier, &encoded, None).is_ok());

    let mut negative_zero = Sign1Message::new(Some(b"payload".to_vec()));
    negative_zero.protected.insert("number", Value::Float(-0.0));
    let encoded = negative_zero.sign_and_encode(&signer, None).unwrap();
    let mut decoded = Sign1Message::from_slice(&encoded).unwrap();
    decoded.protected.insert("number", Value::Float(0.0));
    assert!(matches!(
        decoded.verify(&verifier, None),
        Err(cose2::Error::InvalidState(_))
    ));
}

#[test]
fn algorithm_resolution_checks_unprotected_and_kid_uses_both_buckets() {
    let payload = b"payload";
    let mut unprotected = Header::new();
    unprotected.set_alg(iana::AlgorithmES256);
    let tbs = Sign1Message::to_be_signed(&[], b"", payload).unwrap();
    let signature = toy_tag(b"signer-secret", &tbs);
    let body = cbor2::to_vec(&(
        serde_bytes::Bytes::new(&[]),
        unprotected,
        serde_bytes::Bytes::new(payload),
        serde_bytes::Bytes::new(&signature),
    ))
    .unwrap();
    let verifier = MockVerifier::new(iana::AlgorithmEdDSA, b"");
    assert!(Sign1Message::verify_and_decode(&verifier, &body, None).is_err());

    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"key");
    let mut message = Sign1Message::new(Some(payload.to_vec()));
    message.protected.set_kid(b"key".to_vec());
    message.sign(&signer, None).unwrap();
    assert!(message.unprotected.kid().unwrap().is_none());
}

struct PrivateCritVerifier(MockVerifier);

impl Verifier for PrivateCritVerifier {
    fn alg(&self) -> Option<Label> {
        Verifier::alg(&self.0)
    }

    fn kid(&self) -> Option<&[u8]> {
        Verifier::kid(&self.0)
    }

    fn understood_critical_headers(&self) -> &[Label] {
        static UNDERSTOOD: std::sync::OnceLock<Vec<Label>> = std::sync::OnceLock::new();
        UNDERSTOOD.get_or_init(|| vec![Label::Text("private".into())])
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), cose2::Error> {
        self.0.verify(data, signature)
    }
}

#[test]
fn high_level_verification_enforces_critical_headers() {
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"key");
    let mut message = Sign1Message::new(Some(b"payload".to_vec()));
    message.protected.insert("private", true);
    message.protected.set_crit(["private"]);
    let encoded = message.sign_and_encode(&signer, None).unwrap();

    let default = MockVerifier::new(iana::AlgorithmEdDSA, b"key");
    assert!(Sign1Message::verify_and_decode(&default, &encoded, None).is_err());

    let aware = PrivateCritVerifier(MockVerifier::new(iana::AlgorithmEdDSA, b"key"));
    assert!(Sign1Message::verify_and_decode(&aware, &encoded, None).is_ok());
}

#[test]
fn claims_keep_text_keys_distinct_and_support_full_value_domain() {
    let mut map = ClaimsMap::new();
    map.insert("exp", 2_000);
    map.insert(iana::CWTClaimAud, vec![Value::from("a"), Value::from("b")]);
    map.insert(iana::CWTClaimExp, Value::Float(2_000.5));
    map.insert(iana::CWTClaimNbf, -5);
    let claims = Claims::from_slice(&map.to_vec().unwrap()).unwrap();
    assert_eq!(claims.expiration, Some(NumericDate::Float(2_000.5)));
    assert_eq!(claims.not_before, Some(NumericDate::from(-5i64)));
    assert_eq!(
        claims.audience,
        Some(Audience::Many(vec!["a".into(), "b".into()]))
    );
    assert_eq!(claims.extra.get_i64("exp").unwrap(), Some(2_000));

    let encoded = claims.to_vec().unwrap();
    assert_eq!(encoded[0] >> 5, 5);
    assert!(Claims::from_slice(&claims.to_legacy_tagged_vec().unwrap()).is_err());
    assert!(Claims::from_slice_legacy_tagged(&claims.to_legacy_tagged_vec().unwrap()).is_ok());
}

#[test]
fn cwt_wrapper_is_outside_the_cose_message() {
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"key");
    let mut message = Sign1Message::new(Some(Claims::new().to_vec().unwrap()));
    message.sign(&signer, None).unwrap();
    let cwt = message.to_cwt_vec().unwrap();
    assert!(cwt.starts_with(tag::CWT_PREFIX));
    assert_eq!(cwt[tag::CWT_PREFIX.len()], tag::SIGN1_PREFIX[0]);
}

#[test]
fn streaming_message_encoding_remains_canonical() {
    let mut message = Sign1Message::new(Some(vec![7u8; 64 * 1024]));
    message.unprotected.insert(-1, "negative");
    message.unprotected.insert(1, "positive");
    message.unprotected.insert("text", true);
    message.set_signature(vec![9u8; 64]).unwrap();

    for encoded in [message.to_vec().unwrap(), message.to_cwt_vec().unwrap()] {
        let value: Value = cbor2::from_slice(&encoded).unwrap();
        assert_eq!(encoded, cbor2::to_canonical_vec(&value).unwrap());
    }
}

#[test]
fn content_type_rejects_out_of_range_integer() {
    let mut map = CoseMap::new();
    map.insert(iana::HeaderParameterContentType, -1);
    assert!(Header::from_slice(&map.to_vec().unwrap()).is_err());

    map.insert(iana::HeaderParameterContentType, 65_536u64);
    assert!(Header::from_slice(&map.to_vec().unwrap()).is_err());

    let mut protected = Header::new();
    protected.set_iv(vec![1u8; 12]);
    let mut unprotected = Header::new();
    unprotected.set_partial_iv(vec![1]);
    let body = cbor2::to_vec(&(
        serde_bytes::Bytes::new(&protected.to_vec().unwrap()),
        unprotected,
        Some(serde_bytes::Bytes::new(b"ciphertext")),
    ))
    .unwrap();
    let encoded = tag::with_tag(tag::ENCRYPT0_PREFIX, &body);
    assert!(cose2::Encrypt0Message::from_slice(&encoded).is_err());
}

#[test]
fn validator_extreme_clock_does_not_overflow() {
    let validator = Validator::new(ValidatorOptions {
        fixed_now: Some(i64::MIN),
        clock_skew_secs: 1,
        ..Default::default()
    })
    .unwrap();
    let claims = Claims {
        expiration: Some(NumericDate::from(2_000i64)),
        ..Default::default()
    };
    assert!(validator.validate(&claims).is_ok());
}

#[test]
fn keyset_processes_entries_independently() {
    let mut valid = Key::new();
    valid.set_kty(iana::KeyTypeSymmetric);
    let valid: Value = cbor2::from_slice(&valid.to_vec().unwrap()).unwrap();
    let encoded = cbor2::to_vec(&Value::Array(vec![Value::Map(vec![]), valid])).unwrap();
    assert_eq!(KeySet::from_slice(&encoded).unwrap().len(), 1);
    assert!(KeySet::from_slice_strict(&encoded).is_err());
}

#[test]
fn recipient_enforces_algorithm_specific_shape_and_preserves_raw_header() {
    let raw_protected = [0xa1, 0x18, 0x01, 0x29]; // nonpreferred {1: -10}
    let mut unprotected = Header::new();
    unprotected.insert(iana::HeaderAlgorithmParameterSalt, vec![7u8; 32]);
    let encoded = cbor2::to_vec(&(
        serde_bytes::Bytes::new(&raw_protected),
        unprotected,
        serde_bytes::Bytes::new(&[]),
    ))
    .unwrap();
    let recipient = Recipient::from_slice(&encoded).unwrap();
    assert_eq!(recipient.protected_raw(), Some(raw_protected.as_slice()));
    assert_eq!(recipient.to_vec().unwrap(), encoded);

    let direct_with_encoded_empty_map = [0x83, 0x41, 0xa0, 0xa1, 0x01, 0x25, 0x40];
    let recipient = Recipient::from_slice(&direct_with_encoded_empty_map).unwrap();
    assert!(recipient.protected.is_empty());
    assert_eq!(recipient.to_vec().unwrap(), direct_with_encoded_empty_map);

    let mut direct_kdf = Recipient::new();
    direct_kdf
        .unprotected
        .set_alg(iana::AlgorithmDirect_HKDF_SHA_256);
    direct_kdf.ciphertext = Some(vec![]);
    assert!(direct_kdf.validate().is_err());

    let mut public_key = Key::new();
    public_key.set_kty(iana::KeyTypeEC2);
    public_key.insert(iana::EC2KeyParameterCrv, iana::EllipticCurveP_256);
    public_key.insert(iana::EC2KeyParameterX, vec![1u8; 32]);
    public_key.insert(iana::EC2KeyParameterY, vec![2u8; 32]);
    let mut ecdh = Recipient::new();
    ecdh.protected.set_alg(iana::AlgorithmECDH_ES_HKDF_256);
    ecdh.unprotected.insert(
        iana::HeaderAlgorithmParameterEphemeralKey,
        cbor2::from_slice::<Value>(&public_key.to_vec().unwrap()).unwrap(),
    );
    ecdh.ciphertext = Some(vec![]);
    assert!(ecdh.validate().is_ok());

    public_key.insert(iana::EC2KeyParameterD, vec![3u8; 32]);
    ecdh.unprotected.insert(
        iana::HeaderAlgorithmParameterEphemeralKey,
        cbor2::from_slice::<Value>(&public_key.to_vec().unwrap()).unwrap(),
    );
    assert!(ecdh.validate().is_err());

    let mut nested = Recipient::new();
    nested.unprotected.set_alg(iana::AlgorithmA128KW);
    nested.ciphertext = Some(vec![1]);
    for _ in 0..130 {
        let mut parent = Recipient::new();
        parent.unprotected.set_alg(iana::AlgorithmA128KW);
        parent.ciphertext = Some(vec![1]);
        parent.recipients.push(nested);
        nested = parent;
    }
    assert!(matches!(
        nested.validate(),
        Err(cose2::Error::LimitExceeded { .. })
    ));
}

#[cfg(feature = "crypto-ring")]
#[test]
fn ring_providers_enforce_key_ops_and_fully_specified_algorithms() {
    use cose2::{
        crypto::{RingEncryptor, RingMacer, RingSigner, RingVerifier},
        Encryptor, Macer,
    };

    let mut key = Key::new();
    key.set_kty(iana::KeyTypeSymmetric)
        .set_alg(iana::AlgorithmHMAC_256_256)
        .set_ops([iana::KeyOperationMacVerify]);
    key.insert(iana::SymmetricKeyParameterK, vec![3u8; 32]);
    let restricted = RingMacer::from_cose_key(&key).unwrap();
    assert!(restricted.mac_create(b"message").is_err());

    let unrestricted = RingMacer::new(iana::AlgorithmHMAC_256_256, &[3u8; 32], None).unwrap();
    let tag = unrestricted.mac_create(b"message").unwrap();
    assert!(restricted.mac_verify(b"message", &tag).is_ok());

    let mut signing_key = Key::new();
    signing_key
        .set_kty(iana::KeyTypeOKP)
        .set_ops([iana::KeyOperationVerify]);
    assert!(matches!(
        RingSigner::from_cose_key(&signing_key),
        Err(cose2::Error::KeyOperation(_))
    ));
    signing_key.set_ops([iana::KeyOperationSign]);
    assert!(matches!(
        RingVerifier::from_cose_key(&signing_key),
        Err(cose2::Error::KeyOperation(_))
    ));

    let mut encryption_key = Key::new();
    encryption_key
        .set_kty(iana::KeyTypeSymmetric)
        .set_alg(iana::AlgorithmA128GCM)
        .set_ops([iana::KeyOperationDecrypt]);
    encryption_key.insert(iana::SymmetricKeyParameterK, vec![4u8; 16]);
    let decrypt_only = RingEncryptor::from_cose_key(&encryption_key).unwrap();
    assert!(decrypt_only.encrypt(&[1u8; 12], b"payload", b"").is_err());
    let unrestricted = RingEncryptor::new(iana::AlgorithmA128GCM, &[4u8; 16], None).unwrap();
    let ciphertext = unrestricted.encrypt(&[1u8; 12], b"payload", b"").unwrap();
    assert_eq!(
        decrypt_only.decrypt(&[1u8; 12], &ciphertext, b"").unwrap(),
        b"payload"
    );
    encryption_key.set_ops([iana::KeyOperationWrapKey]);
    assert!(RingEncryptor::from_cose_key(&encryption_key).is_err());

    let verifier = RingVerifier::ed25519(&[0u8; 32], None).unwrap();
    assert_eq!(verifier.algorithm(), iana::AlgorithmEd25519);
    assert!(RingVerifier::ecdsa(iana::AlgorithmESP256, &[0x04; 65], None).is_ok());
}

#[cfg(feature = "crypto-ed25519-dalek")]
#[test]
fn dalek_rejects_mismatched_private_and_public_key() {
    use cose2::ed25519::{Ed25519Signer, Ed25519Verifier};

    let signer = Ed25519Signer::from_secret_key(&[7u8; 32], None).unwrap();
    let other = Ed25519Signer::from_secret_key(&[8u8; 32], None).unwrap();
    let mut key = signer.to_cose_key().unwrap();
    key.set_ops([iana::KeyOperationSign]);
    key.insert(iana::OKPKeyParameterD, vec![7u8; 32]);
    key.insert(iana::OKPKeyParameterX, other.public_key().to_vec());
    assert!(Ed25519Signer::from_cose_key(&key).is_err());
    assert_eq!(signer.algorithm(), iana::AlgorithmEd25519);

    let mut public = signer.to_cose_key().unwrap();
    public.set_ops([iana::KeyOperationSign]);
    assert!(matches!(
        Ed25519Verifier::from_cose_key(&public),
        Err(cose2::Error::KeyOperation(_))
    ));
}

#[cfg(feature = "crypto-aes-gcm")]
#[test]
fn aes_gcm_provider_enforces_directional_key_ops() {
    use cose2::{aes_gcm::AesGcmEncryptor, Encryptor};

    let mut key = Key::new();
    key.set_kty(iana::KeyTypeSymmetric)
        .set_alg(iana::AlgorithmA128GCM)
        .set_ops([iana::KeyOperationEncrypt]);
    key.insert(iana::SymmetricKeyParameterK, vec![3u8; 16]);
    let encryptor = AesGcmEncryptor::from_cose_key(&key).unwrap();
    let ciphertext = encryptor.encrypt(&[1u8; 12], b"payload", b"").unwrap();
    assert!(encryptor.decrypt(&[1u8; 12], &ciphertext, b"").is_err());

    key.set_ops([iana::KeyOperationWrapKey]);
    assert!(AesGcmEncryptor::from_cose_key(&key).is_err());
}
