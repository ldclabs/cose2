mod common;

use common::*;
use cose2::{
    cwt::{Claims, ClaimsMap, Validator, ValidatorOptions},
    iana, KdfContext, PartyInfo, Sign1Message, SuppPubInfo,
};

// ----------------------------------------------------------------------------
// KDF context
// ----------------------------------------------------------------------------

#[test]
fn party_info_round_trip() {
    let info = PartyInfo {
        identity: Some(b"id".to_vec()),
        nonce: Some(b"nonce".to_vec()),
        other: None,
    };
    let bytes = cbor2::to_canonical_vec(&info).unwrap();
    // 3-element array.
    assert_eq!(bytes[0], 0x83);
    let back: PartyInfo = cbor2::from_slice(&bytes).unwrap();
    assert_eq!(back, info);
}

#[test]
fn supp_pub_info_two_and_three_elements() {
    let mut info = SuppPubInfo {
        key_data_length: 128,
        ..Default::default()
    };
    info.protected
        .insert(iana::HeaderParameterAlg, iana::AlgorithmDirect_HKDF_SHA_256);
    let bytes = cbor2::to_canonical_vec(&info).unwrap();
    assert_eq!(bytes[0], 0x82); // 2-element
    let back: SuppPubInfo = cbor2::from_slice(&bytes).unwrap();
    assert_eq!(back, info);

    info.other = Some(b"extra".to_vec());
    let bytes = cbor2::to_canonical_vec(&info).unwrap();
    assert_eq!(bytes[0], 0x83); // 3-element
    let back: SuppPubInfo = cbor2::from_slice(&bytes).unwrap();
    assert_eq!(back, info);
}

#[test]
fn kdf_context_four_and_five_elements() {
    let mut ctx = KdfContext {
        algorithm_id: iana::AlgorithmA128GCM,
        party_u_info: PartyInfo {
            identity: Some(b"u".to_vec()),
            ..Default::default()
        },
        party_v_info: PartyInfo {
            nonce: Some(b"v".to_vec()),
            ..Default::default()
        },
        supp_pub_info: SuppPubInfo {
            key_data_length: 128,
            ..Default::default()
        },
        supp_priv_info: None,
    };

    let bytes = ctx.to_vec().unwrap();
    assert_eq!(bytes[0], 0x84); // 4-element
    let back = KdfContext::from_slice(&bytes).unwrap();
    assert_eq!(back, ctx);

    ctx.supp_priv_info = Some(b"private".to_vec());
    let bytes = ctx.to_vec().unwrap();
    assert_eq!(bytes[0], 0x85); // 5-element
    let back = KdfContext::from_slice(&bytes).unwrap();
    assert_eq!(back, ctx);
}

#[test]
fn kdf_context_decode_errors_on_truncated_arrays() {
    // Empty array → missing AlgorithmID.
    assert!(KdfContext::from_slice(&[0x80]).is_err());
    // SuppPubInfo with only one element.
    assert!(cbor2::from_slice::<SuppPubInfo>(&[0x81, 0x18, 0x80]).is_err());
    // SuppPubInfo empty.
    assert!(cbor2::from_slice::<SuppPubInfo>(&[0x80]).is_err());
}

// ----------------------------------------------------------------------------
// CWT Claims
// ----------------------------------------------------------------------------

#[test]
fn claims_round_trip_integer_keys() {
    let claims = Claims {
        issuer: Some("ldc:ca".into()),
        subject: Some("ldc:chain".into()),
        audience: Some("ldc:txpool".into()),
        expiration: Some(1_700_000_300),
        not_before: Some(1_700_000_000),
        issued_at: Some(1_700_000_000),
        cwt_id: Some(vec![0xa, 0xb, 0xc]),
    };
    let bytes = claims.to_vec().unwrap();
    // Map keyed by integers 1..=7.
    assert_eq!(bytes[0], 0xa7);
    let back = Claims::from_slice(&bytes).unwrap();
    assert_eq!(back, claims);
}

#[test]
fn claims_omit_absent_fields_and_json() {
    let claims = Claims {
        issuer: Some("iss".into()),
        ..Default::default()
    };
    let bytes = claims.to_vec().unwrap();
    // single-entry map {1: "iss"}
    assert_eq!(bytes[0], 0xa1);

    // JSON keeps the original (renamed) field names — the cbor2 derive leaves
    // serde names intact for other formats.
    // (We don't depend on serde_json here; check the empty-claims default.)
    let empty = Claims::new();
    assert_eq!(empty, Claims::default());
    assert!(empty.to_vec().unwrap() == vec![0xa0]);
}

#[test]
fn claims_decode_ignores_unknown_claims() {
    // {1: "iss", 99: "unknown"}
    let mut map = ClaimsMap::new();
    map.insert(iana::CWTClaimIss, "iss");
    map.insert(99, "unknown");
    let bytes = map.to_vec().unwrap();
    let claims = Claims::from_slice(&bytes).unwrap();
    assert_eq!(claims.issuer.as_deref(), Some("iss"));
}

#[test]
fn cwt_in_sign1_round_trip() {
    let signer = MockSigner::new(iana::AlgorithmEdDSA, b"ca");
    let verifier = MockVerifier::new(iana::AlgorithmEdDSA, b"ca");

    let claims = Claims {
        issuer: Some("ldc:ca".into()),
        audience: Some("ldc:txpool".into()),
        expiration: Some(4_000_000_000),
        ..Default::default()
    };
    let mut msg = Sign1Message::new(Some(claims.to_vec().unwrap()));
    let encoded = msg.sign_and_encode(&signer, None).unwrap();

    let verified = Sign1Message::verify_and_decode(&verifier, &encoded, None).unwrap();
    let decoded = Claims::from_slice(verified.payload.as_deref().unwrap()).unwrap();
    assert_eq!(decoded, claims);
}

// ----------------------------------------------------------------------------
// Validator
// ----------------------------------------------------------------------------

fn validator(opts: ValidatorOptions) -> Validator {
    Validator::new(opts).unwrap()
}

#[test]
fn validator_rejects_excessive_clock_skew() {
    let err = Validator::new(ValidatorOptions {
        clock_skew_secs: 60 * 60,
        ..Default::default()
    });
    assert!(err.is_err());
}

#[test]
fn validator_validates_typed_claims() {
    let v = validator(ValidatorOptions {
        expected_issuer: Some("iss".into()),
        expected_audience: Some("aud".into()),
        clock_skew_secs: 60,
        fixed_now: Some(1_000),
        ..Default::default()
    });

    let claims = Claims {
        issuer: Some("iss".into()),
        audience: Some("aud".into()),
        expiration: Some(2_000),
        not_before: Some(500),
        issued_at: Some(500),
        ..Default::default()
    };
    assert!(v.validate(&claims).is_ok());
}

#[test]
fn validator_time_failures() {
    let base = ValidatorOptions {
        clock_skew_secs: 0,
        fixed_now: Some(1_000),
        ..Default::default()
    };

    // Missing expiration.
    assert!(validator(base.clone())
        .validate(&Claims::default())
        .is_err());

    // Allowed when configured.
    let allow = validator(ValidatorOptions {
        allow_missing_expiration: true,
        ..base.clone()
    });
    assert!(allow.validate(&Claims::default()).is_ok());

    // Expired.
    let expired = Claims {
        expiration: Some(500),
        ..Default::default()
    };
    assert!(validator(base.clone()).validate(&expired).is_err());

    // Not yet valid (nbf in the future).
    let future = Claims {
        expiration: Some(2_000),
        not_before: Some(1_500),
        ..Default::default()
    };
    assert!(validator(base.clone()).validate(&future).is_err());

    // iat in the future, when checked.
    let iat_future = Claims {
        expiration: Some(2_000),
        issued_at: Some(1_500),
        ..Default::default()
    };
    let check_iat = validator(ValidatorOptions {
        expect_issued_in_the_past: true,
        ..base.clone()
    });
    assert!(check_iat.validate(&iat_future).is_err());
    // iat in the future but not checked → ok.
    assert!(validator(base.clone()).validate(&iat_future).is_ok());
}

#[test]
fn validator_identity_failures() {
    let base = ValidatorOptions {
        allow_missing_expiration: true,
        fixed_now: Some(1_000),
        ..Default::default()
    };

    let iss = validator(ValidatorOptions {
        expected_issuer: Some("right".into()),
        ..base.clone()
    });
    assert!(iss
        .validate(&Claims {
            issuer: Some("wrong".into()),
            ..Default::default()
        })
        .is_err());

    let aud = validator(ValidatorOptions {
        expected_audience: Some("right".into()),
        ..base.clone()
    });
    assert!(aud
        .validate(&Claims {
            issuer: Some("x".into()),
            audience: Some("wrong".into()),
            ..Default::default()
        })
        .is_err());
}

#[test]
fn validator_validates_claims_map() {
    let v = validator(ValidatorOptions {
        expected_issuer: Some("iss".into()),
        expected_audience: Some("aud".into()),
        expect_issued_in_the_past: true,
        clock_skew_secs: 60,
        fixed_now: Some(1_000),
        ..Default::default()
    });

    let mut map = ClaimsMap::new();
    map.insert(iana::CWTClaimIss, "iss");
    map.insert(iana::CWTClaimAud, "aud");
    map.insert(iana::CWTClaimExp, 2_000i64);
    map.insert(iana::CWTClaimNbf, 500i64);
    map.insert(iana::CWTClaimIat, 500i64);
    assert!(v.validate_map(&map).is_ok());

    // Expired map.
    let mut expired = ClaimsMap::new();
    expired.insert(iana::CWTClaimExp, 100i64);
    assert!(v.validate_map(&expired).is_err());

    // Map with a non-integer exp → propagates the type error.
    let mut bad = ClaimsMap::new();
    bad.insert(iana::CWTClaimExp, "soon");
    assert!(v.validate_map(&bad).is_err());
}

#[test]
fn validator_uses_system_clock_when_now_unset() {
    // No fixed_now → uses the real system clock; a far-future expiry passes.
    let v = validator(ValidatorOptions {
        clock_skew_secs: 0,
        ..Default::default()
    });
    let claims = Claims {
        expiration: Some(u64::MAX), // saturates to i64::MAX → far future
        not_before: Some(0),
        ..Default::default()
    };
    assert!(v.validate(&claims).is_ok());
}
