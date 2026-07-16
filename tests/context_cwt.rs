mod common;

use cbor2::Cbor;
use common::*;
use cose2::{
    cwt::{Claims, ClaimsMap, Validator, ValidatorOptions},
    iana, tag, KdfContext, Label, PartyInfo, PartyNonce, Sign1Message, SuppPubInfo, Value,
};

// ----------------------------------------------------------------------------
// KDF context
// ----------------------------------------------------------------------------

#[test]
fn party_info_round_trip() {
    let info = PartyInfo {
        identity: Some(b"id".to_vec()),
        nonce: Some(PartyNonce::Bytes(b"nonce".to_vec())),
        other: None,
    };
    let bytes = cbor2::to_canonical_vec(&info).unwrap();
    // 3-element array.
    assert_eq!(bytes[0], 0x83);
    let back: PartyInfo = cbor2::from_slice(&bytes).unwrap();
    assert_eq!(back, info);
}

#[test]
fn party_info_supports_integer_nonce() {
    // RFC 9053 §5.2: nonce is `bstr / int / nil`.
    let info = PartyInfo {
        identity: None,
        nonce: Some(PartyNonce::Int(-42)),
        other: None,
    };
    let bytes = cbor2::to_canonical_vec(&info).unwrap();
    let back: PartyInfo = cbor2::from_slice(&bytes).unwrap();
    assert_eq!(back, info);

    // A peer-encoded `[null, 7, null]` decodes to an integer nonce.
    let wire = cbor2::to_vec(&(
        Option::<&serde_bytes::Bytes>::None,
        7u64,
        Option::<&serde_bytes::Bytes>::None,
    ))
    .unwrap();
    let back: PartyInfo = cbor2::from_slice(&wire).unwrap();
    assert_eq!(back.nonce, Some(PartyNonce::Int(7)));

    // From conversions.
    assert_eq!(PartyNonce::from(7i64), PartyNonce::Int(7));
    assert_eq!(
        PartyNonce::from(b"n".to_vec()),
        PartyNonce::Bytes(b"n".to_vec())
    );
    assert_eq!(
        PartyNonce::from(&b"n"[..]),
        PartyNonce::Bytes(b"n".to_vec())
    );

    // A non-bstr/int nonce (e.g. bool) is rejected.
    let bad = cbor2::to_vec(&(
        Option::<&serde_bytes::Bytes>::None,
        true,
        Option::<&serde_bytes::Bytes>::None,
    ))
    .unwrap();
    assert!(cbor2::from_slice::<PartyInfo>(&bad).is_err());
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
        algorithm_id: Label::Int(iana::AlgorithmA128GCM),
        party_u_info: PartyInfo {
            identity: Some(b"u".to_vec()),
            ..Default::default()
        },
        party_v_info: PartyInfo {
            nonce: Some(PartyNonce::Bytes(b"v".to_vec())),
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
fn kdf_context_supports_text_algorithm_id() {
    // RFC 9053 §5.2: AlgorithmID is `int / tstr`.
    let ctx = KdfContext {
        algorithm_id: Label::Text("private-alg".into()),
        party_u_info: PartyInfo::default(),
        party_v_info: PartyInfo::default(),
        supp_pub_info: SuppPubInfo {
            key_data_length: 256,
            ..Default::default()
        },
        supp_priv_info: None,
    };
    let bytes = ctx.to_vec().unwrap();
    let back = KdfContext::from_slice(&bytes).unwrap();
    assert_eq!(back, ctx);
    assert_eq!(back.algorithm_id.as_text(), Some("private-alg"));
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
        ..Default::default()
    };
    let bytes = claims.to_vec().unwrap();
    assert_eq!(Claims::TAG, Some(iana::CBORTagCWT));
    assert_eq!(&bytes[..2], tag::CWT_PREFIX);
    // Tagged map keyed by integers 1..=7.
    assert_eq!(bytes[2], 0xa7);
    let untagged = claims.to_untagged_vec().unwrap();
    assert_eq!(untagged.as_slice(), tag::skip_tag(tag::CWT_PREFIX, &bytes));
    assert_eq!(untagged[0], 0xa7);
    let back = Claims::from_slice(&bytes).unwrap();
    assert_eq!(back, claims);

    // The cbor2 tag derive accepts untagged claim maps for compatibility.
    assert_eq!(cbor2::from_slice::<Claims>(&untagged).unwrap(), claims);
    assert_eq!(Claims::from_slice(&untagged).unwrap(), claims);

    let wrong_tagged = tag::with_tag(tag::SIGN1_PREFIX, &untagged);
    assert!(Claims::from_slice(&wrong_tagged).is_err());
}

#[test]
fn claims_omit_absent_fields_and_json() {
    let claims = Claims {
        issuer: Some("iss".into()),
        ..Default::default()
    };
    let bytes = claims.to_vec().unwrap();
    // tagged single-entry map {1: "iss"}
    assert_eq!(&bytes[..2], tag::CWT_PREFIX);
    assert_eq!(bytes[2], 0xa1);

    // JSON keeps the original (renamed) field names — the cbor2 derive leaves
    // serde names intact for other formats.
    // (We don't depend on serde_json here; check the empty-claims default.)
    let empty = Claims::new();
    assert_eq!(empty, Claims::default());
    assert_eq!(empty.to_vec().unwrap(), vec![0xd8, 0x3d, 0xa0]);
    assert_eq!(empty.to_untagged_vec().unwrap(), vec![0xa0]);
}

#[test]
fn claims_preserve_extra_claims() {
    // {1: "iss", 99: "unknown", "private": true}
    let mut map = ClaimsMap::new();
    map.insert(iana::CWTClaimIss, "iss");
    map.insert(99, "unknown");
    map.insert("private", true);
    let bytes = map.to_vec().unwrap();

    let claims = Claims::from_slice(&bytes).unwrap();
    assert_eq!(claims.issuer.as_deref(), Some("iss"));
    assert_eq!(claims.extra.get_text(99).unwrap(), Some("unknown"));
    assert_eq!(claims.extra.get_bool("private").unwrap(), Some(true));

    let direct = cbor2::from_slice::<Claims>(&bytes).unwrap();
    assert_eq!(direct, claims);

    let encoded = claims.to_vec().unwrap();
    assert_eq!(&encoded[..2], tag::CWT_PREFIX);
    assert_eq!(encoded[2], 0xa3);
    let round_trip = Claims::from_slice(&encoded).unwrap();
    assert_eq!(round_trip, claims);

    let canonical = cbor2::to_canonical_vec(&claims).unwrap();
    assert_eq!(canonical, encoded);
    assert_eq!(cbor2::from_slice::<Claims>(&canonical).unwrap(), claims);
}

#[test]
fn claims_accept_integral_float_numeric_dates() {
    // RFC 8392 NumericDate may be a CBOR float; whole-second values decode.
    let mut map = ClaimsMap::new();
    map.insert(iana::CWTClaimExp, Value::Float(1_700_000_300.0));
    map.insert(iana::CWTClaimNbf, Value::Float(1_700_000_000.0));
    map.insert(iana::CWTClaimIat, Value::Float(1_700_000_000.0));
    let bytes = map.to_vec().unwrap();

    let claims = Claims::from_slice(&bytes).unwrap();
    assert_eq!(claims.expiration, Some(1_700_000_300));
    assert_eq!(claims.not_before, Some(1_700_000_000));
    assert_eq!(claims.issued_at, Some(1_700_000_000));

    // validate_map tolerates the float encodings too.
    let v = validator(ValidatorOptions {
        fixed_now: Some(1_700_000_100),
        ..Default::default()
    });
    assert!(v.validate_map(&map).is_ok());
    assert!(v.validate(&claims).is_ok());
}

#[test]
fn claims_reject_fractional_or_pre_epoch_numeric_dates() {
    // Fractional seconds are not representable as whole-second timestamps.
    let mut fractional = ClaimsMap::new();
    fractional.insert(iana::CWTClaimExp, Value::Float(1_700_000_300.5));
    let bytes = fractional.to_vec().unwrap();
    let err = Claims::from_slice(&bytes).unwrap_err();
    assert!(format!("{err}").contains("fractional-second NumericDate"));
    let err = validator(ValidatorOptions::default())
        .validate_map(&fractional)
        .unwrap_err();
    assert!(format!("{err}").contains("fractional-second NumericDate"));

    // Pre-epoch (negative) dates are rejected.
    let mut negative = ClaimsMap::new();
    negative.insert(iana::CWTClaimExp, -5i64);
    let bytes = negative.to_vec().unwrap();
    let err = Claims::from_slice(&bytes).unwrap_err();
    assert!(format!("{err}").contains("pre-epoch NumericDate"));

    // validate_map rejects pre-epoch integers too — including `nbf`, which a
    // plain range check would otherwise accept as "already valid".
    let err = validator(ValidatorOptions::default())
        .validate_map(&negative)
        .unwrap_err();
    assert!(format!("{err}").contains("pre-epoch NumericDate"));
    let mut negative_nbf = ClaimsMap::new();
    negative_nbf.insert(iana::CWTClaimNbf, -5i64);
    let err = validator(ValidatorOptions::default())
        .validate_map(&negative_nbf)
        .unwrap_err();
    assert!(format!("{err}").contains("pre-epoch NumericDate"));

    // Non-numeric dates remain type errors.
    let mut text = ClaimsMap::new();
    text.insert(iana::CWTClaimExp, "soon");
    let bytes = text.to_vec().unwrap();
    assert!(Claims::from_slice(&bytes).is_err());
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
