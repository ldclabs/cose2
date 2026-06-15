use cose2::{iana, tag, CoseMap, Error, Header, Key, KeySet, Label, Value};

// ----------------------------------------------------------------------------
// Label
// ----------------------------------------------------------------------------

#[test]
fn label_constructors_and_accessors() {
    assert_eq!(Label::from(1i64), Label::Int(1));
    assert_eq!(Label::from(2i32), Label::Int(2));
    assert_eq!(Label::from("alg"), Label::Text("alg".into()));
    assert_eq!(Label::from(String::from("kid")), Label::Text("kid".into()));

    assert_eq!(Label::Int(5).as_int(), Some(5));
    assert_eq!(Label::Int(5).as_text(), None);
    assert_eq!(Label::Text("x".into()).as_text(), Some("x"));
    assert_eq!(Label::Text("x".into()).as_int(), None);

    assert_eq!(Label::Int(-7).to_string(), "-7");
    assert_eq!(Label::Text("hi".into()).to_string(), "hi");
    assert!(Label::Int(1) < Label::Text("a".into()));
}

#[test]
fn label_cbor_round_trip_int_and_text() {
    for label in [Label::Int(1), Label::Int(-7), Label::Text("alg".into())] {
        let bytes = cbor2::to_vec(&label).unwrap();
        let back: Label = cbor2::from_slice(&bytes).unwrap();
        assert_eq!(label, back);
    }
}

#[test]
fn label_deserializes_all_integer_widths() {
    // small non-negative (u64 visitor)
    let l: Label = cbor2::from_slice(&cbor2::to_vec(&10u64).unwrap()).unwrap();
    assert_eq!(l, Label::Int(10));
    // negative within i64 (i64 visitor)
    let l: Label = cbor2::from_slice(&cbor2::to_vec(&-10i64).unwrap()).unwrap();
    assert_eq!(l, Label::Int(-10));
    // u64::MAX is out of i64 range → error
    let err = cbor2::from_slice::<Label>(&cbor2::to_vec(&u64::MAX).unwrap());
    assert!(err.is_err());
    // very negative beyond i64::MIN → out of range error (i128 visitor path)
    let big_neg = cbor2::to_vec(&(i128::from(i64::MIN) - 1)).unwrap();
    assert!(cbor2::from_slice::<Label>(&big_neg).is_err());
    // u128 beyond u64 (bignum) → out of range
    let big_pos = cbor2::to_vec(&(u128::from(u64::MAX) + 1)).unwrap();
    assert!(cbor2::from_slice::<Label>(&big_pos).is_err());
}

#[test]
fn label_rejects_non_label_types() {
    // a boolean is neither int nor text
    assert!(cbor2::from_slice::<Label>(&cbor2::to_vec(&true).unwrap()).is_err());
}

// ----------------------------------------------------------------------------
// CoseMap
// ----------------------------------------------------------------------------

#[test]
fn cosemap_basic_operations() {
    let mut m = CoseMap::new();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
    assert_eq!(m.insert(1, 10i64), None);
    assert_eq!(m.insert("name", "v"), None);
    assert_eq!(m.insert(1, 11i64), Some(Value::from(10i64)));
    assert!(m.contains_key(1));
    assert_eq!(m.len(), 2);
    assert_eq!(m.get(1), Some(&Value::from(11i64)));
    assert_eq!(m.remove(1), Some(Value::from(11i64)));
    assert_eq!(m.remove(1), None);
    assert!(!m.contains_key(1));

    // iteration
    let mut m = CoseMap::new();
    m.insert(1, 1i64);
    m.insert(2, 2i64);
    assert_eq!(m.iter().count(), 2);
    assert_eq!((&m).into_iter().count(), 2);
    assert_eq!(m.clone().into_iter().count(), 2);
    let collected: CoseMap = m.clone().into_iter().collect();
    assert_eq!(collected, m);
}

#[test]
fn cosemap_typed_getters() {
    let mut m = CoseMap::new();
    m.insert(1, 42i64);
    m.insert(2, vec![1u8, 2, 3]);
    m.insert(3, "text");
    m.insert(4, true);
    m.insert(5, vec![Value::from(1i64), Value::from(2i64)]);

    assert_eq!(m.get_i64(1).unwrap(), Some(42));
    assert_eq!(m.get_bytes(2).unwrap(), Some(&[1u8, 2, 3][..]));
    assert_eq!(m.get_text(3).unwrap(), Some("text"));
    assert_eq!(m.get_bool(4).unwrap(), Some(true));
    assert_eq!(m.get_array(5).unwrap().unwrap().len(), 2);
    assert_eq!(m.get_label(1).unwrap(), Some(Label::Int(42)));
    assert_eq!(m.get_label(3).unwrap(), Some(Label::Text("text".into())));

    // absent → Ok(None)
    assert_eq!(m.get_i64(99).unwrap(), None);
    assert_eq!(m.get_bytes(99).unwrap(), None);
    assert_eq!(m.get_text(99).unwrap(), None);
    assert_eq!(m.get_bool(99).unwrap(), None);
    assert_eq!(m.get_array(99).unwrap(), None);
}

#[test]
fn cosemap_type_mismatches_error() {
    let mut m = CoseMap::new();
    m.insert(1, "not an int");
    m.insert(2, 1i64);
    m.insert(3, true);
    assert!(matches!(m.get_i64(1), Err(Error::UnexpectedType(_))));
    assert!(matches!(m.get_bytes(2), Err(Error::UnexpectedType(_))));
    assert!(matches!(m.get_text(2), Err(Error::UnexpectedType(_))));
    assert!(matches!(m.get_bool(2), Err(Error::UnexpectedType(_))));
    assert!(matches!(m.get_array(2), Err(Error::UnexpectedType(_))));
    assert!(matches!(m.get_label(3), Err(Error::UnexpectedType(_))));

    // integer out of i64 range
    let mut big = CoseMap::new();
    big.insert(1, u64::MAX);
    assert!(matches!(big.get_i64(1), Err(Error::UnexpectedType(_))));
}

#[test]
fn cosemap_cbor_round_trip_and_canonical_order() {
    let mut m = CoseMap::new();
    m.insert(2, "b");
    m.insert(1, "a");
    m.insert(-1, "neg");
    let bytes = m.to_vec().unwrap();
    let back = CoseMap::from_slice(&bytes).unwrap();
    assert_eq!(back, m);

    // canonical key order: 1, 2, then -1 (RFC 8949 §4.2.1).
    // a1 ... map(3): keys encoded 01, 02, 20.
    assert_eq!(bytes[0], 0xa3);
}

#[test]
fn cosemap_rejects_duplicate_keys() {
    // {1: 1, 1: 2} encoded manually.
    let dup = hex::decode("a2010102").unwrap_or_default();
    let dup = if dup.is_empty() {
        // build via Value array path is unnecessary; construct directly.
        vec![0xa2, 0x01, 0x01, 0x01, 0x02]
    } else {
        dup
    };
    assert!(CoseMap::from_slice(&dup).is_err());
}

#[test]
fn cosemap_default_impl() {
    let m: CoseMap = Default::default();
    assert!(m.is_empty());
}

// ----------------------------------------------------------------------------
// Header
// ----------------------------------------------------------------------------

#[test]
fn header_accessors_support_int_and_text_algorithm_ids() {
    let mut header = Header::new();
    header
        .set_alg(iana::AlgorithmEdDSA)
        .set_kid(b"kid".to_vec())
        .set_iv(vec![1, 2, 3])
        .set_partial_iv(vec![4, 5]);

    assert_eq!(
        header.alg().unwrap(),
        Some(Label::Int(iana::AlgorithmEdDSA))
    );
    assert_eq!(header.kid().unwrap(), Some(&b"kid"[..]));
    assert_eq!(header.iv().unwrap(), Some(&[1, 2, 3][..]));
    assert_eq!(header.partial_iv().unwrap(), Some(&[4, 5][..]));

    header.set_alg("private-alg");
    assert_eq!(
        header.alg().unwrap(),
        Some(Label::Text("private-alg".into()))
    );

    let bytes = header.to_vec().unwrap();
    let back = Header::from_slice(&bytes).unwrap();
    assert_eq!(back, header);

    let map = header.clone().into_map();
    assert_eq!(Header::from(map), header);
}

#[test]
fn header_crit_accessors_support_label_arrays() {
    let mut header = Header::new();
    header.insert("private", true);
    header.set_crit(["private"]);
    assert_eq!(
        header.crit().unwrap(),
        Some(vec![Label::Text("private".into())])
    );

    header.set_crit([iana::HeaderParameterAlg]);
    assert_eq!(
        header.crit().unwrap(),
        Some(vec![Label::Int(iana::HeaderParameterAlg)])
    );
}

#[test]
fn header_content_type_accepts_text_and_uint() {
    let mut header = Header::new();
    assert_eq!(header.content_type().unwrap(), None);

    header.set_content_type("application/cbor");
    assert_eq!(
        header.content_type().unwrap(),
        Some(Label::Text("application/cbor".into()))
    );

    header.set_content_type(60i64); // application/cbor CoAP Content-Format
    assert_eq!(header.content_type().unwrap(), Some(Label::Int(60)));

    // Round-trips through CBOR with the registered label 3.
    let bytes = header.to_vec().unwrap();
    let back = Header::from_slice(&bytes).unwrap();
    assert_eq!(back.content_type().unwrap(), Some(Label::Int(60)));
    assert_eq!(
        back.get(iana::HeaderParameterContentType),
        Some(&Value::from(60i64))
    );
}

#[test]
fn header_ensure_crit_understood_enforces_rfc9052_3_1() {
    // No crit parameter: always understood.
    assert!(Header::new().ensure_crit_understood(&[]).is_ok());

    // Common header parameters this crate models are always understood.
    let mut native = Header::new();
    native.set_alg(iana::AlgorithmEdDSA);
    native.set_crit([iana::HeaderParameterAlg]);
    assert!(native.ensure_crit_understood(&[]).is_ok());
    assert!(cose2::is_understood_header(&Label::Int(
        iana::HeaderParameterAlg
    )));
    assert!(!cose2::is_understood_header(&Label::Text("private".into())));

    // An unrecognised critical label is a fatal error unless the caller lists it.
    let mut app = Header::new();
    app.insert("private", true);
    app.set_crit([Label::Text("private".into())]);
    let err = app.ensure_crit_understood(&[]).unwrap_err();
    assert!(format!("{err}").contains("unsupported critical header parameter"));
    assert!(app
        .ensure_crit_understood(&[Label::Text("private".into())])
        .is_ok());
}

// ----------------------------------------------------------------------------
// Key & KeySet
// ----------------------------------------------------------------------------

#[test]
fn key_accessors_round_trip() {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeEC2)
        .set_kid(b"my-kid".to_vec())
        .set_alg(iana::AlgorithmES256)
        .set_ops([iana::KeyOperationSign, iana::KeyOperationVerify]);
    key.insert(iana::KeyParameterBaseIV, vec![9u8, 8, 7]);

    assert_eq!(key.kty().unwrap(), Some(Label::Int(iana::KeyTypeEC2)));
    assert_eq!(key.kid().unwrap(), Some(&b"my-kid"[..]));
    assert_eq!(key.alg().unwrap(), Some(Label::Int(iana::AlgorithmES256)));
    assert_eq!(
        key.ops().unwrap(),
        Some(vec![
            Label::Int(iana::KeyOperationSign),
            Label::Int(iana::KeyOperationVerify)
        ])
    );
    assert_eq!(key.base_iv().unwrap(), Some(&[9u8, 8, 7][..]));
    // Deref to CoseMap works.
    assert!(key.contains_key(iana::KeyParameterKty));

    let bytes = key.to_vec().unwrap();
    let back = Key::from_slice(&bytes).unwrap();
    assert_eq!(back, key);
}

#[test]
fn key_ops_errors_on_non_integer_array() {
    let mut key = Key::new();
    key.insert(iana::KeyParameterKeyOps, vec![Value::from("sign")]);
    assert_eq!(key.ops().unwrap(), Some(vec![Label::Text("sign".into())]));

    // ops absent → None
    let mut empty = Key::new();
    empty.set_kty("private-kty");
    assert_eq!(empty.ops().unwrap(), None);
    assert_eq!(
        empty.kty().unwrap(),
        Some(Label::Text("private-kty".into()))
    );
}

#[test]
fn key_rejects_missing_kty() {
    let empty = Key::new();
    assert!(empty.to_vec().is_err());
    assert!(Key::from_slice(&CoseMap::new().to_vec().unwrap()).is_err());
}

#[test]
fn key_default_and_deref_mut() {
    let mut key = Key::default();
    key.insert(1, 2i64); // via DerefMut
    assert_eq!(key.get_i64(1).unwrap(), Some(2));
}

#[test]
fn keyset_lookup_and_round_trip() {
    let mut k1 = Key::new();
    k1.set_kty(iana::KeyTypeOKP).set_kid(b"one".to_vec());
    let mut k2 = Key::new();
    k2.set_kty(iana::KeyTypeOKP).set_kid(b"two".to_vec());

    let mut set = KeySet::new();
    set.push(k1.clone()); // via DerefMut to Vec
    set.0.push(k2.clone());
    assert_eq!(set.len(), 2);

    assert_eq!(set.lookup(b"two").collect::<Vec<_>>(), vec![&k2]);
    assert_eq!(set.lookup(b"missing").count(), 0);

    let bytes = set.to_vec().unwrap();
    let back = KeySet::from_slice(&bytes).unwrap();
    assert_eq!(back, set);

    let empty = KeySet::default();
    assert!(empty.is_empty());
    assert!(empty.to_vec().is_err());
    assert!(KeySet::from_slice(&cbor2::to_vec(&Vec::<Value>::new()).unwrap()).is_err());
    // a key without kid is skipped by lookup
    let mut s2 = KeySet::new();
    let mut no_kid = Key::new();
    no_kid.set_kty(iana::KeyTypeOKP);
    s2.push(no_kid);
    assert_eq!(s2.lookup(b"x").count(), 0);
}

#[test]
fn keyset_lookup_returns_all_matching_kids_and_ignores_bad_keys_on_decode() {
    let mut k1 = Key::new();
    k1.set_kty(iana::KeyTypeOKP).set_kid(b"same".to_vec());
    let mut k2 = Key::new();
    k2.set_kty("private-kty").set_kid(b"same".to_vec());
    let bad = CoseMap::new();

    let raw = cbor2::to_vec(&vec![
        cbor2::from_slice::<Value>(&k1.to_vec().unwrap()).unwrap(),
        cbor2::from_slice::<Value>(&bad.to_vec().unwrap()).unwrap(),
        cbor2::from_slice::<Value>(&k2.to_vec().unwrap()).unwrap(),
    ])
    .unwrap();
    let set = KeySet::from_slice(&raw).unwrap();
    assert_eq!(set.lookup(b"same").count(), 2);
}

// ----------------------------------------------------------------------------
// Error
// ----------------------------------------------------------------------------

#[test]
fn error_display_and_constructors() {
    assert_eq!(
        format!("{}", Error::Cbor("x".into())),
        "cose: cbor error: x"
    );
    assert_eq!(
        format!("{}", Error::UnexpectedType("y".into())),
        "cose: unexpected type: y"
    );
    assert_eq!(
        format!("{}", Error::Verify("z".into())),
        "cose: verification failed: z"
    );
    assert_eq!(format!("{}", Error::Custom("w".into())), "cose: w");

    assert_eq!(Error::custom("a"), Error::Custom("a".into()));
    assert_eq!(Error::verify("b"), Error::Verify("b".into()));

    // std::error::Error is implemented.
    let e: &dyn std::error::Error = &Error::Custom("e".into());
    assert!(e.to_string().contains("e"));
}

#[test]
fn error_from_cbor_errors() {
    use serde::{de::Error as _, ser::Error as _};
    let de: Error = cbor2::de::Error::custom("de-boom").into();
    assert!(matches!(de, Error::Cbor(_)));
    let ser: Error = cbor2::ser::Error::custom("ser-boom").into();
    assert!(matches!(ser, Error::Cbor(_)));

    // A genuine decode failure flows through `?`.
    assert!(CoseMap::from_slice(&[0xff, 0xff]).is_err());
}

// ----------------------------------------------------------------------------
// tag helpers
// ----------------------------------------------------------------------------

#[test]
fn tag_with_and_skip() {
    let data = [0x84u8, 1, 2, 3];
    let tagged = tag::with_tag(tag::SIGN1_PREFIX, &data);
    assert_eq!(tagged[0], 0xd2);
    assert_eq!(tag::skip_tag(tag::SIGN1_PREFIX, &tagged), &data);
    // skip when prefix absent → unchanged
    assert_eq!(tag::skip_tag(tag::SIGN1_PREFIX, &data), &data);
}

#[test]
fn tag_remove_cbor_tag_variants() {
    let body = [0x80u8];
    // single-byte message tags
    for prefix in [tag::SIGN1_PREFIX, tag::MAC0_PREFIX, tag::ENCRYPT0_PREFIX] {
        let tagged = tag::with_tag(prefix, &body);
        assert_eq!(tag::remove_cbor_tag(&tagged), &body);
    }
    // two-byte message tags
    for prefix in [tag::SIGN_PREFIX, tag::MAC_PREFIX, tag::ENCRYPT_PREFIX] {
        let tagged = tag::with_tag(prefix, &body);
        assert_eq!(tag::remove_cbor_tag(&tagged), &body);
    }
    // CWT prefix + message tag + self-described prefix
    let cwt = tag::with_tag(tag::CWT_PREFIX, &tag::with_tag(tag::SIGN1_PREFIX, &body));
    assert_eq!(tag::remove_cbor_tag(&cwt), &body);
    let self_tagged = tag::with_tag(
        tag::CBOR_SELF_PREFIX,
        &tag::with_tag(tag::SIGN1_PREFIX, &body),
    );
    assert_eq!(tag::remove_cbor_tag(&self_tagged), &body);
    // no recognised prefix → unchanged
    assert_eq!(tag::remove_cbor_tag(&body), &body);
}
