use cose2::{
    cwt::{Claims, ClaimsMap},
    iana, CoseMap, Encrypt0Message, EncryptMessage, Header, Key, KeySet, Label, Mac0Message,
    MacMessage, Sign1Message, SignMessage, Value,
};

#[cfg(feature = "crypto-ring")]
use cose2::crypto::{RingMacer, RingVerifier};

fn hx(input: &str) -> Vec<u8> {
    hex::decode(input.split_whitespace().collect::<String>()).unwrap()
}

fn assert_header_alg(header: &Header, alg: i64) {
    assert_eq!(header.alg().unwrap().unwrap().as_int(), Some(alg));
}

fn assert_header_kid(header: &Header, kid: &[u8]) {
    assert_eq!(header.kid().unwrap(), Some(kid));
}

fn assert_map_bytes(map: &CoseMap, key: i64, expected: &str) {
    let expected = hx(expected);
    assert_eq!(map.get_bytes(key).unwrap(), Some(expected.as_slice()));
}

fn assert_key_alg(key: &Key, alg: i64) {
    assert_eq!(key.alg().unwrap().unwrap().as_int(), Some(alg));
}

fn assert_key_kid(key: &Key, kid: &[u8]) {
    assert_eq!(key.kid().unwrap(), Some(kid));
}

fn rfc8392_claims_set() -> Vec<u8> {
    hx(
        "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b7703
         7818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0
         051a5610d9f0061a5610d9f007420b71",
    )
}

fn rfc8392_symmetric_128_key() -> Key {
    Key::from_slice(&hx(
        "a42050231f4c4d4d3051fdc2ec0a3851d5b3830104024c53796d6d6574726963
         313238030a",
    ))
    .unwrap()
}

fn rfc8392_symmetric_256_key() -> Key {
    Key::from_slice(&hx(
        "a4205820403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d
         795693880104024c53796d6d6574726963323536030a",
    ))
    .unwrap()
}

fn rfc8392_ecdsa_256_key() -> Key {
    Key::from_slice(&hx(
        "a72358206c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858
         bc206c1922582060f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db
         9529971a36e7b9215820143329cce7868e416927599cf65a34f3ce2ffda55a7e
         ca69ed8919a394d42f0f2001010202524173796d6d6574726963454344534132
         35360326",
    ))
    .unwrap()
}

fn rfc8392_signed_cwt() -> Vec<u8> {
    hx(
        "d28443a10126a104524173796d6d657472696345434453413235365850a701756
         36f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f
         61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d
         9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6f
         a29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a5
         2b9b63632c57209120e1c9e30",
    )
}

fn rfc8392_maced_cwt_with_cwt_tag() -> Vec<u8> {
    hx(
        "d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f6170
         3a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a
         2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f006
         1a5610d9f007420b7148093101ef6d789200",
    )
}

fn rfc8392_encrypted_cwt() -> Vec<u8> {
    hx(
        "d08343a1010aa2044c53796d6d6574726963313238054d99a0d7846e762c49ff
         e8a63e0b5858b918a11fd81e438b7f973d9e2e119bcb22424ba0f38a80f27562
         f400ee1d0d6c0fdb559c02421fd384fc2ebe22d7071378b0ea7428fff157444d
         45f7e6afcda1aae5f6495830c58627087fc5b4974f319a8707a635dd643b",
    )
}

fn rfc8392_nested_cwt() -> Vec<u8> {
    hx(
        "d08343a1010aa2044c53796d6d6574726963313238054d4a0694c0e69ee6b595
         6655c7b258b7f6b0914f993de822cc47e5e57a188d7960b528a747446fe12f0e
         7de05650dec74724366763f167a29c002dfd15b34d8993391cf49bc91127f545
         dba8703d66f5b7f1ae91237503d371e6333df9708d78c4fb8a8386c8ff09dc49
         af768b23179deab78d96490a66d5724fb33900c60799d9872fac6da3bdb89043
         d67c2a05414ce331b5b8f1ed8ff7138f45905db2c4d5bc8045ab372bff142631
         610a7e0f677b7e9b0bc73adefdcee16d9d5d284c616abeab5d8c291ce0",
    )
}

fn rfc8392_maced_float_cwt() -> Vec<u8> {
    hx(
        "d18443a10104a1044c53796d6d65747269633235364ba106fb41d584367c2000
         0048b8816f34c0542892",
    )
}

#[test]
fn rfc8392_a1_claims_set_decodes_registered_claims() {
    let claims = Claims::from_slice(&rfc8392_claims_set()).unwrap();

    assert_eq!(claims.issuer.as_deref(), Some("coap://as.example.com"));
    assert_eq!(claims.subject.as_deref(), Some("erikw"));
    assert_eq!(claims.audience.as_deref(), Some("coap://light.example.com"));
    assert_eq!(claims.expiration, Some(1_444_064_944));
    assert_eq!(claims.not_before, Some(1_443_944_944));
    assert_eq!(claims.issued_at, Some(1_443_944_944));
    assert_eq!(claims.cwt_id.as_deref(), Some(&[0x0b, 0x71][..]));
}

#[test]
fn rfc8392_a2_keys_decode() {
    let symmetric128 = rfc8392_symmetric_128_key();
    assert_eq!(
        symmetric128.kty().unwrap().unwrap().as_int(),
        Some(iana::KeyTypeSymmetric)
    );
    assert_key_alg(&symmetric128, iana::AlgorithmAES_CCM_16_64_128);
    assert_key_kid(&symmetric128, b"Symmetric128");
    assert_map_bytes(
        &symmetric128,
        iana::SymmetricKeyParameterK,
        "231f4c4d4d3051fdc2ec0a3851d5b383",
    );

    let symmetric256 = rfc8392_symmetric_256_key();
    assert_eq!(
        symmetric256.kty().unwrap().unwrap().as_int(),
        Some(iana::KeyTypeSymmetric)
    );
    // RFC 8392 Figure 6 encodes alg=10, while Figure 7 and the MAC examples
    // describe this same key material as HMAC 256/64 (alg=4).
    assert_key_alg(&symmetric256, iana::AlgorithmAES_CCM_16_64_128);
    assert_key_kid(&symmetric256, b"Symmetric256");
    assert_map_bytes(
        &symmetric256,
        iana::SymmetricKeyParameterK,
        "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388",
    );

    let ecdsa = rfc8392_ecdsa_256_key();
    assert_eq!(
        ecdsa.kty().unwrap().unwrap().as_int(),
        Some(iana::KeyTypeEC2)
    );
    assert_key_alg(&ecdsa, iana::AlgorithmES256);
    assert_key_kid(&ecdsa, b"AsymmetricECDSA256");
    assert_eq!(
        ecdsa.get_i64(iana::EC2KeyParameterCrv).unwrap(),
        Some(iana::EllipticCurveP_256)
    );
    assert_map_bytes(
        &ecdsa,
        iana::EC2KeyParameterD,
        "6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19",
    );
}

#[test]
fn rfc8392_a3_signed_cwt_decodes() {
    let msg = Sign1Message::from_slice(&rfc8392_signed_cwt()).unwrap();

    assert_header_alg(&msg.protected, iana::AlgorithmES256);
    assert_header_kid(&msg.unprotected, b"AsymmetricECDSA256");
    assert_eq!(msg.protected_raw(), hx("a10126"));
    assert_eq!(
        msg.payload.as_deref(),
        Some(rfc8392_claims_set().as_slice())
    );
    assert_eq!(
        msg.signature(),
        hx(
            "5427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5a
             cd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30"
        )
    );

    let claims = Claims::from_slice(msg.payload.as_deref().unwrap()).unwrap();
    assert_eq!(claims.subject.as_deref(), Some("erikw"));
}

#[cfg(feature = "crypto-ring")]
#[test]
fn rfc8392_a3_signed_cwt_verifies_with_appendix_key() {
    let verifier = RingVerifier::from_cose_key(&rfc8392_ecdsa_256_key()).unwrap();
    let msg = Sign1Message::verify_and_decode(&verifier, &rfc8392_signed_cwt(), None).unwrap();

    let claims = Claims::from_slice(msg.payload.as_deref().unwrap()).unwrap();
    assert_eq!(claims.audience.as_deref(), Some("coap://light.example.com"));
}

#[test]
fn rfc8392_a4_maced_cwt_with_cwt_tag_decodes() {
    let msg = Mac0Message::from_slice(&rfc8392_maced_cwt_with_cwt_tag()).unwrap();

    assert_header_alg(&msg.protected, iana::AlgorithmHMAC_256_64);
    assert_header_kid(&msg.unprotected, b"Symmetric256");
    assert_eq!(msg.protected_raw(), hx("a10104"));
    assert_eq!(
        msg.payload.as_deref(),
        Some(rfc8392_claims_set().as_slice())
    );
    assert_eq!(msg.tag(), hx("093101ef6d789200"));
}

#[cfg(feature = "crypto-ring")]
#[test]
fn rfc8392_a4_maced_cwt_verifies_with_appendix_key() {
    let key = rfc8392_symmetric_256_key();
    let macer = RingMacer::new(
        iana::AlgorithmHMAC_256_64,
        key.get_bytes(iana::SymmetricKeyParameterK)
            .unwrap()
            .unwrap(),
        Some(b"Symmetric256".to_vec()),
    )
    .unwrap();
    let msg =
        Mac0Message::verify_and_decode(&macer, &rfc8392_maced_cwt_with_cwt_tag(), None).unwrap();

    let claims = Claims::from_slice(msg.payload.as_deref().unwrap()).unwrap();
    assert_eq!(claims.issuer.as_deref(), Some("coap://as.example.com"));
}

#[test]
fn rfc8392_a5_encrypted_cwt_decodes() {
    let msg = Encrypt0Message::from_slice(&rfc8392_encrypted_cwt()).unwrap();

    assert_header_alg(&msg.protected, iana::AlgorithmAES_CCM_16_64_128);
    assert_header_kid(&msg.unprotected, b"Symmetric128");
    assert_eq!(
        msg.unprotected.iv().unwrap(),
        Some(hx("99a0d7846e762c49ffe8a63e0b").as_slice())
    );
    assert_eq!(msg.ciphertext().len(), 88);
}

#[test]
fn rfc8392_a6_nested_cwt_decodes_outer_encrypt0() {
    let msg = Encrypt0Message::from_slice(&rfc8392_nested_cwt()).unwrap();

    assert_header_alg(&msg.protected, iana::AlgorithmAES_CCM_16_64_128);
    assert_header_kid(&msg.unprotected, b"Symmetric128");
    assert_eq!(
        msg.unprotected.iv().unwrap(),
        Some(hx("4a0694c0e69ee6b5956655c7b2").as_slice())
    );
    assert_eq!(msg.ciphertext().len(), 183);
}

#[test]
fn rfc8392_a7_maced_float_cwt_decodes_float_claim() {
    let msg = Mac0Message::from_slice(&rfc8392_maced_float_cwt()).unwrap();

    assert_header_alg(&msg.protected, iana::AlgorithmHMAC_256_64);
    assert_header_kid(&msg.unprotected, b"Symmetric256");
    assert_eq!(msg.tag(), hx("b8816f34c0542892"));

    let claims = ClaimsMap::from_slice(msg.payload.as_deref().unwrap()).unwrap();
    assert_eq!(
        claims.get(iana::CWTClaimIat),
        Some(&Value::Float(1_443_944_944.5))
    );
}

#[cfg(feature = "crypto-ring")]
#[test]
fn rfc8392_a7_maced_float_cwt_verifies_with_appendix_key() {
    let key = rfc8392_symmetric_256_key();
    let macer = RingMacer::new(
        iana::AlgorithmHMAC_256_64,
        key.get_bytes(iana::SymmetricKeyParameterK)
            .unwrap()
            .unwrap(),
        Some(b"Symmetric256".to_vec()),
    )
    .unwrap();
    assert!(Mac0Message::verify_and_decode(&macer, &rfc8392_maced_float_cwt(), None).is_ok());
}

fn rfc9052_c1_1_sign_single_signature() -> Vec<u8> {
    hx(
        "d8628440a054546869732069732074686520636f6e74656e742e818343a10126
         a1044231315840e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06
         cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b
         98f53afd2fa0f30a",
    )
}

fn rfc9052_c1_2_sign_multiple_signers() -> Vec<u8> {
    hx(
        "d8628440a054546869732069732074686520636f6e74656e742e828343a10126
         a1044231315840e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06
         cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b
         98f53afd2fa0f30a8344a1013823a104581e62696c626f2e62616767696e7340
         686f626269746f6e2e6578616d706c65588400a2d28a7c2bdb1587877420f65a
         df7d0b9a06635dd1de64bb62974c863f0b160dd2163734034e6ac003b01e870
         5524c5c4ca479a952f0247ee8cb0b4fb7397ba08d009e0c8bf482270cc5771
         aa143966e5a469a09f613488030c5b07ec6d722e3835adb5b2d8c44e95ffb1
         3877dd2582866883535de3bb03d01753f83ab87bb4f7a0297",
    )
}

fn rfc9052_c1_3_sign_with_criticality() -> Vec<u8> {
    hx(
        "d8628456a2687265736572766564f40281687265736572766564a054546869
         732069732074686520636f6e74656e742e818343a10126a10442313158403fc5
         4702aa56e1b2cb20284294c9106a63f91bac658d69351210a031d8fc7c5ff3
         e4be39445b1a3e83e1510d1aca2f2e8a7c081c7645042b18aba9d1fad1bd
         9c",
    )
}

fn rfc9052_c2_1_sign1_single_ecdsa() -> Vec<u8> {
    hx(
        "d28443a10126a10442313154546869732069732074686520636f6e74656e742e
         58408eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0
         117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345ca
         cb36",
    )
}

fn rfc9052_c3_1_encrypt_direct_ecdh() -> Vec<u8> {
    hx(
        "d8608443a10101a1054cc9cf4df2fe6c632bf788641358247adbe2709ca818fb
         415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0818344
         a1013818a20458246d65726961646f632e6272616e64796275636b406275636b
         6c616e642e6578616d706c6520a40102200121582098f50a4ff6c05861c8860
         d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022f540",
    )
}

fn rfc9052_c3_2_encrypt_direct_plus_key_derivation() -> Vec<u8> {
    hx(
        "d8608443a1010aa1054d89f52f65a1c580933b5261a76c581c753548a19b130
         7084ca7b2056924ed95f2e3b17006dfe931b687b847818343a10129a2044a
         6f75722d73656372657433506161626263636464656566666767686840",
    )
}

fn rfc9052_c3_3_encrypt_with_external_data() -> Vec<u8> {
    hx(
        "d8608443a10101a1054c02d1f7e6f26c43d4868d87ce582464f84d913ba60a76
         070a9a48f26e97e863e28529d8f5335e5f0165eee976b4a5f6c6f09d818344
         a101381fa30458246d65726961646f632e6272616e64796275636b406275636b
         6c616e642e6578616d706c65225821706572656772696e2e746f6f6b40747563
         6b626f726f7567682e6578616d706c6535420101581841e0d76f579dbd0d936a
         662d54d8582037de2e366fde1c62",
    )
}

fn rfc9052_c4_1_encrypt0_simple() -> Vec<u8> {
    hx(
        "d08343a1010aa1054d89f52f65a1c580933b5261a78c581c5974e1b99a3a4c
         c09a659aa2e9e7fff161d38ce71cb45ce460ffb569",
    )
}

fn rfc9052_c4_2_encrypt0_partial_iv() -> Vec<u8> {
    hx(
        "d08343a1010aa1064261a7581c252a8911d465c125b6764739700f0141ed0919
         2de139e053bd09abca",
    )
}

fn rfc9052_c5_1_mac_direct() -> Vec<u8> {
    hx(
        "d8618543a1010fa054546869732069732074686520636f6e74656e742e489e12
         26ba1f81b848818340a20125044a6f75722d73656372657440",
    )
}

fn rfc9052_c5_2_mac_ecdh_direct() -> Vec<u8> {
    hx(
        "d8618543a10105a054546869732069732074686520636f6e74656e742e582081
         a03448acd3d305376eaa11fb3fe416a955be2cbe7ec96f012c994bc3f16a41
         818344a101381aa30458246d65726961646f632e6272616e64796275636b4062
         75636b6c616e642e6578616d706c65225821706572656772696e2e746f6f6b
         407475636b626f726f7567682e6578616d706c653558404d8553e7e74f3c6a
         3a9dd3ef286a8195cbf8a23d19558ccfec7d34b824f42d92bd06bd2c7f02
         71f0214e141fb779ae2856abf585a58368b017e7f2a9e5ce4db540",
    )
}

fn rfc9052_c5_3_mac_wrapped() -> Vec<u8> {
    hx(
        "d8618543a1010ea054546869732069732074686520636f6e74656e742e4836f5
         afaf0bab5d43818340a2012404582430313863306165352d346439622d343731
         622d626664362d6565663331346263373033375818711ab0dc2fc4585dce27
         effa6781c8093eba906f227b6eb0",
    )
}

fn rfc9052_c5_4_mac_multi_recipient() -> Vec<u8> {
    hx(
        "d8618543a10105a054546869732069732074686520636f6e74656e742e5820bf
         48235e809b5c42e995f2b7d5fa13620e7ed834e337f6aa43df161e49e9323e
         828344a101381ca204581e62696c626f2e62616767696e7340686f626269746f
         6e2e6578616d706c6520a4010220032158420043b12669acac3fd27898ffba
         0bcd2e6c366d53bc4db71f909a759304acfb5e18cdc7ba0b13ff8c7636271
         a6924b1ac63c02688075b55ef2d613574e7dc242f79c322f55828339bc4f799
         84cdc6b3e6ce5f315a4c7d2b0ac466fcea69e8c07dfbca5bb1f661bc5f8e0
         df9e3eff58340a2012404582430313863306165352d346439622d343731622d
         626664362d65656633313462633730333758280b2c7cfce04e98276342d647
         6a7723c090dfdd15f9a518e7736549e998370695e6d6a83b4ae507bb",
    )
}

fn rfc9052_c6_1_mac0_direct() -> Vec<u8> {
    hx(
        "d18443a1010fa054546869732069732074686520636f6e74656e742e48726043
         745027214f",
    )
}

#[test]
fn rfc9052_c1_signed_message_examples_decode() {
    let single = SignMessage::from_slice(&rfc9052_c1_1_sign_single_signature()).unwrap();
    assert_eq!(
        single.payload.as_deref(),
        Some(&b"This is the content."[..])
    );
    assert_eq!(single.signatures.len(), 1);
    assert_header_alg(&single.signatures[0].protected, iana::AlgorithmES256);
    assert_header_kid(&single.signatures[0].unprotected, b"11");
    assert_eq!(
        single.signatures[0].signature(),
        hx(
            "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982
             ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a"
        )
    );
    assert_eq!(
        single.to_vec().unwrap(),
        rfc9052_c1_1_sign_single_signature()
    );

    let multiple = SignMessage::from_slice(&rfc9052_c1_2_sign_multiple_signers()).unwrap();
    assert_eq!(multiple.signatures.len(), 2);
    assert_header_alg(&multiple.signatures[0].protected, iana::AlgorithmES256);
    assert_header_alg(&multiple.signatures[1].protected, iana::AlgorithmES512);
    assert_header_kid(
        &multiple.signatures[1].unprotected,
        b"bilbo.baggins@hobbiton.example",
    );
    assert_eq!(multiple.signatures[1].signature().len(), 132);
    assert_eq!(
        multiple.to_vec().unwrap(),
        rfc9052_c1_2_sign_multiple_signers()
    );
}

#[test]
fn rfc9052_c1_3_signed_message_preserves_noncanonical_protected_bytes() {
    let msg = SignMessage::from_slice(&rfc9052_c1_3_sign_with_criticality()).unwrap();

    assert_eq!(
        msg.protected_raw(),
        hx("a2687265736572766564f40281687265736572766564")
    );
    assert_eq!(msg.protected.get_bool("reserved").unwrap(), Some(false));
    assert_eq!(
        msg.protected.crit().unwrap(),
        Some(vec![Label::Text("reserved".into())])
    );
    assert!(msg
        .protected
        .ensure_crit_understood(&[Label::Text("reserved".into())])
        .is_ok());
    assert_eq!(msg.to_vec().unwrap(), rfc9052_c1_3_sign_with_criticality());
}

#[test]
fn rfc9052_c2_1_sign1_example_decodes() {
    let msg = Sign1Message::from_slice(&rfc9052_c2_1_sign1_single_ecdsa()).unwrap();

    assert_header_alg(&msg.protected, iana::AlgorithmES256);
    assert_header_kid(&msg.unprotected, b"11");
    assert_eq!(msg.payload.as_deref(), Some(&b"This is the content."[..]));
    assert_eq!(msg.signature().len(), 64);
    assert_eq!(msg.to_vec().unwrap(), rfc9052_c2_1_sign1_single_ecdsa());
}

#[test]
fn rfc9052_c3_enveloped_message_examples_decode() {
    let direct_ecdh = EncryptMessage::from_slice(&rfc9052_c3_1_encrypt_direct_ecdh()).unwrap();
    assert_header_alg(&direct_ecdh.protected, iana::AlgorithmA128GCM);
    assert_eq!(direct_ecdh.ciphertext().len(), 36);
    assert_eq!(direct_ecdh.recipients.len(), 1);
    assert_header_alg(
        &direct_ecdh.recipients[0].protected,
        iana::AlgorithmECDH_ES_HKDF_256,
    );
    assert!(matches!(
        direct_ecdh.recipients[0]
            .unprotected
            .get(iana::HeaderAlgorithmParameterEphemeralKey),
        Some(Value::Map(_))
    ));
    assert_eq!(
        direct_ecdh.to_vec().unwrap(),
        rfc9052_c3_1_encrypt_direct_ecdh()
    );

    let direct_hkdf =
        EncryptMessage::from_slice(&rfc9052_c3_2_encrypt_direct_plus_key_derivation()).unwrap();
    assert_header_alg(&direct_hkdf.protected, iana::AlgorithmAES_CCM_16_64_128);
    assert_header_alg(
        &direct_hkdf.recipients[0].protected,
        iana::AlgorithmDirect_HKDF_SHA_256,
    );
    assert_header_kid(&direct_hkdf.recipients[0].unprotected, b"our-secret");
    assert_eq!(
        direct_hkdf.to_vec().unwrap(),
        rfc9052_c3_2_encrypt_direct_plus_key_derivation()
    );

    let external = EncryptMessage::from_slice(&rfc9052_c3_3_encrypt_with_external_data()).unwrap();
    assert_header_alg(&external.protected, iana::AlgorithmA128GCM);
    assert_header_alg(
        &external.recipients[0].protected,
        iana::AlgorithmECDH_SS_A128KW,
    );
    assert_map_bytes(
        &external.recipients[0].unprotected,
        iana::HeaderAlgorithmParameterPartyUNonce,
        "0101",
    );
    assert_eq!(
        external.to_vec().unwrap(),
        rfc9052_c3_3_encrypt_with_external_data()
    );
}

#[test]
fn rfc9052_c4_encrypt0_examples_decode() {
    let simple = Encrypt0Message::from_slice(&rfc9052_c4_1_encrypt0_simple()).unwrap();
    assert_header_alg(&simple.protected, iana::AlgorithmAES_CCM_16_64_128);
    assert_eq!(
        simple.unprotected.iv().unwrap(),
        Some(hx("89f52f65a1c580933b5261a78c").as_slice())
    );
    assert_eq!(simple.ciphertext().len(), 28);
    assert_eq!(simple.to_vec().unwrap(), rfc9052_c4_1_encrypt0_simple());

    let partial = Encrypt0Message::from_slice(&rfc9052_c4_2_encrypt0_partial_iv()).unwrap();
    assert_header_alg(&partial.protected, iana::AlgorithmAES_CCM_16_64_128);
    assert_eq!(
        partial.unprotected.partial_iv().unwrap(),
        Some(hx("61a7").as_slice())
    );
    assert_eq!(partial.ciphertext().len(), 28);
    assert_eq!(
        partial.to_vec().unwrap(),
        rfc9052_c4_2_encrypt0_partial_iv()
    );
}

#[test]
fn rfc9052_c5_maced_message_examples_decode() {
    let direct = MacMessage::from_slice(&rfc9052_c5_1_mac_direct()).unwrap();
    assert_header_alg(&direct.protected, iana::AlgorithmAES_MAC_256_64);
    assert_eq!(
        direct.payload.as_deref(),
        Some(&b"This is the content."[..])
    );
    assert_eq!(direct.tag(), hx("9e1226ba1f81b848"));
    assert_eq!(direct.recipients.len(), 1);
    assert_header_alg(&direct.recipients[0].unprotected, iana::AlgorithmDirect);
    assert_eq!(direct.to_vec().unwrap(), rfc9052_c5_1_mac_direct());

    let ecdh = MacMessage::from_slice(&rfc9052_c5_2_mac_ecdh_direct()).unwrap();
    assert_header_alg(&ecdh.protected, iana::AlgorithmHMAC_256_256);
    assert_header_alg(
        &ecdh.recipients[0].protected,
        iana::AlgorithmECDH_SS_HKDF_256,
    );
    assert_eq!(ecdh.tag().len(), 32);
    assert_eq!(ecdh.to_vec().unwrap(), rfc9052_c5_2_mac_ecdh_direct());

    let wrapped = MacMessage::from_slice(&rfc9052_c5_3_mac_wrapped()).unwrap();
    assert_header_alg(&wrapped.protected, iana::AlgorithmAES_MAC_128_64);
    assert_header_alg(&wrapped.recipients[0].unprotected, iana::AlgorithmA256KW);
    assert_eq!(
        wrapped.recipients[0].ciphertext.as_deref().unwrap().len(),
        24
    );
    assert_eq!(wrapped.to_vec().unwrap(), rfc9052_c5_3_mac_wrapped());

    let multi = MacMessage::from_slice(&rfc9052_c5_4_mac_multi_recipient()).unwrap();
    assert_header_alg(&multi.protected, iana::AlgorithmHMAC_256_256);
    assert_eq!(multi.recipients.len(), 2);
    assert_header_alg(
        &multi.recipients[0].protected,
        iana::AlgorithmECDH_ES_A128KW,
    );
    assert_header_alg(&multi.recipients[1].unprotected, iana::AlgorithmA256KW);
    assert_eq!(multi.to_vec().unwrap(), rfc9052_c5_4_mac_multi_recipient());
}

#[test]
fn rfc9052_c6_mac0_example_decodes() {
    let msg = Mac0Message::from_slice(&rfc9052_c6_1_mac0_direct()).unwrap();

    assert_header_alg(&msg.protected, iana::AlgorithmAES_MAC_256_64);
    assert_eq!(msg.payload.as_deref(), Some(&b"This is the content."[..]));
    assert_eq!(msg.tag(), hx("726043745027214f"));
    assert_eq!(msg.to_vec().unwrap(), rfc9052_c6_1_mac0_direct());
}

fn ec2_key(kid: &[u8], crv: i64, x: &str, y: Value, d: Option<&str>) -> Key {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeEC2).set_kid(kid.to_vec());
    key.insert(iana::EC2KeyParameterCrv, crv);
    key.insert(iana::EC2KeyParameterX, hx(x));
    key.insert(iana::EC2KeyParameterY, y);
    if let Some(d) = d {
        key.insert(iana::EC2KeyParameterD, hx(d));
    }
    key
}

fn symmetric_key(kid: &[u8], key_bytes: &str) -> Key {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeSymmetric).set_kid(kid.to_vec());
    key.insert(iana::SymmetricKeyParameterK, hx(key_bytes));
    key
}

fn rfc9052_c7_public_keys() -> KeySet {
    KeySet(vec![
        ec2_key(
            b"meriadoc.brandybuck@buckland.example",
            iana::EllipticCurveP_256,
            "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d",
            Value::Bytes(hx("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")),
            None,
        ),
        ec2_key(
            b"11",
            iana::EllipticCurveP_256,
            "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
            Value::Bytes(hx("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")),
            None,
        ),
        ec2_key(
            b"bilbo.baggins@hobbiton.example",
            iana::EllipticCurveP_521,
            "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad",
            Value::Bytes(hx("01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475")),
            None,
        ),
        ec2_key(
            b"peregrin.took@tuckborough.example",
            iana::EllipticCurveP_256,
            "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280",
            Value::Bytes(hx("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb")),
            None,
        ),
    ])
}

fn rfc9052_c7_private_keys() -> KeySet {
    KeySet(vec![
        ec2_key(
            b"meriadoc.brandybuck@buckland.example",
            iana::EllipticCurveP_256,
            "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d",
            Value::Bytes(hx("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")),
            Some("aff907c99f9ad3aae6c4cdf21122bce2bd68b5283e6907154ad911840fa208cf"),
        ),
        ec2_key(
            b"11",
            iana::EllipticCurveP_256,
            "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
            Value::Bytes(hx("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")),
            Some("57c92077664146e876760c9520d054aa93c3afb04e306705db6090308507b4d3"),
        ),
        ec2_key(
            b"bilbo.baggins@hobbiton.example",
            iana::EllipticCurveP_521,
            "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad",
            Value::Bytes(hx("01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475")),
            Some("00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d"),
        ),
        symmetric_key(
            b"our-secret",
            "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188",
        ),
        ec2_key(
            b"peregrin.took@tuckborough.example",
            iana::EllipticCurveP_256,
            "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280",
            Value::Bytes(hx("f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb")),
            Some("02d1f7e6f26c43d4868d87ceb2353161740aacf1f7163647984b522a848df1c3"),
        ),
        symmetric_key(b"our-secret2", "849b5786457c1491be3a76dcea6c4271"),
        symmetric_key(
            b"018c0ae5-4d9b-471b-bfd6-eef314bc7037",
            "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188",
        ),
    ])
}

#[test]
fn rfc9052_c7_key_sets_encode_to_stated_sizes_and_decode() {
    let public_keys = rfc9052_c7_public_keys();
    let public_bytes = public_keys.to_vec().unwrap();
    assert_eq!(public_bytes.len(), 481);
    let public_decoded = KeySet::from_slice(&public_bytes).unwrap();
    assert_eq!(public_decoded.len(), 4);
    assert_eq!(public_decoded.lookup(b"11").count(), 1);
    assert_eq!(public_decoded, public_keys);

    let private_keys = rfc9052_c7_private_keys();
    let private_bytes = private_keys.to_vec().unwrap();
    assert_eq!(private_bytes.len(), 816);
    let private_decoded = KeySet::from_slice(&private_bytes).unwrap();
    assert_eq!(private_decoded.len(), 7);
    assert_eq!(private_decoded.lookup(b"our-secret").count(), 1);
    assert_eq!(private_decoded.lookup(b"our-secret2").count(), 1);
    assert_eq!(private_decoded, private_keys);
}
