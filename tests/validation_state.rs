mod common;

use common::{MockEncryptor, MockMacer, MockSigner, MockVerifier};
use cose2::{
    iana, Encrypt0Message, EncryptMessage, Error, Header, Mac0Message, MacMessage, Recipient,
    Sign1Message, SignMessage, Value,
};

fn direct_recipient() -> Recipient {
    let mut recipient = Recipient::new();
    recipient.unprotected.set_alg(iana::AlgorithmDirect);
    recipient.ciphertext = Some(vec![]);
    recipient
}

fn check_mutations<M: Clone>(
    message: &M,
    alg: i64,
    header: fn(&mut M) -> &mut Header,
    verify: impl Fn(&mut M) -> Result<(), Error>,
) {
    for mutation in 0..4 {
        let mut changed = message.clone();
        let unprotected = header(&mut changed);
        match mutation {
            0 => {
                unprotected.set_alg(alg);
            }
            1 => {
                unprotected.insert("private", true);
                unprotected.set_crit(["private"]);
            }
            2 => {
                unprotected.set_iv(vec![1; 12]);
                unprotected.set_partial_iv(vec![1]);
            }
            _ => {
                unprotected.insert(iana::HeaderParameterKid, true);
            }
        }
        assert!(
            verify(&mut changed).is_err(),
            "accepted malformed header mutation {mutation}"
        );
    }
    let mut valid = message.clone();
    header(&mut valid).insert("transport", "metadata");
    verify(&mut valid).unwrap();
}

#[test]
fn signature_verification_rechecks_mutated_header_buckets() {
    let signer = MockSigner::new(iana::AlgorithmEd25519, b"key");
    let verifier = MockVerifier::new(iana::AlgorithmEd25519, b"key");
    for detached in [false, true] {
        let mut sign1 = Sign1Message::new(Some(b"payload".to_vec()));
        let mut sign = SignMessage::new(Some(b"payload".to_vec()));
        if detached {
            sign1.sign_detached(&signer, b"payload", None).unwrap();
            sign.sign_detached(&[&signer], b"payload", None).unwrap();
        } else {
            sign1.sign(&signer, None).unwrap();
            sign.sign(&[&signer], None).unwrap();
        }
        check_mutations(
            &sign1,
            iana::AlgorithmEd25519,
            |m| &mut m.unprotected,
            |m| {
                if detached {
                    m.verify_detached(&verifier, b"payload", None)
                } else {
                    m.verify(&verifier, None)
                }
            },
        );
        let verify = |m: &mut SignMessage| {
            if detached {
                m.verify_detached(&[&verifier], b"payload", None)
            } else {
                m.verify(&[&verifier], None)
            }
        };
        check_mutations(
            &sign,
            iana::AlgorithmEd25519,
            |m| &mut m.signatures[0].unprotected,
            verify,
        );
        sign.unprotected.insert("private", true);
        sign.unprotected.set_crit(["private"]);
        assert!(verify(&mut sign).is_err());
    }
}

#[test]
fn mac_verification_rechecks_mutated_header_buckets() {
    let macer = MockMacer::new(iana::AlgorithmHMAC_256_256, b"key");
    for detached in [false, true] {
        let mut mac0 = Mac0Message::new(Some(b"payload".to_vec()));
        let mut mac = MacMessage::new(Some(b"payload".to_vec()));
        mac.recipients.push(direct_recipient());
        if detached {
            mac0.compute_detached(&macer, b"payload", None).unwrap();
            mac.compute_detached(&macer, b"payload", None).unwrap();
        } else {
            mac0.compute(&macer, None).unwrap();
            mac.compute(&macer, None).unwrap();
        }
        check_mutations(
            &mac0,
            iana::AlgorithmHMAC_256_256,
            |m| &mut m.unprotected,
            |m| {
                if detached {
                    m.verify_detached(&macer, b"payload", None)
                } else {
                    m.verify(&macer, None)
                }
            },
        );
        check_mutations(
            &mac,
            iana::AlgorithmHMAC_256_256,
            |m| &mut m.unprotected,
            |m| {
                if detached {
                    m.verify_detached(&macer, b"payload", None)
                } else {
                    m.verify(&macer, None)
                }
            },
        );
    }
}

#[test]
fn decryption_rechecks_mutated_header_buckets() {
    let encryptor = MockEncryptor::new(iana::AlgorithmA128GCM, b"key", 12);
    for detached in [false, true] {
        let mut encrypt0 = Encrypt0Message::new(Some(b"payload".to_vec()));
        let mut encrypt = EncryptMessage::new(Some(b"payload".to_vec()));
        encrypt0.unprotected.set_iv(vec![1; 12]);
        encrypt.unprotected.set_iv(vec![1; 12]);
        encrypt.recipients.push(direct_recipient());
        if detached {
            encrypt0.encrypt_detached(&encryptor, None).unwrap();
            encrypt.encrypt_detached(&encryptor, None).unwrap();
        } else {
            encrypt0.encrypt(&encryptor, None).unwrap();
            encrypt.encrypt(&encryptor, None).unwrap();
        }
        let ciphertext0 = encrypt0.ciphertext().to_vec();
        let ciphertext = encrypt.ciphertext().to_vec();
        check_mutations(
            &encrypt0,
            iana::AlgorithmA128GCM,
            |m| &mut m.unprotected,
            |m| {
                if detached {
                    m.decrypt_detached(&encryptor, &ciphertext0, None)
                } else {
                    m.decrypt(&encryptor, None)
                }
                .map(|_| ())
            },
        );
        check_mutations(
            &encrypt,
            iana::AlgorithmA128GCM,
            |m| &mut m.unprotected,
            |m| {
                if detached {
                    m.decrypt_detached(&encryptor, &ciphertext, None)
                } else {
                    m.decrypt(&encryptor, None)
                }
                .map(|_| ())
            },
        );
        check_mutations(
            &encrypt0,
            iana::AlgorithmA128GCM,
            |m| &mut m.unprotected,
            |m| {
                m.prepare_decryption(Some(iana::AlgorithmA128GCM.into()), 12, None, None)
                    .map(|_| ())
            },
        );
        check_mutations(
            &encrypt,
            iana::AlgorithmA128GCM,
            |m| &mut m.unprotected,
            |m| {
                m.prepare_decryption(Some(iana::AlgorithmA128GCM.into()), 12, None, None)
                    .map(|_| ())
            },
        );
    }
}

#[test]
fn direct_wire_byte_decoding_keeps_type_checks_for_every_message() {
    type Decode = fn(&[u8]) -> Result<(), Error>;
    let cases: &[(u64, Decode)] = &[
        (18, |b| Sign1Message::from_slice(b).map(|_| ())),
        (98, |b| SignMessage::from_slice(b).map(|_| ())),
        (17, |b| Mac0Message::from_slice(b).map(|_| ())),
        (97, |b| MacMessage::from_slice(b).map(|_| ())),
        (16, |b| Encrypt0Message::from_slice(b).map(|_| ())),
        (96, |b| EncryptMessage::from_slice(b).map(|_| ())),
    ];
    let bytes = || Value::Bytes(b"payload".to_vec());
    let recipients = Value::Array(vec![cbor2::from_slice::<Value>(
        &direct_recipient().to_vec().unwrap(),
    )
    .unwrap()]);
    for &(tag, decode) in cases {
        let mut body = vec![Value::Bytes(vec![]), Value::Map(vec![]), bytes()];
        match tag {
            17 | 18 => body.push(bytes()),
            96 => body.push(recipients.clone()),
            97 => {
                body.push(bytes());
                body.push(recipients.clone());
            }
            98 => body.push(Value::Array(vec![Value::Array(vec![
                Value::Bytes(vec![]),
                Value::Map(vec![]),
                bytes(),
            ])])),
            _ => {}
        }
        let encode = |body| cbor2::to_vec(&Value::Tag(tag, Box::new(Value::Array(body)))).unwrap();
        decode(&encode(body.clone())).unwrap();
        let indices: &[usize] = if matches!(tag, 17 | 18 | 97) {
            &[0, 2, 3]
        } else {
            &[0, 2]
        };
        for &index in indices {
            for invalid in [
                Value::Array(vec![]),
                Value::Tag(24, Box::new(bytes())),
                Value::Bool(false),
            ] {
                let mut invalid_body = body.clone();
                invalid_body[index] = invalid;
                assert!(
                    decode(&encode(invalid_body)).is_err(),
                    "tag={tag}, field={index}"
                );
            }
        }
        // The payload/ciphertext slot permits null; protected never does.
        let mut detached = body.clone();
        detached[2] = Value::Null;
        decode(&encode(detached)).unwrap();
        let mut undefined = body.clone();
        undefined[2] = Value::Simple(cbor2::Simple::new(23).unwrap());
        assert!(decode(&encode(undefined)).is_err());
        if tag == 98 {
            let mut invalid_signature = body.clone();
            let Value::Array(signatures) = &mut invalid_signature[3] else {
                unreachable!()
            };
            let Value::Array(signature) = &mut signatures[0] else {
                unreachable!()
            };
            signature[2] = Value::Array(vec![]);
            assert!(decode(&encode(invalid_signature)).is_err());
        }
        body[0] = Value::Null;
        assert!(decode(&encode(body)).is_err());
    }
}

#[test]
fn indefinite_byte_strings_still_decode_into_final_buffers() {
    // Indefinite byte strings are allowed in ordinary COSE, including the
    // protected field itself. Its concatenated contents must be kept verbatim.
    let encoded = hex::decode("845f42a1014132ffa05f4261624163ff5f41644165ff").unwrap();
    let message = Sign1Message::from_slice(&encoded).unwrap();
    assert_eq!(message.protected_raw(), &[0xa1, 0x01, 0x32]);
    assert_eq!(message.payload.as_deref(), Some(b"abc".as_slice()));
    assert_eq!(message.signature(), b"de");
}
