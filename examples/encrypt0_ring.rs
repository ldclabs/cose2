use cose2::{crypto::RingEncryptor, iana, Encrypt0Message, Error, Key};

fn main() -> Result<(), Error> {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeSymmetric)
        .set_alg(iana::AlgorithmA128GCM)
        .set_kid(b"a128gcm-demo".to_vec());
    key.insert(iana::SymmetricKeyParameterK, vec![0x22; 16]);
    key.insert(iana::KeyParameterBaseIV, vec![0xaa; 12]);

    let encryptor = RingEncryptor::from_cose_key(&key)?;

    let mut msg = Encrypt0Message::new(Some(b"confidential payload".to_vec()));
    // This fixed Partial IV is for a deterministic example only. Production
    // code must never reuse an AEAD nonce with the same key.
    msg.unprotected.set_partial_iv(vec![0x01, 0x02]);

    let encoded = msg.encrypt_and_encode(&encryptor, Some(b"encrypt context"))?;
    let decoded =
        Encrypt0Message::decrypt_and_decode(&encryptor, &encoded, Some(b"encrypt context"))?;
    assert_eq!(
        decoded.payload.as_deref(),
        Some(&b"confidential payload"[..])
    );
    assert!(
        Encrypt0Message::decrypt_and_decode(&encryptor, &encoded, Some(b"wrong context")).is_err()
    );

    println!("ring COSE_Encrypt0 bytes: {}", encoded.len());
    Ok(())
}
