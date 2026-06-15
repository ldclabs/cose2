use cose2::{crypto::RingMacer, iana, Error, Key, Mac0Message};

fn main() -> Result<(), Error> {
    let mut key = Key::new();
    key.set_kty(iana::KeyTypeSymmetric)
        .set_alg(iana::AlgorithmHMAC_256_256)
        .set_kid(b"hmac-demo".to_vec());
    key.insert(iana::SymmetricKeyParameterK, vec![0x11; 32]);

    let macer = RingMacer::from_cose_key(&key)?;
    let mut msg = Mac0Message::new(Some(b"authenticated payload".to_vec()));
    let encoded = msg.compute_and_encode(&macer, Some(b"mac context"))?;

    let verified = Mac0Message::verify_and_decode(&macer, &encoded, Some(b"mac context"))?;
    assert_eq!(
        verified.payload.as_deref(),
        Some(&b"authenticated payload"[..])
    );
    assert!(Mac0Message::verify_and_decode(&macer, &encoded, Some(b"wrong context")).is_err());

    println!("ring COSE_Mac0 bytes: {}", encoded.len());
    Ok(())
}
