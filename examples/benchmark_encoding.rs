//! Lightweight throughput probe for authenticated structures, message
//! encoding/decoding and claims decoding.

use std::hint::black_box;
use std::time::Instant;

use cose2::{cwt::Claims, Sign1Message, Value};

fn measure(label: &str, iterations: usize, mut operation: impl FnMut()) {
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    println!(
        "{label}: {:.0} ns",
        started.elapsed().as_nanos() as f64 / iterations as f64
    );
}

fn main() {
    let iterations = 1_000usize;
    for size in [32usize, 64 * 1024, 1024 * 1024] {
        let payload = vec![0x42; size];
        measure(
            &format!("payload={size} bytes: to_be_signed"),
            iterations,
            || {
                black_box(
                    Sign1Message::to_be_signed(b"\xa1\x01\x27", b"aad", black_box(&payload))
                        .expect("fixed benchmark input is valid"),
                );
            },
        );

        let mut message = Sign1Message::new(Some(payload));
        message.set_signature(vec![0; 64]).unwrap();
        let encoded = message.to_vec().unwrap();
        measure(
            &format!("payload={size} bytes: decoding"),
            iterations,
            || {
                black_box(Sign1Message::from_slice(black_box(&encoded)).unwrap());
            },
        );
    }

    // An SD-CWT presentation carries its disclosures in the unprotected header.
    let mut message = Sign1Message::new(Some(vec![0x42; 256]));
    message.protected.set_alg(cose2::iana::AlgorithmEd25519);
    let disclosures = (0..2_000)
        .map(|index| Value::Bytes(vec![index as u8; 64]))
        .collect();
    message.unprotected.insert(17, Value::Array(disclosures));
    message.set_signature(vec![0; 64]).unwrap();
    let encoded = message.to_vec().unwrap();
    measure("unprotected=2000 disclosures: encoding", iterations, || {
        black_box(black_box(&message).to_vec().unwrap());
    });
    measure("unprotected=2000 disclosures: decoding", iterations, || {
        black_box(Sign1Message::from_slice(black_box(&encoded)).unwrap());
    });

    let mut claims = Claims::new();
    for key in 0..20_000i64 {
        claims.extra.insert(1_000 + key, key);
    }
    let encoded = claims.to_vec().unwrap();
    measure("claims=20000: decoding", 50, || {
        black_box(Claims::from_slice(black_box(&encoded)).unwrap());
    });
}
