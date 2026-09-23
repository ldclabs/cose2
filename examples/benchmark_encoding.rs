//! Lightweight throughput probe for authenticated structures and message decoding.

use std::hint::black_box;
use std::time::Instant;

use cose2::Sign1Message;

fn main() {
    let iterations = 1_000usize;
    for size in [32usize, 64 * 1024, 1024 * 1024] {
        let payload = vec![0x42; size];
        let started = Instant::now();
        for _ in 0..iterations {
            black_box(
                Sign1Message::to_be_signed(b"\xa1\x01\x27", b"aad", black_box(&payload))
                    .expect("fixed benchmark input is valid"),
            );
        }
        println!(
            "payload={size} bytes: {:.0} ns/encoding",
            started.elapsed().as_nanos() as f64 / iterations as f64
        );

        let mut message = Sign1Message::new(Some(payload));
        message.set_signature(vec![0; 64]).unwrap();
        let encoded = message.to_vec().unwrap();
        let started = Instant::now();
        for _ in 0..iterations {
            black_box(Sign1Message::from_slice(black_box(&encoded)).unwrap());
        }
        println!(
            "payload={size} bytes: {:.0} ns/decoding",
            started.elapsed().as_nanos() as f64 / iterations as f64
        );
    }
}
