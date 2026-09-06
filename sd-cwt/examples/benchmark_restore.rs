//! Lightweight scaling probe for SD-CWT map restoration.

use std::hint::black_box;
use std::time::Instant;

use cbor2::Value;
use sd_cwt::{restore_for_verifier, Sha256RedactionHasher};

fn main() {
    for count in [1_000i64, 2_000, 4_000, 8_000] {
        let claims = Value::Map(
            (0..count)
                .map(|key| (Value::from(key), Value::from(key)))
                .collect(),
        );
        let started = Instant::now();
        let restored = restore_for_verifier(claims, [], &Sha256RedactionHasher)
            .expect("fixed benchmark input is valid");
        black_box(restored);
        println!(
            "claims={count}: {:.3} ms",
            started.elapsed().as_secs_f64() * 1_000.0
        );
    }
}
