#![no_main]

use libfuzzer_sys::fuzz_target;
use sd_cwt::{restore_payload_from_message, Disclosure, RestoreMode, SdCwtValidator};

fuzz_target!(|data: &[u8]| {
    let _ = Disclosure::from_encoded(data.to_vec());
    if let Ok(message) = cose2::Sign1Message::from_slice(data) {
        let _ = restore_payload_from_message(&message, RestoreMode::Verifier);
        let _ = SdCwtValidator::default().validate_and_restore(&message, RestoreMode::Verifier);
    }
});
