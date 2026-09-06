#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cose2::Header::from_slice(data);
    let _ = cose2::Key::from_slice(data);
    let _ = cose2::KeySet::from_slice(data);
    let _ = cose2::KdfContext::from_slice(data);
    let _ = cose2::cwt::Claims::from_slice(data);
    let _ = cose2::Sign1Message::from_slice(data);
    let _ = cose2::SignMessage::from_slice(data);
    let _ = cose2::Mac0Message::from_slice(data);
    let _ = cose2::MacMessage::from_slice(data);
    let _ = cose2::Encrypt0Message::from_slice(data);
    let _ = cose2::EncryptMessage::from_slice(data);
    let _ = cose2::Recipient::from_slice(data);
});
