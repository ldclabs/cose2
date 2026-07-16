# sd-cwt

Selective Disclosure CBOR Web Token (SD-CWT) helpers for Rust, built on
[`cose2`](https://crates.io/crates/cose2) and
[`cbor2`](https://crates.io/crates/cbor2).

This crate implements the SD-CWT disclosure and redaction mechanics from
`draft-ietf-spice-sd-cwt-08`. It does not replace `cose2`'s COSE signing and
verification APIs. Instead, it provides the SD-CWT-specific pieces you compose
with `cose2::Sign1Message`:

- registered SD-CWT header labels: `sd_claims`, `sd_alg`,
  `sd_aead_encrypted_claims`, `sd_aead`, `kcwt`, `CWT_Claims`, and `typ`;
- `simple(59)` for `redacted_claim_keys`, using `cbor2::Value::Simple`;
- tag 60 redacted array elements;
- tag 58 / tag 62 pre-issuance conversion into issued redactions and
  disclosures;
- Salted Disclosed Claim encoding, decoding, and SHA-256 hashing;
- Holder and Verifier restoration modes;
- AEAD encrypted disclosure wire structures and header helpers.

The crate does not generate randomness and does not implement KBT signing
policy for you. Issuers provide 16-byte salts; applications still use
`cose2` to sign and verify SD-CWT and KBT messages.

## Install

```toml
[dependencies]
cose2 = "0.4"
sd-cwt = "0.2"
```

When working from this repository:

```toml
[dependencies]
cose2 = { path = ".." }
sd-cwt = { path = "../sd-cwt" }
```

## Basic flow

The example below shows the core SD-CWT flow without real cryptography:

1. The Holder or client sends a pre-issued claims value with tag 58 redaction
   requests.
2. The Issuer converts it into an issued claims value, creating `sd_claims`.
3. The Issuer signs the redacted payload with `cose2::Sign1Message`.
4. The Holder validates with the strict one-to-one disclosure rule.
5. The Verifier receives a presentation with only selected disclosures and
   removes the rest.

```rust
use cbor2::Value;
use cose2::{Error, Sign1Message};
use sd_cwt::{
    issue_from_preissuance, restore_payload_from_message, set_disclosures,
    set_sd_alg, set_sd_cwt_typ, RedactionHasher, RestoreMode, Sha256RedactionHasher,
    TO_BE_REDACTED_TAG,
};

# struct DemoSigner;
# impl cose2::Signer for DemoSigner {
#     fn alg(&self) -> Option<cose2::Label> { Some(cose2::iana::AlgorithmEdDSA.into()) }
#     fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> { Ok(data.to_vec()) }
# }
# struct DemoVerifier;
# impl cose2::Verifier for DemoVerifier {
#     fn alg(&self) -> Option<cose2::Label> { Some(cose2::iana::AlgorithmEdDSA.into()) }
#     fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
#         if data == signature { Ok(()) } else { Err(Error::verify("signature mismatch")) }
#     }
# }
# fn example() -> Result<(), Error> {
let preissued = Value::Map(vec![
    (Value::from(1), Value::from("https://issuer.example")),
    (
        Value::Tag(TO_BE_REDACTED_TAG, Box::new(Value::from("name"))),
        Value::from("Alice Example"),
    ),
]);

// sd-cwt never generates randomness. Use fresh unpredictable salts in production.
let mut salt_counter = 1u8;
let mut salts = move || {
    let salt = [salt_counter; 16];
    salt_counter += 1;
    salt
};

let issued = issue_from_preissuance(preissued, &mut salts, &Sha256RedactionHasher)?;

let mut msg = Sign1Message::new(Some(cbor2::to_vec(&issued.value)?));
set_sd_cwt_typ(&mut msg.protected);
set_sd_alg(&mut msg.protected, Sha256RedactionHasher.algorithm());
set_disclosures(&mut msg.unprotected, issued.disclosures.as_slice());

let encoded = msg.sign_and_encode(&DemoSigner, None)?;
let verified = Sign1Message::verify_and_decode(&DemoVerifier, &encoded, None)?;
let restored = restore_payload_from_message(&verified, RestoreMode::Holder)?;

assert_eq!(restored.disclosed, 1);
# Ok(())
# }
```

Run the full example:

```sh
cargo run -p sd-cwt --example basic
```

## API by task

| Task                                                            | API                                                                                                        |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Create `simple(59)` redacted map key label                      | `redacted_claim_keys_label()`                                                                              |
| Create tag 60 redacted array element                            | `redacted_element(hash)`                                                                                   |
| Convert tag 58/62 pre-issuance claims into issued SD-CWT claims | `issue_from_preissuance(...)`                                                                              |
| Provide issuance salts                                          | Implement `SaltGenerator`, or pass a `FnMut() -> [u8; 16]`                                                 |
| Build a Salted Disclosed Claim manually                         | `Disclosure::claim`, `Disclosure::element`, `Disclosure::decoy`                                            |
| Read or write `sd_claims`                                       | `disclosures_from_unprotected`, `set_disclosures`, `DisclosureSet::from_unprotected`                       |
| Read or write `sd_alg`                                          | `sd_alg`, `set_sd_alg`, `default_hasher_for_sd_alg`                                                        |
| Restore as Holder                                               | `restore_for_holder` or `restore_payload_from_message(..., RestoreMode::Holder)`                           |
| Restore as Verifier                                             | `restore_for_verifier` or `restore_payload_from_message(..., RestoreMode::Verifier)`                       |
| Handle AEAD encrypted disclosure metadata                       | `AeadEncryptedDisclosure`, `set_aead_encrypted_disclosures`, `aead_encrypted_disclosures_from_unprotected` |

## Holder vs Verifier restoration

`RestoreMode::Holder` is strict. Every redacted claim hash in the payload must
have a matching disclosure, and every disclosure must match a redaction. This
is the mode for issuance-time Holder validation.

`RestoreMode::Verifier` accepts partial disclosure presentations. Disclosures
must still match a redacted claim hash, but redactions without a selected
disclosure are removed from the validated claims set.

In both modes, a disclosure that restores a map key already present at the same
level is rejected.

## Protocol boundaries

- `sd_claims` is an unprotected COSE header parameter. A production
  presentation needs a Key Binding Token (KBT) to bind the selected
  disclosures to the Holder.
- `sd_alg` defaults to SHA-256 (`-16`) when omitted. The built-in helper
  supports SHA-256; profiles using another hash can implement
  `RedactionHasher`.
- AEAD encrypted disclosures are represented by wire structures and header
  helpers. Key selection, key management, and concrete AEAD encryption or
  decryption are profile/application responsibilities.
- Salted disclosures are hashed over their bstr-encoded Salted Disclosed Claim
  bytes. `Disclosure::from_encoded` preserves those exact bytes for hashing.

## Verification

```sh
cargo test -p sd-cwt
cargo run -p sd-cwt --example basic
RUSTDOCFLAGS='-D warnings' cargo doc -p sd-cwt --no-deps
```
