# cose2

CBOR Object Signing and Encryption ([COSE, RFC 9052][cose]) and CBOR Web Token
([CWT, RFC 8392][cwt]) for Rust, built on [`cbor2`][cbor2] and its
`#[derive(cbor2::Cbor)]` macro.

[![crates.io](https://img.shields.io/crates/v/cose2.svg)](https://crates.io/crates/cose2)
[![docs.rs](https://docs.rs/cose2/badge.svg)](https://docs.rs/cose2)

`cose2` models the COSE wire structures and CWT claims and leaves the
cryptography to you: signing, verification, MAC and content encryption are
supplied through the [`Signer`], [`Verifier`], [`Macer`] and [`Encryptor`]
traits, so the default build carries **no cryptographic dependencies**.
Pick any crypto library (e.g. `ed25519-dalek`, `p256`, `aes-gcm`, `hmac`) and
implement the relevant trait.

Enable the optional `crypto-ring` feature (or the aggregate `crypto` feature)
to use the built-in [`crypto`] module backed by [`ring`], or `crypto-aws-lc-rs`
to back it with [`aws-lc-rs`] instead. Both backends expose the same providers
and implement Ed25519/EdDSA, ESP256/ES256, ESP384/ES384, RS256/384/512,
PS256/384/512, HMAC
256/64, HMAC 256/256, HMAC 384/384, HMAC 512/512, A128GCM, A256GCM and
ChaCha20/Poly1305. Algorithms outside the backend's support are rejected at
provider construction. When both backend features are enabled, `crypto-ring`
takes precedence.

Alternatively, enable `crypto-ed25519-dalek` for a standalone Ed25519
`Signer`/`Verifier` (module [`ed25519`]) backed by [`ed25519-dalek`], or
`crypto-aes-gcm` for an AES-GCM (`A128GCM`/`A256GCM`) `Encryptor` (module
[`aes_gcm`]) backed by [`aes-gcm`] — both without a `ring`/`aws-lc-rs`
dependency.

- Typescript version: [https://github.com/ldclabs/cose-ts](https://github.com/ldclabs/cose-ts)
- Golang version: [https://github.com/ldclabs/cose](https://github.com/ldclabs/cose)

## Features

- **Messages** — `COSE_Sign1`, `COSE_Sign`, `COSE_Mac0`, `COSE_Mac`,
  `COSE_Encrypt0`, `COSE_Encrypt`, `COSE_recipient`.
- **Keys** — `COSE_Key` objects (`Key`) and non-empty key sets (`KeySet`) with
  typed accessors for `kty`, `kid`, `alg`, `key_ops` and `Base IV`.
- **Headers** — protected/unprotected `Header` maps with integer or text
  labels and registry constants under [`iana`], including legacy RFC 8152 full
  countersignature parsing and verification.
- **CWT** — typed [`cwt::Claims`], a label-keyed [`cwt::ClaimsMap`], and a
  [`cwt::Validator`] for expiry, not-before, issued-at, issuer and audience.
- **SD-CWT** — the workspace also includes [`sd-cwt`](sd-cwt/README.md), a
  companion crate for selective-disclosure claims, `simple(59)`,
  tag-60 redacted elements, `sd_claims`, and Holder/Verifier restoration.
- **KDF context** — `KdfContext`, `PartyInfo`, `SuppPubInfo` (RFC 9053 §5.2).
- **Tagging** — tagged or untagged COSE messages, with optional CWT and
  self-described CBOR wrappers parsed semantically. `Claims::to_vec` emits the
  untagged claims map used as a COSE payload; `message.to_cwt_vec()` emits the
  RFC 8392 `61(COSE_Tagged(...))` envelope.
- **Optional crypto** — `crypto-ring` or `crypto-aws-lc-rs` provides
  `RingSigner`, `RingVerifier`, `RingMacer` and `RingEncryptor` implementations
  behind a feature flag, backed by `ring` or `aws-lc-rs` respectively.
  `BackendSigner`, `BackendVerifier`, `BackendMacer` and `BackendEncryptor`
  provide backend-neutral aliases for new code.
  `crypto-ed25519-dalek` adds an `Ed25519Signer`/`Ed25519Verifier` backed by
  `ed25519-dalek`, and `crypto-aes-gcm` adds an `AesGcmEncryptor` backed by
  `aes-gcm`.

## Quick start

```rust
use cose2::{iana, Sign1Message, Signer, Verifier, Error};

// Plug in your own crypto. (This toy "signer" is for illustration only.)
struct MySigner;
impl Signer for MySigner {
    fn alg(&self) -> Option<cose2::Label> { Some(iana::AlgorithmEdDSA.into()) }
    fn kid(&self) -> Option<&[u8]> { Some(b"key-1") }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> { /* ... */ Ok(data.to_vec()) }
}
struct MyVerifier;
impl Verifier for MyVerifier {
    fn alg(&self) -> Option<cose2::Label> { Some(iana::AlgorithmEdDSA.into()) }
    fn verify(&self, data: &[u8], sig: &[u8]) -> Result<(), Error> {
        if sig == data { Ok(()) } else { Err(Error::verify("bad signature")) }
    }
}

let mut msg = Sign1Message::new(Some(b"This is the content".to_vec()));
let encoded = msg.sign_and_encode(&MySigner, None)?;

let verified = Sign1Message::verify_and_decode(&MyVerifier, &encoded, None)?;
assert_eq!(verified.payload.as_deref(), Some(&b"This is the content"[..]));
# Ok::<(), cose2::Error>(())
```

## Use the API by task

| Task                       | Start with                                                                            | Notes                                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Sign one embedded payload  | `Sign1Message::sign_and_encode` / `Sign1Message::verify_and_decode`                   | The common COSE_Sign1 flow.                                                                        |
| Sign one detached payload  | `Sign1Message::sign_detached_and_encode` / `Sign1Message::verify_detached_and_decode` | The wire payload is `nil`; carry the payload out of band.                                          |
| Sign with multiple signers | `SignMessage`                                                                         | Each signer has its own `Signature`.                                                               |
| MAC one payload            | `Mac0Message::compute_and_encode` / `Mac0Message::verify_and_decode`                  | Symmetric authentication without recipients.                                                       |
| MAC with recipients        | `MacMessage`                                                                          | Recipient-layer cryptography stays application-owned.                                              |
| Encrypt one payload        | `Encrypt0Message::encrypt_and_encode` / `Encrypt0Message::decrypt_and_decode`         | Requires a full `IV`, or `Partial IV` plus `Encryptor::base_iv`.                                   |
| Encrypt with recipients    | `EncryptMessage`                                                                      | `cose2` validates recipient structure but does not wrap or agree the CEK.                          |
| Async/remote signing       | `prepare_signature` / `prepare_signatures`, then `set_signature` / `set_signatures`   | Sign the returned `Sig_structure` bytes outside the synchronous trait.                             |
| Async/remote MAC           | `prepare_tag` / `prepare_detached_tag`, then `set_tag`                                | MAC the returned `MAC_structure` bytes outside the synchronous trait.                              |
| Async/remote encryption    | `prepare_encryption` then `set_ciphertext`                                            | Encrypt with the returned nonce and `Enc_structure` AAD.                                           |
| Work with CWT claims       | `cwt::Claims`, `cwt::ClaimsMap`, `cwt::Validator`, then `message.to_cwt_vec()`        | `Claims::to_vec` is the untagged payload map; `Claims::extra` preserves custom keys.               |
| Work with SD-CWT claims    | `sd-cwt` companion crate                                                              | Issue tag-58/62 pre-issuance claims, write `sd_claims`, and restore Holder/Verifier presentations. |
| Work with COSE keys        | `Key`, `KeySet`                                                                       | `KeySet::lookup(kid)` returns all matches because `kid` is not unique.                             |

## Runnable examples

These examples are intended as copy/paste starting points for humans and AI
agents:

```sh
cargo run --example custom_crypto_traits
cargo run --example detached_payload
cargo run --example cwt_sign1
cargo run --example sign1_ring --features crypto-ring
cargo run --example mac0_ring --features crypto-ring
cargo run --example encrypt0_ring --features crypto-ring
cargo run -p sd-cwt --example basic
```

For a compact decision checklist — including a [`crypto-ring` algorithm
recipe table][agent-recipes] mapping each algorithm to its required COSE key
parameters — see the [Agent guide for cose2][agent-guide]. Agents modifying this
crate's source should start from [AGENTS.md](AGENTS.md).

Applications upgrading from 0.4 should read [Migrating from cose2 0.4 to
0.5](docs/migration-0.5.md), especially the corrected CWT wrapper and typed
claim changes.

For selective-disclosure credentials, start with the
[`sd-cwt` README](sd-cwt/README.md) and its runnable `basic` example. The
example shows pre-issuance redaction requests, issuer signing with
`Sign1Message`, Holder validation, and Verifier presentation with a disclosure
subset.

## Design notes

- Header, key and claim maps share one ordered type, [`CoseMap`], keyed by
  [`Label`] (`int` / `tstr`). Values are [`cbor2::Value`].
- [`Header`] is a `CoseMap` newtype with typed accessors for common COSE
  parameters (`alg`, `crit`, `kid`, `iv`, `Partial IV`) while still
  dereferencing to the underlying map for custom labels. Message and recipient
  decoding rejects malformed `crit` values and protected/unprotected bucket
  label collisions. Verification and decryption reject unknown critical
  headers unless the provider declares that it processes them.
- [`Key`] requires `kty`; built-in providers enforce `key_ops`. [`KeySet`]
  processes each entry independently as required by RFC 9052;
  `from_slice_strict` is available when one malformed entry should reject the
  entire set. `lookup` returns all matching `kid` values.
- `alg` values in crypto traits are `Option<Label>`, so both registered
  integer algorithms and private text-string algorithms are representable.
- The default build has no crypto dependency. The `crypto-ring` and
  `crypto-aws-lc-rs` features offer ready-to-use providers for the algorithms
  listed above, while unsupported algorithms return an explicit error instead of
  falling back to a mismatched primitive.
- The protected header is captured as raw bytes on decode and reused verbatim
  in the `Sig_structure`/`MAC_structure`/`Enc_structure`, so signatures made
  with non-canonical encodings still verify. Mutating the public protected
  header after those bytes are prepared invalidates the message state;
  `Sign1Message::validate_headers` rechecks it explicitly.
- Decoders enforce protocol wire types, reject duplicate map keys recursively,
  accept semantically equivalent CBOR tag encodings, and require a CWT tag to
  wrap a tagged COSE message. The old `61(claims-map)` form can be read only
  through `Claims::from_slice_legacy_tagged`.
  `Sign1Message::from_slice_with_limits` applies caller-selected depth, item
  and definite-length limits to the whole input.
- Detached payloads are explicit: use `sign_detached*`,
  `compute_detached*`, `verify_detached*`, or `verify_detached_and_decode`.
- Detached ciphertext is explicit: use `encrypt_detached*` and
  `decrypt_detached*` for COSE_Encrypt/COSE_Encrypt0 messages whose ciphertext
  field is encoded as `nil`.
- `Recipient` validates RFC 9052 recipient-layer structure for registered
  direct, key-wrap, key-transport and key-agreement algorithms. Actual key
  wrapping/agreement cryptography remains delegated to application code.
- Encryption requires an explicit plaintext payload; use `Some(Vec::new())`
  for an empty plaintext.
- Newly built protected headers and keys serialize with canonical
  (deterministic) CBOR (RFC 8949 §4.2.1).
- Nonces are taken from the unprotected `IV`, or derived from `Partial IV` by
  XORing the left-padded partial value with [`Encryptor::base_iv`]. This crate
  generates no randomness.

## Testing

`cargo test` runs the unit, integration and doc tests, including a byte-exact
reproduction of the [RFC 9052 Appendix C.4.1][c41] `COSE_Encrypt0` vector.
CI runs formatting, clippy, tests, rustdoc, MSRV, backend-specific builds,
coverage and fuzz-target compilation. The coverage job enforces the threshold
recorded in `.github/workflows/ci.yml`; it does not claim unreachable paths are
covered.

Lightweight performance probes are available with:

```sh
cargo run --release --example benchmark_encoding
cargo run --release -p sd-cwt --example benchmark_restore
```

## License

Licensed under the MIT License.

[cose]: https://datatracker.ietf.org/doc/html/rfc9052
[cwt]: https://datatracker.ietf.org/doc/html/rfc8392
[cbor2]: https://crates.io/crates/cbor2
[ring]: https://crates.io/crates/ring
[`aws-lc-rs`]: https://crates.io/crates/aws-lc-rs
[c41]: https://datatracker.ietf.org/doc/html/rfc9052#appendix-C.4
[`Signer`]: https://docs.rs/cose2/latest/cose2/trait.Signer.html
[`Verifier`]: https://docs.rs/cose2/latest/cose2/trait.Verifier.html
[`Macer`]: https://docs.rs/cose2/latest/cose2/trait.Macer.html
[`Encryptor`]: https://docs.rs/cose2/latest/cose2/trait.Encryptor.html
[`iana`]: https://docs.rs/cose2/latest/cose2/iana/index.html
[`Header`]: https://docs.rs/cose2/latest/cose2/struct.Header.html
[`Key`]: https://docs.rs/cose2/latest/cose2/struct.Key.html
[`KeySet`]: https://docs.rs/cose2/latest/cose2/struct.KeySet.html
[`CoseMap`]: https://docs.rs/cose2/latest/cose2/struct.CoseMap.html
[`Label`]: https://docs.rs/cose2/latest/cose2/enum.Label.html
[`cwt::Claims`]: https://docs.rs/cose2/latest/cose2/cwt/struct.Claims.html
[`cwt::ClaimsMap`]: https://docs.rs/cose2/latest/cose2/cwt/type.ClaimsMap.html
[`cwt::Validator`]: https://docs.rs/cose2/latest/cose2/cwt/struct.Validator.html
[`crypto`]: https://docs.rs/cose2/latest/cose2/crypto/index.html
[`ed25519`]: https://docs.rs/cose2/latest/cose2/ed25519/index.html
[`ed25519-dalek`]: https://crates.io/crates/ed25519-dalek
[`aes_gcm`]: https://docs.rs/cose2/latest/cose2/aes_gcm/index.html
[`aes-gcm`]: https://crates.io/crates/aes-gcm
[agent-guide]: docs/agent-guide.md
[agent-recipes]: docs/agent-guide.md#crypto-ring-algorithm-recipes
