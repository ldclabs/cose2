# AGENTS.md

Guidance for AI coding agents working **in this repository**. If you are an
agent trying to **use `cose2` as a dependency**, read
[docs/agent-guide.md](docs/agent-guide.md) first — it has the per-task API
decision table and the protocol rules you should not guess.

## What this is

`cose2` is a Rust library for COSE ([RFC 9052][cose]) and CWT
([RFC 8392][cwt]), built on [`cbor2`][cbor2]. It models the wire structures and
delegates cryptography to caller-supplied trait implementations, so the default
build has **no cryptographic dependencies**.

- Edition 2021, MSRV **1.89** (`rust-version` in `Cargo.toml`).
- `#![forbid(unsafe_code)]`.

## Setup and verification

There is no codegen or build step beyond Cargo. Run these before proposing any
change; CI (`.github/workflows/ci.yml`) runs the same set:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
```

Quick example smoke test:

```sh
cargo run --example custom_crypto_traits
cargo run --example sign1_ring --features crypto-ring
```

## Feature flags

- `default = []` — no crypto backend. The pluggable traits are always available.
- `crypto-ring` — `ring`-based `RingSigner` / `RingVerifier` / `RingMacer` /
  `RingEncryptor` (module `crypto`).
- `crypto-aws-lc-rs` — the same providers backed by `aws-lc-rs` instead of
  `ring`. The two backends share `src/crypto.rs` via a `use ring as backend` /
  `use aws_lc_rs as backend` alias; a handful of API differences are bridged
  with `#[cfg]` arms. When both features are enabled, `crypto-ring` wins.
- `crypto` — aggregate alias that currently enables `crypto-ring`.

## Repository layout

| Path                                        | Contents                                                        |
| ------------------------------------------- | --------------------------------------------------------------- |
| `src/lib.rs`                                | Crate root and public re-exports.                               |
| `src/iana.rs`                               | IANA registry constants (algorithms, key params, claims, tags). |
| `src/label.rs`, `src/map.rs`                | `Label` (`int`/`tstr`) and the shared `CoseMap`.                |
| `src/header.rs`, `src/key.rs`               | `Header`; `Key` / `KeySet`.                                     |
| `src/sign1.rs`, `src/sign.rs`               | `Sign1Message`; `SignMessage` / `Signature`.                    |
| `src/mac0.rs`, `src/mac.rs`                 | `Mac0Message`; `MacMessage`.                                    |
| `src/encrypt0.rs`, `src/encrypt.rs`         | `Encrypt0Message`; `EncryptMessage`.                            |
| `src/recipient.rs`, `src/context.rs`        | `Recipient`; `KdfContext` / `PartyInfo` / `SuppPubInfo`.        |
| `src/traits.rs`                             | `Signer` / `Verifier` / `Macer` / `Encryptor`.                  |
| `src/cwt.rs`                                | `Claims` / `ClaimsMap` / `Validator`.                           |
| `src/crypto.rs`                             | Built-in providers (`crypto-ring` / `crypto-aws-lc-rs`).        |
| `src/error.rs`, `src/tag.rs`, `src/util.rs` | `Error`; CBOR-tag helpers; internal helpers.                    |
| `examples/`, `tests/`, `docs/`              | Runnable examples, integration tests, the consumer agent guide. |

## Invariants to preserve

Do not regress these — they are correctness/compatibility contracts, and several
are load-bearing for cryptographic soundness:

1. **No `unsafe`.** The crate is `#![forbid(unsafe_code)]`.
2. **Default build stays crypto-free.** Any crypto dependency must live behind a
   feature flag (`crypto-ring` / `crypto-aws-lc-rs`). Never add an always-on
   crypto dep.
3. **Reuse decoded protected-header bytes verbatim.** The raw protected header
   captured on decode is fed back into `Sig_structure` / `MAC_structure` /
   `Enc_structure` so signatures over non-canonical encodings still verify. Do
   not re-encode it.
4. **Newly built protected headers and keys serialize canonically** (RFC 8949
   §4.2.1) via `cbor2::to_canonical_vec`.
5. **The crate generates no randomness or nonces.** Encryption takes a full `IV`,
   or a `Partial IV` combined with `Encryptor::base_iv`.
6. **`external_aad: None` means an empty byte string**, not "ignore AAD". It must
   match on create and verify/decrypt.
7. **Detached payload / detached ciphertext are explicit APIs** (`*_detached*`).
   Do not hand-encode `nil` and call the embedded helpers.
8. **Keep tests green and coverage high.** The suite targets 100% of lines and
   functions (`cargo llvm-cov`); the only uncovered arms are unreachable
   serialization error paths. New code paths need tests in `tests/` or inline.
9. **`clippy -D warnings`, `rustdoc -D warnings`, and `rustfmt` must all pass.**

## Adding a backend algorithm

The provider→algorithm mapping lives in the helper functions at the bottom of
`src/crypto.rs` (`hmac_algorithm`, `aead_algorithm`, `ecdsa_verification_algorithm`,
`rsa_signing_algorithm`, `rsa_verification_algorithm`). Unsupported algorithms
must return an explicit `unsupported_alg(...)` error rather than silently falling
back to a different primitive. Add the algorithm to
[docs/agent-guide.md](docs/agent-guide.md#crypto-ring-algorithm-recipes) and a
round-trip test in `tests/crypto_ring.rs`.

`src/crypto.rs` is shared by both backends. `--all-features` builds run against
`ring` (it wins when both features are on), so the `aws-lc-rs`-only `#[cfg]` arms
are exercised separately by `tests/crypto_aws_lc_rs.rs` under
`cargo test --no-default-features --features crypto-aws-lc-rs`. When you touch a
backend-specific arm, run that command too.

[cose]: https://datatracker.ietf.org/doc/html/rfc9052
[cwt]: https://datatracker.ietf.org/doc/html/rfc8392
[cbor2]: https://crates.io/crates/cbor2
