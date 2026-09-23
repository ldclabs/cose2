# AGENTS.md

Guidance for AI coding agents working **in this repository**. If you are an
agent trying to **use `cose2` as a dependency**, read
[docs/agent-guide.md](docs/agent-guide.md) first — it has the per-task API
decision table and the protocol rules you should not guess.

## What this is

This workspace contains two crates:

- `cose2`: COSE ([RFC 9052][cose]) and CWT ([RFC 8392][cwt]), built on
  [`cbor2`][cbor2]. It models wire structures and delegates cryptography to
  caller-supplied traits. Its default build has **no cryptographic dependencies**.
- `sd-cwt`: selective-disclosure helpers implementing
  `draft-ietf-spice-sd-cwt-08`. It depends on `cose2` and uses SHA-256 for
  disclosure hashing. Read [sd-cwt/README.md](sd-cwt/README.md) for its protocol
  boundaries.

- Edition 2021, MSRV **1.89** (`rust-version` in `Cargo.toml`).
- `cose2` has `#![forbid(unsafe_code)]`; keep all repository code safe Rust.

## Setup and verification

There is no codegen or build step beyond Cargo. Use `--workspace` to include
`sd-cwt`; Cargo commands at the repository root otherwise default to `cose2`.
The release scripts and their tests require Python 3.11+ (`tomllib`). Run these
before proposing changes; CI (`.github/workflows/ci.yml`) runs the same set:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Quick example smoke test:

```sh
cargo run --example custom_crypto_traits
cargo run --example sign1_ring --features crypto-ring
cargo run -p sd-cwt --example basic
```

`--all-targets` does not run doctests; keep the separate `--doc` command.
For changes affecting feature gates or providers, also lint and test the
affected backend alone. In particular, `--all-features` never exercises the
aws-lc-rs implementation because ring takes precedence:

```sh
cargo clippy -p cose2 --no-default-features --features crypto-aws-lc-rs --all-targets -- -D warnings
cargo test -p cose2 --no-default-features --features crypto-aws-lc-rs --all-targets
```

Use the same commands with `crypto-ed25519-dalek` or `crypto-aes-gcm` for their
standalone builds. Other checks, when the affected area warrants them:

```sh
cargo +1.89 test --workspace --all-targets --all-features
cargo build -p cose2 --no-default-features
cargo tree -p cose2 --no-default-features -e normal
cargo check --manifest-path fuzz/Cargo.toml --locked
cargo llvm-cov --workspace --all-targets --all-features --fail-under-lines 85
```

The default `cose2` dependency tree must not contain `ring`, `aws-lc-rs`,
`ed25519-dalek`, or `aes-gcm`. Fuzz-target compilation is a build check, not a
fuzzing run. CI also checks package contents, RustSec advisories and the IANA
algorithm registry; report which checks actually ran.

## Feature flags

- `default = []` — no crypto backend. The pluggable traits are always available.
- `crypto-ring` — `ring`-based `RingSigner` / `RingVerifier` / `RingMacer` /
  `RingEncryptor` (module `crypto`).
- `crypto-aws-lc-rs` — the same providers backed by `aws-lc-rs` instead of
  `ring`. The two backends share `src/crypto.rs` via a `use ring as backend` /
  `use aws_lc_rs as backend` alias; a handful of API differences are bridged
  with `#[cfg]` arms. When both features are enabled, `crypto-ring` wins.
- `crypto` — aggregate alias that currently enables `crypto-ring`.
- `crypto-ed25519-dalek` — standalone `Ed25519Signer` / `Ed25519Verifier`
  (module `ed25519`).
- `crypto-aes-gcm` — standalone `AesGcmEncryptor` (module `aes_gcm`).

## Repository layout

| Path | Contents |
| --- | --- |
| `src/lib.rs` | Crate root and public re-exports. |
| `src/iana.rs` | IANA constants for algorithms, key parameters, claims and tags. |
| `src/label.rs`, `src/map.rs` | `Label` (`int`/`tstr`) and the shared `CoseMap`. |
| `src/header.rs`, `src/key.rs` | `Header`; `Key` / `KeySet`. |
| `src/sign1.rs`, `src/sign.rs` | `Sign1Message`; `SignMessage` / `Signature`. |
| `src/mac0.rs`, `src/mac.rs` | `Mac0Message`; `MacMessage`. |
| `src/encrypt0.rs`, `src/encrypt.rs` | `Encrypt0Message`; `EncryptMessage`. |
| `src/recipient.rs`, `src/context.rs` | `Recipient`; `KdfContext` / `PartyInfo` / `SuppPubInfo`. |
| `src/traits.rs` | `Signer` / `Verifier` / `Macer` / `Encryptor`. |
| `src/cwt.rs` | `Claims`, `Audience`, `NumericDate`, `ClaimsMap` and `Validator`. |
| `src/crypto.rs` | Shared ring/aws-lc-rs providers, also exposed through `Backend*` aliases. |
| `src/ed25519.rs`, `src/aes_gcm.rs` | Standalone cryptographic providers. |
| `src/strict.rs`, `src/countersign.rs` | Strict CBOR checks; legacy full countersignatures. |
| `src/error.rs`, `src/tag.rs`, `src/util.rs` | Errors, CBOR-tag handling and message helpers. |
| `tests/hardening.rs`, `tests/validation_state.rs` | Protocol, mutable-state and decoder regressions. |
| `tests/rfc_examples.rs`, `tests/crypto_*.rs` | RFC vectors and backend coverage. |
| `fuzz/fuzz_targets/` | COSE decode and SD-CWT fuzz targets; separate Cargo workspace. |
| `scripts/check_iana_algorithms.py` | Compare algorithm constants with an IANA XML snapshot. |
| `scripts/publish_crates.py`, `scripts/test_publish_crates.py` | Repeatable publishing and mocked release tests. |
| `examples/`, `docs/` | Runnable examples, consumer guide and migration notes. |

`sd-cwt` keeps its public API at the crate root; its processing modules are
private. Preserve the root re-exports when moving code:

| Path | Contents |
| --- | --- |
| `sd-cwt/src/lib.rs` | Public exports, constants, header helpers, encrypted-disclosure metadata and shared limits. |
| `sd-cwt/src/disclosure.rs` | Disclosure encoding/decoding, hashing and plaintext disclosure headers. |
| `sd-cwt/src/issuance.rs` | Salt provider and pre-issuance redaction/decoy conversion. |
| `sd-cwt/src/restore.rs` | Disclosure matching, bounded restoration and pruning. |
| `sd-cwt/src/validation.rs` | Envelope/claim validation and combined signature-verification API. |
| `sd-cwt/src/tests.rs`, `sd-cwt/tests/hardening.rs` | Unit tests and protocol regressions. |

## Invariants to preserve

Do not regress these — they are correctness/compatibility contracts, and several
are load-bearing for cryptographic soundness:

1. **No `unsafe`.** The crate is `#![forbid(unsafe_code)]`.
2. **The default `cose2` build stays crypto-free.** Crypto dependencies belong
   behind the backend feature flags. The companion `sd-cwt` crate's SHA-256
   dependency is intentional.
3. **Reuse decoded protected-header bytes verbatim.** The raw protected header
   captured on decode is fed back into `Sig_structure` / `MAC_structure` /
   `Enc_structure` so signatures over non-canonical encodings still verify. Do
   not re-encode it.
4. **Newly built protected headers and keys serialize canonically** (RFC 8949
   §4.2.1) via `cbor2::to_canonical_vec`.
5. **Message APIs generate no keys or encryption nonces.** Encryption takes a full
   `IV`, or a `Partial IV` combined with `Encryptor::base_iv`. Optional signing
   backends use their own RNG for ECDSA/RSA signature operations.
6. **`external_aad: None` means an empty byte string**, not "ignore AAD". It must
   match on create and verify/decrypt.
7. **Detached payload / detached ciphertext are explicit APIs** (`*_detached*`).
   Do not hand-encode `nil` and call the embedded helpers.
8. **Keep tests green and coverage high.** CI enforces the line threshold in
   `.github/workflows/ci.yml`; new protocol paths need positive and negative
   tests in `tests/` or inline.
9. **`clippy -D warnings`, `rustdoc -D warnings`, and `rustfmt` must all pass.**
10. **Recheck mutable header buckets at crypto entry points.** Public headers
    can change after decoding. Verification/decryption must reject bucket
    collisions, misplaced `crit` and conflicting IV parameters, just as encoding
    does. Unknown critical headers require explicit provider support; built-in
    providers must enforce imported `key_ops` restrictions.
11. **Keep CWT wrappers outside claims.** `Claims::to_vec` encodes an untagged
    map; `message.to_cwt_vec()` emits `61(COSE_Tagged(...))`. The old
    `61(claims-map)` form has explicit legacy helpers.

## SD-CWT rules

- Work against the draft revision declared by the crate, currently draft-08.
  Keep protocol changes consistent with its README, examples and regressions.
- Registered claims that must never be redacted are checked at the payload and
  protected `CWT_Claims` roots. The same numeric keys in application maps nested
  inside claims do not acquire registered-claim semantics.
- Compare duplicate structured claims after restoring available disclosures.
  Keep unmatched markers until comparison finishes, then prune them for Verifier
  mode. Different salts/hashes are not proof of different original values;
  reject visible conflicts. Holder mode requires every redaction to be matched.
- Apply definite-length CBOR checks to embedded protected-header bytes and
  encoded payloads/disclosures as well as the outer COSE message. Ordinary COSE
  still accepts valid nonpreferred and indefinite-length encodings.
- Issuance and restoration must agree on allowed keys, including the 1–255
  **octet** text-key limit. Preserve disclosure bytes exactly for hashing, require
  unique salts, and enforce `ProcessingLimits` across traversal/restoration.
- Restore-only helpers do not verify issuer signatures. The combined
  `verify_validate_and_restore_sd_cwt` API verifies the issuer and checks draft
  structure. KBT/holder binding, trust, current-time/identity policy and concrete
  encrypted-disclosure cryptography remain application responsibilities.

## Performance and code structure

- Keep private message Wire decoders behind `tag::message_body`'s strict shape
  validation, which also rejects duplicate map keys at every depth. Their
  direct `serde_bytes` decoding avoids an intermediate copy, and their header
  maps use `header::deserialize_checked` instead of a second strict pass;
  independently deserializable types still need strict byte-string handling.
- `CoseMap::to_vec` writes deterministic CBOR without copying the map into a
  dynamic `Value`. Its output must stay byte-identical to
  `cbor2::to_canonical_vec`; extend
  `tests/hardening.rs::map_encoding_matches_cbor2_deterministic_encoding` when
  changing it.
- Message modules share `util::prepare_headers`, `util::sync_protected_raw`
  and `header::validate_layer` for the prepare, attach-result and recheck
  steps. One-step operations store their result directly after `prepare_*`
  instead of repeating the validation in `set_*`.
- Protected-state checks compare canonical bytes first and retain a semantic
  fallback for decoded nonpreferred encodings. Never replace authenticated raw
  bytes as part of this optimization.
- Prefer borrowed serialization and appropriately sized buffers for large
  payloads/ciphertexts. Reuse existing header/algorithm helpers; keep small,
  explicit protocol modules instead of introducing a generic message framework.
- Measure encoding, decoding and restoration separately with the supplied
  probes. Report measured scope rather than extrapolating a helper's speedup to
  the entire library:

```sh
cargo run --release --example benchmark_encoding
cargo run --release -p sd-cwt --example benchmark_restore
```

## Adding a backend algorithm

The provider→algorithm mapping lives in the helper functions at the bottom of
`src/crypto.rs` (`hmac_algorithm`, `aead_algorithm`, `ecdsa_verification_algorithm`,
`rsa_signing_algorithm`, `rsa_verification_algorithm`). Unsupported algorithms
must return an explicit `unsupported_alg(...)` error rather than silently falling
back to a different primitive. Add the algorithm to
[docs/agent-guide.md](docs/agent-guide.md#crypto-ring-algorithm-recipes) and a
round-trip test in `tests/crypto_ring.rs`.

`src/crypto.rs` is shared by both backends. When modifying it, run the isolated
aws-lc-rs checks above as well as the all-features suite. Add backend-specific
regressions to `tests/crypto_aws_lc_rs.rs` when needed. Ed25519 COSE private-key
import requires both `d` and matching `x` for ring/aws-lc-rs; the standalone
dalek importer can derive an omitted `x`.

## Packaging and releases

- `.github/workflows/release.yml` runs on pushed `v*` tags, uses the `release`
  GitHub environment and authenticates to crates.io through Trusted Publishing.
  Its environment must match the crates.io publisher configuration.
- `scripts/publish_crates.py` reads package versions from both manifests and
  publishes `cose2` before `sd-cwt`. It skips existing versions and rechecks the
  registry between retries, allowing recovery from partial publication.
- `python3 scripts/publish_crates.py --dry-run` reads registry state without
  uploading. Running it without `--dry-run` publishes packages. Script tests
  mock both the registry and Cargo and perform no uploads.
- `cargo package -p cose2` verifies the main package. CI uses
  `cargo package -p sd-cwt --list` to check its archive contents while the
  required `cose2` version may not yet be available in the registry; that list
  check does not verify the packaged companion crate's build.

[cose]: https://datatracker.ietf.org/doc/html/rfc9052
[cwt]: https://datatracker.ietf.org/doc/html/rfc8392
[cbor2]: https://crates.io/crates/cbor2
