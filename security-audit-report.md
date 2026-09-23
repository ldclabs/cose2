# Security and Protocol Review: cose2 0.5

Date: 2026-09-06
Base revision: `847d74aef0217139ec188dd4be5d3a2e10caaaf4`
Scope: the complete `cose2` and `sd-cwt` runtime, public decoders, optional
crypto providers, tests, examples, documentation, packaging, and CI.

The review used RFC 9052, RFC 9053, RFC 8392,
`draft-ietf-spice-sd-cwt-08`, and the IANA COSE registry. The resulting 0.5
working-tree changes close every validated finding below.

## Remediated findings

| Finding | Prior behavior | Remediation | Regression evidence |
| --- | --- | --- | --- |
| SD-CWT stack exhaustion | A chain of shallow disclosures could assemble unbounded recursive depth and abort the process. | `ProcessingLimits` bounds depth, visited items, disclosure count/bytes, and container size before recursion becomes unsafe. | `sd-cwt/tests/hardening.rs::disclosure_chain_hits_limit_without_overflowing_stack` |
| Incorrect CWT tag placement | `Claims::to_vec` emitted `61(claims-map)` inside the COSE payload. | Claims Sets are untagged; every top-level message has `to_cwt_vec` for `61(COSE_Tagged(...))`; legacy storage has explicit compatibility methods. | `tests/context_cwt.rs`, `tests/hardening.rs::cwt_wrapper_is_outside_the_cose_message` |
| Permissive CBOR coercion | Arrays of integers and tagged byte strings could be accepted as protocol `bstr` fields; nested duplicate keys survived. | A strict raw-CBOR layer validates exact wire types, semantic tags, recursive duplicate keys, depth, item count, and complete consumption. | `tests/hardening.rs::message_decoder_enforces_wire_types_and_semantic_tags`, `nested_duplicate_map_keys_are_rejected` |
| Ignored `key_ops` | Built-in sign, verify, MAC, and AEAD providers ignored COSE_Key operation restrictions. | Providers retain `key_ops` and enforce the allowed direction on every operation; exported keys retain or narrow operations appropriately. | `tests/hardening.rs`, `tests/crypto_aws_lc_rs.rs::aws_lc_rs_enforces_key_ops` |
| Protected-header state split | Public parsed headers could differ from the raw bytes used for cryptography while verification still succeeded. | A three-state operation lifecycle and semantic raw/header comparison reject changed protected headers while preserving non-preferred decoded bytes. | `tests/hardening.rs::changing_protected_header_invalidates_authenticated_state`, RFC non-canonical vector tests |
| Missing fully specified signatures | SD-CWT examples and providers used generic EdDSA/ES identifiers and lacked current IANA identifiers. | Added all currently assigned numeric COSE algorithms, Ed25519/ESP256/ESP384 provider support, and fully specified SD-CWT examples. | `tests/core.rs::iana_constants_match_registry`, provider tests, live IANA CI check |
| Incomplete SD-CWT validation | Indefinite CBOR, repeated salts, empty disclosure arrays, illegal map keys/tags, ignored `CWT_Claims`, missing claims, invalid time relationships, and unsafe AEAD metadata could pass helper APIs. | Added strict disclosure parsing, aggregate budgets, `CWT_Claims` restoration/cross-checking, `SdCwtValidator`, combined verify/validate/restore API, draft-required header/claim/time checks, profile content types, and AEAD allow-list/tag checks. | `sd-cwt/tests/hardening.rs` |
| Incomplete recipient validation | Direct, KDF, and ECDH recipient parameter rules were incomplete; empty nested arrays were accepted and protected bytes were lost. | Algorithm classes now enforce zero-length fields, bounded nesting, and required KDF/ECDH parameters. Embedded ECDH sender keys must be valid public EC2/OKP keys without private material. Recipient and KDF structures retain exact protected bytes. | `tests/hardening.rs::recipient_enforces_algorithm_specific_shape_and_preserves_raw_header`, RFC vectors |
| CWT claim type loss | Text keys such as `"exp"` were reinterpreted as integer claim 4; multi-audience, fractional, and pre-epoch dates were rejected. | A dedicated CBOR codec keeps text and integer labels distinct. `Audience` and `NumericDate` model the complete RFC forms without saturating time arithmetic. | `tests/hardening.rs::claims_keep_text_keys_distinct_and_support_full_value_domain`, `tests/context_cwt.rs` |
| `kid` and `alg` routing | `alg` in the unprotected bucket was ignored; optional `kid` was treated as a hard multi-signature gate; automatic `kid` insertion could duplicate a protected value. | Header resolution is protected-first, algorithm values are always compared, and `kid` ranks candidates as a hint with cryptographic verification as the decision. | `tests/hardening.rs::algorithm_resolution_checks_unprotected_and_kid_uses_both_buckets`, multi-signature tests |
| Critical headers not enforced | One-step verification/decryption could succeed with an unknown critical parameter. | Providers declare application critical labels through `understood_critical_headers`; high-level operations reject all others. | `tests/hardening.rs::high_level_verification_enforces_critical_headers` |
| Ed25519 `x`/`d` mismatch | The dalek signer ignored an inconsistent optional public key. | Import recomputes and checks `x` whenever it is present. | `tests/hardening.rs::dalek_rejects_mismatched_private_and_public_key` |
| KeySet behavior | Default decoding rejected a whole set for one malformed member, contrary to RFC 9052 independent processing. | Default decode keeps valid members; `from_slice_strict` preserves all-or-nothing behavior. | `tests/core.rs::keyset_decode_is_rfc_compliant_by_default_and_has_strict_option` |

## Performance and dependency hardening

- Authenticated structures serialize borrowed byte slices rather than allocating
  a dynamic `Value` tree and copying payload/AAD buffers.
- Message encoders canonicalize small map-containing fragments, then stream
  large payload and ciphertext byte strings into exactly sized output buffers.
- Embedded decryption no longer copies the stored ciphertext; ring in-place
  decryption returns its existing buffer after truncation.
- Detached encrypt-and-encode transfers ciphertext ownership to the caller.
- SD-CWT duplicate detection uses hash sets rather than repeated linear scans.
- Crypto provider clones share retained secret material and cipher state.
- AES-GCM disables unused default RNG support and enables zeroization for its
  expanded cipher state. The default cose2 feature set remains crypto-free.

On the review host, the supplied probes measured authenticated-structure
encoding about 30% faster for a small payload and 55–65% faster for 64 KiB to
1 MiB payloads. An 8,000-key SD-CWT restore fell from roughly 83 ms to roughly
0.4 ms, with linear rather than quadratic growth. These are microbenchmarks and
absolute timings are machine-dependent.

## Remaining protocol boundary

`sd-cwt` validates disclosure mechanics and draft structure but still does not
implement KBT signing, confirmation-key trust, certificate validation, nonce
freshness storage, expected identity/audience policy, current-time policy, or
application privacy policy. Those operations require application keys, trust
anchors, and transaction state. The combined
`verify_validate_and_restore_sd_cwt` API verifies the issuer signature and
performs the draft structural and disclosure checks supported by its inputs.

## Verification gates

The repository requires formatting, clippy with warnings denied, full tests,
rustdoc with warnings denied, the Rust 1.89 MSRV, aws-lc-rs-only checks,
standalone backend checks, package construction, fuzz-target compilation,
coverage, IANA registry comparison, and a RustSec dependency audit. CI now
contains matching jobs and an 85% minimum line-coverage gate.

## Follow-up review: 2026-09-23

The follow-up fixes five remaining inconsistencies: registered SD-CWT claim
redaction policy now applies only at Claims Map roots; duplicate structured
claims are compared after disclosure restoration and before unmatched hashes
are removed; protected-header CBOR receives its own definite-length check;
issuance and restoration share text-key validation; and cryptographic message
operations recheck mutable protected/unprotected header buckets.

Protected-state checks now compare canonical bytes first, while preserving the
semantic fallback for nonpreferred wire encodings. Private message wire types
decode byte strings directly after strict shape validation, and ring/aws-lc
encryption reserves room for the authentication tag before copying plaintext.
The encoding probe now also measures full message decoding.

Regression coverage is in `tests/validation_state.rs` and
`sd-cwt/tests/hardening.rs`. Release publishing now declares its configured
environment and skips existing package versions when rerun; the publisher is
tested with simulated registry and Cargo responses, without uploading crates.
