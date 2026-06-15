# Agent guide for cose2

This guide is for AI coding agents and code-generation tools that need to use
`cose2` without rediscovering the COSE and CWT protocol shape from scratch.

> Modifying this crate's own source? See [AGENTS.md](../AGENTS.md) for repository
> conventions, build/test/lint commands, and invariants to preserve.

## First decision

| Task | Use this API | Notes |
| --- | --- | --- |
| Sign one embedded payload | `Sign1Message::sign_and_encode` and `Sign1Message::verify_and_decode` | Most common COSE signature shape. |
| Sign one detached payload | `Sign1Message::sign_detached_and_encode` and `Sign1Message::verify_detached_and_decode` | The wire payload is `nil`; transport the payload separately. |
| Sign with multiple signers | `SignMessage` | Each signer gets its own `Signature`. |
| MAC one payload | `Mac0Message::compute_and_encode` and `Mac0Message::verify_and_decode` | Use for symmetric authentication without recipients. |
| MAC with recipients | `MacMessage` | Recipient-layer key distribution remains application-owned. |
| Encrypt one payload | `Encrypt0Message::encrypt_and_encode` and `Encrypt0Message::decrypt_and_decode` | Requires `IV`, or `Partial IV` plus `Encryptor::base_iv`. |
| Encrypt with recipients | `EncryptMessage` | `cose2` models recipients but does not perform CEK wrapping/agreement. |
| Encode or validate CWT claims | `cwt::Claims`, `cwt::ClaimsMap`, `cwt::Validator` | `Claims` preserves the registered typed subset. Use `ClaimsMap` for custom claims. |
| Store COSE keys | `Key` and `KeySet` | `KeySet::lookup(kid)` returns an iterator because `kid` is not unique. |

## Feature selection

- Default features are empty. The default build has no cryptographic backend.
- Use the `Signer`, `Verifier`, `Macer`, and `Encryptor` traits when the
  application already owns cryptography.
- Enable `crypto-ring` or aggregate `crypto` to use `RingSigner`,
  `RingVerifier`, `RingMacer`, and `RingEncryptor`.
- Do not add an always-on crypto dependency to this crate. Optional crypto
  providers belong behind feature flags.

## Crypto-ring algorithm recipes

These tables describe the built-in `crypto-ring` providers. They are the source
of the two mistakes agents make most often: choosing the wrong `iana` algorithm
constant, and omitting a required COSE key parameter. All constants live in the
[`iana`](https://docs.rs/cose2/latest/cose2/iana/index.html) module and are
plain `i64` values.

`from_cose_key` requires the key's `alg` to be a registered **integer**
algorithm; private text-string algorithms are rejected by the ring backend.

### Signatures — `RingSigner` / `RingVerifier`

| Algorithm | `iana` algorithm constant | `kty` | `crv` | Signer key params (private) | Verifier key params (public) |
| --- | --- | --- | --- | --- | --- |
| EdDSA (Ed25519) | `AlgorithmEdDSA` | `KeyTypeOKP` | `EllipticCurveEd25519` | `d`, `x` | `x` |
| ES256 | `AlgorithmES256` | `KeyTypeEC2` | `EllipticCurveP_256` | `d`, `x`, `y` | `x`, `y` |
| ES384 | `AlgorithmES384` | `KeyTypeEC2` | `EllipticCurveP_384` | `d`, `x`, `y` | `x`, `y` |
| RS256 / RS384 / RS512 | `AlgorithmRS256` / `AlgorithmRS384` / `AlgorithmRS512` | `KeyTypeRSA` | — | `n`, `e`, `d`, `p`, `q`, `dP`, `dQ`, `qInv` | `n`, `e` |
| PS256 / PS384 / PS512 | `AlgorithmPS256` / `AlgorithmPS384` / `AlgorithmPS512` | `KeyTypeRSA` | — | `n`, `e`, `d`, `p`, `q`, `dP`, `dQ`, `qInv` | `n`, `e` |

Key-parameter constants: `OKPKeyParameterD` / `OKPKeyParameterX`,
`EC2KeyParameterD` / `EC2KeyParameterX` / `EC2KeyParameterY`,
`RSAKeyParameterN` / `E` / `D` / `P` / `Q` / `DP` / `DQ` / `QInv`. ECDSA `x`/`y`
are the raw affine coordinates; the provider builds the uncompressed SEC1 point.

Non-key constructors also exist: `RingSigner::ed25519_from_pkcs8`,
`es256_from_pkcs8`, `es384_from_pkcs8`, `rsa_from_pkcs8`, `rsa_from_der`;
`RingVerifier::ed25519`, `ecdsa`, `rsa_components`, `rsa_der`.

### MAC — `RingMacer` (`kty = KeyTypeSymmetric`, key param `k`)

| Algorithm | `iana` algorithm constant | Tag length |
| --- | --- | --- |
| HMAC 256/64 | `AlgorithmHMAC_256_64` | 8 bytes |
| HMAC 256/256 | `AlgorithmHMAC_256_256` | 32 bytes |
| HMAC 384/384 | `AlgorithmHMAC_384_384` | 48 bytes |
| HMAC 512/512 | `AlgorithmHMAC_512_512` | 64 bytes |

### AEAD content encryption — `RingEncryptor` (`kty = KeyTypeSymmetric`, key param `k`)

| Algorithm | `iana` algorithm constant | Key size | Nonce (IV) size |
| --- | --- | --- | --- |
| A128GCM | `AlgorithmA128GCM` | 16 bytes | 12 bytes |
| A256GCM | `AlgorithmA256GCM` | 32 bytes | 12 bytes |
| ChaCha20/Poly1305 | `AlgorithmChaCha20Poly1305` | 32 bytes | 12 bytes |

The symmetric key byte string is `SymmetricKeyParameterK`. For `Partial IV`
support, set the key's `Base IV` (`KeyParameterBaseIV`) or call
`RingEncryptor::with_base_iv`; otherwise supply a full 12-byte `IV`.

Constructors taking raw bytes: `RingMacer::new(alg, key, kid)`,
`RingEncryptor::new(alg, key, kid)`.

## Copy-paste starting points

Run these examples from the repository root:

```sh
cargo run --example custom_crypto_traits
cargo run --example detached_payload
cargo run --example cwt_sign1
cargo run --example sign1_ring --features crypto-ring
cargo run --example mac0_ring --features crypto-ring
cargo run --example encrypt0_ring --features crypto-ring
```

Use `examples/custom_crypto_traits.rs` when integrating another crypto library.
Use the `*_ring.rs` examples when the built-in `ring` backend is acceptable.

## Protocol rules agents should not guess

- `external_aad` must match on creation and verification/decryption. Passing
  `None` is equivalent to an empty byte string, not to "ignore AAD".
- Protected header parameters are authenticated. Unprotected `kid` is only a
  key hint and is not globally unique.
- Decoding validates malformed `crit` and protected/unprotected label
  collisions. For untrusted messages, applications must still call
  `Header::ensure_crit_understood` with the private critical labels they
  understand.
- `cose2` does not generate randomness or nonces. Encryption needs a full `IV`
  or a `Partial IV` combined with the encryptor's Base IV. Never reuse an AEAD
  nonce with the same key.
- Recipient structures are validated for known algorithm classes, but key wrap,
  key transport, ECDH agreement, and recipient-layer cryptography are
  application code.
- Detached payloads and detached ciphertext are explicit APIs. Do not encode
  `None` manually and then call the embedded-payload helpers.
- Top-level COSE messages use registered CBOR tags when encoded. Decoders accept
  untagged messages for compatibility.
- Header, key, and claim maps use `Label` keys and `cbor2::Value` values. Use
  typed accessors where they exist.

## Verification commands

Use these before proposing a generated change:

```sh
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
```

For quick example-only checks:

```sh
cargo run --example custom_crypto_traits
cargo run --example detached_payload
cargo run --example cwt_sign1
cargo run --example sign1_ring --features crypto-ring
cargo run --example mac0_ring --features crypto-ring
cargo run --example encrypt0_ring --features crypto-ring
```
