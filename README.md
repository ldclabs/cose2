# cose2

CBOR Object Signing and Encryption ([COSE, RFC 9052][cose]) and CBOR Web Token
([CWT, RFC 8392][cwt]) for Rust, built on [`cbor2`][cbor2] and its
`#[derive(cbor2::Cbor)]` macro.

[![crates.io](https://img.shields.io/crates/v/cose2.svg)](https://crates.io/crates/cose2)
[![docs.rs](https://docs.rs/cose2/badge.svg)](https://docs.rs/cose2)

`cose2` models the COSE wire structures and CWT claims and leaves the
cryptography to you: signing, verification, MAC and content encryption are
supplied through the [`Signer`], [`Verifier`], [`Macer`] and [`Encryptor`]
traits, so the crate carries **no cryptographic dependencies** of its own.
Pick any crypto library (e.g. `ed25519-dalek`, `p256`, `aes-gcm`, `hmac`) and
implement the relevant trait.

## Features

- **Messages** — `COSE_Sign1`, `COSE_Sign`, `COSE_Mac0`, `COSE_Mac`,
  `COSE_Encrypt0`, `COSE_Encrypt`, `COSE_recipient`.
- **Keys** — `COSE_Key` objects (`Key`) and key sets (`KeySet`) with typed
  accessors for `kty`, `kid`, `alg`, `key_ops` and `Base IV`.
- **Headers** — protected/unprotected `Header` maps with integer or text
  labels and the full IANA parameter registry under [`iana`].
- **CWT** — typed [`cwt::Claims`], a label-keyed [`cwt::ClaimsMap`], and a
  [`cwt::Validator`] for expiry, not-before, issued-at, issuer and audience.
- **KDF context** — `KdfContext`, `PartyInfo`, `SuppPubInfo` (RFC 9053 §5.2).
- **Tagging** — tagged or untagged messages, with optional CWT and
  self-described CBOR prefixes handled transparently. Newly encoded COSE
  messages and CWT claims use their registered CBOR tags through
  `#[derive(cbor2::Cbor)]`.

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

## Design notes

- Header, key and claim maps share one ordered type, [`CoseMap`], keyed by
  [`Label`] (`int` / `tstr`). Values are [`cbor2::Value`].
- [`Header`] is a `CoseMap` newtype with typed accessors for common COSE
  parameters (`alg`, `kid`, `iv`, `Partial IV`) while still dereferencing to
  the underlying map for custom labels.
- `alg` values in crypto traits are `Option<Label>`, so both registered
  integer algorithms and private text-string algorithms are representable.
- The protected header is captured as raw bytes on decode and reused verbatim
  in the `Sig_structure`/`MAC_structure`/`Enc_structure`, so signatures made
  with non-canonical encodings still verify.
- Top-level COSE message wire types use named Rust structs with
  `#[cbor(tag = ..., array)]`, preserving the COSE array wire shape while
  declaring their IANA CBOR tags. CWT claims declare their IANA CBOR tag with
  `#[cbor(tag = 61)]`. Decoders still accept untagged COSE messages and
  untagged claim maps for compatibility.
- Detached payloads are explicit: use `sign_detached*`,
  `compute_detached*`, `verify_detached*`, or `verify_detached_and_decode`.
- Encryption requires an explicit plaintext payload; use `Some(Vec::new())`
  for an empty plaintext.
- Newly built protected headers and keys serialize with canonical
  (deterministic) CBOR (RFC 8949 §4.2.1).
- IVs are taken from the unprotected header; this crate generates no
  randomness.

## Testing

`cargo test` runs the unit, integration and doc tests, including a byte-exact
reproduction of the [RFC 9052 Appendix C.4.1][c41] `COSE_Encrypt0` vector.
Coverage measured with `cargo llvm-cov` is **100% of lines and functions**;
the remaining uncovered regions are unreachable error-propagation arms on
serialization that cannot fail.

## License

Dual-licensed under MIT or the [UNLICENSE](http://unlicense.org).

[cose]: https://datatracker.ietf.org/doc/html/rfc9052
[cwt]: https://datatracker.ietf.org/doc/html/rfc8392
[cbor2]: https://crates.io/crates/cbor2
[c41]: https://datatracker.ietf.org/doc/html/rfc9052#appendix-C.4
[`Signer`]: https://docs.rs/cose2/latest/cose2/trait.Signer.html
[`Verifier`]: https://docs.rs/cose2/latest/cose2/trait.Verifier.html
[`Macer`]: https://docs.rs/cose2/latest/cose2/trait.Macer.html
[`Encryptor`]: https://docs.rs/cose2/latest/cose2/trait.Encryptor.html
[`iana`]: https://docs.rs/cose2/latest/cose2/iana/index.html
[`Header`]: https://docs.rs/cose2/latest/cose2/struct.Header.html
[`CoseMap`]: https://docs.rs/cose2/latest/cose2/struct.CoseMap.html
[`Label`]: https://docs.rs/cose2/latest/cose2/enum.Label.html
[`cwt::Claims`]: https://docs.rs/cose2/latest/cose2/cwt/struct.Claims.html
[`cwt::ClaimsMap`]: https://docs.rs/cose2/latest/cose2/cwt/type.ClaimsMap.html
[`cwt::Validator`]: https://docs.rs/cose2/latest/cose2/cwt/struct.Validator.html
