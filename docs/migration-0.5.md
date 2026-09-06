# Migrating from cose2 0.4 to 0.5

Version 0.5 tightens protocol decoding and corrects CWT wire encoding. Inputs
that relied on permissive CBOR coercions now return an error.

## CWT encoding

`Claims::to_vec()` now returns the untagged Claims Set map that belongs in the
COSE payload. After signing, MACing, or encrypting that payload, call the
message's `to_cwt_vec()` method to produce RFC 8392 `61(COSE_Tagged(...))`.

The former `61(claims-map)` representation is available only through
`Claims::to_legacy_tagged_vec()` and `Claims::from_slice_legacy_tagged()` while
stored 0.4 data is migrated.

## Typed claims

`Claims::audience` is now `Option<Audience>` and supports both the single
string and array forms. Time fields use `Option<NumericDate>`, retaining
integer, fractional, and pre-epoch values. Integer construction uses
`NumericDate::from(value)`; finite floats use `NumericDate::from_f64(value)?`.

## Algorithms and key use

Raw Ed25519 constructors now advertise the fully specified IANA Ed25519
identifier (`-19`). Use the explicit `*_with_alg` constructors to read or emit
legacy EdDSA (`-8`). ESP256 (`-9`) and ESP384 (`-51`) are supported by the
shared ring/aws-lc provider.

Built-in providers enforce `key_ops` whenever it is present. A combined MAC or
encryption provider may be constructed with one direction only; a forbidden
method returns `Error::KeyOperation`. `Encryptor` protects COSE message content,
so it requires `Encrypt`/`Decrypt`; `WrapKey`/`UnwrapKey` alone do not authorize
those methods.

## Stricter decoding and lifecycle checks

COSE byte-string fields no longer accept arrays of integers or tagged byte
strings. Duplicate map keys are rejected recursively. CWT tag 61 must wrap a
tagged COSE object. Unknown critical protected headers are rejected during
verification/decryption unless the provider returns them from
`understood_critical_headers()`.

Legacy RFC 8152 full countersignatures (header label 7) can be read and set
with `Header::counter_signatures()` / `Header::set_counter_signatures()` and
verified with `CounterSignature::verify()`. Their creation remains available
for interoperability, although RFC 9338 recommends countersignature V2 for new
protocols.

Mutating a protected header after signing, MACing, encrypting, or decoding now
causes `Error::InvalidState`. Re-run the matching `prepare_*` operation before
attaching new cryptographic output.

`KeySet::from_slice()` now follows RFC 9052 and independently ignores malformed
members. Use `KeySet::from_slice_strict()` for the previous all-or-nothing
behavior.

`Header::content_type()` returns `ContentType`, whose numeric variant is a
`u16` CoAP Content-Format identifier. Decoding rejects negative integers and
values above 65535. Use `ContentType::try_from` when converting wider unsigned
integers. Header serialization also rejects malformed media-type text and a
layer containing both `IV` and `Partial IV`.

Detached `encrypt_detached_and_encode()` transfers ciphertext ownership into
its return value, so the sender message's `ciphertext()` is empty afterward.

Recipient validation now checks complete public ECDH sender keys, including
curve-specific coordinate lengths, absent private material, matching `alg`,
and public-key `key_ops` rules.

## SD-CWT companion crate

`sd-cwt` 0.3 rejects repeated salts, applies one aggregate resource budget to
all plaintext disclosures, validates nested safe-map rules and permitted AEAD
identifiers with their algorithm-specific nonce and tag sizes, and accepts
registered profile media types ending in `+sd-cwt`.
Claims in the protected `CWT_Claims` header participate in restoration and
must agree with duplicate unredacted payload claims. Their restored map is
available as `RestoreReport::protected_claims`.
