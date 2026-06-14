//! CBOR tag prefixes for COSE structures and helpers to add/strip them.
//!
//! COSE messages may be transported tagged (e.g. `0xd2` for COSE_Sign1) or
//! untagged. These helpers add a tag prefix on encode and tolerate optional
//! prefixes on decode.

/// Fixed prefix of a CWT CBOR tag (`#6.61`).
pub const CWT_PREFIX: &[u8] = &[0xd8, 0x3d];
/// Fixed prefix of a COSE_Encrypt0 tag (`#6.16`).
pub const ENCRYPT0_PREFIX: &[u8] = &[0xd0];
/// Fixed prefix of a COSE_Mac0 tag (`#6.17`).
pub const MAC0_PREFIX: &[u8] = &[0xd1];
/// Fixed prefix of a COSE_Sign1 tag (`#6.18`).
pub const SIGN1_PREFIX: &[u8] = &[0xd2];
/// Fixed prefix of a COSE_Encrypt tag (`#6.96`).
pub const ENCRYPT_PREFIX: &[u8] = &[0xd8, 0x60];
/// Fixed prefix of a COSE_Mac tag (`#6.97`).
pub const MAC_PREFIX: &[u8] = &[0xd8, 0x61];
/// Fixed prefix of a COSE_Sign tag (`#6.98`).
pub const SIGN_PREFIX: &[u8] = &[0xd8, 0x62];
/// Self-described CBOR prefix (`#6.55799`, RFC 8949 §3.4.6).
pub const CBOR_SELF_PREFIX: &[u8] = &[0xd9, 0xd9, 0xf7];

/// Returns `tag` followed by `data`.
pub fn with_tag(tag: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + data.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(data);
    out
}

/// Strips a leading `tag` prefix from `data` if present; otherwise returns
/// `data` unchanged.
pub fn skip_tag<'a>(tag: &[u8], data: &'a [u8]) -> &'a [u8] {
    match data.strip_prefix(tag) {
        Some(rest) => rest,
        None => data,
    }
}

/// Removes a leading self-described CBOR prefix, a CWT tag prefix and any one
/// COSE message tag prefix from `data`.
pub fn remove_cbor_tag(data: &[u8]) -> &[u8] {
    let data = skip_tag(CBOR_SELF_PREFIX, data);
    let data = skip_tag(CWT_PREFIX, data);

    for prefix in [
        SIGN1_PREFIX,
        MAC0_PREFIX,
        ENCRYPT0_PREFIX,
        SIGN_PREFIX,
        MAC_PREFIX,
        ENCRYPT_PREFIX,
    ] {
        if let Some(rest) = data.strip_prefix(prefix) {
            return rest;
        }
    }

    data
}

/// Strips the self-described CBOR and CWT prefixes, then the given COSE
/// message tag prefix if present, leaving the bare message body.
pub(crate) fn untag<'a>(data: &'a [u8], message_prefix: &[u8]) -> &'a [u8] {
    let data = skip_tag(CBOR_SELF_PREFIX, data);
    let data = skip_tag(CWT_PREFIX, data);
    skip_tag(message_prefix, data)
}
