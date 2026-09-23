//! CBOR tag prefixes for COSE structures and helpers to add/strip them.
//!
//! COSE messages may be transported tagged or untagged. Encoding uses the
//! preferred tag bytes below; decoding compares semantic tag numbers and also
//! accepts valid non-preferred CBOR encodings.

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

pub(crate) const CWT_ENCRYPT0_PREFIX: &[u8] = &[0xd8, 0x3d, 0xd0];
pub(crate) const CWT_MAC0_PREFIX: &[u8] = &[0xd8, 0x3d, 0xd1];
pub(crate) const CWT_SIGN1_PREFIX: &[u8] = &[0xd8, 0x3d, 0xd2];
pub(crate) const CWT_ENCRYPT_PREFIX: &[u8] = &[0xd8, 0x3d, 0xd8, 0x60];
pub(crate) const CWT_MAC_PREFIX: &[u8] = &[0xd8, 0x3d, 0xd8, 0x61];
pub(crate) const CWT_SIGN_PREFIX: &[u8] = &[0xd8, 0x3d, 0xd8, 0x62];

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

/// Removes a leading self-described CBOR tag, CWT tag and one known COSE tag.
/// Malformed or multi-item input is returned unchanged.
pub fn remove_cbor_tag(data: &[u8]) -> &[u8] {
    crate::strict::remove_known_tags(data).unwrap_or(data)
}

/// Validates semantic wrapper tags and returns the untagged COSE array body.
///
/// The strict pass rejects duplicate map keys at every depth, so wire decoders
/// may read header maps from the returned body without validating them again.
pub(crate) fn message_body(data: &[u8], expected_tag: u64) -> Result<&[u8], crate::Error> {
    message_body_with_limits(data, expected_tag, crate::CborLimits::default())
}

/// [`message_body`] with caller-selected parser limits.
pub(crate) fn message_body_with_limits(
    data: &[u8],
    expected_tag: u64,
    limits: crate::CborLimits,
) -> Result<&[u8], crate::Error> {
    crate::strict::message_body(data, expected_tag, limits)
}
