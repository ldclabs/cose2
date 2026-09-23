//! Strict CBOR helpers for protocol fields whose wire type matters.

use std::{borrow::Cow, collections::HashSet};

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Value};

pub(crate) const DEFAULT_MAX_DEPTH: usize = 128;
pub(crate) const DEFAULT_MAX_ITEMS: usize = 100_000;

/// Resource and encoding limits for strict CBOR validation.
#[derive(Clone, Copy, Debug)]
pub struct CborLimits {
    /// Maximum nested containers/tags.
    pub max_depth: usize,
    /// Maximum total decoded CBOR items.
    pub max_items: usize,
    /// Reject every indefinite-length string, array, or map.
    pub require_definite: bool,
}

impl Default for CborLimits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_items: DEFAULT_MAX_ITEMS,
            require_definite: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Unsigned,
    Negative,
    Bytes,
    Text,
    Array,
    Map,
    Tag(u64),
    Simple(u8),
    Float,
}

#[derive(Debug)]
struct Item {
    kind: Kind,
    start: usize,
    content_start: usize,
    end: usize,
    indefinite: bool,
    children: Vec<Item>,
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
    items: usize,
    limits: CborLimits,
    reject_duplicate_keys: bool,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8], limits: CborLimits, reject_duplicate_keys: bool) -> Self {
        Self {
            data,
            pos: 0,
            items: 0,
            limits,
            reject_duplicate_keys,
        }
    }

    fn err(&self, message: impl Into<String>) -> Error {
        Error::Cbor(format!("{} at byte {}", message.into(), self.pos))
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let byte = *self
            .data
            .get(self.pos)
            .ok_or_else(|| self.err("unexpected end of CBOR"))?;
        self.pos += 1;
        Ok(byte)
    }

    fn uint(&mut self, additional: u8) -> Result<Option<u64>, Error> {
        let width = match additional {
            0..=23 => return Ok(Some(u64::from(additional))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 => return Ok(None),
            _ => return Err(self.err("reserved CBOR additional information")),
        };
        let end = self
            .pos
            .checked_add(width)
            .ok_or_else(|| self.err("CBOR length overflow"))?;
        let bytes = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| self.err("truncated CBOR argument"))?;
        self.pos = end;
        let mut value = 0u64;
        for &byte in bytes {
            value = (value << 8) | u64::from(byte);
        }
        Ok(Some(value))
    }

    fn length(&self, value: u64) -> Result<usize, Error> {
        usize::try_from(value).map_err(|_| self.err("CBOR length does not fit usize"))
    }

    fn count_item(&mut self) -> Result<(), Error> {
        self.items = self
            .items
            .checked_add(1)
            .ok_or_else(|| self.err("CBOR item count overflow"))?;
        if self.items > self.limits.max_items {
            return Err(Error::limit("CBOR item", self.limits.max_items));
        }
        Ok(())
    }

    fn parse(&mut self, depth: usize) -> Result<Item, Error> {
        if depth > self.limits.max_depth {
            return Err(Error::limit("CBOR nesting", self.limits.max_depth));
        }
        self.count_item()?;
        let start = self.pos;
        let initial = self.byte()?;
        if initial == 0xff {
            return Err(self.err("unexpected CBOR break"));
        }
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let argument = self.uint(additional)?;
        let content_start = self.pos;
        let indefinite = argument.is_none();
        if indefinite && !matches!(major, 2..=5) {
            return Err(self.err("indefinite marker is invalid for this CBOR type"));
        }
        if indefinite && self.limits.require_definite {
            return Err(self.err("indefinite-length CBOR is not permitted"));
        }

        let mut children = Vec::new();
        let kind = match major {
            0 => {
                argument.ok_or_else(|| self.err("unsigned integer missing argument"))?;
                Kind::Unsigned
            }
            1 => {
                argument.ok_or_else(|| self.err("negative integer missing argument"))?;
                Kind::Negative
            }
            2 | 3 => {
                let kind = if major == 2 { Kind::Bytes } else { Kind::Text };
                match argument {
                    Some(length) => {
                        let length = self.length(length)?;
                        self.pos = self
                            .pos
                            .checked_add(length)
                            .filter(|end| *end <= self.data.len())
                            .ok_or_else(|| self.err("truncated CBOR string"))?;
                    }
                    None => loop {
                        if self.data.get(self.pos) == Some(&0xff) {
                            self.pos += 1;
                            break;
                        }
                        let chunk = self.parse(depth + 1)?;
                        if chunk.kind != kind || chunk.indefinite {
                            return Err(self.err("invalid indefinite CBOR string chunk"));
                        }
                        children.push(chunk);
                    },
                }
                kind
            }
            4 => {
                match argument {
                    Some(length) => {
                        let length = self.length(length)?;
                        children.reserve(length.min(1024));
                        for _ in 0..length {
                            children.push(self.parse(depth + 1)?);
                        }
                    }
                    None => loop {
                        if self.data.get(self.pos) == Some(&0xff) {
                            self.pos += 1;
                            break;
                        }
                        children.push(self.parse(depth + 1)?);
                    },
                }
                Kind::Array
            }
            5 => {
                let pairs = match argument {
                    Some(length) => Some(self.length(length)?),
                    None => None,
                };
                // Map entries are not retained: no caller inspects them.
                let mut canonical_keys = self.reject_duplicate_keys.then(HashSet::new);
                let mut parsed = 0usize;
                loop {
                    if pairs.is_none() && self.data.get(self.pos) == Some(&0xff) {
                        self.pos += 1;
                        break;
                    }
                    if pairs.is_some_and(|pairs| parsed == pairs) {
                        break;
                    }
                    let key = self.parse(depth + 1)?;
                    if let Some(canonical_keys) = &mut canonical_keys {
                        if !canonical_keys.insert(self.canonical_key(&key)?) {
                            return Err(self.err("duplicate CBOR map key"));
                        }
                    }
                    if pairs.is_none() && self.data.get(self.pos) == Some(&0xff) {
                        return Err(self.err("indefinite CBOR map has a key without a value"));
                    }
                    self.parse(depth + 1)?;
                    parsed += 1;
                }
                Kind::Map
            }
            6 => {
                let tag = argument.ok_or_else(|| self.err("CBOR tag missing number"))?;
                children.push(self.parse(depth + 1)?);
                Kind::Tag(tag)
            }
            7 => match additional {
                0..=23 => Kind::Simple(additional),
                24 => Kind::Simple(
                    u8::try_from(argument.ok_or_else(|| self.err("simple value missing"))?)
                        .map_err(|_| self.err("simple value out of range"))?,
                ),
                25..=27 => Kind::Float,
                _ => return Err(self.err("invalid CBOR simple or floating-point value")),
            },
            _ => unreachable!(),
        };

        Ok(Item {
            kind,
            start,
            content_start,
            end: self.pos,
            indefinite,
            children,
        })
    }

    /// Returns the deterministic encoding used to compare map keys.
    ///
    /// Integers and definite-length strings whose head is already in preferred
    /// form are their own deterministic encoding, so they are compared in
    /// place. Every other key is decoded and re-encoded deterministically.
    fn canonical_key(&self, key: &Item) -> Result<Cow<'a, [u8]>, Error> {
        let data: &'a [u8] = self.data;
        let raw = &data[key.start..key.end];
        let scalar = matches!(key.kind, Kind::Unsigned | Kind::Negative)
            || (matches!(key.kind, Kind::Bytes | Kind::Text) && !key.indefinite);
        if scalar {
            let head = &raw[..key.content_start - key.start];
            let argument = match head[0] & 0x1f {
                additional @ 0..=23 => u64::from(additional),
                _ => head[1..]
                    .iter()
                    .fold(0u64, |value, byte| (value << 8) | u64::from(*byte)),
            };
            let preferred_len = match argument {
                0..=23 => 1,
                24..=0xff => 2,
                0x100..=0xffff => 3,
                0x1_0000..=0xffff_ffff => 5,
                _ => 9,
            };
            if head.len() == preferred_len {
                return Ok(Cow::Borrowed(raw));
            }
        }
        let value: Value = cbor2::from_slice(raw)?;
        Ok(Cow::Owned(cbor2::to_canonical_vec(&value)?))
    }
}

fn root(data: &[u8], limits: CborLimits) -> Result<Item, Error> {
    root_with_duplicate_policy(data, limits, true)
}

fn root_with_duplicate_policy(
    data: &[u8],
    limits: CborLimits,
    reject_duplicate_keys: bool,
) -> Result<Item, Error> {
    let mut parser = Parser::new(data, limits, reject_duplicate_keys);
    let item = parser.parse(0)?;
    if parser.pos != data.len() {
        return Err(Error::Cbor(format!(
            "trailing CBOR data at byte {}",
            parser.pos
        )));
    }
    Ok(item)
}

pub(crate) fn validate_map(data: &[u8]) -> Result<(), Error> {
    let item = root(data, CborLimits::default())?;
    if item.kind != Kind::Map {
        return Err(Error::UnexpectedType("expected a CBOR map".into()));
    }
    Ok(())
}

pub(crate) fn validate_array(data: &[u8]) -> Result<(), Error> {
    let item = root(data, CborLimits::default())?;
    if item.kind != Kind::Array {
        return Err(Error::UnexpectedType("expected a CBOR array".into()));
    }
    Ok(())
}

/// Returns the exact encodings of an array's direct members while allowing a
/// malformed member to contain duplicate map keys. Callers must validate each
/// returned member independently.
pub(crate) fn independently_validated_array_members(data: &[u8]) -> Result<Vec<&[u8]>, Error> {
    let item = root_with_duplicate_policy(data, CborLimits::default(), false)?;
    if item.kind != Kind::Array {
        return Err(Error::UnexpectedType("expected a CBOR array".into()));
    }
    Ok(item
        .children
        .iter()
        .map(|child| &data[child.start..child.end])
        .collect())
}

/// Validates one complete CBOR item, including duplicate keys and limits.
pub fn validate_with_limits(data: &[u8], limits: CborLimits) -> Result<(), Error> {
    root(data, limits)?;
    cbor2::validate_slice(data)?;
    Ok(())
}

fn append_bytes(data: &[u8], item: &Item, output: &mut Vec<u8>) -> Result<(), Error> {
    if item.kind != Kind::Bytes {
        return Err(Error::UnexpectedType("expected a CBOR byte string".into()));
    }
    if item.indefinite {
        for chunk in &item.children {
            append_bytes(data, chunk, output)?;
        }
    } else {
        output.extend_from_slice(&data[item.content_start..item.end]);
    }
    Ok(())
}

pub(crate) fn decode_bytes(data: &[u8]) -> Result<Vec<u8>, Error> {
    let item = root(data, CborLimits::default())?;
    if item.kind != Kind::Bytes {
        return Err(Error::UnexpectedType("expected a CBOR byte string".into()));
    }
    let mut output = Vec::new();
    append_bytes(data, &item, &mut output)?;
    Ok(output)
}

pub(crate) fn decode_optional_bytes(data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let item = root(data, CborLimits::default())?;
    if item.kind == Kind::Simple(22) {
        return Ok(None);
    }
    let mut output = Vec::new();
    append_bytes(data, &item, &mut output)?;
    Ok(Some(output))
}

pub(crate) fn message_body(
    data: &[u8],
    expected_tag: u64,
    limits: CborLimits,
) -> Result<&[u8], Error> {
    let item = root(data, limits)?;
    let mut current = &item;
    if current.kind == Kind::Tag(55799) {
        current = &current.children[0];
    }

    let cwt_wrapped = current.kind == Kind::Tag(61);
    if cwt_wrapped {
        current = &current.children[0];
    }

    let cose_tagged = current.kind == Kind::Tag(expected_tag);
    if cose_tagged {
        current = &current.children[0];
    } else if matches!(current.kind, Kind::Tag(_)) {
        return Err(Error::Custom(format!(
            "unexpected CBOR tag for COSE message, expected {expected_tag}"
        )));
    }

    if cwt_wrapped && !cose_tagged {
        return Err(Error::Custom(
            "CWT tag must wrap a tagged COSE message".into(),
        ));
    }
    if current.kind != Kind::Array {
        return Err(Error::UnexpectedType(
            "COSE message must be an array".into(),
        ));
    }
    validate_message_shape(current, expected_tag)?;
    Ok(&data[current.start..current.end])
}

fn require_kind(item: &Item, kind: Kind, name: &str) -> Result<(), Error> {
    if item.kind == kind {
        Ok(())
    } else {
        Err(Error::UnexpectedType(format!(
            "{name} has the wrong CBOR type"
        )))
    }
}

fn require_bytes_or_null(item: &Item, name: &str) -> Result<(), Error> {
    if item.kind == Kind::Bytes || item.kind == Kind::Simple(22) {
        Ok(())
    } else {
        Err(Error::UnexpectedType(format!(
            "{name} must be a byte string or null"
        )))
    }
}

fn validate_recipient_shape(item: &Item) -> Result<(), Error> {
    require_kind(item, Kind::Array, "COSE_recipient")?;
    if !(3..=4).contains(&item.children.len()) {
        return Err(Error::UnexpectedType(
            "COSE_recipient must contain 3 or 4 elements".into(),
        ));
    }
    require_kind(&item.children[0], Kind::Bytes, "recipient protected header")?;
    require_kind(&item.children[1], Kind::Map, "recipient unprotected header")?;
    require_bytes_or_null(&item.children[2], "recipient ciphertext")?;
    if item.children.len() == 4 {
        let recipients = &item.children[3];
        require_kind(recipients, Kind::Array, "nested recipients")?;
        if recipients.children.is_empty() {
            return Err(Error::Custom(
                "nested recipients array must not be empty".into(),
            ));
        }
        for recipient in &recipients.children {
            validate_recipient_shape(recipient)?;
        }
    }
    Ok(())
}

fn validate_recipients(item: &Item) -> Result<(), Error> {
    require_kind(item, Kind::Array, "recipients")?;
    if item.children.is_empty() {
        return Err(Error::Custom("recipients array must not be empty".into()));
    }
    for recipient in &item.children {
        validate_recipient_shape(recipient)?;
    }
    Ok(())
}

fn validate_message_shape(item: &Item, tag: u64) -> Result<(), Error> {
    let expected = match tag {
        16 => 3,
        17 | 18 | 96 | 98 => 4,
        97 => 5,
        _ => return Err(Error::Custom(format!("unsupported COSE tag {tag}"))),
    };
    if item.children.len() != expected {
        return Err(Error::UnexpectedType(format!(
            "COSE message with tag {tag} must contain {expected} elements"
        )));
    }
    require_kind(&item.children[0], Kind::Bytes, "protected header")?;
    require_kind(&item.children[1], Kind::Map, "unprotected header")?;
    match tag {
        16 => require_bytes_or_null(&item.children[2], "ciphertext")?,
        17 | 18 => {
            require_bytes_or_null(&item.children[2], "payload")?;
            require_kind(
                &item.children[3],
                Kind::Bytes,
                if tag == 17 { "MAC tag" } else { "signature" },
            )?;
        }
        96 => {
            require_bytes_or_null(&item.children[2], "ciphertext")?;
            validate_recipients(&item.children[3])?;
        }
        97 => {
            require_bytes_or_null(&item.children[2], "payload")?;
            require_kind(&item.children[3], Kind::Bytes, "MAC tag")?;
            validate_recipients(&item.children[4])?;
        }
        98 => {
            require_bytes_or_null(&item.children[2], "payload")?;
            let signatures = &item.children[3];
            require_kind(signatures, Kind::Array, "signatures")?;
            if signatures.children.is_empty() {
                return Err(Error::Custom("signatures array must not be empty".into()));
            }
            for signature in &signatures.children {
                require_kind(signature, Kind::Array, "COSE_Signature")?;
                if signature.children.len() != 3 {
                    return Err(Error::UnexpectedType(
                        "COSE_Signature must contain 3 elements".into(),
                    ));
                }
                require_kind(
                    &signature.children[0],
                    Kind::Bytes,
                    "signature protected header",
                )?;
                require_kind(
                    &signature.children[1],
                    Kind::Map,
                    "signature unprotected header",
                )?;
                require_kind(&signature.children[2], Kind::Bytes, "signature value")?;
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

pub(crate) fn tagged_body(data: &[u8], expected_tag: u64) -> Result<&[u8], Error> {
    let item = root(data, CborLimits::default())?;
    let mut current = &item;
    if current.kind == Kind::Tag(55799) {
        current = &current.children[0];
    }
    if current.kind != Kind::Tag(expected_tag) {
        return Err(Error::Custom(format!("expected CBOR tag {expected_tag}")));
    }
    let child = &current.children[0];
    Ok(&data[child.start..child.end])
}

pub(crate) fn remove_known_tags(data: &[u8]) -> Result<&[u8], Error> {
    let item = root(data, CborLimits::default())?;
    let mut current = &item;
    if current.kind == Kind::Tag(55799) {
        current = &current.children[0];
    }
    if current.kind == Kind::Tag(61) {
        current = &current.children[0];
    }
    if matches!(current.kind, Kind::Tag(16 | 17 | 18 | 96 | 97 | 98)) {
        current = &current.children[0];
    }
    Ok(&data[current.start..current.end])
}

#[derive(Debug)]
pub(crate) struct StrictBytes(pub(crate) Vec<u8>);

impl Serialize for StrictBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for StrictBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
            return Ok(Self(bytes.into_vec()));
        }
        let raw = cbor2::RawValue::deserialize(deserializer)?;
        decode_bytes(raw.as_bytes())
            .map(Self)
            .map_err(D::Error::custom)
    }
}

#[derive(Debug)]
pub(crate) struct StrictOptionalBytes(pub(crate) Option<Vec<u8>>);

impl Serialize for StrictOptionalBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.as_deref() {
            Some(bytes) => serializer.serialize_some(&serde_bytes::Bytes::new(bytes)),
            None => serializer.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for StrictOptionalBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let bytes = Option::<serde_bytes::ByteBuf>::deserialize(deserializer)?;
            return Ok(Self(bytes.map(serde_bytes::ByteBuf::into_vec)));
        }
        let raw = cbor2::RawValue::deserialize(deserializer)?;
        decode_optional_bytes(raw.as_bytes())
            .map(Self)
            .map_err(D::Error::custom)
    }
}

pub(crate) mod optional_bytes {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value.as_deref() {
            Some(bytes) => serializer.serialize_some(&serde_bytes::Bytes::new(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        StrictOptionalBytes::deserialize(deserializer).map(|value| value.0)
    }
}
