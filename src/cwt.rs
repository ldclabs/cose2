//! CBOR Web Token (CWT) claims and validation (RFC 8392).

use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use cbor2::Cbor;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{iana, tag, CoseMap, Error, Value};

const MAX_CLOCK_SKEW_SECS: u64 = 10 * 60;

/// A CWT NumericDate, retaining integer and floating-point wire forms.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NumericDate {
    /// An exact CBOR integer number of seconds relative to the UNIX epoch.
    Integer(i128),
    /// A finite CBOR floating-point number of seconds relative to the epoch.
    Float(f64),
}

impl NumericDate {
    /// Creates a finite floating-point NumericDate.
    pub fn from_f64(value: f64) -> Result<Self, Error> {
        if !value.is_finite() {
            return Err(Error::UnexpectedType(
                "NumericDate must be a finite number".into(),
            ));
        }
        Ok(Self::Float(value))
    }

    fn validate(self) -> Result<Self, Error> {
        match self {
            Self::Float(value) if !value.is_finite() => Err(Error::UnexpectedType(
                "NumericDate must be a finite number".into(),
            )),
            Self::Integer(value)
                if value < -1 - i128::from(u64::MAX) || value > i128::from(u64::MAX) =>
            {
                Err(Error::UnexpectedType(
                    "NumericDate integer out of CBOR range".into(),
                ))
            }
            _ => Ok(self),
        }
    }

    fn partial_cmp_integer(self, other: i128) -> Option<Ordering> {
        match self {
            Self::Integer(value) => value.partial_cmp(&other),
            Self::Float(value) => compare_f64_to_i128(value, other),
        }
    }
}

fn compare_f64_to_i128(value: f64, other: i128) -> Option<Ordering> {
    if !value.is_finite() {
        return None;
    }
    if value >= i128::MAX as f64 {
        return Some(Ordering::Greater);
    }
    if value < i128::MIN as f64 {
        return Some(Ordering::Less);
    }
    let truncated = value as i128;
    match truncated.cmp(&other) {
        Ordering::Equal if value == truncated as f64 => Some(Ordering::Equal),
        Ordering::Equal if value.is_sign_negative() => Some(Ordering::Less),
        Ordering::Equal => Some(Ordering::Greater),
        ordering => Some(ordering),
    }
}

macro_rules! numeric_date_from_integer {
    ($($ty:ty),+ $(,)?) => {$ (
        impl From<$ty> for NumericDate {
            fn from(value: $ty) -> Self {
                Self::Integer(i128::from(value))
            }
        }
    )+ };
}

numeric_date_from_integer!(i8, i16, i32, i64, u8, u16, u32, u64);

impl Serialize for NumericDate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.validate().map_err(serde::ser::Error::custom)? {
            Self::Integer(value) => serializer.serialize_i128(value),
            Self::Float(value) => serializer.serialize_f64(value),
        }
    }
}

impl<'de> Deserialize<'de> for NumericDate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = NumericDate;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a finite integer or floating-point NumericDate")
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(NumericDate::from(value))
            }

            fn visit_i128<E: de::Error>(self, value: i128) -> Result<Self::Value, E> {
                NumericDate::Integer(value).validate().map_err(E::custom)
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(NumericDate::from(value))
            }

            fn visit_u128<E: de::Error>(self, value: u128) -> Result<Self::Value, E> {
                let value =
                    i128::try_from(value).map_err(|_| E::custom("NumericDate out of range"))?;
                NumericDate::Integer(value).validate().map_err(E::custom)
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                NumericDate::from_f64(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// One or more intended CWT audiences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Audience {
    /// One StringOrURI audience.
    One(String),
    /// An array of StringOrURI audiences.
    Many(Vec<String>),
}

impl Audience {
    /// Returns true when this audience contains `expected`.
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }

    /// Returns the audience when this is the single-string form.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::One(value) => Some(value),
            Self::Many(_) => None,
        }
    }
}

impl From<String> for Audience {
    fn from(value: String) -> Self {
        Self::One(value)
    }
}

impl From<&str> for Audience {
    fn from(value: &str) -> Self {
        Self::One(value.to_owned())
    }
}

impl From<Vec<String>> for Audience {
    fn from(value: Vec<String>) -> Self {
        Self::Many(value)
    }
}

impl Serialize for Audience {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::One(value) => serializer.serialize_str(value),
            Self::Many(values) => values.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Audience {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Audience;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an audience string or array of strings")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(Audience::One(value.to_owned()))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(Audience::One(value))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::with_capacity(access.size_hint().unwrap_or(0));
                while let Some(value) = access.next_element::<String>()? {
                    values.push(value);
                }
                Ok(Audience::Many(values))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// The common, typed subset of CWT claims (RFC 8392 §3).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Claims {
    /// Issuer (`iss`, claim 1).
    pub issuer: Option<String>,
    /// Subject (`sub`, claim 2).
    pub subject: Option<String>,
    /// Audience (`aud`, claim 3).
    pub audience: Option<Audience>,
    /// Expiration time (`exp`, claim 4).
    pub expiration: Option<NumericDate>,
    /// Not-before time (`nbf`, claim 5).
    pub not_before: Option<NumericDate>,
    /// Issued-at time (`iat`, claim 6).
    pub issued_at: Option<NumericDate>,
    /// CWT ID (`cti`, claim 7).
    pub cwt_id: Option<Vec<u8>>,
    /// Additional CWT claims.
    pub extra: CoseMap,
}

impl Cbor for Claims {
    const KEYS: &'static [(&'static str, i128)] = &[
        ("iss", 1),
        ("sub", 2),
        ("aud", 3),
        ("exp", 4),
        ("nbf", 5),
        ("iat", 6),
        ("cti", 7),
    ];
    const TAG: Option<u64> = None;
}

#[derive(Serialize, Deserialize)]
struct HumanClaims {
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none", default)]
    issuer: Option<String>,
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none", default)]
    subject: Option<String>,
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none", default)]
    audience: Option<Audience>,
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none", default)]
    expiration: Option<NumericDate>,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none", default)]
    not_before: Option<NumericDate>,
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none", default)]
    issued_at: Option<NumericDate>,
    #[serde(
        rename = "cti",
        with = "serde_bytes",
        skip_serializing_if = "Option::is_none",
        default
    )]
    cwt_id: Option<Vec<u8>>,
    #[serde(flatten, default)]
    extra: CoseMap,
}

impl From<HumanClaims> for Claims {
    fn from(value: HumanClaims) -> Self {
        Self {
            issuer: value.issuer,
            subject: value.subject,
            audience: value.audience,
            expiration: value.expiration,
            not_before: value.not_before,
            issued_at: value.issued_at,
            cwt_id: value.cwt_id,
            extra: value.extra,
        }
    }
}

fn insert_claim(map: &mut CoseMap, key: i64, value: Value) -> Result<(), Error> {
    if map.insert(key, value).is_some() {
        return Err(Error::Custom(format!(
            "claim {key} appears in both typed fields and Claims::extra"
        )));
    }
    Ok(())
}

fn numeric_date_value(value: NumericDate) -> Result<Value, Error> {
    match value.validate()? {
        NumericDate::Integer(value) => cbor2::value::Integer::try_from(value)
            .map(Value::Integer)
            .map_err(|_| Error::UnexpectedType("NumericDate out of range".into())),
        NumericDate::Float(value) => Ok(Value::Float(value)),
    }
}

fn numeric_date_from_value(value: Value, name: &str) -> Result<NumericDate, Error> {
    match value {
        Value::Integer(value) => Ok(NumericDate::Integer(i128::from(value))),
        Value::Float(value) => NumericDate::from_f64(value),
        _ => Err(Error::UnexpectedType(format!(
            "{name} must be an integer or finite float"
        ))),
    }
}

fn audience_from_value(value: Value) -> Result<Audience, Error> {
    match value {
        Value::Text(value) => Ok(Audience::One(value)),
        Value::Array(values) => values
            .into_iter()
            .map(|value| match value {
                Value::Text(value) => Ok(value),
                _ => Err(Error::UnexpectedType(
                    "aud array entries must be text strings".into(),
                )),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Audience::Many),
        _ => Err(Error::UnexpectedType(
            "aud must be a text string or array of text strings".into(),
        )),
    }
}

impl Claims {
    /// Creates an empty claims set.
    pub fn new() -> Self {
        Self::default()
    }

    fn to_map(&self) -> Result<CoseMap, Error> {
        let mut map = self.extra.clone();
        if let Some(value) = &self.issuer {
            insert_claim(&mut map, iana::CWTClaimIss, Value::Text(value.clone()))?;
        }
        if let Some(value) = &self.subject {
            insert_claim(&mut map, iana::CWTClaimSub, Value::Text(value.clone()))?;
        }
        if let Some(value) = &self.audience {
            let value = match value {
                Audience::One(value) => Value::Text(value.clone()),
                Audience::Many(values) => {
                    Value::Array(values.iter().cloned().map(Value::Text).collect())
                }
            };
            insert_claim(&mut map, iana::CWTClaimAud, value)?;
        }
        for (key, value) in [
            (iana::CWTClaimExp, self.expiration),
            (iana::CWTClaimNbf, self.not_before),
            (iana::CWTClaimIat, self.issued_at),
        ] {
            if let Some(value) = value {
                insert_claim(&mut map, key, numeric_date_value(value)?)?;
            }
        }
        if let Some(value) = &self.cwt_id {
            insert_claim(&mut map, iana::CWTClaimCti, Value::Bytes(value.clone()))?;
        }
        Ok(map)
    }

    fn from_map(mut map: CoseMap) -> Result<Self, Error> {
        let issuer = match map.remove(iana::CWTClaimIss) {
            None => None,
            Some(Value::Text(value)) => Some(value),
            Some(_) => return Err(Error::UnexpectedType("iss must be a text string".into())),
        };
        let subject = match map.remove(iana::CWTClaimSub) {
            None => None,
            Some(Value::Text(value)) => Some(value),
            Some(_) => return Err(Error::UnexpectedType("sub must be a text string".into())),
        };
        let audience = map
            .remove(iana::CWTClaimAud)
            .map(audience_from_value)
            .transpose()?;
        let expiration = map
            .remove(iana::CWTClaimExp)
            .map(|value| numeric_date_from_value(value, "exp"))
            .transpose()?;
        let not_before = map
            .remove(iana::CWTClaimNbf)
            .map(|value| numeric_date_from_value(value, "nbf"))
            .transpose()?;
        let issued_at = map
            .remove(iana::CWTClaimIat)
            .map(|value| numeric_date_from_value(value, "iat"))
            .transpose()?;
        let cwt_id = match map.remove(iana::CWTClaimCti) {
            None => None,
            Some(Value::Bytes(value)) => Some(value),
            Some(_) => return Err(Error::UnexpectedType("cti must be a byte string".into())),
        };
        Ok(Self {
            issuer,
            subject,
            audience,
            expiration,
            not_before,
            issued_at,
            cwt_id,
            extra: map,
        })
    }

    /// Decodes an untagged CWT Claims Set map.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        crate::strict::validate_map(data)?;
        Ok(cbor2::from_slice(data)?)
    }

    /// Decodes the legacy `61(claims-map)` representation emitted by cose2 0.4.
    pub fn from_slice_legacy_tagged(data: &[u8]) -> Result<Self, Error> {
        let body = crate::strict::tagged_body(data, iana::CBORTagCWT)?;
        Self::from_slice(body)
    }

    /// Encodes the untagged CWT Claims Set map canonically.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        Ok(cbor2::to_canonical_vec(self)?)
    }

    /// Alias for [`Claims::to_vec`], retained for source compatibility.
    pub fn to_untagged_vec(&self) -> Result<Vec<u8>, Error> {
        self.to_vec()
    }

    /// Encodes the legacy `61(claims-map)` representation emitted by cose2 0.4.
    pub fn to_legacy_tagged_vec(&self) -> Result<Vec<u8>, Error> {
        let claims = crate::util::canonical_raw(self)?;
        crate::util::encode_prefixed(tag::CWT_PREFIX, &claims)
    }

    /// The CBOR tag used around a complete tagged COSE CWT message.
    pub const CWT_TAG: u64 = iana::CBORTagCWT;
}

impl Serialize for Claims {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            HumanClaims {
                issuer: self.issuer.clone(),
                subject: self.subject.clone(),
                audience: self.audience.clone(),
                expiration: self.expiration,
                not_before: self.not_before,
                issued_at: self.issued_at,
                cwt_id: self.cwt_id.clone(),
                extra: self.extra.clone(),
            }
            .serialize(serializer)
        } else {
            self.to_map()
                .map_err(serde::ser::Error::custom)?
                .serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Claims {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            HumanClaims::deserialize(deserializer).map(Claims::from)
        } else {
            let map = CoseMap::deserialize(deserializer)?;
            Self::from_map(map).map_err(de::Error::custom)
        }
    }
}

/// Serde helpers for `Option<NumericDate>` fields in application structs.
pub mod numeric_date {
    use super::NumericDate;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serializes an optional NumericDate.
    pub fn serialize<S: Serializer>(
        value: &Option<NumericDate>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }

    /// Deserializes an optional NumericDate.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<NumericDate>, D::Error> {
        Option::<NumericDate>::deserialize(deserializer)
    }
}

/// A CWT claims set keyed by [`Label`](crate::Label), preserving all claims.
pub type ClaimsMap = CoseMap;

/// Options controlling [`Validator`] behaviour.
#[derive(Clone, Debug, Default)]
pub struct ValidatorOptions {
    /// If set, the token's `iss` must equal this value.
    pub expected_issuer: Option<String>,
    /// If set, `aud` must contain this value.
    pub expected_audience: Option<String>,
    /// Permit tokens without an `exp` claim.
    pub allow_missing_expiration: bool,
    /// Require `iat`, when present, to be in the past.
    pub expect_issued_in_the_past: bool,
    /// Allowed clock skew, in seconds (at most 10 minutes).
    pub clock_skew_secs: u64,
    /// Fixed current time in UNIX seconds; uses the system clock when absent.
    pub fixed_now: Option<i64>,
}

/// Validates CWT claims against time and identity constraints.
#[derive(Clone, Debug)]
pub struct Validator {
    opts: ValidatorOptions,
}

fn numeric_date_claim(
    claims: &ClaimsMap,
    key: i64,
    name: &str,
) -> Result<Option<NumericDate>, Error> {
    claims
        .get(key)
        .cloned()
        .map(|value| numeric_date_from_value(value, name))
        .transpose()
}

fn audience_claim(claims: &ClaimsMap) -> Result<Option<Audience>, Error> {
    claims
        .get(iana::CWTClaimAud)
        .cloned()
        .map(audience_from_value)
        .transpose()
}

impl Validator {
    /// Creates a validator, rejecting a clock skew above 10 minutes.
    pub fn new(opts: ValidatorOptions) -> Result<Self, Error> {
        if opts.clock_skew_secs > MAX_CLOCK_SKEW_SECS {
            return Err(Error::Custom(format!(
                "clock skew too large, expected <= {MAX_CLOCK_SKEW_SECS} seconds, got {}",
                opts.clock_skew_secs
            )));
        }
        Ok(Self { opts })
    }

    fn now(&self) -> i128 {
        self.opts.fixed_now.map(i128::from).unwrap_or_else(|| {
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => i128::from(duration.as_secs()),
                Err(error) => {
                    let duration = error.duration();
                    -i128::from(duration.as_secs())
                        - i128::from(u8::from(duration.subsec_nanos() != 0))
                }
            }
        })
    }

    /// Validates typed claims.
    pub fn validate(&self, claims: &Claims) -> Result<(), Error> {
        self.check_times(claims.expiration, claims.not_before, claims.issued_at)?;
        self.check_identity(claims.issuer.as_deref(), claims.audience.as_ref())
    }

    /// Validates a [`ClaimsMap`], reading registered claims by integer key.
    pub fn validate_map(&self, claims: &ClaimsMap) -> Result<(), Error> {
        self.check_times(
            numeric_date_claim(claims, iana::CWTClaimExp, "exp")?,
            numeric_date_claim(claims, iana::CWTClaimNbf, "nbf")?,
            numeric_date_claim(claims, iana::CWTClaimIat, "iat")?,
        )?;
        self.check_identity(
            claims.get_text(iana::CWTClaimIss)?,
            audience_claim(claims)?.as_ref(),
        )
    }

    fn check_times(
        &self,
        exp: Option<NumericDate>,
        nbf: Option<NumericDate>,
        iat: Option<NumericDate>,
    ) -> Result<(), Error> {
        let now = self.now();
        let skew = i128::from(self.opts.clock_skew_secs);

        match exp.map(NumericDate::validate).transpose()? {
            None if !self.opts.allow_missing_expiration => {
                return Err(Error::Custom("token doesn't have an expiration set".into()));
            }
            Some(exp) if exp.partial_cmp_integer(now - skew) != Some(Ordering::Greater) => {
                return Err(Error::Custom("token has expired".into()));
            }
            _ => {}
        }

        if let Some(nbf) = nbf.map(NumericDate::validate).transpose()? {
            if nbf.partial_cmp_integer(now + skew) == Some(Ordering::Greater) {
                return Err(Error::Custom("token cannot be used yet".into()));
            }
        }

        if self.opts.expect_issued_in_the_past {
            if let Some(iat) = iat.map(NumericDate::validate).transpose()? {
                if iat.partial_cmp_integer(now + skew) == Some(Ordering::Greater) {
                    return Err(Error::Custom(
                        "token has an invalid iat claim in the future".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn check_identity(
        &self,
        issuer: Option<&str>,
        audience: Option<&Audience>,
    ) -> Result<(), Error> {
        if let Some(expected) = &self.opts.expected_issuer {
            if Some(expected.as_str()) != issuer {
                return Err(Error::Custom(format!(
                    "issuer mismatch, expected {expected:?}, got {issuer:?}"
                )));
            }
        }
        if let Some(expected) = &self.opts.expected_audience {
            if !audience.is_some_and(|audience| audience.contains(expected)) {
                return Err(Error::Custom(format!(
                    "audience mismatch, expected {expected:?}"
                )));
            }
        }
        Ok(())
    }
}
