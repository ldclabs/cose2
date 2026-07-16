//! CBOR Web Token (CWT) claims and validation (RFC 8392).

use std::time::{SystemTime, UNIX_EPOCH};

use cbor2::Cbor;

use crate::{iana, tag, CoseMap, Error, Value};

/// The maximum permitted clock skew, in seconds (10 minutes).
const MAX_CLOCK_SKEW_SECS: u64 = 10 * 60;

/// The common, typed subset of CWT claims (RFC 8392 §3).
///
/// Claims outside the typed subset are retained in [`Claims::extra`]. The
/// struct encodes to a CBOR map with the registered integer claim keys, while
/// still serializing to natural field names for JSON and other formats.
#[derive(Clone, Debug, Default, PartialEq, Cbor)]
#[cbor(tag = 61)]
pub struct Claims {
    /// Issuer (`iss`, claim 1).
    #[cbor(key = 1)]
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none", default)]
    pub issuer: Option<String>,
    /// Subject (`sub`, claim 2).
    #[cbor(key = 2)]
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none", default)]
    pub subject: Option<String>,
    /// Audience (`aud`, claim 3).
    #[cbor(key = 3)]
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none", default)]
    pub audience: Option<String>,
    /// Expiration time, seconds since the UNIX epoch (`exp`, claim 4).
    ///
    /// See [`numeric_date`] for the accepted NumericDate encodings.
    #[cbor(key = 4)]
    #[serde(
        rename = "exp",
        with = "numeric_date",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expiration: Option<u64>,
    /// Not-before time, seconds since the UNIX epoch (`nbf`, claim 5).
    ///
    /// See [`numeric_date`] for the accepted NumericDate encodings.
    #[cbor(key = 5)]
    #[serde(
        rename = "nbf",
        with = "numeric_date",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub not_before: Option<u64>,
    /// Issued-at time, seconds since the UNIX epoch (`iat`, claim 6).
    ///
    /// See [`numeric_date`] for the accepted NumericDate encodings.
    #[cbor(key = 6)]
    #[serde(
        rename = "iat",
        with = "numeric_date",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub issued_at: Option<u64>,
    /// CWT ID (`cti`, claim 7).
    #[cbor(key = 7)]
    #[serde(
        rename = "cti",
        with = "serde_bytes",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub cwt_id: Option<Vec<u8>>,
    /// Additional CWT claims outside the typed subset above.
    ///
    /// Use this for application/private claims and registered claims that do
    /// not yet have typed fields here. The keys are flattened into the CWT
    /// claim map on encode and retained on decode.
    #[serde(flatten, skip_serializing_if = "CoseMap::is_empty", default)]
    pub extra: CoseMap,
}

/// Serde helpers for RFC 8392 `NumericDate` claims modeled as `Option<u64>`.
///
/// RFC 8392 allows a NumericDate to be a CBOR integer or float. This crate
/// models timestamps as whole seconds since the UNIX epoch: integer encodings
/// and integral-valued float encodings (e.g. `1700000000.0`) are accepted;
/// fractional-second floats and pre-epoch (negative) dates are rejected with
/// a descriptive error. Encoding always produces an integer.
pub mod numeric_date {
    use serde::{de, Deserializer, Serializer};

    /// Converts an integral, in-range CBOR float to whole seconds.
    pub(crate) fn from_f64<E: de::Error>(v: f64) -> Result<u64, E> {
        if !v.is_finite() || v.fract() != 0.0 {
            return Err(E::custom(
                "fractional-second NumericDate is not supported, use whole seconds",
            ));
        }
        if v < 0.0 {
            return Err(E::custom("pre-epoch NumericDate is not supported"));
        }
        if v >= u64::MAX as f64 {
            return Err(E::custom("NumericDate out of range"));
        }
        Ok(v as u64)
    }

    /// Serializes the timestamp as a CBOR integer.
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => serializer.serialize_u64(*v),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes a NumericDate encoded as a CBOR integer or integral float.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        struct DateVisitor;

        impl de::Visitor<'_> for DateVisitor {
            type Value = u64;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a NumericDate in whole seconds since the UNIX epoch")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
                Ok(v)
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
                u64::try_from(v).map_err(|_| E::custom("pre-epoch NumericDate is not supported"))
            }

            fn visit_u128<E: de::Error>(self, v: u128) -> Result<u64, E> {
                u64::try_from(v).map_err(|_| E::custom("NumericDate out of range"))
            }

            fn visit_i128<E: de::Error>(self, v: i128) -> Result<u64, E> {
                u64::try_from(v).map_err(|_| E::custom("NumericDate out of range or pre-epoch"))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<u64, E> {
                from_f64(v)
            }
        }

        struct OptionVisitor;

        impl<'de> de::Visitor<'de> for OptionVisitor {
            type Value = Option<u64>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an optional NumericDate")
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D2: Deserializer<'de>>(
                self,
                deserializer: D2,
            ) -> Result<Self::Value, D2::Error> {
                deserializer.deserialize_any(DateVisitor).map(Some)
            }
        }

        deserializer.deserialize_option(OptionVisitor)
    }
}

impl Claims {
    /// Creates empty claims.
    pub fn new() -> Self {
        Claims::default()
    }

    /// Decodes claims from CBOR bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        let data = tag::skip_tag(tag::CBOR_SELF_PREFIX, data);
        if !data.starts_with(tag::CWT_PREFIX) && tag::starts_with_cbor_tag(data) {
            return Err(Error::Custom("unexpected CBOR tag for CWT Claims".into()));
        }
        Ok(cbor2::from_slice(data)?)
    }

    /// Encodes claims to canonical CBOR bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        Ok(cbor2::to_canonical_vec(self)?)
    }

    /// Encodes claims to canonical CBOR bytes without the CWT CBOR tag.
    pub fn to_untagged_vec(&self) -> Result<Vec<u8>, Error> {
        let tagged = self.to_vec()?;
        Ok(tag::skip_tag(tag::CWT_PREFIX, &tagged).to_vec())
    }
}

/// A CWT claims set keyed by [`Label`](crate::Label), preserving all claims
/// including unregistered ones.
pub type ClaimsMap = CoseMap;

/// Options controlling [`Validator`] behaviour.
#[derive(Clone, Debug, Default)]
pub struct ValidatorOptions {
    /// If set, the token's `iss` must equal this value.
    pub expected_issuer: Option<String>,
    /// If set, the token's `aud` must equal this value.
    pub expected_audience: Option<String>,
    /// Permit tokens without an `exp` claim.
    pub allow_missing_expiration: bool,
    /// Require `iat`, when present, to be in the past.
    pub expect_issued_in_the_past: bool,
    /// Allowed clock skew, in seconds (at most 10 minutes).
    pub clock_skew_secs: u64,
    /// Fixed "now" in UNIX seconds; uses the system clock when `None`.
    pub fixed_now: Option<i64>,
}

/// Validates CWT [`Claims`] and [`ClaimsMap`]s against time and identity
/// constraints (RFC 8392).
#[derive(Clone, Debug)]
pub struct Validator {
    opts: ValidatorOptions,
}

fn to_secs(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Reads a registered NumericDate claim from a [`ClaimsMap`], accepting a
/// CBOR integer or an integral-valued float (RFC 8392 NumericDate).
fn numeric_date_claim(claims: &ClaimsMap, key: i64) -> Result<Option<i64>, Error> {
    match claims.get(key) {
        Some(Value::Float(f)) => numeric_date::from_f64::<serde::de::value::Error>(*f)
            .map(|secs| Some(to_secs(secs)))
            .map_err(|err| Error::UnexpectedType(err.to_string())),
        _ => claims.get_i64(key),
    }
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
        Ok(Validator { opts })
    }

    fn now(&self) -> i64 {
        match self.opts.fixed_now {
            Some(now) => now,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| to_secs(d.as_secs()))
                .unwrap_or(0),
        }
    }

    /// Validates the typed [`Claims`].
    pub fn validate(&self, claims: &Claims) -> Result<(), Error> {
        self.check_times(
            claims.expiration.map(to_secs),
            claims.not_before.map(to_secs),
            claims.issued_at.map(to_secs),
        )?;
        self.check_identity(claims.issuer.as_deref(), claims.audience.as_deref())
    }

    /// Validates a [`ClaimsMap`], reading the registered time/identity claims.
    ///
    /// The time claims accept integer and integral-valued float NumericDate
    /// encodings (see [`numeric_date`]).
    pub fn validate_map(&self, claims: &ClaimsMap) -> Result<(), Error> {
        self.check_times(
            numeric_date_claim(claims, iana::CWTClaimExp)?,
            numeric_date_claim(claims, iana::CWTClaimNbf)?,
            numeric_date_claim(claims, iana::CWTClaimIat)?,
        )?;
        self.check_identity(
            claims.get_text(iana::CWTClaimIss)?,
            claims.get_text(iana::CWTClaimAud)?,
        )
    }

    fn check_times(
        &self,
        exp: Option<i64>,
        nbf: Option<i64>,
        iat: Option<i64>,
    ) -> Result<(), Error> {
        let now = self.now();
        let skew = to_secs(self.opts.clock_skew_secs);

        match exp {
            None if !self.opts.allow_missing_expiration => {
                return Err(Error::Custom("token doesn't have an expiration set".into()));
            }
            Some(exp) if exp <= now - skew => {
                return Err(Error::Custom("token has expired".into()));
            }
            _ => {}
        }

        if let Some(nbf) = nbf {
            if nbf > now + skew {
                return Err(Error::Custom("token cannot be used yet".into()));
            }
        }

        if self.opts.expect_issued_in_the_past {
            if let Some(iat) = iat {
                if iat > now + skew {
                    return Err(Error::Custom(
                        "token has an invalid iat claim in the future".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn check_identity(&self, issuer: Option<&str>, audience: Option<&str>) -> Result<(), Error> {
        if let Some(expected) = &self.opts.expected_issuer {
            if Some(expected.as_str()) != issuer {
                return Err(Error::Custom(format!(
                    "issuer mismatch, expected {expected:?}, got {issuer:?}"
                )));
            }
        }
        if let Some(expected) = &self.opts.expected_audience {
            if Some(expected.as_str()) != audience {
                return Err(Error::Custom(format!(
                    "audience mismatch, expected {expected:?}, got {audience:?}"
                )));
            }
        }
        Ok(())
    }
}
