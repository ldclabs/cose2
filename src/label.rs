//! The COSE [`Label`] type: an integer or text-string map key.

use std::fmt;

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::Value;

/// A COSE label, used as the key of header, key and claim maps.
///
/// RFC 9052 defines a label as `int / tstr`, so a `Label` is either a
/// signed integer or a text string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Label {
    /// An integer label (negative integers are valid COSE labels).
    Int(i64),
    /// A text-string label.
    Text(String),
}

impl Label {
    /// Returns the integer value if this is an [`Label::Int`].
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Label::Int(i) => Some(*i),
            Label::Text(_) => None,
        }
    }

    /// Returns the text value if this is an [`Label::Text`].
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Label::Text(s) => Some(s),
            Label::Int(_) => None,
        }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Label::Int(i) => write!(f, "{i}"),
            Label::Text(s) => write!(f, "{s}"),
        }
    }
}

impl From<i64> for Label {
    fn from(value: i64) -> Self {
        Label::Int(value)
    }
}

impl From<i32> for Label {
    fn from(value: i32) -> Self {
        Label::Int(value as i64)
    }
}

impl From<String> for Label {
    fn from(value: String) -> Self {
        Label::Text(value)
    }
}

impl From<&str> for Label {
    fn from(value: &str) -> Self {
        Label::Text(value.to_string())
    }
}

impl From<Label> for Value {
    fn from(value: Label) -> Self {
        match value {
            Label::Int(i) => Value::from(i),
            Label::Text(s) => Value::from(s),
        }
    }
}

impl From<&Label> for Value {
    fn from(value: &Label) -> Self {
        match value {
            Label::Int(i) => Value::from(*i),
            Label::Text(s) => Value::from(s.clone()),
        }
    }
}

impl Serialize for Label {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Label::Int(i) => serializer.serialize_i64(*i),
            Label::Text(s) => serializer.serialize_str(s),
        }
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LabelVisitor;

        impl Visitor<'_> for LabelVisitor {
            type Value = Label;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an integer or text string COSE label")
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Label, E> {
                Ok(Label::Int(v))
            }

            fn visit_i128<E: de::Error>(self, v: i128) -> Result<Label, E> {
                i64::try_from(v)
                    .map(Label::Int)
                    .map_err(|_| E::custom("integer label out of range"))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Label, E> {
                i64::try_from(v)
                    .map(Label::Int)
                    .map_err(|_| E::custom("integer label out of range"))
            }

            fn visit_u128<E: de::Error>(self, v: u128) -> Result<Label, E> {
                i64::try_from(v)
                    .map(Label::Int)
                    .map_err(|_| E::custom("integer label out of range"))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Label, E> {
                Ok(Label::Text(v.to_string()))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Label, E> {
                Ok(Label::Text(v))
            }
        }

        deserializer.deserialize_any(LabelVisitor)
    }
}
