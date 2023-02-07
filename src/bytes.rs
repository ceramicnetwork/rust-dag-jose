use serde::{
    de::{self, Visitor},
    Deserialize, Serialize,
};

/// Sequence of byte values.
#[derive(PartialEq, Default, Debug)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Unwraps this `Bytes` returning the underlying vector.
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
}
impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.as_slice())
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_byte_buf(BytesVisitor)
    }
}
struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of bytes")
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v.into())
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(value: Bytes) -> Self {
        value.into_inner()
    }
}
