//! TODO
#![deny(missing_docs)]
#![deny(warnings)]

use libipld::{Cid, Ipld};
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{bytes::Bytes, error::Error, JsonWebEncryption};
use crate::{Jose, Signature};
use crate::{JsonWebSignature, Recipient};

/// Encoded represents the union of fields from JSON Web Signature (JWS)
/// and JSON Web Encryption (JWE) objects.
///
/// The data is repsented as bytes and therefore can be encoded
/// into a DAG-JOSE object using DAG-CBOR.
///
/// See https://ipld.io/specs/codecs/dag-jose/spec/#format
#[derive(PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct Encoded {
    // NOTE: Serde serialized fields in the order they appear
    // However DAG-CBOR specifies the fields must be serialized
    // sorted by length of key.
    //
    // Within each grouping the fields are defined in their correct
    // sort order.

    // JWS fields
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signatures: Option<Vec<EncodedSignature>>,

    // JWE fields
    #[serde(skip_serializing_if = "Option::is_none")]
    iv: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aad: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protected: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipients: Option<Vec<EncodedRecipient>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unprotected: Option<BTreeMap<String, Ipld>>,
}

impl TryFrom<JsonWebSignature> for Encoded {
    type Error = Error;

    fn try_from(mut value: JsonWebSignature) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: Some(Bytes::from_base64(value.payload)?),
            signatures: if value.signatures.is_empty() {
                None
            } else {
                Some(
                    value
                        .signatures
                        .drain(..)
                        .map(EncodedSignature::try_from)
                        .collect::<Result<Vec<EncodedSignature>, Self::Error>>()?,
                )
            },
            aad: None,
            ciphertext: None,
            iv: None,
            protected: None,
            recipients: None,
            tag: None,
            unprotected: None,
        })
    }
}

impl TryFrom<Encoded> for JsonWebSignature {
    type Error = Error;

    fn try_from(value: Encoded) -> Result<Self, Self::Error> {
        let link = Cid::try_from(value.payload.as_ref().ok_or(Error::NotJws)?.as_slice())?;
        Ok(Self {
            payload: value.payload.to_base64().ok_or(Error::NotJws)?,
            signatures: value
                .signatures
                .unwrap_or_else(|| Vec::new())
                .drain(..)
                .map(Signature::from)
                .collect(),
            link,
        })
    }
}

impl TryFrom<JsonWebEncryption> for Encoded {
    type Error = Error;

    fn try_from(mut value: JsonWebEncryption) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: None,
            signatures: None,
            iv: if value.iv.is_empty() {
                None
            } else {
                Some(Bytes::from_base64(value.iv)?)
            },
            aad: Option::from_base64(value.aad)?,
            tag: if value.tag.is_empty() {
                None
            } else {
                Some(Bytes::from_base64(value.tag)?)
            },
            protected: if value.protected.is_empty() { None } else {Some(Bytes::from_base64(value.protected)?)},
            ciphertext: Some(Bytes::from_base64(value.ciphertext)?),
            recipients: if value.recipients.is_empty() {
                None
            } else {
                Some(
                    value
                        .recipients
                        .drain(..)
                        .map(EncodedRecipient::try_from)
                        .collect::<Result<Vec<EncodedRecipient>, Self::Error>>()?,
                )
            },
            unprotected: if value.unprotected.is_empty() {
                None
            } else {
                Some(value.unprotected)
            },
        })
    }
}

impl TryFrom<Encoded> for JsonWebEncryption {
    type Error = Error;

    fn try_from(value: Encoded) -> Result<Self, Self::Error> {
        Ok(Self {
            aad: value.aad.to_base64(),
            ciphertext: value.ciphertext.to_base64().ok_or(Error::NotJwe)?,
            iv: value.iv.to_base64().ok_or(Error::NotJwe)?,
            protected: value.protected.to_base64().ok_or(Error::NotJwe)?,
            recipients: value
                .recipients
                .unwrap_or_else(|| Vec::new())
                .drain(..)
                .map(Recipient::from)
                .collect(),
            tag: value.tag.to_base64().ok_or(Error::NotJwe)?,
            unprotected: value.unprotected.unwrap_or_else(|| BTreeMap::new()),
        })
    }
}
impl TryFrom<Jose> for Encoded {
    type Error = Error;

    fn try_from(value: Jose) -> Result<Self, Self::Error> {
        match value {
            Jose::Signature(jws) => jws.try_into(),
            Jose::Encryption(jwe) => jwe.try_into(),
        }
    }
}

impl TryFrom<Encoded> for Jose {
    type Error = Error;

    fn try_from(value: Encoded) -> Result<Self, Self::Error> {
        Ok(match value.payload {
            Some(_) => Jose::Signature(value.try_into()?),
            None => Jose::Encryption(value.try_into()?),
        })
    }
}

#[derive(PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct EncodedSignature {
    // NOTE: Serde serialized fields in the order they appear
    // However DAG-CBOR specifies the fields must be serialized
    // sorted by length of key.
    //
    // We explicilty order the fields correctly below
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<BTreeMap<String, Ipld>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protected: Option<Bytes>,
    signature: Bytes,
}

impl TryFrom<Signature> for EncodedSignature {
    type Error = Error;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        Ok(Self {
            header: if value.header.is_empty() {
                None
            } else {
                Some(value.header)
            },
            protected: Option::from_base64(value.protected)?,
            signature: Bytes::from_base64(value.signature)?,
        })
    }
}

impl From<EncodedSignature> for Signature {
    fn from(value: EncodedSignature) -> Self {
        Self {
            header: value.header.unwrap_or_else(|| BTreeMap::new()),
            protected: value.protected.to_base64(),
            signature: value.signature.to_base64(),
        }
    }
}

#[derive(PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct EncodedRecipient {
    // NOTE: Serde serialized fields in the order they appear
    // However DAG-CBOR specifies the fields must be serialized
    // sorted by length of key.
    //
    // We explicilty order the fields correctly below
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<BTreeMap<String, Ipld>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_key: Option<Bytes>,
}

impl TryFrom<Recipient> for EncodedRecipient {
    type Error = Error;

    fn try_from(value: Recipient) -> Result<Self, Self::Error> {
        Ok(Self {
            header: if value.header.is_empty() {
                None
            } else {
                Some(value.header)
            },
            encrypted_key: Option::from_base64(value.encrypted_key)?,
        })
    }
}

impl From<EncodedRecipient> for Recipient {
    fn from(value: EncodedRecipient) -> Self {
        Self {
            encrypted_key: value.encrypted_key.to_base64(),
            header: value.header.unwrap_or_else(|| BTreeMap::new()),
        }
    }
}

trait FromBase64<T>: Sized {
    type Error;

    /// Decode a value from base64
    fn from_base64(value: T) -> Result<Self, Self::Error>;
}

impl FromBase64<String> for Bytes {
    type Error = Error;

    fn from_base64(value: String) -> Result<Self, Self::Error> {
        Ok((base64_url::decode(value.as_str())?).into())
    }
}

impl<T, U> FromBase64<Option<T>> for Option<U>
where
    U: FromBase64<T>,
{
    type Error = U::Error;

    fn from_base64(value: Option<T>) -> Result<Self, Self::Error> {
        value.map(|v| U::from_base64(v)).transpose()
    }
}

trait ToBase64<T>: Sized {
    /// Encode value to base64
    fn to_base64(self) -> T;
}
impl ToBase64<String> for Bytes {
    fn to_base64(self) -> String {
        base64_url::encode(&self.into_inner())
    }
}
impl<T, U> ToBase64<Option<T>> for Option<U>
where
    U: ToBase64<T>,
{
    fn to_base64(self) -> Option<T> {
        self.map(|v| v.to_base64())
    }
}
