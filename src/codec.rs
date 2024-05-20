//! Implementation of the DAG-JOSE code by defining DAG-CBOR structure.
#![deny(missing_docs)]
#![deny(warnings)]

use ipld_core::cid::Cid;
use ipld_core::ipld::Ipld;
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
    //
    // Additionally according to the spec:
    //
    //  > Any field which is represented as base64url(<data>) we map directly to Bytes.
    //
    //  https://ipld.io/specs/codecs/dag-jose/spec/#mapping-from-the-jose-general-json-serialization-to-dag-jose-serialization
    //
    // This means that these fields are represented as a Bytes type of the raw bytes of the field
    // so they can be DAB-CBOR encoded/decoded as raw bytes not a base64url encoded string..
    //
    // When we convert the data to a Jose object we construct the base64url encoded string from the
    // raw bytes.
    //
    // The dag-json feature takes advantage of this to encode the Jose structs directly preserving
    // the base64url encoded string.

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

impl<'a> TryFrom<&'a JsonWebSignature> for Encoded {
    type Error = Error;

    fn try_from(value: &'a JsonWebSignature) -> Result<Self, Self::Error> {
        Ok(Self {
            payload: Some(value.payload.decode_base64()?),
            signatures: if value.signatures.is_empty() {
                None
            } else {
                Some(
                    value
                        .signatures
                        .iter()
                        .map(EncodedSignature::try_from)
                        .collect::<Result<Vec<EncodedSignature>, Self::Error>>()?,
                )
            },
            ..Default::default()
        })
    }
}

impl TryFrom<Encoded> for JsonWebSignature {
    type Error = Error;

    fn try_from(value: Encoded) -> Result<Self, Self::Error> {
        let payload = value.payload.as_ref().ok_or(Error::NotJws)?;

        let (link, pld) = match serde_json::from_slice::<serde_json::Value>(payload.as_ref()) {
            Ok(json) => {
                let res = match crate::JsonPld(json).try_into().map_err(|_| Error::NotJws)? {
                    Ipld::Map(map) => map,
                    _ => return Err(Error::NotJws),
                };
                (None, Some(res))
            }
            Err(_) => (Some(Cid::try_from(payload.as_ref())?), None),
        };
        Ok(Self {
            payload: value
                .payload
                .map(|v| v.encode_base64())
                .ok_or(Error::NotJws)?,
            signatures: value
                .signatures
                .unwrap_or_default()
                .into_iter()
                .map(Signature::from)
                .collect(),
            link,
            pld,
        })
    }
}

impl<'a> TryFrom<&'a JsonWebEncryption> for Encoded {
    type Error = Error;

    fn try_from(value: &'a JsonWebEncryption) -> Result<Self, Self::Error> {
        Ok(Self {
            iv: if value.iv.is_empty() {
                None
            } else {
                Some(value.iv.decode_base64()?)
            },
            aad: value.aad.as_ref().map(|v| v.decode_base64()).transpose()?,
            tag: if value.tag.is_empty() {
                None
            } else {
                Some(value.tag.decode_base64()?)
            },
            protected: if value.protected.is_empty() {
                None
            } else {
                Some(value.protected.decode_base64()?)
            },
            ciphertext: Some(value.ciphertext.decode_base64()?),
            recipients: if value.recipients.is_empty() {
                None
            } else {
                Some(
                    value
                        .recipients
                        .iter()
                        .map(EncodedRecipient::try_from)
                        .collect::<Result<Vec<EncodedRecipient>, Self::Error>>()?,
                )
            },
            unprotected: if value.unprotected.is_empty() {
                None
            } else {
                Some(value.unprotected.to_owned())
            },
            ..Default::default()
        })
    }
}

impl TryFrom<Encoded> for JsonWebEncryption {
    type Error = Error;

    fn try_from(value: Encoded) -> Result<Self, Self::Error> {
        Ok(Self {
            aad: value.aad.map(|v| v.encode_base64()),
            ciphertext: value
                .ciphertext
                .map(|v| v.encode_base64())
                .ok_or(Error::NotJwe)?,
            iv: value.iv.map(|v| v.encode_base64()).ok_or(Error::NotJwe)?,
            protected: value
                .protected
                .map(|v| v.encode_base64())
                .ok_or(Error::NotJwe)?,
            recipients: value
                .recipients
                .unwrap_or_default()
                .into_iter()
                .map(Recipient::from)
                .collect(),
            tag: value.tag.map(|v| v.encode_base64()).ok_or(Error::NotJwe)?,
            unprotected: value.unprotected.unwrap_or_default(),
        })
    }
}
impl<'a> TryFrom<&'a Jose> for Encoded {
    type Error = Error;

    fn try_from(value: &'a Jose) -> Result<Self, Self::Error> {
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

impl<'a> TryFrom<&'a Signature> for EncodedSignature {
    type Error = Error;

    fn try_from(value: &'a Signature) -> Result<Self, Self::Error> {
        Ok(Self {
            header: if value.header.is_empty() {
                None
            } else {
                Some(value.header.to_owned())
            },
            protected: value
                .protected
                .as_ref()
                .map(|v| v.decode_base64())
                .transpose()?,
            signature: value.signature.decode_base64()?,
        })
    }
}

impl From<EncodedSignature> for Signature {
    fn from(value: EncodedSignature) -> Self {
        Self {
            header: value.header.unwrap_or_default(),
            protected: value.protected.map(|v| v.encode_base64()),
            signature: value.signature.encode_base64(),
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

impl<'a> TryFrom<&'a Recipient> for EncodedRecipient {
    type Error = Error;

    fn try_from(value: &'a Recipient) -> Result<Self, Self::Error> {
        Ok(Self {
            header: if value.header.is_empty() {
                None
            } else {
                Some(value.header.to_owned())
            },
            encrypted_key: value
                .encrypted_key
                .as_ref()
                .map(|v| v.decode_base64())
                .transpose()?,
        })
    }
}

impl From<EncodedRecipient> for Recipient {
    fn from(value: EncodedRecipient) -> Self {
        Self {
            encrypted_key: value.encrypted_key.map(|v| v.encode_base64()),
            header: value.header.unwrap_or_default(),
        }
    }
}

/// Decode base64 url encoded data from Self into T.
trait DecodeBase64<T: From<Vec<u8>>>: AsRef<[u8]> {
    type Error: From<base64_url::base64::DecodeError>;

    fn decode_base64(&self) -> Result<T, Self::Error> {
        Ok(T::from(base64_url::decode(self.as_ref())?))
    }
}

impl DecodeBase64<Bytes> for String {
    type Error = Error;
}
impl<'a> DecodeBase64<Bytes> for &'a str {
    type Error = Error;
}

/// Encode data from Self into a base64 url encoded string.
trait EncodeBase64: AsRef<[u8]> {
    /// Encode value using base64 url encoding.
    fn encode_base64(&self) -> String {
        base64_url::encode(self.as_ref())
    }
}

impl EncodeBase64 for Bytes {}
