//! DAG-JOSE codec.
//!
//! Structures are provided for encoding and decoding JSON Web Signatures and Encryption values.
//!
//! ```
//! use std::io::Cursor;
//! use dag_jose::{DagJoseCodec, Jose};
//! use libipld::codec::{Decode, Encode};
//!
//! fn main() {
//!     let data = hex::decode("
//! a2677061796c6f616458240171122089556551c3926679cc52c72e182a5619056a4727409ee93a26
//! d05ad727ca11f46a7369676e61747572657381a26970726f7465637465644f7b22616c67223a2245
//! 64445341227d697369676e61747572655840fbff49e4e65c979955b9196023534913373416a11beb
//! fdb256c9146903ddb9c450e287be379ca70a5e7bc039b848fb66d4bd5b96dae986941e04e7968d55
//! b505".chars().filter(|c| !c.is_whitespace()).collect::<String>()).unwrap();
//!
//!     // Decode binary data into an JOSE value.
//!     let jose = Jose::decode(DagJoseCodec, &mut Cursor::new(&data)).unwrap();
//!
//!     // Encode an JOSE value into bytes
//!     let mut bytes = Vec::new();
//!     jose.encode(DagJoseCodec, &mut bytes).unwrap();
//!
//!     assert_eq!(data, bytes);
//! }
//! ```
//!
//! With the feature `dag-json` the JOSE values may also be encoded to DAG-JSON.
//!
//! ```
//! use std::io::Cursor;
//! use dag_jose::{DagJoseCodec, Jose};
//! use libipld::codec::{Decode, Encode};
//! use libipld_json::DagJsonCodec;
//!
//! fn main() {
//!     let data = hex::decode("
//! a2677061796c6f616458240171122089556551c3926679cc52c72e182a5619056a4727409ee93a26
//! d05ad727ca11f46a7369676e61747572657381a26970726f7465637465644f7b22616c67223a2245
//! 64445341227d697369676e61747572655840fbff49e4e65c979955b9196023534913373416a11beb
//! fdb256c9146903ddb9c450e287be379ca70a5e7bc039b848fb66d4bd5b96dae986941e04e7968d55
//! b505".chars().filter(|c| !c.is_whitespace()).collect::<String>()).unwrap();
//!
//!     // Decode binary data into an JOSE value.
//!     let jose = Jose::decode(DagJoseCodec, &mut Cursor::new(&data)).unwrap();
//!
//!     // Encode an JOSE value into DAG-JSON bytes
//!     let mut bytes = Vec::new();
//!     jose.encode(DagJsonCodec, &mut bytes).unwrap();
//!
//!     assert_eq!(String::from_utf8(bytes).unwrap(), r#"{
//!         "link":{"/":"bafyreiejkvsvdq4smz44yuwhfymcuvqzavveoj2at3utujwqlllspsqr6q"},
//!         "payload":"AXESIIlVZVHDkmZ5zFLHLhgqVhkFakcnQJ7pOibQWtcnyhH0",
//!         "signatures":[{
//!             "protected":"eyJhbGciOiJFZERTQSJ9",
//!             "signature":"-_9J5OZcl5lVuRlgI1NJEzc0FqEb6_2yVskUaQPducRQ4oe-N5ynCl57wDm4SPtm1L1bltrphpQeBOeWjVW1BQ"
//!         }]}"#.chars().filter(|c| !c.is_whitespace()).collect::<String>());
//! }
//! ```
#![deny(missing_docs)]
#![deny(warnings)]

mod bytes;
mod codec;
mod error;

use std::{collections::BTreeMap, io::BufReader};

use libipld::error::UnsupportedCodec;
use libipld::Cid;
use libipld::Ipld;
use libipld::{
    codec::{Codec, Decode, Encode},
    ipld,
};
#[cfg(feature = "dag-json")]
use libipld_json::DagJsonCodec;

use codec::Encoded;

/// DAG-JOSE codec
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DagJoseCodec;

impl Codec for DagJoseCodec {}

impl From<DagJoseCodec> for u64 {
    fn from(_: DagJoseCodec) -> Self {
        // Multicode comes from here https://github.com/multiformats/multicodec/blob/master/table.csv
        0x85
    }
}

impl TryFrom<u64> for DagJoseCodec {
    type Error = UnsupportedCodec;

    fn try_from(_: u64) -> core::result::Result<Self, Self::Error> {
        Ok(Self)
    }
}

impl Encode<DagJoseCodec> for Ipld {
    fn encode<W: std::io::Write>(&self, _c: DagJoseCodec, w: &mut W) -> anyhow::Result<()> {
        Ok(serde_ipld_dagcbor::to_writer(w, self)?)
    }
}
impl Decode<DagJoseCodec> for Ipld {
    fn decode<R: std::io::Read + std::io::Seek>(
        _c: DagJoseCodec,
        r: &mut R,
    ) -> anyhow::Result<Self> {
        Ok(serde_ipld_dagcbor::from_reader(BufReader::new(r))?)
    }
}

/// A JSON Object Signing and Encryption value as defined in RFC7165.
#[derive(Clone, Debug, PartialEq)]
pub enum Jose {
    /// JSON Web Signature value
    Signature(JsonWebSignature),
    /// JSON Web Encryption value
    Encryption(JsonWebEncryption),
}

impl Encode<DagJoseCodec> for Jose {
    fn encode<W: std::io::Write>(&self, _c: DagJoseCodec, w: &mut W) -> anyhow::Result<()> {
        let encoded: Encoded = self.try_into()?;
        Ok(serde_ipld_dagcbor::to_writer(w, &encoded)?)
    }
}
impl Decode<DagJoseCodec> for Jose {
    fn decode<R: std::io::Read + std::io::Seek>(
        _c: DagJoseCodec,
        r: &mut R,
    ) -> anyhow::Result<Self> {
        let encoded: Encoded = serde_ipld_dagcbor::from_reader(BufReader::new(r))?;
        Ok(encoded.try_into()?)
    }
}

#[cfg(feature = "dag-json")]
impl Encode<DagJsonCodec> for Jose {
    fn encode<W: std::io::Write>(&self, c: DagJsonCodec, w: &mut W) -> anyhow::Result<()> {
        match self {
            Jose::Signature(jws) => jws.encode(c, w),
            Jose::Encryption(jwe) => jwe.encode(c, w),
        }
    }
}

/// A JSON Web Signature object as defined in RFC7515.
#[derive(Clone, Debug, PartialEq)]
pub struct JsonWebSignature {
    /// The payload base64 url encoded.
    pub payload: String,

    /// The set of signatures.
    pub signatures: Vec<Signature>,

    /// CID link from the payload.
    pub link: Cid,
}

impl<'a> From<&'a JsonWebSignature> for Ipld {
    fn from(value: &'a JsonWebSignature) -> Self {
        ipld!({
            "payload": value.payload.to_owned(),
            "signatures": value.signatures.iter().map(Ipld::from).collect::<Vec<Ipld>>(),
            "link": value.link,
        })
    }
}

impl Encode<DagJoseCodec> for JsonWebSignature {
    fn encode<W: std::io::Write>(&self, _c: DagJoseCodec, w: &mut W) -> anyhow::Result<()> {
        let encoded: Encoded = self.try_into()?;
        Ok(serde_ipld_dagcbor::to_writer(w, &encoded)?)
    }
}
impl Decode<DagJoseCodec> for JsonWebSignature {
    fn decode<R: std::io::Read + std::io::Seek>(
        _c: DagJoseCodec,
        r: &mut R,
    ) -> anyhow::Result<Self> {
        let encoded: Encoded = serde_ipld_dagcbor::from_reader(BufReader::new(r))?;
        Ok(encoded.try_into()?)
    }
}
#[cfg(feature = "dag-json")]
impl Encode<DagJsonCodec> for JsonWebSignature {
    fn encode<W: std::io::Write>(&self, c: DagJsonCodec, w: &mut W) -> anyhow::Result<()> {
        let data: Ipld = self.into();
        data.encode(c, w)
    }
}

/// A signature part of a JSON Web Signature.
#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    /// The optional unprotected header.
    pub header: BTreeMap<String, Ipld>,
    /// The protected header as a JSON object base64 url encoded.
    pub protected: Option<String>,
    /// The web signature base64 url encoded.
    pub signature: String,
}

impl<'a> From<&'a Signature> for Ipld {
    fn from(value: &'a Signature) -> Self {
        let mut fields: BTreeMap<String, Ipld> = BTreeMap::new();
        if !value.header.is_empty() {
            fields.insert("header".to_string(), value.header.to_owned().into());
        }
        if let Some(protected) = value.protected.to_owned() {
            fields.insert("protected".to_string(), protected.into());
        };
        fields.insert("signature".to_string(), value.signature.to_owned().into());
        Ipld::Map(fields)
    }
}

/// A JSON Web Encryption object as defined in RFC7516.
#[derive(Clone, Debug, PartialEq)]
pub struct JsonWebEncryption {
    /// The optional additional authenticated data.
    pub aad: Option<String>,

    /// The ciphertext value resulting from authenticated encryption of the
    /// plaintext with additional authenticated data.
    pub ciphertext: String,

    /// Initialization Vector value used when encrypting the plaintext base64 url encoded.
    pub iv: String,

    /// The protected header as a JSON object base64 url encoded.
    pub protected: String,

    /// The set of recipients.
    pub recipients: Vec<Recipient>,

    /// The authentication tag value resulting from authenticated encryption.
    pub tag: String,

    /// The optional unprotected header.
    pub unprotected: BTreeMap<String, Ipld>,
}

impl<'a> From<&'a JsonWebEncryption> for Ipld {
    fn from(value: &'a JsonWebEncryption) -> Self {
        let mut fields: BTreeMap<String, Ipld> = BTreeMap::new();
        if let Some(aad) = value.aad.to_owned() {
            fields.insert("aad".to_string(), aad.into());
        }
        fields.insert("ciphertext".to_string(), value.ciphertext.to_owned().into());
        fields.insert("iv".to_string(), value.iv.to_owned().into());
        fields.insert("protected".to_string(), value.protected.to_owned().into());
        if !value.recipients.is_empty() {
            fields.insert(
                "recipients".to_string(),
                value
                    .recipients
                    .iter()
                    .map(Ipld::from)
                    .collect::<Vec<Ipld>>()
                    .into(),
            );
        }

        fields.insert("tag".to_string(), value.tag.to_owned().into());
        if !value.unprotected.is_empty() {
            fields.insert(
                "unprotected".to_string(),
                value.unprotected.to_owned().into(),
            );
        }
        Ipld::Map(fields)
    }
}
impl Encode<DagJoseCodec> for JsonWebEncryption {
    fn encode<W: std::io::Write>(&self, _c: DagJoseCodec, w: &mut W) -> anyhow::Result<()> {
        let encoded: Encoded = self.try_into()?;
        Ok(serde_ipld_dagcbor::to_writer(w, &encoded)?)
    }
}
impl Decode<DagJoseCodec> for JsonWebEncryption {
    fn decode<R: std::io::Read + std::io::Seek>(
        _c: DagJoseCodec,
        r: &mut R,
    ) -> anyhow::Result<Self> {
        let encoded: Encoded = serde_ipld_dagcbor::from_reader(BufReader::new(r))?;
        Ok(encoded.try_into()?)
    }
}

#[cfg(feature = "dag-json")]
impl Encode<DagJsonCodec> for JsonWebEncryption {
    fn encode<W: std::io::Write>(&self, c: DagJsonCodec, w: &mut W) -> anyhow::Result<()> {
        let data: Ipld = self.into();
        data.encode(c, w)
    }
}

/// A recipient of a JSON Web Encryption message.
#[derive(Clone, Debug, PartialEq)]
pub struct Recipient {
    /// The encrypted content encryption key value.
    pub encrypted_key: Option<String>,

    /// The optional unprotected header.
    pub header: BTreeMap<String, Ipld>,
}

impl<'a> From<&'a Recipient> for Ipld {
    fn from(value: &'a Recipient) -> Self {
        let mut fields: BTreeMap<String, Ipld> = BTreeMap::new();
        if let Some(encrypted_key) = value.encrypted_key.to_owned() {
            fields.insert("encrypted_key".to_string(), encrypted_key.into());
        }
        if !value.header.is_empty() {
            fields.insert("header".to_string(), value.header.to_owned().into());
        }
        Ipld::Map(fields)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    use libipld::{codec::assert_roundtrip, ipld};

    fn fixture_jws() -> (Box<[u8]>, Box<[u8]>, Box<[u8]>) {
        let payload =
            base64_url::decode("AXESIIlVZVHDkmZ5zFLHLhgqVhkFakcnQJ7pOibQWtcnyhH0").unwrap();
        let protected = base64_url::decode("eyJhbGciOiJFZERTQSJ9").unwrap();
        let signature =  base64_url::decode("-_9J5OZcl5lVuRlgI1NJEzc0FqEb6_2yVskUaQPducRQ4oe-N5ynCl57wDm4SPtm1L1bltrphpQeBOeWjVW1BQ").unwrap();
        (
            payload.into_boxed_slice(),
            protected.into_boxed_slice(),
            signature.into_boxed_slice(),
        )
    }
    fn fixture_jws_base64(
        payload: &Box<[u8]>,
        protected: &Box<[u8]>,
        signature: &Box<[u8]>,
    ) -> (String, String, String) {
        (
            base64_url::encode(payload.as_ref()),
            base64_url::encode(protected.as_ref()),
            base64_url::encode(signature.as_ref()),
        )
    }
    fn fixture_jwe() -> (Box<[u8]>, Box<[u8]>, Box<[u8]>, Box<[u8]>) {
        let ciphertext = base64_url::decode("3XqLW28NHP-raqW8vMfIHOzko4N3IRaR").unwrap();
        let iv = base64_url::decode("PSWIuAyO8CpevzCL").unwrap();
        let protected = base64_url::decode("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0").unwrap();
        let tag = base64_url::decode("WZAMBblhzDCsQWOAKdlkSA").unwrap();
        (
            ciphertext.into_boxed_slice(),
            iv.into_boxed_slice(),
            protected.into_boxed_slice(),
            tag.into_boxed_slice(),
        )
    }
    fn fixture_jwe_base64(
        ciphertext: &Box<[u8]>,
        iv: &Box<[u8]>,
        protected: &Box<[u8]>,
        tag: &Box<[u8]>,
    ) -> (String, String, String, String) {
        (
            base64_url::encode(ciphertext.as_ref()),
            base64_url::encode(iv.as_ref()),
            base64_url::encode(protected.as_ref()),
            base64_url::encode(tag.as_ref()),
        )
    }
    #[test]
    fn roundtrip_jws() {
        let (payload, protected, signature) = fixture_jws();
        let (payload_b64, protected_b64, signature_b64) =
            fixture_jws_base64(&payload, &protected, &signature);
        let link = Cid::try_from(base64_url::decode(&payload_b64).unwrap()).unwrap();
        assert_roundtrip(
            DagJoseCodec,
            &JsonWebSignature {
                payload: payload_b64,
                signatures: vec![Signature {
                    header: BTreeMap::from([
                        ("k0".to_string(), Ipld::from("v0")),
                        ("k1".to_string(), Ipld::from(1)),
                    ]),
                    protected: Some(protected_b64),
                    signature: signature_b64,
                }],
                link,
            },
            &ipld!({
                "payload": payload,
                "signatures": [{
                    "header": {
                        "k0": "v0",
                        "k1": 1
                    },
                    "protected": protected,
                    "signature": signature,
                }],
            }),
        );
    }
    #[test]
    fn roundtrip_jwe() {
        let (ciphertext, iv, protected, tag) = fixture_jwe();
        let (ciphertext_b64, iv_b64, protected_b64, tag_b64) =
            fixture_jwe_base64(&ciphertext, &iv, &protected, &tag);
        assert_roundtrip(
            DagJoseCodec,
            &JsonWebEncryption {
                aad: None,
                ciphertext: ciphertext_b64,
                iv: iv_b64,
                protected: protected_b64,
                recipients: vec![],
                tag: tag_b64,
                unprotected: BTreeMap::new(),
            },
            &ipld!({
                "ciphertext": ciphertext,
                "iv": iv,
                "protected": protected,
                "tag": tag,
            }),
        );
    }
}
