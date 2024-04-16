//! DAG-JOSE codec.
//!
//! Structures are provided for encoding and decoding JSON Web Signatures and Encryption values.
//!
//! ```
//! use dag_jose::{DagJoseCodec, Jose};
//! use ipld_core::codec::Codec;
//!
//!     let data = hex::decode("
//! a2677061796c6f616458240171122089556551c3926679cc52c72e182a5619056a4727409ee93a26
//! d05ad727ca11f46a7369676e61747572657381a26970726f7465637465644f7b22616c67223a2245
//! 64445341227d697369676e61747572655840fbff49e4e65c979955b9196023534913373416a11beb
//! fdb256c9146903ddb9c450e287be379ca70a5e7bc039b848fb66d4bd5b96dae986941e04e7968d55
//! b505".chars().filter(|c| !c.is_whitespace()).collect::<String>()).unwrap();
//!
//!     // Decode binary data into an JOSE value.
//!     let jose: Jose = DagJoseCodec::decode_from_slice(&data).unwrap();
//!
//!     // Encode an JOSE value into bytes
//!     let bytes = DagJoseCodec::encode_to_vec(&jose).unwrap();
//!
//!     assert_eq!(data, bytes);
//! ```
//!
#![cfg_attr(
    feature = "dag-json",
    doc = "
 With the feature `dag-json` the JOSE values may also be encoded to DAG-JSON.

 ```
 use dag_jose::{DagJoseCodec, Jose};
 use ipld_core::codec::Codec;
 use serde_ipld_dagjson::codec::DagJsonCodec;

     let data = hex::decode(\"
 a2677061796c6f616458240171122089556551c3926679cc52c72e182a5619056a4727409ee93a26
 d05ad727ca11f46a7369676e61747572657381a26970726f7465637465644f7b22616c67223a2245
 64445341227d697369676e61747572655840fbff49e4e65c979955b9196023534913373416a11beb
 fdb256c9146903ddb9c450e287be379ca70a5e7bc039b848fb66d4bd5b96dae986941e04e7968d55
 b505\".chars().filter(|c| !c.is_whitespace()).collect::<String>()).unwrap();

     // Decode binary data into an JOSE value.
     let jose: Jose = DagJoseCodec::decode_from_slice(&data).unwrap();

     // Encode an JOSE value into DAG-JSON bytes
     let bytes = DagJsonCodec::encode_to_vec(&jose).unwrap();

     assert_eq!(String::from_utf8(bytes).unwrap(), r#\"{
         \"link\":{\"/\":\"bafyreiejkvsvdq4smz44yuwhfymcuvqzavveoj2at3utujwqlllspsqr6q\"},
         \"payload\":\"AXESIIlVZVHDkmZ5zFLHLhgqVhkFakcnQJ7pOibQWtcnyhH0\",
         \"signatures\":[{
             \"protected\":\"eyJhbGciOiJFZERTQSJ9\",
             \"signature\":\"-_9J5OZcl5lVuRlgI1NJEzc0FqEb6_2yVskUaQPducRQ4oe-N5ynCl57wDm4SPtm1L1bltrphpQeBOeWjVW1BQ\"
         }]}\"#.chars().filter(|c| !c.is_whitespace()).collect::<String>());
 ```
 "
)]
#![cfg_attr(
    not(feature = "dag-json"),
    doc = "Enable the feature 'dag-json' to be able to encode/decode Jose values using DAG-JSON."
)]
#![deny(missing_docs)]

mod bytes;
mod codec;
mod error;

use std::collections::BTreeMap;

use ipld_core::{
    cid::Cid,
    codec::{Codec, Links},
    ipld,
    ipld::Ipld,
};
use serde_derive::Serialize;
use serde_ipld_dagcbor::codec::DagCborCodec;
#[cfg(feature = "dag-json")]
use serde_ipld_dagjson::codec::DagJsonCodec;

use codec::Encoded;

/// DAG-JOSE codec
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DagJoseCodec;

impl Links for DagJoseCodec {
    type LinksError = error::Error;

    fn links(bytes: &[u8]) -> Result<impl Iterator<Item = Cid>, Self::LinksError> {
        Ok(DagCborCodec::links(bytes)?)
    }
}
impl Codec<Ipld> for DagJoseCodec {
    const CODE: u64 = 0x85;

    type Error = error::Error;

    fn decode<R: std::io::BufRead>(reader: R) -> Result<Ipld, Self::Error> {
        Ok(serde_ipld_dagcbor::from_reader(reader)?)
    }

    fn encode<W: std::io::Write>(writer: W, data: &Ipld) -> Result<(), Self::Error> {
        Ok(serde_ipld_dagcbor::to_writer(writer, data)?)
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

impl Codec<Jose> for DagJoseCodec {
    const CODE: u64 = 0x85;

    type Error = error::Error;

    fn decode<R: std::io::BufRead>(reader: R) -> Result<Jose, Self::Error> {
        let encoded: Encoded = serde_ipld_dagcbor::from_reader(reader)?;
        encoded.try_into()
    }

    fn encode<W: std::io::Write>(writer: W, data: &Jose) -> Result<(), Self::Error> {
        let encoded: Encoded = data.try_into()?;
        Ok(serde_ipld_dagcbor::to_writer(writer, &encoded)?)
    }
}

#[cfg(feature = "dag-json")]
impl Codec<Jose> for DagJsonCodec {
    const CODE: u64 = 0x0129;
    type Error = error::Error;

    fn decode<R: std::io::BufRead>(reader: R) -> Result<Jose, Self::Error> {
        let encoded: Encoded = serde_ipld_dagjson::from_reader(reader)?;
        encoded.try_into()
    }

    fn encode<W: std::io::Write>(writer: W, data: &Jose) -> Result<(), Self::Error> {
        match data {
            Jose::Signature(jws) => DagJsonCodec::encode(writer, jws),
            Jose::Encryption(jwe) => DagJsonCodec::encode(writer, jwe),
        }
    }
}

/// A JSON Web Signature object as defined in RFC7515.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct JsonWebSignature {
    /// CID link from the payload.
    pub link: Cid,

    /// The payload base64 url encoded.
    pub payload: String,

    /// The set of signatures.
    pub signatures: Vec<Signature>,
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

impl Codec<JsonWebSignature> for DagJoseCodec {
    const CODE: u64 = 0x85;

    type Error = error::Error;

    fn decode<R: std::io::BufRead>(reader: R) -> Result<JsonWebSignature, Self::Error> {
        let encoded: Encoded = serde_ipld_dagcbor::from_reader(reader)?;
        encoded.try_into()
    }

    fn encode<W: std::io::Write>(writer: W, data: &JsonWebSignature) -> Result<(), Self::Error> {
        let encoded: Encoded = data.try_into()?;
        Ok(serde_ipld_dagcbor::to_writer(writer, &encoded)?)
    }
}

#[cfg(feature = "dag-json")]
impl Codec<JsonWebSignature> for DagJsonCodec {
    const CODE: u64 = 0x0129;

    type Error = error::Error;

    fn decode<R: std::io::BufRead>(reader: R) -> Result<JsonWebSignature, Self::Error> {
        let encoded: Encoded = serde_ipld_dagjson::from_reader(reader)?;
        encoded.try_into()
    }

    fn encode<W: std::io::Write>(writer: W, data: &JsonWebSignature) -> Result<(), Self::Error> {
        // Here we directly encode the JsonWebSignature type without using the Encoded type.
        // This is because when encoding to DAG-JSON we do not want to encode the payload etc at
        // raw bytes but instead encode them as base64url encoded strings.
        Ok(serde_ipld_dagjson::to_writer(writer, &data)?)
    }
}

/// A signature part of a JSON Web Signature.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Signature {
    /// The optional unprotected header.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
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
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct JsonWebEncryption {
    /// The optional additional authenticated data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,

    /// The ciphertext value resulting from authenticated encryption of the
    /// plaintext with additional authenticated data.
    pub ciphertext: String,

    /// Initialization Vector value used when encrypting the plaintext base64 url encoded.
    pub iv: String,

    /// The protected header as a JSON object base64 url encoded.
    pub protected: String,

    /// The set of recipients.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<Recipient>,

    /// The authentication tag value resulting from authenticated encryption.
    pub tag: String,

    /// The optional unprotected header.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
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

impl Codec<JsonWebEncryption> for DagJoseCodec {
    const CODE: u64 = 0x85;

    type Error = error::Error;

    fn decode<R: std::io::BufRead>(reader: R) -> Result<JsonWebEncryption, Self::Error> {
        let encoded: Encoded = serde_ipld_dagcbor::from_reader(reader)?;
        encoded.try_into()
    }

    fn encode<W: std::io::Write>(writer: W, data: &JsonWebEncryption) -> Result<(), Self::Error> {
        let encoded: Encoded = data.try_into()?;
        Ok(serde_ipld_dagcbor::to_writer(writer, &encoded)?)
    }
}

#[cfg(feature = "dag-json")]
impl Codec<JsonWebEncryption> for DagJsonCodec {
    const CODE: u64 = 0x0129;

    type Error = error::Error;

    fn decode<R: std::io::BufRead>(reader: R) -> Result<JsonWebEncryption, Self::Error> {
        let encoded: Encoded = serde_ipld_dagjson::from_reader(reader)?;
        encoded.try_into()
    }

    fn encode<W: std::io::Write>(writer: W, data: &JsonWebEncryption) -> Result<(), Self::Error> {
        // Here we directly encode the JsonWebEncryption type without using the Encoded type.
        // This is because when encoding to DAG-JSON we do not want to encode the protected field etc as
        // raw bytes but instead encode them as base64url encoded strings.
        Ok(serde_ipld_dagjson::to_writer(writer, &data)?)
    }
}

/// A recipient of a JSON Web Encryption message.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Recipient {
    /// The encrypted content encryption key value.
    pub encrypted_key: Option<String>,

    /// The optional unprotected header.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
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

    struct JwsFixture {
        payload: Box<[u8]>,
        protected: Box<[u8]>,
        signature: Box<[u8]>,
    }
    fn fixture_jws() -> JwsFixture {
        let payload =
            base64_url::decode("AXESIIlVZVHDkmZ5zFLHLhgqVhkFakcnQJ7pOibQWtcnyhH0").unwrap();
        let protected = base64_url::decode("eyJhbGciOiJFZERTQSJ9").unwrap();
        let signature =  base64_url::decode("-_9J5OZcl5lVuRlgI1NJEzc0FqEb6_2yVskUaQPducRQ4oe-N5ynCl57wDm4SPtm1L1bltrphpQeBOeWjVW1BQ").unwrap();
        JwsFixture {
            payload: payload.into_boxed_slice(),
            protected: protected.into_boxed_slice(),
            signature: signature.into_boxed_slice(),
        }
    }
    fn fixture_jws_base64(
        payload: &[u8],
        protected: &[u8],
        signature: &[u8],
    ) -> (String, String, String) {
        (
            base64_url::encode(payload),
            base64_url::encode(protected),
            base64_url::encode(signature),
        )
    }
    struct JweFixture {
        ciphertext: Box<[u8]>,
        iv: Box<[u8]>,
        protected: Box<[u8]>,
        tag: Box<[u8]>,
    }
    fn fixture_jwe() -> JweFixture {
        let ciphertext = base64_url::decode("3XqLW28NHP-raqW8vMfIHOzko4N3IRaR").unwrap();
        let iv = base64_url::decode("PSWIuAyO8CpevzCL").unwrap();
        let protected = base64_url::decode("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0").unwrap();
        let tag = base64_url::decode("WZAMBblhzDCsQWOAKdlkSA").unwrap();
        JweFixture {
            ciphertext: ciphertext.into_boxed_slice(),
            iv: iv.into_boxed_slice(),
            protected: protected.into_boxed_slice(),
            tag: tag.into_boxed_slice(),
        }
    }
    fn fixture_jwe_base64(
        ciphertext: &[u8],
        iv: &[u8],
        protected: &[u8],
        tag: &[u8],
    ) -> (String, String, String, String) {
        (
            base64_url::encode(ciphertext),
            base64_url::encode(iv),
            base64_url::encode(protected),
            base64_url::encode(tag),
        )
    }
    #[test]
    fn roundtrip_jws() {
        let JwsFixture {
            payload,
            protected,
            signature,
        } = fixture_jws();
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
        let JweFixture {
            ciphertext,
            iv,
            protected,
            tag,
        } = fixture_jwe();
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

    // Utility for testing codecs.
    //
    // Encodes the `data` using the codec `c` and checks that it matches the `ipld`.
    fn assert_roundtrip<C, T>(_c: C, data: &T, ipld: &Ipld)
    where
        C: Codec<T>,
        C: Codec<Ipld>,
        <C as Codec<T>>::Error: std::fmt::Debug,
        <C as Codec<Ipld>>::Error: std::fmt::Debug,
        T: std::cmp::PartialEq + std::fmt::Debug,
    {
        let bytes = C::encode_to_vec(data).unwrap();
        let bytes2 = C::encode_to_vec(ipld).unwrap();
        if bytes != bytes2 {
            panic!(
                r#"assertion failed: `(left == right)`
        left: `{}`,
       right: `{}`"#,
                hex::encode(&bytes),
                hex::encode(&bytes2)
            );
        }
        let ipld2: Ipld = C::decode_from_slice(&bytes).unwrap();
        assert_eq!(&ipld2, ipld);
        let data2: T = C::decode_from_slice(&bytes).unwrap();
        assert_eq!(&data2, data);
    }
}
