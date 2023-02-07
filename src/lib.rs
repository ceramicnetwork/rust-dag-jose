//! Jose codec.
//! TODO
#![deny(missing_docs)]
#![deny(warnings)]

mod bytes;
mod codec;
mod error;

use std::{collections::BTreeMap, io::BufReader};

use libipld::codec::{Codec, Decode, Encode};
use libipld::error::UnsupportedCodec;
#[cfg(feature = "dag-json")]
use libipld::json::DagJsonCodec;
use libipld::Cid;
use libipld::Ipld;

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
        let encoded: Encoded = self.clone().try_into()?;
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
    // TODO Create a Base64Url encoded string type?
    pub payload: String,

    /// The set of signatures.
    pub signatures: Vec<Signature>,

    /// CID link from the payload.
    pub link: Cid,
}

impl Encode<DagJoseCodec> for JsonWebSignature {
    fn encode<W: std::io::Write>(&self, _c: DagJoseCodec, w: &mut W) -> anyhow::Result<()> {
        //TODO use reference
        let encoded: Encoded = self.clone().try_into()?;
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
    fn encode<W: std::io::Write>(&self, _c: DagJsonCodec, _w: &mut W) -> anyhow::Result<()> {
        todo!()
        //let decoded: Decoded = self.clone().try_into()?;
        //// TODO: add direct conversion of Decoded type to Ipld
        //let bytes = serde_ipld_dagcbor::to_vec(&decoded)?;
        //let data: Ipld = serde_ipld_dagcbor::from_slice(&bytes)?;
        //data.encode(c, w)
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
impl Encode<DagJoseCodec> for JsonWebEncryption {
    fn encode<W: std::io::Write>(&self, _c: DagJoseCodec, w: &mut W) -> anyhow::Result<()> {
        let encoded: Encoded = self.clone().try_into()?;
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
    fn encode<W: std::io::Write>(&self, _c: DagJsonCodec, _w: &mut W) -> anyhow::Result<()> {
        todo!()
        //let decoded: Decoded = self.clone().try_into()?;
        //// TODO: add direct conversion of Decoded type to Ipld
        //let bytes = serde_ipld_dagcbor::to_vec(&decoded)?;
        //let data: Ipld = serde_ipld_dagcbor::from_slice(&bytes)?;
        //data.encode(c, w)
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, io::Cursor};

    use super::*;

    use libipld::ipld;

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
    /// Utility for testing codecs.
    ///
    /// Encodes the `data` using the codec `c` and checks that it matches the `ipld`.
    fn assert_roundtrip<C, T>(c: C, data: &T, ipld: &Ipld)
    where
        C: Codec,
        T: Decode<C> + Encode<C> + core::fmt::Debug + PartialEq,
        Ipld: Decode<C> + Encode<C>,
    {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
        }
        let mut bytes = Vec::new();
        data.encode(c, &mut bytes).unwrap();
        let mut bytes2 = Vec::new();
        ipld.encode(c, &mut bytes2).unwrap();
        let ipld2: Ipld = Decode::decode(c, &mut Cursor::new(bytes.as_slice())).unwrap();
        assert_eq!(
            &ipld2, ipld,
            "decoded IPLD data is not equal\nleft: {:#?}\nright: {:#?}\n",
            &ipld2, ipld
        );
        let data2: T = Decode::decode(c, &mut Cursor::new(bytes.as_slice())).unwrap();
        assert_eq!(
            &data2, data,
            "decoded data is not equal\nleft: {:#?}\nright: {:#?}",
            &data2, data
        );

        if bytes != bytes2 {
            panic!(
                r#"assertion failed: `(left == right)`
        left: `{}`,
       right: `{}`"#,
                hex(&bytes),
                hex(&bytes2)
            );
        }
    }
}
