//! JOSE error types.
use ipld_core::cid;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("data not a JWE value")]
    NotJwe,
    #[error("data not a JWS value")]
    NotJws,
    #[error("invalid CID data in payload")]
    InvalidCid(#[from] cid::Error),
    #[error("invalid base64 url data")]
    InvalidBase64Url(#[from] base64_url::base64::DecodeError),
    #[error("invalid cbor encoding")]
    Codec(#[from] serde_ipld_dagcbor::error::CodecError),
    #[error("failed encoding")]
    CborEncode(#[from] serde_ipld_dagcbor::EncodeError<std::io::Error>),
    #[error("failed decoding")]
    CborDecode(#[from] serde_ipld_dagcbor::DecodeError<std::io::Error>),
    #[cfg(feature = "dag-json")]
    #[error("failed encoding")]
    JsonEncode(#[from] serde_ipld_dagjson::EncodeError),
    #[cfg(feature = "dag-json")]
    #[error("failed decoding")]
    JsonDecode(#[from] serde_ipld_dagjson::DecodeError),
}
