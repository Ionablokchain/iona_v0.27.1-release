use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("key error: {0}")]
    Key(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct PublicKeyBytes(pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureBytes(pub Vec<u8>);

pub trait Signer: Send + Sync {
    fn public_key(&self) -> PublicKeyBytes;
    fn sign(&self, msg: &[u8]) -> SignatureBytes;
}

pub trait Verifier: Send + Sync {
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError>;
}

pub mod ed25519;

pub mod tx;

pub mod keystore;

pub mod remote_signer;

pub mod hsm;
