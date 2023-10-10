use crate::preludes::*;

use k256::{
    ecdh::SharedSecret,
    ecdsa::{SigningKey, VerifyingKey},
};
use sha3::{Digest, Keccak256};

pub fn get_eth_address(key: &VerifyingKey) -> String {
    let key = key.to_encoded_point(false);
    let key = key.as_bytes();
    let mut hasher = Keccak256::default();
    hasher.update(&key[1..]);
    let hash = hasher.finalize();
    format!("0x{}", hex::encode(&hash[12..]))
}

pub fn parse_signing_key<T: Into<String>>(key_str: T) -> Result<SigningKey> {
    let bytes = hex::decode(key_str.into())?;
    let bytes = bytes.as_slice();
    Ok(SigningKey::from_slice(bytes)?)
}

pub fn clone_shared_secret(k: &SharedSecret) -> SharedSecret {
    let k = k.raw_secret_bytes().clone();
    SharedSecret::from(k)
}
