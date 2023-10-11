use crate::preludes::*;

use k256::{
    ecdh::SharedSecret,
    ecdsa::{SigningKey, VerifyingKey},
};
use sha3::{Digest, Keccak256};

pub fn get_eth_address_bytes(key: &VerifyingKey) -> Bytes {
    let key = key.to_encoded_point(false);
    let key = key.as_bytes();
    let mut hasher = Keccak256::default();
    hasher.update(&key[1..]);
    let hash = hasher.finalize();
    Bytes::copy_from_slice(&hash[12..])
}

pub fn get_eth_address(key: &VerifyingKey) -> String {
    format!("0x{}", hex::encode(get_eth_address_bytes(key)))
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

pub fn did_str_to_addr_bytes<T: Into<String>>(did_str: T) -> Result<Vec<u8>> {
    let did_str: String = did_str.into();
    let did_str = did_str
        .strip_prefix("did:dephy:0x")
        .ok_or(anyhow!("Not in DID string format."))?;
    if did_str.len() != 40 {
        bail!("Invalid length for an DID string format.")
    }
    Ok(hex::decode(did_str)?)
}
