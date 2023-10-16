use crate::preludes::*;

use anyhow::ensure;
use k256::{
    ecdh::SharedSecret,
    ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey},
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

pub fn check_message(data: &[u8]) -> Result<(SignedMessage, RawMessage)> {
    ensure!(data.len() > 0, "Message should not be empty!");

    let mut hasher = Keccak256::new();

    let msg = SignedMessage::decode(data)?;
    let SignedMessage {
        raw,
        hash,
        nonce,
        signature,
        ..
    } = msg.clone();
    let raw = raw.as_slice();
    let hash = hash.as_slice();
    let hash_hex = hex::encode(hash);
    hasher.update(raw);
    hasher.update(nonce.to_string().as_bytes());
    let curr_hash = hasher.finalize_reset();
    ensure!(
        hash == curr_hash.as_slice(),
        "Hash verification failed: expected=0x{} current=0x{}",
        hash_hex,
        hex::encode(curr_hash)
    );
    debug!("Raw message hash: 0x{}", hash_hex);

    let raw_msg = RawMessage::decode(raw)?;
    let RawMessage {
        timestamp,
        from_address,
        ..
    } = raw_msg.clone();
    ensure!(
        nonce == timestamp,
        "Message timestamp check failed: outer={} inner={}",
        nonce,
        timestamp
    );

    let from_address = from_address.as_slice();
    let from_address_hex = hex::encode(from_address);
    let signature = signature.as_slice();
    ensure!(signature.len() == 65, "Bad signature length!");
    let r = &signature[0..32];
    let s = &signature[32..64];
    let v = &signature[64..];
    debug!(
        "R: 0x{}\nS: 0x{}\nV: 0x{}\nSigner address: 0x{}",
        hex::encode(r),
        hex::encode(s),
        hex::encode(v),
        from_address_hex,
    );
    let rs = Signature::try_from(&signature[0..64])?;
    let v = RecoveryId::try_from(v[0])?;
    hasher.update(hash);
    let r_key = VerifyingKey::recover_from_digest(hasher, &rs, v)?;
    let r_key_addr = get_eth_address_bytes(&r_key);
    let r_key_addr = r_key_addr.as_ref();
    ensure!(
        from_address == r_key_addr.as_ref(),
        "Signature check failed! expected_signer=0x{} actual_signer=0x{}",
        from_address_hex,
        hex::encode(r_key_addr)
    );
    debug!(
        "Signer public key: 0x{}",
        hex::encode(r_key.to_sec1_bytes())
    );
    debug!(
        "Last touched: 0x{}",
        if let Some(addr) = &msg.last_edge_addr {
            let addr = addr.as_slice();
            hex::encode(addr)
        } else {
            "None".to_string()
        }
    );

    Ok((msg, raw_msg))
}
