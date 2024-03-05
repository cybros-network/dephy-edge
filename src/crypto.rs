use crate::nostr::default_kind;
use crate::preludes::*;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockEncryptMut, KeyIvInit};
use anyhow::ensure;
use dephy_types::borsh::{from_slice, to_vec};
use k256::{
    ecdh::{diffie_hellman, SharedSecret},
    ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey},
    PublicKey,
};
use rand::{rngs::OsRng, Fill};
use sha3::{Digest, Keccak256};
use std::time::{SystemTime, UNIX_EPOCH};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

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

    let msg = from_slice::<SignedMessage>(data)?;
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

    let raw_msg = from_slice::<RawMessage>(raw)?;
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
        from_address == r_key_addr,
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

#[async_trait::async_trait]
pub trait DephySigningKey {
    async fn create_message(
        &self,
        session_id: Vec<u8>,
        nonce: Option<u64>,
        channel: MessageChannel,
        payload: Vec<u8>,
        to_address: Option<Vec<u8>>,
        encr_target: Option<PublicKey>,
    ) -> Result<(SignedMessage, RawMessage)>;
    async fn create_nostr_event(
        &self,
        session_id: Vec<u8>,
        nonce: Option<u64>,
        channel: MessageChannel,
        payload: Vec<u8>,
        to_address: Option<Vec<u8>>,
        encr_target: Option<PublicKey>,
        keys: &Keys,
    ) -> Result<Event>;
    fn eth_addr(&self) -> Bytes;
    fn eth_addr_string(&self) -> String;
    fn public_key(&self) -> PublicKey;
}

#[async_trait::async_trait]
impl DephySigningKey for SigningKey {
    async fn create_message(
        &self,
        session_id: Vec<u8>,
        nonce: Option<u64>,
        channel: MessageChannel,
        payload: Vec<u8>,
        to_address: Option<Vec<u8>>,
        encr_target: Option<PublicKey>,
    ) -> Result<(SignedMessage, RawMessage)> {
        let iv = if encr_target.is_some() {
            let mut buf = [0u8; 16];
            buf.try_fill(&mut OsRng)?;
            Some(buf.to_vec())
        } else {
            None
        };
        let payload = match &iv {
            Some(iv) => {
                let key = encr_target.as_ref().unwrap();
                let key = diffie_hellman(self.as_nonzero_scalar(), key.as_affine());
                let key = key.extract::<sha3::Keccak256>(None);
                let ii: [u8; 0] = [];
                let mut aes_key = [0u8; 16];
                key.expand(&ii, &mut aes_key).expect("SHARED_KEY.expand");
                let cipher = Aes128CbcEnc::new_from_slices(&aes_key, iv.as_slice())?;
                cipher.encrypt_padded_vec_mut::<Pkcs7>(payload.as_slice())
            }
            None => payload,
        };
        let from_address = get_eth_address_bytes(&self.into()).to_vec();
        let to_address = if let Some(pk) = encr_target.as_ref() {
            get_eth_address_bytes(&pk.into()).try_into()?
        } else {
            if let Some(t) = to_address {
                t
            } else {
                [0u8; 20].into()
            }
        };
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let raw_msg = RawMessage {
            channel,
            timestamp,
            from_address: from_address.clone(),
            to_address,
            encrypted: encr_target.is_some(),
            payload,
            enc_iv: iv,
        };
        let raw = to_vec(&raw_msg)?;
        let mut hasher = Keccak256::new();
        hasher.update(&raw);
        hasher.update(timestamp.to_string().as_bytes());
        let raw_hash = hasher.finalize_reset();
        hasher.update(&raw_hash);
        let (signature, recid) = self.sign_digest_recoverable(hasher)?;
        let mut sign_bytes = signature.to_vec();
        sign_bytes.append(&mut vec![recid.to_byte()]);

        Ok((
            SignedMessage {
                raw,
                hash: raw_hash.to_vec(),
                nonce: nonce.unwrap_or(timestamp),
                signature: sign_bytes,
                last_edge_addr: Some(from_address),
                session_id,
            },
            raw_msg,
        ))
    }

    async fn create_nostr_event(
        &self,
        session_id: Vec<u8>,
        nonce: Option<u64>,
        channel: MessageChannel,
        payload: Vec<u8>,
        to_address: Option<Vec<u8>>,
        encr_target: Option<PublicKey>,
        keys: &Keys,
    ) -> Result<Event> {
        let (msg, raw) = self
            .create_message(session_id, nonce, channel, payload, to_address, encr_target)
            .await?;
        let content = bs58::encode(to_vec(&msg)?.as_slice()).into_string();
        let tags = vec![
            Tag::Generic(TagKind::Custom("c".to_string()), vec!["dephy".to_string()]),
            Tag::Generic(
                TagKind::Custom("dephy_to".to_string()),
                vec![format!("did:dephy:0x{}", hex::encode(&raw.to_address))],
            ),
            Tag::Generic(
                TagKind::Custom("dephy_from".to_string()),
                vec![format!("did:dephy:0x{}", hex::encode(&raw.from_address))],
            ),
            Tag::Generic(
                TagKind::Custom("dephy_edge".to_string()),
                vec![format!("did:dephy:0x{}", hex::encode(&raw.from_address))],
            ),
        ];
        let ret = EventBuilder::new(default_kind(), content, tags.as_slice()).to_event(keys)?;
        Ok(ret)
    }

    fn eth_addr(&self) -> Bytes {
        get_eth_address_bytes(&self.into())
    }
    fn eth_addr_string(&self) -> String {
        hex::encode(self.eth_addr())
    }
    fn public_key(&self) -> PublicKey {
        self.verifying_key().into()
    }
}
