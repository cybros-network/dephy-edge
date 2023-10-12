pub use dephy_edge::*;
use preludes::*;

use clap::{Parser, Subcommand};
use dephy_edge::crypto::get_eth_address_bytes;
use k256::ecdsa::{hazmat::SignPrimitive, RecoveryId, Signature, SigningKey};
use rand_core::OsRng;
use sha3::{Digest, Keccak256};

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    GenerateEnv {
        #[arg(short, long, env, default_value = "info")]
        log_level: String,
    },
    FakeMessage {
        #[arg(short, long, env, default_value = "Hello Dephy!")]
        payload: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Options::parse();

    match &opt.command {
        Command::GenerateEnv { log_level } => {
            let priv_key = k256::SecretKey::random(&mut OsRng);
            let priv_key = priv_key.as_scalar_primitive();
            let priv_key = priv_key.to_string().to_lowercase();
            println!("RUST_LOG=dephy_edge={},rumqttd::*=off", log_level);
            println!("DEPHY_PRIV_KEY={}", priv_key);
        }
        Command::FakeMessage { payload } => {
            let priv_key = k256::SecretKey::random(&mut OsRng);
            let signing_key: k256::ecdsa::SigningKey = (&priv_key).try_into()?;
            let from_address = get_eth_address_bytes(&priv_key.public_key().into()).to_vec();
            let zero_addr = [0u8; 20].to_vec();
            let timestamp = Timestamp::now();
            let timestamp = timestamp.as_u64();
            let raw = RawMessage {
                timestamp,
                from_address,
                to_address: zero_addr,
                encrypted: false,
                payload: payload.as_bytes().to_vec(),
                iv: None,
                w3b: None,
            };
            let raw = raw.encode_to_vec();
            let mut hasher = Keccak256::new();
            hasher.update(&raw);
            let raw_hash = hasher.finalize();
            let mut hasher = Keccak256::new();
            hasher.update(&raw);
            let (signature, recid) = signing_key.sign_digest_recoverable(hasher)?;
            let mut sign_bytes = signature.to_vec();
            sign_bytes.append(&mut vec![recid.to_byte()]);

            let signed = SignedMessage {
                raw,
                hash: raw_hash.to_vec(),
                nonce: timestamp,
                signature: sign_bytes,
                last_edge_addr: None,
            };
            let signed = signed.encode_to_vec();
            println!("{}", hex::encode(signed));
        }
    }

    Ok(())
}
