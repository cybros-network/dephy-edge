use dephy_edge::*;
use dephy_types::borsh::{from_slice, to_vec};
use preludes::*;

use clap::{Parser, Subcommand, ValueEnum};
use dephy_edge::crypto::get_eth_address_bytes;
use k256::ecdsa::{RecoveryId, Signature};
use rand_core::OsRng;
use sha3::{Digest, Keccak256};

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, ValueEnum)]
enum PayloadType {
    Hex,
    Utf8String,
}

#[derive(Debug, Subcommand)]
enum Command {
    GenerateEnv {
        #[arg(short, long, env, default_value = "info")]
        log_level: String,
    },
    FakeMessage {
        #[arg(
            short,
            long,
            env,
            default_value = "f09f8c9df09f8c9a4465504859f09f8c9df09f8c9a"
        )]
        payload: String,
        #[arg(short = 't', long, env, value_enum, default_value_t = PayloadType::Hex)]
        payload_type: PayloadType,
    },
    CheckMessage {
        #[arg(short, long, env)]
        message_hex: String,
        #[arg(short = 'u', long, env, default_value_t = false)]
        print_payload_in_utf8: bool,
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
        Command::FakeMessage {
            payload,
            payload_type,
        } => {
            let priv_key = k256::SecretKey::random(&mut OsRng);
            let signing_key: k256::ecdsa::SigningKey = (&priv_key).try_into()?;
            let from_address = get_eth_address_bytes(&priv_key.public_key().into()).to_vec();
            let zero_addr = [0u8; 20].to_vec();
            let timestamp = Timestamp::now();
            let timestamp = timestamp.as_u64();
            let payload = match payload_type {
                PayloadType::Hex => hex::decode(payload)?,
                PayloadType::Utf8String => payload.as_bytes().to_vec(),
            };
            let raw = RawMessage {
                timestamp,
                from_address,
                to_address: zero_addr,
                encrypted: false,
                payload,
                channel: MessageChannel::Normal(0),
                enc_iv: None,
            };
            let raw = to_vec(&raw)?;
            let mut hasher = Keccak256::new();
            hasher.update(&raw);
            hasher.update(timestamp.to_string().as_bytes());
            let raw_hash = hasher.finalize_reset();
            hasher.update(&raw_hash);
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
            let signed = to_vec(&signed)?;
            println!("{}", hex::encode(signed));
        }
        Command::CheckMessage {
            message_hex,
            print_payload_in_utf8,
        } => {
            assert!(message_hex.len() > 0, "Message should not be empty!");
            let mut hasher = Keccak256::new();

            let message_hex = hex::decode(message_hex)?;
            let msg = from_slice(message_hex.as_slice())?;

            let SignedMessage {
                raw,
                hash,
                nonce,
                signature,
                last_edge_addr,
            } = msg;
            let raw = raw.as_slice();
            let raw_hex = hex::encode(raw);
            let hash = hash.as_slice();
            let hash_hex = hex::encode(hash);

            hasher.update(raw);
            hasher.update(nonce.to_string().as_bytes());
            let curr_hash = hasher.finalize_reset();

            println!("==========");
            println!("Raw message: 0x{}", raw_hex);
            assert_eq!(
                hash,
                curr_hash.as_slice(),
                "Hash verification failed: expected=0x{} current=0x{}",
                hash_hex,
                hex::encode(curr_hash)
            );
            println!("Raw message hash: 0x{}", hash_hex);
            let raw_msg = from_slice(raw)?;
            let RawMessage {
                timestamp,
                from_address,
                to_address,
                payload,
                ..
            } = raw_msg;
            assert_eq!(
                nonce, timestamp,
                "Message timestamp check failed: outer={} inner={}",
                nonce, timestamp
            );
            let t = chrono::DateTime::from_timestamp(nonce as i64, 0).expect("Invalid timestamp!");
            println!("Created at: {} ({})", t.to_rfc3339(), nonce);
            if let Some(last_edge_addr) = last_edge_addr {
                println!(
                    "Last touched edge broker: 0x{}",
                    hex::encode(last_edge_addr)
                );
            } else {
                println!("Last touched edge broker: none");
            }

            let from_address = from_address.as_slice();
            let from_address_hex = hex::encode(from_address);
            let signature = signature.as_slice();
            assert_eq!(signature.len(), 65, "Bad signature length!");
            let r = &signature[0..32];
            let s = &signature[32..64];
            let v = &signature[64..];
            println!("----------");
            println!(
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
            assert_eq!(
                from_address,
                r_key_addr.as_ref(),
                "Signature check failed! expected_signer=0x{} actual_signer=0x{}",
                from_address_hex,
                hex::encode(r_key_addr)
            );
            println!(
                "Signer public key: 0x{}",
                hex::encode(r_key.to_sec1_bytes())
            );
            println!("----------");
            println!(
                "Recipient address: 0x{}",
                hex::encode(to_address.as_slice())
            );
            if *print_payload_in_utf8 {
                let payload = String::from_utf8_lossy(payload.as_slice());
                println!("Payload: <<EOF\n{}\nEOF", payload);
            } else {
                println!("Payload: 0x{}", hex::encode(payload.as_slice()));
            }
            println!("====OK====");
        }
    }
    Ok(())
}
