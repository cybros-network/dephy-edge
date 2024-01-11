use crate::crypto::*;
use clap::{Parser, Subcommand, ValueEnum};
use dephy_edge::*;
use dephy_types::borsh::{from_slice, to_vec};
use dotenv::dotenv;
use preludes::*;
use rand_core::OsRng;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
    #[clap(short = 'k', long, env = "P2P_DEBUG_PRIV_KEY")]
    pub priv_key: Option<String>,
    #[clap(short = 'n', long, env, default_values_t = ["wss://relay-poc.dephy.io".to_string()])]
    pub nostr_relay_list: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
    SimulateUser {
        #[clap(short = 'N', long, env, default_values_t = ["https://rings-poc.dephy.io".to_string()])]
        p2p_bootstrap_node_list: Vec<String>,
        #[clap(short = 't', long, env)]
        target_address: String,
    },
    SimulateDevice {
        #[arg(short, long, env, default_value = "mqtt://127.0.0.1:1883")]
        mqtt_address: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opt = Options::parse();

    let signing_key = match &opt.priv_key {
        Some(k) => parse_signing_key(k.replace("0x", "").as_str())?,
        None => {
            let priv_key = k256::SecretKey::random(&mut OsRng);
            priv_key.into()
        }
    };
    let verifying_key = signing_key.verifying_key().clone();
    let eth_addr_bytes = get_eth_address_bytes(&verifying_key);
    let eth_addr = format!("0x{}", hex::encode(&eth_addr_bytes));
    info!("My address: {}", &eth_addr);

    match &opt.command {
        Command::SimulateUser {
            p2p_bootstrap_node_list,
            target_address,
        } => {
            simulate_user_main(
                signing_key,
                verifying_key,
                eth_addr_bytes,
                p2p_bootstrap_node_list
                    .iter()
                    .map(|i| i.as_str())
                    .collect::<Vec<_>>(),
                target_address.as_str(),
            )
            .await
        }
        Command::SimulateDevice { mqtt_address } => {
            simulate_user_device(
                signing_key,
                verifying_key,
                eth_addr_bytes,
                mqtt_address.as_str(),
            )
            .await
        }
    }
}

async fn simulate_user_main(
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    eth_addr_bytes: Bytes,
    p2p_bootstrap_node_list: Vec<&str>,
    target_address: &str,
) -> Result<()> {
    Ok(())
}
async fn simulate_user_device(
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    eth_addr_bytes: Bytes,
    mqtt_address: &str,
) -> Result<()> {
    Ok(())
}
