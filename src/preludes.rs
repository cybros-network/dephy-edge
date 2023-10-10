pub use anyhow::{bail, Error, Result};
pub use k256;
pub use k256::ecdsa::{SigningKey, VerifyingKey};
pub use log::{debug, error, info, trace, warn};
pub use primitive_types::{U128, U256};
pub use rumqttd::local::{LinkRx, LinkTx};
pub use rumqttd::Broker;
pub use std::str::FromStr;
pub use std::sync::Arc;
pub use tokio::sync::{mpsc, Mutex};

use clap::Parser;

#[derive(Debug, Parser, Clone)]
pub struct CliOpt {
    #[clap(short = 'p', long, env, default_value = "./rumqttd.toml")]
    pub mqtt_config_file: String,
    #[clap(short = 'k', long, env = "DEPHY_PRIV_KEY")]
    pub priv_key: String,
}

pub struct AppContext {
    pub opt: CliOpt,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub eth_addr: String,
    pub mqtt_tx: Arc<Mutex<LinkTx>>,
}
