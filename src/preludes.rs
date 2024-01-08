pub use anyhow::{anyhow, bail, Error, Result};
pub use bytes::Bytes;
pub use dephy_types::preludes::*;
pub use k256;
pub use k256::ecdsa::{SigningKey, VerifyingKey};
pub use log::{debug, error, info, trace, warn};
pub use nostr_sdk::{
    secp256k1::SecretKey, Alphabet, Client, Event, EventBuilder, Filter, Keys, Kind,
    RelayPoolNotification, Tag, TagKind, Timestamp,
};
pub use primitive_types::{U128, U256};
pub use prost::Message;
pub use rumqttd::local::{LinkRx, LinkTx};
pub use rumqttd::Broker;
use std::net::SocketAddr;
pub use std::str::FromStr;
pub use std::sync::Arc;
pub use tokio::sync::{mpsc, Mutex};

use clap::Parser;

pub static DEPHY_TOPIC: &'static str = "/dephy/signed_message";

#[derive(Debug, Parser, Clone)]
pub struct CliOpt {
    #[clap(long, env, default_value_t = false)]
    pub no_mqtt_server: bool,
    #[clap(long, env, default_value_t = false)]
    pub no_http_server: bool,

    #[clap(short = 'q', long, env, default_value = "./rumqttd.toml")]
    pub mqtt_config_file: String,
    #[clap(short = 'l', long, env, default_values = ["[::]:3883"])]
    pub http_bind_address: Vec<SocketAddr>,

    #[clap(short = 'k', long, env = "DEPHY_PRIV_KEY")]
    pub priv_key: String,
    #[clap(short = 'n', long, env, default_values_t = ["wss://relay.damus.io".to_string()])]
    pub nostr_relay_list: Vec<String>,
}

pub struct AppContext {
    pub opt: CliOpt,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub eth_addr: String,
    pub eth_addr_bytes: Bytes,
    pub mqtt_tx: Arc<Mutex<LinkTx>>,
    pub nostr_client: Arc<Client>,
    pub nostr_tx: mpsc::UnboundedSender<SignedMessage>,
}
