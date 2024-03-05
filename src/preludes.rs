pub use crate::crypto::DephySigningKey;
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
use rand::RngCore;
use rand_core::OsRng;
use rings_core::session;
pub use rumqttd::local::{LinkRx, LinkTx};
pub use rumqttd::Broker;
use std::collections::HashMap;
pub use std::str::FromStr;
pub use std::sync::Arc;
pub use tokio::sync::{mpsc, Mutex};

use clap::Parser;
use rings_node::provider::Provider;
use std::net::SocketAddr;

pub static DEPHY_TOPIC: &'static str = "/dephy/signed_message";
pub static DEPHY_P2P_TOPIC: &'static str = "/dephy/p2p/#";
pub static DEPHY_P2P_TOPIC_PREFIX: &'static str = "/dephy/p2p/";

pub static ETH_ADDRESS_PREFIX: &'static str = "0x";

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
    #[clap(short = 'n', long, env, default_values_t = ["wss://poc-relay.dephy.cloud/".to_string()])]
    pub nostr_relay_list: Vec<String>,
    #[clap(short = 'N', long, env, default_values_t = ["https://poc-rings.dephy.cloud/".to_string()])]
    pub p2p_bootstrap_node_list: Vec<String>,
}

pub struct DephySessionStoreInner {
    pub session_id: Vec<u8>,
    pub next_nonce: u64,
}

#[derive(Clone)]
pub struct DephySessionStore {
    pub inner: Arc<Mutex<DephySessionStoreInner>>,
}

impl DephySessionStore {
    pub fn new() -> Self {
        let mut session_id = vec![0u8; 8];
        OsRng.fill_bytes(session_id.as_mut_slice());
        let inner = DephySessionStoreInner {
            session_id,
            next_nonce: 0,
        };
        let inner = Arc::new(Mutex::new(inner));
        DephySessionStore { inner }
    }
    pub async fn fetch(&self) -> (Vec<u8>, u64) {
        let store = self.inner.clone();
        let mut store = store.lock().await;
        let ret = (store.session_id.clone(), store.next_nonce);
        store.next_nonce += 1;
        ret
    }
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
    pub rings_provider: Arc<Provider>,
    pub device_addr_to_session_id_map: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    pub session_id_to_device_map: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    pub user_addr_and_session_id_authorized_map: Arc<Mutex<HashMap<(Vec<u8>, Vec<u8>), bool>>>,
    pub messaging_session: DephySessionStore,
}
