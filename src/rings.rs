use crate::preludes::*;
use async_trait::async_trait;
use dephy_types::borsh::{from_slice, to_vec};
use rings_core::dht::Did;
use rings_core::ecc::SecretKey as RingsSecretKey;
use rings_core::message::Message;
use rings_core::message::MessagePayload;
use rings_core::session::SessionSkBuilder;
use rings_core::storage::MemStorage;
use rings_core::swarm::callback::SwarmCallback;
use rings_core::swarm::callback::SwarmEvent;
use rings_node::backend::types::BackendMessage;
use rings_node::processor::ProcessorBuilder;
use rings_node::processor::ProcessorConfig;
use rings_node::provider::Provider;
use rings_rpc::method::Method;
use rings_rpc::method::Method::SendBackendMessage;
use rings_rpc::protos::rings_node::*;
use std::time::Duration;

pub struct BackendBehaviour {
    pub provider: Arc<Provider>,
    pub ctx: Arc<AppContext>,
}

#[async_trait]
impl SwarmCallback for BackendBehaviour {
    async fn on_inbound(&self, payload: &MessagePayload) -> Result<(), Box<dyn std::error::Error>> {
        let msg: Message = payload.transaction.data()?;
        if let Message::CustomMessage(msg) = msg {
            let msg: BackendMessage = bincode::deserialize(msg.0.as_slice())?;
            if let BackendMessage::Extension(msg) = msg {
                let msg = from_slice::<PtpUserMessageFromUser>(msg.as_ref())?;
                self.ctx.clone().handle_message_from_user(msg).await?;
            };
        }
        Ok(())
    }

    async fn on_event(&self, event: &SwarmEvent) -> Result<(), Box<dyn std::error::Error>> {
        #[allow(clippy::single_match)]
        match event {
            SwarmEvent::ConnectionStateChange { peer, state } => {
                info!("ConnectionStateChange: {:?} {:?}", peer, state);
            }
            _ => {}
        }
        Ok(())
    }
}

#[async_trait]
pub trait AppRingsProvider {
    async fn create<'a>(key: &'a SigningKey) -> Result<Arc<Self>>;
    fn init(
        self: Arc<Self>,
        p2p_bootstrap_node_list: &Vec<String>,
        backend: Arc<dyn SwarmCallback + Send + Sync>,
    ) -> Result<()>;
}

#[async_trait]
impl AppRingsProvider for Provider {
    async fn create(key: &SigningKey) -> Result<Arc<Self>> {
        let key = key.to_bytes();
        let key: &[u8; 32] = key.as_slice().try_into()?;
        let key = libsecp256k1::SecretKey::parse(key)?;
        let key: RingsSecretKey = key.into();
        let did = Did::from(key.address());
        debug!("Local p2p node started with DID {}", did.to_string());

        let mut skb = SessionSkBuilder::new(did.to_string(), "secp256k1".to_string());
        let sig = key.sign(&skb.unsigned_proof());
        skb = skb.set_session_sig(sig.to_vec());
        let sk = skb.build()?;

        let config = ProcessorConfig::new("stun://stun.l.google.com:19302".to_string(), sk, 3);
        let storage = Box::new(MemStorage::new());
        let processor = Arc::new(
            ProcessorBuilder::from_config(&config)?
                .storage(storage)
                .build()?,
        );
        Ok(Arc::new(Self::from_processor(processor)))
    }

    fn init(
        self: Arc<Self>,
        p2p_bootstrap_node_list: &Vec<String>,
        backend: Arc<dyn SwarmCallback + Send + Sync>,
    ) -> Result<()> {
        let self_move = self.clone();
        self.set_swarm_callback(backend)?;
        tokio::spawn(async move { self_move.listen().await });

        let self_move = self.clone();
        tokio::spawn(async move {
            loop {
                let resp = self_move
                    .request(Method::NodeInfo, NodeInfoRequest {})
                    .await
                    .unwrap();
                debug!("NodeInfo: {:?}", resp);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });

        for url in p2p_bootstrap_node_list {
            let provider = self.clone();
            let url = url.to_string();
            tokio::spawn(async move {
                // todo: monitor connection to bootstrap nodes
                let resp = provider
                    .request(
                        Method::ConnectPeerViaHttp,
                        ConnectPeerViaHttpRequest {
                            url: url.to_string(),
                        },
                    )
                    .await;
                match resp {
                    Ok(resp) => {
                        info!("Connecting to {}: {}", url, resp);
                    }
                    Err(e) => error!("Connecting to {}: {}", url, e),
                }
            });
        }

        Ok(())
    }
}

#[async_trait]
pub trait ToRingsDIDString {
    fn to_did_string(&self) -> String;
}

#[async_trait]
impl ToRingsDIDString for Vec<u8> {
    fn to_did_string(&self) -> String {
        format!("0x{}", hex::encode(self))
    }
}

#[async_trait]
pub trait AppRingsHandler {
    async fn handle_message_from_user(self: Arc<Self>, msg: PtpUserMessageFromUser) -> Result<()>;
    async fn send_rings_message(
        self: Arc<Self>,
        to: String,
        msg: &PtpUserMessageFromBroker,
    ) -> Result<()>;
    // async fn
}

#[async_trait]
impl AppRingsHandler for AppContext {
    async fn handle_message_from_user(self: Arc<Self>, msg: PtpUserMessageFromUser) -> Result<()> {
        match msg {
            PtpUserMessageFromUser::TrySession(info) => {
                let authorized_map = self.user_addr_and_session_id_authorized_map.clone();
                let session_id_to_device_map = self.session_id_to_device_map.clone();
                let device_addr_to_session_id_map = self.device_addr_to_session_id_map.clone();

                if let Some(result) = authorized_map
                    .lock()
                    .await
                    .get(&(info.user_addr.clone(), info.session_id.clone()))
                {
                    if *result {
                        let payload = PtpUserMessageFromBroker::SessionConnected(info.clone());
                        self.send_rings_message(info.user_addr.to_did_string(), &payload)
                            .await?;
                        return Ok(());
                    }
                    if let Some(val) = session_id_to_device_map.lock().await.get(&info.session_id) {
                        if val.ne(&info.device_addr) {
                            warn!("session_id and device_addr mismatch");
                            return Ok(());
                        }
                        if let Some(val) = device_addr_to_session_id_map
                            .lock()
                            .await
                            .get(&info.device_addr)
                        {
                            if val.ne(&info.session_id) {
                                warn!("device_addr and session_id mismatch");
                                return Ok(());
                            }
                        }
                        self.send_rings_message(
                            info.user_addr.to_did_string(),
                            &PtpUserMessageFromBroker::SessionConnected(info.clone()),
                        )
                        .await?;
                    }
                };
            }
            PtpUserMessageFromUser::Message(info, payload) => {
                let mqtt_tx = self.mqtt_tx.clone();
                let signer = self.signing_key.clone();

                let payload =
                    PtpLocalMessageFromBroker::ShouldReceiveMessage(info.user_addr, payload);
                let (payload, _) = signer
                    .create_message(
                        MessageChannel::TunnelNegotiate,
                        to_vec(&payload)?,
                        Some(info.device_addr.clone()),
                        None,
                    )
                    .await?;
                mqtt_tx.lock().await.publish(
                    format!(
                        "{}0x{}",
                        DEPHY_P2P_TOPIC_PREFIX,
                        hex::encode(&info.device_addr)
                    ),
                    to_vec(&payload)?,
                )?;
            }
        }
        Ok(())
    }
    async fn send_rings_message(
        self: Arc<Self>,
        to: String,
        msg: &PtpUserMessageFromBroker,
    ) -> Result<()> {
        let provider = self.rings_provider.clone();
        let msg = BackendMessage::Extension(to_vec(msg)?.into());
        let msg = msg.into_send_backend_message_request(to)?;
        provider.request(SendBackendMessage, msg).await?;

        Ok(())
    }
}
