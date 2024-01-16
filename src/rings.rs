use crate::preludes::*;
use async_trait::async_trait;
use rings_core::dht::Did;
use rings_core::ecc::SecretKey as RingsSecretKey;
use rings_core::message::Message;
use rings_core::message::MessagePayload;
use rings_core::session::SessionSkBuilder;
use rings_core::storage::PersistenceStorage;
use rings_core::swarm::callback::SwarmCallback;
use rings_core::swarm::callback::SwarmEvent;
use rings_node::processor::ProcessorBuilder;
use rings_node::processor::ProcessorConfig;
use rings_node::provider::Provider;
use rings_rpc::method::Method;
use rings_rpc::protos::rings_node::*;
use std::time::Duration;

pub struct BackendBehaviour {}

#[async_trait]
impl SwarmCallback for BackendBehaviour {
    async fn on_inbound(&self, payload: &MessagePayload) -> Result<(), Box<dyn std::error::Error>> {
        let msg: Message = payload.transaction.data()?;
        match msg {
            Message::CustomMessage(msg) => {
                info!("{:?}", String::from_utf8_lossy(msg.0.as_slice()));
            }
            _ => {}
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
    async fn create<'a>(key: &'a SigningKey) -> Result<Arc<Self>> {
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
        let storage = PersistenceStorage::random_path("./tmp");
        let storage = PersistenceStorage::new_with_path(storage.as_str()).await?;
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
