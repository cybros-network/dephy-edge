use crate::preludes::*;
use async_trait::async_trait;
use rings_core::dht::Did;
use rings_core::ecc::SecretKey as RingsSecretKey;
use rings_core::message::MessagePayload;
use rings_core::session::SessionSkBuilder;
use rings_core::storage::PersistenceStorage;
use rings_node::backend::types::BackendMessage;
use rings_node::backend::types::MessageHandler;
use rings_node::backend::Backend;
use rings_node::processor::ProcessorBuilder;
use rings_node::processor::ProcessorConfig;
use rings_node::provider::Provider;
use rings_rpc::method::Method;
use rings_rpc::protos::rings_node::*;

struct BackendBehaviour;

#[async_trait]
impl MessageHandler<BackendMessage> for BackendBehaviour {
    async fn handle_message(
        &self,
        _provider: Arc<Provider>,
        _ctx: &MessagePayload,
        msg: &BackendMessage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Received message: {:?}", msg);
        Ok(())
    }
}

pub async fn init_node(key: &SigningKey) -> Result<Arc<Provider>> {
    let key = key.to_bytes();
    let key: &[u8; 32] = key.as_slice().try_into()?;
    let key = libsecp256k1::SecretKey::parse(key)?;
    let key: RingsSecretKey = key.into();
    let did = Did::from(key.address());
    debug!("Local p2p node started with DID {}", did.to_string());

    let mut skb = SessionSkBuilder::new(did.to_string(), "secp256k1".to_string());
    let sig = key.sign(&skb.unsigned_proof());
    skb = skb.set_session_sig(sig.to_vec());
    let sk = skb.build().unwrap();

    let config = ProcessorConfig::new("stun://stun.l.google.com:19302".to_string(), sk, 3);
    let storage_path = PersistenceStorage::random_path("./tmp");
    let storage = PersistenceStorage::new_with_path(storage_path.as_str())
        .await
        .unwrap();
    let processor = Arc::new(
        ProcessorBuilder::from_config(&config)
            .unwrap()
            .storage(storage)
            .build()
            .unwrap(),
    );

    let provider = Arc::new(Provider::from_processor(processor));
    let backend = Arc::new(Backend::new(provider.clone(), Box::new(BackendBehaviour)));
    provider.set_swarm_callback(backend).unwrap();
    let listening_provider = provider.clone();
    tokio::spawn(async move { listening_provider.listen().await });

    let resp = provider
        .request(Method::NodeInfo, NodeInfoRequest {})
        .await?;
    debug!("NodeInfo: {:?}", resp);

    Ok(provider)
}
