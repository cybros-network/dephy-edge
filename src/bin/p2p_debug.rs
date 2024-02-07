use crate::crypto::*;
use clap::{Parser, Subcommand};
use dephy_edge::rings::AppRingsProvider;
use dephy_edge::{app_main::wait_for_join_set, nostr::default_filter, *};
use dephy_types::borsh::{from_slice, to_vec};
use dotenv::dotenv;
use preludes::*;
use rand::Fill;
use rand_core::OsRng;
use rings_core::message::MessagePayload;
use rings_core::swarm::callback::SwarmCallback;
use rings_core::swarm::callback::SwarmEvent;
use rings_node::backend::types::BackendMessage;
use rings_node::provider::Provider;
use rings_rpc::method::Method;
use rumqttc::{self, AsyncClient, MqttOptions, Publish, QoS};
use rumqttc::{Event, Incoming};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::Barrier;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    SimulateUser {
        #[clap(short = 'k', long, env = "P2P_DEBUG_PRIV_KEY_USER")]
        priv_key: Option<String>,
        #[clap(short = 'N', long, env, default_values_t = ["https://rings-poc.dephy.io".to_string()])]
        p2p_bootstrap_node_list: Vec<String>,
        #[clap(short = 'n', long, env, default_values_t = ["wss://relay-poc.dephy.io".to_string()])]
        nostr_relay_list: Vec<String>,
        #[clap(short = 't', long, env)]
        target_address: String,
    },
    SimulateDevice {
        #[clap(short = 'k', long, env = "P2P_DEBUG_PRIV_KEY_DEVICE")]
        priv_key: Option<String>,
        #[arg(
            short,
            long,
            env,
            default_value = "mqtt://127.0.0.1:1883?client_id={client_id}"
        )]
        mqtt_address: String,
    },
}

fn get_signer(priv_key: Option<String>) -> SigningKey {
    let ret = match priv_key {
        Some(k) => parse_signing_key(k.replace("0x", "").as_str()).unwrap(),
        None => {
            let priv_key = k256::SecretKey::random(&mut OsRng);
            priv_key.into()
        }
    };
    let eth_addr = format!("0x{}", ret.eth_addr_string());
    info!("My address: {}", &eth_addr);
    ret
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opt = Options::parse();

    match &opt.command {
        Command::SimulateUser {
            p2p_bootstrap_node_list,
            nostr_relay_list,
            target_address,
            priv_key,
        } => {
            info!("Simulating user...");
            let signer = get_signer(priv_key.clone());
            simulate_user_main(
                signer,
                p2p_bootstrap_node_list,
                nostr_relay_list,
                target_address.as_str(),
            )
            .await
        }
        Command::SimulateDevice {
            mqtt_address,
            priv_key,
        } => {
            info!("Simulating device...");
            let signer = get_signer(priv_key.clone());
            simulate_device_main(signer, mqtt_address.as_str()).await
        }
    }
}

struct SimulateUserContext {
    pub cancel_token: CancellationToken,
    pub signing_key: SigningKey,
    pub nostr_client: Arc<Client>,
    pub nostr_keys: Keys,
    pub rings_provider: Arc<Provider>,
    pub target_address: Vec<u8>,
    pub state: Arc<Mutex<SimulateUserState>>,
    pub tx: UserChannelTx,
}

enum UserChannelPayload {
    Retain,
    StateChanged(SimulateUserState),
}

type UserChannelTx = mpsc::Sender<UserChannelPayload>;
type UserChannelRx = mpsc::Receiver<UserChannelPayload>;

async fn simulate_user_main(
    signer: SigningKey,
    p2p_bootstrap_node_list: &Vec<String>,
    nostr_relay_list: &Vec<String>,
    target_address: &str,
) -> Result<()> {
    let cancel_token = CancellationToken::new();

    let target_address = target_address.replace("0x", "");
    let target_address = hex::decode(target_address)?;

    if target_address.len() != 20 {
        bail!("Bad target address!")
    }

    let signer_key = SecretKey::from_slice(signer.to_bytes().as_slice())?;
    let keys = Keys::new(signer_key);
    let nostr_client = Client::new(&keys);
    for r in nostr_relay_list.iter() {
        nostr_client.add_relay(r.as_str(), None).await?;
    }
    let nostr_client = Arc::new(nostr_client);
    let rings_provider = Provider::create(&signer).await?;

    let state = Arc::new(Mutex::new(SimulateUserState::Init));

    let (tx, rx) = mpsc::channel::<UserChannelPayload>(4096);

    let ctx = Arc::new(SimulateUserContext {
        cancel_token: cancel_token.clone(),
        signing_key: signer.clone(),
        nostr_client,
        nostr_keys: keys,
        rings_provider: rings_provider.clone(),
        target_address,
        state,
        tx: tx.clone(),
    });

    let rings_handler = UserBackendBehaviour {
        ctx: ctx.clone(),
        provider: rings_provider.clone(),
    };
    rings_provider.init(p2p_bootstrap_node_list, Arc::new(rings_handler))?;

    let mut js = JoinSet::new();
    js.spawn(user_nostr(ctx.clone()));
    js.spawn(user_loop(ctx.clone(), rx));

    tokio::spawn(async move {
        sleep(Duration::from_secs(3)).await;
        let _ = tx
            .send(UserChannelPayload::StateChanged(SimulateUserState::Init))
            .await;
    });

    tokio::select! {
        _ = cancel_token.cancelled() => {
            info!("Exiting...")
        }
        ret = wait_for_join_set(js, cancel_token.clone()) => {
            if let Err(e) = ret {
                error!("wait_for_join_set: {:?}", e)
            }
        }
        ret = tokio::signal::ctrl_c() => {
            cancel_token.clone().cancel();
            if let Err(e) = ret {
                error!("ctrl_c: {:?}", e)
            }
        }
    }

    Ok(())
}

struct UserBackendBehaviour {
    ctx: Arc<SimulateUserContext>,
    provider: Arc<Provider>,
}

#[async_trait::async_trait]
impl SwarmCallback for UserBackendBehaviour {
    async fn on_inbound(&self, payload: &MessagePayload) -> Result<(), Box<dyn std::error::Error>> {
        let msg: rings_core::message::Message = payload.transaction.data()?;
        if let rings_core::message::Message::CustomMessage(msg) = msg {
            let msg: BackendMessage = bincode::deserialize(msg.0.as_slice())?;
            if let BackendMessage::Extension(msg) = msg {
                let msg = from_slice::<PtpUserMessageFromBroker>(msg.as_ref())?;
                match msg {
                    PtpUserMessageFromBroker::SessionConnected(_) => {
                        self.ctx
                            .clone()
                            .tx
                            .send(UserChannelPayload::StateChanged(
                                SimulateUserState::Connected,
                            ))
                            .await?;
                    }
                    PtpUserMessageFromBroker::SessionConnLost(_) => {
                        // todo
                    }
                    PtpUserMessageFromBroker::Message {
                        session: info,
                        data: payload,
                    } => {
                        // todo: check info
                        let n = from_slice::<u64>(&payload)?;
                        info!(
                            "Message received from 0x{}, payload: 0x{}(parsed u64: {})",
                            hex::encode(&info.device_addr),
                            hex::encode(&payload),
                            n
                        );
                    }
                }
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

async fn user_nostr(ctx: Arc<SimulateUserContext>) -> Result<()> {
    let client = ctx.nostr_client.clone();
    client.connect().await;

    let subscription_filter = default_filter(None).since(Timestamp::now());
    client.subscribe(vec![subscription_filter]).await;
    info!("Subscribing DePHY events from NoStr network...");
    client
        .handle_notifications(move |n| {
            let ctx = ctx.clone();
            let cancel_token = ctx.cancel_token.clone();
            async move {
                if cancel_token.is_cancelled() {
                    return Ok(true);
                }
                tokio::spawn(user_wrap_handle_notification(ctx, n));
                Ok(false)
            }
        })
        .await?;
    Ok(())
}

async fn user_handle_notification(
    ctx: Arc<SimulateUserContext>,
    n: RelayPoolNotification,
) -> Result<()> {
    let curr_addr = ctx.signing_key.eth_addr();

    if let RelayPoolNotification::Event(u, n) = n {
        debug!("receiving dephy event from {:?}: {:?}", u, &n);

        let mut c_dephy = false;
        let mut edge = None;
        let mut from = None;
        let mut to = None;
        for t in n.tags {
            if let Tag::Generic(TagKind::Custom(t), m) = t {
                if m.len() == 1 {
                    match t.as_str() {
                        "c" => c_dephy = m[0].as_str() == "dephy",
                        "dephy_edge" => edge = Some(did_str_to_addr_bytes(&m[0])?),
                        "dephy_from" => from = Some(did_str_to_addr_bytes(&m[0])?),
                        "dephy_to" => to = Some(did_str_to_addr_bytes(&m[0])?),
                        _ => {}
                    }
                }
            }
        }
        if !c_dephy || edge.is_none() || from.is_none() || to.is_none() {
            return Ok(());
        }
        let edge = edge.unwrap();
        let from = from.unwrap();
        let to = to.unwrap();
        if edge.eq(&curr_addr) {
            return Ok(());
        }
        let content = bs58::decode(n.content).into_vec()?;
        let (_, raw) = check_message(content.as_slice())?;
        if from.ne(&raw.from_address) || to.ne(&raw.to_address) {
            return Ok(());
        }
        if raw.channel != MessageChannel::TunnelNegotiate {
            return Ok(());
        }
        let msg: PtpRemoteNegotiateMessageFromDevice = from_slice(raw.payload.as_slice())?;
        match msg {
            PtpRemoteNegotiateMessageFromDevice::Hello(info) => {
                let tx = ctx.tx.clone();
                tx.send(UserChannelPayload::StateChanged(
                    SimulateUserState::GotBroker(info),
                ))
                .await?;
            }
            PtpRemoteNegotiateMessageFromDevice::BrokerNotSupported => {
                error!("The Broker to which the device connected doesn't support P2P connection.")
            }
            PtpRemoteNegotiateMessageFromDevice::DeviceNotSupported => {
                error!("The device doesn't support P2P connection.")
            }
        }
    }
    Ok(())
}

async fn user_wrap_handle_notification(ctx: Arc<SimulateUserContext>, n: RelayPoolNotification) {
    if let Err(e) = user_handle_notification(ctx, n).await {
        debug!("handle_notification: {:?}", e)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SimulateUserState {
    Init,
    GotBroker(PtpRemoteNegotiateInfo),
    Connected,
}

async fn user_loop(ctx: Arc<SimulateUserContext>, mut rx: UserChannelRx) -> Result<()> {
    let cancel_token = ctx.cancel_token.clone();
    let nostr = ctx.nostr_client.clone();
    let signer = ctx.signing_key.clone();
    let to_address = ctx.target_address.clone();
    let keys = ctx.nostr_keys;
    let mut nonce = [0u8; 16];
    nonce.try_fill(&mut OsRng)?;
    let nonce = nonce.to_vec();
    let public_key = signer.verifying_key().to_encoded_point(false);
    let public_key = public_key.as_bytes().to_vec();

    let mut conn_info = None;

    while let Some(msg) = rx.recv().await {
        if cancel_token.clone().is_cancelled() {
            return Ok(());
        }

        match msg {
            UserChannelPayload::Retain => {
                // do nothing
            }
            UserChannelPayload::StateChanged(state) => {
                *ctx.state.clone().lock().await = state.clone();
                let cancel_token = cancel_token.clone();

                match state {
                    SimulateUserState::Init => {
                        let nonce = nonce.clone();
                        let public_key = public_key.clone();
                        let nostr = nostr.clone();
                        let signer = signer.clone();
                        let to_address = to_address.clone();
                        let state = ctx.state.clone();
                        tokio::spawn(async move {
                            let mut tick = 0u16;
                            loop {
                                if cancel_token.is_cancelled() {
                                    break;
                                }
                                let payload = PtpRemoteNegotiateMessageFromUser::Hello {
                                    nonce: nonce.clone(),
                                    public_key: public_key.clone(),
                                };
                                let event = signer
                                    .create_nostr_event(
                                        MessageChannel::TunnelNegotiate,
                                        to_vec(&payload)?,
                                        Some(to_address.clone()),
                                        None,
                                        &keys,
                                    )
                                    .await?;
                                nostr.send_event(event).await?;
                                info!("Hello sent, waiting for response.");

                                tick += 1;
                                sleep(Duration::from_millis(1500)).await;
                                if let SimulateUserState::Init = *state.lock().await {
                                    if tick > 10 {
                                        error!("No response from device.");
                                        cancel_token.cancel();
                                    }
                                } else {
                                    break;
                                }
                            }
                            Ok::<(), anyhow::Error>(())
                        });
                    }
                    SimulateUserState::GotBroker(info) => {
                        let state = ctx.state.clone();
                        let rings_provider = ctx.rings_provider.clone();
                        let signer = ctx.signing_key.clone();
                        let to_address = ctx.target_address.clone();

                        conn_info = Some(info.clone());

                        info!("GotBroker: {:?}", &info);
                        tokio::spawn(async move {
                            let mut tick = 0u16;
                            loop {
                                if cancel_token.is_cancelled() {
                                    break;
                                }
                                let payload = PtpUserMessageFromUser::TrySession(TrySessionInfo {
                                    user_addr: signer.eth_addr().to_vec(),
                                    device_addr: to_address.clone(),
                                    session_id: info.session_id.clone(),
                                });
                                let to = format!("0x{}", hex::encode(info.broker_address.clone()));
                                info!("Sending TrySession to {}: {:?}", &to, &payload);
                                let msg = BackendMessage::Extension(to_vec(&payload)?.into());
                                let msg = msg.into_send_backend_message_request(to)?;
                                rings_provider
                                    .request(Method::SendBackendMessage, msg)
                                    .await?;
                                info!("TrySession sent, waiting for response.");

                                tick += 1;
                                sleep(Duration::from_millis(1500)).await;
                                if let SimulateUserState::GotBroker(_) = *state.lock().await {
                                    if tick > 10 {
                                        error!("No response from broker.");
                                        cancel_token.cancel();
                                    }
                                } else {
                                    break;
                                }
                            }
                            Ok::<(), anyhow::Error>(())
                        });
                    }
                    SimulateUserState::Connected => {
                        info!("Connected to broker via Rings.");
                        let info = conn_info.clone().unwrap();
                        let rings_provider = ctx.rings_provider.clone();
                        let mut round = 1u64;
                        loop {
                            if cancel_token.is_cancelled() {
                                break;
                            }

                            let payload = PtpUserMessageFromUser::Message {
                                session: TrySessionInfo {
                                    user_addr: signer.eth_addr().to_vec(),
                                    device_addr: to_address.clone(),
                                    session_id: info.session_id.clone(),
                                },
                                data: to_vec(&round)?,
                            };
                            let payload = BackendMessage::Extension(to_vec(&payload)?.into());
                            let payload = payload.into_send_backend_message_request(format!(
                                "0x{}",
                                hex::encode(info.broker_address.clone())
                            ))?;
                            let _ = rings_provider
                                .request(Method::SendBackendMessage, payload)
                                .await;
                            info!("Round {} sent.", round);

                            round += 1;
                            sleep(Duration::from_secs(3)).await;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

struct SimulateDeviceContext {
    pub cancel_token: CancellationToken,
    pub signing_key: SigningKey,
    pub mqtt_client: AsyncClient,
    pub topic_receiver: String,
    pub topic_p2p: String,
    pub nonce_seen_map: Arc<Mutex<HashMap<Vec<u8>, bool>>>,
    pub user_to_nonce_map: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    pub user_authorized_map: Arc<Mutex<HashMap<Vec<u8>, bool>>>,
    pub session_id: Arc<Mutex<Option<Vec<u8>>>>,
    pub broker_addr: Arc<Mutex<Option<Vec<u8>>>>,
}

async fn simulate_device_main(signer: SigningKey, mqtt_address: &str) -> Result<()> {
    let cancel_token = CancellationToken::new();

    let mut mqtt_client =
        MqttOptions::parse_url(mqtt_address.replace("{client_id}", &signer.eth_addr_string()))?;
    mqtt_client.set_keep_alive(Duration::from_secs(5));
    let (mqtt_client, mut mqtt_loop) = AsyncClient::new(mqtt_client.clone(), 16);

    let topic_receiver = format!("/dephy/to/0x{}", signer.eth_addr_string());
    let topic_p2p = format!("{}0x{}", DEPHY_P2P_TOPIC_PREFIX, signer.eth_addr_string());

    let ctx = Arc::new(SimulateDeviceContext {
        cancel_token: cancel_token.clone(),
        signing_key: signer.clone(),
        mqtt_client: mqtt_client.clone(),
        topic_receiver: topic_receiver.clone(),
        topic_p2p: topic_p2p.clone(),
        nonce_seen_map: Arc::new(Mutex::new(HashMap::new())),
        user_to_nonce_map: Arc::new(Mutex::new(HashMap::new())),
        user_authorized_map: Arc::new(Mutex::new(HashMap::new())),
        session_id: Arc::new(Mutex::new(None)),
        broker_addr: Arc::new(Mutex::new(None)),
    });

    mqtt_client
        .subscribe(topic_receiver.as_str(), QoS::AtMostOnce)
        .await?;
    mqtt_client
        .subscribe(topic_p2p.as_str(), QoS::AtMostOnce)
        .await?;

    let mut js = JoinSet::new();

    let init_barrier = Arc::new(Barrier::new(2));

    let ctx_move = ctx.clone();
    let ib_move = init_barrier.clone();
    js.spawn(async move {
        let ctx = ctx_move.clone();

        let cancel_token = ctx.cancel_token.clone();
        let topic_receiver = ctx.topic_receiver.as_str();
        let topic_p2p = ctx.topic_p2p.as_str();
        loop {
            if cancel_token.is_cancelled() {
                break;
            }
            let notification = mqtt_loop.poll().await.unwrap();
            match notification {
                Event::Incoming(notification) => match notification {
                    Incoming::ConnAck(_) => {
                        info!("Connected to MQTT broker.");
                    }
                    Incoming::Publish(p) => {
                        let topic = p.topic.as_str();
                        if topic == topic_receiver {
                            let ib = ib_move.clone();
                            ib.wait().await;
                            let ctx = ctx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = device_topic_receiver_handler(ctx, p).await {
                                    warn!("device_topic_receiver_handler: {:?}", e)
                                }
                            });
                        } else if topic == topic_p2p {
                            let ctx = ctx.clone();
                            let ib_move = ib_move.clone();
                            tokio::spawn(async move {
                                if let Err(e) = device_topic_p2p_handler(ctx, p, ib_move).await {
                                    debug!("device_topic_p2p_handler: {:?}", e)
                                }
                            });
                        }
                    }
                    Incoming::Subscribe(s) => {
                        info!("MQTT subscription: {:?}", s);
                    }
                    _ => {}
                },
                Event::Outgoing(_) => {}
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let ctx_move = ctx.clone();
    tokio::spawn(async move {
        let ctx = ctx_move;
        let signer = ctx.signing_key.clone();
        let mqtt_client = ctx.mqtt_client.clone();
        let topic_p2p = ctx.topic_p2p.as_str();

        let (msg, _) = signer
            .create_message(
                MessageChannel::TunnelNegotiate,
                to_vec(&PtpLocalMessageFromDevice::Hello)?.to_vec(),
                None,
                None,
            )
            .await?;
        mqtt_client
            .publish_bytes(topic_p2p, QoS::AtMostOnce, false, to_vec(&msg)?.into())
            .await?;

        info!("Hello sent to broker.");

        Ok::<(), anyhow::Error>(())
    });

    tokio::select! {
        _ = cancel_token.cancelled() => {
            info!("Exiting...")
        }
        ret = wait_for_join_set(js, cancel_token.clone()) => {
            if let Err(e) = ret {
                error!("wait_for_join_set: {:?}", e)
            }
        }
        ret = tokio::signal::ctrl_c() => {
            cancel_token.clone().cancel();
            if let Err(e) = ret {
                error!("ctrl_c: {:?}", e)
            }
        }
    }

    Ok(())
}

async fn device_topic_p2p_handler(
    ctx: Arc<SimulateDeviceContext>,
    p: Publish,
    barrier: Arc<Barrier>,
) -> Result<()> {
    let mqtt_broker = ctx.mqtt_client.clone();
    let topic = ctx.topic_p2p.as_str();
    let signer = ctx.signing_key.clone();
    let session_id = ctx.session_id.clone();
    let broker_addr = ctx.broker_addr.clone();
    let user_authorized_map = ctx.user_authorized_map.clone();

    let (_, msg) = check_message(p.payload.as_ref())?;
    let payload = from_slice::<PtpLocalMessageFromBroker>(msg.payload.as_slice())?;
    match payload {
        PtpLocalMessageFromBroker::Hello(session_id_new) => {
            info!(
                "Hello received from 0x{}, session_id: 0x{}",
                hex::encode(&msg.from_address),
                hex::encode(&session_id_new)
            );
            *session_id.lock().await = Some(session_id_new);
            *broker_addr.lock().await = Some(msg.from_address.clone());
            barrier.wait().await;
        }
        PtpLocalMessageFromBroker::Keepalive => {
            if session_id.lock().await.is_none() {
                bail!("Keepalive received before Hello.")
            }
            if broker_addr.lock().await.is_none() {
                bail!("Keepalive received before Hello.")
            }
            let (msg, _) = signer
                .create_message(
                    MessageChannel::TunnelNegotiate,
                    to_vec(&PtpLocalMessageFromDevice::Keepalive)?.to_vec(),
                    broker_addr.lock().await.clone(),
                    None,
                )
                .await?;
            mqtt_broker
                .publish_bytes(topic, QoS::AtMostOnce, false, to_vec(&msg)?.into())
                .await?;
        }
        PtpLocalMessageFromBroker::AreYouThere {
            user_addr,
            session_id: session_id_new,
        } => {
            if session_id.lock().await.is_none() {
                bail!("Keepalive received before Hello.")
            }
            if broker_addr.lock().await.is_none() {
                bail!("Keepalive received before Hello.")
            }
            user_authorized_map
                .lock()
                .await
                .insert(user_addr.clone(), true);
            let (msg, _) = signer
                .create_message(
                    MessageChannel::TunnelNegotiate,
                    to_vec(&PtpLocalMessageFromDevice::MeVoila(session_id_new))?.to_vec(),
                    broker_addr.lock().await.clone(),
                    None,
                )
                .await?;
            mqtt_broker
                .publish_bytes(topic, QoS::AtMostOnce, false, to_vec(&msg)?.into())
                .await?;
            info!("Broker authorized user: 0x{}", hex::encode(&user_addr));
        }
        PtpLocalMessageFromBroker::ShouldReceiveMessage {
            user_addr,
            data: payload,
        } => {
            let n = from_slice::<u64>(&payload)?;
            info!(
                "ShouldReceiveMessage received from 0x{}, payload: 0x{}(parsed u64: {})",
                hex::encode(&user_addr),
                hex::encode(&payload),
                n
            );
            let n = n ^ 0xfefefefefefefefe << 8;
            let (msg, _) = signer
                .create_message(
                    MessageChannel::TunnelNegotiate,
                    to_vec(&PtpLocalMessageFromDevice::ShouldSendMessage {
                        user_addr: user_addr.clone(),
                        data: to_vec(&n)?,
                    })?
                    .to_vec(),
                    broker_addr.lock().await.clone(),
                    None,
                )
                .await?;
            mqtt_broker
                .publish_bytes(topic, QoS::AtMostOnce, false, to_vec(&msg)?.into())
                .await?;
            info!("Response {} sent to 0x{}", n, hex::encode(&user_addr));
        }
    }
    Ok(())
}

async fn device_topic_receiver_handler(ctx: Arc<SimulateDeviceContext>, p: Publish) -> Result<()> {
    // let mqtt_broker = ctx.mqtt_client.clone();

    let (_, msg) = check_message(p.payload.as_ref())?;
    let payload = from_slice::<PtpRemoteNegotiateMessageFromUser>(msg.payload.as_slice())?;
    match payload {
        PtpRemoteNegotiateMessageFromUser::Hello {
            ref nonce,
            ref public_key,
        } => {
            let nonce_seen_map = ctx.nonce_seen_map.clone();
            if nonce_seen_map.lock().await.get(nonce).is_some() {
                warn!("Nonce seen, ignore.");
                return Ok(());
            }
            nonce_seen_map.lock().await.insert(nonce.clone(), true);

            let verifier = VerifyingKey::from_encoded_point(&k256::EncodedPoint::from_bytes(
                public_key.as_slice(),
            )?)?;
            let user_addr = get_eth_address_bytes(&verifier);
            if msg.from_address.ne(&user_addr) {
                bail!("Public key doesn't match with the address.")
            }

            let user_to_nonce_map = ctx.user_to_nonce_map.clone();
            let user_authorized_map = ctx.user_authorized_map.clone();
            let mqtt_client = ctx.mqtt_client.clone();
            let signer = ctx.signing_key.clone();
            let user_addr = user_addr.to_vec();

            let barrier = Arc::new(Barrier::new(2));

            let barrier_move = barrier.clone();
            let mqtt_client_move = mqtt_client.clone();
            let signer_move = signer.clone();
            let user_addr_move = user_addr.clone();
            let user_authorized_map_move = user_authorized_map.clone();
            let topic_p2p_move = ctx.topic_p2p.clone();
            tokio::spawn(async move {
                let barrier = barrier_move.clone();
                let mqtt_client = mqtt_client_move;

                if let Err(e) = async move {
                    // todo: need to drop if timed out
                    info!("trying to acquire session from broker...");
                    let (msg, _) = signer_move
                        .create_message(
                            MessageChannel::TunnelNegotiate,
                            to_vec(&PtpLocalMessageFromDevice::ShouldAuthorizeUser(
                                user_addr_move.clone(),
                            ))?,
                            None,
                            None,
                        )
                        .await?;

                    mqtt_client
                        .publish_bytes(topic_p2p_move, QoS::AtMostOnce, false, to_vec(&msg)?.into())
                        .await?;
                    loop {
                        sleep(Duration::from_millis(500)).await;
                        if let Some(a) = user_authorized_map_move.lock().await.get(&user_addr_move)
                        {
                            if *a {
                                break;
                            }
                        }
                    }
                    barrier_move.wait().await;
                    Ok::<(), anyhow::Error>(())
                }
                .await
                {
                    barrier.wait().await;
                    warn!("acquire_session: {:?}", e);
                }
            });
            barrier.wait().await;

            let session_id = ctx.session_id.clone();
            let session_id = session_id
                .lock()
                .await
                .clone()
                .ok_or(anyhow!("No session_id."))?;
            let broker_addr = ctx.broker_addr.clone();
            let broker_addr = broker_addr
                .lock()
                .await
                .clone()
                .ok_or(anyhow!("No broker_addr."))?;

            let payload = to_vec(&PtpRemoteNegotiateMessageFromDevice::Hello(
                PtpRemoteNegotiateInfo {
                    nonce: nonce.clone(),
                    public_key: signer.public_key().to_sec1_bytes().to_vec(),
                    session_id: session_id.clone(),
                    broker_address: broker_addr.clone(),
                },
            ))?;
            let (payload, _) = signer
                .create_message(
                    MessageChannel::TunnelNegotiate,
                    payload,
                    Some(broker_addr),
                    None,
                )
                .await?;
            let payload = to_vec(&payload)?;
            mqtt_client
                .publish_bytes(DEPHY_TOPIC, QoS::AtMostOnce, false, payload.into())
                .await?;

            user_to_nonce_map
                .lock()
                .await
                .insert(user_addr.clone(), nonce.clone());
        }
    }

    Ok(())
}
