use crate::crypto::*;
use base58::ToBase58;
use clap::{Parser, Subcommand};
use dephy_edge::rings::AppRingsProvider;
use dephy_edge::{app_main::wait_for_join_set, nostr::default_filter, *};
use dephy_types::borsh::{from_slice, to_vec};
use dotenv::dotenv;
use preludes::*;
use rand::Fill;
use rand_core::OsRng;
use rings_core::message::Message as RingsMessage;
use rings_core::message::MessagePayload;
use rings_core::swarm::callback::SwarmCallback;
use rings_core::swarm::callback::SwarmEvent;
use rings_node::provider::Provider;
use rings_rpc::method::Method;
use rings_rpc::protos::rings_node::SendCustomMessageRequest;
use rumqttc::{self, AsyncClient, MqttOptions, QoS};
use std::time::Duration;
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
        #[arg(short, long, env, default_value = "mqtt://127.0.0.1:1883")]
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
        match msg {
            rings_core::message::Message::CustomMessage(msg) => {
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
                let _ = tokio::spawn(user_wrap_handle_notification(ctx, n));
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
                bail!("The Broker to which the device connected doesn't support P2P connection.")
            }
            PtpRemoteNegotiateMessageFromDevice::DeviceNotSupported => {
                bail!("The device doesn't support P2P connection.")
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
                                let _ = rings_provider
                                    .request(
                                        Method::SendCustomMessage,
                                        SendCustomMessageRequest {
                                            destination_did: format!(
                                                "0x{}",
                                                hex::encode(info.broker_address.clone())
                                            ),
                                            data: to_vec(&payload)?.to_base58(),
                                        },
                                    )
                                    .await;
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
                        let info = conn_info.clone().unwrap();
                        let rings_provider = ctx.rings_provider.clone();
                        let mut round = 1u64;
                        loop {
                            if cancel_token.is_cancelled() {
                                break;
                            }

                            let payload = PtpUserMessageFromUser::Message(
                                TrySessionInfo {
                                    user_addr: signer.eth_addr().to_vec(),
                                    device_addr: to_address.clone(),
                                    session_id: info.session_id.clone(),
                                },
                                format!("Hello from user, round {}", round)
                                    .as_bytes()
                                    .to_vec(),
                            );
                            let _ = rings_provider
                                .request(
                                    Method::SendCustomMessage,
                                    SendCustomMessageRequest {
                                        destination_did: format!(
                                            "0x{}",
                                            hex::encode(info.broker_address.clone())
                                        ),
                                        data: to_vec(&payload)?.to_base58(),
                                    },
                                )
                                .await;
                            info!("Round {} sent.", round);

                            round += 1;
                            sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn simulate_device_main(signer: SigningKey, mqtt_address: &str) -> Result<()> {
    //    MqttOptions::parse_url(url)
    Ok(())
}
