use crate::crypto::*;
use clap::{Parser, Subcommand};
use dephy_edge::nostr::default_kind;
use dephy_edge::{app_main::wait_for_join_set, nostr::default_filter, *};
use dephy_types::borsh::{from_slice, to_vec};
use dotenv::dotenv;
use preludes::*;
use rand::Fill;
use rand_core::OsRng;
use rings_node::provider::Provider;
use rings_rpc::protos::rings_node::SendBackendMessageRequest;
use rumqttc::{self, AsyncClient, MqttOptions, QoS};
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
    #[clap(short = 'k', long, env = "P2P_DEBUG_PRIV_KEY")]
    pub priv_key: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
    SimulateUser {
        #[clap(short = 'N', long, env, default_values_t = ["https://rings-poc.dephy.io".to_string()])]
        p2p_bootstrap_node_list: Vec<String>,
        #[clap(short = 'n', long, env, default_values_t = ["wss://relay-poc.dephy.io".to_string()])]
        nostr_relay_list: Vec<String>,
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

    let signer = match &opt.priv_key {
        Some(k) => parse_signing_key(k.replace("0x", "").as_str())?,
        None => {
            let priv_key = k256::SecretKey::random(&mut OsRng);
            priv_key.into()
        }
    };
    let eth_addr = format!("0x{}", signer.eth_addr_string());
    info!("My address: {}", &eth_addr);

    match &opt.command {
        Command::SimulateUser {
            p2p_bootstrap_node_list,
            nostr_relay_list,
            target_address,
        } => {
            simulate_user_main(
                signer,
                p2p_bootstrap_node_list,
                nostr_relay_list,
                target_address.as_str(),
            )
            .await
        }
        Command::SimulateDevice { mqtt_address } => {
            simulate_user_device(signer, mqtt_address.as_str()).await
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
}

async fn simulate_user_main(
    signer: SigningKey,
    p2p_bootstrap_node_list: &Vec<String>,
    nostr_relay_list: &Vec<String>,
    target_address: &str,
) -> Result<()> {
    let cancel_token = CancellationToken::new();

    let target_address = target_address.replace("0x", "");
    let target_address = hex::decode(target_address)?;

    //    if target_address.len() != 20 {
    //        bail!("Bad target address!")
    //    }

    let signer_key = SecretKey::from_slice(signer.to_bytes().as_slice())?;
    let keys = Keys::new(signer_key);
    let nostr_client = Client::new(&keys.into());
    for r in nostr_relay_list.iter() {
        nostr_client.add_relay(r.as_str(), None).await?;
    }
    let nostr_client = Arc::new(nostr_client);
    let rings_provider = dephy_edge::rings::init_node(&signer, p2p_bootstrap_node_list).await?;

    let state = Arc::new(Mutex::new(SimulateUserState::Init));

    let ctx = Arc::new(SimulateUserContext {
        cancel_token: cancel_token.clone(),
        signing_key: signer,
        nostr_client,
        nostr_keys: keys,
        rings_provider,
        target_address,
        state,
    });

    let mut js = JoinSet::new();
    js.spawn(user_nostr(ctx.clone()));
    js.spawn(user_loop(ctx.clone()));

    tokio::select! {
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
                let state = ctx.state.clone();
                *state.lock().await = SimulateUserState::GotBroker(info);
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

#[derive(Debug, Clone)]
enum SimulateUserState {
    Init,
    GotBroker(PtpRemoteNegotiateInfo),
    Connected,
}

async fn user_loop(ctx: Arc<SimulateUserContext>) -> Result<()> {
    let cancel_token = ctx.cancel_token.clone();
    let nostr = ctx.nostr_client.clone();
    let signer = ctx.signing_key.clone();
    let to_address = ctx.target_address.clone();
    let keys = ctx.nostr_keys.clone();
    let mut nonce = [0u8; 16];
    nonce.try_fill(&mut OsRng)?;
    let nonce = nonce.to_vec();
    let public_key = signer.verifying_key().to_encoded_point(false);
    let public_key = public_key.as_bytes().to_vec();

    let mut session_info = None as Option<PtpRemoteNegotiateInfo>;
    let mut last_state = SimulateUserState::Init;
    let mut tick = 0u16;
    loop {
        if cancel_token.is_cancelled() {
            return Ok(());
        }
        let curr_state = ctx.state.clone();
        let curr_state = curr_state.lock().await.clone();

        match &curr_state {
            SimulateUserState::Init => {
                if tick % 50 == 0 {
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
                    info!("Hello sent, waiting for response.")
                }
                if tick > 500 {
                    bail!("Hello timed out!");
                }
                sleep(Duration::from_millis(100)).await;
                tick += 1;
            }
            SimulateUserState::GotBroker(info) => {
                match last_state {
                    SimulateUserState::GotBroker(_) => {
                        if tick == 1 || tick % 50 == 0 {
                            // rings hello
                            info!("TrySession sent, waiting for response.")
                        }
                        if tick > 500 {
                            bail!("TrySession timed out!");
                        }
                    }
                    _ => {
                        tick = 0;
                        info!("Got broker: {:?}", &info);
                        session_info = Some(info.clone());
                    }
                }
                sleep(Duration::from_millis(100)).await;
                tick += 1;
            }
            SimulateUserState::Connected => {}
        }
        last_state = curr_state;
    }
}

async fn simulate_user_device(signer: SigningKey, mqtt_address: &str) -> Result<()> {
    //    MqttOptions::parse_url(url)
    Ok(())
}
