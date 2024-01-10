use crate::crypto::get_eth_address_bytes;
use crate::crypto::parse_signing_key;
use crate::http::start_http_server;
use crate::mqtt_broker::mqtt_broker;
use crate::nostr::{send_signed_message_to_network, start_nostr_context};
use crate::preludes::*;

use clap::Parser;
use dotenv::dotenv;
use std::thread;
use tokio::runtime::Runtime;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub fn app_main() -> Result<()> {
    dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opt = CliOpt::parse();

    let signing_key = parse_signing_key(opt.priv_key.as_str())?;
    let verifying_key = signing_key.verifying_key().clone();
    let eth_addr_bytes = get_eth_address_bytes(&verifying_key);
    let eth_addr = format!("0x{}", hex::encode(&eth_addr_bytes));
    info!("My address: {}", &eth_addr);

    let mqtt_config = config::Config::builder()
        .add_source(config::File::new(
            opt.mqtt_config_file.as_str(),
            config::FileFormat::Toml,
        ))
        .build()?;
    let mqtt_config = mqtt_config.try_deserialize()?;
    debug!(
        "Loaded MQTT broker configuration from {}",
        opt.mqtt_config_file.as_str()
    );
    let mut broker = Broker::new(mqtt_config);

    let (mut mqtt_tx, mqtt_rx) = broker.link(format!("edge-{}", &eth_addr).as_str()).unwrap();

    if opt.no_mqtt_server {
        warn!("Not starting MQTT broker due to --no-mqtt-server")
    } else {
        info!("Started MQTT server");
        let _ = thread::spawn(move || {
            if let Err(e) = broker.start() {
                error!("broker::start: {:?}", e)
            }
        });
    }

    mqtt_tx.subscribe(DEPHY_TOPIC)?;
    mqtt_tx.subscribe(DEPHY_P2P_TOPIC)?;

    let opt_move = opt.clone();
    let async_main_handle = thread::spawn(move || {
        wrap_async_main(
            opt_move,
            signing_key,
            verifying_key,
            eth_addr_bytes,
            mqtt_tx,
            mqtt_rx,
        )
    });
    async_main_handle.join().expect("async_main_handle.join");
    Ok(())
}

fn wrap_async_main(
    opt: CliOpt,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    eth_addr_bytes: Bytes,
    mqtt_tx: LinkTx,
    mqtt_rx: LinkRx,
) {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("wrap_async_main: {:?}", e);
            return;
        }
    };
    if let Err(e) = rt.block_on(async_main(
        opt,
        signing_key,
        verifying_key,
        eth_addr_bytes,
        mqtt_tx,
        mqtt_rx,
    )) {
        error!("wrap_async_main.block_on: {:?}", e);
    }
}

async fn async_main(
    opt: CliOpt,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    eth_addr_bytes: Bytes,
    mqtt_tx: LinkTx,
    mqtt_rx: LinkRx,
) -> Result<()> {
    let cancel_token = CancellationToken::new();

    let mqtt_tx = Arc::new(Mutex::new(mqtt_tx));
    let (nostr_tx, nostr_sender_rx) = mpsc::unbounded_channel::<SignedMessage>();

    let keys = SecretKey::from_str(opt.priv_key.as_str())?;
    let keys = Keys::new(keys);
    let nostr_client = Client::new(&keys);
    for r in opt.nostr_relay_list.iter() {
        nostr_client.add_relay(r.as_str(), None).await?;
    }

    let rings_provider = crate::rings::init_node(&signing_key).await?;

    let nostr_client = Arc::new(nostr_client);
    let ctx = Arc::new(AppContext {
        opt,
        signing_key,
        verifying_key,
        eth_addr: format!("0x{}", hex::encode(&eth_addr_bytes)),
        eth_addr_bytes,
        mqtt_tx: mqtt_tx.clone(),
        nostr_client: nostr_client.clone(),
        nostr_tx,
        rings_provider,
    });

    let mut js = JoinSet::new();

    js.spawn(mqtt_broker(ctx.clone(), mqtt_rx, cancel_token.clone()));
    if *&ctx.opt.no_mqtt_server {
        info!("Not starting HTTP server due to --no-http-server")
    } else {
        js.spawn(start_http_server(ctx.clone()));
    }
    js.spawn(start_nostr_context(ctx.clone(), cancel_token.clone()));
    js.spawn(nostr_sender_loop(
        ctx.clone(),
        cancel_token.clone(),
        nostr_sender_rx,
        keys.clone(),
    ));

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

async fn wait_for_join_set(
    mut js: JoinSet<Result<()>>,
    cancel_token: CancellationToken,
) -> Result<()> {
    while let Some(res) = js.join_next().await {
        cancel_token.clone().cancel();
        let e: Option<Error> = match res {
            Ok(e) => {
                if let Err(e) = e {
                    Some(e.into())
                } else {
                    None
                }
            }
            Err(e) => Some(e.into()),
        };
        if let Some(e) = e {
            error!("async_main: {:?}", &e);
            return Err(e.into());
        }
    }
    Ok(())
}

async fn nostr_sender_loop(
    ctx: Arc<AppContext>,
    cancel_token: CancellationToken,
    mut nostr_sender_rx: mpsc::UnboundedReceiver<SignedMessage>,
    keys: Keys,
) -> Result<()> {
    while let Some(m) = nostr_sender_rx.recv().await {
        if cancel_token.is_cancelled() {
            return Ok(());
        }
        let nostr_client = ctx.nostr_client.clone();

        if let Err(e) = send_signed_message_to_network(ctx.clone(), nostr_client, m, &keys).await {
            debug!("send_signed_message_to_network: {:?}", e)
        }
    }
    Ok(())
}
