pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/dephy.message.rs"));
}

mod crypto;
mod http;
mod mqtt_broker;
mod nostr;
mod preludes;

use crate::crypto::get_eth_address_bytes;
use crate::http::start_http_server;
use crate::{preludes::*, proto::SignedMessage};

use crate::nostr::{send_signed_message_to_network, start_nostr_context};
use clap::Parser;
use crypto::parse_signing_key;
use dotenv::dotenv;
use mqtt_broker::mqtt_broker;
use std::thread;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

fn main() -> Result<()> {
    dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let opt = CliOpt::parse();

    let signing_key = parse_signing_key(opt.priv_key.as_str())?;
    let verifying_key = signing_key.verifying_key().clone();
    let eth_addr_bytes = get_eth_address_bytes(&verifying_key);
    let eth_addr = format!("0x{}", hex::encode(&eth_addr_bytes));

    let mqtt_config = config::Config::builder()
        .add_source(config::File::new(
            opt.mqtt_config_file.as_str(),
            config::FileFormat::Toml,
        ))
        .build()?;
    info!(
        "Loaded MQTT broker configuration from {}",
        opt.mqtt_config_file.as_str()
    );
    let mut broker = Broker::new(mqtt_config.try_deserialize()?);

    let (mut mqtt_tx, mqtt_rx) = broker.link(format!("edge-{}", &eth_addr).as_str()).unwrap();

    if opt.no_mqtt_server {
        info!("Not starting MQTT broker due to --no-mqtt-server")
    } else {
        info!("Started MQTT server");
        let _ = thread::spawn(move || {
            if let Err(e) = broker.start() {
                error!("broker::start: {:?}", e)
            }
        });
    }

    mqtt_tx.subscribe("/dephy/signed_message")?;

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
    let (nostr_tx, mut nostr_sender_rx) = mpsc::unbounded_channel::<SignedMessage>();

    let keys = SecretKey::from_str(opt.priv_key.as_str())?;
    let keys = Keys::new(keys);
    let nostr_client = Client::new(&keys);
    for r in opt.nostr_relay_list.iter() {
        nostr_client.add_relay(r.as_str(), None).await?;
    }

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
    });

    let mqtt_broker_handle = tokio::spawn(mqtt_broker(ctx.clone(), mqtt_rx, cancel_token.clone()));
    let http_handle = tokio::spawn(start_http_server(ctx.clone()));
    let nostr_handle = tokio::spawn(start_nostr_context(ctx.clone(), cancel_token.clone()));

    let cancel_token_move = cancel_token.clone();
    let nostr_client_move = nostr_client.clone();
    let nostr_rx_handle = tokio::spawn(async move {
        while let Some(m) = nostr_sender_rx.recv().await {
            if cancel_token_move.is_cancelled() {
                return;
            }
            if let Err(e) =
                send_signed_message_to_network(ctx.clone(), nostr_client_move.clone(), m, &keys)
                    .await
            {
                debug!("send_signed_message_to_network: {:?}", e)
            }
        }
    });

    tokio::select! {
        ret = nostr_handle => {
            cancel_token.cancel();
            match ret {
                Ok(ret) => {
                    if let Err(e) = ret {
                        error!("nostr_handle: {:?}", e);
                    }
                }
                Err(e) => {
                    error!("spawning nostr_handle: {:?}", e);
                }
            }
        }
        ret = nostr_rx_handle => {
            cancel_token.cancel();
            if let Err(e) = ret {
                error!("spawning nostr_rx_handle: {:?}", e);
            }
        }
        ret = mqtt_broker_handle => {
            cancel_token.cancel();
            match ret {
                Ok(ret) => {
                    if let Err(e) = ret {
                        error!("mqtt_broker_handle: {:?}", e);
                    }
                }
                Err(e) => {
                    error!("spawning mqtt_broker_handle: {:?}", e);
                }
            }
        }
        ret = http_handle => {
            cancel_token.cancel();
            match ret {
                Ok(ret) => {
                    if let Err(e) = ret {
                        error!("http_handle: {:?}", e);
                    }
                }
                Err(e) => {
                    error!("spawning http_handle: {:?}", e);
                }
            }
        }
        ret = tokio::signal::ctrl_c() => {
            cancel_token.cancel();
            if let Err(e) = ret {
                error!("ctrl_c: {:?}", e)
            }
        }
    }

    Ok(())
}
