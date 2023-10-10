mod crypto;
mod mqtt_broker;
mod preludes;

use crate::preludes::*;

use clap::Parser;
use crypto::{get_eth_address, parse_signing_key};
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
    let eth_addr = get_eth_address(&verifying_key);

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

    let _mqtt_server_handle = thread::spawn(move || {
        if let Err(e) = broker.start() {
            error!("broker::start: {:?}", e)
        }
    });
    mqtt_tx.subscribe("/dephy/signed_message")?;

    let opt_move = opt.clone();
    let async_main_handle = thread::spawn(move || {
        wrap_async_main(
            opt_move,
            signing_key,
            verifying_key,
            eth_addr,
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
    eth_addr: String,
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
        eth_addr,
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
    eth_addr: String,
    mqtt_tx: LinkTx,
    mqtt_rx: LinkRx,
) -> Result<()> {
    let cancel_token = CancellationToken::new();

    let mqtt_tx = Arc::new(Mutex::new(mqtt_tx));
    let ctx = Arc::new(AppContext {
        opt,
        signing_key,
        verifying_key,
        eth_addr,
        mqtt_tx: mqtt_tx.clone(),
    });

    let mqtt_broker_handle = tokio::spawn(mqtt_broker(ctx.clone(), mqtt_rx, cancel_token.clone()));

    tokio::select! {
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
        ret = tokio::signal::ctrl_c() => {
            cancel_token.cancel();
            if let Err(e) = ret {
                error!("ctrl_c: {:?}", e)
            }
        }
    }

    Ok(())
}
