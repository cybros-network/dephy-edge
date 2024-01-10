use bytes::Bytes;
use dephy_types::borsh::from_slice;
use rumqttd::local::LinkRx;
use tokio_util::sync::CancellationToken;

use crate::{crypto::check_message, preludes::*};

pub async fn mqtt_broker(
    ctx: Arc<AppContext>,
    mut rx: LinkRx,
    cancel_token: CancellationToken,
) -> Result<()> {
    loop {
        if cancel_token.is_cancelled() {
            return Ok(());
        };
        if let Some(n) = rx.next().await? {
            match n {
                rumqttd::Notification::Forward(n) => {
                    let n = n.publish;
                    let ctx = ctx.clone();
                    let topic = std::str::from_utf8(n.topic.as_ref())?;
                    if topic == DEPHY_TOPIC {
                        let _ = tokio::spawn(async move {
                            if let Err(e) = handle_payload(ctx, n.payload).await {
                                error!("handle_payload: {:?}", e)
                            }
                        });
                    } else {
                        let target = topic
                            .replace(DEPHY_P2P_TOPIC_PREFIX, "")
                            .replace(ETH_ADDRESS_PREFIX, "");
                        let _ = tokio::spawn(async move {
                            if let Err(e) = handle_local_payload(ctx, target, n.payload).await {
                                error!("handle_local_payload: {:?}", e)
                            }
                        });
                    }
                }
                _ => {}
            }
        }
    }
}

// Forward events from MQTT to NoStr
async fn handle_payload(ctx: Arc<AppContext>, payload: Bytes) -> Result<()> {
    let (msg, raw) = check_message(payload.as_ref())?;

    let mqtt_tx = ctx.mqtt_tx.clone();
    let mut mqtt_tx = mqtt_tx.lock().await;
    mqtt_tx.publish(
        format!("/dephy/from/0x{}", hex::encode(raw.from_address.as_slice())),
        payload.clone(),
    )?;
    mqtt_tx.publish(
        format!("/dephy/to/0x{}", hex::encode(raw.to_address.as_slice())),
        payload,
    )?;
    drop(mqtt_tx);

    // Don't redistribute self
    if let Some(last_edge_addr) = &msg.last_edge_addr {
        debug!(
            "{} {}",
            hex::encode(last_edge_addr.as_slice()),
            hex::encode(&ctx.eth_addr_bytes)
        );
        if last_edge_addr.as_slice() == &ctx.eth_addr_bytes {
            return Ok(());
        }
    }

    let nostr_tx = ctx.nostr_tx.clone();
    nostr_tx.send(msg)?;

    Ok(())
}

async fn handle_local_payload(ctx: Arc<AppContext>, target: String, payload: Bytes) -> Result<()> {
    let (_, raw) = check_message(payload.as_ref())?;

    if raw.from_address != hex::decode(&target)? {
        bail!("bad from_address to match {}", &target)
    }

    if MessageChannel::TunnelNegotiate != raw.channel {
        bail!("Message to bad channel from {}", &target)
    }

    let msg = from_slice::<PtpLocalNegotiateMessage>(raw.payload.as_slice())?;

    // todo: handle local message

    Ok(())
}
