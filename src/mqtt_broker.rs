use bytes::Bytes;
use dephy_types::borsh::{from_slice, to_vec};
use rand::Fill;
use rand_core::OsRng;
use rumqttd::local::LinkRx;
use tokio_util::sync::CancellationToken;

use crate::rings::{AppRingsHandler, ToRingsDIDString};
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
        if let Some(rumqttd::Notification::Forward(n)) = rx.next().await? {
            let n = n.publish;
            let ctx = ctx.clone();
            let topic = std::str::from_utf8(n.topic.as_ref())?;
            if topic == DEPHY_TOPIC {
                tokio::spawn(async move {
                    if let Err(e) = handle_payload(ctx, n.payload).await {
                        warn!("handle_payload: {:?}", e)
                    }
                });
            } else {
                let target = topic
                    .replace(DEPHY_P2P_TOPIC_PREFIX, "")
                    .replace(ETH_ADDRESS_PREFIX, "");
                tokio::spawn(async move {
                    if let Err(e) = handle_local_payload(ctx, target, n.payload).await {
                        warn!("handle_local_payload: {:?}", e)
                    }
                });
            }
        }
    }
}

// Forward events from MQTT to NoStr
async fn handle_payload(ctx: Arc<AppContext>, payload: Bytes) -> Result<()> {
    debug!("handle_payload");
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
        if last_edge_addr.as_slice() == ctx.eth_addr_bytes {
            return Ok(());
        }
    }

    let nostr_tx = ctx.nostr_tx.clone();
    nostr_tx.send(msg)?;

    Ok(())
}

async fn handle_local_payload(ctx: Arc<AppContext>, target: String, payload: Bytes) -> Result<()> {
    let mqtt_tx = ctx.mqtt_tx.clone();
    let (_, raw) = check_message(payload.as_ref())?;
    let p2p_topic = format!("{}0x{}", DEPHY_P2P_TOPIC_PREFIX, target);
    let device_addr = hex::decode(&target)?;
    let signer = ctx.signing_key.clone();
    let device_addr_to_session_id_map = ctx.device_addr_to_session_id_map.clone();
    let session_id_to_device_map = ctx.session_id_to_device_map.clone();
    let user_addr_and_session_id_authorized_map =
        ctx.user_addr_and_session_id_authorized_map.clone();

    if raw.from_address != device_addr {
        bail!(
            "bad from_address to match {} ({})",
            &target,
            hex::encode(&raw.from_address)
        )
    }

    if MessageChannel::TunnelNegotiate != raw.channel {
        bail!("Message to bad channel from {}", &target)
    }

    let msg = from_slice::<PtpLocalMessageFromDevice>(raw.payload.as_slice())?;

    match msg {
        PtpLocalMessageFromDevice::Hello => {
            let mut session_id = [0u8; 16];
            session_id.try_fill(&mut OsRng)?;
            let session_id = session_id.to_vec();
            let (msg, _) = signer
                .create_message(
                    MessageChannel::TunnelNegotiate,
                    to_vec(&PtpLocalMessageFromBroker::Hello(session_id.clone()))?,
                    Some(device_addr.clone()),
                    None,
                )
                .await?;
            mqtt_tx
                .lock()
                .await
                .publish(p2p_topic.clone(), to_vec(&msg)?)?;
            device_addr_to_session_id_map
                .lock()
                .await
                .insert(device_addr.clone(), session_id.clone());
            session_id_to_device_map
                .lock()
                .await
                .insert(session_id, device_addr.clone());
            info!("Response Hello to 0x{}", target);
        }
        PtpLocalMessageFromDevice::Keepalive => {
            // todo: maintain session
        }
        PtpLocalMessageFromDevice::ShouldAuthorizeUser(user_addr) => {
            let session_id = device_addr_to_session_id_map
                .lock()
                .await
                .get(&device_addr)
                .ok_or_else(|| anyhow!("No session_id for device_addr {}", &target))?
                .clone();
            let (msg, _) = signer
                .create_message(
                    MessageChannel::TunnelNegotiate,
                    to_vec(&PtpLocalMessageFromBroker::AreYouThere {
                        user_addr: user_addr.clone(),
                        session_id: session_id.clone(),
                    })?,
                    Some(device_addr.clone()),
                    None,
                )
                .await?;
            mqtt_tx
                .lock()
                .await
                .publish(p2p_topic.clone(), to_vec(&msg)?)?;
            user_addr_and_session_id_authorized_map
                .lock()
                .await
                .insert((user_addr, session_id.clone()), true);
            device_addr_to_session_id_map
                .lock()
                .await
                .insert(device_addr.clone(), session_id.clone());
            session_id_to_device_map
                .lock()
                .await
                .insert(session_id, device_addr);
            // todo: add timeout
            info!("Responsed Hello to 0x{}", target);
        }
        PtpLocalMessageFromDevice::MeVoila(_) => {
            // todo: maintain session
        }
        PtpLocalMessageFromDevice::ShouldSendMessage {
            user_addr: user_addr,
            data: payload,
        } => {
            if let Some(session_id) = device_addr_to_session_id_map.lock().await.get(&device_addr) {
                if let Some(result) = user_addr_and_session_id_authorized_map
                    .lock()
                    .await
                    .get(&(user_addr.clone(), session_id.clone()))
                {
                    if !*result {
                        warn!(
                            "Unauthorized user_addr 0x{} to device_addr 0x{}",
                            hex::encode(&user_addr),
                            hex::encode(&target)
                        );
                        return Ok(());
                    }
                    ctx.send_rings_message(
                        user_addr.to_did_string(),
                        &PtpUserMessageFromBroker::Message {
                            session: TrySessionInfo {
                                user_addr,
                                device_addr,
                                session_id: session_id.clone(),
                            },
                            data: payload,
                        },
                    )
                    .await?;
                } else {
                    warn!("No result for user_addr 0x{}", hex::encode(&user_addr));
                    return Ok(());
                }
            } else {
                warn!("No session_id for device_addr {}", &target);
                return Ok(());
            }
        }
    }

    Ok(())
}
