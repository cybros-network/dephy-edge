use bytes::Bytes;
use rumqttd::local::LinkRx;
use tokio_util::sync::CancellationToken;

use crate::preludes::*;

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
                    let _ = tokio::spawn(async move {
                        if let Err(e) = handle_payload(ctx, n.payload).await {
                            error!("handle_payload: {:?}", e)
                        }
                    });
                }
                _ => {}
            }
        }
    }
}

// Forward events from MQTT to NoStr
async fn handle_payload(ctx: Arc<AppContext>, payload: Bytes) -> Result<()> {
    let nostr_tx = ctx.nostr_tx.clone();

    let msg = SignedMessage::decode(payload.as_ref())?;

    // Don't redistribute self
    if let Some(last_edge_addr) = &msg.last_edge_addr {
        if last_edge_addr.as_slice() == &ctx.eth_addr_bytes {
            return Ok(());
        }
    }
    nostr_tx.send(msg)?;
    Ok(())
}
