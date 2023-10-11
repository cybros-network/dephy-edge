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

async fn handle_payload(ctx: Arc<AppContext>, payload: Bytes) -> Result<()> {
    let nostr_tx = ctx.nostr_tx.clone();
    let m = SignedMessage {
        raw: vec![],
        hash: vec![],
        nonce: 12312312312,
        signature: vec![],
    };
    nostr_tx.send(m)?;
    Ok(())
}
