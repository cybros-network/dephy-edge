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
                    let _ = tokio::spawn(async move {
                        if let Err(e) = handle_payload(n.payload).await {
                            error!("handle_payload: {:?}", e)
                        }
                    });
                }
                _ => {}
            }
        }
    }
}

async fn handle_payload(payload: Bytes) -> Result<()> {
    Ok(())
}
