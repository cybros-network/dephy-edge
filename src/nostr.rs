use crate::preludes::*;

use base58::{FromBase58, ToBase58};
use tokio_util::sync::CancellationToken;

pub static DEPHY_NOSTR_KIND: Kind = Kind::Regular(1111);

pub fn default_kind() -> Kind {
    DEPHY_NOSTR_KIND.clone()
}

pub fn default_filter(kind: Option<Kind>) -> Filter {
    let kind = match kind {
        Some(kind) => kind,
        None => default_kind(),
    };
    Filter::new()
        .kind(kind)
        .custom_tag(Alphabet::C, vec!["dephy"])
}

pub async fn start_nostr_context(
    ctx: Arc<AppContext>,
    cancel_token: CancellationToken,
) -> Result<()> {
    let client = ctx.nostr_client.clone();
    client.connect().await;

    // todo: blacklist
    let subscription_filter = default_filter(None).since(Timestamp::now());
    client.subscribe(vec![subscription_filter]).await;
    info!("Subscribing dephy events from NoStr network...");
    client
        .handle_notifications(move |n| {
            let ctx = ctx.clone();
            let cancel_token = cancel_token.clone();
            async move {
                if cancel_token.is_cancelled() {
                    return Ok(true);
                }
                let _ = tokio::spawn(wrap_handle_notification(ctx, n));
                Ok(false)
            }
        })
        .await?;

    Ok(())
}

async fn handle_notification(ctx: Arc<AppContext>, n: RelayPoolNotification) -> Result<()> {
    // todo: blacklist
    if let RelayPoolNotification::Event(u, n) = n {
        debug!("receiving dephy event from {:?}: {:?}", u, &n);
        let content = n
            .content
            .from_base58()
            .map_err(|e| anyhow!("error while parsing content: {:?}", e))?;

        let _signed = SignedMessage::decode(content.as_slice())?;
        // todo: check signature
        let mqtt_tx = ctx.mqtt_tx.clone();
        let mut mqtt_tx = mqtt_tx.lock().await;
        mqtt_tx.publish(DEPHY_TOPIC, content)?;
        drop(mqtt_tx);
    }
    Ok(())
}

async fn wrap_handle_notification(ctx: Arc<AppContext>, n: RelayPoolNotification) {
    if let Err(e) = handle_notification(ctx, n).await {
        error!("handle_notification: {:?}", e)
    }
}

// Forward messages from MQTT/HTTP to NoStr
pub async fn send_signed_message_to_network(
    ctx: Arc<AppContext>,
    client: Arc<Client>,
    msg: SignedMessage,
    keys: &Keys,
) -> Result<()> {
    trace!("send_signed_message_to_network");

    // todo: check signature
    let raw = RawMessage::decode(msg.raw.as_slice())?;
    let from_addr = if raw.from_address.len() == 20 {
        hex::encode(&raw.from_address)
    } else {
        bail!("Bad from_addr")
    };
    let to_addr = if raw.to_address.len() == 20 {
        hex::encode(&raw.to_address)
    } else {
        bail!("Bad to_addr")
    };

    let new_msg = SignedMessage {
        raw: msg.raw,
        hash: msg.hash,
        nonce: msg.nonce,
        signature: msg.signature,
        last_edge_addr: Some(ctx.eth_addr_bytes.to_vec()),
    };
    let content = new_msg.encode_to_vec().as_slice().to_base58();
    let tags = vec![
        Tag::Generic(TagKind::Custom("c".to_string()), vec!["dephy".to_string()]),
        Tag::Generic(
            TagKind::Custom("dephy_to".to_string()),
            vec![format!("did:dephy:0x{}", to_addr)],
        ),
        Tag::Generic(
            TagKind::Custom("dephy_from".to_string()),
            vec![format!("did:dephy:0x{}", from_addr)],
        ),
        Tag::Generic(
            TagKind::Custom("dephy_edge".to_string()),
            vec![format!("did:dephy:{}", ctx.eth_addr.as_str())],
        ),
    ];
    let event = EventBuilder::new(default_kind(), content, tags.as_slice()).to_event(keys)?;
    client.send_event(event).await?;
    Ok(())
}
