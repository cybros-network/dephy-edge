use crate::{
    crypto::{check_message, did_str_to_addr_bytes},
    preludes::*,
};

use dephy_types::borsh::to_vec;
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

        let curr_addr = &ctx.eth_addr_bytes;
        if edge.eq(curr_addr) {
            return Ok(());
        }

        let content = bs58::decode(n.content).into_vec()?;
        let (mut signed, raw) = check_message(content.as_slice())?;

        if *&signed.last_edge_addr.is_none() {
            return Ok(());
        }

        if from.ne(&raw.from_address) || to.ne(&raw.to_address) {
            return Ok(());
        }

        signed.last_edge_addr = Some(curr_addr.to_vec());
        let content = to_vec(&signed)?;

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
    let (msg, raw) = check_message(to_vec(&msg)?.as_slice())?;

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
    let content = bs58::encode(to_vec(&new_msg)?.as_slice()).into_string();
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
