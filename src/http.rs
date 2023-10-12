use crate::preludes::*;

use base58::ToBase58;
use tokio::task::JoinSet;
use warp::{http::StatusCode, Filter};

fn with_ctx(
    ctx: Arc<AppContext>,
) -> impl Filter<Extract = (Arc<AppContext>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || ctx.clone())
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AppHttpError {
    pub error: String,
}

pub async fn start_http_server(ctx: Arc<AppContext>) -> Result<()> {
    let main_filter = warp::post()
        .and(warp::path!("dephy" / "signed_message"))
        .and(warp::body::content_length_limit(1024 * 1024))
        .and(warp::header::exact("content-type", "application/x-dephy"))
        .and(with_ctx(ctx.clone()))
        .and(warp::body::bytes())
        .and_then(wrap_handle_signed_message);

    let mut js = JoinSet::new();
    for addr in ctx.opt.http_bind_address.clone().into_iter() {
        let main_filter = main_filter.clone();
        js.spawn(async move {
            info!("Started HTTP server on {:?}", &addr);
            warp::serve(main_filter).run(addr).await;
        });
    }
    while let Some(res) = js.join_next().await {
        let e: Option<Error> = match res {
            Ok(_) => None,
            Err(e) => {
                error!("start_server: {:?}", &e);
                Some(e.into())
            }
        };
        if let Some(e) = e {
            error!("start_server: {:?}", &e);
            return Err(e.into());
        }
    }
    Ok(())
}

async fn wrap_handle_signed_message(
    ctx: Arc<AppContext>,
    body: Bytes,
) -> Result<Box<dyn warp::Reply>, warp::Rejection> {
    match handle_signed_message(ctx, body).await {
        Ok(v) => Ok(v),
        Err(e) => {
            let j = serde_json::json!({
                "ok": false,
                "error": format!("{:?}", e),
            });
            Ok(Box::new(warp::reply::with_status(
                warp::reply::json(&j),
                StatusCode::BAD_REQUEST,
            )))
        }
    }
}

async fn handle_signed_message(ctx: Arc<AppContext>, body: Bytes) -> Result<Box<dyn warp::Reply>> {
    let msg = SignedMessage::decode(body.as_ref())?;

    if *&msg.last_edge_addr.is_some() {
        bail!("Message must be from a device!");
    }

    // todo: check signature

    let content = body.to_base58();

    let mqtt_tx = ctx.mqtt_tx.clone();
    let mut mqtt_tx = mqtt_tx.lock().await;
    mqtt_tx.publish(DEPHY_TOPIC, content)?;
    drop(mqtt_tx);

    // no need to manually redistribute to nostr here

    let j = serde_json::json!({
        "ok": true,
    });
    Ok(Box::new(warp::reply::json(&j)))
}
