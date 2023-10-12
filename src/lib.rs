pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/dephy.message.rs"));
}

pub mod app_main;
pub mod crypto;
pub mod http;
pub mod mqtt_broker;
pub mod nostr;
pub mod preludes;
