#[cfg(feature = "derive")]
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between user and device through NoStr
pub enum PtpRemoteNegotiateMessageFromUser {
    Hello { nonce: Vec<u8>, public_key: Vec<u8> },
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between user and device through NoStr
pub enum PtpRemoteNegotiateMessageFromDevice {
    Hello(PtpRemoteNegotiateInfo),
    BrokerNotSupported,
    DeviceNotSupported,
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
pub struct PtpRemoteNegotiateInfo {
    nonce: Vec<u8>,
    public_key: Vec<u8>,
    session_id: Vec<u8>,
    broker_address: Vec<u8>,
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between user and broker
pub enum PtpUserMessageFromUser {
    TrySession(Vec<u8>, Vec<u8>),       // (ETH_ADDR, SESSION_ID)
    Message(Vec<u8>, Vec<u8>, Vec<u8>), // (ETH_ADDR, SESSION_ID, data)
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between user and broker
pub enum PtpUserMessageFromBroker {
    SessionConnected(Vec<u8>, Vec<u8>), // (ETH_ADDR, SESSION_ID)
    SessionConnLost(Vec<u8>, Vec<u8>),  // (ETH_ADDR, SESSION_ID)
    Message(Vec<u8>, Vec<u8>, Vec<u8>), // (ETH_ADDR, SESSION_ID, data)
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between broker and device
pub enum PtpLocalMessage {
    FromDevice(PtpLocalMessageFromDevice),
    FromBroker(PtpLocalMessageFromBroker),
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between broker and device
pub enum PtpLocalMessageFromDevice {
    Hello(Vec<u8>),            // nonce, the nonce should be changed during a connection
    Keepalive(Vec<u8>),        // SESSION_ID
    MeVoila(Vec<u8>),          // nonce
    Message(Vec<u8>, Vec<u8>), // (TO_ADDR, data)
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between broker and device
pub enum PtpLocalMessageFromBroker {
    Hello(Vec<u8>, Vec<u8>), // (nonce, SESSION_ID)
    Keepalive,
    AreYouThere(Vec<u8>, Vec<u8>), // (FROM_ADDR, nonce)
    Message(Vec<u8>, Vec<u8>),     // (FROM_ADDR, data)
}
