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
    pub nonce: Vec<u8>,
    pub public_key: Vec<u8>,
    pub session_id: Vec<u8>,
    pub broker_address: Vec<u8>,
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between user and broker
pub enum PtpUserMessageFromUser {
    TrySession(TrySessionInfo),
    Message(TrySessionInfo, Vec<u8>), // (TrySessionInfo, data)
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between user and broker
pub struct TrySessionInfo {
    pub user_addr: Vec<u8>,
    pub device_addr: Vec<u8>,
    pub session_id: Vec<u8>,
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between user and broker
pub enum PtpUserMessageFromBroker {
    SessionConnected(TrySessionInfo), // (ETH_ADDR, SESSION_ID)
    SessionConnLost(TrySessionInfo),  // (ETH_ADDR, SESSION_ID)
    Message(TrySessionInfo, Vec<u8>), // (ETH_ADDR, SESSION_ID, data)
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between broker and device
pub enum PtpLocalMessageFromDevice {
    Hello,
    Keepalive,
    ShouldAuthorizeUser(Vec<u8>),        // user_addr
    MeVoila(Vec<u8>),                    // session_id
    ShouldSendMessage(Vec<u8>, Vec<u8>), // (user_addr, data)
}

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
#[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
/// Message between broker and device
pub enum PtpLocalMessageFromBroker {
    Hello(Vec<u8>), // SESSION_ID
    Keepalive,
    AreYouThere(Vec<u8>, Vec<u8>),          // (user_addr, session_id)
    ShouldReceiveMessage(Vec<u8>, Vec<u8>), // (user_addr, data)
}
