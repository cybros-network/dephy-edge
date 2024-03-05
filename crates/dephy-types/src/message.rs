pub use inner::*;

#[cfg_attr(
    feature = "generate_js",
    borsher_macro::borsher("../../../js-packages/dephy-borsh-types/src/generated/message.js")
)]
mod inner {
    #[cfg(feature = "derive")]
    use borsh::{BorshDeserialize, BorshSerialize};

    #[derive(Clone, PartialEq)]
    #[cfg_attr(feature = "std", derive(Debug))]
    #[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
    pub enum MessageChannel {
        Normal(u8),
        // Normal message to be rolled up on-chain with 256 sub-channels for application use
        OffchainControl(u8),
        // Offchain control with 256 sub-channels for application use, WILL NOT be rolled up on-chain
        TunnelNegotiate, // Exclusive P2P channel for tunnel negotiate, WILL NOT be rolled up on-chain
    }

    #[derive(Clone, PartialEq)]
    #[cfg_attr(feature = "std", derive(Debug))]
    #[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
    pub struct RawMessage {
        pub channel: MessageChannel,
        pub timestamp: u64,
        pub from_address: Vec<u8>,
        // ethereum address in bytes form
        pub to_address: Vec<u8>,
        // ethereum address in bytes form
        pub encrypted: bool,
        // Whether the payload is encrypted, the key should be negotiated with ECDH
        pub enc_iv: Option<Vec<u8>>,
        pub payload: Vec<u8>,
    }

    #[derive(Clone, PartialEq)]
    #[cfg_attr(feature = "std", derive(Debug))]
    #[cfg_attr(feature = "derive", derive(BorshSerialize, BorshDeserialize))]
    pub struct SignedMessage {
        pub raw: Vec<u8>,
        pub hash: Vec<u8>,
        pub nonce: u64,
        pub signature: Vec<u8>,
        pub last_edge_addr: Option<Vec<u8>>,
        pub session_id: Vec<u8>,
    }
}
