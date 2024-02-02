// Generated file, don't edit!
import { BorshSchema } from 'borsher';

export const MessageChannel = BorshSchema.Enum({
Normal: BorshSchema.u8,
OffchainControl: BorshSchema.u8,
TunnelNegotiate: BorshSchema.Unit
});
export const RawMessage = BorshSchema.Struct({
channel: MessageChannel,
timestamp: BorshSchema.u64,
from_address: BorshSchema.Vec(BorshSchema.u8),
to_address: BorshSchema.Vec(BorshSchema.u8),
encrypted: BorshSchema.bool,
enc_iv: BorshSchema.Option(BorshSchema.Vec(BorshSchema.u8)),
payload: BorshSchema.Vec(BorshSchema.u8)
});
export const SignedMessage = BorshSchema.Struct({
raw: BorshSchema.Vec(BorshSchema.u8),
hash: BorshSchema.Vec(BorshSchema.u8),
nonce: BorshSchema.u64,
signature: BorshSchema.Vec(BorshSchema.u8),
last_edge_addr: BorshSchema.Option(BorshSchema.Vec(BorshSchema.u8))
});
