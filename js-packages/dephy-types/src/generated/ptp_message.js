// Generated file, don't edit!
import { BorshSchema } from 'borsher';

export const PtpRemoteNegotiateInfo = BorshSchema.Struct({
nonce: BorshSchema.Vec(BorshSchema.u8),
public_key: BorshSchema.Vec(BorshSchema.u8),
session_id: BorshSchema.Vec(BorshSchema.u8),
broker_address: BorshSchema.Vec(BorshSchema.u8)
});
export const PtpRemoteNegotiateMessageFromUser = BorshSchema.Enum({
Hello: BorshSchema.Struct({
nonce: BorshSchema.Vec(BorshSchema.u8),
public_key: BorshSchema.Vec(BorshSchema.u8)
})
});
export const PtpRemoteNegotiateMessageFromDevice = BorshSchema.Enum({
Hello: PtpRemoteNegotiateInfo,
BrokerNotSupported: BorshSchema.Unit,
DeviceNotSupported: BorshSchema.Unit
});
export const TrySessionInfo = BorshSchema.Struct({
user_addr: BorshSchema.Vec(BorshSchema.u8),
device_addr: BorshSchema.Vec(BorshSchema.u8),
session_id: BorshSchema.Vec(BorshSchema.u8)
});
export const PtpUserMessageFromUser = BorshSchema.Enum({
TrySession: TrySessionInfo,
Message: BorshSchema.Struct({
session: TrySessionInfo,
data: BorshSchema.Vec(BorshSchema.u8)
})
});
export const PtpUserMessageFromBroker = BorshSchema.Enum({
SessionConnected: TrySessionInfo,
SessionConnLost: TrySessionInfo,
Message: BorshSchema.Struct({
session: TrySessionInfo,
data: BorshSchema.Vec(BorshSchema.u8)
})
});
export const PtpLocalMessageFromDevice = BorshSchema.Enum({
Hello: BorshSchema.Unit,
Keepalive: BorshSchema.Unit,
ShouldAuthorizeUser: BorshSchema.Vec(BorshSchema.u8),
MeVoila: BorshSchema.Vec(BorshSchema.u8),
ShouldSendMessage: BorshSchema.Struct({
user_addr: BorshSchema.Vec(BorshSchema.u8),
data: BorshSchema.Vec(BorshSchema.u8)
})
});
export const PtpLocalMessageFromBroker = BorshSchema.Enum({
Hello: BorshSchema.Vec(BorshSchema.u8),
Keepalive: BorshSchema.Unit,
AreYouThere: BorshSchema.Struct({
user_addr: BorshSchema.Vec(BorshSchema.u8),
session_id: BorshSchema.Vec(BorshSchema.u8)
}),
ShouldReceiveMessage: BorshSchema.Struct({
user_addr: BorshSchema.Vec(BorshSchema.u8),
data: BorshSchema.Vec(BorshSchema.u8)
})
});
