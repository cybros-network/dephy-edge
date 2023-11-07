import {Client} from 'https://deno.land/x/mqtt@0.1.2/deno/mod.ts'
import dephyProto from "npm:dephy-proto"

const {RawMessage, SignedMessage} = dephyProto

const url = Deno.env.get("BROKER_URL") || 'mqtt://demo-edge.dephy.io:1883'
const client = new Client({url})

await client.connect()
console.log("Connected to broker.")

await client.subscribe("/dephy/signed_message");

client.on('message', (_, payload) => {
    try {
        const msg = SignedMessage.decodeBinary(payload);
        const raw = RawMessage.decodeBinary(msg.raw);
        console.log(raw)
    } catch (error) {
        console.log({payload, error})
    }
});
