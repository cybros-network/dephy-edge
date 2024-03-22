import { Relay, useWebSocketImplementation } from 'nostr-tools'
import { kvsEnvStorage } from "@kvs/env/lib/node";
import { handleNostrMessageTrunk, handleIncomingNostrMessage } from './message';
import WebSocket from "ws";
import {
  NAME_PROCESSED_TS,
  NAME_STORAGE,
  NOSTR_START_TIME,
  NOSTR_RELAY_URL,
  CONST_TIME_ONE_HOUR
} from './constants';

useWebSocketImplementation(WebSocket);

async function initStorage() {
  const kv = await kvsEnvStorage({
    name: NAME_STORAGE,
    version: 1
  });
  const curr = await kv.get(NAME_PROCESSED_TS);
  if (typeof curr !== 'number') {
    await kv.set(NAME_PROCESSED_TS, NOSTR_START_TIME - 1);
    console.log('Starting from', NOSTR_START_TIME);
  } else {
    console.log('Resuming from', curr);
  }
  return kv;
}

async function initRelay() {
  const relay = await Relay.connect(NOSTR_RELAY_URL);
  console.log(`connected to ${relay.url}`);
  return relay;
}

async function main() {
  const kv = await initStorage();
  const relay = await initRelay();

  let shouldContinue = false;
  while (!shouldContinue) {
    shouldContinue = await processHistoricMessages(kv, relay);
  }

  await subscribeMessages(kv, relay);
}

main().then(() => {
  console.log("Main done.");
  process.exit(0);
}).catch(e => {
  console.error(e);
  process.exit(255);
});

async function processHistoricMessages(kv, relay) {
  const last_processed = await kv.get(NAME_PROCESSED_TS);
  const now = Math.floor(Date.now() / 1000);
  const delta = now - last_processed;

  if (delta < 0) {
    throw new Error(`Time went backwards: last ${last_processed} -> now ${now}`);
  }

  if (delta < CONST_TIME_ONE_HOUR) {
    return true;
  }

  const trunkCount = Math.round(delta / CONST_TIME_ONE_HOUR) + 1;
  const trunks = new Array(trunkCount)
    .fill(null)
    .reduce((prev, _, i, arr) => {
      const from = last_processed + (i * CONST_TIME_ONE_HOUR) + 1;
      const toE = last_processed + ((i + 1) * CONST_TIME_ONE_HOUR);
      if (i + 1 === arr.length) {
        const to = Math.min(toE, now);
        prev.push({ from, to, i });
      } else {
        prev.push({ from, to: toE, i });
      }
      return prev
    }, []);

  for (const t of trunks) {
    console.log(`(${1 + t.i}/${trunks.length}) Processing messages from ${t.from} to ${t.to}`);

    await handleNostrMessageTrunk([{
      kinds: [1111],
      ["#c"]: ["dephy"],
      since: t.from,
      until: t.to,
    }], relay);


    await kv.set(NAME_PROCESSED_TS, t.to);
  }

  return false;
}

async function subscribeMessages(kv, relay) {
  const from = 1 + await kv.get(NAME_PROCESSED_TS);
  console.log('Subscribing to new messages from', from);
  await handleIncomingNostrMessage(kv, [{
    kinds: [1111],
    ["#c"]: ["dephy"],
    since: from
  }], relay)
}
