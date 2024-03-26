import bs58 from "bs58";
import { borshDeserialize } from "borsher";
import {
  SignedMessage,
  RawMessage,
} from "dephy-borsh-types/src/generated/message";
import PQueue from "p-queue/dist";
import { processCustomMessage, processTrunkCustomMessage } from "./custom";
import {
  NAME_PROCESSED_TS,
  SHOULD_ENFORCE_MESSAGE_ORDER,
  SHOULD_IGNORE_PROCESS_ERROR,
} from "./constants";

let lastTs = 0;
let lastEvent = null;

function processNostrMessage(kv, event) {
  if (event.created_at >= lastTs) {
    lastTs = event.created_at;
    lastEvent = event;
  } else {
    console.error("Out of order", {
      currTs: event.created_at,
      lastTs,
      event,
      lastEvent,
    });
    if (SHOULD_ENFORCE_MESSAGE_ORDER) {
      throw new Error("Out of order");
    }
  }

  const promise = _processNostrMessage(kv, event);
  return SHOULD_IGNORE_PROCESS_ERROR
    ? promise.catch((e) => {
        console.error("Error while processNostrMessage:", e, event);
      })
    : promise;
}

async function _processNostrMessage(kv, event) {
  const msg = unpackNostrMessage(event);
  await processCustomMessage(msg);
  await kv.set(NAME_PROCESSED_TS, event.created_at);
}

function unpackNostrMessage(event) {
  const content = bs58.decode(event.content);
  const m = borshDeserialize(SignedMessage, content);
  const r = borshDeserialize(RawMessage, new Uint8Array(m.raw));
  // todo(?): may need to check singnature here

  return {
    id: event.id,
    event,
    m,
    r,
  };
}

function handleNostrMessageTrunk(filter, relay, kv) {
  const events = [];

  return new Promise(async (resolve, reject) => {
    const finish = () => {
      if (events.length === 0) {
        resolve();
        return;
      }
      processTrunkCustomMessage(events)
        .then(async () => {
          await kv.set(NAME_PROCESSED_TS, filter.until);
          resolve();
        })
        .catch((e) => {
          console.error("Error while processTrunkCustomMessage:", e);
          if (!SHOULD_IGNORE_PROCESS_ERROR) {
            resolve();
          } else {
            reject(e);
          }
        });
    };

    const sub = relay.subscribe(filter, {
      onevent(e) {
        let msg;
        try {
          msg = unpackNostrMessage(e);
        } catch (e) {
          console.error("Error while unpackNostrMessage:", e);
          if (!SHOULD_IGNORE_PROCESS_ERROR) {
            sub.close("error");
            reject(e);
            return;
          }
        }
        if (msg) {
          events.push(msg);
        }
      },
      oneose() {
        sub.close("eose");
        finish();
      },
    });
  });
}

const incomingQueue = new PQueue({ concurrency: 1 });

function handleIncomingNostrMessage(kv, filter, relay) {
  return new Promise(async (resolve) => {
    relay.subscribe(filter, {
      onevent(e) {
        incomingQueue.add(async () => {
          await processNostrMessage(kv, e);
        });
      },
      // oneose() {
      // sub.close("eose");
      // resolve();
      // },
      onclose() {
        console.log("The relay has closed the connection, exiting...");
        resolve();
      },
    });
  });
}

export {
  processNostrMessage,
  unpackNostrMessage,
  handleNostrMessageTrunk,
  handleIncomingNostrMessage,
};
