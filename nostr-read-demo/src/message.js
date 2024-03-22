import bs58 from "bs58";
import { borshDeserialize } from "borsher";
import { SignedMessage, RawMessage } from 'dephy-borsh-types/src/generated/message'
import PQueue from 'p-queue/dist';
import { processCustomMessage } from "./custom";
import { NAME_PROCESSED_TS } from "./constants";

async function processNostrMessage(event) {
  try {
    const content = bs58.decode(event.content);
    const m = borshDeserialize(SignedMessage, content);
    const r = borshDeserialize(RawMessage, new Uint8Array(m.raw));
    // todo(?): may need to check singnature here

    const msg = {
      id: event.id,
      event,
      m,
      r,
    }

    await processCustomMessage(msg);
  } catch (e) {
    console.error(`Error while processing event:`, event)
  }
}

function handleNostrMessageTrunk(filter, relay) {
  const q = new PQueue({ concurrency: 255 });

  return new Promise(async (resolve) => {
    q.on('empty', () => {
      console.log('Batch done.')
      q.off('empty');
      resolve();
    });

    const sub = relay.subscribe(filter, {
      onevent(e) {
        q.add(() => processNostrMessage(e));
      },
      oneose() {
        if (q.size === 0) {
          sub.close("eose");
          q.off('empty');
          resolve();
        }
      }
    });
  });
}

const incomingQueue = new PQueue({ concurrency: 1 });

function handleIncomingNostrMessage(kv, filter, relay) {
  return new Promise(async (resolve) => {
    relay.subscribe(filter, {
      onevent(e) {
        incomingQueue.add(async () => {
          await processNostrMessage(e)
          await kv.set(NAME_PROCESSED_TS, e['created_at']);
        });
      },
      // oneose() {
      // sub.close("eose");
      // resolve();
      // },
      onclose() {
        console.log("The relay has closed the connection, exiting...")
        resolve();
      }
    });
  });
}

export {
  processNostrMessage,
  handleNostrMessageTrunk,
  handleIncomingNostrMessage
}
