import { BorshSchema, borshDeserialize } from "borsher";

const EventData = BorshSchema.Struct({
  original: BorshSchema.f64,
  weight: BorshSchema.f64,
  actually: BorshSchema.f64,
});

async function processCustomMessage({ id, event, m, r }) {
  const payload = borshDeserialize(EventData, new Uint8Array(r.payload));
  // console.log(id, event['created_at'], payload);
}

export { processCustomMessage };
