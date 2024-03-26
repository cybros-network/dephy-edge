export const NAME_STORAGE = "dephy_kv";
export const NAME_PROCESSED_TS = "processed_ts";

export const CONST_TIME_ONE_HOUR = 60 * 60;

export const NOSTR_RELAY_URL =
  process.env.NOSTR_RELAY_URL || "wss://poc-relay.dephy.cloud/";
export const NOSTR_START_TIME =
  parseInt(process.env.NOSTR_START_TIME) || 1710864000; // Tue Mar 19 2024 16:00:00 GMT+0000

export const SCAN_DURATION =
  parseInt(process.env.SCAN_DURATION) || 5;

export const SHOULD_IGNORE_PROCESS_ERROR =
  process.env.SHOULD_IGNORE_PROCESS_ERROR === "true" || false;

export const SHOULD_ENFORCE_MESSAGE_ORDER =
  process.env.SHOULD_ENFORCE_MESSAGE_ORDER === "true" || false;

export const USE_OLD_SUBSCRIBE_BEHAVIOR =
  process.env.USE_OLD_SUBSCRIBE_BEHAVIOR === "true" || false;
