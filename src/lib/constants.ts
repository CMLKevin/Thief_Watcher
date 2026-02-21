import path from "node:path";

export const TRANSFER_TOPIC =
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

export const DEFAULT_RPC_POOL = [
  "https://1rpc.io/matic",
  "https://polygon.gateway.tenderly.co",
  "https://polygon.api.onfinality.io/public",
  "https://polygon-pokt.nodies.app",
] as const;

export const TOKENS = [
  {
    symbol: "USDC",
    address: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
    decimals: 6,
  },
  {
    symbol: "USDC.e",
    address: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
    decimals: 6,
  },
] as const;

export const DEFAULT_THIEF_WALLET =
  "0xF5eF5Ac6B71373Be7af86eBD00Af44794CE3074E";

export const DEFAULT_VICTIM_WALLET =
  "0x3addc290c324d45a8e4fa8ef129054d15a8590ef";

export const POLL_INTERVAL_MS = 8000;
export const LOOKBACK_BLOCKS = 250;
export const MAX_STORED_EVENTS = 1000;

const base = process.env.VERCEL ? "/tmp/thief_watcher" : path.join(process.cwd(), ".tw_data");
export const DATA_DIR = process.env.THIEF_WATCHER_DATA_DIR || base;

export const STATE_FILE = path.join(DATA_DIR, "watch_state.json");
export const TAGS_FILE = path.join(DATA_DIR, "custom_tags.json");
