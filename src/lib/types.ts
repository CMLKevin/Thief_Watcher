export type Severity = "critical" | "warning" | "error" | "info" | "ok";

export type LabelType =
  | "victim"
  | "suspect"
  | "bridge"
  | "protocol"
  | "dex"
  | "dex_aggregator"
  | "mixer"
  | "cex"
  | "contract"
  | "eoa"
  | "unknown"
  | "custom";

export interface AddressLabel {
  address: string;
  label?: string | null;
  type: LabelType | string;
  source: string;
  notes?: string;
  tags?: string[];
  confidence?: "high" | "medium" | "low";
  isContract?: boolean | null;
}

export interface WatchEvent {
  id: string;
  time: string;
  severity: Severity | string;
  message: string;
  wallet?: string;
  direction?: "in" | "out";
  token?: string;
  amount?: number;
  amountRaw?: string;
  from?: string;
  to?: string;
  counterparty?: string;
  counterpartyLabel?: AddressLabel;
  txHash?: string;
  block?: number;
  nonceOld?: number;
  nonceNew?: number;
  maticOld?: number;
  maticNew?: number;
  error?: string;
}

export interface WatchState {
  running: boolean;
  startedAt: string | null;
  lastPollAt: string | null;
  lastError: string | null;
  rpcPool: string[];
  thiefWallet: string;
  watching: string[];
  pollIntervalMs: number;
  lookbackBlocks: number;
  lastCheckedBlock: number | null;
  currentBlock: number | null;
  nonce: number | null;
  maticBalance: number;
  tokenBalances: Record<string, number>;
  events: WatchEvent[];
  eventCount: number;
  webhookUrl: string | null;
}

export interface TraceEdge {
  id: string;
  from: string;
  to: string;
  token: string;
  amount: number;
  block: number;
  txHash: string;
  hop: number;
}

export interface TraceNode {
  address: string;
  label: AddressLabel;
}

export interface TraceGraph {
  seeds: string[];
  hops: number;
  fromBlock: number;
  toBlock: number;
  nodeCount: number;
  edgeCount: number;
  nodes: TraceNode[];
  edges: TraceEdge[];
  riskBuckets: Record<string, number>;
  exposures: Record<string, number>;
  generatedAt: string;
}

export interface ProfileResult {
  address: string;
  label: AddressLabel;
  balances: {
    MATIC: number;
    nonce: number;
    USDC: number;
    "USDC.e": number;
  };
  recentWindowBlocks: number;
  recentTransfers: Array<{
    direction: "in" | "out";
    token: string;
    amount: number;
    txHash: string;
    block: number;
    counterparty: string;
    counterpartyLabel: AddressLabel;
  }>;
  profileHint: {
    title: string | null;
    canonical: string | null;
    username: string | null;
    isAnon: boolean | null;
  };
  queriedAt: string;
}
