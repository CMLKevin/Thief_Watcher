import { createHash } from "node:crypto";

import {
  DEFAULT_RPC_POOL,
  DEFAULT_THIEF_WALLET,
  LOOKBACK_BLOCKS,
  MAX_STORED_EVENTS,
  POLL_INTERVAL_MS,
  TOKENS,
} from "@/lib/constants";
import {
  blockNumber,
  maticBalance,
  scanTokenTransfers,
  tokenBalance,
  txCount,
} from "@/lib/rpc";
import { readCustomTags, readState, writeCustomTags, writeState } from "@/lib/storage";
import type {
  AddressLabel,
  ProfileResult,
  TraceEdge,
  TraceGraph,
  TraceNode,
  WatchEvent,
  WatchState,
} from "@/lib/types";
import {
  addrTopic,
  dedupe,
  isHexAddress,
  normalizeAddress,
  nowIso,
  toFloatSafe,
} from "@/lib/utils";

const TRACKED_THIEF_WALLET = normalizeAddress(DEFAULT_THIEF_WALLET);

const defaultTags: Record<string, Partial<AddressLabel>> = {
  "0x3addc290c324d45a8e4fa8ef129054d15a8590ef": {
    label: "Victim Polymarket Proxy Wallet",
    type: "victim",
    source: "case",
    notes: "Shared custody account",
  },
  "0xf5ef5ac6b71373be7af86ebd00af44794ce3074e": {
    label: "Final Recipient (Case)",
    type: "suspect",
    source: "case",
    notes: "Receives both relay settlements",
  },
  "0xf70da97812cb96acdf810712aa562db8dfa3dbef": {
    label: "Relay Solver",
    type: "bridge",
    source: "protocol",
    notes: "Relay infrastructure wallet",
  },
  "0xab45c5a4b0c941a2f231c04c3f49182e1a254052": {
    label: "ProxyWalletFactory",
    type: "protocol",
    source: "verified_contract",
    notes: "Polymarket proxy wallet system",
  },
  "0xd216153c06e857cd7f72665e0af1d7d82172f494": {
    label: "RelayHub",
    type: "protocol",
    source: "verified_contract",
    notes: "Meta-tx relay hub contract",
  },
  "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff": {
    label: "QuickSwap V2 Router",
    type: "dex",
    source: "docs",
  },
  "0xe592427a0aece92de3edee1f18e0157c05861564": {
    label: "Uniswap V3 SwapRouter",
    type: "dex",
    source: "deployed_contract",
  },
  "0x1111111254eeb25477b68fb85ed929f73a960582": {
    label: "1inch Aggregation Router",
    type: "dex_aggregator",
    source: "known",
  },
  "0xdef171fe48cf0115b1d80b88dc8eab59176fee57": {
    label: "ParaSwap Augustus",
    type: "dex_aggregator",
    source: "known",
  },
  "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {
    label: "Tornado Cash Proxy",
    type: "mixer",
    source: "known",
  },
  "0x722122df12d4e14e13ac3b6895a86e84145b6967": {
    label: "Tornado Cash Relayer Registry",
    type: "mixer",
    source: "known",
  },
};

const labelCache = new Map<string, AddressLabel>();

function defaultState(): WatchState {
  return {
    running: true,
    startedAt: nowIso(),
    lastPollAt: null,
    lastError: null,
    rpcPool: [...DEFAULT_RPC_POOL],
    thiefWallet: TRACKED_THIEF_WALLET,
    watching: [TRACKED_THIEF_WALLET],
    pollIntervalMs: POLL_INTERVAL_MS,
    lookbackBlocks: LOOKBACK_BLOCKS,
    lastCheckedBlock: null,
    currentBlock: null,
    nonce: null,
    maticBalance: 0,
    tokenBalances: {
      USDC: 0,
      "USDC.e": 0,
    },
    events: [],
    eventCount: 0,
    webhookUrl: null,
  };
}

function normalizeTagMap(
  tags: Record<string, Partial<AddressLabel>>,
): Record<string, Partial<AddressLabel>> {
  const out: Record<string, Partial<AddressLabel>> = {};
  for (const [key, value] of Object.entries(tags || {})) {
    if (!isHexAddress(key)) continue;
    out[normalizeAddress(key)] = value;
  }
  return out;
}

export async function listTags(): Promise<Record<string, Partial<AddressLabel>>> {
  const custom = normalizeTagMap(await readCustomTags());
  return {
    ...defaultTags,
    ...custom,
  };
}

export async function addCustomTag(input: {
  address: string;
  label: string;
  type: string;
  notes?: string;
  source?: string;
}): Promise<void> {
  const address = normalizeAddress(input.address);
  if (!isHexAddress(address)) {
    throw new Error("Invalid address");
  }

  const existing = normalizeTagMap(await readCustomTags());
  existing[address] = {
    address,
    label: input.label,
    type: input.type || "custom",
    source: input.source || "manual",
    notes: input.notes || "",
    confidence: "high",
  };
  await writeCustomTags(existing);
  labelCache.delete(address);
}

export async function classifyAddress(address: string): Promise<AddressLabel> {
  const key = normalizeAddress(address);
  if (labelCache.has(key)) {
    return labelCache.get(key)!;
  }

  const tags = await listTags();
  const tagged = tags[key];
  if (tagged) {
    const label: AddressLabel = {
      address: key,
      label: tagged.label || null,
      type: tagged.type || "unknown",
      source: tagged.source || "case",
      notes: tagged.notes || "",
      confidence: "high",
      isContract: tagged.type === "contract" ? true : null,
      tags: [],
    };
    labelCache.set(key, label);
    return label;
  }

  const out: AddressLabel = {
    address: key,
    label: null,
    type: "unknown",
    source: "none",
    notes: "",
    confidence: "low",
    isContract: null,
    tags: [],
  };

  try {
    const res = await fetch(`https://polygon.blockscout.com/api/v2/addresses/${key}`, {
      cache: "no-store",
    });
    if (res.ok) {
      const data = (await res.json()) as Record<string, unknown>;
      const metadata = (data.metadata || {}) as { tags?: Array<{ name?: string }> };
      const tags = (metadata.tags || []).map((t) => t.name).filter(Boolean) as string[];
      const name = String(data.name || "") || null;
      const isContract = Boolean(data.is_contract);
      const joined = `${name || ""} ${tags.join(" ")}`.toLowerCase();

      let inferred = isContract ? "contract" : "eoa";
      if (["relay", "bridge", "cctp", "across", "stargate", "hop"].some((x) => joined.includes(x))) {
        inferred = "bridge";
      }
      if (["swap", "router", "quickswap", "uniswap", "1inch", "paraswap", "dex"].some((x) => joined.includes(x))) {
        inferred = "dex";
      }
      if (["binance", "coinbase", "kraken", "okx", "bybit", "kucoin", "exchange"].some((x) => joined.includes(x))) {
        inferred = "cex";
      }
      if (["tornado", "mixer", "railgun", "sinbad"].some((x) => joined.includes(x))) {
        inferred = "mixer";
      }

      out.label = name;
      out.isContract = isContract;
      out.tags = tags;
      out.type = inferred;
      out.source = "blockscout";
      out.confidence = "medium";
    }
  } catch {
    // best-effort enrichment only
  }

  labelCache.set(key, out);
  return out;
}

async function emitWebhook(event: WatchEvent, state: WatchState): Promise<void> {
  if (!state.webhookUrl) return;
  const sev = String(event.severity || "").toLowerCase();
  if (!["critical", "warning", "error"].includes(sev)) return;

  try {
    await fetch(state.webhookUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        text: `[${String(event.severity).toUpperCase()}] ${event.message}`,
        event,
        timestamp: nowIso(),
        service: "thief_watcher_next",
      }),
    });
  } catch {
    // ignore webhook failures
  }
}

function eventId(payload: string): string {
  return createHash("sha256").update(payload).digest("hex").slice(0, 24);
}

async function appendEvents(state: WatchState, events: WatchEvent[]): Promise<WatchState> {
  if (!events.length) return state;
  const existing = new Set(state.events.map((e) => e.id));
  const inserted: WatchEvent[] = [];

  for (const ev of events) {
    if (existing.has(ev.id)) continue;
    inserted.push(ev);
    existing.add(ev.id);
  }
  if (!inserted.length) return state;

  const merged = [...inserted, ...state.events].slice(0, MAX_STORED_EVENTS);
  for (const ev of inserted) {
    await emitWebhook(ev, state);
  }

  return {
    ...state,
    events: merged,
    eventCount: state.eventCount + inserted.length,
  };
}

async function tickInternal(state: WatchState): Promise<WatchState> {
  const wallet = TRACKED_THIEF_WALLET;
  const rpcPool = state.rpcPool?.length ? state.rpcPool : [...DEFAULT_RPC_POOL];

  const current = await blockNumber(rpcPool);
  let last = state.lastCheckedBlock;
  if (last === null) {
    last = Math.max(0, current - state.lookbackBlocks);
  }

  let nextState: WatchState = {
    ...state,
    currentBlock: current,
    lastCheckedBlock: last,
  };

  if (current > last) {
    const events: WatchEvent[] = [];
    let start = last + 1;
    const window = 1200;

    while (start <= current) {
      const end = Math.min(start + window - 1, current);
      for (const token of TOKENS) {
        const transfers = await scanTokenTransfers(wallet, token, start, end, rpcPool);
        for (const transfer of transfers) {
          const counterpartyLabel = await classifyAddress(transfer.counterparty);
          const severity =
            transfer.direction === "out"
              ? "critical"
              : ["bridge", "mixer", "cex", "dex"].includes(String(counterpartyLabel.type))
                ? "warning"
                : "info";

          events.push({
            id: eventId(
              `${transfer.txHash}:${transfer.logIndex}:${transfer.direction}:${token.symbol}`,
            ),
            time: nowIso(),
            severity,
            message:
              transfer.direction === "out"
                ? `Outgoing ${token.symbol} from watched wallet`
                : `Incoming ${token.symbol} to watched wallet`,
            wallet,
            direction: transfer.direction,
            token: token.symbol,
            amount: Number(transfer.amount.toFixed(6)),
            amountRaw: transfer.amountRaw.toString(),
            from: transfer.direction === "out" ? wallet : transfer.counterparty,
            to: transfer.direction === "out" ? transfer.counterparty : wallet,
            counterparty: transfer.counterparty,
            counterpartyLabel,
            txHash: transfer.txHash,
            block: transfer.block,
          });
        }
      }

      start = end + 1;
    }

    nextState = await appendEvents(nextState, events);
    nextState.lastCheckedBlock = current;
  }

  const nonce = await txCount(wallet, rpcPool);
  const matic = await maticBalance(wallet, rpcPool);

  if (nextState.nonce !== null && nonce > nextState.nonce) {
    nextState = await appendEvents(nextState, [
      {
        id: eventId(`nonce:${nextState.nonce}->${nonce}:${Date.now()}`),
        time: nowIso(),
        severity: "critical",
        message: "Watched wallet nonce increased (outgoing tx likely)",
        wallet,
        nonceOld: nextState.nonce,
        nonceNew: nonce,
      },
    ]);
  }

  if (matic > toFloatSafe(nextState.maticBalance, 0) + 1e-12) {
    nextState = await appendEvents(nextState, [
      {
        id: eventId(`matic:${nextState.maticBalance}->${matic}:${Date.now()}`),
        time: nowIso(),
        severity: "warning",
        message: "Watched wallet received MATIC gas funding",
        wallet,
        maticOld: nextState.maticBalance,
        maticNew: Number(matic.toFixed(8)),
      },
    ]);
  }

  const balances: Record<string, number> = {};
  for (const token of TOKENS) {
    balances[token.symbol] = Number((await tokenBalance(token.address, wallet, token.decimals, rpcPool)).toFixed(6));
  }

  nextState.nonce = nonce;
  nextState.maticBalance = Number(matic.toFixed(8));
  nextState.tokenBalances = balances;
  nextState.lastPollAt = nowIso();
  nextState.lastError = null;
  return nextState;
}

export async function ensureState(): Promise<WatchState> {
  const current = await readState(defaultState());
  const merged: WatchState = {
    ...defaultState(),
    ...current,
    // Hard lock monitoring target to the incident thief wallet.
    thiefWallet: TRACKED_THIEF_WALLET,
    watching: [TRACKED_THIEF_WALLET],
    rpcPool:
      Array.isArray(current.rpcPool) && current.rpcPool.length
        ? current.rpcPool
        : [...DEFAULT_RPC_POOL],
    events: Array.isArray(current.events) ? current.events : [],
    tokenBalances: {
      USDC: toFloatSafe(current.tokenBalances?.USDC, 0),
      "USDC.e": toFloatSafe(current.tokenBalances?.["USDC.e"], 0),
    },
  };
  await writeState(merged);
  return merged;
}

export async function refreshState(options?: {
  forceTick?: boolean;
  ignoreRunningFlag?: boolean;
}): Promise<WatchState> {
  const state = await ensureState();
  const forceTick = Boolean(options?.forceTick);
  const ignoreRunningFlag = Boolean(options?.ignoreRunningFlag);

  const running = ignoreRunningFlag ? true : state.running;
  if (!running && !forceTick) {
    return state;
  }

  const lastPollMs = state.lastPollAt ? Date.parse(state.lastPollAt) : 0;
  const stale = Date.now() - lastPollMs >= state.pollIntervalMs;
  if (!forceTick && !stale) {
    return state;
  }

  try {
    const updated = await tickInternal({ ...state, running });
    await writeState(updated);
    return updated;
  } catch (error) {
    const failed = {
      ...state,
      lastError: String(error),
      lastPollAt: nowIso(),
    };

    const withErrEvent = await appendEvents(failed, [
      {
        id: eventId(`error:${Date.now()}:${failed.lastError}`),
        time: nowIso(),
        severity: "error",
        message: "Watcher polling error",
        error: failed.lastError || undefined,
      },
    ]);

    await writeState(withErrEvent);
    return withErrEvent;
  }
}

export async function setRunning(running: boolean): Promise<WatchState> {
  const state = await ensureState();
  const next: WatchState = {
    ...state,
    running,
    startedAt: running ? state.startedAt || nowIso() : state.startedAt,
  };
  await writeState(next);
  return next;
}

export async function setWebhook(url: string | null): Promise<WatchState> {
  const state = await ensureState();
  const next: WatchState = {
    ...state,
    webhookUrl: url && url.trim() ? url.trim() : null,
  };
  await writeState(next);
  return next;
}

export async function filterEvents(params: {
  limit?: number;
  severity?: string;
  direction?: string;
  token?: string;
  q?: string;
}): Promise<{ events: WatchEvent[]; total: number; returned: number }> {
  const state = await refreshState();
  const limit = Math.max(1, Math.min(1000, params.limit || 150));
  const sevFilter = new Set((params.severity || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean));
  const dirFilter = new Set((params.direction || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean));
  const tokenFilter = new Set((params.token || "").split(",").map((s) => s.trim().toUpperCase()).filter(Boolean));
  const q = (params.q || "").trim().toLowerCase();

  const selected = state.events.filter((event) => {
    const sev = String(event.severity || "").toLowerCase();
    const dir = String(event.direction || "").toLowerCase();
    const token = String(event.token || "").toUpperCase();
    if (sevFilter.size && !sevFilter.has(sev)) return false;
    if (dirFilter.size && !dirFilter.has(dir)) return false;
    if (tokenFilter.size && !tokenFilter.has(token)) return false;
    if (!q) return true;
    const blob = `${event.message || ""} ${event.counterparty || ""} ${event.txHash || ""}`.toLowerCase();
    return blob.includes(q);
  });

  return {
    events: selected.slice(0, limit),
    total: state.eventCount,
    returned: Math.min(limit, selected.length),
  };
}

export async function polymarketProfileHint(address: string): Promise<{
  title: string | null;
  canonical: string | null;
  username: string | null;
  isAnon: boolean | null;
}> {
  const out: {
    title: string | null;
    canonical: string | null;
    username: string | null;
    isAnon: boolean | null;
  } = {
    title: null,
    canonical: null,
    username: null,
    isAnon: null,
  };

  try {
    const res = await fetch(`https://polymarket.com/profile/${normalizeAddress(address)}`, {
      cache: "no-store",
    });
    if (!res.ok) return out;
    const html = await res.text();

    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    if (titleMatch) out.title = titleMatch[1].trim();

    const canonicalMatch = html.match(/<link rel="canonical" href="([^"]+)"/i);
    if (canonicalMatch) out.canonical = canonicalMatch[1];

    const usernameMatch = html.match(/"username":"([^"]+)"/i);
    if (usernameMatch) out.username = usernameMatch[1];

    const anonMatch = html.match(/"isAnon":(true|false)/i);
    if (anonMatch) out.isAnon = anonMatch[1] === "true";
  } catch {
    // ignore
  }

  return out;
}

export async function profileAddress(
  address: string,
  recentWindowBlocks = 50000,
): Promise<ProfileResult> {
  const normalized = normalizeAddress(address);
  const state = await ensureState();
  const rpcPool = state.rpcPool;

  const current = await blockNumber(rpcPool);
  const start = Math.max(0, current - recentWindowBlocks);

  const label = await classifyAddress(normalized);
  const balances = {
    MATIC: Number((await maticBalance(normalized, rpcPool)).toFixed(8)),
    nonce: await txCount(normalized, rpcPool),
    USDC: Number((await tokenBalance(TOKENS[0].address, normalized, 6, rpcPool)).toFixed(6)),
    "USDC.e": Number((await tokenBalance(TOKENS[1].address, normalized, 6, rpcPool)).toFixed(6)),
  };

  const recentTransfers: ProfileResult["recentTransfers"] = [];
  for (const token of TOKENS) {
    const rows = await scanTokenTransfers(normalized, token, start, current, rpcPool);
    for (const row of rows) {
      recentTransfers.push({
        direction: row.direction,
        token: row.token,
        amount: Number(row.amount.toFixed(6)),
        txHash: row.txHash,
        block: row.block,
        counterparty: row.counterparty,
        counterpartyLabel: await classifyAddress(row.counterparty),
      });
    }
  }

  recentTransfers.sort((a, b) => b.block - a.block);

  return {
    address: normalized,
    label,
    balances,
    recentWindowBlocks,
    recentTransfers: recentTransfers.slice(0, 220),
    profileHint: await polymarketProfileHint(normalized),
    queriedAt: nowIso(),
  };
}

function exposureFromNodes(nodes: TraceNode[]): Record<string, number> {
  const exposures: Record<string, number> = {
    cex: 0,
    dex: 0,
    mixer: 0,
    bridge: 0,
  };

  for (const node of nodes) {
    const type = String(node.label?.type || "").toLowerCase();
    if (exposures[type] !== undefined) {
      exposures[type] += 1;
    }
  }

  return exposures;
}

export async function buildTraceGraph(input: {
  seeds: string[];
  hops?: number;
  fromBlock?: number | null;
  toBlock?: number | null;
  maxEdges?: number;
}): Promise<TraceGraph> {
  const state = await ensureState();
  const rpcPool = state.rpcPool;

  const current = await blockNumber(rpcPool);
  const fromBlock = input.fromBlock ?? Math.max(0, current - 200000);
  const toBlock = input.toBlock ?? current;
  const hops = Math.max(1, Math.min(5, Math.floor(input.hops ?? 2)));
  const maxEdges = Math.max(50, Math.min(3000, Math.floor(input.maxEdges ?? 1000)));

  const seeds = dedupe(
    input.seeds
      .map((s) => s.trim())
      .filter((s) => isHexAddress(s))
      .map((s) => normalizeAddress(s)),
  );
  if (!seeds.length) {
    throw new Error("Provide at least one valid seed address");
  }

  const queue: Array<{ address: string; depth: number }> = seeds.map((address) => ({
    address,
    depth: 0,
  }));
  const visited = new Set(seeds);

  const nodes = new Map<string, TraceNode>();
  const edges: TraceEdge[] = [];

  while (queue.length && edges.length < maxEdges) {
    const currentNode = queue.shift();
    if (!currentNode) break;

    if (!nodes.has(currentNode.address)) {
      nodes.set(currentNode.address, {
        address: currentNode.address,
        label: await classifyAddress(currentNode.address),
      });
    }

    if (currentNode.depth >= hops) continue;

    for (const token of TOKENS) {
      const logs = await scanTokenTransfers(
        currentNode.address,
        token,
        fromBlock,
        toBlock,
        rpcPool,
      );

      for (const log of logs.filter((item) => item.direction === "out").slice(0, 500)) {
        const to = normalizeAddress(log.counterparty);
        const edge: TraceEdge = {
          id: `${log.txHash}:${log.logIndex}:${token.symbol}`,
          from: currentNode.address,
          to,
          token: token.symbol,
          amount: Number(log.amount.toFixed(6)),
          block: log.block,
          txHash: log.txHash,
          hop: currentNode.depth + 1,
        };
        edges.push(edge);

        if (!nodes.has(to)) {
          nodes.set(to, {
            address: to,
            label: await classifyAddress(to),
          });
        }

        if (!visited.has(to) && currentNode.depth + 1 <= hops) {
          visited.add(to);
          queue.push({ address: to, depth: currentNode.depth + 1 });
        }

        if (edges.length >= maxEdges) break;
      }
      if (edges.length >= maxEdges) break;
    }
  }

  const nodeArr = [...nodes.values()];
  const riskBuckets: Record<string, number> = {
    cex: 0,
    dex: 0,
    mixer: 0,
    bridge: 0,
    suspect: 0,
    unknown: 0,
  };
  for (const node of nodeArr) {
    const type = String(node.label?.type || "unknown");
    riskBuckets[type] = (riskBuckets[type] || 0) + 1;
  }

  return {
    seeds,
    hops,
    fromBlock,
    toBlock,
    nodeCount: nodeArr.length,
    edgeCount: edges.length,
    nodes: nodeArr,
    edges,
    riskBuckets,
    exposures: exposureFromNodes(nodeArr),
    generatedAt: nowIso(),
  };
}

export async function recoveryPlaybook(): Promise<Record<string, unknown>> {
  const status = await refreshState();
  const critical = status.events.filter((e) =>
    ["critical", "error"].includes(String(e.severity).toLowerCase()),
  );

  return {
    generatedAt: nowIso(),
    objective: "Identify insider and maximize recovery probability",
    immediateActions: [
      "Preserve exchangeability: alert when suspect wallet receives MATIC or emits outgoing transfer.",
      "Request data preservation from Polymarket for authentication/session logs around incident window.",
      "Request preservation from Relay and relevant bridges using transaction hashes in the trace report.",
      "Migrate remaining shared assets to multisig with signer segregation and action audit trails.",
      "Prepare legal handoff package with timeline, trace graph, address labels, and exposure summary.",
    ],
    watchSignals: {
      criticalEventsSeen: critical.length,
      currentNonce: status.nonce,
      currentMatic: status.maticBalance,
      usdcBalance: status.tokenBalances.USDC,
      usdceBalance: status.tokenBalances["USDC.e"],
      webhookConfigured: Boolean(status.webhookUrl),
    },
  };
}

export async function statusWithIntel(): Promise<{
  status: WatchState;
  intelSummary: Record<string, unknown>;
  watchedWalletLabel: AddressLabel;
}> {
  const status = await refreshState();
  const tags = await listTags();
  const types: Record<string, number> = {};
  for (const val of Object.values(tags)) {
    const t = String(val.type || "unknown").toLowerCase();
    types[t] = (types[t] || 0) + 1;
  }

  return {
    status,
    intelSummary: {
      totalTags: Object.keys(tags).length,
      types,
    },
    watchedWalletLabel: await classifyAddress(status.thiefWallet),
  };
}

export async function manualTick(): Promise<WatchState> {
  const state = await ensureState();
  if (state.running) {
    throw new Error("Watcher is already running; stop it before manual tick");
  }
  return refreshState({ forceTick: true, ignoreRunningFlag: true });
}

export async function generateEscalationPacket(input: {
  caseId?: string;
  analyst?: string;
  cexName?: string;
  notes?: string;
  victimWallet?: string;
  suspectWallet?: string;
  seeds?: string[];
  window?: number;
  hops?: number;
  maxEdges?: number;
  fromBlock?: number;
  toBlock?: number;
}): Promise<{
  packetId: string;
  generatedAt: string;
  summary: Record<string, unknown>;
  artifacts: Record<string, string>;
}> {
  const caseId = (input.caseId || "polymarket-insider-drain").trim();
  const analyst = (input.analyst || "Unknown analyst").trim();
  const cexName = (input.cexName || "Unknown CEX").trim();
  const notes = (input.notes || "").trim();

  const status = await refreshState({ forceTick: true, ignoreRunningFlag: true });
  // Keep packet generation bound to the monitored thief wallet.
  const suspect = TRACKED_THIEF_WALLET;
  const victim = normalizeAddress(input.victimWallet || "0x3addc290c324d45a8e4fa8ef129054d15a8590ef");

  const seedSet = dedupe([
    ...(input.seeds || []).map(normalizeAddress).filter(isHexAddress),
    victim,
    suspect,
  ]);

  const profileWindow = Math.max(5000, Math.min(50000, Number(input.window || 20000)));
  const rpcPool = status.rpcPool?.length ? status.rpcPool : [...DEFAULT_RPC_POOL];

  const quickProfile = async (address: string) => ({
    address,
    label: await classifyAddress(address),
    balances: {
      MATIC: Number((await maticBalance(address, rpcPool)).toFixed(8)),
      nonce: await txCount(address, rpcPool),
      USDC: Number((await tokenBalance(TOKENS[0].address, address, 6, rpcPool)).toFixed(6)),
      "USDC.e": Number((await tokenBalance(TOKENS[1].address, address, 6, rpcPool)).toFixed(6)),
    },
    profileHint: await polymarketProfileHint(address),
    windowUsed: profileWindow,
    mode: "quick",
  });

  const [suspectProfile, victimProfile] = await Promise.all([
    quickProfile(suspect),
    quickProfile(victim),
  ]);
  const trace = await buildTraceGraph({
    seeds: seedSet,
    hops: input.hops || 2,
    maxEdges: input.maxEdges || 1200,
    fromBlock: input.fromBlock,
    toBlock: input.toBlock,
  });

  const traceHashes = new Set(trace.edges.map((e) => e.txHash));
  const nodeSet = new Set(trace.nodes.map((n) => n.address));

  const relevantEvents = status.events.filter((event) => {
    if (event.txHash && traceHashes.has(event.txHash)) return true;
    if (event.counterparty && nodeSet.has(event.counterparty)) return true;
    if (event.wallet && [suspect, victim].includes(event.wallet)) return true;
    return false;
  });

  const packet = {
    packetType: "cex-escalation",
    packetVersion: "1.0",
    generatedAt: nowIso(),
    case: {
      caseId,
      analyst,
      cexName,
      notes,
      objective: "Identify account holder and preserve evidence for possible freeze/recovery",
    },
    wallets: {
      victim,
      suspect,
      seeds: seedSet,
    },
    statusSnapshot: {
      currentBlock: status.currentBlock,
      nonce: status.nonce,
      tokenBalances: status.tokenBalances,
      eventCount: status.eventCount,
    },
    traceSummary: {
      hops: trace.hops,
      fromBlock: trace.fromBlock,
      toBlock: trace.toBlock,
      nodeCount: trace.nodeCount,
      edgeCount: trace.edgeCount,
      exposures: trace.exposures,
    },
    suspectProfile,
    victimProfile,
    trace,
    relevantEvents: relevantEvents.slice(0, 500),
    criticalEvents: relevantEvents
      .filter((ev) => ["critical", "error", "warning"].includes(String(ev.severity).toLowerCase()))
      .slice(0, 300),
  };

  const csvHeaders =
    "hop,block,tx_hash,from,to,token,amount,from_type,to_type,from_label,to_label\n";
  const traceCsv =
    csvHeaders +
    trace.edges
      .map((e) => {
        const fromLabel = trace.nodes.find((n) => n.address === e.from)?.label;
        const toLabel = trace.nodes.find((n) => n.address === e.to)?.label;
        return [
          e.hop,
          e.block,
          e.txHash,
          e.from,
          e.to,
          e.token,
          e.amount,
          fromLabel?.type || "",
          toLabel?.type || "",
          (fromLabel?.label || "").replace(/,/g, " "),
          (toLabel?.label || "").replace(/,/g, " "),
        ].join(",");
      })
      .join("\n");

  const addressesCsv =
    "address,type,label,source,confidence,notes\n" +
    trace.nodes
      .map((n) =>
        [
          n.address,
          n.label.type || "",
          (n.label.label || "").replace(/,/g, " "),
          n.label.source || "",
          n.label.confidence || "",
          (n.label.notes || "").replace(/,/g, " "),
        ].join(","),
      )
      .join("\n");

  const timelineCsv =
    "time,severity,message,token,amount,counterparty,tx_hash,block\n" +
    relevantEvents
      .map((ev) =>
        [
          ev.time,
          ev.severity,
          (ev.message || "").replace(/,/g, " "),
          ev.token || "",
          ev.amount ?? "",
          ev.counterparty || "",
          ev.txHash || "",
          ev.block ?? "",
        ].join(","),
      )
      .join("\n");

  const requestMd = `# CEX Escalation Request\n\n## Case Metadata\n- Case ID: ${caseId}\n- Generated (UTC): ${packet.generatedAt}\n- Analyst: ${analyst}\n- Requested Exchange: ${cexName}\n\n## Summary\n- Victim Wallet: ${victim}\n- Suspect Wallet: ${suspect}\n- Trace Nodes: ${trace.nodeCount}\n- Trace Edges: ${trace.edgeCount}\n- Exposures: ${JSON.stringify(trace.exposures)}\n\n## Evidence Requests\n1. Preserve KYC/account-ownership records for all linked deposit/withdrawal entities.\n2. Preserve login metadata (IP/device/user agent/MFA events) around this incident.\n3. Preserve internal transfer and conversion logs tied to listed hashes.\n4. Preserve risk-engine or abuse alerts connected to these entities.\n\n## Notes\n${notes || "(none)"}\n`;

  const packetId = `pkt_${Date.now()}`;
  return {
    packetId,
    generatedAt: packet.generatedAt,
    summary: {
      caseId,
      cexName,
      nodeCount: trace.nodeCount,
      edgeCount: trace.edgeCount,
      exposures: trace.exposures,
      criticalEventCount: packet.criticalEvents.length,
    },
    artifacts: {
      "packet.json": JSON.stringify(packet, null, 2),
      "trace_edges.csv": traceCsv,
      "addresses.csv": addressesCsv,
      "timeline.csv": timelineCsv,
      "cex_request_template.md": requestMd,
    },
  };
}

export function normalizeRouteAddress(value: string): string {
  if (!isHexAddress(value)) {
    throw new Error("Address must be a valid 0x-prefixed 40-byte address");
  }
  return normalizeAddress(value);
}

export function normalizeSeeds(raw: unknown): string[] {
  if (Array.isArray(raw)) {
    return dedupe(
      raw
        .map((x) => String(x || "").trim())
        .filter((x) => isHexAddress(x))
        .map((x) => normalizeAddress(x)),
    );
  }
  if (typeof raw === "string") {
    return dedupe(
      raw
        .split(/[\n,]+/)
        .map((x) => x.trim())
        .filter((x) => isHexAddress(x))
        .map((x) => normalizeAddress(x)),
    );
  }
  return [];
}

export function topicForAddress(address: string): string {
  return addrTopic(address);
}
