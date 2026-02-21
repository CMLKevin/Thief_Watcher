import { DEFAULT_RPC_POOL, TRANSFER_TOPIC } from "@/lib/constants";
import { addrTopic, fromTopicAddress, toBigInt, toInt } from "@/lib/utils";

export interface RpcLog {
  address: string;
  topics: string[];
  data: string;
  blockNumber: string;
  transactionHash: string;
  logIndex: string;
}

interface RpcPayload {
  jsonrpc: "2.0";
  id: number;
  method: string;
  params: unknown[];
}

interface RpcResponse<T> {
  result?: T;
  error?: { code?: number; message?: string };
}

async function postRpc<T>(url: string, payload: RpcPayload, timeoutMs = 15000): Promise<RpcResponse<T>> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
      cache: "no-store",
    });

    if (!response.ok) {
      return { error: { code: response.status, message: `HTTP ${response.status}` } };
    }

    return (await response.json()) as RpcResponse<T>;
  } catch (error) {
    return { error: { message: String(error) } };
  } finally {
    clearTimeout(timer);
  }
}

export async function rpcCall<T>(
  method: string,
  params: unknown[],
  rpcPool: readonly string[] = DEFAULT_RPC_POOL,
): Promise<T> {
  if (!rpcPool.length) {
    throw new Error("RPC pool is empty");
  }
  const errors: string[] = [];
  const start = preferredRpcIndex % rpcPool.length;

  for (let offset = 0; offset < rpcPool.length; offset += 1) {
    const idx = (start + offset) % rpcPool.length;
    const rpcUrl = rpcPool[idx];
    const payload: RpcPayload = {
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    };
    const res = await postRpc<T>(rpcUrl, payload, 4500);
    if (!res.error && res.result !== undefined) {
      preferredRpcIndex = idx;
      return res.result;
    }
    errors.push(`${rpcUrl}: ${res.error?.message || "unknown"}`);
  }

  throw new Error(`RPC failed on all endpoints: ${errors.slice(0, 4).join(" | ")}`);
}

let preferredRpcIndex = 0;

export async function blockNumber(rpcPool?: readonly string[]): Promise<number> {
  const hex = await rpcCall<string>("eth_blockNumber", [], rpcPool);
  return toInt(hex);
}

export async function txCount(address: string, rpcPool?: readonly string[]): Promise<number> {
  const hex = await rpcCall<string>("eth_getTransactionCount", [address, "latest"], rpcPool);
  return toInt(hex);
}

export async function maticBalance(address: string, rpcPool?: readonly string[]): Promise<number> {
  const hex = await rpcCall<string>("eth_getBalance", [address, "latest"], rpcPool);
  return Number(toBigInt(hex)) / 1e18;
}

export async function tokenBalance(
  tokenAddress: string,
  address: string,
  decimals: number,
  rpcPool?: readonly string[],
): Promise<number> {
  const data = `0x70a08231${"0".repeat(24)}${address.toLowerCase().replace(/^0x/, "")}`;
  const raw = await rpcCall<string>("eth_call", [{ to: tokenAddress, data }, "latest"], rpcPool);
  return Number(toBigInt(raw)) / 10 ** decimals;
}

export async function getLogs(
  tokenAddress: string,
  topics: (string | null)[],
  fromBlock: number,
  toBlock: number,
  rpcPool?: readonly string[],
): Promise<RpcLog[]> {
  let window = 10000;
  let current = fromBlock;
  const out: RpcLog[] = [];

  while (current <= toBlock) {
    const end = Math.min(current + window - 1, toBlock);
    try {
      const logs = await rpcCall<RpcLog[] | null>(
        "eth_getLogs",
        [
          {
            fromBlock: `0x${current.toString(16)}`,
            toBlock: `0x${end.toString(16)}`,
            address: tokenAddress,
            topics,
          },
        ],
        rpcPool,
      );
      out.push(...(logs || []));
      current = end + 1;
    } catch (error) {
      const msg = String(error).toLowerCase();
      const rangeLimited =
        msg.includes("maximum block range") ||
        msg.includes("limited to 0 -") ||
        msg.includes("exceed maximum block range");
      if (rangeLimited && window > 250) {
        window = Math.max(250, Math.floor(window / 2));
        continue;
      }
      throw error;
    }
  }

  return out;
}

export interface TransferScanItem {
  direction: "in" | "out";
  token: string;
  amountRaw: bigint;
  amount: number;
  txHash: string;
  block: number;
  counterparty: string;
  logIndex: number;
}

interface BlockscoutTransferItem {
  block_number?: number;
  transaction_hash?: string;
  total?: { value?: string; decimals?: string };
  from?: { hash?: string };
  to?: { hash?: string };
  token?: { address?: string; symbol?: string };
}

async function fallbackFromBlockscout(
  wallet: string,
  token: { symbol: string; address: string; decimals: number },
  fromBlock: number,
  toBlock: number,
): Promise<TransferScanItem[]> {
  const out: TransferScanItem[] = [];
  let url = `https://polygon.blockscout.com/api/v2/addresses/${wallet}/token-transfers`;
  let page = 0;

  while (url && page < 5) {
    page += 1;
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) break;
    const data = (await res.json()) as {
      items?: BlockscoutTransferItem[];
      next_page_params?: Record<string, unknown> | null;
    };
    const items = data.items || [];
    if (!items.length) break;

    for (const item of items) {
      const block = Number(item.block_number || 0);
      if (!Number.isFinite(block) || block < fromBlock || block > toBlock) continue;

      const txHash = String(item.transaction_hash || "");
      if (!txHash) continue;

      const from = normalizeHex(item.from?.hash || "");
      const to = normalizeHex(item.to?.hash || "");
      const direction = from === wallet.toLowerCase() ? "out" : to === wallet.toLowerCase() ? "in" : null;
      if (!direction) continue;

      const tokenAddress = normalizeHex(item.token?.address || "");
      const tokenSymbol = String(item.token?.symbol || "").toUpperCase();
      const fallbackMatch =
        tokenAddress === token.address.toLowerCase() ||
        tokenSymbol === token.symbol.toUpperCase() ||
        (token.symbol === "USDC.e" && !tokenAddress);
      if (!fallbackMatch) continue;

      const value = BigInt(item.total?.value || "0");
      const decimals = Number(item.total?.decimals || token.decimals);
      const amount = Number(value) / 10 ** decimals;

      out.push({
        direction,
        token: token.symbol,
        amountRaw: value,
        amount: Number.isFinite(amount) ? amount : 0,
        txHash,
        block,
        counterparty: direction === "out" ? normalizeHex(to) : normalizeHex(from),
        logIndex: 0,
      });
    }

    if (!data.next_page_params) break;
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(data.next_page_params)) {
      if (value !== null && value !== undefined) {
        params.set(key, String(value));
      }
    }
    url = `https://polygon.blockscout.com/api/v2/addresses/${wallet}/token-transfers?${params.toString()}`;
  }

  return out;
}

function normalizeHex(value: string): string {
  if (!value) return "";
  return `0x${value.toLowerCase().replace(/^0x/, "")}`;
}

export async function scanTokenTransfers(
  wallet: string,
  token: { symbol: string; address: string; decimals: number },
  fromBlock: number,
  toBlock: number,
  rpcPool?: readonly string[],
): Promise<TransferScanItem[]> {
  const outgoing = await getLogs(
    token.address,
    [TRANSFER_TOPIC, addrTopic(wallet)],
    fromBlock,
    toBlock,
    rpcPool,
  );

  const incoming = await getLogs(
    token.address,
    [TRANSFER_TOPIC, null, addrTopic(wallet)],
    fromBlock,
    toBlock,
    rpcPool,
  );

  const rows: TransferScanItem[] = [];
  for (const log of outgoing) {
    const amountRaw = toBigInt(log.data);
    rows.push({
      direction: "out",
      token: token.symbol,
      amountRaw,
      amount: Number(amountRaw) / 10 ** token.decimals,
      txHash: log.transactionHash,
      block: toInt(log.blockNumber),
      counterparty: fromTopicAddress(log.topics[2]),
      logIndex: toInt(log.logIndex),
    });
  }

  for (const log of incoming) {
    const amountRaw = toBigInt(log.data);
    rows.push({
      direction: "in",
      token: token.symbol,
      amountRaw,
      amount: Number(amountRaw) / 10 ** token.decimals,
      txHash: log.transactionHash,
      block: toInt(log.blockNumber),
      counterparty: fromTopicAddress(log.topics[1]),
      logIndex: toInt(log.logIndex),
    });
  }

  if (!rows.length) {
    try {
      const fallbackRows = await fallbackFromBlockscout(
        wallet.toLowerCase(),
        token,
        fromBlock,
        toBlock,
      );
      rows.push(...fallbackRows);
    } catch {
      // ignore fallback failures
    }
  }

  return rows.sort((a, b) => b.block - a.block || b.logIndex - a.logIndex);
}
