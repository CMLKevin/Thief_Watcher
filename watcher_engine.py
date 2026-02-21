#!/usr/bin/env python3
"""Advanced live monitoring and forensic toolkit for wallet tracing on Polygon."""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
DEFAULT_POLYGON_RPCS = [
    "https://1rpc.io/matic",
    "https://polygon.gateway.tenderly.co",
    "https://polygon.api.onfinality.io/public",
    "https://polygon-pokt.nodies.app",
    "https://rpc-mainnet.matic.quiknode.pro",
    "https://polygon-bor-rpc.publicnode.com",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _to_int(hex_value: str) -> int:
    return int(hex_value, 16)


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _addr_topic(address: str) -> str:
    return "0x" + "0" * 24 + address.lower().removeprefix("0x")


def _checksumless(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x")


@dataclass
class TokenConfig:
    symbol: str
    address: str
    decimals: int


class PolygonRPC:
    def __init__(self, rpc_url: str, timeout: int = 20, backup_urls: Optional[List[str]] = None):
        urls = [rpc_url.strip()]
        for candidate in (backup_urls or []):
            cand = str(candidate or "").strip()
            if cand and cand not in urls:
                urls.append(cand)
        self.rpc_urls = urls
        self._preferred_idx = 0
        self._lock = threading.Lock()
        self.timeout = timeout

    def call(self, method: str, params: List[Any]) -> Any:
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }
        ).encode("utf-8")
        with self._lock:
            start = self._preferred_idx

        errors: List[str] = []
        total = len(self.rpc_urls)
        for offset in range(total):
            idx = (start + offset) % total
            rpc_url = self.rpc_urls[idx]
            req = urllib.request.Request(
                rpc_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                if "error" in data:
                    errors.append(f"{rpc_url}: {data['error']}")
                    continue

                with self._lock:
                    self._preferred_idx = idx
                return data.get("result")
            except urllib.error.URLError as exc:
                errors.append(f"{rpc_url}: {exc}")
                continue

        raise RuntimeError("RPC request failed on all endpoints: " + " | ".join(errors[:4]))


class IntelStore:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.feed_dir = os.path.join(base_dir, "intel_feeds")
        self.custom_path = os.path.join(self.feed_dir, "custom_tags.json")
        os.makedirs(self.feed_dir, exist_ok=True)
        self._lock = threading.Lock()

        self.default_tags: Dict[str, Dict[str, Any]] = {
            # Case addresses
            "0x3addc290c324d45a8e4fa8ef129054d15a8590ef": {
                "label": "Victim Polymarket Proxy Wallet",
                "type": "victim",
                "source": "case",
                "notes": "Shared custody account",
            },
            "0xf5ef5ac6b71373be7af86ebd00af44794ce3074e": {
                "label": "Final Recipient (Case)",
                "type": "suspect",
                "source": "case",
                "notes": "Receives both relay settlements",
            },
            "0xf70da97812cb96acdf810712aa562db8dfa3dbef": {
                "label": "Relay Solver",
                "type": "bridge",
                "source": "protocol",
                "notes": "Relay infrastructure wallet",
            },
            "0xab45c5a4b0c941a2f231c04c3f49182e1a254052": {
                "label": "ProxyWalletFactory",
                "type": "protocol",
                "source": "verified_contract",
                "notes": "Polymarket proxy wallet system",
            },
            "0xd216153c06e857cd7f72665e0af1d7d82172f494": {
                "label": "RelayHub",
                "type": "protocol",
                "source": "verified_contract",
                "notes": "Meta-tx relay hub contract",
            },
            # DEX / aggregators on Polygon
            "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff": {
                "label": "QuickSwap V2 Router",
                "type": "dex",
                "source": "docs",
                "notes": "QuickSwap docs",
            },
            "0xe592427a0aece92de3edee1f18e0157c05861564": {
                "label": "Uniswap V3 SwapRouter",
                "type": "dex",
                "source": "deployed_contract",
                "notes": "Canonical Uniswap V3 router",
            },
            "0x1111111254eeb25477b68fb85ed929f73a960582": {
                "label": "1inch Aggregation Router",
                "type": "dex_aggregator",
                "source": "known",
                "notes": "1inch router",
            },
            "0xdef171fe48cf0115b1d80b88dc8eab59176fee57": {
                "label": "ParaSwap Augustus",
                "type": "dex_aggregator",
                "source": "known",
                "notes": "ParaSwap routing",
            },
            # Mixers / privacy (chain-agnostic detection targets)
            "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {
                "label": "Tornado Cash Proxy",
                "type": "mixer",
                "source": "known",
                "notes": "Flag for mixer exposure",
            },
            "0x722122df12d4e14e13ac3b6895a86e84145b6967": {
                "label": "Tornado Cash Relayer Registry",
                "type": "mixer",
                "source": "known",
                "notes": "Flag for mixer exposure",
            },
        }
        self.custom_tags: Dict[str, Dict[str, Any]] = {}
        self._load_custom()

    def _load_custom(self) -> None:
        if not os.path.isfile(self.custom_path):
            self.custom_tags = {}
            return
        try:
            with open(self.custom_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.custom_tags = {
                _checksumless(k): v for k, v in data.items() if isinstance(v, dict)
            }
        except Exception:
            self.custom_tags = {}

    def _save_custom(self) -> None:
        with open(self.custom_path, "w", encoding="utf-8") as f:
            json.dump(self.custom_tags, f, indent=2)

    def all_tags(self) -> Dict[str, Dict[str, Any]]:
        out = dict(self.default_tags)
        out.update(self.custom_tags)
        return out

    def get(self, address: str) -> Optional[Dict[str, Any]]:
        key = _checksumless(address)
        if key in self.custom_tags:
            return self.custom_tags[key]
        return self.default_tags.get(key)

    def upsert_custom(self, address: str, entry: Dict[str, Any]) -> None:
        with self._lock:
            key = _checksumless(address)
            normalized = {
                "label": entry.get("label") or "Custom tag",
                "type": entry.get("type") or "custom",
                "source": entry.get("source") or "manual",
                "notes": entry.get("notes") or "",
                "updated_at": _now_iso(),
            }
            self.custom_tags[key] = normalized
            self._save_custom()


class AddressLabeler:
    def __init__(self, intel: IntelStore):
        self.intel = intel
        self._cache: Dict[str, Dict[str, Any]] = {}

    def classify(self, address: str) -> Dict[str, Any]:
        key = _checksumless(address)
        if key in self._cache:
            return self._cache[key]

        tagged = self.intel.get(key)
        if tagged:
            out = dict(tagged)
            out.update({"address": key, "confidence": "high"})
            self._cache[key] = out
            return out

        out = {
            "address": key,
            "label": None,
            "type": "unknown",
            "source": "none",
            "notes": "",
            "is_contract": None,
            "tags": [],
            "confidence": "low",
        }

        url = f"https://polygon.blockscout.com/api/v2/addresses/{address}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if isinstance(data, dict):
                tags = []
                md = data.get("metadata") or {}
                for tag in md.get("tags") or []:
                    name = tag.get("name")
                    if name:
                        tags.append(name)

                name = data.get("name")
                is_contract = bool(data.get("is_contract"))
                joined = " ".join([name or "", *tags]).lower()

                inferred_type = "contract" if is_contract else "eoa"
                if any(x in joined for x in ["relay", "bridge", "cctp", "across", "stargate", "hop"]):
                    inferred_type = "bridge"
                if any(x in joined for x in ["swap", "router", "quickswap", "uniswap", "1inch", "paraswap", "dex"]):
                    inferred_type = "dex"
                if any(x in joined for x in ["binance", "coinbase", "kraken", "okx", "bybit", "kucoin", "mexc", "exchange"]):
                    inferred_type = "cex"
                if any(x in joined for x in ["tornado", "mixer", "railgun", "sinbad"]):
                    inferred_type = "mixer"

                out.update(
                    {
                        "label": name,
                        "is_contract": is_contract,
                        "tags": tags,
                        "type": inferred_type,
                        "source": "blockscout",
                        "confidence": "medium",
                    }
                )
        except Exception:
            pass

        self._cache[key] = out
        return out


class ThiefWatcher:
    def __init__(
        self,
        thief_wallet: str,
        rpc_url: str = "https://1rpc.io/matic",
        backup_rpc_urls: Optional[List[str]] = None,
        poll_interval_sec: int = 8,
        lookback_blocks: int = 250,
        state_file: str = "watch_state.json",
        webhook_url: Optional[str] = None,
    ):
        self.thief_wallet = thief_wallet
        backups = backup_rpc_urls or [u for u in DEFAULT_POLYGON_RPCS if u != rpc_url]
        self.rpc = PolygonRPC(rpc_url, backup_urls=backups)
        self.poll_interval_sec = poll_interval_sec
        self.lookback_blocks = lookback_blocks
        self.state_file = state_file
        self.webhook_url = webhook_url

        self.base_dir = os.path.dirname(os.path.abspath(state_file)) or "."
        self.intel = IntelStore(self.base_dir)
        self.labeler = AddressLabeler(self.intel)

        self.tokens = [
            TokenConfig("USDC", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", 6),
            TokenConfig("USDC.e", "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", 6),
        ]

        self._callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        self.state: Dict[str, Any] = {
            "running": False,
            "started_at": None,
            "last_poll_at": None,
            "last_error": None,
            "rpc_url": rpc_url,
            "rpc_failover_pool": [rpc_url, *[u for u in backups if u != rpc_url]],
            "thief_wallet": thief_wallet,
            "watching": [thief_wallet],
            "last_checked_block": None,
            "current_block": None,
            "nonce": None,
            "matic_balance": 0.0,
            "token_balances": {"USDC": 0.0, "USDC.e": 0.0},
            "events": [],
            "event_count": 0,
            "webhook_url": webhook_url,
        }
        self._load_state()

    # ---------- state ----------
    def _load_state(self) -> None:
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            for k in ("last_checked_block", "events", "event_count", "webhook_url"):
                if k in saved:
                    self.state[k] = saved[k]
            if saved.get("webhook_url"):
                self.webhook_url = saved["webhook_url"]
        except FileNotFoundError:
            return
        except Exception:
            return

    def _save_state(self) -> None:
        payload = {
            "last_checked_block": self.state.get("last_checked_block"),
            "events": self.state.get("events", [])[:700],
            "event_count": self.state.get("event_count", 0),
            "webhook_url": self.webhook_url,
            "saved_at": _now_iso(),
        }
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    # ---------- rpc utils ----------
    def _rpc_block_number(self) -> int:
        return _to_int(self.rpc.call("eth_blockNumber", []))

    def _rpc_nonce(self, address: str) -> int:
        return _to_int(self.rpc.call("eth_getTransactionCount", [address, "latest"]))

    def _rpc_matic_balance(self, address: str) -> float:
        wei = _to_int(self.rpc.call("eth_getBalance", [address, "latest"]))
        return wei / 1e18

    def _rpc_token_balance(self, token: TokenConfig, address: str) -> float:
        data = "0x70a08231" + ("0" * 24) + _checksumless(address).removeprefix("0x")
        raw = self.rpc.call("eth_call", [{"to": token.address, "data": data}, "latest"])
        return _to_int(raw) / (10 ** token.decimals)

    def _query_logs_chunked(
        self,
        token_address: str,
        topics: List[Optional[str]],
        from_block: int,
        to_block: int,
        max_range: int = 10000,
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        window = max(250, max_range)
        cur = from_block
        while cur <= to_block:
            end = min(cur + window - 1, to_block)
            params = [
                {
                    "fromBlock": hex(cur),
                    "toBlock": hex(end),
                    "address": token_address,
                    "topics": topics,
                }
            ]
            try:
                logs = self.rpc.call("eth_getLogs", params)
                out.extend(logs)
                cur = end + 1
            except RuntimeError as exc:
                msg = str(exc).lower()
                range_limited = (
                    "maximum block range" in msg
                    or "limited to 0 - " in msg
                    or "exceed maximum block range" in msg
                )
                if range_limited and window > 250:
                    window = max(250, window // 2)
                    continue
                raise
        return out

    # ---------- notifications ----------
    def add_event_callback(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        self._callbacks.append(cb)

    def set_webhook(self, url: Optional[str]) -> None:
        self.webhook_url = url or None
        with self._lock:
            self.state["webhook_url"] = self.webhook_url
        self._save_state()

    def _notify_webhook(self, event: Dict[str, Any]) -> None:
        if not self.webhook_url:
            return
        if event.get("severity") not in {"critical", "warning", "error"}:
            return
        try:
            body = json.dumps(
                {
                    "text": f"[{event.get('severity','INFO').upper()}] {event.get('message')}",
                    "event": event,
                    "timestamp": _now_iso(),
                    "service": "thief_watcher",
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8):
                pass
        except Exception:
            pass

    def _emit_event(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self.state["events"].insert(0, event)
            self.state["events"] = self.state["events"][:700]
            self.state["event_count"] += 1
        self._save_state()
        self._notify_webhook(event)
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception:
                continue

    # ---------- profile + intelligence ----------
    def add_custom_tag(self, address: str, label: str, kind: str, notes: str = "", source: str = "manual") -> None:
        self.intel.upsert_custom(
            address,
            {
                "label": label,
                "type": kind,
                "notes": notes,
                "source": source,
            },
        )
        self.labeler._cache.pop(_checksumless(address), None)

    def list_tags(self) -> Dict[str, Dict[str, Any]]:
        return self.intel.all_tags()

    def _polymarket_profile_hint(self, address: str) -> Dict[str, Any]:
        out = {"title": None, "canonical": None, "username": None, "isAnon": None}
        try:
            with urllib.request.urlopen(f"https://polymarket.com/profile/{address}", timeout=10) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
            def pick(prefix: str) -> Optional[str]:
                i = html.find(prefix)
                if i == -1:
                    return None
                j = html.find('"', i + len(prefix))
                return html[i + len(prefix):j]

            title_s = "<title"
            ti = html.find("<title")
            if ti != -1:
                ts = html.find(">", ti)
                te = html.find("</title>", ts)
                if ts != -1 and te != -1:
                    out["title"] = html[ts + 1 : te].strip()

            out["canonical"] = pick('<link rel="canonical" href="')
            out["username"] = pick('"username":"')
            anon = pick('"isAnon":')
            if anon is not None:
                out["isAnon"] = anon.startswith("true")
        except Exception:
            pass
        return out

    def address_profile(self, address: str, recent_window_blocks: int = 50000) -> Dict[str, Any]:
        address = _checksumless(address)
        current = self._rpc_block_number()
        start = max(0, current - recent_window_blocks)

        label = self.labeler.classify(address)
        balances = {
            "MATIC": round(self._rpc_matic_balance(address), 8),
            "nonce": self._rpc_nonce(address),
            "USDC": round(self._rpc_token_balance(self.tokens[0], address), 6),
            "USDC.e": round(self._rpc_token_balance(self.tokens[1], address), 6),
        }

        recents = []
        for token in self.tokens:
            out_logs = self._query_logs_chunked(
                token.address,
                [TRANSFER_TOPIC, _addr_topic(address)],
                start,
                current,
            )
            in_logs = self._query_logs_chunked(
                token.address,
                [TRANSFER_TOPIC, None, _addr_topic(address)],
                start,
                current,
            )
            for lg in out_logs:
                to_addr = "0x" + lg["topics"][2][-40:]
                recents.append(
                    {
                        "direction": "out",
                        "token": token.symbol,
                        "amount": round(_to_int(lg["data"]) / (10 ** token.decimals), 6),
                        "tx_hash": lg["transactionHash"],
                        "block": _to_int(lg["blockNumber"]),
                        "counterparty": to_addr,
                        "counterparty_label": self.labeler.classify(to_addr),
                    }
                )
            for lg in in_logs:
                from_addr = "0x" + lg["topics"][1][-40:]
                recents.append(
                    {
                        "direction": "in",
                        "token": token.symbol,
                        "amount": round(_to_int(lg["data"]) / (10 ** token.decimals), 6),
                        "tx_hash": lg["transactionHash"],
                        "block": _to_int(lg["blockNumber"]),
                        "counterparty": from_addr,
                        "counterparty_label": self.labeler.classify(from_addr),
                    }
                )

        recents.sort(key=lambda x: x["block"], reverse=True)

        return {
            "address": address,
            "label": label,
            "balances": balances,
            "recent_window_blocks": recent_window_blocks,
            "recent_transfers": recents[:200],
            "profile_hint": self._polymarket_profile_hint(address),
            "queried_at": _now_iso(),
        }

    def build_trace_graph(
        self,
        seeds: List[str],
        hops: int = 2,
        from_block: Optional[int] = None,
        to_block: Optional[int] = None,
        max_edges: int = 1500,
    ) -> Dict[str, Any]:
        current = self._rpc_block_number()
        start = from_block if from_block is not None else max(0, current - 200000)
        end = to_block if to_block is not None else current

        queue: List[Tuple[str, int]] = [(_checksumless(s), 0) for s in seeds]
        visited: Set[str] = set(_checksumless(s) for s in seeds)

        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []

        while queue and len(edges) < max_edges:
            address, depth = queue.pop(0)
            if address not in nodes:
                nodes[address] = {
                    "address": address,
                    "label": self.labeler.classify(address),
                }

            if depth >= hops:
                continue

            for token in self.tokens:
                out_logs = self._query_logs_chunked(
                    token.address,
                    [TRANSFER_TOPIC, _addr_topic(address)],
                    start,
                    end,
                )
                out_logs = out_logs[:500]

                for lg in out_logs:
                    to_addr = "0x" + lg["topics"][2][-40:]
                    to_addr = _checksumless(to_addr)
                    amount = _to_int(lg["data"]) / (10 ** token.decimals)

                    edge_id = f"{lg['transactionHash']}:{lg['logIndex']}:{token.symbol}"
                    edge = {
                        "id": edge_id,
                        "from": address,
                        "to": to_addr,
                        "token": token.symbol,
                        "amount": round(amount, 6),
                        "block": _to_int(lg["blockNumber"]),
                        "tx_hash": lg["transactionHash"],
                        "hop": depth + 1,
                    }
                    edges.append(edge)

                    if to_addr not in nodes:
                        nodes[to_addr] = {
                            "address": to_addr,
                            "label": self.labeler.classify(to_addr),
                        }

                    if to_addr not in visited:
                        visited.add(to_addr)
                        queue.append((to_addr, depth + 1))

                    if len(edges) >= max_edges:
                        break
                if len(edges) >= max_edges:
                    break

        risk_buckets = {"cex": 0, "dex": 0, "mixer": 0, "bridge": 0, "suspect": 0, "unknown": 0}
        for n in nodes.values():
            t = (n.get("label") or {}).get("type") or "unknown"
            risk_buckets[t] = risk_buckets.get(t, 0) + 1

        return {
            "seeds": [_checksumless(s) for s in seeds],
            "hops": hops,
            "from_block": start,
            "to_block": end,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": list(nodes.values()),
            "edges": edges,
            "risk_buckets": risk_buckets,
            "generated_at": _now_iso(),
        }

    def recovery_playbook(self) -> Dict[str, Any]:
        snap = self.snapshot()
        critical = [e for e in snap.get("events", []) if e.get("severity") == "critical"]
        return {
            "generated_at": _now_iso(),
            "objective": "Identify insider and maximize recovery probability",
            "immediate_actions": [
                "Preserve exchangeability: alert when suspect wallet receives MATIC or emits any outgoing transfer.",
                "Issue data preservation request to Polymarket for auth/session logs around incident window.",
                "Issue data preservation request to Relay with request IDs and settlement tx hashes.",
                "Move any remaining shared assets to multisig with separate signers and per-user auth.",
                "Prepare legal packet with tx graph and recipient addresses for subpoena-ready handoff.",
            ],
            "watch_signals": {
                "critical_events_seen": len(critical),
                "current_nonce": snap.get("nonce"),
                "current_matic": snap.get("matic_balance"),
                "usdc_balance": snap.get("token_balances", {}).get("USDC"),
            },
        }

    # ---------- live watcher ----------
    def _health_checks(self) -> None:
        nonce = self._rpc_nonce(self.thief_wallet)
        matic = self._rpc_matic_balance(self.thief_wallet)

        with self._lock:
            old_nonce = self.state.get("nonce")
            old_matic = _safe_float(self.state.get("matic_balance"), 0.0)
            self.state["nonce"] = nonce
            self.state["matic_balance"] = round(matic, 8)

        if old_nonce is not None and nonce > old_nonce:
            self._emit_event(
                {
                    "id": f"nonce:{nonce}",
                    "time": _now_iso(),
                    "severity": "critical",
                    "message": "Watched wallet nonce increased (outgoing tx likely)",
                    "wallet": self.thief_wallet,
                    "nonce_old": old_nonce,
                    "nonce_new": nonce,
                }
            )

        if matic > old_matic + 1e-12:
            self._emit_event(
                {
                    "id": f"matic:{time.time_ns()}",
                    "time": _now_iso(),
                    "severity": "warning",
                    "message": "Watched wallet received MATIC gas funding",
                    "wallet": self.thief_wallet,
                    "matic_old": round(old_matic, 8),
                    "matic_new": round(matic, 8),
                }
            )

        balances: Dict[str, float] = {}
        for token in self.tokens:
            balances[token.symbol] = round(self._rpc_token_balance(token, self.thief_wallet), 6)
        with self._lock:
            self.state["token_balances"] = balances

    def _process_window(self, from_block: int, to_block: int) -> None:
        wallet = self.thief_wallet
        for token in self.tokens:
            out_logs = self._query_logs_chunked(
                token.address,
                [TRANSFER_TOPIC, _addr_topic(wallet)],
                from_block,
                to_block,
            )
            in_logs = self._query_logs_chunked(
                token.address,
                [TRANSFER_TOPIC, None, _addr_topic(wallet)],
                from_block,
                to_block,
            )

            for lg in out_logs:
                to_addr = _checksumless("0x" + lg["topics"][2][-40:])
                amount_raw = _to_int(lg["data"])
                amount = round(amount_raw / (10 ** token.decimals), 6)
                lbl = self.labeler.classify(to_addr)
                event = {
                    "id": f"{lg['transactionHash']}:{lg['logIndex']}:out:{token.symbol}",
                    "time": _now_iso(),
                    "severity": "critical",
                    "message": f"Outgoing {token.symbol} from watched wallet",
                    "wallet": wallet,
                    "direction": "out",
                    "token": token.symbol,
                    "amount": amount,
                    "amount_raw": amount_raw,
                    "from": wallet,
                    "to": to_addr,
                    "counterparty": to_addr,
                    "counterparty_label": lbl,
                    "tx_hash": lg["transactionHash"],
                    "block": _to_int(lg["blockNumber"]),
                }
                with self._lock:
                    seen = {e["id"] for e in self.state["events"]}
                if event["id"] not in seen:
                    self._emit_event(event)

            for lg in in_logs:
                from_addr = _checksumless("0x" + lg["topics"][1][-40:])
                amount_raw = _to_int(lg["data"])
                amount = round(amount_raw / (10 ** token.decimals), 6)
                lbl = self.labeler.classify(from_addr)
                sev = "warning" if lbl.get("type") in {"bridge", "mixer", "cex", "dex"} else "info"
                event = {
                    "id": f"{lg['transactionHash']}:{lg['logIndex']}:in:{token.symbol}",
                    "time": _now_iso(),
                    "severity": sev,
                    "message": f"Incoming {token.symbol} to watched wallet",
                    "wallet": wallet,
                    "direction": "in",
                    "token": token.symbol,
                    "amount": amount,
                    "amount_raw": amount_raw,
                    "from": from_addr,
                    "to": wallet,
                    "counterparty": from_addr,
                    "counterparty_label": lbl,
                    "tx_hash": lg["transactionHash"],
                    "block": _to_int(lg["blockNumber"]),
                }
                with self._lock:
                    seen = {e["id"] for e in self.state["events"]}
                if event["id"] not in seen:
                    self._emit_event(event)

    def _tick(self) -> None:
        current = self._rpc_block_number()
        with self._lock:
            last = self.state.get("last_checked_block")
            if last is None:
                last = max(0, current - self.lookback_blocks)
                self.state["last_checked_block"] = last
            self.state["current_block"] = current

        if current > last:
            start = last + 1
            max_window = 1200
            while start <= current:
                end = min(start + max_window - 1, current)
                self._process_window(start, end)
                start = end + 1
            with self._lock:
                self.state["last_checked_block"] = current

        self._health_checks()

    def _run(self) -> None:
        with self._lock:
            self.state["running"] = True
            self.state["started_at"] = _now_iso()

        while self._running:
            try:
                self._tick()
                with self._lock:
                    self.state["last_poll_at"] = _now_iso()
                    self.state["last_error"] = None
                self._save_state()
            except Exception as exc:
                err = str(exc)
                with self._lock:
                    self.state["last_error"] = err
                self._emit_event(
                    {
                        "id": f"err:{time.time_ns()}",
                        "time": _now_iso(),
                        "severity": "error",
                        "message": "Watcher polling error",
                        "error": err,
                    }
                )
            time.sleep(self.poll_interval_sec)

        with self._lock:
            self.state["running"] = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self.state))

    def manual_tick(self) -> Dict[str, Any]:
        if self._running:
            raise RuntimeError("Watcher is already running; stop it before manual tick")
        self._tick()
        with self._lock:
            self.state["last_poll_at"] = _now_iso()
            self.state["last_error"] = None
        self._save_state()
        return self.snapshot()
