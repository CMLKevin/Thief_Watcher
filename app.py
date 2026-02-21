#!/usr/bin/env python3
"""Web dashboard and API for advanced wallet tracing operations."""

from __future__ import annotations

import csv
import hashlib
import json
import mimetypes
import os
import re
import zipfile
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from watcher_engine import ThiefWatcher

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
EXPORTS_DIR = os.path.join(BASE_DIR, "exports")
MAX_EVENT_LIMIT = 700
DEFAULT_VICTIM_WALLET = "0x3ADdC290C324d45A8E4fa8Ef129054d15a8590eF"

os.makedirs(EXPORTS_DIR, exist_ok=True)

WATCHER = ThiefWatcher(
    thief_wallet="0xF5eF5Ac6B71373Be7af86eBD00Af44794CE3074E",
    rpc_url="https://1rpc.io/matic",
    poll_interval_sec=8,
    lookback_blocks=250,
    state_file=os.path.join(BASE_DIR, "watch_state.json"),
)
WATCHER.start()


def _clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(minimum, min(maximum, parsed))


def _is_hex_address(value: str) -> bool:
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", value or ""))


def _normalize_address(value: str) -> str:
    return "0x" + value.lower().removeprefix("0x")


def _json_error(message: str, code: int = 400) -> Tuple[Dict[str, Any], int]:
    return {"ok": False, "error": message}, code


def _infer_type_counts(tags: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    by_type: Dict[str, int] = {}
    for details in tags.values():
        tag_type = str(details.get("type") or "unknown").lower()
        by_type[tag_type] = by_type.get(tag_type, 0) + 1
    return {"total_tags": len(tags), "types": by_type}


def _safe_slug(raw: str, fallback: str = "case") -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", (raw or "").strip())
    slug = slug.strip("-._")
    if not slug:
        return fallback
    return slug[:120]


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256_path(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class Handler(BaseHTTPRequestHandler):
    server_version = "ThiefWatcher/3.0"

    def _send_json(self, payload: Dict[str, Any], code: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str, ctype: Optional[str] = None) -> None:
        if not os.path.isfile(path):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        with open(path, "rb") as f:
            data = f.read()
        if ctype is None:
            guessed, _ = mimetypes.guess_type(path)
            ctype = guessed or "application/octet-stream"

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
            if isinstance(payload, dict):
                return payload
        except Exception:
            pass
        raise ValueError("Request body must be JSON object")

    def _filtered_events(self, params: Dict[str, List[str]]) -> Dict[str, Any]:
        limit = _clamp_int(params.get("limit", [150])[0], 1, MAX_EVENT_LIMIT, 150)
        severity_filter = {
            s.strip().lower()
            for s in ",".join(params.get("severity", [])).split(",")
            if s.strip()
        }
        direction_filter = {
            s.strip().lower()
            for s in ",".join(params.get("direction", [])).split(",")
            if s.strip()
        }
        token_filter = {
            s.strip().upper()
            for s in ",".join(params.get("token", [])).split(",")
            if s.strip()
        }
        needle = str(params.get("q", [""])[0] or "").strip().lower()

        status = WATCHER.snapshot()
        all_events = status.get("events", [])
        selected = []
        for event in all_events:
            sev = str(event.get("severity") or "").lower()
            direction = str(event.get("direction") or "").lower()
            token = str(event.get("token") or "").upper()
            if severity_filter and sev not in severity_filter:
                continue
            if direction_filter and direction not in direction_filter:
                continue
            if token_filter and token not in token_filter:
                continue

            if needle:
                text_blob = " ".join(
                    [
                        str(event.get("message") or ""),
                        str(event.get("counterparty") or ""),
                        str(event.get("tx_hash") or ""),
                    ]
                ).lower()
                if needle not in text_blob:
                    continue

            selected.append(event)
            if len(selected) >= limit:
                break

        return {
            "ok": True,
            "events": selected,
            "total": status.get("event_count", 0),
            "returned": len(selected),
            "filters": {
                "severity": sorted(severity_filter),
                "direction": sorted(direction_filter),
                "token": sorted(token_filter),
                "q": needle,
                "limit": limit,
            },
        }

    def _trace(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        seeds_in = payload.get("seeds")
        seeds: List[str] = []
        if isinstance(seeds_in, str):
            seeds = [s.strip() for s in seeds_in.split(",") if s.strip()]
        elif isinstance(seeds_in, list):
            seeds = [str(s).strip() for s in seeds_in if str(s).strip()]

        cleaned = []
        seen = set()
        for seed in seeds:
            if not _is_hex_address(seed):
                continue
            normalized = _normalize_address(seed)
            if normalized not in seen:
                cleaned.append(normalized)
                seen.add(normalized)

        if not cleaned:
            raise ValueError("Provide at least one valid seed address")

        hops = _clamp_int(payload.get("hops", 2), 1, 5, 2)
        max_edges = _clamp_int(payload.get("max_edges", 900), 50, 2000, 900)
        from_block: Optional[int] = None
        to_block: Optional[int] = None
        if payload.get("from_block") not in (None, "", "null"):
            from_block = _clamp_int(payload.get("from_block"), 0, 2**63 - 1, 0)
        if payload.get("to_block") not in (None, "", "null"):
            to_block = _clamp_int(payload.get("to_block"), 0, 2**63 - 1, 0)

        result = WATCHER.build_trace_graph(
            seeds=cleaned,
            hops=hops,
            from_block=from_block,
            to_block=to_block,
            max_edges=max_edges,
        )
        exposures = {"cex": 0, "dex": 0, "mixer": 0, "bridge": 0}
        for node in result.get("nodes", []):
            node_type = str((node.get("label") or {}).get("type") or "").lower()
            if node_type in exposures:
                exposures[node_type] += 1
        result["exposures"] = exposures
        return {"ok": True, "graph": result}

    def _tags_list(self, params: Dict[str, List[str]]) -> Dict[str, Any]:
        q = str(params.get("q", [""])[0] or "").strip().lower()
        type_q = str(params.get("type", [""])[0] or "").strip().lower()

        tags = WATCHER.list_tags()
        out = []
        for addr, details in tags.items():
            entry = {"address": addr}
            entry.update(details)
            if q:
                hay = " ".join(
                    [addr, str(details.get("label") or ""), str(details.get("notes") or "")]
                ).lower()
                if q not in hay:
                    continue
            if type_q and str(details.get("type") or "").lower() != type_q:
                continue
            out.append(entry)
        out.sort(key=lambda x: (str(x.get("type") or ""), str(x.get("label") or ""), x["address"]))
        return {"ok": True, "count": len(out), "tags": out}

    def _serve_static(self, path: str) -> bool:
        if path == "/":
            self._send_file(os.path.join(STATIC_DIR, "index.html"), "text/html; charset=utf-8")
            return True
        if not path.startswith("/static/"):
            return False

        rel = os.path.normpath(path.removeprefix("/static/"))
        if rel.startswith(".."):
            self.send_error(HTTPStatus.FORBIDDEN)
            return True

        full_path = os.path.join(STATIC_DIR, rel)
        ctype = "text/plain; charset=utf-8"
        if full_path.endswith(".html"):
            ctype = "text/html; charset=utf-8"
        elif full_path.endswith(".css"):
            ctype = "text/css; charset=utf-8"
        elif full_path.endswith(".js"):
            ctype = "application/javascript; charset=utf-8"
        elif full_path.endswith(".json"):
            ctype = "application/json; charset=utf-8"
        self._send_file(full_path, ctype)
        return True

    def _serve_exports(self, path: str) -> bool:
        if not path.startswith("/exports/"):
            return False
        rel = os.path.normpath(path.removeprefix("/exports/"))
        if rel.startswith(".."):
            self.send_error(HTTPStatus.FORBIDDEN)
            return True

        full_path = os.path.join(EXPORTS_DIR, rel)
        self._send_file(full_path)
        return True

    def _list_packets(self) -> Dict[str, Any]:
        packets: List[Dict[str, Any]] = []
        if not os.path.isdir(EXPORTS_DIR):
            return {"ok": True, "count": 0, "packets": []}

        for name in sorted(os.listdir(EXPORTS_DIR), reverse=True):
            path = os.path.join(EXPORTS_DIR, name)
            if not os.path.isdir(path):
                continue
            files = []
            for file_name in sorted(os.listdir(path)):
                fp = os.path.join(path, file_name)
                if os.path.isfile(fp):
                    files.append(
                        {
                            "name": file_name,
                            "size": os.path.getsize(fp),
                            "url": f"/exports/{name}/{file_name}",
                        }
                    )
            packets.append(
                {
                    "packet_id": name,
                    "path": path,
                    "created_at": datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
                    .replace(microsecond=0)
                    .isoformat(),
                    "files": files,
                }
            )
        return {"ok": True, "count": len(packets), "packets": packets}

    def _build_escalation_packet(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        case_id = str(payload.get("case_id") or "polymarket-insider-drain").strip()
        case_slug = _safe_slug(case_id)
        analyst = str(payload.get("analyst") or "Unknown analyst").strip()[:120]
        cex_name = str(payload.get("cex_name") or "Unknown CEX").strip()[:120]
        notes = str(payload.get("notes") or "").strip()[:3000]

        suspect = str(payload.get("suspect_wallet") or WATCHER.snapshot().get("thief_wallet") or "").strip()
        victim = str(payload.get("victim_wallet") or DEFAULT_VICTIM_WALLET).strip()
        if not _is_hex_address(suspect):
            raise ValueError("Field `suspect_wallet` must be a 0x-prefixed 40-byte address")
        if not _is_hex_address(victim):
            raise ValueError("Field `victim_wallet` must be a 0x-prefixed 40-byte address")
        suspect = _normalize_address(suspect)
        victim = _normalize_address(victim)

        seeds_input = payload.get("seeds")
        seeds: List[str] = []
        if isinstance(seeds_input, list):
            for raw in seeds_input:
                candidate = str(raw).strip()
                if _is_hex_address(candidate):
                    seeds.append(_normalize_address(candidate))
        elif isinstance(seeds_input, str):
            for raw in re.split(r"[,\n]+", seeds_input):
                candidate = raw.strip()
                if _is_hex_address(candidate):
                    seeds.append(_normalize_address(candidate))

        if victim not in seeds:
            seeds.append(victim)
        if suspect not in seeds:
            seeds.append(suspect)

        uniq = []
        seen = set()
        for s in seeds:
            if s not in seen:
                uniq.append(s)
                seen.add(s)
        seeds = uniq

        window = _clamp_int(payload.get("window", 75000), 500, 250000, 75000)
        hops = _clamp_int(payload.get("hops", 2), 1, 5, 2)
        max_edges = _clamp_int(payload.get("max_edges", 1200), 100, 3000, 1200)

        from_block: Optional[int] = None
        to_block: Optional[int] = None
        if payload.get("from_block") not in (None, "", "null"):
            from_block = _clamp_int(payload.get("from_block"), 0, 2**63 - 1, 0)
        if payload.get("to_block") not in (None, "", "null"):
            to_block = _clamp_int(payload.get("to_block"), 0, 2**63 - 1, 0)

        status = WATCHER.snapshot()
        suspect_profile = WATCHER.address_profile(suspect, recent_window_blocks=window)
        victim_profile = WATCHER.address_profile(victim, recent_window_blocks=window)
        trace = WATCHER.build_trace_graph(
            seeds=seeds,
            hops=hops,
            from_block=from_block,
            to_block=to_block,
            max_edges=max_edges,
        )

        exposures = {"cex": 0, "dex": 0, "mixer": 0, "bridge": 0, "suspect": 0, "unknown": 0}
        for node in trace.get("nodes", []):
            ntype = str((node.get("label") or {}).get("type") or "unknown").lower()
            exposures[ntype] = exposures.get(ntype, 0) + 1
        trace["exposures"] = exposures

        trace_hashes = {str(e.get("tx_hash") or "") for e in trace.get("edges", []) if e.get("tx_hash")}
        node_set = {str(n.get("address") or "") for n in trace.get("nodes", [])}

        relevant_events: List[Dict[str, Any]] = []
        for event in status.get("events", []):
            tx_hash = str(event.get("tx_hash") or "")
            cp = str(event.get("counterparty") or "")
            wallet = str(event.get("wallet") or "")
            if tx_hash and tx_hash in trace_hashes:
                relevant_events.append(event)
                continue
            if cp and cp in node_set:
                relevant_events.append(event)
                continue
            if wallet in {suspect, victim}:
                relevant_events.append(event)

        critical_events = [e for e in relevant_events if str(e.get("severity") or "").lower() in {"critical", "error", "warning"}]

        packet = {
            "packet_type": "cex-escalation",
            "packet_version": "1.0",
            "generated_at": _now_iso(),
            "case": {
                "case_id": case_id,
                "analyst": analyst,
                "cex_name": cex_name,
                "notes": notes,
                "objective": "Identify account holder(s) and freeze suspect funds where possible",
            },
            "wallets": {
                "victim_wallet": victim,
                "suspect_wallet": suspect,
                "seed_wallets": seeds,
            },
            "status_snapshot": {
                "running": status.get("running"),
                "current_block": status.get("current_block"),
                "event_count": status.get("event_count"),
                "nonce": status.get("nonce"),
                "token_balances": status.get("token_balances"),
            },
            "trace_summary": {
                "hops": trace.get("hops"),
                "from_block": trace.get("from_block"),
                "to_block": trace.get("to_block"),
                "node_count": trace.get("node_count"),
                "edge_count": trace.get("edge_count"),
                "exposures": exposures,
            },
            "suspect_profile": suspect_profile,
            "victim_profile": victim_profile,
            "trace": trace,
            "relevant_events": relevant_events[:500],
            "critical_events": critical_events[:300],
            "recommended_preservation_requests": [
                "Preserve KYC, login IPs, device fingerprints, and withdrawal destinations tied to suspect deposit addresses.",
                "Preserve internal transfer records and chain monitoring alerts for all listed tx hashes.",
                "Preserve account communications and security event logs during incident window.",
            ],
        }

        packet_id = f"{_utc_stamp()}_{case_slug}"
        packet_dir = os.path.join(EXPORTS_DIR, packet_id)
        os.makedirs(packet_dir, exist_ok=True)

        packet_json_path = os.path.join(packet_dir, "packet.json")
        trace_csv_path = os.path.join(packet_dir, "trace_edges.csv")
        addr_csv_path = os.path.join(packet_dir, "addresses.csv")
        timeline_csv_path = os.path.join(packet_dir, "timeline.csv")
        request_md_path = os.path.join(packet_dir, "cex_request_template.md")

        with open(packet_json_path, "w", encoding="utf-8") as f:
            json.dump(packet, f, indent=2)

        with open(trace_csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "hop",
                    "block",
                    "tx_hash",
                    "from",
                    "to",
                    "token",
                    "amount",
                    "from_type",
                    "to_type",
                    "from_label",
                    "to_label",
                ],
            )
            writer.writeheader()
            for edge in trace.get("edges", []):
                from_label = WATCHER.labeler.classify(edge.get("from"))
                to_label = WATCHER.labeler.classify(edge.get("to"))
                writer.writerow(
                    {
                        "hop": edge.get("hop"),
                        "block": edge.get("block"),
                        "tx_hash": edge.get("tx_hash"),
                        "from": edge.get("from"),
                        "to": edge.get("to"),
                        "token": edge.get("token"),
                        "amount": edge.get("amount"),
                        "from_type": from_label.get("type"),
                        "to_type": to_label.get("type"),
                        "from_label": from_label.get("label"),
                        "to_label": to_label.get("label"),
                    }
                )

        with open(addr_csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["address", "type", "label", "source", "confidence", "notes"],
            )
            writer.writeheader()
            for node in trace.get("nodes", []):
                lbl = node.get("label") or {}
                writer.writerow(
                    {
                        "address": node.get("address"),
                        "type": lbl.get("type"),
                        "label": lbl.get("label"),
                        "source": lbl.get("source"),
                        "confidence": lbl.get("confidence"),
                        "notes": lbl.get("notes"),
                    }
                )

        with open(timeline_csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["time", "severity", "message", "token", "amount", "counterparty", "tx_hash", "block"],
            )
            writer.writeheader()
            for event in relevant_events[:500]:
                writer.writerow(
                    {
                        "time": event.get("time"),
                        "severity": event.get("severity"),
                        "message": event.get("message"),
                        "token": event.get("token"),
                        "amount": event.get("amount"),
                        "counterparty": event.get("counterparty"),
                        "tx_hash": event.get("tx_hash"),
                        "block": event.get("block"),
                    }
                )

        md_template = f"""# CEX Escalation Request

## Case Metadata
- Case ID: `{case_id}`
- Generated (UTC): `{packet['generated_at']}`
- Analyst: `{analyst}`
- Requested Exchange: `{cex_name}`

## Incident Summary
- Victim Wallet: `{victim}`
- Suspect Wallet: `{suspect}`
- Trace Node Count: `{trace.get('node_count')}`
- Trace Edge Count: `{trace.get('edge_count')}`
- Exposure Buckets: `{json.dumps(exposures)}`

## Requested Preservation Scope
1. Account ownership/KYC data for addresses or internal deposit accounts associated with listed transaction hashes.
2. Login metadata (IP, user agent, device IDs, MFA events) around the incident window.
3. Internal movement logs (sub-account transfers, conversion records, withdrawal records) associated with suspect pathways.
4. Abuse/risk-system alerts connected to these entities.

## On-Chain Evidence References
- Exported CSV: `trace_edges.csv`
- Timeline: `timeline.csv`
- Address Intel: `addresses.csv`
- Full Packet: `packet.json`

## Notes
{notes or '(none provided)'}
"""
        with open(request_md_path, "w", encoding="utf-8") as f:
            f.write(md_template)

        manifest = {
            "generated_at": _now_iso(),
            "packet_id": packet_id,
            "files": {},
        }
        for filename in ["packet.json", "trace_edges.csv", "addresses.csv", "timeline.csv", "cex_request_template.md"]:
            fp = os.path.join(packet_dir, filename)
            manifest["files"][filename] = {
                "size": os.path.getsize(fp),
                "sha256": _sha256_path(fp),
            }

        manifest_path = os.path.join(packet_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        zip_path = os.path.join(packet_dir, "cex_escalation_bundle.zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for filename in [
                "packet.json",
                "trace_edges.csv",
                "addresses.csv",
                "timeline.csv",
                "cex_request_template.md",
                "manifest.json",
            ]:
                zf.write(os.path.join(packet_dir, filename), arcname=filename)

        urls = {
            "packet_json": f"/exports/{packet_id}/packet.json",
            "trace_csv": f"/exports/{packet_id}/trace_edges.csv",
            "addresses_csv": f"/exports/{packet_id}/addresses.csv",
            "timeline_csv": f"/exports/{packet_id}/timeline.csv",
            "request_md": f"/exports/{packet_id}/cex_request_template.md",
            "manifest": f"/exports/{packet_id}/manifest.json",
            "bundle_zip": f"/exports/{packet_id}/cex_escalation_bundle.zip",
        }

        return {
            "ok": True,
            "packet_id": packet_id,
            "generated_at": packet["generated_at"],
            "case_id": case_id,
            "trace_summary": packet["trace_summary"],
            "critical_event_count": len(critical_events),
            "urls": urls,
        }

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        try:
            if self._serve_static(path):
                return
            if self._serve_exports(path):
                return

            if path == "/api/health":
                running = WATCHER.snapshot().get("running")
                return self._send_json({"ok": True, "service": "thief_watcher", "running": running})

            if path == "/api/status":
                status = WATCHER.snapshot()
                tags = WATCHER.list_tags()
                status["intel_summary"] = _infer_type_counts(tags)
                status["watched_wallet_label"] = WATCHER.labeler.classify(status.get("thief_wallet"))
                return self._send_json({"ok": True, "status": status})

            if path == "/api/events":
                return self._send_json(self._filtered_events(params))

            if path == "/api/tags":
                return self._send_json(self._tags_list(params))

            if path == "/api/profile":
                address = str(params.get("address", [""])[0] or "").strip()
                if not _is_hex_address(address):
                    payload, code = _json_error("Query param `address` must be a 0x-prefixed 40-byte address")
                    return self._send_json(payload, code)
                window = _clamp_int(params.get("window", [50000])[0], 500, 200000, 50000)
                prof = WATCHER.address_profile(_normalize_address(address), recent_window_blocks=window)
                return self._send_json({"ok": True, "profile": prof})

            if path == "/api/playbook":
                return self._send_json({"ok": True, "playbook": WATCHER.recovery_playbook()})

            if path == "/api/state":
                status = WATCHER.snapshot()
                return self._send_json({"ok": True, "state": status, "tags": WATCHER.list_tags()})

            if path == "/api/escalation-packets":
                return self._send_json(self._list_packets())

            if path == "/api/control/start":
                WATCHER.start()
                return self._send_json({"ok": True, "message": "watcher started"})

            if path == "/api/control/stop":
                WATCHER.stop()
                return self._send_json({"ok": True, "message": "watcher stopped"})

            self.send_error(HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            payload, code = _json_error(str(exc), 400)
            self._send_json(payload, code)
        except Exception as exc:
            payload, code = _json_error(f"Unhandled server error: {exc}", 500)
            self._send_json(payload, code)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            payload = self._read_json_body()

            if path == "/api/control/start":
                WATCHER.start()
                return self._send_json({"ok": True, "message": "watcher started"})

            if path == "/api/control/stop":
                WATCHER.stop()
                return self._send_json({"ok": True, "message": "watcher stopped"})

            if path == "/api/control/tick":
                snap = WATCHER.manual_tick()
                return self._send_json({"ok": True, "message": "manual tick completed", "status": snap})

            if path == "/api/tags":
                address = str(payload.get("address") or "").strip()
                if not _is_hex_address(address):
                    raise ValueError("Field `address` must be a 0x-prefixed 40-byte address")
                label = str(payload.get("label") or "").strip()
                if not label:
                    raise ValueError("Field `label` is required")
                kind = str(payload.get("type") or "custom").strip().lower()[:64]
                notes = str(payload.get("notes") or "").strip()[:1000]
                source = str(payload.get("source") or "manual").strip()[:100]
                WATCHER.add_custom_tag(_normalize_address(address), label, kind, notes=notes, source=source)
                return self._send_json(
                    {
                        "ok": True,
                        "message": "tag added",
                        "address": _normalize_address(address),
                        "label": label,
                        "type": kind,
                    }
                )

            if path == "/api/profile":
                address = str(payload.get("address") or "").strip()
                if not _is_hex_address(address):
                    raise ValueError("Field `address` must be a 0x-prefixed 40-byte address")
                window = _clamp_int(payload.get("window", 50000), 500, 200000, 50000)
                prof = WATCHER.address_profile(_normalize_address(address), recent_window_blocks=window)
                return self._send_json({"ok": True, "profile": prof})

            if path == "/api/trace":
                return self._send_json(self._trace(payload))

            if path == "/api/webhook":
                raw_url = str(payload.get("url") or "").strip()
                if raw_url and not (raw_url.startswith("http://") or raw_url.startswith("https://")):
                    raise ValueError("Webhook URL must start with http:// or https://")
                WATCHER.set_webhook(raw_url or None)
                return self._send_json({"ok": True, "webhook_url": WATCHER.webhook_url})

            if path == "/api/escalation-packet":
                return self._send_json(self._build_escalation_packet(payload))

            self.send_error(HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            error_payload, code = _json_error(str(exc), 400)
            self._send_json(error_payload, code)
        except Exception as exc:
            error_payload, code = _json_error(f"Unhandled server error: {exc}", 500)
            self._send_json(error_payload, code)

    def log_message(self, fmt: str, *args) -> None:
        return


def run(host: str = "127.0.0.1", port: int = 8787) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Thief watcher webapp running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        WATCHER.stop()
        server.server_close()


if __name__ == "__main__":
    run()
