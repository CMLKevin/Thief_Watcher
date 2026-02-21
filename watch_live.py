#!/usr/bin/env python3
"""CLI live watcher for the thief wallet case."""

from __future__ import annotations

import argparse
import json
import time
from watcher_engine import ThiefWatcher


def main() -> None:
    parser = argparse.ArgumentParser(description="Live watcher for thief wallet movement")
    parser.add_argument("--wallet", default="0xF5eF5Ac6B71373Be7af86eBD00Af44794CE3074E")
    parser.add_argument("--rpc", default="https://1rpc.io/matic")
    parser.add_argument("--interval", type=int, default=8)
    parser.add_argument("--lookback", type=int, default=250)
    args = parser.parse_args()

    watcher = ThiefWatcher(
        thief_wallet=args.wallet,
        rpc_url=args.rpc,
        poll_interval_sec=args.interval,
        lookback_blocks=args.lookback,
    )

    def on_event(event):
        sev = event.get("severity", "info").upper()
        print(f"[{sev}] {event.get('time')} {event.get('message')}")
        if event.get("tx_hash"):
            print("  tx:", event["tx_hash"])
        if event.get("direction"):
            print(
                f"  {event.get('direction')} {event.get('amount')} {event.get('token')}"
                f" | from {event.get('from')} to {event.get('to')}"
            )
        if event.get("counterparty_label"):
            print("  counterparty label:", json.dumps(event["counterparty_label"], ensure_ascii=False))

    watcher.add_event_callback(on_event)
    watcher.start()

    print("Live watcher started. Press Ctrl+C to stop.")
    try:
        while True:
            snap = watcher.snapshot()
            print(
                f"status block={snap.get('current_block')} nonce={snap.get('nonce')} "
                f"matic={snap.get('matic_balance')} usdc={snap.get('token_balances', {}).get('USDC')} "
                f"usdc.e={snap.get('token_balances', {}).get('USDC.e')}"
            )
            time.sleep(max(10, args.interval))
    except KeyboardInterrupt:
        print("Stopping watcher...")
    finally:
        watcher.stop()


if __name__ == "__main__":
    main()
