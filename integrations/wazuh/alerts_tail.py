#!/usr/bin/env python3
"""Continuously forward new Wazuh alerts.json records to SentinelScope.

The collector persists the byte offset only after a successful delivery. If a
delivery is repeated after a crash, SentinelScope deduplicates it by alert ID.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError

from sentinelscope import normalise, post_alerts


DEFAULT_ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
DEFAULT_STATE_FILE = "/var/ossec/queue/sentinelscope-alerts.offset"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stream Wazuh alerts.json into SentinelScope")
    parser.add_argument("--file", default=os.environ.get("WAZUH_ALERTS_FILE", DEFAULT_ALERTS_FILE))
    parser.add_argument("--state-file", default=os.environ.get("SENTINELSCOPE_STATE_FILE", DEFAULT_STATE_FILE))
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--min-level", type=int, default=int(os.environ.get("SENTINELSCOPE_MIN_LEVEL", "3")))
    parser.add_argument("--from-start", action="store_true", help="Read the existing file on first run")
    parser.add_argument("--once", action="store_true", help="Process currently available records, then exit")
    return parser.parse_args()


def file_identity(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {"device": stat.st_dev, "inode": stat.st_ino}


def load_state(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save_state(path: Path, identity: dict[str, int], offset: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps({**identity, "offset": offset}), encoding="utf-8")
    temporary.replace(path)


def starting_offset(path: Path, state: dict, from_start: bool) -> int:
    identity = file_identity(path)
    same_file = state.get("device") == identity["device"] and state.get("inode") == identity["inode"]
    if same_file:
        return min(max(int(state.get("offset", 0)), 0), path.stat().st_size)
    if state:
        return 0  # Rotation: consume the replacement file from its beginning.
    return 0 if from_start else path.stat().st_size


def rule_level(alert: dict) -> int:
    try:
        return int((alert.get("rule") or {}).get("level", 0))
    except (TypeError, ValueError):
        return 0


def deliver_with_retry(alerts: list[dict], once: bool) -> bool:
    delay = 2
    while True:
        try:
            result = post_alerts(alerts)
            print(f"Delivered {result.get('accepted', len(alerts))} Wazuh alert(s) to SentinelScope", flush=True)
            return True
        except (HTTPError, URLError, RuntimeError, TimeoutError, OSError) as error:
            print(f"Delivery failed; retrying in {delay}s: {error}", file=sys.stderr, flush=True)
            if once:
                return False
            time.sleep(delay)
            delay = min(delay * 2, 30)


def run(args: argparse.Namespace) -> int:
    alerts_path = Path(args.file)
    state_path = Path(args.state_file)
    if args.batch_size < 1 or args.batch_size > 100:
        raise ValueError("--batch-size must be between 1 and 100")

    while not alerts_path.exists():
        if args.once:
            print(f"Wazuh alerts file not found: {alerts_path}", file=sys.stderr)
            return 2
        print(f"Waiting for Wazuh alerts file: {alerts_path}", flush=True)
        time.sleep(max(args.poll_interval, 0.2))

    state = load_state(state_path)
    identity = file_identity(alerts_path)
    offset = starting_offset(alerts_path, state, args.from_start)
    print(f"Watching {alerts_path} from byte {offset}", flush=True)

    while True:
        current_identity = file_identity(alerts_path)
        if current_identity != identity or alerts_path.stat().st_size < offset:
            identity = current_identity
            offset = 0

        batch: list[dict] = []
        next_offset = offset
        with alerts_path.open("rb") as source:
            source.seek(offset)
            while len(batch) < args.batch_size:
                line = source.readline()
                if not line:
                    break
                next_offset = source.tell()
                try:
                    item = json.loads(line.decode("utf-8"))
                    if isinstance(item, dict) and rule_level(item) >= args.min_level:
                        batch.append(normalise(item))
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    print(f"Skipped malformed Wazuh record ending at byte {next_offset}: {error}", file=sys.stderr)

        if batch and not deliver_with_retry(batch, args.once):
            return 1
        if next_offset != offset:
            offset = next_offset
            save_state(state_path, identity, offset)
            continue
        if args.once:
            return 0
        time.sleep(max(args.poll_interval, 0.2))


def main() -> int:
    try:
        return run(parse_args())
    except (OSError, ValueError) as error:
        print(f"Collector error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
