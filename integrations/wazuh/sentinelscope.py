#!/usr/bin/env python3
"""Wazuh custom integration: forward one Wazuh alert to SentinelScope.

Configure Wazuh to invoke this script with the alert JSON file path as $1.
Set SENTINELSCOPE_INGEST_URL and SENTINELSCOPE_INGEST_KEY in the service
environment. Never place secrets in this file.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SEVERITY_BY_LEVEL = ((12, "critical"), (8, "high"), (4, "medium"), (0, "low"))


def severity_for(level: object) -> str:
    try:
        numeric_level = int(level)
    except (TypeError, ValueError):
        numeric_level = 0
    return next(severity for threshold, severity in SEVERITY_BY_LEVEL if numeric_level >= threshold)


def normalise(wazuh_alert: dict) -> dict:
    rule = wazuh_alert.get("rule") or {}
    agent = wazuh_alert.get("agent") or {}
    data = wazuh_alert.get("data") or {}
    entity = agent.get("name") or data.get("srcuser") or data.get("srcip") or "unknown-asset"
    mitre = rule.get("mitre") or {}
    techniques = mitre.get("technique") if isinstance(mitre, dict) else None
    technique = techniques[0] if isinstance(techniques, list) and techniques else ""
    return {
        "id": f"wazuh-{wazuh_alert.get('id', '')}",
        "rule_name": rule.get("description") or "Wazuh detection",
        "severity": severity_for(rule.get("level")),
        "mitre_technique": technique,
        "entity": str(entity),
        "source": "Wazuh",
        "observed_at": wazuh_alert.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "raw_event": wazuh_alert,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: sentinelscope.py /path/to/wazuh-alert.json", file=sys.stderr)
        return 2
    ingest_url = os.environ.get("SENTINELSCOPE_INGEST_URL", "").rstrip("/")
    ingest_key = os.environ.get("SENTINELSCOPE_INGEST_KEY", "")
    if not ingest_url or not ingest_key:
        print("SENTINELSCOPE_INGEST_URL and SENTINELSCOPE_INGEST_KEY are required", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as source:
        payload = {"alerts": [normalise(json.load(source))]}
    request = Request(
        f"{ingest_url}/api/ingest",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Ingest-Key": ingest_key},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            response.read()
        return 0
    except (HTTPError, URLError) as error:
        print(f"SentinelScope delivery failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
