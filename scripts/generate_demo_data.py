"""Create synthetic SIEM events and demonstrate simple detection rules.

This intentionally uses only the Python standard library so recruiters can run it
without setup. It illustrates the collection -> normalization -> detection flow.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVENTS = ROOT / "data" / "events.json"
ALERTS = ROOT / "data" / "alerts.json"


def detect(events: list[dict]) -> list[dict]:
    alerts: list[dict] = []
    failed_by_user: dict[str, int] = {}
    for event in events:
        if event["action"] == "logon_failure":
            failed_by_user[event.get("user", "unknown")] = failed_by_user.get(event.get("user", "unknown"), 0) + 1
        if event["action"] == "process_create" and "-enc" in event.get("process", ""):
            alerts.append({"rule": "Encoded PowerShell", "severity": "medium", "mitre": "T1059.001", "entity": event["host"]})
        if event["source"] == "azure-ad" and event.get("previous_location") and event["location"] != event["previous_location"]:
            alerts.append({"rule": "Impossible Travel", "severity": "critical", "mitre": "T1078", "entity": event["user"]})
    for user, count in failed_by_user.items():
        if count >= 5:
            alerts.append({"rule": "Brute Force Authentication", "severity": "high", "mitre": "T1110", "entity": user})
    return alerts


def main() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    events = [
        {"timestamp": (now - timedelta(minutes=2)).isoformat(), "source": "windows-security", "host": "WIN-DC01", "event_id": 4625, "user": "svc-backup", "action": "logon_failure", "source_ip": "10.10.14.37", "severity": "medium"},
        {"timestamp": (now - timedelta(minutes=1)).isoformat(), "source": "endpoint-edr", "host": "WS-FIN-023", "action": "process_create", "process": "powershell.exe -enc SQBFAFgA", "user": "n.levy", "severity": "high"},
        {"timestamp": now.isoformat(), "source": "azure-ad", "user": "n.levy@contoso.io", "action": "sign_in", "location": "Singapore", "previous_location": "Tel Aviv", "severity": "high"},
    ]
    EVENTS.write_text(json.dumps(events, indent=2), encoding="utf-8")
    ALERTS.write_text(json.dumps(detect(events), indent=2), encoding="utf-8")
    print(f"Wrote {len(events)} normalized events and {len(detect(events))} alerts.")


if __name__ == "__main__":
    main()
