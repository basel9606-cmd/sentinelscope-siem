# SentinelScope SIEM

A portfolio-ready Security Information and Event Management (SIEM) demonstration built for SOC analyst roles. It ingests sample endpoint, identity, and network events, normalizes them, applies detection rules, and presents triage-ready alerts in a browser dashboard.

## What it demonstrates

- Log normalization across Windows, VPN, and firewall sources
- Detection engineering: brute-force, impossible travel, privilege escalation, and C2 beaconing
- Risk scoring with MITRE ATT&CK technique mapping
- Alert triage workflow: investigate, assign, resolve, or close alerts
- SOC-focused metrics: alert volume, mean time to acknowledge, severity distribution, and active incidents

## Run locally

No external dependencies are required.

```powershell
python -m http.server 8000
```

Open `http://localhost:8000` in a browser. To regenerate the demonstration events and detection output:

```powershell
python scripts/generate_demo_data.py
```

## Receive real alerts

The local API can safely receive normalized webhook alerts using an ingest key. See [the production integration guide](docs/production-integration.md), the [sample alert payload](samples/ingest-alert.json), and the [Wazuh connector](integrations/wazuh/README.md). GitHub Pages is the dashboard host only; production ingestion must run on a server or cloud function.

## Project structure

```text
index.html                  # Interactive SOC dashboard
assets/css/styles.css       # Dashboard styling
assets/js/app.js            # Filtering and alert-triage interactions
data/events.json            # Normalized source events
data/alerts.json            # Detection findings consumed by the dashboard
scripts/generate_demo_data.py # Standard-library event generator + rule engine
```

## CV wording

**SentinelScope SIEM | Personal Project** — Built an interactive SIEM prototype that normalizes multi-source security logs and detects brute-force authentication, impossible travel, privilege escalation, and command-and-control activity. Implemented risk scoring, MITRE ATT&CK mapping, and an analyst-facing triage dashboard using JavaScript and Python.

> This is a training and portfolio project. The telemetry is synthetic and not intended for production monitoring.
