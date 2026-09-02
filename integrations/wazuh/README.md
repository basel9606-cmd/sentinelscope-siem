# Wazuh to SentinelScope connector

The recommended collector follows Wazuh's real `alerts.json` file, maps each record to SentinelScope's normalized ingest schema, and posts batches to the protected API. It saves a checkpoint only after successful delivery, survives API outages, and handles Wazuh log rotation.

## Continuous alerts.json collector (recommended)

Run these steps on the Wazuh manager. Do not place the ingest key in the repository or command history.

1. Copy `alerts_tail.py` and `sentinelscope.py` to `/opt/sentinelscope-wazuh/`.
2. Copy `sentinelscope-collector.service.example` to `/etc/systemd/system/sentinelscope-collector.service`.
3. Create `/etc/sentinelscope/wazuh-collector.env` with permissions `0600`:

```ini
SENTINELSCOPE_INGEST_URL=https://your-sentinelscope-api.example
SENTINELSCOPE_INGEST_KEY=replace-with-a-long-random-secret
SENTINELSCOPE_MIN_LEVEL=3
```

4. Enable the collector:

```bash
sudo chown -R root:wazuh /opt/sentinelscope-wazuh
sudo chmod 750 /opt/sentinelscope-wazuh/*.py
sudo chown root:root /etc/sentinelscope/wazuh-collector.env
sudo chmod 600 /etc/sentinelscope/wazuh-collector.env
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelscope-collector
sudo systemctl status sentinelscope-collector --no-pager
```

The first service start follows new records only. To import the current `alerts.json` once before enabling the service, run:

```bash
set -a
source /etc/sentinelscope/wazuh-collector.env
set +a
python3 /opt/sentinelscope-wazuh/alerts_tail.py --from-start --once
```

Verify delivery without exposing the ingest key:

```bash
journalctl -u sentinelscope-collector -n 50 --no-pager
```

SentinelScope polls its own `/api/alerts` endpoint every 10 seconds and updates the alert table automatically.

## Per-alert custom integration (alternative)

The existing `sentinelscope.py` entry point can also be invoked by Wazuh once per alert. Use this method only if you do not run the continuous collector; running both creates duplicate delivery attempts (the API still deduplicates by Wazuh alert ID).

## Install on the Wazuh manager

1. Copy `sentinelscope.py` to `/var/ossec/integrations/sentinelscope` and make it executable.
2. Set `SENTINELSCOPE_INGEST_URL` and `SENTINELSCOPE_INGEST_KEY` in the Wazuh manager service environment or a protected wrapper script. Use an HTTPS URL reachable only from the manager.
3. Add this integration in `/var/ossec/etc/ossec.conf` and restart the Wazuh manager:

```xml
<integration>
  <name>sentinelscope</name>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

## Test before enabling

Run the SentinelScope API locally, then execute:

```bash
export SENTINELSCOPE_INGEST_URL="http://127.0.0.1:8000"
export SENTINELSCOPE_INGEST_KEY="your-long-random-secret"
python3 integrations/wazuh/sentinelscope.py samples/wazuh-alert.json
```

Use a TLS-protected endpoint in production. Do not forward full raw events outside the organization until retention, privacy, and customer approval are in place.
