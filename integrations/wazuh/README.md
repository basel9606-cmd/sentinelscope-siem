# Wazuh to SentinelScope connector

This custom integration maps Wazuh alerts to SentinelScope's normalized ingest schema and posts them to the protected local API.

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
