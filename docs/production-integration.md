# Production ingestion guide

GitHub Pages hosts the SentinelScope interface only. Run `server.py` behind a reverse proxy, container platform, or cloud function to receive external telemetry. Do not expose a Supabase service-role key or an ingest key in browser code.

## Local proof of concept

```powershell
$env:SENTINELSCOPE_INGEST_KEY = "replace-with-a-long-random-secret"
python scripts/init_database.py
python server.py
```

Check the service:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
```

Send a test alert:

```powershell
$headers = @{ "X-Ingest-Key" = $env:SENTINELSCOPE_INGEST_KEY }
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/ingest -Headers $headers -ContentType "application/json" -InFile samples/ingest-alert.json
```

Read ingested alerts:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/alerts
```

## Security requirements before customer use

- Terminate TLS at a reverse proxy and restrict `/api/ingest` to known source IPs or VPN.
- Store `SENTINELSCOPE_INGEST_KEY` in a secret manager and rotate it. Never commit it.
- Validate vendor signatures where provided (for example, a signed webhook) in addition to the ingest key.
- Forward normalized events from Wazuh, Elastic, Defender, firewall, or identity providers using the sample schema.
- Send production data to Postgres/Supabase through a server-side worker. Browser clients must use only the publishable key and RLS policies.
- Add rate limiting, alert retention, backup, monitoring, and incident-response ownership before selling the service.
