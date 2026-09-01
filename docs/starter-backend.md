# SentinelScope Starter backend

The Starter edition stores SOC workflow records in D1 (Cloudflare SQLite):

- `users`: analyst, admin, and viewer identities.
- `cases`: incident lifecycle, severity, owner, and SLA-oriented next step.
- `alerts`: normalized detection findings.
- `case_alerts`: many-to-many relationship between incidents and findings.
- `case_notes`: analyst investigation notes.
- `audit_log`: traceable changes for customer reporting.

## First API slice

- `GET /api/cases?status=investigating`
- `POST /api/cases`
- `PATCH /api/cases/:id`
- `POST /api/cases/:id/notes`
- `POST /api/cases/:id/alerts`

Every mutation should write an `audit_log` record. Authentication and role checks are added before exposing the API to customers.
