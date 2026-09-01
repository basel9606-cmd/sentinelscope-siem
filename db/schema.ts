/** SentinelScope Starter — D1/SQLite data model. */
export const schemaStatements = [
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'viewer')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
    status TEXT NOT NULL CHECK(status IN ('new', 'investigating', 'contained', 'resolved', 'closed')) DEFAULT 'new',
    owner_id TEXT REFERENCES users(id),
    summary TEXT,
    next_step TEXT,
    opened_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    mitre_technique TEXT,
    entity TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    raw_event_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS case_alerts (
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (case_id, alert_id)
  )`,
  `CREATE TABLE IF NOT EXISTS case_notes (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    author_id TEXT REFERENCES users(id),
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    actor_id TEXT REFERENCES users(id),
    case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    detail_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE INDEX IF NOT EXISTS idx_cases_status_updated ON cases(status, updated_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_cases_owner_status ON cases(owner_id, status)`,
  `CREATE INDEX IF NOT EXISTS idx_alerts_entity_observed ON alerts(entity, observed_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_case_notes_case_created ON case_notes(case_id, created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_log_case_created ON audit_log(case_id, created_at DESC)`
];
