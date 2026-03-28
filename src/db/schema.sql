-- FlowScript Cloud — D1 Database Schema
-- Run: wrangler d1 execute flowscript-cloud-db --local --file=src/db/schema.sql

-- Organizations (tenants)
CREATE TABLE IF NOT EXISTS organizations (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  slug        TEXT NOT NULL UNIQUE,
  plan        TEXT NOT NULL DEFAULT 'free',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

-- Teams within organizations
CREATE TABLE IF NOT EXISTS teams (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES organizations(id),
  name        TEXT NOT NULL,
  slug        TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  UNIQUE(org_id, slug)
);

-- Namespaces = agent identity within an org
CREATE TABLE IF NOT EXISTS namespaces (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES organizations(id),
  team_id     TEXT REFERENCES teams(id),
  owner       TEXT NOT NULL,
  agent       TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  last_event  TEXT,
  event_count INTEGER NOT NULL DEFAULT 0,
  chain_head_seq  INTEGER,
  chain_head_hash TEXT,
  chain_head_ts   TEXT,
  UNIQUE(org_id, agent)
);
CREATE INDEX IF NOT EXISTS idx_namespaces_org ON namespaces(org_id);
CREATE INDEX IF NOT EXISTS idx_namespaces_team ON namespaces(team_id);

-- API Keys
CREATE TABLE IF NOT EXISTS api_keys (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL REFERENCES organizations(id),
  role        TEXT NOT NULL,
  scope_type  TEXT NOT NULL,
  scope_id    TEXT NOT NULL,
  label       TEXT,
  created_by  TEXT,                          -- key_id of the key that created this one (audit trail)
  created_at  TEXT NOT NULL,
  last_used   TEXT,
  revoked_at  TEXT,
  expires_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_keys_org ON api_keys(org_id);

-- Events (the core audit payload)
CREATE TABLE IF NOT EXISTS events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  namespace_id  TEXT NOT NULL REFERENCES namespaces(id),
  seq           INTEGER NOT NULL,
  event_ts      TEXT NOT NULL,
  event_type    TEXT NOT NULL,
  session_id    TEXT,
  trace_id      TEXT,
  adapter       TEXT,
  hash          TEXT NOT NULL,
  prev_hash     TEXT NOT NULL,
  payload       TEXT NOT NULL,
  received_at   TEXT NOT NULL,
  UNIQUE(namespace_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_events_ns ON events(namespace_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(namespace_id, event_type);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(namespace_id, session_id);
CREATE INDEX IF NOT EXISTS idx_events_trace ON events(namespace_id, trace_id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(namespace_id, event_ts);

-- Witness attestations
CREATE TABLE IF NOT EXISTS witnesses (
  id                TEXT PRIMARY KEY,
  namespace_id      TEXT NOT NULL REFERENCES namespaces(id),
  chain_head_seq    INTEGER NOT NULL,
  chain_head_hash   TEXT NOT NULL,
  chain_head_ts     TEXT NOT NULL,
  chain_tail_seq    INTEGER NOT NULL,
  chain_tail_hash   TEXT NOT NULL,
  chain_tail_ts     TEXT NOT NULL,
  total_events      INTEGER NOT NULL,
  witnessed_at      TEXT NOT NULL,
  signature         TEXT,
  UNIQUE(namespace_id, chain_head_seq)
);
CREATE INDEX IF NOT EXISTS idx_witnesses_ns ON witnesses(namespace_id);

-- Alerts (chain breaks, anomalies)
CREATE TABLE IF NOT EXISTS alerts (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL REFERENCES organizations(id),
  namespace_id  TEXT REFERENCES namespaces(id),
  type          TEXT NOT NULL,
  severity      TEXT NOT NULL,
  message       TEXT NOT NULL,
  data          TEXT,
  created_at    TEXT NOT NULL,
  resolved_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_org ON alerts(org_id, created_at);
