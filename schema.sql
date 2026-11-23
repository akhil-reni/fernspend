PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS orgs (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  slug          TEXT NOT NULL UNIQUE,
  plan          TEXT NOT NULL DEFAULT 'starter',
  seats         INTEGER NOT NULL DEFAULT 5,
  sso_domain    TEXT,
  sso_provider  TEXT,
  invite_domain TEXT,
  internal_notes TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS memberships (
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  role       TEXT NOT NULL DEFAULT 'member',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, org_id)
);

CREATE TABLE IF NOT EXISTS expenses (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id       TEXT NOT NULL REFERENCES users(id),
  merchant      TEXT NOT NULL,
  category      TEXT NOT NULL,
  amount_cents  INTEGER NOT NULL,
  currency      TEXT NOT NULL DEFAULT 'USD',
  status        TEXT NOT NULL DEFAULT 'pending',
  note          TEXT,
  spent_at      TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_expenses_org ON expenses(org_id, spent_at);

CREATE TABLE IF NOT EXISTS webhooks (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  url          TEXT NOT NULL,
  events       TEXT NOT NULL DEFAULT 'expense.created',
  headers_json TEXT NOT NULL DEFAULT '{}',
  active       INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id               TEXT PRIMARY KEY,
  webhook_id       TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event            TEXT NOT NULL,
  status_code      INTEGER,
  content_type     TEXT,
  response_snippet TEXT,
  error            TEXT,
  duration_ms      INTEGER,
  created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS integration_secrets (
  id         TEXT PRIMARY KEY,
  org_id     TEXT,
  provider   TEXT NOT NULL,
  label      TEXT NOT NULL,
  value      TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS wallets (
  user_id       TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  balance_cents INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS receipts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  expense_id   TEXT NOT NULL REFERENCES expenses(id) ON DELETE CASCADE,
  org_id       TEXT NOT NULL,
  filename     TEXT NOT NULL,
  content_type TEXT NOT NULL,
  data_b64     TEXT NOT NULL,
  size         INTEGER NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS comments (
  id         TEXT PRIMARY KEY,
  expense_id TEXT NOT NULL REFERENCES expenses(id) ON DELETE CASCADE,
  user_id    TEXT NOT NULL REFERENCES users(id),
  body       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS invites (
  token      TEXT PRIMARY KEY,
  org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  email      TEXT NOT NULL,
  role       TEXT NOT NULL DEFAULT 'member',
  invited_by TEXT NOT NULL,
  accepted   INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reports (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  title       TEXT NOT NULL,
  period_from TEXT NOT NULL,
  period_to   TEXT NOT NULL,
  created_by  TEXT NOT NULL,
  share_sig   TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS api_tokens (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id       TEXT NOT NULL,
  role         TEXT NOT NULL,
  name         TEXT NOT NULL,
  scope        TEXT NOT NULL DEFAULT 'read',
  token_hash   TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL,
  last_used_at TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
