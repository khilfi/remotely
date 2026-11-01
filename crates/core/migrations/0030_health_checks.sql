-- 0.7.0 F2: health checks with history and alerts (MO-08).
--
-- health_checks
--   One row per check: a kind (ping, a TCP port, HTTP(S), a certificate's days left, a DNS name, or a service over
--   SSH), a target (a typed address, a saved session, or a VM by its key: its guest IP), the kind's own fields as
--   JSON (`options`: port, path, expected status, unit name...), how often it runs (30 s to 1 h), how long one run may
--   take, and how many failed runs in a row make it down. A paused check doesn't run. Checks run from this PC for the
--   workspace shown (FD-02), like MO-07's alerts. Edits are audited (`check_changed`); runs are reads, not audited.
-- health_check_results
--   One row per run: when (Unix time in milliseconds, UTC), its result (`up`; `down`: the probe failed; `unknown`:
--   Remotely couldn't check, e.g. the vault is locked or a login is parked), the time it took, a one-line detail,
--   and a certificate check's days left. Kept for the dashboard history's retention (`metrics.historyRetention`) and
--   pruned with it (MO-06). A check's results go with it. WITHOUT ROWID: read by check and time.
--
-- alert_rules, alerts
--   MO-07 gains three metrics on checks (`checkDown`, a state; `checkSlow`, milliseconds; `certExpiring`, days), two
--   scopes (`allChecks`, `check`) and a target kind (`check`). SQLite can't change a CHECK constraint in place, so
--   both tables are rebuilt with the same columns, in the same order, and their rows, keeping every value 0022 allows.
--   Nothing references them by a foreign key.

CREATE TABLE health_checks (
    id                    TEXT PRIMARY KEY,
    workspace_id          TEXT NOT NULL REFERENCES workspaces(id),
    user_id               TEXT NOT NULL REFERENCES users(id),
    name                  TEXT NOT NULL,
    kind                  TEXT NOT NULL CHECK (kind IN ('ping', 'tcp', 'http', 'certificate', 'dns', 'service')),
    target_kind           TEXT NOT NULL CHECK (target_kind IN ('address', 'session', 'vm')),
    target_key            TEXT NOT NULL,
    options               TEXT NOT NULL,
    interval_secs         INTEGER NOT NULL CHECK (interval_secs BETWEEN 30 AND 3600),
    timeout_secs          INTEGER NOT NULL CHECK (timeout_secs BETWEEN 1 AND 60),
    failures_before_down  INTEGER NOT NULL CHECK (failures_before_down BETWEEN 1 AND 10),
    paused                INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1)),
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);

CREATE INDEX health_checks_by_workspace ON health_checks (workspace_id, name COLLATE NOCASE);

CREATE TABLE health_check_results (
    check_id      TEXT NOT NULL REFERENCES health_checks(id) ON DELETE CASCADE,
    at            INTEGER NOT NULL,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    result        TEXT NOT NULL CHECK (result IN ('up', 'down', 'unknown')),
    took_ms       INTEGER,
    detail        TEXT NOT NULL,
    cert_days     INTEGER,
    PRIMARY KEY (check_id, at)
) WITHOUT ROWID;

CREATE TABLE alert_rules_new (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    builtin       TEXT,
    name          TEXT NOT NULL,
    metric        TEXT NOT NULL CHECK (metric IN ('cpu', 'memory', 'disk', 'swap', 'unreachable', 'stopped',
                                                  'checkDown', 'checkSlow', 'certExpiring')),
    scope_kind    TEXT NOT NULL CHECK (scope_kind IN ('allVms', 'vm', 'tag', 'host', 'allHosts', 'thisPc',
                                                      'allChecks', 'check')),
    scope_key     TEXT,
    threshold     REAL,
    for_secs      INTEGER NOT NULL CHECK (for_secs >= 0),
    severity      TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    notify        INTEGER NOT NULL CHECK (notify IN (0, 1)),
    enabled       INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (workspace_id, builtin)
);

INSERT INTO alert_rules_new (id, workspace_id, user_id, builtin, name, metric, scope_kind, scope_key, threshold,
                             for_secs, severity, notify, enabled, created_at, updated_at)
SELECT id, workspace_id, user_id, builtin, name, metric, scope_kind, scope_key, threshold, for_secs, severity, notify,
       enabled, created_at, updated_at
FROM alert_rules;

DROP TABLE alert_rules;

ALTER TABLE alert_rules_new RENAME TO alert_rules;

CREATE TABLE alerts_new (
    id               TEXT PRIMARY KEY,
    workspace_id     TEXT NOT NULL REFERENCES workspaces(id),
    user_id          TEXT NOT NULL REFERENCES users(id),
    rule_id          TEXT NOT NULL,
    rule_name        TEXT NOT NULL,
    metric           TEXT NOT NULL,
    severity         TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    target_kind      TEXT NOT NULL CHECK (target_kind IN ('vm', 'session', 'thisPc', 'check')),
    target_key       TEXT NOT NULL,
    target_name      TEXT NOT NULL,
    threshold        REAL,
    for_secs         INTEGER NOT NULL,
    value            REAL,
    peak             REAL,
    message          TEXT NOT NULL,
    fired_at         TEXT NOT NULL,
    resolved_at      TEXT,
    resolution       TEXT CHECK (resolution IN ('cleared', 'gone', 'ruleChanged', 'restarted')),
    acknowledged_at  TEXT
);

INSERT INTO alerts_new (id, workspace_id, user_id, rule_id, rule_name, metric, severity, target_kind, target_key,
                        target_name, threshold, for_secs, value, peak, message, fired_at, resolved_at, resolution,
                        acknowledged_at)
SELECT id, workspace_id, user_id, rule_id, rule_name, metric, severity, target_kind, target_key, target_name,
       threshold, for_secs, value, peak, message, fired_at, resolved_at, resolution, acknowledged_at
FROM alerts;

DROP TABLE alerts;

ALTER TABLE alerts_new RENAME TO alerts;

CREATE INDEX alerts_by_time ON alerts (workspace_id, fired_at DESC);

CREATE INDEX alerts_open ON alerts (workspace_id, fired_at DESC) WHERE resolved_at IS NULL;
