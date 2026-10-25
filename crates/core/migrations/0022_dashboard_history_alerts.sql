-- 0.5.0 R9: dashboard history on disk (MO-06) and alerts (MO-07). The dashboard layout (MO-16) is a setting
-- (`dashboard.layout`), so it needs no table.
--
-- metric_series
--   One row per series the dashboard has kept history for: a VM's host side (its .vmx path or VirtualBox
--   UUID), a watched host's guest metrics (the session id), or this PC ('this-pc'). The minutes refer to it
--   by its integer id, so a long .vmx path is stored once rather than once a minute.
-- metric_minutes
--   One row per series per minute: the average of that minute's rounds (every 5 s on the host side, every
--   5 to 60 s for a guest), with the lowest and highest CPU, the highest memory, load and fullest disk. Written
--   once a minute in one transaction, pruned daily after the retention setting (`metrics.historyRetention`,
--   7 days by default). `minute` is Unix time in minutes (UTC). Percentages are 0 to 100; bytes and bytes per
--   second are whole numbers. WITHOUT ROWID: the table is its primary key, read by series and time.
-- alert_rules
--   MO-07 rules: a metric (cpu, memory, disk, swap, unreachable, stopped), a scope (all VMs, a VM, a tag, an
--   SSH host, all watched hosts, this PC), a threshold, how long it must hold, a severity, and whether it
--   notifies. `builtin` names a rule Remotely ships (created at start, never deleted, reset to its defaults
--   on request); the owner's own rules have none.
-- alerts
--   Each time a rule fired for a target: the reading then, the worst one while it fired, when it resolved and
--   why, and when it was acknowledged. Names are copied in, so an alert outlives its rule and its target.
--   Resolved alerts are pruned with the history.
--
-- The table metric_samples (0001), kept for MO-06 but never written, is dropped: its one row per sample would
-- have taken several times the space.

DROP TABLE metric_samples;

CREATE TABLE metric_series (
    id            INTEGER PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    source        TEXT NOT NULL CHECK (source IN ('host', 'guest', 'thisPc')),
    target_key    TEXT NOT NULL COLLATE NOCASE,
    created_at    TEXT NOT NULL,
    UNIQUE (workspace_id, source, target_key)
);

CREATE TABLE metric_minutes (
    series_id      INTEGER NOT NULL REFERENCES metric_series(id) ON DELETE CASCADE,
    minute         INTEGER NOT NULL,
    workspace_id   TEXT NOT NULL REFERENCES workspaces(id),
    user_id        TEXT NOT NULL REFERENCES users(id),
    samples        INTEGER NOT NULL CHECK (samples > 0),
    cpu_avg        REAL,
    cpu_min        REAL,
    cpu_max        REAL,
    mem_avg        INTEGER,
    mem_max        INTEGER,
    mem_total      INTEGER,
    swap_avg       INTEGER,
    swap_total     INTEGER,
    read_avg       INTEGER,
    write_avg      INTEGER,
    rx_avg         INTEGER,
    tx_avg         INTEGER,
    load_avg       REAL,
    load_max       REAL,
    disk_used_max  REAL,
    PRIMARY KEY (series_id, minute)
) WITHOUT ROWID;

CREATE TABLE alert_rules (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    builtin       TEXT,
    name          TEXT NOT NULL,
    metric        TEXT NOT NULL CHECK (metric IN ('cpu', 'memory', 'disk', 'swap', 'unreachable', 'stopped')),
    scope_kind    TEXT NOT NULL CHECK (scope_kind IN ('allVms', 'vm', 'tag', 'host', 'allHosts', 'thisPc')),
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

CREATE TABLE alerts (
    id               TEXT PRIMARY KEY,
    workspace_id     TEXT NOT NULL REFERENCES workspaces(id),
    user_id          TEXT NOT NULL REFERENCES users(id),
    rule_id          TEXT NOT NULL,
    rule_name        TEXT NOT NULL,
    metric           TEXT NOT NULL,
    severity         TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    target_kind      TEXT NOT NULL CHECK (target_kind IN ('vm', 'session', 'thisPc')),
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

CREATE INDEX alerts_by_time ON alerts (workspace_id, fired_at DESC);

CREATE INDEX alerts_open ON alerts (workspace_id, fired_at DESC) WHERE resolved_at IS NULL;
