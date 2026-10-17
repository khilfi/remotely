-- Remotely schema v1.
--
-- Conventions
--   * Every data table carries workspace_id and user_id from day one, so customer workspaces (FD-02)
--     need no data migration later. Only the identity tables (users, workspaces) are exempt.
--   * IDs are UUID text; timestamps are RFC 3339 UTC text.
--   * The database runs in WAL mode (set on connect), with foreign keys on.

-- ---------------------------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------------------------

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    account       TEXT NOT NULL UNIQUE COLLATE NOCASE,  -- Windows account, DOMAIN\user
    display_name  TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE workspaces (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),     -- owner
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (user_id, name)
);

-- Per-workspace settings, e.g. the editable policy rules (AP-01).
CREATE TABLE settings (
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    key           TEXT NOT NULL,
    value_json    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (workspace_id, key)
);

-- ---------------------------------------------------------------------------------------------
-- Vault (SS-04): ciphertext only. AES-256-GCM per item; the data key is wrapped by DPAPI or an
-- Argon2id-derived master key (vault_meta).
-- ---------------------------------------------------------------------------------------------

CREATE TABLE vault_meta (
    workspace_id   TEXT PRIMARY KEY REFERENCES workspaces(id),
    user_id        TEXT NOT NULL REFERENCES users(id),
    unlock_method  TEXT NOT NULL CHECK (unlock_method IN ('dpapi', 'master_password')),
    kdf_salt       BLOB,
    kdf_params     TEXT,
    wrapped_key    BLOB NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE TABLE vault_items (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    kind          TEXT NOT NULL CHECK (kind IN ('password', 'private_key', 'passphrase')),
    label         TEXT NOT NULL,
    nonce         BLOB NOT NULL,
    ciphertext    BLOB NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- ---------------------------------------------------------------------------------------------
-- Inventory (VM-01, AP-04, SS-06)
-- ---------------------------------------------------------------------------------------------

CREATE TABLE vms (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    vmx_path      TEXT NOT NULL COLLATE NOCASE,          -- Windows paths are case-insensitive
    display_name  TEXT NOT NULL,
    guest_os      TEXT,
    num_vcpus     INTEGER,
    memsize_mb    INTEGER,
    power_state   TEXT NOT NULL DEFAULT 'unknown'
                  CHECK (power_state IN ('unknown', 'running', 'not_running', 'suspended', 'paused')),
    ip_address    TEXT,
    tools_state   TEXT,
    environment   TEXT NOT NULL DEFAULT 'none' CHECK (environment IN ('none', 'lab', 'staging', 'prod')),
    protected     INTEGER NOT NULL DEFAULT 0 CHECK (protected IN (0, 1)),
    last_seen_at  TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (workspace_id, vmx_path)
);

CREATE TABLE tags (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL COLLATE NOCASE,
    color         TEXT,
    created_at    TEXT NOT NULL,
    UNIQUE (workspace_id, name)
);

CREATE TABLE target_tags (
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    tag_id        TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    target_kind   TEXT NOT NULL CHECK (target_kind IN ('vm', 'session')),
    target_id     TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (tag_id, target_kind, target_id)
);

-- Saved selections for VM-02 and BX-01.
CREATE TABLE saved_filters (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    target_kind   TEXT NOT NULL CHECK (target_kind IN ('vm', 'session', 'any')),
    filter_json   TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (workspace_id, name)
);

-- ---------------------------------------------------------------------------------------------
-- Sessions (SS-01, SS-02, SS-05, SS-06)
-- ---------------------------------------------------------------------------------------------

CREATE TABLE session_folders (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    parent_id     TEXT REFERENCES session_folders(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    sort_order    INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE sessions (
    id                 TEXT PRIMARY KEY,
    workspace_id       TEXT NOT NULL REFERENCES workspaces(id),
    user_id            TEXT NOT NULL REFERENCES users(id),
    folder_id          TEXT REFERENCES session_folders(id) ON DELETE SET NULL,
    name               TEXT NOT NULL,
    protocol           TEXT NOT NULL DEFAULT 'ssh'
                       CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'telnet', 'serial', 'winrm')),
    host               TEXT NOT NULL,
    port               INTEGER NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
    username           TEXT,
    auth_method        TEXT NOT NULL DEFAULT 'password' CHECK (auth_method IN ('password', 'key', 'agent')),
    credential_id      TEXT REFERENCES vault_items(id) ON DELETE SET NULL,
    key_passphrase_id  TEXT REFERENCES vault_items(id) ON DELETE SET NULL,
    jump_session_id    TEXT REFERENCES sessions(id) ON DELETE SET NULL,
    startup_command    TEXT,
    environment        TEXT NOT NULL DEFAULT 'none' CHECK (environment IN ('none', 'lab', 'staging', 'prod')),
    color              TEXT,
    protected          INTEGER NOT NULL DEFAULT 0 CHECK (protected IN (0, 1)),
    keepalive_secs     INTEGER NOT NULL DEFAULT 30,
    vm_id              TEXT REFERENCES vms(id) ON DELETE SET NULL,  -- the VM this session reaches, if any
    imported_from      TEXT CHECK (imported_from IN ('putty', 'mobaxterm', 'openssh', 'csv')),
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);

CREATE INDEX sessions_by_folder ON sessions (workspace_id, folder_id);

CREATE TABLE known_hosts (
    id                  TEXT PRIMARY KEY,
    workspace_id        TEXT NOT NULL REFERENCES workspaces(id),
    user_id             TEXT NOT NULL REFERENCES users(id),
    host                TEXT NOT NULL COLLATE NOCASE,
    port                INTEGER NOT NULL,
    key_type            TEXT NOT NULL,
    fingerprint_sha256  TEXT NOT NULL,
    first_seen_at       TEXT NOT NULL,
    last_seen_at        TEXT NOT NULL,
    UNIQUE (workspace_id, host, port, key_type)
);

-- ---------------------------------------------------------------------------------------------
-- Jobs: journaled, so after a crash the app shows which targets finished (NFR Reliability).
-- ---------------------------------------------------------------------------------------------

CREATE TABLE jobs (
    id             TEXT PRIMARY KEY,
    workspace_id   TEXT NOT NULL REFERENCES workspaces(id),
    user_id        TEXT NOT NULL REFERENCES users(id),
    summary        TEXT NOT NULL,
    action         TEXT NOT NULL,
    tier           TEXT NOT NULL CHECK (tier IN ('low', 'medium', 'high', 'critical')),
    command_json   TEXT NOT NULL,
    approval_json  TEXT,
    status         TEXT NOT NULL CHECK (status IN ('queued', 'countdown', 'running', 'succeeded', 'failed',
                                                   'partially_failed', 'cancelled', 'interrupted')),
    retry_of       TEXT REFERENCES jobs(id),
    created_at     TEXT NOT NULL,
    started_at     TEXT,
    finished_at    TEXT
);

CREATE INDEX jobs_by_time ON jobs (workspace_id, created_at DESC);

CREATE TABLE job_targets (
    job_id        TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    target_kind   TEXT NOT NULL CHECK (target_kind IN ('vm', 'session', 'app')),
    target_key    TEXT NOT NULL,
    target_name   TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'skipped', 'cancelled')),
    exit_code     INTEGER,
    output        TEXT,
    error         TEXT,
    started_at    TEXT,
    finished_at   TEXT,
    duration_ms   INTEGER,
    PRIMARY KEY (job_id, target_key)
);

-- ---------------------------------------------------------------------------------------------
-- Metrics (MO-01, MO-02). History and rollups (MO-06) are v2; the table is ready for them.
-- ---------------------------------------------------------------------------------------------

CREATE TABLE metric_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    user_id         TEXT NOT NULL REFERENCES users(id),
    source          TEXT NOT NULL CHECK (source IN ('host', 'guest')),
    target_kind     TEXT NOT NULL CHECK (target_kind IN ('vm', 'session')),
    target_key      TEXT NOT NULL,
    ts              TEXT NOT NULL,
    cpu_pct         REAL,
    mem_bytes       INTEGER,
    disk_read_bps   REAL,
    disk_write_bps  REAL,
    net_rx_bps      REAL,
    net_tx_bps      REAL,
    load1           REAL,
    uptime_secs     INTEGER,
    extra_json      TEXT
);

CREATE INDEX metric_samples_by_target ON metric_samples (workspace_id, target_key, ts);

-- ---------------------------------------------------------------------------------------------
-- Audit log (AP-05): append-only and hash-chained. Each row's hash covers its content and the
-- previous row's hash, so any edit breaks the chain. The triggers block UPDATE and DELETE.
-- No foreign keys: audit rows must outlive the records they describe.
-- ---------------------------------------------------------------------------------------------

CREATE TABLE audit_log (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    id             TEXT NOT NULL UNIQUE,
    workspace_id   TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    ts             TEXT NOT NULL,
    event          TEXT NOT NULL,
    action         TEXT NOT NULL,
    tier           TEXT CHECK (tier IN ('low', 'medium', 'high', 'critical')),
    job_id         TEXT,
    targets_json   TEXT NOT NULL,
    approval_json  TEXT,
    result         TEXT,
    detail         TEXT,
    prev_hash      TEXT NOT NULL UNIQUE,
    hash           TEXT NOT NULL UNIQUE
);

CREATE INDEX audit_log_by_job ON audit_log (job_id);

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
