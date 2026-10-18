-- Post-MVP P4: the terminal workspace (QL-02, QL-03).

-- QL-03: what the last connection to a session saw: the IP address actually reached and the server's own
-- host name (`hostname` on the same connection, or DNS when the server didn't say), and when.
ALTER TABLE sessions ADD COLUMN last_ip TEXT;
ALTER TABLE sessions ADD COLUMN last_hostname TEXT;
ALTER TABLE sessions ADD COLUMN last_seen_at TEXT;

-- QL-02: when a terminal to the session was last opened, for the Recent sessions list.
ALTER TABLE sessions ADD COLUMN last_opened_at TEXT;
CREATE INDEX sessions_by_last_opened ON sessions (workspace_id, last_opened_at);

-- QL-02: quick connections that were not saved as sessions: where to and how to log in, never a typed
-- password. Vault items are referenced by ID, like sessions do. One row per host, port and user.
CREATE TABLE quick_connect_history (
    id                 TEXT PRIMARY KEY,
    workspace_id       TEXT NOT NULL REFERENCES workspaces(id),
    user_id            TEXT NOT NULL REFERENCES users(id),
    host               TEXT NOT NULL COLLATE NOCASE,
    port               INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    username           TEXT NOT NULL DEFAULT '',
    auth_method        TEXT NOT NULL CHECK (auth_method IN ('password', 'key', 'agent')),
    credential_id      TEXT REFERENCES vault_items(id) ON DELETE SET NULL,
    key_passphrase_id  TEXT REFERENCES vault_items(id) ON DELETE SET NULL,
    used_at            TEXT NOT NULL,
    UNIQUE (workspace_id, host, port, username)
);

CREATE INDEX quick_connect_by_use ON quick_connect_history (workspace_id, used_at);
