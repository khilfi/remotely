-- Post-MVP P8: SS-07 saved port forwards, per session.
--
-- One row per forward: local (a port on this PC to a host the session's host reaches), remote (a
-- port on the session's host back to a host this PC reaches) or dynamic (a SOCKS proxy on this PC).
-- Where it listens (bind_address, bind_port; port 0 lets the system choose), where it leads
-- (dest_host, dest_port; empty for SOCKS), an optional label, and whether it starts with the
-- session's terminal. Opening one goes through the command bus; this table only remembers them.
-- Deleting the session deletes its forwards.
CREATE TABLE port_forwards (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    session_id    TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    position      INTEGER NOT NULL,
    label         TEXT,
    kind          TEXT NOT NULL CHECK (kind IN ('local', 'remote', 'dynamic')),
    bind_address  TEXT NOT NULL,
    bind_port     INTEGER NOT NULL CHECK (bind_port BETWEEN 0 AND 65535),
    dest_host     TEXT NOT NULL DEFAULT '',
    dest_port     INTEGER NOT NULL DEFAULT 0 CHECK (dest_port BETWEEN 0 AND 65535),
    auto_start    INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE INDEX port_forwards_by_session ON port_forwards (workspace_id, session_id, position);
