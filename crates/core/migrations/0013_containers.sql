-- 0.4.0 Q6: containers (CT-01, CT-02).
--
-- 1. container_hosts: the saved sessions the user marked as container hosts, one row per engine (Docker,
--    Podman). `sudo` says how that engine's CLI runs: as the login user ('off'), under sudo with a password
--    on stdin ('password': the vault item in sudo_password_id, or the session's login password when it is
--    NULL), or under sudo without one ('no_password', NOPASSWD in sudoers). Deleting the session deletes
--    its marks; deleting the vault item falls back to the login password. Docker Desktop on this PC needs
--    no row: it is found like vmrun.
--
-- 2. job_targets takes the target kind 'container' (a container, image, volume or the engine on such a
--    host). SQLite can't change a CHECK constraint in place, so the table is rebuilt with the same columns,
--    in the same order, and its rows, as 0010 did.

CREATE TABLE container_hosts (
    workspace_id      TEXT NOT NULL REFERENCES workspaces(id),
    user_id           TEXT NOT NULL REFERENCES users(id),
    session_id        TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    engine            TEXT NOT NULL CHECK (engine IN ('docker', 'podman')),
    sudo              TEXT NOT NULL DEFAULT 'off' CHECK (sudo IN ('off', 'password', 'no_password')),
    sudo_password_id  TEXT REFERENCES vault_items(id) ON DELETE SET NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (session_id, engine)
);

CREATE INDEX container_hosts_by_workspace ON container_hosts (workspace_id, session_id);

CREATE TABLE job_targets_new (
    job_id            TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    workspace_id      TEXT NOT NULL REFERENCES workspaces(id),
    user_id           TEXT NOT NULL REFERENCES users(id),
    target_kind       TEXT NOT NULL CHECK (target_kind IN ('vm', 'session', 'app', 'terminal', 'container')),
    target_key        TEXT NOT NULL,
    target_name       TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'skipped', 'cancelled')),
    exit_code         INTEGER,
    output            TEXT,
    error             TEXT,
    started_at        TEXT,
    finished_at       TEXT,
    duration_ms       INTEGER,
    safety_snapshot   TEXT,
    stderr            TEXT,
    stdout_bytes      INTEGER,
    stderr_bytes      INTEGER,
    output_truncated  INTEGER NOT NULL DEFAULT 0 CHECK (output_truncated IN (0, 1)),
    output_hash       TEXT,
    output_hash_loose TEXT,
    error_code        TEXT,
    PRIMARY KEY (job_id, target_key)
);

INSERT INTO job_targets_new (job_id, workspace_id, user_id, target_kind, target_key, target_name, status,
                             exit_code, output, error, started_at, finished_at, duration_ms, safety_snapshot,
                             stderr, stdout_bytes, stderr_bytes, output_truncated, output_hash,
                             output_hash_loose, error_code)
SELECT job_id, workspace_id, user_id, target_kind, target_key, target_name, status, exit_code, output, error,
       started_at, finished_at, duration_ms, safety_snapshot, stderr, stdout_bytes, stderr_bytes,
       output_truncated, output_hash, output_hash_loose, error_code
FROM job_targets;

DROP TABLE job_targets;

ALTER TABLE job_targets_new RENAME TO job_targets;
