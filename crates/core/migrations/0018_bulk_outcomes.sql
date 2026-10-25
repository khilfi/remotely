-- 0.4.3 safer operations (H9, audit trail).
--
-- 1. job_targets takes the status 'unknown': a host that timed out, or whose command was cancelled while
--    it ran, may have run it, so it is neither failed nor cancelled, and "retry failed" leaves it out
--    unless asked. SQLite can't change a CHECK constraint in place, so the table is rebuilt with the same
--    columns, in the same order, and its rows, as 0010 and 0013 did.
-- 2. Two new columns record how each remote target was reached: peer_ip, the address this PC connected
--    to (NULL behind jump hosts, where this PC only reached the first one), and host_key, the type and
--    SHA-256 fingerprint of the key the host presented and the run accepted.

CREATE TABLE job_targets_new (
    job_id            TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    workspace_id      TEXT NOT NULL REFERENCES workspaces(id),
    user_id           TEXT NOT NULL REFERENCES users(id),
    target_kind       TEXT NOT NULL CHECK (target_kind IN ('vm', 'session', 'app', 'terminal', 'container')),
    target_key        TEXT NOT NULL,
    target_name       TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'skipped',
                                                      'cancelled', 'unknown')),
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
    peer_ip           TEXT,
    host_key          TEXT,
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
