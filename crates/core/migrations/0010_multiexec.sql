-- Post-MVP P6: MultiExec (SS-10). A line typed into several open terminals is a job whose targets are
-- those terminals, so job_targets takes the target kind 'terminal'. SQLite can't change a CHECK
-- constraint in place, so the table is rebuilt with the same columns, in the same order, and its rows.

CREATE TABLE job_targets_new (
    job_id            TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    workspace_id      TEXT NOT NULL REFERENCES workspaces(id),
    user_id           TEXT NOT NULL REFERENCES users(id),
    target_kind       TEXT NOT NULL CHECK (target_kind IN ('vm', 'session', 'app', 'terminal')),
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
