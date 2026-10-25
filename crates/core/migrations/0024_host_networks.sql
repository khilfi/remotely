-- 0.5.0 R4: VM insight, host networks and the waste finder (VM-11, VM-14, VM-16, VM-25).
--
-- A NAT port forward's change goes through the command bus with the network as its target (a Workstation vmnet
-- or a VirtualBox NAT network), so job_targets takes the target kind 'network'. SQLite can't change a CHECK
-- constraint in place, so the table is rebuilt with the same columns, in the same order, and its rows, as 0010,
-- 0013, 0018 and 0023 did, keeping every kind they allow (0023's 'new_vm' included). Nothing else changes: the Log
-- and Timeline tabs read the VM's own files, the audit log and the job journal, and the waste finder reads the
-- inventory, the VMs' files and the dashboard's history.

CREATE TABLE job_targets_new (
    job_id            TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    workspace_id      TEXT NOT NULL REFERENCES workspaces(id),
    user_id           TEXT NOT NULL REFERENCES users(id),
    target_kind       TEXT NOT NULL CHECK (target_kind IN ('vm', 'session', 'app', 'terminal', 'container',
                                                           'new_vm', 'network')),
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
                             output_hash_loose, error_code, peer_ip, host_key)
SELECT job_id, workspace_id, user_id, target_kind, target_key, target_name, status, exit_code, output, error,
       started_at, finished_at, duration_ms, safety_snapshot, stderr, stdout_bytes, stderr_bytes,
       output_truncated, output_hash, output_hash_loose, error_code, peer_ip, host_key
FROM job_targets;

DROP TABLE job_targets;

ALTER TABLE job_targets_new RENAME TO job_targets;

-- VM-25: a VM's Timeline reads its own rows of each job it was in.
CREATE INDEX job_targets_by_key ON job_targets (workspace_id, target_key);
