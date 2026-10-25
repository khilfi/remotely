-- The job journal keeps less customer data, for less long, and Activity reads it faster (BX-02, BX-05, SS-10).
--
-- jobs.command_type
--   The command's type (`remoteExec`, `terminalLine`, `vmPower`...: command_json's "type"), so the journal's
--   lists filter on a column instead of parsing every row's JSON. Backfilled here; '' for a row whose JSON
--   can't be read.
-- jobs.bodies_removed_at
--   When the retention purge emptied the job's outputs (job_targets.output and stderr) and the script or line
--   text in command_json. The job row, its summary, tier, targets, results and output hashes stay, so Activity
--   still lists it. NULL: not purged yet.
-- jobs.command_redacted
--   1: what looked like a secret in the stored script or line was replaced by [redacted] (export::redact_secrets),
--   so the command can't be run again as it was (BX-04 retry). 0: nothing was. NULL: a row from before this
--   migration that the app has not checked yet; it checks them at start.
--
-- Indexes: Compare's runs by type (jobs_by_type), the jobs still open at start (jobs_open, a partial index on
-- status), the purge's next jobs (jobs_to_purge, only rows not purged yet) and the old rows still to redact
-- (jobs_unchecked, empty once they are).

ALTER TABLE jobs ADD COLUMN command_type TEXT NOT NULL DEFAULT '';

UPDATE jobs SET command_type = CASE
    WHEN json_valid(command_json) THEN IFNULL(json_extract(command_json, '$.type'), '')
    ELSE ''
END;

ALTER TABLE jobs ADD COLUMN bodies_removed_at TEXT;

ALTER TABLE jobs ADD COLUMN command_redacted INTEGER CHECK (command_redacted IN (0, 1));

-- Only a script or a typed line can hold a secret (or JSON that can't be read, which is checked as text).
UPDATE jobs SET command_redacted = 0 WHERE command_type NOT IN ('remoteExec', 'terminalLine', '');

CREATE INDEX jobs_by_type ON jobs (workspace_id, command_type, created_at DESC);

CREATE INDEX jobs_open ON jobs (status) WHERE status IN ('queued', 'countdown', 'running');

CREATE INDEX jobs_to_purge ON jobs (workspace_id, created_at) WHERE bodies_removed_at IS NULL;

CREATE INDEX jobs_unchecked ON jobs (id) WHERE command_redacted IS NULL;
