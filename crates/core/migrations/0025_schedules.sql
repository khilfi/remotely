-- 0.5.0 R7: schedules (VM-27 snapshot schedules, VM-14 scheduled power and idle auto-suspend), and the standing
-- approvals they run under (docs/plan-0.5.md, "Approval tiers").
--
-- schedules
--   One row per schedule: a name, what it does, on which targets and when (`spec_json`: an action, VMs or tags,
--   and hourly, daily, weekly or "when idle" timing in local time), and `content_hash`, the SHA-256 of that
--   content. `state` is active, paused (by the user) or needsApproval (new, edited, or something changed since it
--   was approved: a target became Prod or protected, a new VM has the tag, the approval rules changed), with the
--   reason in `state_reason`. `approval_id` is the standing approval it runs under; `next_run_at` and
--   `next_note` (a daylight-saving change on that day) are kept for the list and the scheduler.
-- standing_approvals
--   The command bus's record of an approval given when a schedule was saved: the content and the rules it was
--   given for (hashes), the tier, the commands each run may submit (targets left out), the targets it was shown
--   with their labels then, and the answers (an ApprovalRecord, no secret). Each scheduled command the bus takes
--   is checked against it; a revoked one (the schedule was edited, re-approved or deleted) is never used again.
--   Rows are kept, so a run's approval can always be looked up.
-- schedule_runs
--   Each time a schedule was due: when, how it went (running, succeeded, partiallyFailed, failed, missed,
--   skipped, paused), why, and its jobs. A missed run (the PC asleep or off, Remotely closed) is reported once
--   and never caught up. The newest 200 runs per schedule are kept.
-- schedule_snapshots
--   VM-27: every snapshot a schedule took, by the hypervisor's own id for it (VMware's .vmsd uid, VirtualBox's
--   snapshot UUID) and its name. Retention deletes only these, oldest first, and only while the id and the name
--   still match. `ended_at` and `ended_why` say when one stopped counting: deleted by retention, gone (deleted
--   some other way), or renamed (kept: someone named it, so it is theirs now).

CREATE TABLE schedules (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    spec_json     TEXT NOT NULL,
    content_hash  TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('active', 'paused', 'needsApproval')),
    state_reason  TEXT,
    approval_id   TEXT,
    next_run_at   TEXT,
    next_note     TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE INDEX schedules_by_workspace ON schedules (workspace_id, name COLLATE NOCASE);

CREATE TABLE standing_approvals (
    id             TEXT PRIMARY KEY,
    workspace_id   TEXT NOT NULL REFERENCES workspaces(id),
    user_id        TEXT NOT NULL REFERENCES users(id),
    owner_id       TEXT NOT NULL,
    content_hash   TEXT NOT NULL,
    rules_hash     TEXT NOT NULL,
    tier           TEXT NOT NULL CHECK (tier IN ('low', 'medium', 'high', 'critical')),
    commands_json  TEXT NOT NULL,
    targets_json   TEXT NOT NULL,
    record_json    TEXT NOT NULL,
    granted_at     TEXT NOT NULL,
    revoked_at     TEXT,
    revoked_why    TEXT
);

CREATE INDEX standing_approvals_by_owner ON standing_approvals (workspace_id, owner_id);

CREATE TABLE schedule_runs (
    id            TEXT PRIMARY KEY,
    schedule_id   TEXT NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    due_at        TEXT NOT NULL,
    started_at    TEXT,
    finished_at   TEXT,
    outcome       TEXT NOT NULL CHECK (outcome IN
                      ('running', 'succeeded', 'partiallyFailed', 'failed', 'missed', 'skipped', 'paused')),
    detail        TEXT,
    job_ids       TEXT NOT NULL DEFAULT '[]',
    approval_id   TEXT
);

CREATE INDEX schedule_runs_by_schedule ON schedule_runs (schedule_id, due_at DESC);

CREATE TABLE schedule_snapshots (
    schedule_id   TEXT NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    vm_key        TEXT NOT NULL COLLATE NOCASE,
    snapshot_id   TEXT NOT NULL,
    name          TEXT NOT NULL,
    run_id        TEXT,
    taken_at      TEXT NOT NULL,
    ended_at      TEXT,
    ended_why     TEXT CHECK (ended_why IN ('deleted', 'gone', 'renamed')),
    PRIMARY KEY (schedule_id, vm_key, snapshot_id)
);
