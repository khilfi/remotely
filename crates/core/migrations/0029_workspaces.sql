-- 0.5.0 R11: customer workspaces (FD-02) and change IDs (AP-08).
--
-- Every record has carried workspace_id and user_id since 0001, so the engagement data needs no move: what the app
-- held so far stays in the workspace it was in ("Default" unless the owner renames it).
--
-- workspaces.color
--   The workspace's colour in the top bar's switcher: one of the app's named colours (workspaces::COLORS).
-- workspaces.archived_at
--   When the workspace was archived (NULL: active). An archived workspace keeps its data and its audit log, can't be
--   switched to, and runs no schedules, until it is restored.
-- workspaces.is_home
--   1 for the workspace each user started with. It is how the app finds the user's own workspace at start (its name
--   can change), and it holds the settings that are this PC's rather than an engagement's (settings::MACHINE_KEYS:
--   tool paths, scanned folders, update checks, retention...), so those don't change with the workspace shown.
-- workspaces.audit_legacy_until
--   AP-05: before 0.5.0 the audit log was one hash chain for the whole file. From now on each workspace has its own
--   chain, so a workspace's log verifies and exports on its own entries. Entries up to this seq (the last one written
--   before this migration) keep their old links; the workspace's next entry links to a start hash made from the
--   workspace's id and its last old entry (store::audit::chain_start). 0 for workspaces made since.
--
-- vm_assignments
--   VMs are on this PC, shared by every engagement, so each VM belongs to one workspace at most: the one it is
--   assigned to. Only that workspace lists it and can act on it (the command bus refuses the others); a VM no
--   workspace has waits in the VMs page's Unassigned view until it is added to one. vm_key is the VM's key
--   (.vmx path, or a VirtualBox VM's UUID), as vms.vmx_path. Every VM the inventory knows now joins the workspace that
--   lists it.
--
-- jobs.change_id
--   AP-08: the ticket or change number given with a High or Critical approval (also in approval_json, and so in the
--   audit entry), for Activity's lists and the exports. Redacted and at most 64 characters (command_bus).

ALTER TABLE workspaces ADD COLUMN color TEXT NOT NULL DEFAULT 'slate';

ALTER TABLE workspaces ADD COLUMN archived_at TEXT;

ALTER TABLE workspaces ADD COLUMN is_home INTEGER NOT NULL DEFAULT 0 CHECK (is_home IN (0, 1));

ALTER TABLE workspaces ADD COLUMN audit_legacy_until INTEGER NOT NULL DEFAULT 0;

-- Each user's first workspace: the one named Default before workspaces could be renamed.
UPDATE workspaces SET is_home = 1 WHERE name = 'Default';

UPDATE workspaces SET audit_legacy_until = (SELECT IFNULL(MAX(seq), 0) FROM audit_log);

CREATE INDEX audit_log_by_workspace ON audit_log (workspace_id, seq);

CREATE TABLE vm_assignments (
    vm_key        TEXT PRIMARY KEY COLLATE NOCASE,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    assigned_at   TEXT NOT NULL
);

CREATE INDEX vm_assignments_by_workspace ON vm_assignments (workspace_id);

-- A database used by two Windows accounts may list a VM in both: the first workspace to have listed it keeps it.
INSERT OR IGNORE INTO vm_assignments (vm_key, workspace_id, user_id, assigned_at)
    SELECT vmx_path, workspace_id, user_id, created_at FROM vms ORDER BY created_at, rowid;

UPDATE vms SET missing = 1
    WHERE NOT EXISTS (SELECT 1 FROM vm_assignments a WHERE a.vm_key = vms.vmx_path AND a.workspace_id = vms.workspace_id);

ALTER TABLE jobs ADD COLUMN change_id TEXT;
