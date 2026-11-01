-- 0.7.0 F5: notes (FD-06), stars and recents (QL-26) and the trash (QL-27). Every row carries workspace_id and
-- user_id. (0030 to 0032 belong to other 0.7.0 packages; a package that needs none leaves its number unused.)
--
-- notes
--   One markdown note per session, VM and session folder. target_key is the session's or folder's id, or the VM's key
--   (.vmx path or VirtualBox UUID, as vms.vmx_path), so a VM's note stays with the VM whatever its row in vms does. Not
--   a foreign key: a deleted session's note goes to the trash with it (crate::trash), a deleted folder's is deleted
--   with the folder. handover = 1: F6's handover pack includes it. Editing a note is audited without its text and
--   refused by the read-only lock (crate::notes).
--
-- stars
--   QL-26: what the user starred: a session (its id), a VM (its key) or a command (`favourite:<id>` for a saved
--   command, `library:<id>` for a built-in one). Not foreign keys, so a session restored from the trash keeps its star.
--   Like the notification centre, stars and recents are not audited and the read-only lock leaves them alone.
--
-- recent_items
--   QL-26: the sessions, VMs and pages opened last (item_key: a session's id, a VM's key, a page's id), newest first;
--   crate::stars keeps the 20 latest per workspace.
--
-- trash
--   QL-27: what was deleted (a session, a saved command, a size, an image, a launch template or a stack), as a
--   snapshot of its rows: `snapshot` is JSON {"row": {...}, "attached": [{"table": "...", "row": {...}}...],
--   "tags": [...], "note": {...} | null, "sent": [...]}, each row column by column as it was (crate::trash::rows).
--   The live tables keep their hard deletes, so no read changes. item_id is the deleted item's id, so a restore puts
--   it back under it (a template finds its image again, a group its session). name and place say what and from where;
--   detail what came along. Kept 30 days, then purged daily. Never in an FD-07 export.

CREATE TABLE notes (
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    target_kind   TEXT NOT NULL CHECK (target_kind IN ('session', 'vm', 'folder')),
    target_key    TEXT NOT NULL COLLATE NOCASE,
    body          TEXT NOT NULL,
    handover      INTEGER NOT NULL DEFAULT 0 CHECK (handover IN (0, 1)),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (workspace_id, target_kind, target_key)
);

CREATE TABLE stars (
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    kind          TEXT NOT NULL CHECK (kind IN ('session', 'vm', 'command')),
    item_key      TEXT NOT NULL COLLATE NOCASE,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (workspace_id, kind, item_key)
);

CREATE TABLE recent_items (
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    kind          TEXT NOT NULL CHECK (kind IN ('session', 'vm', 'page')),
    item_key      TEXT NOT NULL COLLATE NOCASE,
    opened_at     TEXT NOT NULL,
    PRIMARY KEY (workspace_id, kind, item_key)
);

CREATE INDEX recent_items_by_time ON recent_items (workspace_id, opened_at);

CREATE TABLE trash (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    kind          TEXT NOT NULL CHECK (kind IN ('session', 'command', 'size', 'image', 'template', 'stack')),
    item_id       TEXT NOT NULL,
    name          TEXT NOT NULL,
    place         TEXT NOT NULL,
    detail        TEXT NOT NULL DEFAULT '',
    snapshot      TEXT NOT NULL,
    deleted_at    TEXT NOT NULL
);

CREATE INDEX trash_by_workspace ON trash (workspace_id, deleted_at);
