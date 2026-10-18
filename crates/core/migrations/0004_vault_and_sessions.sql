-- Milestone 3: vault (SS-04, AP-06) and session library (SS-01, SS-06).

-- SS-04, AP-06: `wrapped_key` always holds the data key wrapped by the Argon2id-derived master key
-- (kdf_salt and kdf_params describe it), so the master password unlocks the vault on its own and is
-- what Critical actions ask for again. When the Windows login also unlocks it (unlock_method
-- 'dpapi'), this is a second copy of the data key, protected by DPAPI for the current Windows user.
-- No release ever wrote vault_meta (the vault was a stub until now), so no row needs converting.
ALTER TABLE vault_meta ADD COLUMN dpapi_key BLOB;

-- SS-04: secrets are picked by label in the session editor, so a label names one secret.
CREATE UNIQUE INDEX vault_items_by_label ON vault_items (workspace_id, label COLLATE NOCASE);

-- SS-01: the folder tree.
CREATE INDEX session_folders_by_parent ON session_folders (workspace_id, parent_id);
