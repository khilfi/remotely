-- QL-01: how a session's VM link (sessions.vm_id) was made.
--   NULL     no decision yet: auto-linking may link the session when its host matches a VM's guest IP.
--   'auto'   linked by auto-linking and not confirmed: auto-linking keeps it up to date.
--   'manual' chosen, confirmed or removed by the user (vm_id NULL then): auto-linking never changes it.
ALTER TABLE sessions ADD COLUMN vm_link TEXT CHECK (vm_link IN ('auto', 'manual'));

-- Every link made before 0.3.0 was chosen in the session editor.
UPDATE sessions SET vm_link = 'manual' WHERE vm_id IS NOT NULL;
