-- VM-01: every VM, not only running ones, from Workstation's library, user-chosen folders and
-- `vmrun list`.

-- The OS name the guest reported through VMware Tools (e.g. "Ubuntu 24.04 LTS"); guest_os stays
-- Workstation's id (e.g. "ubuntu-64").
ALTER TABLE vms ADD COLUMN guest_os_name TEXT;

-- 1 when the last refresh did not find the VM: removed from the library, folder no longer chosen,
-- drive unplugged. The row stays, so its tags, label and protection (AP-04) come back with it.
ALTER TABLE vms ADD COLUMN missing INTEGER NOT NULL DEFAULT 0 CHECK (missing IN (0, 1));

CREATE INDEX target_tags_by_target ON target_tags (target_kind, target_id);
