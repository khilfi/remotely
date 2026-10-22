-- 0.4.0 Q7: host details (MO-13).
--
-- The latest OS and hardware facts of each saved SSH session and each VM, so their details still show while
-- the host is offline or the VM's files can't be read. A new reading replaces the row; no history is kept.
-- The facts are a cache of reads: nothing here is audited, and the FD-07 export leaves them out.
--
-- session_specs
--   specs         JSON (remotely_core::host_details::HostSpecs): OS, kernel, CPU, memory, disks, filesystems
--   collected_at  when it was read (RFC 3339)
--   collected_by  what read it: 'terminal' (a terminal's own connection when it opened), 'dashboard' (the MO-02
--                 poll's kept connection, at most every few hours) or 'refresh' (the user asked)
--
-- vm_specs
--   specs         JSON (remotely_core::adapters::vm_hardware::VmHardware): vCPUs, memory, firmware, virtual
--                 disks with their sizes, network adapters with their MACs
--   collected_at  when the VM's files were read

CREATE TABLE session_specs (
    session_id    TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    specs         TEXT NOT NULL,
    collected_at  TEXT NOT NULL,
    collected_by  TEXT NOT NULL CHECK (collected_by IN ('terminal', 'dashboard', 'refresh'))
);

CREATE INDEX session_specs_by_workspace ON session_specs (workspace_id);

CREATE TABLE vm_specs (
    vm_id         TEXT PRIMARY KEY REFERENCES vms(id) ON DELETE CASCADE,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    specs         TEXT NOT NULL,
    collected_at  TEXT NOT NULL
);

CREATE INDEX vm_specs_by_workspace ON vm_specs (workspace_id);
