-- 0.5.0 R6: stacks (VM-08). A stack is a named set of launch templates, each with a count, in boot order, with a
-- delay and a readiness check between steps; deploying one makes a stack instance, whose VMs show as a group and
-- start, stop and tear down together.
--
-- Stacks are the app's own data, like the catalogue: edits are audited (`stack_changed`, no approval tier), refused
-- by the read-only lock, and carried by the FD-07 export. Instances are this PC's own VMs, so the export leaves them
-- out. Every row carries workspace_id and user_id.
--
-- stacks.steps: JSON, in boot order: [{"templateId": "<uuid>", "count": 1..50, "readiness": {"kind": "none"} |
--   {"kind": "tools"} | {"kind": "sshPort", "port": 22}, "readyTimeoutSecs": 30..3600, "delaySecs": 0..3600}].
--   templateId names a launch template but is not a foreign key, so a stack whose template was deleted stays and
--   says why it can't deploy (as a template does for its image).
--
-- stack_instances: one deploy of a stack. stack_id is the stack it came from (not a foreign key: the stack may be
--   deleted or changed since; stack_name and steps keep what was deployed). steps: JSON, in boot order:
--   [{"label": "<template name>", "readiness": ..., "readyTimeoutSecs": ..., "delaySecs": ...}], what starting the
--   instance waits for between its steps. job_id is the deploy's job.
--
-- stack_instance_vms: which VMs belong to which instance, so teardown deletes exactly those. vm_key is the VM's key
--   (.vmx path or VirtualBox UUID, as vms.vmx_path); a VM belongs to one instance at most. step is its step's index
--   (0 is the first to boot). origin 'deploy': the instance's deploy made it, and its teardown deletes it; 'hand': the
--   user added it, and a teardown keeps it unless the user picks it on purpose.

CREATE TABLE stacks (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL COLLATE NOCASE,
    description   TEXT,
    steps         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (workspace_id, name)
);

CREATE TABLE stack_instances (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    stack_id      TEXT NOT NULL,
    stack_name    TEXT NOT NULL,
    name          TEXT NOT NULL COLLATE NOCASE,
    steps         TEXT NOT NULL,
    job_id        TEXT,
    created_at    TEXT NOT NULL,
    UNIQUE (workspace_id, name)
);

CREATE TABLE stack_instance_vms (
    instance_id   TEXT NOT NULL REFERENCES stack_instances(id) ON DELETE CASCADE,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    vm_key        TEXT NOT NULL COLLATE NOCASE,
    vm_name       TEXT NOT NULL,
    step          INTEGER NOT NULL CHECK (step >= 0),
    origin        TEXT NOT NULL CHECK (origin IN ('deploy', 'hand')),
    added_at      TEXT NOT NULL,
    PRIMARY KEY (workspace_id, vm_key)
);

CREATE INDEX stack_instance_vms_instance ON stack_instance_vms (instance_id, step);
