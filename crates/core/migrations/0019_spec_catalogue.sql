-- 0.5.0 R1: the spec catalogue (VM-19 sizes, VM-20 images, VM-21 launch templates), what deploy (R2) runs.
--
-- The twelve built-in sizes and the OS profiles are part of the app (remotely_core::catalog), not rows here.
-- Edits are the app's own data: audited like the session library, with no approval tier, refused by the read-only
-- lock, and carried by the FD-07 export. Every row carries workspace_id and user_id.
--
-- catalog_sizes: the owner's own sizes. vCPU is sockets x cores_per_socket; disks is JSON, the boot disk first:
--   [{"sizeGb": 40, "provisioning": "thin" | "thick", "controller": null | "scsi" | "sata" | "nvme" | "ide"}]
--   (a null controller is the OS profile's). Names are unique per workspace, and never a built-in's (the core
--   checks that).
--
-- catalog_images: where a new VM's OS comes from. kind 'golden_vm' names a VM by its key (vm_key: .vmx path or
--   VirtualBox UUID) and one of its snapshots by its id (Workstation's snapshotN.uid, VirtualBox's snapshot UUID;
--   snapshot_name is its name when the image was added). The other kinds name a file (path) and its format.
--   hypervisors: 'vmware', 'virtualbox' or 'vmware,virtualbox'. sha256 and size_bytes are the file's when it was
--   added (none for a golden VM). Paths on network shares are refused before they get here.
--
-- catalog_templates: launch templates. image_id is an image's id and size_id a built-in size's name or an own
--   size's id; neither is a foreign key, so a template whose image or size was deleted stays and says why it
--   can't deploy. network and after_deploy are JSON (remotely_core::catalog::{Network, AfterDeploy}); tags is a
--   JSON list of tag names the deployed VMs get. ssh_key_id names a vault private key, whose public half alone
--   goes to the VMs; it is not a foreign key either, for the same reason.

CREATE TABLE catalog_sizes (
    id                TEXT PRIMARY KEY,
    workspace_id      TEXT NOT NULL REFERENCES workspaces(id),
    user_id           TEXT NOT NULL REFERENCES users(id),
    name              TEXT NOT NULL COLLATE NOCASE,
    sockets           INTEGER NOT NULL CHECK (sockets >= 1),
    cores_per_socket  INTEGER NOT NULL CHECK (cores_per_socket >= 1),
    memory_mb         INTEGER NOT NULL CHECK (memory_mb >= 1),
    disks             TEXT NOT NULL,
    description       TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    UNIQUE (workspace_id, name)
);

CREATE TABLE catalog_images (
    id             TEXT PRIMARY KEY,
    workspace_id   TEXT NOT NULL REFERENCES workspaces(id),
    user_id        TEXT NOT NULL REFERENCES users(id),
    name           TEXT NOT NULL COLLATE NOCASE,
    kind           TEXT NOT NULL CHECK (kind IN ('golden_vm', 'cloud_image', 'iso', 'appliance')),
    path           TEXT,
    format         TEXT CHECK (format IS NULL OR format IN ('vmdk', 'ova', 'ovf', 'raw', 'qcow2', 'iso')),
    vm_key         TEXT,
    snapshot_id    TEXT,
    snapshot_name  TEXT,
    hypervisors    TEXT NOT NULL,
    os_profile     TEXT NOT NULL,
    sha256         TEXT,
    size_bytes     INTEGER,
    notes          TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    UNIQUE (workspace_id, name),
    CHECK ((kind = 'golden_vm' AND vm_key IS NOT NULL AND snapshot_id IS NOT NULL AND path IS NULL)
        OR (kind <> 'golden_vm' AND path IS NOT NULL AND format IS NOT NULL AND vm_key IS NULL))
);

CREATE TABLE catalog_templates (
    id              TEXT PRIMARY KEY,
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    user_id         TEXT NOT NULL REFERENCES users(id),
    name            TEXT NOT NULL COLLATE NOCASE,
    image_id        TEXT NOT NULL,
    size_id         TEXT NOT NULL,
    hypervisor      TEXT NOT NULL CHECK (hypervisor IN ('vmware', 'virtualbox')),
    vm_folder       TEXT,
    network         TEXT NOT NULL,
    ssh_key_id      TEXT,
    naming_pattern  TEXT NOT NULL,
    default_count   INTEGER NOT NULL CHECK (default_count >= 1),
    environment     TEXT NOT NULL DEFAULT 'none' CHECK (environment IN ('none', 'lab', 'staging', 'prod')),
    tags            TEXT NOT NULL DEFAULT '[]',
    after_deploy    TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (workspace_id, name)
);
