-- 0.8.0 G7: golden image builds (VM-30).
--
-- "Build an image" installs one VM from an install config through G6's unattended deploy, makes it generic, shuts it
-- down and snapshots it (powered off, no memory). Each build is a new VM: a version is that VM and its one snapshot.
--
-- catalog_images.build: the recipe of an image Remotely builds (JSON, remotely_core::golden::BuildRecipe: the ISO
--   image, the install config, the size, the hypervisor and its network, the folder, the config's own values, the
--   versions kept). NULL for every other image. The image's own vm_key, snapshot_id and snapshot_name always name
--   its newest version, so launch templates and deploys that use it deploy that one, as before.
--
-- image_versions: every version an image's builds made, newest first by number (1, 2, 3...; a number is never used
--   twice for one image). vm_key is the version's VM (a .vmx path or a VirtualBox UUID), snapshot_id the snapshot
--   its clones are made from (Workstation's snapshotN.uid, VirtualBox's snapshot UUID). config_id and
--   config_fingerprint are the install config it was built from and its SHA-256 then
--   (remotely_core::deploy::spec::config_fingerprint), never the file: a Windows image's clones read that config's
--   passes, and refuse when it changed since.
--   facts is what making it generic found (JSON: cloud-init, the guest tools...). deleted_at is set when retention
--   or the owner deleted the version's VM (then an image that deployed it deploys its newest version left); the row
--   stays so the number is never used again. Only a version newer than every other moves the image. A version a
--   linked clone still depends on is never deleted (VM-04's guard); its row stays as it is, and a later build tries
--   again.
--   image_id is not a foreign key: a deleted image's rows go to the trash with it (QL-27) and come back with it.
--
-- Both carry workspace_id and user_id (rule 5); the job that built a version is named by job_id.

ALTER TABLE catalog_images ADD COLUMN build TEXT;

CREATE TABLE image_versions (
    id                  TEXT PRIMARY KEY,
    workspace_id        TEXT NOT NULL REFERENCES workspaces(id),
    user_id             TEXT NOT NULL REFERENCES users(id),
    image_id            TEXT NOT NULL,
    number              INTEGER NOT NULL CHECK (number >= 1),
    hypervisor          TEXT NOT NULL CHECK (hypervisor IN ('vmware', 'virtualbox')),
    vm_key              TEXT NOT NULL,
    vm_name             TEXT NOT NULL,
    snapshot_id         TEXT NOT NULL,
    snapshot_name       TEXT NOT NULL,
    config_id           TEXT NOT NULL,
    config_name         TEXT NOT NULL,
    config_fingerprint  TEXT NOT NULL,
    facts               TEXT NOT NULL DEFAULT '{}',
    job_id              TEXT,
    built_at            TEXT NOT NULL,
    deleted_at          TEXT,
    UNIQUE (workspace_id, image_id, number)
);

CREATE INDEX image_versions_by_image ON image_versions (workspace_id, image_id, number);
