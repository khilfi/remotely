-- 0.8.0 G5: install configs (VM-28), a catalogue kind beside sizes, images and launch templates (0019). (0034 belongs
-- to G3; a package that needs none leaves its number unused.)
--
-- install_configs: an answer file an unattended install reads: Ubuntu autoinstall (YAML), Kickstart, Debian preseed,
--   cloud-init user data, or Windows unattend (autounattend.xml). `body` is the file as the editor shows it, with
--   Remotely's {{placeholders}} (remotely_core::catalog::install): {{hostname}}, {{ip}}, {{n}}, {{template}}, {{date}},
--   the config's own variables, and {{password.<name>}} / {{ssh_key.<name>}} for what comes from the vault.
--   `variables` is JSON [{"name": "...", "default": "..." | null}]; `secrets` is JSON
--   [{"name": "...", "kind": "password" | "sshKey", "secretId": "<vault item id>" | null}], so the file never holds a
--   password, a hash or a private key: the core refuses to save one. A password reaches a rendered file only as a
--   SHA-512 crypt hash (Windows: a one-time password), at render time, and the rendered file is never stored here.
--   secretId is not a foreign key: a config whose vault item was deleted stays and says why it can't render.
--   Names are unique per workspace. The starter library is part of the app (remotely_core::catalog::install::starters),
--   not rows here. Edits are audited (`catalog_changed`, no approval tier), refused by the read-only lock, carried by the
--   FD-07 export (without any secret) and go to the trash (QL-27).
--
-- catalog_templates.install_config_id: the install config a launch template's deploys use (G6 delivers it), an own
--   config's id or a starter's; NULL for none. Not a foreign key either, as image_id isn't.
--
-- trash: takes the kind 'install_config'. SQLite can't change a CHECK constraint in place, so the table is rebuilt
--   with the same columns, in the same order, and its rows, as 0023 did for job_targets.

CREATE TABLE install_configs (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL COLLATE NOCASE,
    kind          TEXT NOT NULL CHECK (kind IN ('autoinstall', 'kickstart', 'preseed', 'cloud_init', 'unattend')),
    body          TEXT NOT NULL,
    variables     TEXT NOT NULL DEFAULT '[]',
    secrets       TEXT NOT NULL DEFAULT '[]',
    notes         TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (workspace_id, name)
);

ALTER TABLE catalog_templates ADD COLUMN install_config_id TEXT;

CREATE TABLE trash_new (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    kind          TEXT NOT NULL CHECK (kind IN ('session', 'command', 'size', 'image', 'template', 'stack',
                                                'install_config')),
    item_id       TEXT NOT NULL,
    name          TEXT NOT NULL,
    place         TEXT NOT NULL,
    detail        TEXT NOT NULL DEFAULT '',
    snapshot      TEXT NOT NULL,
    deleted_at    TEXT NOT NULL
);

INSERT INTO trash_new (id, workspace_id, user_id, kind, item_id, name, place, detail, snapshot, deleted_at)
SELECT id, workspace_id, user_id, kind, item_id, name, place, detail, snapshot, deleted_at FROM trash;

DROP TABLE trash;

ALTER TABLE trash_new RENAME TO trash;

CREATE INDEX trash_by_workspace ON trash (workspace_id, deleted_at);
