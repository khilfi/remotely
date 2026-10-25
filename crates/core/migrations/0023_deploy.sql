-- 0.5.0 R2: deploy (VM-10, VM-21, VM-22). What a launch template adds for its deploys.
--
-- guest_user: the user cloud-init makes on first boot (VM-22), with sudo and the template's SSH public key. NULL:
--   the image's own default user (ubuntu, debian...) gets the key instead.
-- packages: a JSON list of package names cloud-init installs on first boot; '[]' for none.
-- clone_mode: how a golden VM image is cloned: 'full' (a copy that stands alone, the default) or 'linked' (shares
--   the golden VM's snapshot disk: quicker and smaller, but it needs that snapshot, and its disk can't grow).
--
-- The user data never holds a password: the .vmx and the NoCloud seed are readable on this PC. Templates saved
-- before 0.5.0 R2 get no guest user, no packages and full clones.

ALTER TABLE catalog_templates ADD COLUMN guest_user TEXT;
ALTER TABLE catalog_templates ADD COLUMN packages TEXT NOT NULL DEFAULT '[]';
ALTER TABLE catalog_templates ADD COLUMN clone_mode TEXT NOT NULL DEFAULT 'full'
    CHECK (clone_mode IN ('full', 'linked'));
