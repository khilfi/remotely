-- SS-09: the public half of the SSH keys in the vault.
--
-- The private key is a `private_key` item in vault_items, encrypted like every secret. This table only
-- holds what is public anyway (the OpenSSH public key line, its SHA-256 fingerprint and comment), so the
-- key manager can show and copy a public key while the vault is locked, and push it to hosts. A row is
-- written when Remotely generates a key, or when it first reads the public half of a private key that
-- was added another way. Deleting the vault item deletes the row; replacing its value deletes the row
-- too (store::vault), since the public half no longer matches.
CREATE TABLE ssh_keys (
    secret_id     TEXT PRIMARY KEY REFERENCES vault_items(id) ON DELETE CASCADE,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    algorithm     TEXT NOT NULL,                       -- ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256, ...
    public_key    TEXT NOT NULL,                       -- "<algorithm> <base64> <comment>"
    fingerprint   TEXT NOT NULL,                       -- SHA256:...
    bits          INTEGER,                             -- RSA modulus size
    generated     INTEGER NOT NULL DEFAULT 0 CHECK (generated IN (0, 1)),  -- made by Remotely
    created_at    TEXT NOT NULL
);
