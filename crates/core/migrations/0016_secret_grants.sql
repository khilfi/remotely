-- SS-04, AP-06: where a vault password may go without the vault password being asked again.
--
-- A password or passphrase from the vault goes to a host when a session logs in with it, when sudo gets it
-- (a container host's mark, a Compare run), or when it is typed into a terminal (QL-06). It may go without
-- asking to the hosts of the sessions that already use it: as their login password, as a container mark's
-- sudo password, or through a row here. Any other host needs the master password first; for a saved
-- session the answer adds a row, so the next time is free. Deleting the session or the secret deletes its
-- rows. Private keys and their passphrases never leave this PC (a login only signs with them), so they
-- need no row.

CREATE TABLE session_secret_grants (
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    session_id    TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    secret_id     TEXT NOT NULL REFERENCES vault_items(id) ON DELETE CASCADE,
    granted_at    TEXT NOT NULL,
    PRIMARY KEY (session_id, secret_id)
);

CREATE INDEX session_secret_grants_by_secret ON session_secret_grants (workspace_id, secret_id);
