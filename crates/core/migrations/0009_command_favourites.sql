-- Post-MVP P5: BX-08 favourite commands, for the Terminal page's command panel.
--
-- One row per saved command: its folder ('' for none: one level of folders, named by the user), its
-- place in that folder, a name, the command text (it may hold {{variables}}, asked when it is pasted)
-- and an optional description. The built-in library is part of the app, not stored here. Commands are
-- the user's own text, like a session's startup command; the vault keeps secrets, not this table.
CREATE TABLE command_favourites (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    folder        TEXT NOT NULL DEFAULT '' COLLATE NOCASE,
    position      INTEGER NOT NULL,
    name          TEXT NOT NULL COLLATE NOCASE,
    command       TEXT NOT NULL,
    description   TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (workspace_id, folder, name)
);

CREATE INDEX command_favourites_by_place ON command_favourites (workspace_id, folder, position);
