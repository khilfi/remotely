-- 0.5.0 R8: sessions and terminals (QL-16 to QL-19). Every new row carries workspace_id and user_id.

-- QL-16 folder defaults. A folder can set the user, the login (a key, a vault password, the SSH agent, or a
-- password asked when connecting), the jump host, the environment label and tags. A session uses its own value
-- first, then the nearest folder up the path that sets one, then the app's default (crate::sessions::defaults):
-- one resolver, used wherever a session is. NULL (or an empty tag list) means "not set here", so the folder above
-- decides. Tags add up: a session has its own and every folder's up the path. There is no "no label" override, so
-- a folder's Prod label can't be taken off a session in it by leaving its label empty; a session or subfolder can
-- choose another label. One row per folder that sets anything; it goes with its folder.
CREATE TABLE session_folder_defaults (
    folder_id          TEXT PRIMARY KEY REFERENCES session_folders(id) ON DELETE CASCADE,
    workspace_id       TEXT NOT NULL REFERENCES workspaces(id),
    user_id            TEXT NOT NULL REFERENCES users(id),
    username           TEXT,
    -- NULL: the folder above decides. 'password' with no credential: asked when connecting.
    auth_method        TEXT CHECK (auth_method IN ('password', 'key', 'agent')),
    credential_id      TEXT REFERENCES vault_items(id) ON DELETE SET NULL,
    key_passphrase_id  TEXT REFERENCES vault_items(id) ON DELETE SET NULL,
    jump_session_id    TEXT REFERENCES sessions(id) ON DELETE SET NULL,
    -- 1: no jump host for the sessions in it, whatever a folder above sets (jump_session_id is then NULL).
    jump_direct        INTEGER NOT NULL DEFAULT 0 CHECK (jump_direct IN (0, 1)),
    environment        TEXT CHECK (environment IN ('lab', 'staging', 'prod')),
    -- Tag names separated by char(31), as checked tags can't hold control characters.
    tags               TEXT NOT NULL DEFAULT '',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    CHECK (jump_direct = 0 OR jump_session_id IS NULL)
);

CREATE INDEX session_folder_defaults_by_workspace ON session_folder_defaults (workspace_id);

-- QL-16: a session's own choices about its folders. auth_from_folder = 1: it logs in as its folders say (its
-- auth_method and credentials are then not used). jump_direct = 1: no jump host, whatever its folders set. Both 0 for
-- every session saved before, so nothing changes until a folder sets something.
ALTER TABLE sessions ADD COLUMN auth_from_folder INTEGER NOT NULL DEFAULT 0 CHECK (auth_from_folder IN (0, 1));
ALTER TABLE sessions ADD COLUMN jump_direct INTEGER NOT NULL DEFAULT 0 CHECK (jump_direct IN (0, 1));

-- QL-17 highlight and alert rules: a regular expression that colours what it matches in terminals, and may also
-- notify when a line matches. Scope: every terminal, the terminals of sessions with an environment label, or one
-- session's. The built-in rules are part of the app (crate::terminal::rules); terminal_builtin_rules keeps only how
-- the user changed them (on or off, alerting or not).
CREATE TABLE terminal_rules (
    id              TEXT PRIMARY KEY,
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    user_id         TEXT NOT NULL REFERENCES users(id),
    name            TEXT NOT NULL COLLATE NOCASE,
    pattern         TEXT NOT NULL,
    case_sensitive  INTEGER NOT NULL DEFAULT 0 CHECK (case_sensitive IN (0, 1)),
    -- A named colour (as session colours); NULL: no highlight, the rule only alerts.
    color           TEXT,
    style           TEXT NOT NULL DEFAULT 'text' CHECK (style IN ('text', 'fill')),
    alert           INTEGER NOT NULL DEFAULT 0 CHECK (alert IN (0, 1)),
    scope           TEXT NOT NULL DEFAULT 'global' CHECK (scope IN ('global', 'environment', 'session')),
    environment     TEXT CHECK (environment IN ('lab', 'staging', 'prod')),
    session_id      TEXT REFERENCES sessions(id) ON DELETE CASCADE,
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    position        INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (workspace_id, name),
    CHECK ((scope = 'environment') = (environment IS NOT NULL)),
    CHECK ((scope = 'session') = (session_id IS NOT NULL))
);

CREATE INDEX terminal_rules_by_place ON terminal_rules (workspace_id, position);

CREATE TABLE terminal_builtin_rules (
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    rule_key      TEXT NOT NULL,
    enabled       INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    alert         INTEGER NOT NULL CHECK (alert IN (0, 1)),
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (workspace_id, rule_key)
);

-- QL-19 saved MultiExec groups ("all web servers"): a named set of saved sessions, in order. Opening a group opens a
-- terminal for each and turns MultiExec on for them; selecting it picks the ones already open. A deleted session
-- leaves its groups.
CREATE TABLE multiexec_groups (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL COLLATE NOCASE,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (workspace_id, name)
);

CREATE TABLE multiexec_group_members (
    group_id      TEXT NOT NULL REFERENCES multiexec_groups(id) ON DELETE CASCADE,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    session_id    TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    position      INTEGER NOT NULL,
    PRIMARY KEY (group_id, session_id)
);

CREATE INDEX multiexec_group_members_by_session ON multiexec_group_members (session_id);
