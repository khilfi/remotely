-- 0.8.0 G3: bookmarks on the Files page (SS-14).
--
-- file_bookmarks
--   A folder on a saved session's host, named, for the Files page's host pane. Per workspace (rule 5), each row with
--   its user; at most 100 per session (crate::bookmarks). `path` is the host's, absolute and `/`-separated, checked like
--   every path the window sends (crate::terminal::file_ops::check_path). A session that is deleted takes its bookmarks
--   with it: into the trash (QL-27, crate::trash keeps them among the session's rows and puts them back on restore), and
--   ON DELETE CASCADE for the session row's hard delete there. They travel in FD-07 exports with their session.
--   Adding, renaming and removing one is audited (`file_bookmark_changed`) and refused by the read-only lock.
--
-- Numbered 0034, which the plan gave G3. 0035 (G5) and 0039 (G2) were merged first; sqlx applies a migration it has
-- not seen whatever its number, so a database that ran them first takes this one next.

CREATE TABLE file_bookmarks (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    session_id    TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    path          TEXT NOT NULL,
    position      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE INDEX file_bookmarks_by_session ON file_bookmarks (workspace_id, session_id, position);
