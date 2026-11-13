//! SS-14 (0.8.0 G3): bookmarks on the Files page: named folders on a saved session's host, per workspace (rule 8).
//!
//! * A bookmark is the user's own data, like a favourite command: adding, renaming and removing one is audited
//!   (`file_bookmark_changed`, the session as its target) and refused by the read-only lock ([`Change::FileBookmarks`]).
//!   Nothing here touches a host, so it skips the command bus. Opening one is just listing its folder (a read).
//! * The path is checked like every path the window sends ([`check_path`]): absolute, never resolved, no control or
//!   invisible formatting character. The name is one line of at most [`MAX_NAME_CHARS`] characters.
//! * A session's bookmarks go to the trash with it (QL-27) and come back with it, and travel in FD-07 exports with it.
//!   A quick connection that was not saved has none: there is no session to keep them by.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{Context, Target};
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::store::{NewAuditEntry, Store};
use crate::terminal::file_ops::check_path;
use crate::untrusted::is_format_char;

/// Bookmarks kept per session.
pub const MAX_BOOKMARKS: usize = 100;
/// The longest name, in characters.
pub const MAX_NAME_CHARS: usize = 80;

/// One bookmark, as the Files page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bookmark {
    pub id: Uuid,
    pub session_id: Uuid,
    pub name: String,
    /// The host's folder, absolute.
    pub path: String,
    pub created_at: String,
    pub updated_at: String,
}

/// A name as kept: trimmed, one line, no control or invisible formatting character.
pub fn clean_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CoreError::InvalidInput("Give the bookmark a name.".into()));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(CoreError::InvalidInput(format!(
            "A bookmark's name can be at most {MAX_NAME_CHARS} characters."
        )));
    }
    if name
        .chars()
        .any(|c| c.is_control() || is_format_char(c) || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return Err(CoreError::InvalidInput(
            "A bookmark's name can't hold control or invisible formatting characters.".into(),
        ));
    }
    Ok(name.to_owned())
}

/// The default name of a bookmark of `path`: its last folder, or `/`.
pub fn default_name(path: &str) -> String {
    let last = path.rsplit('/').find(|p| !p.is_empty()).unwrap_or("/");
    last.chars().take(MAX_NAME_CHARS).collect()
}

#[derive(Clone)]
pub struct Bookmarks {
    store: Store,
}

impl Bookmarks {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// The session's target, or why it isn't one of this workspace's.
    async fn session(&self, ctx: &Context, session_id: Uuid) -> Result<Target> {
        let session = self
            .store
            .get_session(ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("session {session_id}")))?;
        Ok(session.target())
    }

    /// The session's bookmarks, in their order.
    pub async fn list(&self, ctx: &Context, session_id: Uuid) -> Result<Vec<Bookmark>> {
        self.store.list_bookmarks(ctx, Some(session_id)).await
    }

    /// Every bookmark in the workspace (QL-20 search, FD-07).
    pub async fn all(&self, ctx: &Context) -> Result<Vec<Bookmark>> {
        self.store.list_bookmarks(ctx, None).await
    }

    /// Adds a bookmark of `path` on the session's host; `name` empty: the folder's name. A path bookmarked already is
    /// refused, saying under which name. Audited; refused while presenting with the lock on.
    pub async fn add(&self, ctx: &Context, session_id: Uuid, name: &str, path: &str) -> Result<Bookmark> {
        self.store.read_only().check(Change::FileBookmarks)?;
        check_path(path)?;
        let name = if name.trim().is_empty() {
            default_name(path)
        } else {
            clean_name(name)?
        };
        let target = self.session(ctx, session_id).await?;
        let there = self.list(ctx, session_id).await?;
        if let Some(same) = there.iter().find(|b| b.path == path) {
            return Err(CoreError::InvalidInput(format!(
                "That folder is bookmarked already, as '{}'.",
                same.name
            )));
        }
        if there.len() >= MAX_BOOKMARKS {
            return Err(CoreError::InvalidInput(format!(
                "A session keeps at most {MAX_BOOKMARKS} bookmarks; remove one first."
            )));
        }
        let position = there.len() as i64;
        let bookmark = self
            .store
            .insert_bookmark(ctx, session_id, &name, path, position)
            .await?;
        self.audit(
            ctx,
            &format!("Bookmarked a folder on '{}'", target.name),
            &target,
            &format!("'{name}': {path}"),
        )
        .await?;
        Ok(bookmark)
    }

    /// Renames a bookmark. Audited; an unchanged name writes nothing.
    pub async fn rename(&self, ctx: &Context, id: Uuid, name: &str) -> Result<Bookmark> {
        self.store.read_only().check(Change::FileBookmarks)?;
        let name = clean_name(name)?;
        let before = self
            .store
            .get_bookmark(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget("bookmark".into()))?;
        if before.name == name {
            return Ok(before);
        }
        let target = self.session(ctx, before.session_id).await?;
        self.store.rename_bookmark(ctx, id, &name).await?;
        self.audit(
            ctx,
            &format!("Renamed a bookmark on '{}'", target.name),
            &target,
            &format!("'{}' is '{name}' now ({})", before.name, before.path),
        )
        .await?;
        self.store
            .get_bookmark(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget("bookmark".into()))
    }

    /// Removes a bookmark. Audited. False when there was none.
    pub async fn remove(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        self.store.read_only().check(Change::FileBookmarks)?;
        let Some(before) = self.store.get_bookmark(ctx, id).await? else {
            return Ok(false);
        };
        let target = self.session(ctx, before.session_id).await?;
        self.store.delete_bookmark(ctx, id).await?;
        self.audit(
            ctx,
            &format!("Removed a bookmark on '{}'", target.name),
            &target,
            &format!("'{}': {}", before.name, before.path),
        )
        .await?;
        Ok(true)
    }

    /// FD-07: bookmarks that came with an imported session (name, path), each one whose path isn't bookmarked there yet
    /// and that passes the checks, up to [`MAX_BOOKMARKS`]; audited once. How many were added. The import itself is
    /// refused by the read-only lock (its own edit kind).
    pub async fn import(
        &self,
        ctx: &Context,
        session_id: Uuid,
        marks: &[(String, String)],
        source: &str,
    ) -> Result<usize> {
        let target = self.session(ctx, session_id).await?;
        let mut there = self.list(ctx, session_id).await?;
        let mut added = 0;
        for (name, path) in marks {
            if there.len() >= MAX_BOOKMARKS || check_path(path).is_err() || there.iter().any(|b| &b.path == path) {
                continue;
            }
            let name = clean_name(name).unwrap_or_else(|_| default_name(path));
            let saved = self
                .store
                .insert_bookmark(ctx, session_id, &name, path, there.len() as i64)
                .await?;
            there.push(saved);
            added += 1;
        }
        if added > 0 {
            self.audit(
                ctx,
                &format!("Imported bookmarks on '{}'", target.name),
                &target,
                &format!("{added} bookmark(s) from {source}"),
            )
            .await?;
        }
        Ok(added)
    }

    async fn audit(&self, ctx: &Context, action: &str, target: &Target, detail: &str) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "file_bookmark_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: std::slice::from_ref(target),
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_one_line_and_paths_name_a_default() {
        assert_eq!(clean_name("  web root ").unwrap(), "web root");
        assert!(clean_name("").is_err());
        assert!(clean_name("a\nb").is_err());
        assert!(clean_name("logs\u{202E}gol").is_err());
        assert!(clean_name(&"x".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert_eq!(default_name("/srv/www"), "www");
        assert_eq!(default_name("/"), "/");
    }
}
