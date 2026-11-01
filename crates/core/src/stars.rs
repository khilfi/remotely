//! QL-26 stars and recents, per workspace.
//!
//! * A star marks a session, a VM or a command (a saved one, `favourite:<id>`, or a built-in one, `library:<id>`), so
//!   it comes first in the session tree, the VMs list and Ctrl+K. The window calls them "starred" (BX-08's saved
//!   commands are already its "favourites").
//! * Recents: the [`MAX_RECENTS`] sessions, VMs and pages opened last, newest first, for Ctrl+K's and the Terminal
//!   page's "Recent". A terminal opening notes its session here by itself (`Store::record_session_opened`).
//! * Like the notification centre (QL-25), neither is audited and the read-only lock leaves them alone: they change
//!   only how the window orders what it shows. Stars are kept by key, not by foreign key, so a session restored from
//!   the trash (QL-27) keeps its star; one whose item is gone is simply not shown.

use serde::{Deserialize, Serialize};

use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::store::Store;

/// Recently opened items kept per workspace.
pub const MAX_RECENTS: usize = 20;
/// Stars kept per workspace.
pub const MAX_STARS: i64 = 2000;
/// The longest key (a VM's .vmx path is the long one).
const MAX_KEY: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StarKind {
    Session,
    Vm,
    Command,
}

impl StarKind {
    pub fn as_str(self) -> &'static str {
        match self {
            StarKind::Session => "session",
            StarKind::Vm => "vm",
            StarKind::Command => "command",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "session" => Some(StarKind::Session),
            "vm" => Some(StarKind::Vm),
            "command" => Some(StarKind::Command),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecentKind {
    Session,
    Vm,
    Page,
}

impl RecentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RecentKind::Session => "session",
            RecentKind::Vm => "vm",
            RecentKind::Page => "page",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "session" => Some(RecentKind::Session),
            "vm" => Some(RecentKind::Vm),
            "page" => Some(RecentKind::Page),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Star {
    pub kind: StarKind,
    pub key: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recent {
    pub kind: RecentKind,
    pub key: String,
    pub opened_at: String,
}

/// A key as given: trimmed, one line, not too long.
fn clean_key(key: &str) -> Result<String> {
    let key = key.trim();
    if key.is_empty() || key.chars().count() > MAX_KEY || key.chars().any(char::is_control) {
        return Err(CoreError::InvalidInput(
            "That item can't be starred or kept as recent.".into(),
        ));
    }
    Ok(key.to_owned())
}

#[derive(Clone)]
pub struct Stars {
    store: Store,
}

impl Stars {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    pub async fn list(&self, ctx: &Context) -> Result<Vec<Star>> {
        self.store.list_stars(ctx).await
    }

    /// Stars `key` or takes its star off; returns every star. Not audited; the read-only lock allows it.
    pub async fn set(&self, ctx: &Context, kind: StarKind, key: &str, starred: bool) -> Result<Vec<Star>> {
        let key = clean_key(key)?;
        if starred && self.store.count_stars(ctx).await? >= MAX_STARS {
            return Err(CoreError::InvalidInput(format!(
                "A workspace keeps at most {MAX_STARS} starred items."
            )));
        }
        self.store.set_star(ctx, kind, &key, starred).await?;
        self.list(ctx).await
    }

    /// The items opened last, newest first.
    pub async fn recents(&self, ctx: &Context) -> Result<Vec<Recent>> {
        self.store.list_recents(ctx).await
    }

    /// Notes that `key` was opened now (a VM's details, a page; a session's terminal notes itself). Not audited; the
    /// read-only lock allows it.
    pub async fn opened(&self, ctx: &Context, kind: RecentKind, key: &str) -> Result<Vec<Recent>> {
        let key = clean_key(key)?;
        self.store.note_recent(ctx, kind, &key).await?;
        self.recents(ctx).await
    }
}
