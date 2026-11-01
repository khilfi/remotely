//! QL-27 trash: a deleted session, saved command, size, image, launch template or stack is kept for [`KEEP_DAYS`] days,
//! and can be put back.
//!
//! * Deleting one moves a snapshot of its rows into the `trash` table, with what hangs off it: a session's port
//!   forwards, VM link (its own columns), container host marks, places in saved (MultiExec) groups, its own highlight
//!   and alert rules (QL-17), the vault passwords it was allowed to send, its tags and its note ([`rows`] keeps each row column by column). The live tables keep their hard
//!   deletes, in the same transaction, so no read of them changes.
//! * Restore puts the rows back under the item's own id (a template finds its image again, a group its session; a
//!   session id taken since gets a new one). A name taken since gets " (restored)". A folder, jump host, VM, vault item
//!   or saved group that is gone is left out, with a note; a template whose image or size is gone, or a stack whose
//!   template is gone, comes back and says why it can't deploy, as it would have. SS-04, AP-06: a restored session that
//!   would send a vault password somewhere it didn't go before it was deleted (a jump host gone, or a folder whose login
//!   changed) asks for the vault password, as an edit would.
//! * Restore, Delete now and Empty trash are audited (`trash_restored`, `trash_deleted`, `trash_emptied`) and refused by
//!   the read-only lock; moving to the trash is part of the delete's own entry. Entries older than [`KEEP_DAYS`] days are
//!   purged at start and daily, in every workspace (`trash_purged` when it removed something), like BX-02's journal.
//! * Per workspace (FD-02); never in an FD-07 export. A session's vault secrets stay in the vault, as before: the trash
//!   keeps only their ids.

pub mod rows;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use self::rows::RowValues;
use crate::domain::{now_rfc3339, Context, Environment, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::sessions::{OwnValues, SessionAuth};
use crate::store::{NewAuditEntry, Store};
use crate::vault::{Destination, SecretBindings, SecretId, SecretString};
use crate::workspaces::Current;

/// How long a deleted item is kept.
pub const KEEP_DAYS: i64 = 30;
/// How often the purge runs, by the wall clock.
const PURGE_EVERY: time::Duration = time::Duration::hours(24);
/// How often the purge loop looks at the clock.
const TICK: Duration = Duration::from_secs(10 * 60);

/// What was deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrashKind {
    Session,
    /// BX-08: a favourite (saved) command.
    Command,
    Size,
    Image,
    Template,
    Stack,
}

impl TrashKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TrashKind::Session => "session",
            TrashKind::Command => "command",
            TrashKind::Size => "size",
            TrashKind::Image => "image",
            TrashKind::Template => "template",
            TrashKind::Stack => "stack",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "session" => Some(TrashKind::Session),
            "command" => Some(TrashKind::Command),
            "size" => Some(TrashKind::Size),
            "image" => Some(TrashKind::Image),
            "template" => Some(TrashKind::Template),
            "stack" => Some(TrashKind::Stack),
            _ => None,
        }
    }

    /// "session", "saved command"...
    pub fn noun(self) -> &'static str {
        match self {
            TrashKind::Session => "session",
            TrashKind::Command => "favourite command",
            TrashKind::Size => "size",
            TrashKind::Image => "image",
            TrashKind::Template => "launch template",
            TrashKind::Stack => "stack",
        }
    }

    fn table(self) -> &'static str {
        match self {
            TrashKind::Session => "sessions",
            TrashKind::Command => "command_favourites",
            TrashKind::Size => "catalog_sizes",
            TrashKind::Image => "catalog_images",
            TrashKind::Template => "catalog_templates",
            TrashKind::Stack => "stacks",
        }
    }

    /// The longest name the item may have, for " (restored)".
    fn max_name(self) -> usize {
        match self {
            TrashKind::Session => crate::sessions::MAX_SESSION_NAME,
            TrashKind::Command => crate::snippets::MAX_NAME,
            TrashKind::Size => crate::catalog::sizes::MAX_SIZE_NAME,
            TrashKind::Image => crate::catalog::images::MAX_IMAGE_NAME,
            TrashKind::Template => crate::catalog::templates::MAX_TEMPLATE_NAME,
            TrashKind::Stack => crate::stacks::spec::MAX_NAME,
        }
    }

    /// How many a workspace keeps, if there is a limit.
    fn most(self) -> Option<usize> {
        match self {
            TrashKind::Session => None,
            TrashKind::Command => Some(crate::snippets::MAX_FAVOURITES),
            TrashKind::Size => Some(crate::catalog::sizes::MAX_SIZES),
            TrashKind::Image => Some(crate::catalog::images::MAX_IMAGES),
            TrashKind::Template => Some(crate::catalog::templates::MAX_TEMPLATES),
            TrashKind::Stack => Some(crate::stacks::spec::MAX_STACKS),
        }
    }

    /// Rows that hang off the item and go with it: (table, column naming the item).
    fn attached(self) -> &'static [(&'static str, &'static str)] {
        match self {
            TrashKind::Session => &[
                ("port_forwards", "session_id"),
                ("container_hosts", "session_id"),
                ("multiexec_group_members", "session_id"),
                ("session_secret_grants", "session_id"),
                ("terminal_rules", "session_id"),
            ],
            _ => &[],
        }
    }
}

/// A row that went with the item.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Attached {
    table: String,
    row: RowValues,
}

/// SS-04, AP-06: where a session went and what it sent when it was deleted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SentThen {
    host: String,
    port: u16,
    jump: Option<Uuid>,
    secrets: Vec<Uuid>,
}

/// `trash.snapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Snapshot {
    row: RowValues,
    #[serde(default)]
    attached: Vec<Attached>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    note: Option<RowValues>,
    #[serde(default)]
    sent: Option<SentThen>,
    /// Sessions and folders whose own jump host it was: they lost it with the delete and stay without it.
    #[serde(default)]
    jump_users: Vec<String>,
}

/// One item in the trash, as Settings lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashEntry {
    pub id: Uuid,
    pub kind: TrashKind,
    /// The deleted item's id.
    pub item_id: String,
    pub name: String,
    /// Where it was ("Sessions › Customer A", "Templates › Sizes").
    pub place: String,
    /// What came along ("2 port forwards, its note").
    pub detail: String,
    pub deleted_at: String,
    /// When the daily purge removes it.
    pub expires_at: String,
}

/// What a restore did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreReport {
    pub kind: TrashKind,
    /// Its id now (a new one when its own was taken).
    pub item_id: String,
    /// Its name now (with " (restored)" when its own was taken).
    pub name: String,
    /// What was left out or changed, in words.
    pub notes: Vec<String>,
}

/// What a purge removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashPurge {
    pub at: String,
    pub removed: usize,
}

/// What a delete moves to the trash. The caller has checked the item exists and the lock.
pub(crate) struct TrashItem<'a> {
    pub kind: TrashKind,
    pub item_id: &'a str,
    pub name: &'a str,
    pub place: String,
    /// A session's place and the vault passwords it sends (SS-04), for its restore.
    pub sent: Option<(Destination, Vec<SecretId>)>,
    /// A session's: the sessions (by name) and folders ("folder 'X'") whose own jump host it is.
    pub jump_users: Vec<String>,
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Moves the item's rows into the trash, in one transaction with the delete. `None` when there is no such item.
pub(crate) async fn move_to_trash(store: &Store, ctx: &Context, item: TrashItem<'_>) -> Result<Option<TrashEntry>> {
    let ws = ctx.workspace_id.to_string();
    let mut tx = store.pool().begin().await?;
    let kind = item.kind;
    let mut found = rows::read(&mut tx, kind.table(), "id", item.item_id, &ws).await?;
    let Some(row) = found.pop() else {
        return Ok(None);
    };
    let mut attached = Vec::new();
    for (table, column) in kind.attached() {
        for row in rows::read(&mut tx, table, column, item.item_id, &ws).await? {
            attached.push(Attached {
                table: (*table).to_owned(),
                row,
            });
        }
    }
    let mut tags = Vec::new();
    let mut note = None;
    if kind == TrashKind::Session {
        tags = sqlx::query_scalar(
            "SELECT t.name FROM target_tags tt JOIN tags t ON t.id = tt.tag_id
             WHERE tt.target_kind = 'session' AND tt.target_id = ? AND t.workspace_id = ? ORDER BY t.name",
        )
        .bind(item.item_id)
        .bind(&ws)
        .fetch_all(&mut *tx)
        .await?;
        let notes =
            sqlx::query("SELECT * FROM notes WHERE workspace_id = ? AND target_kind = 'session' AND target_key = ?")
                .bind(&ws)
                .bind(item.item_id)
                .fetch_all(&mut *tx)
                .await?;
        note = notes.first().map(rows::to_json).transpose()?;
        // MO-08: its health checks, so none is left pointing at a deleted session. Their results stay out of the
        // trash (a check every minute keeps 10,000 a week) and go with them.
        let checks = sqlx::query(
            "SELECT * FROM health_checks WHERE workspace_id = ? AND target_kind = 'session' AND target_key = ?",
        )
        .bind(&ws)
        .bind(item.item_id)
        .fetch_all(&mut *tx)
        .await?;
        for row in &checks {
            attached.push(Attached {
                table: "health_checks".to_owned(),
                row: rows::to_json(row)?,
            });
        }
    }
    let count = |table: &str| attached.iter().filter(|a| a.table == table).count();
    let mut came = Vec::new();
    match count("port_forwards") {
        0 => {}
        n => came.push(plural(n, "port forward")),
    }
    if count("container_hosts") > 0 {
        came.push("its container host mark".to_owned());
    }
    match count("multiexec_group_members") {
        0 => {}
        1 => came.push("its place in 1 saved group".to_owned()),
        n => came.push(format!("its places in {n} saved groups")),
    }
    match count("terminal_rules") {
        0 => {}
        n => came.push(plural(n, "highlight rule")),
    }
    match count("health_checks") {
        0 => {}
        n => came.push(plural(n, "health check")),
    }
    if note.is_some() {
        came.push("its note".to_owned());
    }
    let detail = came.join(", ");
    let snapshot = Snapshot {
        row,
        attached,
        tags,
        note,
        sent: item.sent.map(|(place, secrets)| SentThen {
            host: place.host,
            port: place.port,
            jump: place.jump,
            secrets: secrets.into_iter().map(|s| s.0).collect(),
        }),
        jump_users: item.jump_users,
    };
    let id = Uuid::new_v4();
    let now = now_rfc3339();
    sqlx::query(
        "INSERT INTO trash (id, workspace_id, user_id, kind, item_id, name, place, detail, snapshot, deleted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(&ws)
    .bind(ctx.user_id.to_string())
    .bind(kind.as_str())
    .bind(item.item_id)
    .bind(item.name)
    .bind(&item.place)
    .bind(&detail)
    .bind(serde_json::to_string(&snapshot)?)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    if kind == TrashKind::Session {
        sqlx::query("DELETE FROM target_tags WHERE target_kind = 'session' AND target_id = ?")
            .bind(item.item_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM notes WHERE workspace_id = ? AND target_kind = 'session' AND target_key = ?")
            .bind(&ws)
            .bind(item.item_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM health_checks WHERE workspace_id = ? AND target_kind = 'session' AND target_key = ?")
            .bind(&ws)
            .bind(item.item_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM \"{}\" WHERE workspace_id = ? AND id = ?",
        kind.table()
    )))
    .bind(&ws)
    .bind(item.item_id)
    .execute(&mut *tx)
    .await?;
    if kind == TrashKind::Session {
        crate::store::delete_unused_tags(&mut tx, ctx).await?;
    }
    tx.commit().await?;
    Ok(Some(entry(
        id,
        kind,
        item.item_id,
        item.name,
        &item.place,
        &detail,
        &now,
    )))
}

fn expires(deleted_at: &str) -> String {
    OffsetDateTime::parse(deleted_at, &Rfc3339)
        .ok()
        .and_then(|at| (at + time::Duration::days(KEEP_DAYS)).format(&Rfc3339).ok())
        .unwrap_or_default()
}

fn entry(id: Uuid, kind: TrashKind, item_id: &str, name: &str, place: &str, detail: &str, at: &str) -> TrashEntry {
    TrashEntry {
        id,
        kind,
        item_id: item_id.to_owned(),
        name: name.to_owned(),
        place: place.to_owned(),
        detail: detail.to_owned(),
        deleted_at: at.to_owned(),
        expires_at: expires(at),
    }
}

fn row_to_entry(row: &sqlx::sqlite::SqliteRow) -> Result<Option<TrashEntry>> {
    let kind: String = row.try_get("kind")?;
    let Some(kind) = TrashKind::parse(&kind) else {
        return Ok(None);
    };
    let id: String = row.try_get("id")?;
    let id = Uuid::parse_str(&id).map_err(|e| CoreError::Db(sqlx::Error::Decode(Box::new(e))))?;
    let item_id: String = row.try_get("item_id")?;
    let name: String = row.try_get("name")?;
    let place: String = row.try_get("place")?;
    let detail: String = row.try_get("detail")?;
    let at: String = row.try_get("deleted_at")?;
    Ok(Some(entry(id, kind, &item_id, &name, &place, &detail, &at)))
}

/// `days` before now, as the trash's times are written.
fn cutoff(days: i64) -> String {
    let at = OffsetDateTime::now_utc() - time::Duration::days(days);
    at.format(&Rfc3339).unwrap_or_default()
}

/// `name`, or `name (restored)`, `name (restored 2)`... for the first one not in `taken` (lower case), within `max`.
fn free_name(name: &str, taken: &HashSet<String>, max: usize) -> String {
    if !taken.contains(&name.to_lowercase()) {
        return name.to_owned();
    }
    (1..)
        .map(|n| {
            let suffix = if n == 1 {
                " (restored)".to_owned()
            } else {
                format!(" (restored {n})")
            };
            let keep = max.saturating_sub(suffix.chars().count());
            format!("{}{suffix}", name.chars().take(keep).collect::<String>())
        })
        .find(|candidate| !taken.contains(&candidate.to_lowercase()))
        .unwrap_or_else(|| name.to_owned())
}

/// The id a row names in `column`, as a UUID.
fn uuid_in(row: &RowValues, column: &str) -> Option<Uuid> {
    rows::text(row, column).and_then(|s| Uuid::parse_str(s).ok())
}

/// QL-16: what a session's row sets itself, of what a folder can set too.
fn own_of(row: &RowValues, tags: &[String]) -> OwnValues {
    let credential = uuid_in(row, "credential_id").map(SecretId);
    let passphrase = uuid_in(row, "key_passphrase_id").map(SecretId);
    let auth = if rows::integer(row, "auth_from_folder").unwrap_or(0) != 0 {
        SessionAuth::Folder
    } else {
        match rows::text(row, "auth_method").unwrap_or("password") {
            "key" => SessionAuth::Key {
                key_id: credential,
                passphrase_id: passphrase,
            },
            "agent" => SessionAuth::Agent,
            _ => SessionAuth::Password {
                password_id: credential,
            },
        }
    };
    OwnValues {
        username: rows::text(row, "username").map(str::to_owned),
        auth,
        jump_session_id: uuid_in(row, "jump_session_id"),
        jump_direct: rows::integer(row, "jump_direct").unwrap_or(0) != 0,
        environment: Environment::parse(rows::text(row, "environment").unwrap_or("none")),
        tags: tags.to_vec(),
    }
}

/// The trash of the shown workspace (`Core.trash`). The shell starts the purge with [`Trash::run`].
#[derive(Clone)]
pub struct Trash {
    store: Store,
    current: Current,
    bindings: Option<SecretBindings>,
    /// QL-17: reloaded when a restored session brings its own highlight and alert rules back.
    terminal_rules: Option<crate::terminal::rules::TerminalRules>,
    /// MO-08: reloaded when a restored session brings its health checks back.
    checks: Option<crate::checks::Checks>,
    purging: Arc<tokio::sync::Mutex<()>>,
}

/// What fitting a session's rows to what is here now did.
struct SessionFix {
    notes: Vec<String>,
    /// How the vault password was given, when it was asked.
    asked: Option<&'static str>,
    /// The vault passwords to settle once it is saved.
    confirmed: Vec<SecretId>,
    /// Its own highlight rules came back.
    rules: bool,
    /// Its health checks came back.
    checks: bool,
}

/// "'web01' and folder 'Prod' used it as their jump host and still connect without it; choose it again there".
fn jump_users_note(users: &[String]) -> String {
    let shown: Vec<&str> = users.iter().take(3).map(String::as_str).collect();
    let mut list = match shown.as_slice() {
        [one] => (*one).to_owned(),
        [first @ .., last] => format!("{} and {last}", first.join(", ")),
        [] => String::new(),
    };
    if users.len() > shown.len() {
        list = format!("{} and {} more", shown.join(", "), users.len() - shown.len());
    }
    let their = if users.len() == 1 { "its" } else { "their" };
    format!("{list} used it as {their} jump host and still go without it; choose it again there if you want")
}

impl Trash {
    pub fn new(store: Store, current: Current) -> Self {
        Self {
            store,
            current,
            bindings: None,
            terminal_rules: None,
            checks: None,
            purging: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// MO-08: a restored session's health checks run again at once.
    pub fn with_checks(mut self, checks: crate::checks::Checks) -> Self {
        self.checks = Some(checks);
        self
    }

    /// QL-17: a restored session's own highlight and alert rules reach open panes at once.
    pub fn with_terminal_rules(mut self, rules: crate::terminal::rules::TerminalRules) -> Self {
        self.terminal_rules = Some(rules);
        self
    }

    /// SS-04, AP-06: a restored session that would send a vault password to a new place asks for it first.
    pub fn with_bindings(mut self, bindings: SecretBindings) -> Self {
        self.bindings = Some(bindings);
        self
    }

    /// What is in the workspace's trash, newest first.
    pub async fn list(&self, ctx: &Context) -> Result<Vec<TrashEntry>> {
        let rows = sqlx::query(
            "SELECT id, kind, item_id, name, place, detail, deleted_at FROM trash
             WHERE workspace_id = ? ORDER BY deleted_at DESC, rowid DESC",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(self.store.pool())
        .await?;
        Ok(rows
            .iter()
            .map(row_to_entry)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect())
    }

    async fn load(&self, ctx: &Context, id: Uuid) -> Result<(TrashEntry, Snapshot)> {
        let row = sqlx::query(
            "SELECT id, kind, item_id, name, place, detail, deleted_at, snapshot FROM trash
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or_else(|| CoreError::UnknownTarget("that item is no longer in the trash".into()))?;
        let entry = row_to_entry(&row)?
            .ok_or_else(|| CoreError::UnknownTarget("that item is no longer in the trash".into()))?;
        let snapshot: String = row.try_get("snapshot")?;
        let snapshot: Snapshot = serde_json::from_str(&snapshot)?;
        Ok((entry, snapshot))
    }

    /// The newest trash entry for an item, for a delete's Undo.
    pub async fn latest_for(&self, ctx: &Context, kind: TrashKind, item_id: &str) -> Result<Option<TrashEntry>> {
        let row = sqlx::query(
            "SELECT id, kind, item_id, name, place, detail, deleted_at FROM trash
             WHERE workspace_id = ? AND kind = ? AND item_id = ? ORDER BY deleted_at DESC, rowid DESC LIMIT 1",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(kind.as_str())
        .bind(item_id)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row.as_ref().map(row_to_entry).transpose()?.flatten())
    }

    /// A delete's Undo: restores the newest trash entry for the item.
    pub async fn undo(
        &self,
        ctx: &Context,
        kind: TrashKind,
        item_id: &str,
        vault_password: Option<&SecretString>,
    ) -> Result<RestoreReport> {
        self.store.read_only().check(Change::Trash)?;
        let entry = self
            .latest_for(ctx, kind, item_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget("that item is no longer in the trash".into()))?;
        self.restore(ctx, entry.id, vault_password).await
    }

    /// Puts an item back (see the module's notes). Audited; refused while presenting.
    pub async fn restore(
        &self,
        ctx: &Context,
        id: Uuid,
        vault_password: Option<&SecretString>,
    ) -> Result<RestoreReport> {
        self.store.read_only().check(Change::Trash)?;
        let (entry, mut snap) = self.load(ctx, id).await?;
        let kind = entry.kind;
        let ws = ctx.workspace_id.to_string();
        let mut notes: Vec<String> = Vec::new();
        let now = now_rfc3339();

        // Its id: its own, unless something took it since.
        let mut item_id = entry.item_id.clone();
        let id_taken: bool = match kind {
            TrashKind::Session => {
                let id = Uuid::parse_str(&item_id).unwrap_or_else(|_| Uuid::new_v4());
                self.store.session_id_taken(id).await?
            }
            _ => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
                    "SELECT COUNT(*) FROM \"{}\" WHERE id = ?",
                    kind.table()
                )))
                .bind(&item_id)
                .fetch_one(self.store.pool())
                .await?
                    > 0
            }
        };
        if id_taken {
            item_id = Uuid::new_v4().to_string();
        }

        // Room for it, and a free name.
        if let Some(most) = kind.most() {
            let have: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT COUNT(*) FROM \"{}\" WHERE workspace_id = ?",
                kind.table()
            )))
            .bind(&ws)
            .fetch_one(self.store.pool())
            .await?;
            if usize::try_from(have).unwrap_or(usize::MAX) >= most {
                return Err(CoreError::InvalidInput(format!(
                    "A workspace keeps at most {most} of these; delete one first, then restore '{}'.",
                    entry.name
                )));
            }
        }
        let name = rows::text(&snap.row, "name").unwrap_or(&entry.name).to_owned();
        let taken: HashSet<String> = match kind {
            TrashKind::Command => {
                let folder = rows::text(&snap.row, "folder").unwrap_or("").to_owned();
                sqlx::query_scalar::<_, String>(
                    "SELECT name FROM command_favourites WHERE workspace_id = ? AND folder = ?",
                )
                .bind(&ws)
                .bind(folder)
                .fetch_all(self.store.pool())
                .await?
            }
            _ => {
                sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(format!(
                    "SELECT name FROM \"{}\" WHERE workspace_id = ?",
                    kind.table()
                )))
                .bind(&ws)
                .fetch_all(self.store.pool())
                .await?
            }
        }
        .into_iter()
        .map(|n| n.to_lowercase())
        .collect();
        let new_name = free_name(&name, &taken, kind.max_name());
        if new_name != name {
            notes.push(format!("'{name}' was taken, so it is '{new_name}' now"));
        }

        let row = &mut snap.row;
        row.insert("id".into(), Value::String(item_id.clone()));
        row.insert("name".into(), Value::String(new_name.clone()));
        row.insert("user_id".into(), Value::String(ctx.user_id.to_string()));
        row.insert("workspace_id".into(), Value::String(ws.clone()));
        if row.contains_key("updated_at") {
            row.insert("updated_at".into(), Value::String(now.clone()));
        }

        let mut confirmed: Vec<SecretId> = Vec::new();
        let mut asked: Option<&'static str> = None;
        let mut rules_back = false;
        let mut checks_back = false;
        match kind {
            TrashKind::Session => {
                let fix = self
                    .fix_session(ctx, &mut snap, &item_id, &entry.name, vault_password)
                    .await?;
                notes.extend(fix.notes);
                asked = fix.asked;
                confirmed = fix.confirmed;
                rules_back = fix.rules;
                checks_back = fix.checks;
            }
            TrashKind::Command => {
                let folder = rows::text(&snap.row, "folder").unwrap_or("").to_owned();
                let last: Option<i64> = sqlx::query_scalar(
                    "SELECT MAX(position) FROM command_favourites WHERE workspace_id = ? AND folder = ?",
                )
                .bind(&ws)
                .bind(folder)
                .fetch_one(self.store.pool())
                .await?;
                snap.row
                    .insert("position".into(), Value::from(last.map_or(0, |p| p + 1)));
            }
            TrashKind::Template => notes.extend(self.template_notes(ctx, &snap.row).await?),
            TrashKind::Stack => notes.extend(self.stack_notes(ctx, &snap.row).await?),
            TrashKind::Size | TrashKind::Image => {}
        }

        // Everything back, and out of the trash, at once.
        let mut tx = self.store.pool().begin().await?;
        if !rows::insert(&mut tx, kind.table(), &snap.row).await? {
            return Err(CoreError::InvalidInput(format!(
                "'{}' can't be restored: something here has its place.",
                entry.name
            )));
        }
        for attached in &snap.attached {
            if !rows::insert(&mut tx, &attached.table, &attached.row).await? {
                notes.push(match attached.table.as_str() {
                    "port_forwards" => "a port forward was left out: its place is taken".to_owned(),
                    _ => "something that came with it was left out: its place is taken".to_owned(),
                });
            }
        }
        if kind == TrashKind::Session {
            if let Ok(id) = Uuid::parse_str(&item_id) {
                crate::store::set_session_tags(&mut tx, ctx, id, &snap.tags).await?;
            }
            if let Some(note) = &snap.note {
                rows::insert(&mut tx, "notes", note).await?;
            }
        }
        sqlx::query("DELETE FROM trash WHERE workspace_id = ? AND id = ?")
            .bind(&ws)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        if let Some(bindings) = &self.bindings {
            bindings.settle(&confirmed);
        }
        // QL-17: open panes follow the restored session's own alert rules again.
        if rules_back {
            if let Some(rules) = &self.terminal_rules {
                if let Err(err) = rules.switch_to(ctx).await {
                    tracing::warn!(error = %err, "could not reload the highlight rules after a restore");
                }
            }
        }
        // MO-08: its health checks run again from the next tick.
        if checks_back {
            if let Some(checks) = &self.checks {
                if let Err(err) = checks.reload(*ctx).await {
                    tracing::warn!(error = %err, "could not reload the health checks after a restore");
                }
            }
        }

        let mut detail = vec![format!("from the trash ({})", entry.place)];
        if !entry.detail.is_empty() {
            detail.push(format!("with {}", entry.detail));
        }
        detail.extend(notes.iter().cloned());
        if let Some(how) = asked {
            detail.push(how.to_owned());
        }
        let targets: Vec<Target> = match kind {
            TrashKind::Session => Uuid::parse_str(&item_id)
                .ok()
                .map(|session_id| Target {
                    target: TargetRef::Session { session_id },
                    name: new_name.clone(),
                    environment: Environment::parse(rows::text(&snap.row, "environment").unwrap_or("none")),
                    protected: rows::integer(&snap.row, "protected").unwrap_or(0) != 0,
                })
                .into_iter()
                .collect(),
            _ => Vec::new(),
        };
        self.audit(
            ctx,
            "trash_restored",
            &format!("Restored the {} '{new_name}'", kind.noun()),
            &targets,
            &detail.join("; "),
        )
        .await?;
        Ok(RestoreReport {
            kind,
            item_id,
            name: new_name,
            notes,
        })
    }

    /// A session's rows made to fit what is here now; the vault passwords it would send to a new place confirmed.
    /// Returns the notes, how the vault password was given (when asked) and the passwords to settle.
    async fn fix_session(
        &self,
        ctx: &Context,
        snap: &mut Snapshot,
        item_id: &str,
        name: &str,
        vault_password: Option<&SecretString>,
    ) -> Result<SessionFix> {
        let mut notes = Vec::new();
        let folders = self.store.session_folders(ctx).await?;
        let sessions: HashMap<Uuid, crate::sessions::SessionKind> = self
            .store
            .list_sessions(ctx)
            .await?
            .into_iter()
            .map(|s| (s.id, s.kind))
            .collect();
        let vault: HashSet<Uuid> = self.store.vault_items(ctx).await?.into_iter().map(|m| m.id.0).collect();
        let row = &mut snap.row;
        if let Some(folder) = uuid_in(row, "folder_id") {
            if folders.get(folder).is_none() {
                row.insert("folder_id".into(), Value::Null);
                notes.push("its folder is gone, so it is at the top level".to_owned());
            }
        }
        if let Some(jump) = uuid_in(row, "jump_session_id") {
            match sessions.get(&jump) {
                None => {
                    row.insert("jump_session_id".into(), Value::Null);
                    notes.push("its jump host is gone, so it was left out".to_owned());
                }
                // SS-12: a jump host is an SSH session; this one became another kind while this was in the trash.
                Some(kind) if !kind.is_ssh() => {
                    row.insert("jump_session_id".into(), Value::Null);
                    notes.push(format!(
                        "its jump host is a {} session now, so it was left out",
                        kind.label()
                    ));
                }
                Some(_) => {}
            }
        }
        for column in ["credential_id", "key_passphrase_id"] {
            if let Some(secret) = uuid_in(row, column) {
                if !vault.contains(&secret) {
                    row.insert(column.into(), Value::Null);
                    notes.push("a vault item it logged in with is gone".to_owned());
                }
            }
        }
        if let Some(vm) = rows::text(row, "vm_id").map(str::to_owned) {
            if self.store.vm_by_id(ctx, &vm).await?.is_none() {
                row.insert("vm_id".into(), Value::Null);
                row.insert("vm_link".into(), Value::Null);
                notes.push("the VM it reached is gone, so it is not linked".to_owned());
            }
        }
        let session_id = Uuid::parse_str(item_id).unwrap_or_else(|_| Uuid::new_v4());
        let own = own_of(row, &snap.tags);
        let folder_id = uuid_in(row, "folder_id");
        let effective = folders.resolve(Some(session_id), &own, folder_id);
        let host = rows::text(row, "host").unwrap_or_default().to_owned();
        let port = rows::integer(row, "port")
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(22);
        let place = Destination::new(&host, port, effective.jump_session_id);
        let then = snap.sent.clone().unwrap_or_default();
        let same_place = place.same(&Destination::new(&then.host, then.port, then.jump));

        // What hangs off it: its own id, gone items left out.
        let groups: HashSet<String> =
            sqlx::query_scalar::<_, String>("SELECT id FROM multiexec_groups WHERE workspace_id = ?")
                .bind(ctx.workspace_id.to_string())
                .fetch_all(self.store.pool())
                .await?
                .into_iter()
                .collect();
        let rules: Vec<(String, String, i64)> =
            sqlx::query_as("SELECT id, name, position FROM terminal_rules WHERE workspace_id = ?")
                .bind(ctx.workspace_id.to_string())
                .fetch_all(self.store.pool())
                .await?;
        let mut rules_here = rules.len();
        let mut rule_names: HashSet<String> = rules.iter().map(|(_, n, _)| n.to_lowercase()).collect();
        let rule_ids: HashSet<String> = rules.iter().map(|(id, _, _)| id.to_lowercase()).collect();
        let mut rule_position = rules.iter().map(|(_, _, p)| *p).max().unwrap_or(-1);
        let mut restored_rules = false;
        let mut checks_here = self.store.count_checks(ctx).await?;
        let mut restored_checks = false;
        let mut kept = Vec::new();
        let mut sends: Vec<SecretId> = effective.sent_secret().into_iter().collect();
        for mut attached in std::mem::take(&mut snap.attached) {
            let r = &mut attached.row;
            r.insert("session_id".into(), Value::String(item_id.to_owned()));
            r.insert("user_id".into(), Value::String(ctx.user_id.to_string()));
            match attached.table.as_str() {
                "port_forwards" => {
                    r.insert("id".into(), Value::String(Uuid::new_v4().to_string()));
                }
                "container_hosts" => {
                    if let Some(secret) = uuid_in(r, "sudo_password_id") {
                        if vault.contains(&secret) {
                            if rows::text(r, "sudo") == Some("password") {
                                sends.push(SecretId(secret));
                            }
                        } else {
                            r.insert("sudo_password_id".into(), Value::Null);
                            notes.push("the sudo password of its container host mark is gone from the vault".into());
                        }
                    }
                }
                "multiexec_group_members" => {
                    let group = rows::text(r, "group_id").unwrap_or_default().to_owned();
                    if !groups.contains(&group) {
                        notes.push("a saved group it was in is gone".into());
                        continue;
                    }
                    let members: i64 =
                        sqlx::query_scalar("SELECT COUNT(*) FROM multiexec_group_members WHERE group_id = ?")
                            .bind(&group)
                            .fetch_one(self.store.pool())
                            .await?;
                    if usize::try_from(members).unwrap_or(usize::MAX) >= crate::multiexec_groups::MAX_MEMBERS {
                        notes.push("a saved group it was in is full, so it was left out".into());
                        continue;
                    }
                }
                "terminal_rules" => {
                    // QL-17: under the workspace's cap, with a free name, after the rules there now.
                    if rules_here >= crate::terminal::rules::MAX_RULES {
                        notes.push("a highlight rule was left out: there are as many rules as there can be".into());
                        continue;
                    }
                    let name = rows::text(r, "name").unwrap_or("rule").to_owned();
                    let free = free_name(&name, &rule_names, crate::terminal::rules::MAX_NAME_CHARS);
                    if free != name {
                        notes.push(format!(
                            "its highlight rule '{name}' is '{free}' now: the name was taken"
                        ));
                    }
                    rule_names.insert(free.to_lowercase());
                    r.insert("name".into(), Value::String(free));
                    if rows::text(r, "id").is_some_and(|id| rule_ids.contains(&id.to_lowercase())) {
                        r.insert("id".into(), Value::String(Uuid::new_v4().to_string()));
                    }
                    rule_position += 1;
                    r.insert("position".into(), Value::from(rule_position));
                    rules_here += 1;
                    restored_rules = true;
                }
                "health_checks" => {
                    // MO-08: under the workspace's cap, on the session as it comes back, under its own id if free.
                    if checks_here >= crate::checks::spec::MAX_CHECKS {
                        notes.push("a health check was left out: the workspace holds as many as it can".into());
                        continue;
                    }
                    r.insert("target_key".into(), Value::String(item_id.to_owned()));
                    if let Some(check_id) = rows::text(r, "id").map(str::to_owned) {
                        let taken: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM health_checks WHERE id = ?")
                            .bind(&check_id)
                            .fetch_one(self.store.pool())
                            .await?;
                        if taken > 0 {
                            r.insert("id".into(), Value::String(Uuid::new_v4().to_string()));
                        }
                    }
                    checks_here += 1;
                    restored_checks = true;
                }
                "session_secret_grants" => {
                    let Some(secret) = uuid_in(r, "secret_id") else {
                        continue;
                    };
                    if !vault.contains(&secret) || !same_place {
                        continue;
                    }
                    sends.push(SecretId(secret));
                }
                _ => {}
            }
            kept.push(attached);
        }
        snap.attached = kept;
        if !snap.jump_users.is_empty() {
            notes.push(jump_users_note(&snap.jump_users));
        }
        if let Some(note) = snap.note.as_mut() {
            note.insert("target_key".into(), Value::String(item_id.to_owned()));
            note.insert("user_id".into(), Value::String(ctx.user_id.to_string()));
        }

        // SS-04, AP-06: what it sent there before it was deleted may go there again; anything else asks.
        let Some(bindings) = &self.bindings else {
            return Ok(SessionFix {
                notes,
                asked: None,
                confirmed: Vec::new(),
                rules: restored_rules,
                checks: restored_checks,
            });
        };
        let already: Vec<SecretId> = if same_place {
            then.secrets.iter().copied().map(SecretId).collect()
        } else {
            Vec::new()
        };
        let mut new = Vec::new();
        let mut confirmed = Vec::new();
        for secret in sends {
            if confirmed.contains(&secret) {
                continue;
            }
            confirmed.push(secret);
            if already.contains(&secret) || bindings.may_go(ctx, secret, &place, None).await? {
                continue;
            }
            new.push(bindings.describe(ctx, secret).await?);
        }
        if new.is_empty() {
            return Ok(SessionFix {
                notes,
                asked: None,
                confirmed,
                rules: restored_rules,
                checks: restored_checks,
            });
        }
        let reason = format!(
            "This would send the {} to {}:{}, where no saved session sends it yet",
            new.join(" and the "),
            place.host,
            place.port
        );
        let how = bindings
            .confirm(
                ctx,
                vault_password,
                &format!("Failed to restore session '{name}'"),
                &reason,
            )
            .await?;
        Ok(SessionFix {
            notes,
            asked: Some(how),
            confirmed,
            rules: restored_rules,
            checks: restored_checks,
        })
    }

    async fn template_notes(&self, ctx: &Context, row: &RowValues) -> Result<Vec<String>> {
        let mut notes = Vec::new();
        if let Some(image) = rows::text(row, "image_id") {
            let found: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM catalog_images WHERE workspace_id = ? AND id = ?")
                    .bind(ctx.workspace_id.to_string())
                    .bind(image)
                    .fetch_one(self.store.pool())
                    .await?;
            if found == 0 {
                notes.push("its image is gone: choose another before deploying".to_owned());
            }
        }
        if let Some(size) = rows::text(row, "size_id") {
            if crate::catalog::sizes::built_in(size).is_none() {
                let found: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM catalog_sizes WHERE workspace_id = ? AND id = ?")
                        .bind(ctx.workspace_id.to_string())
                        .bind(size)
                        .fetch_one(self.store.pool())
                        .await?;
                if found == 0 {
                    notes.push("its size is gone: choose another before deploying".to_owned());
                }
            }
        }
        Ok(notes)
    }

    async fn stack_notes(&self, ctx: &Context, row: &RowValues) -> Result<Vec<String>> {
        let steps: Value = rows::text(row, "steps")
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(Value::Null);
        let here: HashSet<String> =
            sqlx::query_scalar::<_, String>("SELECT id FROM catalog_templates WHERE workspace_id = ?")
                .bind(ctx.workspace_id.to_string())
                .fetch_all(self.store.pool())
                .await?
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect();
        let gone = steps
            .as_array()
            .map(|steps| {
                steps
                    .iter()
                    .filter_map(|s| s.get("templateId").and_then(Value::as_str))
                    .filter(|id| !here.contains(&id.to_lowercase()))
                    .count()
            })
            .unwrap_or(0);
        Ok(match gone {
            0 => Vec::new(),
            1 => vec!["a launch template it uses is gone: it says so until it gets another".to_owned()],
            n => vec![format!(
                "{n} launch templates it uses are gone: it says so until they get others"
            )],
        })
    }

    /// Deletes one item for good. Audited; refused while presenting.
    pub async fn delete_now(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::Trash)?;
        let (entry, _) = self.load(ctx, id).await?;
        sqlx::query("DELETE FROM trash WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(self.store.pool())
            .await?;
        self.audit(
            ctx,
            "trash_deleted",
            &format!(
                "Deleted the {} '{}' from the trash for good",
                entry.kind.noun(),
                entry.name
            ),
            &[],
            &format!("from {}", entry.place),
        )
        .await?;
        self.store.checkpoint().await.ok();
        Ok(())
    }

    /// Deletes everything in the workspace's trash for good. Audited with how many; refused while presenting.
    pub async fn empty(&self, ctx: &Context) -> Result<usize> {
        self.store.read_only().check(Change::Trash)?;
        let done = sqlx::query("DELETE FROM trash WHERE workspace_id = ?")
            .bind(ctx.workspace_id.to_string())
            .execute(self.store.pool())
            .await?;
        let removed = usize::try_from(done.rows_affected()).unwrap_or(0);
        self.audit(
            ctx,
            "trash_emptied",
            "Emptied the trash",
            &[],
            &format!("{} deleted for good", plural(removed, "item")),
        )
        .await?;
        self.store.checkpoint().await.ok();
        Ok(removed)
    }

    /// Removes what has been in the trash longer than [`KEEP_DAYS`] days, in every workspace of the user. Not stopped by
    /// the read-only lock; audited in each workspace it removed something from.
    pub async fn purge(&self) -> Result<TrashPurge> {
        let _one = self.purging.lock().await;
        let before = cutoff(KEEP_DAYS);
        let shown = self.current.get();
        let mut removed = 0;
        for workspace in self.store.list_workspaces(shown.user_id).await? {
            let ctx = Context {
                workspace_id: workspace.id,
                user_id: shown.user_id,
            };
            let done = sqlx::query("DELETE FROM trash WHERE workspace_id = ? AND deleted_at < ?")
                .bind(ctx.workspace_id.to_string())
                .bind(&before)
                .execute(self.store.pool())
                .await?;
            let here = usize::try_from(done.rows_affected()).unwrap_or(0);
            if here > 0 {
                removed += here;
                self.audit(
                    &ctx,
                    "trash_purged",
                    "Removed old items from the trash",
                    &[],
                    &format!("{} deleted more than {KEEP_DAYS} days ago", plural(here, "item")),
                )
                .await?;
            }
        }
        if removed > 0 {
            self.store.checkpoint().await.ok();
        }
        Ok(TrashPurge {
            at: now_rfc3339(),
            removed,
        })
    }

    /// Purges now, then whenever a day has passed by the wall clock, until `stop`.
    pub async fn run(self, stop: CancellationToken) {
        let mut last_run: Option<OffsetDateTime> = None;
        loop {
            let now = OffsetDateTime::now_utc();
            if last_run.is_none_or(|at| now - at >= PURGE_EVERY) {
                last_run = Some(now);
                if let Err(err) = self.purge().await {
                    tracing::error!(error = %err, "the trash's daily purge failed");
                }
            }
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(TICK) => {}
            }
        }
    }

    async fn audit(&self, ctx: &Context, event: &str, action: &str, targets: &[Target], detail: &str) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event,
                    action,
                    tier: None,
                    job_id: None,
                    targets,
                    approval: None,
                    result: None,
                    detail: (!detail.is_empty()).then_some(detail),
                },
            )
            .await
            .map(drop)
    }
}

/// Sessions › Customer A / Web: where a session was.
pub(crate) fn session_place(folders: &crate::sessions::Folders, folder: Option<Uuid>) -> String {
    let path: Vec<String> = folders.path(folder).iter().rev().map(|f| f.name.clone()).collect();
    if path.is_empty() {
        "Sessions".to_owned()
    } else {
        format!("Sessions › {}", path.join(" / "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_taken_name_gets_restored() {
        let taken: HashSet<String> = ["web01".into(), "web01 (restored)".into()].into_iter().collect();
        assert_eq!(free_name("db01", &taken, 100), "db01");
        assert_eq!(free_name("WEB01", &taken, 100), "WEB01 (restored 2)");
        let long = "x".repeat(40);
        let taken: HashSet<String> = [long.clone()].into_iter().collect();
        let freed = free_name(&long, &taken, 40);
        assert_eq!(freed.chars().count(), 40);
        assert!(freed.ends_with(" (restored)"));
    }

    #[test]
    fn kinds_read_back() {
        for kind in [
            TrashKind::Session,
            TrashKind::Command,
            TrashKind::Size,
            TrashKind::Image,
            TrashKind::Template,
            TrashKind::Stack,
        ] {
            assert_eq!(TrashKind::parse(kind.as_str()), Some(kind));
            assert!(rows::TABLES.contains(&kind.table()));
            for (table, _) in kind.attached() {
                assert!(rows::TABLES.contains(table));
            }
        }
    }

    #[test]
    fn jump_users_are_named_a_few_at_a_time() {
        let one = jump_users_note(&["'web01'".into()]);
        assert!(one.starts_with("'web01' used it as its jump host"), "{one}");
        let two = jump_users_note(&["'web01'".into(), "folder 'Prod'".into()]);
        assert!(two.starts_with("'web01' and folder 'Prod' used it as their"), "{two}");
        let many: Vec<String> = (1..=5).map(|n| format!("'s{n}'")).collect();
        assert!(jump_users_note(&many).starts_with("'s1', 's2', 's3' and 2 more used it"));
    }

    #[test]
    fn items_expire_after_thirty_days() {
        assert_eq!(expires("2026-11-01T10:00:00Z"), "2026-12-01T10:00:00Z");
    }
}
