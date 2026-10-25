//! Store: one local SQLite file (WAL mode, via sqlx) for inventory, sessions, the vault's ciphertext,
//! jobs, metrics, favourite commands and the audit log. Reads (inventory, metrics) go straight here and skip the command bus.
//!
//! Queries are checked at runtime, not with `query!`, so building needs no `DATABASE_URL`.

mod alerts;
mod audit;
mod catalog;
mod containers;
mod favourites;
mod forwards;
mod host_specs;
mod inventory;
mod jobs;
mod known_hosts;
mod metrics;
mod multiexec_groups;
mod quick_connect;
#[cfg(test)]
mod retention_tests;
mod sessions;
mod ssh_keys;
mod tags;
mod terminal_rules;
mod timeline;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod upgrade_tests;
mod vault;

use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous};
use uuid::Uuid;

use crate::domain::{now_rfc3339, Context, UserId, WorkspaceId};
use crate::error::Result;
use crate::presentation::ReadOnlyLock;

pub use audit::{AuditEntry, ChainCheck, NewAuditEntry, GENESIS_HASH};
pub(crate) use catalog::{NewImage, TemplateRow};
pub(crate) use favourites::{FavouriteFields, FavouriteRow};
pub use host_specs::StoredSpecs;
pub use inventory::{DiscoveredVm, VmRecord};
pub(crate) use jobs::NewJob;
pub use jobs::{JobSummary, JobTargetRecord, PurgedBodies, TargetResult};
pub use metrics::{HistoryPruned, HistorySize};
pub(crate) use multiexec_groups::GroupRow;
pub use quick_connect::MAX_QUICK_CONNECT_HISTORY;
pub(crate) use sessions::unsaved_spec;
pub(crate) use tags::{clean_name, MAX_TAG_LEN};
pub use tags::{SavedFilter, Tag};
pub(crate) use terminal_rules::{BuiltinRuleRow, TerminalRuleFields, TerminalRuleRow};
pub use timeline::{vm_needle, JobTargetBrief};
pub(crate) use vault::VaultMetaRow;

pub const POLICY_RULES_KEY: &str = "policy.rules";
/// Full path to vmrun.exe chosen in Settings; JSON null means "find it automatically".
pub const VMRUN_PATH_KEY: &str = "vmware.vmrunPath";
/// VM-18: full path to VBoxManage.exe chosen in Settings; JSON null means "find it automatically".
pub const VBOXMANAGE_PATH_KEY: &str = "virtualbox.vboxmanagePath";
/// FD-14: whether the app checks GitHub Releases for updates; off for air-gapped sites. Default on.
pub const UPDATE_CHECKS_KEY: &str = "updates.checkEnabled";
/// VM-01: folders scanned for .vmx files, besides Workstation's library. A JSON list of paths.
pub const SCAN_FOLDERS_KEY: &str = "vmware.scanFolders";
/// VM-06: how many VMs may power on at once.
pub const POWER_ON_LIMIT_KEY: &str = "jobs.powerOnLimit";
/// VM-03: seconds a soft stop may take before the VM counts as still running.
pub const SHUTDOWN_WAIT_KEY: &str = "vmware.shutdownWaitSecs";
/// BX-02: how many hosts a bulk run reaches at once.
pub const REMOTE_LIMIT_KEY: &str = "jobs.remoteLimit";
pub const DEFAULT_WORKSPACE: &str = "Default";

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
    /// Serializes audit appends so the hash chain stays linear.
    audit_lock: Arc<tokio::sync::Mutex<()>>,
    /// FD-03: presentation mode's read-only lock, shared by every service that edits the app's data and by the
    /// command bus. Set by [`crate::presentation::PresentationMode`].
    read_only: ReadOnlyLock,
}

impl Store {
    /// Opens (or creates) the database file and applies migrations.
    pub async fn open(path: &Path) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5))
            // SS-04, BX-02: a deleted or rewritten row (an old wrapped key or ciphertext, job outputs and scripts the
            // retention purge removes) is overwritten on disk, not left in a free page for a copy of the file to give
            // back.
            .pragma("secure_delete", "ON");
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?;
        Self::from_pool(pool).await
    }

    /// A private in-memory database, for tests. One connection, so every query sees the same data.
    pub async fn open_in_memory() -> Result<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?
            .foreign_keys(true)
            .pragma("secure_delete", "ON");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await?;
        Self::from_pool(pool).await
    }

    async fn from_pool(pool: SqlitePool) -> Result<Self> {
        if let Err(err) = sqlx::migrate!("./migrations").run(&pool).await {
            // QL-15: the file is closed before the error is reported, so it can be set aside at once.
            pool.close().await;
            return Err(err.into());
        }
        Ok(Self {
            pool,
            audit_lock: Arc::new(tokio::sync::Mutex::new(())),
            read_only: ReadOnlyLock::default(),
        })
    }

    /// Closes the database's connections (QL-15: after a failed start, so the file can be set aside).
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// FD-03: whether presentation mode's read-only lock applies now.
    pub fn read_only(&self) -> &ReadOnlyLock {
        &self.read_only
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Returns the user for this Windows account and their default workspace, creating them on first run.
    pub async fn ensure_identity(&self, account: &str, display_name: &str) -> Result<Context> {
        let now = now_rfc3339();
        let new_user = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users (id, account, display_name, created_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(account) DO NOTHING",
        )
        .bind(&new_user)
        .bind(account)
        .bind(display_name)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        let user_id: String = sqlx::query_scalar("SELECT id FROM users WHERE account = ?")
            .bind(account)
            .fetch_one(&self.pool)
            .await?;

        let new_ws = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO workspaces (id, user_id, name, created_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(user_id, name) DO NOTHING",
        )
        .bind(&new_ws)
        .bind(&user_id)
        .bind(DEFAULT_WORKSPACE)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        let workspace_id: String = sqlx::query_scalar("SELECT id FROM workspaces WHERE user_id = ? AND name = ?")
            .bind(&user_id)
            .bind(DEFAULT_WORKSPACE)
            .fetch_one(&self.pool)
            .await?;

        Ok(Context {
            workspace_id: WorkspaceId(parse_uuid(&workspace_id)?),
            user_id: UserId(parse_uuid(&user_id)?),
        })
    }

    pub async fn get_setting<T: DeserializeOwned>(&self, ctx: &Context, key: &str) -> Result<Option<T>> {
        let raw: Option<String> =
            sqlx::query_scalar("SELECT value_json FROM settings WHERE workspace_id = ? AND key = ?")
                .bind(ctx.workspace_id.to_string())
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;
        raw.map(|s| serde_json::from_str(&s)).transpose().map_err(Into::into)
    }

    pub async fn put_setting<T: Serialize>(&self, ctx: &Context, key: &str, value: &T) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (workspace_id, user_id, key, value_json, updated_at) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id, key) DO UPDATE SET
                 value_json = excluded.value_json, user_id = excluded.user_id, updated_at = excluded.updated_at",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(key)
        .bind(serde_json::to_string(value)?)
        .bind(now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// QL-15: moves a setting this version can't read to `<key>.unreadable` (replacing an older one there),
    /// so its default applies and the value is kept, not deleted. False when there was none.
    pub async fn set_setting_aside(&self, ctx: &Context, key: &str) -> Result<bool> {
        let moved =
            sqlx::query("UPDATE OR REPLACE settings SET key = ?, updated_at = ? WHERE workspace_id = ? AND key = ?")
                .bind(format!("{key}.unreadable"))
                .bind(now_rfc3339())
                .bind(ctx.workspace_id.to_string())
                .bind(key)
                .execute(&self.pool)
                .await?;
        Ok(moved.rows_affected() > 0)
    }
}

fn parse_uuid(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| sqlx::Error::Decode(Box::new(e)).into())
}

/// The serde name of a unit enum value ("vmStart", "partiallyFailed", ...), for TEXT columns.
pub(crate) fn serde_name<T: Serialize>(value: &T) -> Result<String> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(s) => Ok(s),
        other => {
            Err(<serde_json::Error as serde::ser::Error>::custom(format!("expected a unit enum, got {other}")).into())
        }
    }
}
