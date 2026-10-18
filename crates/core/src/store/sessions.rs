//! Session library rows (SS-01, SS-06): sessions, their folders and their tags. Checks of what the
//! user typed live in `crate::sessions`; this module only reads and writes.

use std::collections::HashMap;

use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::adapters::remote::{AuthMethod, SessionSpec};
use crate::domain::{now_rfc3339, Context, Environment};
use crate::error::{CoreError, Result};
use crate::sessions::{SessionAuth, SessionColor, SessionFolder, SessionInput, SessionRecord};
use crate::vault::SecretId;

/// Separates tag names in the `tags` column (SQL `char(31)`); tag names cannot hold control characters.
const TAG_SEPARATOR: char = '\u{1f}';

macro_rules! session_columns {
    () => {
        "id, folder_id, name, protocol, host, port, username, auth_method, credential_id, key_passphrase_id,
         jump_session_id, startup_command, environment, color, protected, vm_id, imported_from, created_at, updated_at,
         last_ip, last_hostname, last_seen_at, last_opened_at,
         (SELECT group_concat(t.name, char(31)) FROM target_tags tt JOIN tags t ON t.id = tt.tag_id
          WHERE tt.target_kind = 'session' AND tt.target_id = sessions.id) AS tags"
    };
}

fn optional_uuid(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<Option<Uuid>> {
    let value: Option<String> = row.try_get(column)?;
    value.as_deref().map(parse_uuid).transpose()
}

fn row_to_session(row: &sqlx::sqlite::SqliteRow) -> Result<SessionRecord> {
    let id: String = row.try_get("id")?;
    let credential = optional_uuid(row, "credential_id")?.map(SecretId);
    let passphrase = optional_uuid(row, "key_passphrase_id")?.map(SecretId);
    let method: String = row.try_get("auth_method")?;
    let auth = match method.as_str() {
        "key" => SessionAuth::Key {
            key_id: credential,
            passphrase_id: passphrase,
        },
        "agent" => SessionAuth::Agent,
        _ => SessionAuth::Password {
            password_id: credential,
        },
    };
    let port: i64 = row.try_get("port")?;
    let env: String = row.try_get("environment")?;
    let color: Option<String> = row.try_get("color")?;
    let protected: i64 = row.try_get("protected")?;
    let tags: Option<String> = row.try_get("tags")?;
    let mut tags: Vec<String> = tags
        .unwrap_or_default()
        .split(TAG_SEPARATOR)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect();
    tags.sort_by_key(|t| t.to_lowercase());
    Ok(SessionRecord {
        id: parse_uuid(&id)?,
        folder_id: optional_uuid(row, "folder_id")?,
        name: row.try_get("name")?,
        protocol: row.try_get("protocol")?,
        host: row.try_get("host")?,
        port: u16::try_from(port).unwrap_or(22),
        username: row.try_get("username")?,
        auth,
        jump_session_id: optional_uuid(row, "jump_session_id")?,
        startup_command: row.try_get("startup_command")?,
        environment: Environment::parse(&env),
        color: color.as_deref().and_then(SessionColor::parse),
        protected: protected != 0,
        tags,
        vm_id: row.try_get("vm_id")?,
        imported_from: row.try_get("imported_from")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        last_ip: row.try_get("last_ip")?,
        last_hostname: row.try_get("last_hostname")?,
        last_seen_at: row.try_get("last_seen_at")?,
        last_opened_at: row.try_get("last_opened_at")?,
    })
}

fn row_to_folder(row: &sqlx::sqlite::SqliteRow) -> Result<SessionFolder> {
    let id: String = row.try_get("id")?;
    Ok(SessionFolder {
        id: parse_uuid(&id)?,
        parent_id: optional_uuid(row, "parent_id")?,
        name: row.try_get("name")?,
        sort_order: row.try_get("sort_order")?,
    })
}

/// Makes the session's tags exactly `names` (already checked), creating tags on first use and
/// deleting tags left on nothing.
async fn set_session_tags(
    tx: &mut Transaction<'_, Sqlite>,
    ctx: &Context,
    session: Uuid,
    names: &[String],
) -> Result<()> {
    let ws = ctx.workspace_id.to_string();
    let user = ctx.user_id.to_string();
    let now = now_rfc3339();
    sqlx::query("DELETE FROM target_tags WHERE target_kind = 'session' AND target_id = ?")
        .bind(session.to_string())
        .execute(&mut **tx)
        .await?;
    for name in names {
        sqlx::query(
            "INSERT INTO tags (id, workspace_id, user_id, name, created_at) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id, name) DO NOTHING",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&ws)
        .bind(&user)
        .bind(name)
        .bind(&now)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "INSERT INTO target_tags (workspace_id, user_id, tag_id, target_kind, target_id, created_at)
             SELECT ?, ?, id, 'session', ?, ? FROM tags WHERE workspace_id = ? AND name = ?
             ON CONFLICT(tag_id, target_kind, target_id) DO NOTHING",
        )
        .bind(&ws)
        .bind(&user)
        .bind(session.to_string())
        .bind(&now)
        .bind(&ws)
        .bind(name)
        .execute(&mut **tx)
        .await?;
    }
    delete_unused_tags(tx, ctx).await
}

async fn delete_unused_tags(tx: &mut Transaction<'_, Sqlite>, ctx: &Context) -> Result<()> {
    sqlx::query(
        "DELETE FROM tags WHERE workspace_id = ? AND NOT EXISTS (SELECT 1 FROM target_tags WHERE tag_id = tags.id)",
    )
    .bind(ctx.workspace_id.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

impl Store {
    /// Every session in the workspace, by name.
    pub async fn list_sessions(&self, ctx: &Context) -> Result<Vec<SessionRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            session_columns!(),
            " FROM sessions WHERE workspace_id = ? ORDER BY name COLLATE NOCASE, host"
        ))
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_session).collect()
    }

    pub async fn get_session(&self, ctx: &Context, id: Uuid) -> Result<Option<SessionRecord>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            session_columns!(),
            " FROM sessions WHERE workspace_id = ? AND id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_session).transpose()
    }

    /// `input` must already be checked (`crate::sessions`). `imported_from`: SS-02's source name.
    pub(crate) async fn insert_session(
        &self,
        ctx: &Context,
        id: Uuid,
        input: &SessionInput,
        imported_from: Option<&str>,
    ) -> Result<()> {
        let now = now_rfc3339();
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO sessions (id, workspace_id, user_id, folder_id, name, protocol, host, port, username,
                                   auth_method, credential_id, key_passphrase_id, jump_session_id, startup_command,
                                   environment, color, vm_id, imported_from, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, 'ssh', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(input.folder_id.map(|f| f.to_string()))
        .bind(&input.name)
        .bind(&input.host)
        .bind(i64::from(input.port))
        .bind(&input.username)
        .bind(input.auth.method())
        .bind(input.auth.credential_id().map(|s| s.0.to_string()))
        .bind(input.auth.passphrase_id().map(|s| s.0.to_string()))
        .bind(input.jump_session_id.map(|j| j.to_string()))
        .bind(&input.startup_command)
        .bind(input.environment.as_str())
        .bind(input.color.map(SessionColor::as_str))
        .bind(&input.vm_id)
        .bind(imported_from)
        .bind(&now)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        set_session_tags(&mut tx, ctx, id, &input.tags).await?;
        tx.commit().await?;
        Ok(())
    }

    /// `input` must already be checked. False when there is no such session.
    pub(crate) async fn update_session(&self, ctx: &Context, id: Uuid, input: &SessionInput) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let done = sqlx::query(
            "UPDATE sessions SET folder_id = ?, name = ?, host = ?, port = ?, username = ?, auth_method = ?,
                 credential_id = ?, key_passphrase_id = ?, jump_session_id = ?, startup_command = ?, environment = ?,
                 color = ?, vm_id = ?, user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(input.folder_id.map(|f| f.to_string()))
        .bind(&input.name)
        .bind(&input.host)
        .bind(i64::from(input.port))
        .bind(&input.username)
        .bind(input.auth.method())
        .bind(input.auth.credential_id().map(|s| s.0.to_string()))
        .bind(input.auth.passphrase_id().map(|s| s.0.to_string()))
        .bind(input.jump_session_id.map(|j| j.to_string()))
        .bind(&input.startup_command)
        .bind(input.environment.as_str())
        .bind(input.color.map(SessionColor::as_str))
        .bind(&input.vm_id)
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
        if done.rows_affected() == 0 {
            return Ok(false);
        }
        set_session_tags(&mut tx, ctx, id, &input.tags).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Sessions that jumped through it lose their jump host (the foreign key sets NULL).
    pub(crate) async fn delete_session(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM target_tags WHERE target_kind = 'session' AND target_id = ?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        let done = sqlx::query("DELETE FROM sessions WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        delete_unused_tags(&mut tx, ctx).await?;
        tx.commit().await?;
        Ok(done.rows_affected() > 0)
    }

    /// Moves sessions into a folder (`None`: the top level). Returns how many moved.
    pub(crate) async fn move_sessions(&self, ctx: &Context, ids: &[Uuid], folder: Option<Uuid>) -> Result<u64> {
        let mut tx = self.pool.begin().await?;
        let now = now_rfc3339();
        let mut moved = 0;
        for id in ids {
            moved += sqlx::query(
                "UPDATE sessions SET folder_id = ?, user_id = ?, updated_at = ? WHERE workspace_id = ? AND id = ?",
            )
            .bind(folder.map(|f| f.to_string()))
            .bind(ctx.user_id.to_string())
            .bind(&now)
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        }
        tx.commit().await?;
        Ok(moved)
    }

    /// Each session's jump host, for the cycle check.
    pub(crate) async fn session_jumps(&self, ctx: &Context) -> Result<HashMap<Uuid, Option<Uuid>>> {
        let rows = sqlx::query("SELECT id, jump_session_id FROM sessions WHERE workspace_id = ?")
            .bind(ctx.workspace_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                let id: String = r.try_get("id")?;
                Ok((parse_uuid(&id)?, optional_uuid(r, "jump_session_id")?))
            })
            .collect()
    }

    pub async fn list_session_folders(&self, ctx: &Context) -> Result<Vec<SessionFolder>> {
        let rows = sqlx::query(
            "SELECT id, parent_id, name, sort_order FROM session_folders WHERE workspace_id = ?
             ORDER BY sort_order, name COLLATE NOCASE",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_folder).collect()
    }

    pub(crate) async fn insert_session_folder(
        &self,
        ctx: &Context,
        id: Uuid,
        name: &str,
        parent: Option<Uuid>,
    ) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO session_folders (id, workspace_id, user_id, parent_id, name, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(parent.map(|p| p.to_string()))
        .bind(name)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Renames and moves a folder in one go (checked by the caller).
    pub(crate) async fn update_session_folder(
        &self,
        ctx: &Context,
        id: Uuid,
        name: &str,
        parent: Option<Uuid>,
    ) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE session_folders SET name = ?, parent_id = ?, user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(name)
        .bind(parent.map(|p| p.to_string()))
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Deletes a folder. Its sessions and subfolders move up to its parent; nothing else is deleted.
    pub(crate) async fn delete_session_folder(&self, ctx: &Context, id: Uuid, parent: Option<Uuid>) -> Result<bool> {
        let ws = ctx.workspace_id.to_string();
        let now = now_rfc3339();
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE sessions SET folder_id = ?, updated_at = ? WHERE workspace_id = ? AND folder_id = ?")
            .bind(parent.map(|p| p.to_string()))
            .bind(&now)
            .bind(&ws)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE session_folders SET parent_id = ?, updated_at = ? WHERE workspace_id = ? AND parent_id = ?",
        )
        .bind(parent.map(|p| p.to_string()))
        .bind(&now)
        .bind(&ws)
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
        let done = sqlx::query("DELETE FROM session_folders WHERE workspace_id = ? AND id = ?")
            .bind(&ws)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(done.rows_affected() > 0)
    }

    /// Name, label and protection of a saved session (SS-06: what the policy engine needs). A session
    /// that reaches a VM (BX-01) counts as Prod when the VM is labelled Prod, and as protected when
    /// either is (AP-04): a command over SSH changes the VM as much as a VM action would.
    pub async fn find_session_target(&self, ctx: &Context, id: Uuid) -> Result<Option<(String, Environment, bool)>> {
        let row = sqlx::query(
            "SELECT s.name, s.environment, s.protected, v.environment AS vm_environment, v.protected AS vm_protected
             FROM sessions s LEFT JOIN vms v ON v.id = s.vm_id AND v.workspace_id = s.workspace_id
             WHERE s.workspace_id = ? AND s.id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| -> Result<_> {
            let env = Environment::parse(&r.try_get::<String, _>("environment")?);
            let vm_env = r
                .try_get::<Option<String>, _>("vm_environment")?
                .map(|e| Environment::parse(&e));
            let protected: i64 = r.try_get("protected")?;
            let vm_protected: Option<i64> = r.try_get("vm_protected")?;
            let env = if vm_env == Some(Environment::Prod) {
                Environment::Prod
            } else {
                env
            };
            Ok((
                r.try_get("name")?,
                env,
                protected != 0 || vm_protected.unwrap_or(0) != 0,
            ))
        })
        .transpose()
    }

    /// QL-02: a terminal to the session was opened now (Recent sessions). Not an edit: `updated_at`
    /// stays.
    pub(crate) async fn record_session_opened(&self, ctx: &Context, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE sessions SET last_opened_at = ? WHERE workspace_id = ? AND id = ?")
            .bind(now_rfc3339())
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// QL-03: what a connection to the session saw. A `None` keeps the value seen before. Not an
    /// edit: `updated_at` stays.
    pub(crate) async fn record_host_facts(
        &self,
        ctx: &Context,
        id: Uuid,
        ip: Option<&str>,
        hostname: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE sessions SET last_ip = COALESCE(?, last_ip), last_hostname = COALESCE(?, last_hostname),
                 last_seen_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(ip)
        .bind(hostname)
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// QL-02: the sessions opened most recently, newest first.
    pub async fn recent_sessions(&self, ctx: &Context, limit: u32) -> Result<Vec<SessionRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            session_columns!(),
            " FROM sessions WHERE workspace_id = ? AND last_opened_at IS NOT NULL
              ORDER BY last_opened_at DESC LIMIT ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_session).collect()
    }

    /// BX-01: sessions that reach each VM, by VM id, in name order.
    pub async fn sessions_by_vm(&self, ctx: &Context) -> Result<HashMap<String, Vec<Uuid>>> {
        let rows = sqlx::query(
            "SELECT id, vm_id FROM sessions WHERE workspace_id = ? AND vm_id IS NOT NULL
             ORDER BY name COLLATE NOCASE, host",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let mut by_vm: HashMap<String, Vec<Uuid>> = HashMap::new();
        for r in &rows {
            let id: String = r.try_get("id")?;
            by_vm.entry(r.try_get("vm_id")?).or_default().push(parse_uuid(&id)?);
        }
        Ok(by_vm)
    }

    /// Connection details for the remote adapter. The jump host (SS-07, v2) is resolved one level, so
    /// the terminal can name it. A key login with no key chosen can't connect, so it is an error here.
    pub async fn session_spec(&self, ctx: &Context, id: Uuid) -> Result<Option<SessionSpec>> {
        let Some(session) = self.get_session(ctx, id).await? else {
            return Ok(None);
        };
        let auth = match &session.auth {
            SessionAuth::Key { key_id: None, .. } => {
                return Err(CoreError::InvalidInput(format!(
                    "'{}' logs in with a key, but no key is chosen. Edit the session to choose one.",
                    session.name
                )))
            }
            auth => auth_method(auth),
        };
        let jump = match session.jump_session_id {
            Some(jump) => self
                .get_session(ctx, jump)
                .await?
                .map(|j| Box::new(spec_of(j, AuthMethod::Agent, None))),
            None => None,
        };
        Ok(Some(spec_of(session, auth, jump)))
    }
}

/// QL-02: connection details for a quick connection that is not saved. `input` must already be
/// checked. A key login with no key chosen can't connect.
pub(crate) fn unsaved_spec(input: &SessionInput) -> Result<SessionSpec> {
    if let SessionAuth::Key { key_id: None, .. } = input.auth {
        return Err(CoreError::InvalidInput("Choose the key to log in with.".into()));
    }
    Ok(SessionSpec {
        id: Uuid::new_v4(),
        name: input.name.clone(),
        host: input.host.clone(),
        port: input.port,
        username: input.username.clone().unwrap_or_default(),
        auth: auth_method(&input.auth),
        jump: None,
        environment: input.environment,
        startup_command: None,
    })
}

fn auth_method(auth: &SessionAuth) -> AuthMethod {
    match auth {
        SessionAuth::Password { password_id } => AuthMethod::Password(*password_id),
        SessionAuth::Key {
            key_id: Some(key),
            passphrase_id,
        } => AuthMethod::PrivateKey {
            key: *key,
            passphrase: *passphrase_id,
        },
        // Only for a jump host's spec, which is never connected to in the MVP.
        SessionAuth::Key { key_id: None, .. } | SessionAuth::Agent => AuthMethod::Agent,
    }
}

fn spec_of(session: SessionRecord, auth: AuthMethod, jump: Option<Box<SessionSpec>>) -> SessionSpec {
    SessionSpec {
        id: session.id,
        name: session.name,
        host: session.host,
        port: session.port,
        username: session.username.unwrap_or_default(),
        auth,
        jump,
        environment: session.environment,
        startup_command: session.startup_command,
    }
}
