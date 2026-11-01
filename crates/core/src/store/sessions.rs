//! Session library rows (SS-01, SS-06): sessions, their folders and their tags. Checks of what the
//! user typed live in `crate::sessions`; this module only reads and writes.

use std::collections::HashMap;

use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use super::{parse_uuid, Store};
use crate::adapters::remote::{AuthMethod, SessionSpec};
use crate::domain::{now_rfc3339, Context, Environment};
use crate::error::{CoreError, Result};
use crate::sessions::defaults::APP_DEFAULT_AUTH;
use crate::sessions::{
    FolderDefaults, Folders, Inherited, OwnValues, SessionAuth, SessionColor, SessionFolder, SessionInput, SessionKind,
    SessionRecord, MAX_JUMP_DEPTH,
};
use crate::vault::SecretId;
use crate::vm_links::VmLink;

/// Separates tag names in the `tags` column (SQL `char(31)`); tag names cannot hold control characters.
const TAG_SEPARATOR: char = '\u{1f}';

macro_rules! session_columns {
    () => {
        "id, folder_id, name, protocol, host, port, username, auth_method, credential_id, key_passphrase_id,
         jump_session_id, startup_command, startup_on_reconnect, prompt_hook, environment, color, protected, vm_id,
         vm_link, imported_from, created_at, updated_at, last_ip, last_hostname, last_seen_at, last_opened_at,
         auth_from_folder, jump_direct, kind_options,
         (SELECT group_concat(t.name, char(31)) FROM target_tags tt JOIN tags t ON t.id = tt.tag_id
          WHERE tt.target_kind = 'session' AND tt.target_id = sessions.id) AS tags"
    };
}

fn optional_uuid(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<Option<Uuid>> {
    let value: Option<String> = row.try_get(column)?;
    value.as_deref().map(parse_uuid).transpose()
}

/// A login as the `auth_method`, `credential_id` and `key_passphrase_id` columns hold it.
fn auth_of(method: Option<&str>, credential: Option<SecretId>, passphrase: Option<SecretId>) -> Option<SessionAuth> {
    Some(match method? {
        "key" => SessionAuth::Key {
            key_id: credential,
            passphrase_id: passphrase,
        },
        "agent" => SessionAuth::Agent,
        _ => SessionAuth::Password {
            password_id: credential,
        },
    })
}

/// The `auth_method` column for a login; QL-16's "as its folders say" is kept in `auth_from_folder` (with the
/// column's default beside it).
fn method_column(auth: &SessionAuth) -> &'static str {
    match auth {
        SessionAuth::Folder => "password",
        auth => auth.method(),
    }
}

/// QL-16: the session's own values, as read; what applies is filled in by [`Store::resolve_sessions`].
fn row_to_session(row: &sqlx::sqlite::SqliteRow) -> Result<SessionRecord> {
    let id: String = row.try_get("id")?;
    let credential = optional_uuid(row, "credential_id")?.map(SecretId);
    let passphrase = optional_uuid(row, "key_passphrase_id")?.map(SecretId);
    let method: String = row.try_get("auth_method")?;
    let from_folder: i64 = row.try_get("auth_from_folder")?;
    let jump_direct: i64 = row.try_get("jump_direct")?;
    let auth = if from_folder != 0 {
        SessionAuth::Folder
    } else {
        auth_of(Some(&method), credential, passphrase).unwrap_or(APP_DEFAULT_AUTH)
    };
    let port: i64 = row.try_get("port")?;
    let env: String = row.try_get("environment")?;
    let color: Option<String> = row.try_get("color")?;
    let protected: i64 = row.try_get("protected")?;
    let startup_on_reconnect: i64 = row.try_get("startup_on_reconnect")?;
    let prompt_hook: Option<i64> = row.try_get("prompt_hook")?;
    let vm_link: Option<String> = row.try_get("vm_link")?;
    let tags: Option<String> = row.try_get("tags")?;
    let mut tags: Vec<String> = tags
        .unwrap_or_default()
        .split(TAG_SEPARATOR)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect();
    tags.sort_by_key(|t| t.to_lowercase());
    let own = OwnValues {
        username: row.try_get("username")?,
        auth,
        jump_session_id: optional_uuid(row, "jump_session_id")?,
        jump_direct: jump_direct != 0,
        environment: Environment::parse(&env),
        tags,
    };
    // SS-12: a protocol this version doesn't open (F4's `winrm` in a newer database) reads as SSH, but keeps its
    // protocol, and `session_spec` refuses anything that is not `ssh`, so nothing connects to it over SSH.
    let protocol: String = row.try_get("protocol")?;
    let options: Option<String> = row.try_get("kind_options")?;
    let kind = SessionKind::read(&protocol, options.as_deref()).unwrap_or_default();
    Ok(SessionRecord {
        id: parse_uuid(&id)?,
        folder_id: optional_uuid(row, "folder_id")?,
        name: row.try_get("name")?,
        protocol,
        kind,
        host: row.try_get("host")?,
        port: u16::try_from(port).unwrap_or(22),
        username: own.username.clone(),
        auth: match &own.auth {
            SessionAuth::Folder => APP_DEFAULT_AUTH,
            auth => auth.clone(),
        },
        jump_session_id: own.jump_session_id,
        startup_command: row.try_get("startup_command")?,
        startup_on_reconnect: startup_on_reconnect != 0,
        prompt_hook: prompt_hook.map(|h| h != 0),
        environment: own.environment,
        color: color.as_deref().and_then(SessionColor::parse),
        protected: protected != 0,
        tags: own.tags.clone(),
        vm_id: row.try_get("vm_id")?,
        vm_link: vm_link.as_deref().and_then(VmLink::parse),
        imported_from: row.try_get("imported_from")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        last_ip: row.try_get("last_ip")?,
        last_hostname: row.try_get("last_hostname")?,
        last_seen_at: row.try_get("last_seen_at")?,
        last_opened_at: row.try_get("last_opened_at")?,
        own,
        inherited: Inherited::default(),
    })
}

/// QL-16: a folder's row joined with its defaults (all NULL when it sets none).
fn row_to_folder(row: &sqlx::sqlite::SqliteRow) -> Result<SessionFolder> {
    let id: String = row.try_get("id")?;
    let method: Option<String> = row.try_get("d_auth_method")?;
    let credential = optional_uuid(row, "d_credential_id")?.map(SecretId);
    let passphrase = optional_uuid(row, "d_key_passphrase_id")?.map(SecretId);
    let environment: Option<String> = row.try_get("d_environment")?;
    let jump_direct: Option<i64> = row.try_get("d_jump_direct")?;
    let tags: Option<String> = row.try_get("d_tags")?;
    let mut tags: Vec<String> = tags
        .unwrap_or_default()
        .split(TAG_SEPARATOR)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect();
    tags.sort_by_key(|t| t.to_lowercase());
    Ok(SessionFolder {
        id: parse_uuid(&id)?,
        parent_id: optional_uuid(row, "parent_id")?,
        name: row.try_get("name")?,
        sort_order: row.try_get("sort_order")?,
        defaults: FolderDefaults {
            username: row.try_get("d_username")?,
            auth: auth_of(method.as_deref(), credential, passphrase),
            jump_session_id: optional_uuid(row, "d_jump_session_id")?,
            jump_direct: jump_direct.unwrap_or(0) != 0,
            environment: environment
                .as_deref()
                .map(Environment::parse)
                .filter(|e| *e != Environment::None),
            tags,
        },
    })
}

/// Makes the session's tags exactly `names` (already checked), creating tags on first use and
/// deleting tags left on nothing.
pub(crate) async fn set_session_tags(
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

pub(crate) async fn delete_unused_tags(tx: &mut Transaction<'_, Sqlite>, ctx: &Context) -> Result<()> {
    sqlx::query(
        "DELETE FROM tags WHERE workspace_id = ? AND NOT EXISTS (SELECT 1 FROM target_tags WHERE tag_id = tags.id)",
    )
    .bind(ctx.workspace_id.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

impl Store {
    /// QL-16: the folder tree with each folder's defaults, to resolve sessions against.
    pub async fn session_folders(&self, ctx: &Context) -> Result<Folders> {
        Ok(Folders::new(self.list_session_folders(ctx).await?))
    }

    /// QL-16: fills in what applies to each session (its own values, then its folders', then the app's).
    pub(crate) fn resolve_sessions(sessions: &mut [SessionRecord], folders: &Folders) {
        for session in sessions {
            let effective = session.resolve_in(folders);
            session.apply(effective);
        }
    }

    /// Every session in the workspace, by name, with what applies to it (QL-16).
    pub async fn list_sessions(&self, ctx: &Context) -> Result<Vec<SessionRecord>> {
        let folders = self.session_folders(ctx).await?;
        self.list_sessions_in(ctx, &folders).await
    }

    /// [`Self::list_sessions`], resolved against `folders` (QL-16: as the tree is, or as a change would make it).
    pub(crate) async fn list_sessions_in(&self, ctx: &Context, folders: &Folders) -> Result<Vec<SessionRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            session_columns!(),
            " FROM sessions WHERE workspace_id = ? ORDER BY name COLLATE NOCASE, host"
        ))
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let mut sessions = rows.iter().map(row_to_session).collect::<Result<Vec<_>>>()?;
        Self::resolve_sessions(&mut sessions, folders);
        Ok(sessions)
    }

    /// One session, with what applies to it (QL-16).
    pub async fn get_session(&self, ctx: &Context, id: Uuid) -> Result<Option<SessionRecord>> {
        let folders = self.session_folders(ctx).await?;
        self.get_session_in(ctx, id, &folders).await
    }

    pub(crate) async fn get_session_in(
        &self,
        ctx: &Context,
        id: Uuid,
        folders: &Folders,
    ) -> Result<Option<SessionRecord>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            session_columns!(),
            " FROM sessions WHERE workspace_id = ? AND id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some(mut session) = row.as_ref().map(row_to_session).transpose()? else {
            return Ok(None);
        };
        Self::resolve_sessions(std::slice::from_mut(&mut session), folders);
        Ok(Some(session))
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
                                   startup_on_reconnect, prompt_hook, environment, color, vm_id, imported_from,
                                   created_at, updated_at, auth_from_folder, jump_direct, kind_options)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(input.folder_id.map(|f| f.to_string()))
        .bind(&input.name)
        .bind(input.kind.protocol())
        .bind(&input.host)
        .bind(i64::from(input.port))
        .bind(&input.username)
        .bind(method_column(&input.auth))
        .bind(input.auth.credential_id().map(|s| s.0.to_string()))
        .bind(input.auth.passphrase_id().map(|s| s.0.to_string()))
        .bind(input.jump_session_id.map(|j| j.to_string()))
        .bind(&input.startup_command)
        .bind(i64::from(input.startup_on_reconnect))
        .bind(input.prompt_hook.map(i64::from))
        .bind(input.environment.as_str())
        .bind(input.color.map(SessionColor::as_str))
        .bind(&input.vm_id)
        .bind(imported_from)
        .bind(&now)
        .bind(&now)
        .bind(i64::from(input.auth == SessionAuth::Folder))
        .bind(i64::from(input.jump_direct && input.jump_session_id.is_none()))
        .bind(input.kind.options_json())
        .execute(&mut *tx)
        .await?;
        set_session_tags(&mut tx, ctx, id, &input.tags).await?;
        tx.commit().await?;
        Ok(())
    }

    /// `input` must already be checked. False when there is no such session.
    pub(crate) async fn update_session(&self, ctx: &Context, id: Uuid, input: &SessionInput) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        if !update_session_in(&mut tx, ctx, id, input).await? {
            return Ok(false);
        }
        tx.commit().await?;
        Ok(true)
    }

    /// QL-28: several checked edits in one transaction; none is saved unless all are. Returns how many.
    pub(crate) async fn update_sessions(&self, ctx: &Context, edits: &[(Uuid, SessionInput)]) -> Result<usize> {
        let mut tx = self.pool.begin().await?;
        for (id, input) in edits {
            if !update_session_in(&mut tx, ctx, *id, input).await? {
                return Err(CoreError::UnknownTarget(format!("session {id}")));
            }
        }
        tx.commit().await?;
        Ok(edits.len())
    }
}

/// One checked edit, inside `tx`. False when there is no such session.
async fn update_session_in(
    tx: &mut Transaction<'_, Sqlite>,
    ctx: &Context,
    id: Uuid,
    input: &SessionInput,
) -> Result<bool> {
    {
        let done = sqlx::query(
            "UPDATE sessions SET folder_id = ?, name = ?, host = ?, port = ?, username = ?, auth_method = ?,
                 credential_id = ?, key_passphrase_id = ?, jump_session_id = ?, startup_command = ?,
                 startup_on_reconnect = ?, prompt_hook = ?, environment = ?, color = ?, vm_id = ?, user_id = ?,
                 updated_at = ?, auth_from_folder = ?, jump_direct = ?, protocol = ?, kind_options = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(input.folder_id.map(|f| f.to_string()))
        .bind(&input.name)
        .bind(&input.host)
        .bind(i64::from(input.port))
        .bind(&input.username)
        .bind(method_column(&input.auth))
        .bind(input.auth.credential_id().map(|s| s.0.to_string()))
        .bind(input.auth.passphrase_id().map(|s| s.0.to_string()))
        .bind(input.jump_session_id.map(|j| j.to_string()))
        .bind(&input.startup_command)
        .bind(i64::from(input.startup_on_reconnect))
        .bind(input.prompt_hook.map(i64::from))
        .bind(input.environment.as_str())
        .bind(input.color.map(SessionColor::as_str))
        .bind(&input.vm_id)
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(i64::from(input.auth == SessionAuth::Folder))
        .bind(i64::from(input.jump_direct && input.jump_session_id.is_none()))
        .bind(input.kind.protocol())
        .bind(input.kind.options_json())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&mut **tx)
        .await?;
        if done.rows_affected() == 0 {
            return Ok(false);
        }
        set_session_tags(tx, ctx, id, &input.tags).await?;
        Ok(true)
    }
}

impl Store {
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

    /// Each session's jump host as it applies (QL-16: its own, or its folders' as `folders` has them), for the
    /// cycle check.
    pub(crate) async fn session_jumps_in(
        &self,
        ctx: &Context,
        folders: &Folders,
    ) -> Result<HashMap<Uuid, Option<Uuid>>> {
        Ok(self
            .list_sessions_in(ctx, folders)
            .await?
            .into_iter()
            .map(|s| (s.id, s.jump_session_id))
            .collect())
    }

    /// Every folder with its defaults (QL-16), in the tree's order.
    pub async fn list_session_folders(&self, ctx: &Context) -> Result<Vec<SessionFolder>> {
        let rows = sqlx::query(
            "SELECT f.id, f.parent_id, f.name, f.sort_order,
                    d.username AS d_username, d.auth_method AS d_auth_method, d.credential_id AS d_credential_id,
                    d.key_passphrase_id AS d_key_passphrase_id, d.jump_session_id AS d_jump_session_id,
                    d.jump_direct AS d_jump_direct, d.environment AS d_environment, d.tags AS d_tags
             FROM session_folders f
             LEFT JOIN session_folder_defaults d ON d.folder_id = f.id AND d.workspace_id = f.workspace_id
             WHERE f.workspace_id = ?
             ORDER BY f.sort_order, f.name COLLATE NOCASE",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_folder).collect()
    }

    /// QL-16: what a folder sets for its sessions (already checked by `crate::sessions`). Empty defaults remove
    /// the row.
    pub(crate) async fn set_folder_defaults(
        &self,
        ctx: &Context,
        folder: Uuid,
        defaults: &FolderDefaults,
    ) -> Result<()> {
        if defaults.is_empty() {
            sqlx::query("DELETE FROM session_folder_defaults WHERE workspace_id = ? AND folder_id = ?")
                .bind(ctx.workspace_id.to_string())
                .bind(folder.to_string())
                .execute(&self.pool)
                .await?;
            return Ok(());
        }
        let now = now_rfc3339();
        let auth = defaults.auth.as_ref();
        let tags = defaults.tags.join(&TAG_SEPARATOR.to_string());
        sqlx::query(
            "INSERT INTO session_folder_defaults (folder_id, workspace_id, user_id, username, auth_method, credential_id,
                                                  key_passphrase_id, jump_session_id, jump_direct, environment, tags,
                                                  created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(folder_id) DO UPDATE SET user_id = excluded.user_id, username = excluded.username,
                 auth_method = excluded.auth_method, credential_id = excluded.credential_id,
                 key_passphrase_id = excluded.key_passphrase_id, jump_session_id = excluded.jump_session_id,
                 jump_direct = excluded.jump_direct, environment = excluded.environment, tags = excluded.tags,
                 updated_at = excluded.updated_at",
        )
        .bind(folder.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(&defaults.username)
        .bind(auth.map(SessionAuth::method))
        .bind(auth.and_then(SessionAuth::credential_id).map(|s| s.0.to_string()))
        .bind(auth.and_then(SessionAuth::passphrase_id).map(|s| s.0.to_string()))
        .bind(defaults.jump_session_id.map(|j| j.to_string()))
        .bind(i64::from(defaults.jump_direct && defaults.jump_session_id.is_none()))
        .bind(defaults.environment.map(Environment::as_str))
        .bind(tags)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
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
    ///
    /// QL-16: the label is the one that applies, so a label the session has from its folders counts (a session
    /// in a Prod folder is Prod).
    pub async fn find_session_target(&self, ctx: &Context, id: Uuid) -> Result<Option<(String, Environment, bool)>> {
        let Some(session) = self.get_session(ctx, id).await? else {
            return Ok(None);
        };
        let row = sqlx::query(
            "SELECT s.protected, v.environment AS vm_environment, v.protected AS vm_protected
             FROM sessions s LEFT JOIN vms v ON v.id = s.vm_id AND v.workspace_id = s.workspace_id
             WHERE s.workspace_id = ? AND s.id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| -> Result<_> {
            let env = session.environment;
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
                session.name.clone(),
                env,
                protected != 0 || vm_protected.unwrap_or(0) != 0,
            ))
        })
        .transpose()
    }

    /// QL-02: a terminal to the session was opened now (Recent sessions). Not an edit: `updated_at`
    /// stays. QL-26: it goes to the top of the recently opened items too.
    pub(crate) async fn record_session_opened(&self, ctx: &Context, id: Uuid) -> Result<()> {
        let done = sqlx::query("UPDATE sessions SET last_opened_at = ? WHERE workspace_id = ? AND id = ?")
            .bind(now_rfc3339())
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if done.rows_affected() > 0 {
            self.note_recent(ctx, crate::stars::RecentKind::Session, &id.to_string())
                .await?;
        }
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
        let mut sessions = rows.iter().map(row_to_session).collect::<Result<Vec<_>>>()?;
        Self::resolve_sessions(&mut sessions, &self.session_folders(ctx).await?);
        Ok(sessions)
    }

    /// QL-01: how the session's VM link was made, after a create or an edit set `vm_id`.
    pub(crate) async fn set_vm_link_kind(&self, ctx: &Context, id: Uuid, link: Option<VmLink>) -> Result<()> {
        sqlx::query("UPDATE sessions SET vm_link = ? WHERE workspace_id = ? AND id = ?")
            .bind(link.map(VmLink::as_str))
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// QL-01: auto-linking's write. Changes nothing when the user decided in the meantime (a manual
    /// link or removal) or the link is no longer `expected`, so a manual link is never overwritten.
    /// `vm_id: None` removes an automatic link. True when it changed the session.
    pub(crate) async fn set_auto_vm_link(
        &self,
        ctx: &Context,
        id: Uuid,
        expected: Option<&str>,
        vm_id: Option<&str>,
    ) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE sessions SET vm_id = ?, vm_link = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ? AND vm_id IS ?
               AND (vm_link = 'auto' OR (vm_link IS NULL AND vm_id IS NULL))",
        )
        .bind(vm_id)
        .bind(vm_id.map(|_| VmLink::Auto.as_str()))
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .bind(expected)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// QL-01: the user's choice of VM, or none. Auto-linking leaves it alone. False when there is no
    /// such session.
    pub(crate) async fn set_manual_vm_link(&self, ctx: &Context, id: Uuid, vm_id: Option<&str>) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE sessions SET vm_id = ?, vm_link = 'manual', user_id = ?, updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(vm_id)
        .bind(ctx.user_id.to_string())
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
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

    /// Connection details for the remote adapter, with the whole jump host chain (SS-07): the
    /// session's jump host, that one's own, and so on, each with its own login. Jump hosts that lead
    /// back to a session on the way, or more than [`MAX_JUMP_DEPTH`] of them, can't connect: an
    /// error that names them. So is a key login with no key chosen, here or on a jump host.
    ///
    /// QL-16: each hop's user, login and jump host are the ones that apply to it (its own, then its folders').
    ///
    /// SS-12: SSH sessions only, so nothing that connects over SSH (terminals, bulk runs, MultiExec, the dashboard's
    /// guest polling, containers, host details, key pushes) ever reaches a Telnet, serial, RDP or VNC session that
    /// way: [`CoreError::WrongSessionKind`]. A jump host on the way must be SSH too.
    pub async fn session_spec(&self, ctx: &Context, id: Uuid) -> Result<Option<SessionSpec>> {
        let folders = self.session_folders(ctx).await?;
        let Some(session) = self.get_session_in(ctx, id, &folders).await? else {
            return Ok(None);
        };
        if session.protocol != "ssh" {
            return Err(CoreError::WrongSessionKind {
                session: session.name.clone(),
                kind: session.kind.label(),
                needs: "this works over SSH only".into(),
            });
        }
        self.ssh_chain(ctx, session, &folders).await.map(Some)
    }

    async fn ssh_chain(&self, ctx: &Context, session: SessionRecord, folders: &Folders) -> Result<SessionSpec> {
        let mut names = vec![session.name.clone()];
        let mut seen = vec![session.id];
        let mut jumps: Vec<SessionRecord> = Vec::new();
        let mut next = session.jump_session_id;
        while let Some(jump_id) = next {
            if let Some(at) = seen.iter().position(|s| *s == jump_id) {
                let mut route = names.iter().map(|n| format!("'{n}'")).collect::<Vec<_>>();
                route.push(format!("'{}'", names[at]));
                return Err(CoreError::JumpChain(format!(
                    "the jump hosts of '{}' go round in a loop ({}), so it can't connect. Choose another jump host for one of them",
                    session.name,
                    route.join(" -> ")
                )));
            }
            if jumps.len() == MAX_JUMP_DEPTH {
                return Err(CoreError::JumpChain(format!(
                    "'{}' goes through more than {MAX_JUMP_DEPTH} jump hosts, so it can't connect",
                    session.name
                )));
            }
            // A jump host deleted meanwhile leaves the chain shorter (the link is cleared with it).
            let Some(jump) = self.get_session_in(ctx, jump_id, folders).await? else {
                break;
            };
            if jump.protocol != "ssh" {
                return Err(CoreError::JumpChain(format!(
                    "the jump host '{}' of '{}' is a {} session, and a jump host is an SSH session. Choose another one",
                    jump.name,
                    session.name,
                    jump.kind.label()
                )));
            }
            seen.push(jump.id);
            names.push(jump.name.clone());
            next = jump.jump_session_id;
            jumps.push(jump);
        }
        // Built from the outermost jump host inwards, each holding the one before it.
        let mut via: Option<Box<SessionSpec>> = None;
        for jump in jumps.into_iter().rev() {
            let auth = spec_auth(&jump, Some(&session.name))?;
            via = Some(Box::new(spec_of(jump, auth, via)));
        }
        let auth = spec_auth(&session, None)?;
        Ok(spec_of(session, auth, via))
    }
}

/// How a session logs in, for connecting. A key login with no key chosen can't connect; `jump_of`
/// names the session it is the jump host of, if it is one.
fn spec_auth(session: &SessionRecord, jump_of: Option<&str>) -> Result<AuthMethod> {
    if let SessionAuth::Key { key_id: None, .. } = &session.auth {
        let what = match jump_of {
            Some(of) => format!("The jump host '{}' (of '{of}')", session.name),
            None => format!("'{}'", session.name),
        };
        return Err(CoreError::InvalidInput(format!(
            "{what} logs in with a key, but no key is chosen. Edit that session to choose one."
        )));
    }
    Ok(auth_method(&session.auth))
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
        startup_on_reconnect: false,
        prompt_hook: input.prompt_hook,
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
        // A key login with no key chosen never gets here (see `spec_auth`, `unsaved_spec`).
        SessionAuth::Key { key_id: None, .. } | SessionAuth::Agent => AuthMethod::Agent,
        // QL-16: what applies to a session is never "as its folders say"; a quick connection without a folder
        // gets the app's default.
        SessionAuth::Folder => AuthMethod::Password(None),
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
        startup_on_reconnect: session.startup_on_reconnect,
        prompt_hook: session.prompt_hook,
    }
}
