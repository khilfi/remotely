//! VM and session records (VM-01, SS-01).

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use super::Store;
use crate::adapters::remote::{AuthMethod, SessionSpec};
use crate::adapters::vmware::{path_key, VmxInfo};
use crate::domain::{now_rfc3339, Context, Environment, PowerState};
use crate::error::Result;
use crate::vault::SecretId;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmRecord {
    pub id: String,
    pub vmx_path: String,
    pub display_name: String,
    /// Workstation's guest OS id, e.g. `ubuntu-64`.
    pub guest_os: Option<String>,
    /// What the guest calls itself through VMware Tools, e.g. "Ubuntu 24.04 LTS".
    pub guest_os_name: Option<String>,
    pub num_vcpus: Option<u32>,
    pub memsize_mb: Option<u32>,
    pub power_state: PowerState,
    pub ip_address: Option<String>,
    /// [`crate::adapters::vmware::ToolsState`] as text; `None` when the VM is not running.
    pub tools_state: Option<String>,
    pub environment: Environment,
    pub protected: bool,
    /// Tag names (VM-02), sorted.
    pub tags: Vec<String>,
    pub last_seen_at: Option<String>,
}

/// A VM found by an inventory refresh (VM-01).
#[derive(Debug, Clone)]
pub struct DiscoveredVm {
    pub vmx_path: String,
    pub display_name: String,
    pub info: VmxInfo,
    pub power_state: PowerState,
    pub tools_state: Option<String>,
    pub ip_address: Option<String>,
}

/// Separates tag names in the `tags` column of `vm_columns!` (SQL `char(31)`); tag names cannot
/// contain control characters.
const TAG_SEPARATOR: char = '\u{1f}';

macro_rules! vm_columns {
    () => {
        "id, vmx_path, display_name, guest_os, guest_os_name, num_vcpus, memsize_mb, power_state, ip_address,
         tools_state, environment, protected, last_seen_at,
         (SELECT group_concat(t.name, char(31)) FROM target_tags tt JOIN tags t ON t.id = tt.tag_id
          WHERE tt.target_kind = 'vm' AND tt.target_id = vms.id) AS tags"
    };
}

impl Store {
    /// Saves what a refresh found. VMs it did not find are marked missing and drop out of
    /// [`Store::list_vms`]; their rows stay so tags, labels and protection survive. A VM the app
    /// paused stays paused while vmrun still lists it as running, with its last Tools state and IP
    /// (a paused guest cannot answer).
    pub async fn record_inventory(&self, ctx: &Context, found: &[DiscoveredVm]) -> Result<()> {
        let ws = ctx.workspace_id.to_string();
        let user = ctx.user_id.to_string();
        let now = now_rfc3339();
        let mut tx = self.pool.begin().await?;

        sqlx::query("UPDATE vms SET missing = 1, updated_at = ? WHERE workspace_id = ? AND missing = 0")
            .bind(&now)
            .bind(&ws)
            .execute(&mut *tx)
            .await?;

        for vm in found {
            sqlx::query(
                "INSERT INTO vms (id, workspace_id, user_id, vmx_path, display_name, guest_os, guest_os_name,
                                  num_vcpus, memsize_mb, power_state, ip_address, tools_state, missing,
                                  last_seen_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                 ON CONFLICT(workspace_id, vmx_path) DO UPDATE SET
                     display_name  = excluded.display_name,
                     guest_os      = excluded.guest_os,
                     guest_os_name = COALESCE(excluded.guest_os_name, vms.guest_os_name),
                     num_vcpus     = excluded.num_vcpus,
                     memsize_mb    = excluded.memsize_mb,
                     power_state   = CASE WHEN excluded.power_state = 'running' AND vms.power_state = 'paused'
                                          THEN 'paused' ELSE excluded.power_state END,
                     ip_address    = CASE WHEN excluded.power_state = 'running' AND vms.power_state = 'paused'
                                          THEN vms.ip_address ELSE excluded.ip_address END,
                     tools_state   = CASE WHEN excluded.power_state = 'running' AND vms.power_state = 'paused'
                                          THEN vms.tools_state ELSE excluded.tools_state END,
                     missing       = 0,
                     last_seen_at  = excluded.last_seen_at,
                     updated_at    = excluded.updated_at",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&ws)
            .bind(&user)
            .bind(&vm.vmx_path)
            .bind(&vm.display_name)
            .bind(&vm.info.guest_os)
            .bind(&vm.info.guest_os_name)
            .bind(vm.info.num_vcpus.map(i64::from))
            .bind(vm.info.memsize_mb.map(i64::from))
            .bind(vm.power_state.as_str())
            .bind(&vm.ip_address)
            .bind(&vm.tools_state)
            .bind(&now)
            .bind(&now)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Every VM the last refresh found, by name.
    pub async fn list_vms(&self, ctx: &Context) -> Result<Vec<VmRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            vm_columns!(),
            " FROM vms WHERE workspace_id = ? AND missing = 0 ORDER BY display_name COLLATE NOCASE, vmx_path"
        ))
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_vm).collect()
    }

    /// A VM by .vmx path (any letter case), including one the last refresh did not find.
    pub async fn find_vm(&self, ctx: &Context, vmx_path: &str) -> Result<Option<VmRecord>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            vm_columns!(),
            " FROM vms WHERE workspace_id = ? AND vmx_path = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(vmx_path)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_vm).transpose()
    }

    /// Saved power state per VM, keyed by [`path_key`].
    pub async fn vm_power_states(&self, ctx: &Context) -> Result<HashMap<String, PowerState>> {
        let rows = sqlx::query("SELECT vmx_path, power_state FROM vms WHERE workspace_id = ?")
            .bind(ctx.workspace_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                let path: String = r.try_get("vmx_path")?;
                let state: String = r.try_get("power_state")?;
                Ok((path_key(Path::new(&path)), PowerState::parse(&state)))
            })
            .collect()
    }

    /// After a power job succeeds, so the list is right before the next refresh. A VM that is off or
    /// suspended has no IP address or running Tools.
    pub(crate) async fn set_vm_power_state(&self, ctx: &Context, vmx_path: &str, state: PowerState) -> Result<()> {
        let off = !state.is_on();
        sqlx::query(
            "UPDATE vms SET power_state = ?,
                 ip_address  = CASE WHEN ? THEN NULL ELSE ip_address END,
                 tools_state = CASE WHEN ? THEN NULL ELSE tools_state END,
                 updated_at  = ?
             WHERE workspace_id = ? AND vmx_path = ?",
        )
        .bind(state.as_str())
        .bind(off)
        .bind(off)
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(vmx_path)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Name, label and protection of a saved session.
    pub async fn find_session_target(&self, ctx: &Context, id: Uuid) -> Result<Option<(String, Environment, bool)>> {
        let row = sqlx::query("SELECT name, environment, protected FROM sessions WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| -> Result<_> {
            let env: String = r.try_get("environment")?;
            let protected: i64 = r.try_get("protected")?;
            Ok((r.try_get("name")?, Environment::parse(&env), protected != 0))
        })
        .transpose()
    }

    /// Connection details for the remote adapter. Jump hosts are resolved one level for now.
    pub async fn session_spec(&self, ctx: &Context, id: Uuid) -> Result<Option<SessionSpec>> {
        let row = sqlx::query(
            "SELECT id, name, host, port, username, auth_method, credential_id, key_passphrase_id, environment
             FROM sessions WHERE workspace_id = ? AND id = ?",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };

        let secret = |col: &str| -> Result<Option<SecretId>> {
            let v: Option<String> = r.try_get(col)?;
            Ok(v.and_then(|s| Uuid::parse_str(&s).ok()).map(SecretId))
        };
        let auth_method: String = r.try_get("auth_method")?;
        let auth = match (auth_method.as_str(), secret("credential_id")?) {
            ("password", Some(id)) => AuthMethod::Password(id),
            ("key", Some(key)) => AuthMethod::PrivateKey {
                key,
                passphrase: secret("key_passphrase_id")?,
            },
            _ => AuthMethod::Agent,
        };
        let port: i64 = r.try_get("port")?;
        let env: String = r.try_get("environment")?;
        Ok(Some(SessionSpec {
            id,
            name: r.try_get("name")?,
            host: r.try_get("host")?,
            port: u16::try_from(port).unwrap_or(22),
            username: r.try_get::<Option<String>, _>("username")?.unwrap_or_default(),
            auth,
            jump: None,
            environment: Environment::parse(&env),
        }))
    }
}

fn row_to_vm(row: &sqlx::sqlite::SqliteRow) -> Result<VmRecord> {
    let env: String = row.try_get("environment")?;
    let state: String = row.try_get("power_state")?;
    let protected: i64 = row.try_get("protected")?;
    let cpus: Option<i64> = row.try_get("num_vcpus")?;
    let mem: Option<i64> = row.try_get("memsize_mb")?;
    let tags: Option<String> = row.try_get("tags")?;
    let mut tags: Vec<String> = tags
        .unwrap_or_default()
        .split(TAG_SEPARATOR)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect();
    tags.sort_by_key(|t| t.to_lowercase());
    Ok(VmRecord {
        id: row.try_get("id")?,
        vmx_path: row.try_get("vmx_path")?,
        display_name: row.try_get("display_name")?,
        guest_os: row.try_get("guest_os")?,
        guest_os_name: row.try_get("guest_os_name")?,
        num_vcpus: cpus.and_then(|v| u32::try_from(v).ok()),
        memsize_mb: mem.and_then(|v| u32::try_from(v).ok()),
        power_state: PowerState::parse(&state),
        ip_address: row.try_get("ip_address")?,
        tools_state: row.try_get("tools_state")?,
        environment: Environment::parse(&env),
        protected: protected != 0,
        tags,
        last_seen_at: row.try_get("last_seen_at")?,
    })
}
