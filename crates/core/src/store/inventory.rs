//! VM and session records (VM-01, SS-01).

use std::path::Path;

use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use super::Store;
use crate::adapters::remote::{AuthMethod, SessionSpec};
use crate::adapters::vmware::VmxInfo;
use crate::domain::{now_rfc3339, Context, Environment};
use crate::error::Result;
use crate::vault::SecretId;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmRecord {
    pub id: String,
    pub vmx_path: String,
    pub display_name: String,
    pub guest_os: Option<String>,
    pub num_vcpus: Option<u32>,
    pub memsize_mb: Option<u32>,
    pub power_state: String,
    pub ip_address: Option<String>,
    pub tools_state: Option<String>,
    pub environment: Environment,
    pub protected: bool,
    pub last_seen_at: Option<String>,
}

/// A running VM as reported by Workstation.
pub struct DiscoveredVm {
    pub vmx_path: String,
    pub info: VmxInfo,
}

macro_rules! vm_columns {
    () => {
        "id, vmx_path, display_name, guest_os, num_vcpus, memsize_mb, power_state, ip_address, tools_state,
         environment, protected, last_seen_at"
    };
}

impl Store {
    /// Saves what `vmrun list` reported: these VMs are running, every other known VM is not.
    pub async fn record_running_vms(&self, ctx: &Context, running: &[DiscoveredVm]) -> Result<Vec<VmRecord>> {
        let ws = ctx.workspace_id.to_string();
        let user = ctx.user_id.to_string();
        let now = now_rfc3339();
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "UPDATE vms SET power_state = 'not_running', updated_at = ?
             WHERE workspace_id = ? AND power_state = 'running'",
        )
        .bind(&now)
        .bind(&ws)
        .execute(&mut *tx)
        .await?;

        for vm in running {
            let name = vm.info.display_name.clone().unwrap_or_else(|| {
                Path::new(&vm.vmx_path)
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| vm.vmx_path.clone())
            });
            sqlx::query(
                "INSERT INTO vms (id, workspace_id, user_id, vmx_path, display_name, guest_os, num_vcpus, memsize_mb,
                                  power_state, last_seen_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?)
                 ON CONFLICT(workspace_id, vmx_path) DO UPDATE SET
                     display_name = excluded.display_name,
                     guest_os     = excluded.guest_os,
                     num_vcpus    = excluded.num_vcpus,
                     memsize_mb   = excluded.memsize_mb,
                     power_state  = 'running',
                     last_seen_at = excluded.last_seen_at,
                     updated_at   = excluded.updated_at",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&ws)
            .bind(&user)
            .bind(&vm.vmx_path)
            .bind(&name)
            .bind(&vm.info.guest_os)
            .bind(vm.info.num_vcpus.map(i64::from))
            .bind(vm.info.memsize_mb.map(i64::from))
            .bind(&now)
            .bind(&now)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        self.list_vms(ctx, Some("running")).await
    }

    pub async fn list_vms(&self, ctx: &Context, power_state: Option<&str>) -> Result<Vec<VmRecord>> {
        let rows = match power_state {
            Some(state) => {
                sqlx::query(concat!(
                    "SELECT ",
                    vm_columns!(),
                    " FROM vms WHERE workspace_id = ? AND power_state = ? ORDER BY display_name COLLATE NOCASE"
                ))
                .bind(ctx.workspace_id.to_string())
                .bind(state)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query(concat!(
                    "SELECT ",
                    vm_columns!(),
                    " FROM vms WHERE workspace_id = ? ORDER BY display_name COLLATE NOCASE"
                ))
                .bind(ctx.workspace_id.to_string())
                .fetch_all(&self.pool)
                .await?
            }
        };
        rows.iter().map(row_to_vm).collect()
    }

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
    let protected: i64 = row.try_get("protected")?;
    let cpus: Option<i64> = row.try_get("num_vcpus")?;
    let mem: Option<i64> = row.try_get("memsize_mb")?;
    Ok(VmRecord {
        id: row.try_get("id")?,
        vmx_path: row.try_get("vmx_path")?,
        display_name: row.try_get("display_name")?,
        guest_os: row.try_get("guest_os")?,
        num_vcpus: cpus.and_then(|v| u32::try_from(v).ok()),
        memsize_mb: mem.and_then(|v| u32::try_from(v).ok()),
        power_state: row.try_get("power_state")?,
        ip_address: row.try_get("ip_address")?,
        tools_state: row.try_get("tools_state")?,
        environment: Environment::parse(&env),
        protected: protected != 0,
        last_seen_at: row.try_get("last_seen_at")?,
    })
}
