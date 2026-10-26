//! VM records (VM-01).

use std::collections::HashMap;
use std::path::Path;

use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use super::Store;
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::vmware::{path_key, VmxInfo};
use crate::domain::{now_rfc3339, Context, Environment, PowerState, UserId, WorkspaceId};
use crate::error::{CoreError, Result};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmRecord {
    pub id: String,
    /// The VM's key: its .vmx path (VMware), or its UUID (VirtualBox, VM-18).
    pub vmx_path: String,
    /// VM-18: the hypervisor that runs it.
    pub hypervisor: Hypervisor,
    /// VM-18: a VirtualBox VM's settings file (.vbox); `None` for VMware, whose key is its .vmx.
    pub config_path: Option<String>,
    pub display_name: String,
    /// The guest OS chosen for the VM: Workstation's id (`ubuntu-64`) or VirtualBox's OS type
    /// ("Ubuntu (64-bit)").
    pub guest_os: Option<String>,
    /// What the guest calls itself through VMware Tools ("Ubuntu 24.04 LTS") or the Guest Additions.
    pub guest_os_name: Option<String>,
    pub num_vcpus: Option<u32>,
    pub memsize_mb: Option<u32>,
    pub power_state: PowerState,
    pub ip_address: Option<String>,
    /// [`crate::adapters::vmware::ToolsState`] (VMware Tools or Guest Additions) as text; `None` when
    /// the VM is not running.
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
    /// The VM's key: .vmx path or VirtualBox UUID.
    pub vmx_path: String,
    pub display_name: String,
    pub info: VmxInfo,
    pub power_state: PowerState,
    pub tools_state: Option<String>,
    pub ip_address: Option<String>,
    pub hypervisor: Hypervisor,
    /// VM-18: a VirtualBox VM's .vbox file.
    pub config_path: Option<String>,
}

impl VmRecord {
    /// The folder holding the VM's files: the .vmx's, or the .vbox's (VM-07, MO-04 free space).
    pub fn folder(&self) -> Option<&Path> {
        match self.hypervisor {
            Hypervisor::Vmware => Path::new(&self.vmx_path).parent(),
            Hypervisor::VirtualBox => self.config_path.as_deref().and_then(|p| Path::new(p).parent()),
        }
    }
}

/// Separates tag names in the `tags` column of `vm_columns!` (SQL `char(31)`); tag names cannot
/// contain control characters.
const TAG_SEPARATOR: char = '\u{1f}';

macro_rules! vm_columns {
    () => {
        "id, vmx_path, hypervisor, config_path, display_name, guest_os, guest_os_name, num_vcpus, memsize_mb, power_state, ip_address,
         tools_state, environment, protected, last_seen_at,
         (SELECT group_concat(t.name, char(31)) FROM target_tags tt JOIN tags t ON t.id = tt.tag_id
          WHERE tt.target_kind = 'vm' AND tt.target_id = vms.id) AS tags"
    };
}

impl Store {
    /// Saves what a refresh found into the context's workspace, adding every VM no workspace has to it first (store
    /// tests and single-workspace callers). See [`Store::record_discovery`].
    pub async fn record_inventory(&self, ctx: &Context, found: &[DiscoveredVm]) -> Result<()> {
        self.record_discovery(ctx.user_id, found, &Hypervisor::ALL, Some(ctx))
            .await
            .map(drop)
    }

    /// FD-02, VM-01: saves what a refresh found on this PC. Each VM goes to the workspace it belongs to
    /// (`vm_assignments`); with `auto` (the user's only active workspace), a VM no workspace has joins that one
    /// first. VMs of the user's workspaces it did not find are marked missing and drop out of [`Store::list_vms`];
    /// their rows stay so tags, labels and protection survive. Returns the VMs found that no workspace has.
    ///
    /// VM-18: only the hypervisors in `read` were read in full; VMs of the others are left as they were (VirtualBox
    /// could not be asked this time), not marked missing. A VM the app paused stays paused while vmrun still lists it
    /// as running, with its last Tools state and IP (a paused guest cannot answer); a VirtualBox VM reports its own
    /// pause, so only a VMware VM stays paused that way.
    pub(crate) async fn record_discovery(
        &self,
        user: UserId,
        found: &[DiscoveredVm],
        read: &[Hypervisor],
        auto: Option<&Context>,
    ) -> Result<Vec<DiscoveredVm>> {
        let owners = self.vm_assignments().await?;
        let now = now_rfc3339();
        let mut unassigned = Vec::new();
        let mut tx = self.pool.begin().await?;

        for hypervisor in read {
            sqlx::query(
                "UPDATE vms SET missing = 1, updated_at = ?
                 WHERE workspace_id IN (SELECT id FROM workspaces WHERE user_id = ?) AND missing = 0 AND hypervisor = ?",
            )
            .bind(&now)
            .bind(user.to_string())
            .bind(hypervisor.as_str())
            .execute(&mut *tx)
            .await?;
        }

        for vm in found {
            let owner = match owners.get(&vm.vmx_path.to_lowercase()) {
                Some((workspace, owner)) if *owner == user => Context {
                    workspace_id: *workspace,
                    user_id: user,
                },
                // Another Windows account's VM (a database two accounts used): not this user's to list.
                Some(_) => continue,
                None => match auto {
                    Some(ctx) => {
                        sqlx::query(
                            "INSERT INTO vm_assignments (vm_key, workspace_id, user_id, assigned_at) VALUES (?, ?, ?, ?)
                             ON CONFLICT(vm_key) DO NOTHING",
                        )
                        .bind(&vm.vmx_path)
                        .bind(ctx.workspace_id.to_string())
                        .bind(user.to_string())
                        .bind(&now)
                        .execute(&mut *tx)
                        .await?;
                        *ctx
                    }
                    None => {
                        unassigned.push(vm.clone());
                        continue;
                    }
                },
            };
            upsert_vm(&mut tx, &owner, vm, &now).await?;
        }
        tx.commit().await?;
        Ok(unassigned)
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

    /// FD-02: every VM listed in any of the user's workspaces. For what belongs to this PC rather than to an
    /// engagement (the RAM the running VMs hold, which folders hold a VM, whether a host network has a Prod VM on
    /// it): never shown as a list, and never named to a workspace that doesn't have the VM.
    pub(crate) async fn list_vms_all_workspaces(&self, user: UserId) -> Result<Vec<VmRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            vm_columns!(),
            " FROM vms WHERE missing = 0 AND workspace_id IN (SELECT id FROM workspaces WHERE user_id = ?)
              ORDER BY display_name COLLATE NOCASE, vmx_path"
        ))
        .bind(user.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_vm).collect()
    }

    /// FD-02: every VM a workspace of the user lists, with that workspace (a VM is listed in at most one: the one it
    /// belongs to). For the collector, which records each running VM's host side in its own workspace's history.
    pub(crate) async fn listed_vms_by_workspace(&self, user: UserId) -> Result<Vec<(WorkspaceId, VmRecord)>> {
        let rows = sqlx::query(concat!(
            "SELECT workspace_id AS owner, ",
            vm_columns!(),
            " FROM vms WHERE missing = 0 AND workspace_id IN (SELECT id FROM workspaces WHERE user_id = ?)"
        ))
        .bind(user.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let owner: String = row.try_get("owner")?;
                Ok((WorkspaceId(super::parse_uuid(&owner)?), row_to_vm(row)?))
            })
            .collect()
    }

    /// A VM by its id, including one the last refresh did not find (BX-01: a session's VM).
    pub async fn vm_by_id(&self, ctx: &Context, id: &str) -> Result<Option<VmRecord>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            vm_columns!(),
            " FROM vms WHERE workspace_id = ? AND id = ?"
        ))
        .bind(ctx.workspace_id.to_string())
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_vm).transpose()
    }

    /// A VM by its key (.vmx path or VirtualBox UUID, any letter case), including one the last
    /// refresh did not find.
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
    /// FD-02: of every VM the user's workspaces list (the PC's, for a refresh), by key.
    pub async fn vm_power_states(&self, ctx: &Context) -> Result<HashMap<String, PowerState>> {
        let rows = sqlx::query(
            "SELECT vmx_path, power_state FROM vms
             WHERE missing = 0 AND workspace_id IN (SELECT id FROM workspaces WHERE user_id = ?)",
        )
        .bind(ctx.user_id.to_string())
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

    /// AP-04. Only the job runner calls this, for a command the bus cleared. False when the VM is not
    /// in the inventory.
    pub(crate) async fn set_vm_protected(&self, ctx: &Context, vmx_path: &str, protected: bool) -> Result<bool> {
        let done = sqlx::query("UPDATE vms SET protected = ?, updated_at = ? WHERE workspace_id = ? AND vmx_path = ?")
            .bind(i64::from(protected))
            .bind(now_rfc3339())
            .bind(ctx.workspace_id.to_string())
            .bind(vmx_path)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// SS-06 for VMs: sets each VM's environment label, all or none. [`crate::inventory::Inventory`]
    /// checks and audits the change; nothing else calls this. A refresh keeps the label.
    pub(crate) async fn set_vm_environment(
        &self,
        ctx: &Context,
        vmx_paths: &[String],
        environment: Environment,
    ) -> Result<()> {
        if vmx_paths.is_empty() {
            return Err(CoreError::NoTargets);
        }
        let ws = ctx.workspace_id.to_string();
        let now = now_rfc3339();
        let mut tx = self.pool.begin().await?;
        for path in vmx_paths {
            let done =
                sqlx::query("UPDATE vms SET environment = ?, updated_at = ? WHERE workspace_id = ? AND vmx_path = ?")
                    .bind(environment.as_str())
                    .bind(&now)
                    .bind(&ws)
                    .bind(path)
                    .execute(&mut *tx)
                    .await?;
            if done.rows_affected() == 0 {
                return Err(CoreError::UnknownTarget(path.clone()));
            }
        }
        tx.commit().await?;
        Ok(())
    }
}

/// One found VM into its workspace's row (made, or brought back from missing).
async fn upsert_vm(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ctx: &Context,
    vm: &DiscoveredVm,
    now: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO vms (id, workspace_id, user_id, vmx_path, hypervisor, config_path, display_name,
                          guest_os, guest_os_name, num_vcpus, memsize_mb, power_state, ip_address,
                          tools_state, missing, last_seen_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
         ON CONFLICT(workspace_id, vmx_path) DO UPDATE SET
             hypervisor    = excluded.hypervisor,
             config_path   = excluded.config_path,
             display_name  = excluded.display_name,
             guest_os      = excluded.guest_os,
             guest_os_name = COALESCE(excluded.guest_os_name, vms.guest_os_name),
             num_vcpus     = excluded.num_vcpus,
             memsize_mb    = excluded.memsize_mb,
             power_state   = CASE WHEN excluded.power_state = 'running' AND vms.power_state = 'paused'
                                       AND excluded.hypervisor = 'vmware'
                                  THEN 'paused' ELSE excluded.power_state END,
             ip_address    = CASE WHEN (excluded.power_state = 'running' AND vms.power_state = 'paused'
                                        AND excluded.hypervisor = 'vmware')
                                       OR excluded.power_state = 'paused'
                                  THEN vms.ip_address ELSE excluded.ip_address END,
             tools_state   = CASE WHEN (excluded.power_state = 'running' AND vms.power_state = 'paused'
                                        AND excluded.hypervisor = 'vmware')
                                       OR excluded.power_state = 'paused'
                                  THEN vms.tools_state ELSE excluded.tools_state END,
             missing       = 0,
             last_seen_at  = excluded.last_seen_at,
             updated_at    = excluded.updated_at",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(ctx.workspace_id.to_string())
    .bind(ctx.user_id.to_string())
    .bind(&vm.vmx_path)
    .bind(vm.hypervisor.as_str())
    .bind(&vm.config_path)
    .bind(&vm.display_name)
    .bind(&vm.info.guest_os)
    .bind(&vm.info.guest_os_name)
    .bind(vm.info.num_vcpus.map(i64::from))
    .bind(vm.info.memsize_mb.map(i64::from))
    .bind(vm.power_state.as_str())
    .bind(&vm.ip_address)
    .bind(&vm.tools_state)
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn row_to_vm(row: &sqlx::sqlite::SqliteRow) -> Result<VmRecord> {
    let env: String = row.try_get("environment")?;
    let hypervisor: String = row.try_get("hypervisor")?;
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
        hypervisor: Hypervisor::parse(&hypervisor),
        config_path: row.try_get("config_path")?,
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
