//! VM-32 (0.8.0 G6): address pool and lease rows (migration 0036). The checks are `crate::address_pools`'s; this module
//! only reads and writes. Pools are read and written within the workspace of `ctx`. Leases are a workspace's too, but
//! an address is taken on a network of this PC, whatever workspace took it: [`Store::held_addresses`],
//! [`Store::leases_elsewhere`], [`Store::lease_holder`] and [`Store::clear_stale_claims`] look across workspaces by
//! network key (they say which workspace, never more of it), and [`Store::free_vm_leases`] frees a deleted VM's
//! addresses wherever they were leased.
//!
//! A claim is stale when it has no VM and its job isn't open (queued, in its countdown or running): a deploy that was
//! cancelled, failed or stopped with the app. Stale claims count as free everywhere.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use sqlx::Row;
use uuid::Uuid;

use super::Store;
use crate::adapters::hypervisor::Hypervisor;
use crate::address_pools::{AddressLease, LeaseState, PoolRow, PoolSpec};
use crate::catalog::templates::Network;
use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};

fn unreadable(what: &str) -> CoreError {
    CoreError::InvalidInput(format!("an address pool's {what} can't be read"))
}

fn ip_of(text: &str, what: &str) -> Result<Ipv4Addr> {
    text.parse().map_err(|_| unreadable(what))
}

fn pool(row: &sqlx::sqlite::SqliteRow) -> Result<PoolRow> {
    let id: String = row.try_get("id")?;
    let hypervisor: String = row.try_get("hypervisor")?;
    let network: String = row.try_get("network")?;
    let first: String = row.try_get("first_ip")?;
    let last: String = row.try_get("last_ip")?;
    let prefix: i64 = row.try_get("prefix")?;
    let gateway: Option<String> = row.try_get("gateway")?;
    let dns: String = row.try_get("dns")?;
    let dns: Vec<String> = serde_json::from_str(&dns).map_err(|_| unreadable("DNS servers"))?;
    Ok(PoolRow {
        id: Uuid::parse_str(&id).map_err(|_| unreadable("id"))?,
        spec: PoolSpec {
            name: row.try_get("name")?,
            hypervisor: Hypervisor::parse(&hypervisor),
            network: serde_json::from_str::<Network>(&network).map_err(|_| unreadable("network"))?,
            host_adapter: row.try_get("host_adapter")?,
            first: ip_of(&first, "first address")?,
            last: ip_of(&last, "last address")?,
            prefix: u8::try_from(prefix).map_err(|_| unreadable("prefix"))?,
            gateway: gateway.as_deref().map(|g| ip_of(g, "gateway")).transpose()?,
            dns: dns.iter().map(|d| ip_of(d, "DNS server")).collect::<Result<_>>()?,
            notes: row.try_get("notes")?,
        },
        network_key: row.try_get("network_key")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn lease(row: &sqlx::sqlite::SqliteRow) -> Result<AddressLease> {
    let pool_id: String = row.try_get("pool_id")?;
    let ip: String = row.try_get("ip")?;
    let job_id: Option<String> = row.try_get("job_id")?;
    let state: String = row.try_get("state")?;
    let can_free: i64 = row.try_get("can_free")?;
    Ok(AddressLease {
        pool_id: Uuid::parse_str(&pool_id).map_err(|_| unreadable("lease"))?,
        ip: ip_of(&ip, "lease")?,
        vm_key: row.try_get("vm_key")?,
        vm_name: row.try_get("vm_name")?,
        job_id: job_id.as_deref().and_then(|j| Uuid::parse_str(j).ok()),
        state: if state == "assigned" {
            LeaseState::Assigned
        } else {
            LeaseState::Claimed
        },
        created_at: row.try_get("created_at")?,
        can_free: can_free != 0,
    })
}

fn dns_json(spec: &PoolSpec) -> Result<String> {
    let dns: Vec<String> = spec.dns.iter().map(Ipv4Addr::to_string).collect();
    Ok(serde_json::to_string(&dns)?)
}

/// An address held on a network, and the workspace that holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldAddress {
    pub ip: Ipv4Addr,
    pub workspace_id: String,
    pub job_id: Option<Uuid>,
}

impl Store {
    /// The workspace's pools, by name.
    pub(crate) async fn list_address_pools(&self, ctx: &Context) -> Result<Vec<PoolRow>> {
        let rows = sqlx::query("SELECT * FROM address_pools WHERE workspace_id = ? ORDER BY name, created_at")
            .bind(ctx.workspace_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(pool).collect()
    }

    pub(crate) async fn get_address_pool(&self, ctx: &Context, id: Uuid) -> Result<Option<PoolRow>> {
        let row = sqlx::query("SELECT * FROM address_pools WHERE workspace_id = ? AND id = ?")
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(pool).transpose()
    }

    pub(crate) async fn insert_address_pool(&self, ctx: &Context, spec: &PoolSpec, key: &str) -> Result<PoolRow> {
        let id = Uuid::new_v4();
        let now = now_rfc3339();
        sqlx::query(
            "INSERT INTO address_pools (id, workspace_id, user_id, name, hypervisor, network, host_adapter, network_key,
                                        first_ip, last_ip, prefix, gateway, dns, notes, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(&spec.name)
        .bind(spec.hypervisor.as_str())
        .bind(serde_json::to_string(&spec.network)?)
        .bind(&spec.host_adapter)
        .bind(key)
        .bind(spec.first.to_string())
        .bind(spec.last.to_string())
        .bind(i64::from(spec.prefix))
        .bind(spec.gateway.map(|g| g.to_string()))
        .bind(dns_json(spec)?)
        .bind(&spec.notes)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(PoolRow {
            id,
            spec: spec.clone(),
            network_key: key.to_owned(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub(crate) async fn update_address_pool(&self, ctx: &Context, id: Uuid, spec: &PoolSpec, key: &str) -> Result<()> {
        sqlx::query(
            "UPDATE address_pools SET name = ?, hypervisor = ?, network = ?, host_adapter = ?, network_key = ?,
                                      first_ip = ?, last_ip = ?, prefix = ?, gateway = ?, dns = ?, notes = ?,
                                      updated_at = ?
             WHERE workspace_id = ? AND id = ?",
        )
        .bind(&spec.name)
        .bind(spec.hypervisor.as_str())
        .bind(serde_json::to_string(&spec.network)?)
        .bind(&spec.host_adapter)
        .bind(key)
        .bind(spec.first.to_string())
        .bind(spec.last.to_string())
        .bind(i64::from(spec.prefix))
        .bind(spec.gateway.map(|g| g.to_string()))
        .bind(dns_json(spec)?)
        .bind(&spec.notes)
        .bind(now_rfc3339())
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The network a pool resolves to now, when it changed since it was saved (the NAT moved to another vmnet).
    pub(crate) async fn set_address_pool_key(&self, ctx: &Context, id: Uuid, key: &str) -> Result<()> {
        sqlx::query("UPDATE address_pools SET network_key = ? WHERE workspace_id = ? AND id = ?")
            .bind(key)
            .bind(ctx.workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Deletes a pool with no lease (its leases would go with it). False when the workspace has no such pool.
    pub(crate) async fn delete_address_pool(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let done = sqlx::query(
            "DELETE FROM address_pools WHERE workspace_id = ? AND id = ?
               AND NOT EXISTS (SELECT 1 FROM address_leases WHERE pool_id = address_pools.id)",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// How many addresses each pool of the workspace holds: assigned, or claimed by a job still open.
    pub(crate) async fn address_lease_counts(&self, ctx: &Context) -> Result<HashMap<Uuid, u32>> {
        let rows = sqlx::query(
            "SELECT l.pool_id, COUNT(*) AS taken FROM address_leases l
             WHERE l.workspace_id = ?
               AND NOT (l.state = 'claimed' AND l.vm_key IS NULL
                        AND (l.job_id IS NULL
                             OR NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = l.job_id
                                              AND j.status IN ('queued', 'countdown', 'running'))))
             GROUP BY l.pool_id",
        )
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let mut counts = HashMap::new();
        for row in &rows {
            let id: String = row.try_get("pool_id")?;
            let taken: i64 = row.try_get("taken")?;
            if let Ok(id) = Uuid::parse_str(&id) {
                counts.insert(id, u32::try_from(taken).unwrap_or(u32::MAX));
            }
        }
        Ok(counts)
    }

    /// A pool's (or, `None`, every pool's) leases in the workspace, in address order. `can_free`: an assigned lease
    /// whose VM no workspace lists as here (no row, or rows marked missing), or a stale claim.
    pub(crate) async fn address_leases(&self, ctx: &Context, pool_id: Option<Uuid>) -> Result<Vec<AddressLease>> {
        let pool_id = pool_id.map(|p| p.to_string());
        let rows = sqlx::query(
            "SELECT l.pool_id, l.ip, l.vm_key, l.vm_name, l.job_id, l.state, l.created_at,
                    CASE WHEN l.state = 'assigned'
                         THEN NOT EXISTS (SELECT 1 FROM vms v WHERE v.vmx_path = l.vm_key AND v.missing = 0)
                         ELSE (l.vm_key IS NULL
                               AND (l.job_id IS NULL
                                    OR NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = l.job_id
                                                     AND j.status IN ('queued', 'countdown', 'running'))))
                    END AS can_free
             FROM address_leases l
             WHERE l.workspace_id = ? AND (? IS NULL OR l.pool_id = ?)",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(&pool_id)
        .bind(&pool_id)
        .fetch_all(&self.pool)
        .await?;
        let mut leases = rows.iter().map(lease).collect::<Result<Vec<_>>>()?;
        leases.sort_by_key(|l| (l.pool_id, u32::from(l.ip)));
        Ok(leases)
    }

    /// Every address held (not a stale claim) on the network `key`, or by the pool `pool_id` (leases saved under an
    /// older key), in any workspace.
    pub(crate) async fn held_addresses(&self, key: &str, pool_id: Uuid) -> Result<Vec<HeldAddress>> {
        let rows = sqlx::query(
            "SELECT l.ip, l.workspace_id, l.job_id FROM address_leases l
             WHERE (l.network_key = ? OR l.pool_id = ?)
               AND NOT (l.state = 'claimed' AND l.vm_key IS NULL
                        AND (l.job_id IS NULL
                             OR NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = l.job_id
                                              AND j.status IN ('queued', 'countdown', 'running'))))",
        )
        .bind(key)
        .bind(pool_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let mut held = Vec::with_capacity(rows.len());
        for row in &rows {
            let ip: String = row.try_get("ip")?;
            let job_id: Option<String> = row.try_get("job_id")?;
            if let Ok(ip) = ip.parse() {
                held.push(HeldAddress {
                    ip,
                    workspace_id: row.try_get("workspace_id")?,
                    job_id: job_id.as_deref().and_then(|j| Uuid::parse_str(j).ok()),
                });
            }
        }
        Ok(held)
    }

    /// The addresses other workspaces hold on the networks of this workspace's pools: (network key, address).
    pub(crate) async fn leases_elsewhere(&self, ctx: &Context) -> Result<Vec<(String, Ipv4Addr)>> {
        let rows = sqlx::query(
            "SELECT l.network_key, l.ip FROM address_leases l
             WHERE l.workspace_id <> ?
               AND l.network_key IN (SELECT p.network_key FROM address_pools p WHERE p.workspace_id = ?)
               AND NOT (l.state = 'claimed' AND l.vm_key IS NULL
                        AND (l.job_id IS NULL
                             OR NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = l.job_id
                                              AND j.status IN ('queued', 'countdown', 'running'))))",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let ip: String = row.try_get("ip")?;
            if let Ok(ip) = ip.parse() {
                out.push((row.try_get("network_key")?, ip));
            }
        }
        Ok(out)
    }

    /// Who holds `ip` on the network `key` (or in the pool): the workspace's id and the VM's name.
    pub(crate) async fn lease_holder(
        &self,
        key: &str,
        pool_id: Uuid,
        ip: Ipv4Addr,
    ) -> Result<Option<(String, String)>> {
        let row = sqlx::query(
            "SELECT workspace_id, vm_name FROM address_leases WHERE (network_key = ? OR pool_id = ?) AND ip = ? LIMIT 1",
        )
        .bind(key)
        .bind(pool_id.to_string())
        .bind(ip.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| Ok((r.try_get("workspace_id")?, r.try_get("vm_name")?)))
            .transpose()
    }

    /// Deletes the stale claims of `ip` on the network `key` (or in the pool), in any workspace: they would keep a new
    /// claim out. How many went.
    pub(crate) async fn clear_stale_claims(&self, key: &str, pool_id: Uuid, ip: Ipv4Addr) -> Result<u64> {
        let done = sqlx::query(
            "DELETE FROM address_leases
             WHERE (network_key = ? OR pool_id = ?) AND ip = ? AND state = 'claimed' AND vm_key IS NULL
               AND (job_id IS NULL
                    OR NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = address_leases.job_id
                                     AND j.status IN ('queued', 'countdown', 'running')))",
        )
        .bind(key)
        .bind(pool_id.to_string())
        .bind(ip.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Records `ip` of the pool, on the network `key`, as claimed for `vm_name` by `job_id`. False when the address is
    /// held already on that network (another claim won, in this workspace or another).
    pub(crate) async fn insert_address_claim(
        &self,
        ctx: &Context,
        pool_id: Uuid,
        key: &str,
        ip: Ipv4Addr,
        vm_name: &str,
        job_id: Uuid,
    ) -> Result<bool> {
        let done = sqlx::query(
            "INSERT INTO address_leases (pool_id, workspace_id, user_id, network_key, ip, vm_key, vm_name, job_id, state,
                                         created_at)
             SELECT ?, ?, ?, ?, ?, NULL, ?, ?, 'claimed', ?
             WHERE EXISTS (SELECT 1 FROM address_pools WHERE id = ? AND workspace_id = ?)
             ON CONFLICT DO NOTHING",
        )
        .bind(pool_id.to_string())
        .bind(ctx.workspace_id.to_string())
        .bind(ctx.user_id.to_string())
        .bind(key)
        .bind(ip.to_string())
        .bind(vm_name)
        .bind(job_id.to_string())
        .bind(now_rfc3339())
        .bind(pool_id.to_string())
        .bind(ctx.workspace_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// Undoes `job_id`'s own claim of `ip`, and nobody else's. False when it had none.
    pub(crate) async fn delete_address_claim(
        &self,
        ctx: &Context,
        pool_id: Uuid,
        ip: Ipv4Addr,
        job_id: Uuid,
    ) -> Result<bool> {
        let done = sqlx::query(
            "DELETE FROM address_leases
             WHERE workspace_id = ? AND pool_id = ? AND ip = ? AND job_id = ? AND state = 'claimed'",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(pool_id.to_string())
        .bind(ip.to_string())
        .bind(job_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// `job_id`'s claim of the address is `vm_key`'s now. False when the job has no claim of it.
    pub(crate) async fn assign_address_lease(
        &self,
        ctx: &Context,
        pool_id: Uuid,
        ip: Ipv4Addr,
        job_id: Uuid,
        vm_key: &str,
    ) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE address_leases SET state = 'assigned', vm_key = ?
             WHERE workspace_id = ? AND pool_id = ? AND ip = ? AND job_id = ? AND state = 'claimed'",
        )
        .bind(vm_key)
        .bind(ctx.workspace_id.to_string())
        .bind(pool_id.to_string())
        .bind(ip.to_string())
        .bind(job_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// A hand free: the address is free again, when it is still what `can_free` said (one statement, so a live claim that
    /// replaced a stale one since, or a VM listed again, stays). False when nothing went.
    pub(crate) async fn delete_freeable_lease(&self, ctx: &Context, pool_id: Uuid, ip: Ipv4Addr) -> Result<bool> {
        let done = sqlx::query(
            "DELETE FROM address_leases
             WHERE workspace_id = ? AND pool_id = ? AND ip = ?
               AND ((state = 'claimed' AND vm_key IS NULL
                     AND (job_id IS NULL
                          OR NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = address_leases.job_id
                                           AND j.status IN ('queued', 'countdown', 'running'))))
                    OR (state = 'assigned'
                        AND NOT EXISTS (SELECT 1 FROM vms v WHERE v.vmx_path = address_leases.vm_key
                                          AND v.missing = 0)))",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(pool_id.to_string())
        .bind(ip.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() > 0)
    }

    /// The pool's claims that hold nothing (no VM, and their job isn't open), in one statement: a pool edit or delete
    /// takes them, never a claim that replaced one since the edit read them. How many went.
    pub(crate) async fn release_stale_pool_claims(&self, ctx: &Context, pool_id: Uuid) -> Result<u64> {
        let done = sqlx::query(
            "DELETE FROM address_leases
             WHERE workspace_id = ? AND pool_id = ? AND state = 'claimed' AND vm_key IS NULL
               AND (job_id IS NULL
                    OR NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = address_leases.job_id
                                     AND j.status IN ('queued', 'countdown', 'running')))",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(pool_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// The claims `job_id` made that have no VM yet. How many went.
    pub(crate) async fn release_job_claims(&self, ctx: &Context, job_id: Uuid) -> Result<u64> {
        let done = sqlx::query(
            "DELETE FROM address_leases
             WHERE workspace_id = ? AND job_id = ? AND state = 'claimed' AND vm_key IS NULL",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(job_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// The workspace's claims without a VM made before `before` (RFC 3339) whose job isn't open. How many went.
    pub(crate) async fn release_stale_address_claims(&self, ctx: &Context, before: &str) -> Result<u64> {
        let done = sqlx::query(
            "DELETE FROM address_leases
             WHERE workspace_id = ? AND state = 'claimed' AND vm_key IS NULL AND created_at < ?
               AND (job_id IS NULL
                    OR NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = address_leases.job_id
                                     AND j.status IN ('queued', 'countdown', 'running')))",
        )
        .bind(ctx.workspace_id.to_string())
        .bind(before)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// VM-32: the VM was deleted, so its addresses go back to their pools, in whatever workspace leased them (a VM's
    /// key is this PC's). Each freed address with its pool's name, for the delete's note.
    pub(crate) async fn free_vm_leases(&self, vm_key: &str) -> Result<Vec<(Ipv4Addr, String)>> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT l.ip, p.name FROM address_leases l JOIN address_pools p ON p.id = l.pool_id WHERE l.vm_key = ?",
        )
        .bind(vm_key)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        sqlx::query("DELETE FROM address_leases WHERE vm_key = ?")
            .bind(vm_key)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        let mut freed = Vec::with_capacity(rows.len());
        for row in &rows {
            let ip: String = row.try_get("ip")?;
            if let Ok(ip) = ip.parse() {
                freed.push((ip, row.try_get("name")?));
            }
        }
        Ok(freed)
    }
}
