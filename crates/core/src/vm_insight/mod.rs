//! VM-25: the Log and Timeline tabs of a VM's details. Reads only: no bus, no audit, and the read-only lock
//! doesn't stop them.
//!
//! - Log ([`logs`]): the VM's own log files, a capped tail at a time, followed while the VM runs (the UI reads
//!   what was added on an interval, only while the tab shows and the window is visible).
//! - Timeline: everything Remotely did to the VM, from the audit log (every entry that names it: approvals, jobs,
//!   label changes, Open console...), each job's entry with the VM's own outcome from the job journal, newest first,
//!   a page at a time.

pub mod logs;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;

use crate::adapters::host_networks::vm_paths;
use crate::adapters::hypervisor::{Hypervisor, Hypervisors};
use crate::adapters::virtualbox::parse_machine_readable;
use crate::command_bus::ApprovalRecord;
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::store::{vm_needle, Store, VmRecord};

pub use logs::{LogChunk, LogFile, LogListing};

/// A Timeline page, by default.
pub const DEFAULT_PAGE: u32 = 50;
/// The most one page holds.
pub const MAX_PAGE: u32 = 200;
const SHOWVMINFO_TIMEOUT: Duration = Duration::from_secs(30);

/// The VM's own row of a job, from the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineOutcome {
    /// `succeeded`, `failed`, `cancelled`, `skipped`, `unknown`, `running`, `pending`.
    pub status: String,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    /// VM-05: the safety snapshot taken on the VM first.
    pub safety_snapshot: Option<String>,
    pub finished_at: Option<String>,
}

/// One audit entry that names the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEntry {
    /// The audit log's sequence number: the next page asks for entries before the last one.
    pub seq: i64,
    pub at: String,
    /// `approval_requested`, `approval_granted`, `job_started`, `job_finished`, `vm_label_changed`...
    pub event: String,
    pub action: String,
    pub tier: Option<String>,
    pub job_id: Option<String>,
    pub result: Option<String>,
    pub detail: Option<String>,
    /// AP-03: the reason or ticket given when it was approved.
    pub reason: Option<String>,
    /// Other targets of the same entry (a bulk action on several VMs).
    pub other_targets: usize,
    /// For a job's entries: how it went for this VM.
    pub outcome: Option<TimelineOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelinePage {
    pub entries: Vec<TimelineEntry>,
    /// Pass as `before` for the next page; `None` at the end.
    pub next_before: Option<i64>,
}

/// VM-25: a VM's logs and timeline.
pub struct VmInsight {
    ctx: Context,
    store: Store,
    hypervisors: Hypervisors,
    /// Each VirtualBox VM's log folder once read (`showvminfo`), so following its log runs no VBoxManage.
    log_folders: Mutex<HashMap<String, PathBuf>>,
}

impl VmInsight {
    pub fn new(ctx: Context, store: Store, hypervisors: Hypervisors) -> Self {
        Self {
            ctx,
            store,
            hypervisors,
            log_folders: Mutex::new(HashMap::new()),
        }
    }

    async fn vm(&self, key: &str) -> Result<VmRecord> {
        self.store
            .find_vm(&self.ctx, key)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(key.to_owned()))
    }

    /// Where the VM's logs are: a Workstation VM's folder; a VirtualBox VM's `LogFldr` (read fresh when `fresh`),
    /// else `Logs` beside its .vbox.
    async fn log_folder(&self, vm: &VmRecord, fresh: bool) -> Option<PathBuf> {
        match vm.hypervisor {
            Hypervisor::Vmware => Path::new(&vm.vmx_path).parent().map(Path::to_path_buf),
            Hypervisor::VirtualBox => {
                if !fresh {
                    if let Some(folder) = locks::lock(&self.log_folders).get(&vm.vmx_path) {
                        return Some(folder.clone());
                    }
                }
                let read = self
                    .hypervisors
                    .virtualbox()
                    .vboxmanage_host(
                        vec!["showvminfo".into(), vm.vmx_path.clone(), "--machinereadable".into()],
                        SHOWVMINFO_TIMEOUT,
                    )
                    .await;
                let folder = match read {
                    Ok(out) => vm_paths(&parse_machine_readable(&out)).log_folder,
                    Err(err) => {
                        tracing::debug!(error = %err, "could not ask VirtualBox for a VM's log folder");
                        None
                    }
                }
                .or_else(|| {
                    vm.config_path
                        .as_deref()
                        .and_then(|p| Path::new(p).parent())
                        .map(|p| p.join("Logs"))
                })?;
                locks::lock(&self.log_folders).insert(vm.vmx_path.clone(), folder.clone());
                Some(folder)
            }
        }
    }

    /// VM-25: the VM's log files, current first.
    pub async fn logs(&self, key: &str) -> Result<LogListing> {
        let vm = self.vm(key).await?;
        let Some(folder) = self.log_folder(&vm, true).await else {
            return Ok(LogListing {
                folder: None,
                files: Vec::new(),
                problem: Some("Remotely can't tell where this VM keeps its logs.".into()),
            });
        };
        match logs::list(vm.hypervisor, &folder).await {
            Ok(files) => Ok(LogListing {
                folder: Some(folder.display().to_string()),
                problem: files
                    .is_empty()
                    .then(|| "No log files yet: the hypervisor writes one when the VM starts.".to_owned()),
                files,
            }),
            Err(err) => Ok(LogListing {
                folder: Some(folder.display().to_string()),
                files: Vec::new(),
                problem: Some(err.to_string()),
            }),
        }
    }

    /// VM-25: part of one log: its tail (`from` = `None`; `tail` bytes, by default [`logs::DEFAULT_TAIL_BYTES`]), or
    /// what was added after `from`.
    pub async fn read_log(&self, key: &str, file: &str, from: Option<u64>, tail: Option<u64>) -> Result<LogChunk> {
        let vm = self.vm(key).await?;
        let folder = self
            .log_folder(&vm, false)
            .await
            .ok_or_else(|| CoreError::InvalidInput("Remotely can't tell where this VM keeps its logs.".into()))?;
        logs::read(
            vm.hypervisor,
            &folder,
            file,
            from,
            tail.unwrap_or(logs::DEFAULT_TAIL_BYTES),
        )
        .await
    }

    /// VM-25: what Remotely did to the VM, newest first: `limit` entries (at most [`MAX_PAGE`]) before `before`.
    pub async fn timeline(&self, key: &str, before: Option<i64>, limit: Option<u32>) -> Result<TimelinePage> {
        let vm = self.vm(key).await?;
        let limit = limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
        let rows = self
            .store
            .audit_naming(&self.ctx, &vm_needle(&vm.vmx_path), before, limit)
            .await?;
        let mut job_ids: Vec<String> = rows.iter().filter_map(|r| r.job_id.clone()).collect();
        job_ids.sort();
        job_ids.dedup();
        let outcomes = self.store.job_rows_for(&self.ctx, &job_ids, &vm.vmx_path).await?;
        let next_before = (rows.len() as u32 == limit).then(|| rows.last().map(|r| r.seq)).flatten();
        let entries = rows
            .into_iter()
            .map(|row| {
                let reason = row
                    .approval_json
                    .as_deref()
                    .and_then(|j| serde_json::from_str::<ApprovalRecord>(j).ok())
                    .and_then(|a| a.reason);
                let targets = serde_json::from_str::<Vec<serde_json::Value>>(&row.targets_json)
                    .map(|t| t.len())
                    .unwrap_or(1);
                let outcome = row.job_id.as_ref().and_then(|id| outcomes.get(id)).map(|o| TimelineOutcome {
                    status: o.status.clone(),
                    error: o.error.clone(),
                    duration_ms: o.duration_ms,
                    safety_snapshot: o.safety_snapshot.clone(),
                    finished_at: o.finished_at.clone(),
                });
                TimelineEntry {
                    seq: row.seq,
                    at: row.ts,
                    event: row.event,
                    action: row.action,
                    tier: row.tier,
                    job_id: row.job_id,
                    result: row.result,
                    detail: row.detail,
                    reason,
                    other_targets: targets.saturating_sub(1),
                    outcome,
                }
            })
            .collect();
        Ok(TimelinePage { entries, next_before })
    }
}
