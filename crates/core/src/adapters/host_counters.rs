//! Host counters adapter (MO-01, MO-04, VM-07): what Windows knows about this machine and about the
//! `vmware-vmx.exe` process behind each running VM. Reads only, no login needed.
//!
//! Plan: PDH performance counters through the `windows` crate (per-process CPU %, working set, I/O
//! bytes/s), the process command line to map each process to its .vmx, `GlobalMemoryStatusEx` for
//! physical RAM and `GetDiskFreeSpaceExW` for free disk. [`WindowsCounters`] is a stub until then.

use std::path::Path;

use async_trait::async_trait;
use serde::Serialize;

use crate::error::{CoreError, Result};

/// One `vmware-vmx.exe` process.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmProcess {
    pub pid: u32,
    /// Taken from the process command line; `None` when it could not be read.
    pub vmx_path: Option<String>,
    pub cpu_pct: Option<f64>,
    pub working_set_bytes: Option<u64>,
    pub read_bps: Option<f64>,
    pub write_bps: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostTotals {
    pub physical_ram_mb: u64,
    pub logical_cpus: u32,
}

#[async_trait]
pub trait HostCounters: Send + Sync {
    /// MO-01: counters for every running VM's process.
    async fn vm_processes(&self) -> Result<Vec<VmProcess>>;
    /// MO-04, VM-07: physical RAM and logical CPUs.
    async fn host_totals(&self) -> Result<HostTotals>;
    /// VM-07: free space on the drive holding `path`, as a percentage.
    async fn free_disk_pct(&self, path: &Path) -> Result<f64>;
}

/// Windows performance counters. Stub.
pub struct WindowsCounters;

#[async_trait]
impl HostCounters for WindowsCounters {
    async fn vm_processes(&self) -> Result<Vec<VmProcess>> {
        // An empty list keeps the metrics collector quiet until MO-01 lands.
        Ok(Vec::new())
    }

    async fn host_totals(&self) -> Result<HostTotals> {
        Err(CoreError::NotImplemented("MO-04 host totals"))
    }

    async fn free_disk_pct(&self, _path: &Path) -> Result<f64> {
        Err(CoreError::NotImplemented("VM-07 free disk check"))
    }
}
