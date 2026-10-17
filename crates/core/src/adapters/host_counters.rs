//! Host counters adapter (MO-01, MO-04, VM-07): what Windows knows about this machine and about the
//! `vmware-vmx.exe` process behind each running VM. Reads only, no login needed.
//!
//! [`WindowsCounters`] reads physical RAM (`GlobalMemoryStatusEx`), logical CPUs
//! (`GetActiveProcessorCount`) and free disk space (`GetDiskFreeSpaceExW`) through the `windows`
//! crate. Per-VM process counters (MO-01) are still to come: PDH performance counters for CPU %,
//! working set and I/O bytes/s, with the process command line mapping each process to its .vmx.

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
    /// VM-07: free space on the drive holding `path` (an existing file or folder), as a percentage.
    async fn free_disk_pct(&self, path: &Path) -> Result<f64>;
}

/// Windows APIs through the `windows` crate.
pub struct WindowsCounters;

#[async_trait]
impl HostCounters for WindowsCounters {
    async fn vm_processes(&self) -> Result<Vec<VmProcess>> {
        // An empty list keeps the metrics collector quiet until MO-01 lands.
        Ok(Vec::new())
    }

    async fn host_totals(&self) -> Result<HostTotals> {
        win::host_totals()
    }

    async fn free_disk_pct(&self, path: &Path) -> Result<f64> {
        // A network drive can take a while to answer; keep it off the async threads.
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || win::free_disk_pct(&path))
            .await
            .map_err(|err| CoreError::Io(std::io::Error::other(err)))?
    }
}

#[cfg(windows)]
mod win {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows::Win32::System::Threading::{GetActiveProcessorCount, ALL_PROCESSOR_GROUPS};

    use super::HostTotals;
    use crate::error::{CoreError, Result};

    fn os_error(call: &str, err: windows::core::Error) -> CoreError {
        CoreError::Io(std::io::Error::other(format!("{call}: {}", err.message())))
    }

    pub fn host_totals() -> Result<HostTotals> {
        let mut status = MEMORYSTATUSEX {
            dwLength: u32::try_from(std::mem::size_of::<MEMORYSTATUSEX>()).unwrap_or(u32::MAX),
            ..Default::default()
        };
        // SAFETY: `status` is a live, writable MEMORYSTATUSEX whose dwLength is set, as the API requires.
        unsafe { GlobalMemoryStatusEx(&mut status) }.map_err(|e| os_error("GlobalMemoryStatusEx", e))?;
        // SAFETY: takes no pointers; ALL_PROCESSOR_GROUPS counts the processors of every group.
        let cpus = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
        Ok(HostTotals {
            physical_ram_mb: status.ullTotalPhys / (1024 * 1024),
            logical_cpus: cpus,
        })
    }

    pub fn free_disk_pct(path: &Path) -> Result<f64> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let (mut total, mut free) = (0u64, 0u64);
        // SAFETY: `wide` is NUL-terminated and outlives the call; both out pointers point at live u64s.
        unsafe { GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), None, Some(&mut total), Some(&mut free)) }
            .map_err(|e| os_error("GetDiskFreeSpaceExW", e))?;
        if total == 0 {
            return Err(CoreError::Io(std::io::Error::other(format!(
                "{} reports a size of 0 bytes",
                path.display()
            ))));
        }
        Ok(free as f64 * 100.0 / total as f64)
    }
}

#[cfg(not(windows))]
mod win {
    use std::path::Path;

    use super::HostTotals;
    use crate::error::{CoreError, Result};

    pub fn host_totals() -> Result<HostTotals> {
        Err(CoreError::NotImplemented("host totals outside Windows"))
    }

    pub fn free_disk_pct(_path: &Path) -> Result<f64> {
        Err(CoreError::NotImplemented("free disk space outside Windows"))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    // Reads this machine's totals; touches no VM.
    #[tokio::test]
    async fn reads_host_ram_cpus_and_free_disk() {
        let totals = WindowsCounters.host_totals().await.unwrap();
        assert!(totals.physical_ram_mb >= 512, "{totals:?}");
        assert!(totals.logical_cpus >= 1, "{totals:?}");

        let free = WindowsCounters.free_disk_pct(&std::env::temp_dir()).await.unwrap();
        assert!((0.0..=100.0).contains(&free), "{free}");

        let missing = std::env::temp_dir().join(format!("remotely-missing-{}", uuid::Uuid::new_v4()));
        assert!(WindowsCounters.free_disk_pct(&missing).await.is_err());
    }
}
