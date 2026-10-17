//! Metrics collector (MO-01 to MO-04). Reads only: samples go to the dashboard (and later the store)
//! without passing the command bus.
//!
//! Two sources, because Workstation has no per-VM metrics API:
//! * Host side, no login: each running VM is a `vmware-vmx.exe` process; Windows performance
//!   counters give its CPU %, RAM and disk I/O (MO-01, every 5 s).
//! * Guest side, login needed: /proc over SSH for Linux guests (MO-02).
//!
//! Both sources are stubs that return no samples yet; the polling loop and broadcast are real.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::adapters::host_counters::HostCounters;
use crate::domain::{now_rfc3339, TargetRef};
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MetricSource {
    Host,
    Guest,
}

impl MetricSource {
    pub fn as_str(self) -> &'static str {
        match self {
            MetricSource::Host => "host",
            MetricSource::Guest => "guest",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricSample {
    pub source: MetricSource,
    pub target: TargetRef,
    pub ts: String,
    pub cpu_pct: Option<f64>,
    pub mem_bytes: Option<u64>,
    pub disk_read_bps: Option<f64>,
    pub disk_write_bps: Option<f64>,
    pub net_rx_bps: Option<f64>,
    pub net_tx_bps: Option<f64>,
    pub load1: Option<f64>,
    pub uptime_secs: Option<u64>,
}

/// MO-04 and VM-07: assigned vs physical resources on this machine.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostCapacity {
    pub physical_ram_mb: u64,
    pub assigned_ram_mb: u64,
    pub logical_cpus: u32,
    pub assigned_vcpus: u32,
    /// Free space per VM folder drive, e.g. ("D:\\", 12.5).
    pub free_disk_pct: Vec<(String, f64)>,
}

#[async_trait]
pub trait MetricsSource: Send + Sync {
    fn name(&self) -> &'static str;
    async fn collect(&self) -> Result<Vec<MetricSample>>;
}

/// MO-01: per-VM CPU, RAM and disk I/O from the `vmware-vmx.exe` processes, read through the host
/// counters adapter. Processes whose .vmx path is unknown are left out.
pub struct HostProcessSource {
    counters: Arc<dyn HostCounters>,
}

impl HostProcessSource {
    pub fn new(counters: Arc<dyn HostCounters>) -> Self {
        Self { counters }
    }
}

#[async_trait]
impl MetricsSource for HostProcessSource {
    fn name(&self) -> &'static str {
        "host-process"
    }

    async fn collect(&self) -> Result<Vec<MetricSample>> {
        let ts = now_rfc3339();
        Ok(self
            .counters
            .vm_processes()
            .await?
            .into_iter()
            .filter_map(|p| {
                Some(MetricSample {
                    source: MetricSource::Host,
                    target: TargetRef::Vm { vmx_path: p.vmx_path? },
                    ts: ts.clone(),
                    cpu_pct: p.cpu_pct,
                    mem_bytes: p.working_set_bytes,
                    disk_read_bps: p.read_bps,
                    disk_write_bps: p.write_bps,
                    net_rx_bps: None,
                    net_tx_bps: None,
                    load1: None,
                    uptime_secs: None,
                })
            })
            .collect())
    }
}

/// MO-02: Linux guest metrics over SSH (/proc/stat, /proc/meminfo, /proc/diskstats, /proc/net/dev,
/// /proc/loadavg, /proc/uptime). Stub.
pub struct SshGuestSource;

#[async_trait]
impl MetricsSource for SshGuestSource {
    fn name(&self) -> &'static str {
        "ssh-guest"
    }

    async fn collect(&self) -> Result<Vec<MetricSample>> {
        Ok(Vec::new())
    }
}

/// Polls every source on an interval and broadcasts each round of samples.
pub struct MetricsCollector {
    sources: Vec<Arc<dyn MetricsSource>>,
    interval: Duration,
    tx: broadcast::Sender<Vec<MetricSample>>,
}

impl MetricsCollector {
    /// MO-01 refresh rate.
    pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

    pub fn new(sources: Vec<Arc<dyn MetricsSource>>, interval: Duration) -> Self {
        let (tx, _) = broadcast::channel(16);
        Self { sources, interval, tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Vec<MetricSample>> {
        self.tx.subscribe()
    }

    /// Runs until `stop` is cancelled. A failing source is logged and skipped for that round.
    pub fn spawn(self, stop: CancellationToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = ticker.tick() => {}
                }
                let mut round = Vec::new();
                for source in &self.sources {
                    match source.collect().await {
                        Ok(samples) => round.extend(samples),
                        Err(err) => tracing::warn!(source = source.name(), error = %err, "metrics source failed"),
                    }
                }
                if !round.is_empty() {
                    let _ = self.tx.send(round);
                }
            }
        })
    }
}

/// MO-04 / VM-07: physical RAM and CPUs, assigned totals from running VMs' .vmx, free disk. Stub.
pub async fn host_capacity() -> Result<HostCapacity> {
    Err(crate::error::CoreError::NotImplemented("MO-04 host capacity"))
}
