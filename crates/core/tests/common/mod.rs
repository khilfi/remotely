//! Shared setup for the integration tests: a core wired to fake adapters, so no real VM, host, vault
//! or update server is touched.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use remotely_core::domain::TargetRef;
use remotely_core::fakes::{FakeHostCounters, FakeRemote, FakeUpdater, FakeVault, FakeVmware};
use remotely_core::jobs::{JobEvent, JobLimits, JobStatus};
use remotely_core::policy::PolicyRules;
use remotely_core::store::Store;
use remotely_core::{Adapters, Core};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

pub const VAULT_PASSWORD: &str = "correct horse";

pub struct Setup {
    pub vmware: Arc<FakeVmware>,
    pub host: FakeHostCounters,
    pub rules: PolicyRules,
}

impl Setup {
    pub fn new(vmware: FakeVmware) -> Self {
        Self {
            vmware: Arc::new(vmware),
            host: FakeHostCounters::default(),
            // Keep tests fast; the countdown has its own test in command_flow.rs.
            rules: PolicyRules {
                countdown_seconds: 0,
                ..Default::default()
            },
        }
    }

    pub async fn build(self) -> Core {
        let store = Store::open_in_memory().await.unwrap();
        let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
        store
            .put_setting(&ctx, remotely_core::store::POLICY_RULES_KEY, &self.rules)
            .await
            .unwrap();
        let adapters = Adapters {
            vmware: self.vmware,
            remote: Arc::new(FakeRemote::default()),
            vault: Arc::new(FakeVault::with_password(VAULT_PASSWORD)),
            host_counters: Arc::new(self.host),
            updater: Arc::new(FakeUpdater::default()),
        };
        Core::assemble(store, ctx, adapters, JobLimits::default())
            .await
            .unwrap()
    }
}

/// `C:\VMs\<name>\<name>.vmx`.
pub fn vmx(name: &str) -> String {
    format!(r"C:\VMs\{name}\{name}.vmx")
}

pub fn vm(name: &str) -> TargetRef {
    TargetRef::Vm { vmx_path: vmx(name) }
}

pub fn running(fake: &FakeVmware) -> Vec<String> {
    let mut names: Vec<String> = fake
        .running()
        .iter()
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

pub async fn wait_finished(rx: &mut Receiver<JobEvent>, job: Uuid) -> JobStatus {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let JobEvent::Finished { job_id, status } = rx.recv().await.unwrap() {
                if job_id == job {
                    return status;
                }
            }
        }
    })
    .await
    .expect("job finished in time")
}

/// A fresh empty folder under the system temp folder.
pub fn temp_folder(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("remotely-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
