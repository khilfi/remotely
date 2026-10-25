//! Shared setup for the integration tests: a core wired to fake adapters, so no real VM, host, vault
//! or update server is touched.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use remotely_core::adapters::containers::cli::CliEngines;
use remotely_core::adapters::containers::ContainerEngines;
use remotely_core::adapters::network::NetworkAdapter;
use remotely_core::adapters::remote::{RemoteAdapter, RusshAdapter};
use remotely_core::adapters::updater::UpdaterAdapter;
use remotely_core::domain::TargetRef;
use remotely_core::fakes::{
    FakeContainers, FakeHostCounters, FakeKeyProtector, FakeNetwork, FakeRemote, FakeUpdater, FakeVault,
    FakeVirtualBox, FakeVmware,
};
use remotely_core::jobs::{JobEvent, JobLimits, JobStatus};
use remotely_core::policy::PolicyRules;
use remotely_core::store::Store;
use remotely_core::vault::{LocalVault, SecretString, Vault, VaultOptions};
use remotely_core::{Adapters, Core};
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

pub const VAULT_PASSWORD: &str = "correct horse";

pub struct Setup {
    pub vmware: Arc<FakeVmware>,
    /// VM-18: installed, with no VMs, unless a test gives its own ([`Setup::with_virtualbox`]).
    pub virtualbox: Arc<FakeVirtualBox>,
    pub host: FakeHostCounters,
    pub rules: PolicyRules,
    /// The app's own vault (fake DPAPI, fast key derivation), set up with [`VAULT_PASSWORD`] and the
    /// Windows login, and unlocked. Otherwise a [`FakeVault`] with that password.
    pub real_vault: bool,
    /// [`FakeRemote`] unless a test talks SSH to its own local server ([`Setup::with_ssh`]).
    pub remote: Arc<dyn RemoteAdapter>,
    /// FD-14: a [`FakeUpdater`] that offers nothing, unless a test gives its own.
    pub updater: Arc<dyn UpdaterAdapter>,
    /// DNS (QL-01, QL-03) and QL-04 probes: a [`FakeNetwork`] that resolves no name and reaches no
    /// port unless a test adds them; no real lookups unless a test asks for them.
    pub network: Arc<dyn NetworkAdapter>,
    /// CT-01, CT-02: [`FakeContainers`] with no host, or the real CLIs over SSH ([`Setup::with_ssh`]),
    /// which never look for this PC's Docker.
    pub containers: Arc<dyn ContainerEngines>,
}

impl Setup {
    pub fn new(vmware: FakeVmware) -> Self {
        Self {
            vmware: Arc::new(vmware),
            virtualbox: Arc::new(FakeVirtualBox::new()),
            host: FakeHostCounters::default(),
            // Keep tests fast; the countdown has its own test in command_flow.rs.
            rules: PolicyRules {
                countdown_seconds: 0,
                ..Default::default()
            },
            real_vault: false,
            remote: Arc::new(FakeRemote::default()),
            updater: Arc::new(FakeUpdater::default()),
            network: Arc::new(FakeNetwork::default()),
            containers: Arc::new(FakeContainers::default()),
        }
    }

    /// CT-01, CT-02: other container engines, e.g. [`FakeContainers`] with hosts.
    pub fn with_containers(mut self, containers: Arc<dyn ContainerEngines>) -> Self {
        self.containers = containers;
        self
    }

    /// VM-18: VirtualBox's VMs.
    pub fn with_virtualbox(mut self, virtualbox: FakeVirtualBox) -> Self {
        self.virtualbox = Arc::new(virtualbox);
        self
    }

    pub fn with_updater(mut self, updater: Arc<dyn UpdaterAdapter>) -> Self {
        self.updater = updater;
        self
    }

    pub fn with_network(mut self, network: Arc<dyn NetworkAdapter>) -> Self {
        self.network = network;
        self
    }

    /// Another fake remote adapter, e.g. a [`FakeRemote`] with files (SS-08).
    pub fn with_remote(mut self, remote: Arc<dyn RemoteAdapter>) -> Self {
        self.remote = remote;
        self
    }

    /// The real russh adapter, for tests against `fakes::ssh_server::TestSshServer` on 127.0.0.1.
    pub fn with_ssh(mut self) -> Self {
        self.remote = Arc::new(RusshAdapter::new());
        self.containers = Arc::new(CliEngines::without_this_pc());
        self
    }

    pub fn with_real_vault(mut self) -> Self {
        self.real_vault = true;
        self
    }

    pub async fn build(self) -> Core {
        let store = Store::open_in_memory().await.unwrap();
        let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
        store
            .put_setting(&ctx, remotely_core::store::POLICY_RULES_KEY, &self.rules)
            .await
            .unwrap();
        let vault: Arc<dyn Vault> = if self.real_vault {
            let vault = LocalVault::open(
                store.clone(),
                ctx,
                Arc::new(FakeKeyProtector::new()),
                VaultOptions::insecure_fast(),
            )
            .await
            .unwrap();
            vault
                .setup(&ctx, SecretString::new(VAULT_PASSWORD), true)
                .await
                .unwrap();
            Arc::new(vault)
        } else {
            Arc::new(FakeVault::with_password(VAULT_PASSWORD))
        };
        let adapters = Adapters {
            vmware: self.vmware,
            virtualbox: self.virtualbox,
            remote: self.remote,
            vault,
            host_counters: Arc::new(self.host),
            updater: self.updater,
            network: self.network,
            containers: self.containers,
        };
        Core::assemble(store, ctx, adapters, JobLimits::default())
            .await
            .unwrap()
    }
}

/// SS-04, AP-06: as if the user had just given the vault password in its prompt, so the next steps
/// within 5 minutes don't ask again: tests that put one vault password on sessions to several test
/// servers (several places) call it once before saving them.
pub async fn vault_password_given(core: &Core) {
    core.secret_bindings()
        .confirm(
            &core.ctx,
            Some(&SecretString::new(VAULT_PASSWORD)),
            "test",
            "sessions on several test servers share one vault password",
        )
        .await
        .unwrap();
}

/// `C:\VMs\<name>\<name>.vmx`.
pub fn vmx(name: &str) -> String {
    format!(r"C:\VMs\{name}\{name}.vmx")
}

pub fn vm(name: &str) -> TargetRef {
    TargetRef::Vm { vmx_path: vmx(name) }
}

/// VM-18: a VirtualBox VM's target, by its UUID.
pub fn vbox_vm(uuid: &str) -> TargetRef {
    TargetRef::Vm {
        vmx_path: uuid.to_owned(),
    }
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

/// A made-up private key in OpenSSH's text form, new on every call. Only its shape is real: the vault
/// does not parse keys, and no key is ever committed (CLAUDE.md "Public repository rules").
pub fn fake_private_key() -> String {
    let body: String = (0..3).map(|_| Uuid::new_v4().simple().to_string()).collect();
    let kind = "OPENSSH PRIVATE KEY";
    format!("-----BEGIN {kind}-----\n{body}\n-----END {kind}-----\n")
}

/// A fresh empty folder under the system temp folder.
pub fn temp_folder(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("remotely-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
