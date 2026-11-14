//! VM-30 (0.8.0 G7): the deploy runner's part of a golden image build. The build VM is made and installed exactly as
//! G6's unattended deploy makes and installs a VM ([`Deployer::make`], [`Deployer::watch_install`]: the config as
//! approved, the seed in a private folder, the watcher, Windows' first sign-in that sets the vault's password). Its
//! seed (the answer file) is taken out and emptied as soon as the install is done, before anything is made generic
//! (Q2 of PR 100's review). Then it is made generic ([`crate::golden::generic`]): Linux over SSH as the config's first
//! user with its vault key, the steps as root through sudo, within [`LINUX_RUN_LIMIT`], every step reporting `ok`;
//! Windows over WinRM with the vault's password and the certificate the VM wrote to COM1, sysprep from a scheduled
//! task. The guest powers itself off (a VirtualBox VM that aborted, or a Windows one that went off before its task
//! said it removed the listener and started sysprep, fails the build); then its install CDs come out of its settings
//! (the drives themselves), its serial port and VirtualBox's NAT rule go, the seed, the ISO link and the serial log are
//! deleted, and the snapshot is taken (powered off: no memory). A settings change that fails there fails the build
//! before the snapshot (A6). Its clones copy none of the install.
//!
//! A failure before the VM is made removes what this build made (G6's cleanup); after that the VM is kept for a look,
//! its seed taken out (G6's `abandon_install`), and the error says so. The vault: a build needs it for the answer
//! file's passwords and to sign in; while it is locked the step waits ([`super::install::VAULT_WAIT`], which the window
//! turns into a notification) for up to 4 hours, and nothing is sent anywhere meanwhile; each round of the wait asks
//! whether the build's approval still stands (Q1: a schedule edited, paused or deleted meanwhile builds nothing).
//!
//! Rule 7: the key, the passwords and the rendered file never reach a note, an error, the journal or a log.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::install::{self, empty_link, Drive, InstallMade, PinnedCertificate, MAX_VAULT_WAIT, VAULT_WAIT};
use super::{Deployer, Made, SHORT};
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::remote::{
    AuthMethod, ConnectOptions, ConnectRequest, Credentials, HostKeyVerifier, RemoteAdapter, SessionSpec,
};
use crate::adapters::vmx_file::VmxFile;
use crate::adapters::winrm::{WinrmConnect, WinrmSpec, WinrmTuning};
use crate::command_bus::SnapshotOp;
use crate::deploy::spec::{DeploySpec, DeployVm};
use crate::deploy::{virtualbox as vb, DeployProgress};
use crate::domain::{Context, Environment, PowerState};
use crate::error::{CoreError, Result};
use crate::golden::generic::{self, Report};
use crate::golden::{BuildSpec, Built, SignIn, StillApproved};
use crate::known_hosts::HostKey;
use crate::sessions::kinds::{WinrmCertificate, WinrmOptions, WinrmSignIn, WinrmTransport};
use crate::vault::{SecretString, VaultStatus};

/// What a generalization run may print.
const MAX_REPORT: usize = 64 * 1024;
/// Q3 of PR 100's review: the longest the Linux steps may run over SSH. Their `boot` step waits at most 10 minutes
/// each for systemd, cloud-init and package jobs; the rest takes seconds.
const LINUX_RUN_LIMIT: Duration = Duration::from_secs(45 * 60);

/// The build VM as Linux's generalization reaches it: its address, the config's user, its key and sudo's password.
pub struct LinuxGuest<'a> {
    pub vm: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub key: SecretString,
    /// `None`: sudo needs no password (the config's user has none).
    pub sudo_password: Option<SecretString>,
}

/// VM-30: how Linux's generalization reaches a build VM (tests give their own).
#[async_trait]
pub trait GuestShell: Send + Sync {
    /// Runs `script` as root (sudo) on the guest and returns its stdout. Then, only when that report says every step
    /// went ([`Report::linux_problems`] is empty), `power_off` as root on the same connection without waiting for its
    /// answer (the guest's sshd stops, and its host keys are gone, so a new connection couldn't sign in). A VM whose
    /// steps didn't all go is left running, for a look and so the work a step waited for isn't cut short (N4 of
    /// PR 100's second review).
    async fn linux(&self, guest: &LinuxGuest<'_>, script: &str, power_off: &str) -> Result<String>;
}

/// The build VM's host key, taken on first use: the VM was made by this build on this PC's own network moments ago,
/// its host keys are deleted by the generalization, and nothing is saved in known_hosts. Another key on a later
/// connection of the same build is refused.
#[derive(Default)]
struct FirstUse {
    seen: std::sync::Mutex<Option<String>>,
}

#[async_trait]
impl HostKeyVerifier for FirstUse {
    async fn verify(&self, key: &HostKey, _jump: Option<&str>) -> Result<()> {
        let mut seen = crate::locks::lock(&self.seen);
        match seen.as_deref() {
            None => {
                *seen = Some(key.fingerprint.clone());
                Ok(())
            }
            Some(first) if first == key.fingerprint => Ok(()),
            Some(_) => Err(CoreError::HostKeyRejected {
                address: format!("{}:{} (a build VM showed another host key)", key.host, key.port),
                jump: None,
            }),
        }
    }
}

/// The real one: SSH through the app's remote adapter, the script under sudo on an exec channel (BX-07's `sudo -S`).
pub struct SshGuestShell {
    remote: Arc<dyn RemoteAdapter>,
}

impl SshGuestShell {
    pub fn new(remote: Arc<dyn RemoteAdapter>) -> Self {
        Self { remote }
    }
}

#[async_trait]
impl GuestShell for SshGuestShell {
    async fn linux(&self, guest: &LinuxGuest<'_>, script: &str, power_off: &str) -> Result<String> {
        let session = SessionSpec {
            id: Uuid::new_v4(),
            name: guest.vm.to_owned(),
            host: guest.host.to_owned(),
            port: guest.port,
            username: guest.user.to_owned(),
            // The vault item isn't read through here: the key comes in `credentials`.
            auth: AuthMethod::PrivateKey {
                key: crate::vault::SecretId(Uuid::nil()),
                passphrase: None,
            },
            jump: None,
            environment: Environment::None,
            startup_command: None,
            startup_on_reconnect: false,
            prompt_hook: Some(false),
        };
        let options = ConnectOptions::default();
        let connected = self
            .remote
            .connect(ConnectRequest {
                session: &session,
                credentials: Credentials::PrivateKey {
                    key: guest.key.clone(),
                    passphrase: None,
                    label: "the install config's key".into(),
                },
                jump_credentials: Vec::new(),
                options: &options,
                verifier: Arc::new(FirstUse::default()),
                who: "a golden image build",
            })
            .await?;
        let empty = SecretString::new(String::new());
        let password = guest.sudo_password.as_ref().unwrap_or(&empty);
        let ran = connected.run_sudo(script, password, MAX_REPORT).await;
        let out = match ran {
            Ok(result) if result.exit_code == Some(0) => Ok(result.output.stdout),
            Ok(result) => Err(CoreError::InvalidInput(format!(
                "the steps that make it generic stopped (exit code {}): {}",
                result.exit_code.map_or_else(|| "none".into(), |c| c.to_string()),
                result.output.stderr.lines().last().unwrap_or_default()
            ))),
            Err(err) => Err(err),
        };
        let whole = out
            .as_ref()
            .is_ok_and(|stdout| Report::parse(stdout).linux_problems().is_empty());
        if whole {
            // Its answer may never come: the guest goes down.
            let _ = tokio::time::timeout(Duration::from_secs(15), connected.run_sudo(power_off, password, 1024)).await;
        }
        connected.close().await;
        out
    }
}

impl Deployer {
    /// Waits while the vault is locked, saying so, for up to [`MAX_VAULT_WAIT`]; a cancel stops the wait. Q1 of PR 100's
    /// review: the build's approval is asked before the wait and after each round of it, so a scheduled build whose
    /// schedule was edited, paused or deleted (its standing approval withdrawn) while it waited goes no further.
    async fn wait_for_vault(
        &self,
        approved: &dyn StillApproved,
        progress: &DeployProgress<'_>,
        at: f64,
        why: &str,
        token: &CancellationToken,
    ) -> Result<()> {
        let poll = self.tuning().install_poll;
        let deadline = tokio::time::Instant::now() + MAX_VAULT_WAIT;
        loop {
            approved.check().await?;
            if self.vault.status() != VaultStatus::Locked {
                return Ok(());
            }
            progress(at, &format!("{VAULT_WAIT} to {why}"));
            if tokio::time::Instant::now() >= deadline {
                return Err(CoreError::InvalidInput(format!(
                    "the vault stayed locked for {} hours, so the build couldn't {why}",
                    MAX_VAULT_WAIT.as_secs() / 3600
                )));
            }
            tokio::select! {
                _ = token.cancelled() => return Err(CoreError::Cancelled),
                _ = tokio::time::sleep(poll) => {}
            }
        }
    }

    /// A vault item, waiting while the vault is locked.
    async fn vault_item(
        &self,
        ctx: &Context,
        id: crate::vault::SecretId,
        approved: &dyn StillApproved,
        progress: &DeployProgress<'_>,
        why: &str,
        token: &CancellationToken,
    ) -> Result<SecretString> {
        loop {
            self.wait_for_vault(approved, progress, 88.0, why, token).await?;
            match self.vault.get(ctx, id).await {
                Err(CoreError::VaultLocked) => continue,
                other => return other,
            }
        }
    }

    /// VM-30: one build (see the module). The deploy's ISO copy is the job's own, as a deploy's.
    pub(super) async fn build_one(
        &self,
        ctx: &Context,
        job_id: Uuid,
        build: &BuildSpec,
        approved: &dyn StillApproved,
        progress: &DeployProgress<'_>,
        token: &CancellationToken,
    ) -> Result<Built> {
        let spec = &build.deploy;
        let (Some(vm), Some(install)) = (spec.vms.first(), spec.install.as_ref()) else {
            return Err(CoreError::InvalidInput(
                "A build makes one VM from an install config.".into(),
            ));
        };
        // The answer file takes the vault's passwords as it is rendered: nothing is made while the vault is locked.
        self.wait_for_vault(approved, progress, 0.0, "render the answer file", token)
            .await?;
        let mut made = Made::default();
        let outcome = {
            let work = self.make(ctx, job_id, spec, vm, &mut made, progress, token);
            tokio::select! {
                biased;
                _ = token.cancelled() => Err(CoreError::Cancelled),
                done = work => done,
            }
        };
        let key = match outcome {
            Ok(key) => key,
            Err(err) => {
                self.release_claim(ctx, job_id, &made).await;
                if let Some(m) = &made.install {
                    self.isos_forget(job_id, m).await;
                }
                let left = self.clean_up(spec, &made).await;
                if matches!(err, CoreError::Cancelled) && left.is_empty() {
                    return Err(CoreError::Cancelled);
                }
                let mut message = err.to_string();
                if left.is_empty() {
                    message.push_str("; what it made was removed");
                } else {
                    message.push_str(&format!("; what it made was removed but for {}", left.join(", ")));
                }
                return Err(CoreError::DeployFailed {
                    vm: vm.name.clone(),
                    message,
                });
            }
        };
        let Some(m) = made.install.take() else {
            return Err(CoreError::InvalidInput("The build's VM has no install.".into()));
        };
        let mut notes = vec![format!("made in {}", spec.vm_folder(vm).display())];
        notes.append(&mut made.notes);
        let finished = async {
            let address = self
                .watch_install(ctx, spec, install, vm, &key, &m, &mut notes, progress, token)
                .await?;
            let Some(address) = address else {
                return Err(CoreError::InvalidInput(
                    "it is installed, but its address isn't known, so it couldn't be made generic".into(),
                ));
            };
            notes.push(format!("installed, reached at {}", address.0));
            // Q2 of PR 100's review: the seed (the answer file's hashes, or Windows' one-time password, already
            // replaced by the vault's) leaves the VM before anything is made generic. N3: Windows isn't generalized
            // with its answer file still attached (Setup's implicit search reads a removable drive's).
            match self.seed_out(spec, &key, &m).await {
                Ok(said) => notes.push(said),
                Err(said) if build.os.windows() => {
                    return Err(CoreError::InvalidInput(format!(
                        "{said}, so Windows wasn't generalized with its answer file attached"
                    )))
                }
                Err(said) => notes.push(format!("{said}: it goes once the VM is off")),
            }
            let report = self
                .make_generic(ctx, build, vm, &m, &address, approved, progress, token)
                .await?;
            notes.push(format!("made generic: {}", report.done_text()));
            notes.extend(report.notes());
            if build.os != crate::golden::BuildOs::Windows {
                if report.cloud_init() == Some(false) {
                    notes.push("it has no cloud-init: its clones keep this build's hostname, users and keys".into());
                }
                if spec.hypervisor == Hypervisor::Vmware && report.vm_tools() == Some(false) {
                    notes.push(
                        "it has no open-vm-tools: a clone's first boot on Workstation reads cloud-init's settings through them, so add open-vm-tools to the config's packages and build again"
                            .into(),
                    );
                }
            }
            self.wait_powered_off(build, &key, &m, progress, token).await?;
            Ok(report)
        }
        .await;
        let report = match finished {
            Ok(report) => report,
            Err(err) => {
                let cancelled = matches!(err, CoreError::Cancelled);
                notes.push(match err {
                    CoreError::InstallFailed { message, .. } => message,
                    CoreError::Cancelled => "the build was cancelled; the VM goes on as it was".into(),
                    other => format!("the build stopped: {other}"),
                });
                notes.extend(self.abandon_install(job_id, spec, &key, &m).await);
                let message = notes.join("; ");
                return Err(if cancelled {
                    CoreError::InstallCancelled {
                        vm: vm.name.clone(),
                        message,
                    }
                } else {
                    CoreError::InstallFailed {
                        vm: vm.name.clone(),
                        message,
                    }
                });
            }
        };
        progress(96.0, "taking the install's CDs and serial port out");
        // A6 of PR 100's review: a change to its settings that didn't go fails the build before the snapshot, so no
        // version's clones carry the install's drives or serial port.
        match self.seal(job_id, spec, &key, &m).await {
            Ok(said) => notes.extend(said),
            Err(problems) => {
                notes.extend(problems);
                notes.push(
                    "the VM is kept, generic and shut down, without a snapshot: fix its settings, then build the image again"
                        .into(),
                );
                return Err(CoreError::InstallFailed {
                    vm: vm.name.clone(),
                    message: notes.join("; "),
                });
            }
        }
        progress(98.0, "taking the snapshot");
        let snapshot_name = crate::golden::spec::snapshot_name(build.version);
        let taken = self
            .hypervisors
            .snapshot(
                &key,
                &SnapshotOp::Take {
                    name: snapshot_name.clone(),
                },
            )
            .await
            .and(Ok(()));
        let snapshot_id = match taken {
            Ok(()) => self.snapshot_id(&key, &snapshot_name).await,
            Err(err) => Err(err),
        };
        let snapshot_id = snapshot_id.map_err(|err| CoreError::InstallFailed {
            vm: vm.name.clone(),
            message: format!(
                "{}; the snapshot '{snapshot_name}' wasn't taken ({err}): the VM is kept, generic and shut down, so take it by hand and add the image",
                notes.join("; ")
            ),
        })?;
        notes.push(format!("snapshot '{snapshot_name}' taken, powered off"));
        progress(100.0, "built");
        Ok(Built {
            vm_key: self
                .store
                .find_vm(ctx, &key)
                .await
                .ok()
                .flatten()
                .map_or_else(|| key.clone(), |r| r.vmx_path),
            vm_name: vm.name.clone(),
            snapshot_id,
            snapshot_name,
            facts: generic::facts(&report),
            notes,
        })
    }

    /// The snapshot's id as images name it: Workstation's `snapshotN.uid`, VirtualBox's UUID.
    async fn snapshot_id(&self, key: &str, name: &str) -> Result<String> {
        let tree = self.hypervisors.snapshots(key).await?;
        tree.snapshots
            .iter()
            .rev()
            .find(|s| s.name == name)
            .map(|s| s.id.clone().unwrap_or_else(|| s.uid.to_string()))
            .ok_or_else(|| CoreError::UnknownTarget(format!("snapshot '{name}'")))
    }

    /// Q2 of PR 100's review: the seed out of its drive (G6's eject: Workstation's disconnected, VirtualBox's emptied)
    /// and its file emptied (Workstation's drive keeps an empty disc until [`Self::seal`] removes the drive). `Ok`
    /// with what it did once the seed is out of its drive (a file not emptied yet goes with the seal); `Err` while the
    /// drive still holds it.
    async fn seed_out(&self, spec: &DeploySpec, key: &str, m: &InstallMade) -> std::result::Result<String, String> {
        let workstation = spec.hypervisor == Hypervisor::Vmware;
        let ejected = match &m.seed_drive {
            Some(drive) => self.eject(key, drive, &m.seed).await,
            None => Ok(()),
        };
        match ejected {
            Err(err) => Err(format!("its seed couldn't be taken out of its drive ({err})")),
            Ok(()) => Ok(match empty_link(&m.seed, workstation).await {
                Ok(()) => "its seed (the answer file) is taken out and emptied".into(),
                Err(err) => format!("its seed is taken out, but its file couldn't be emptied yet ({err})"),
            }),
        }
    }

    /// Makes the installed system generic (see [`crate::golden::generic`]); Windows' sysprep then runs from its task.
    #[allow(clippy::too_many_arguments)]
    async fn make_generic(
        &self,
        ctx: &Context,
        build: &BuildSpec,
        vm: &DeployVm,
        m: &InstallMade,
        (host, port): &(String, u16),
        approved: &dyn StillApproved,
        progress: &DeployProgress<'_>,
        token: &CancellationToken,
    ) -> Result<Report> {
        let tuning = self.tuning();
        progress(88.0, "making it generic");
        match &build.sign_in {
            SignIn::Ssh {
                user,
                key_id,
                sudo_password_id,
            } => {
                let (probe_host, probe_port) = match &tuning.probe {
                    Some((h, ssh, _)) => (h.clone(), *ssh),
                    None => (host.clone(), *port),
                };
                let ssh_key = self
                    .vault_item(ctx, *key_id, approved, progress, "sign in to make it generic", token)
                    .await?;
                let sudo = match sudo_password_id {
                    Some(id) => Some(
                        self.vault_item(ctx, *id, approved, progress, "sign in to make it generic", token)
                            .await?,
                    ),
                    None => None,
                };
                let shell = self.guest_shell()?;
                let guest = LinuxGuest {
                    vm: &vm.name,
                    host: &probe_host,
                    port: probe_port,
                    user,
                    key: ssh_key,
                    sudo_password: sudo,
                };
                // Q3 of PR 100's review: the run has a time limit (a hung step fails the build, keeping the VM).
                let limit = tuning
                    .install_cap
                    .map_or(LINUX_RUN_LIMIT, |cap| LINUX_RUN_LIMIT.min(cap));
                let run = tokio::time::timeout(
                    limit,
                    shell.linux(&guest, generic::LINUX_SCRIPT, generic::LINUX_POWER_OFF),
                );
                let out = tokio::select! {
                    _ = token.cancelled() => return Err(CoreError::Cancelled),
                    out = run => match out {
                        Ok(out) => out?,
                        Err(_) => {
                            return Err(CoreError::InvalidInput(format!(
                                "the steps that make it generic didn't end within {} minutes",
                                limit.as_secs().div_ceil(60)
                            )))
                        }
                    },
                };
                drop(guest);
                // A3 of PR 100's review: every step must say ok, else the build fails and the VM stays as it is,
                // running (N4: the shell powers off only a VM whose steps all went).
                let report = Report::parse(&out);
                let problems = report.linux_problems();
                if !problems.is_empty() {
                    let done = report.done_text();
                    let said = report.notes();
                    return Err(CoreError::InvalidInput(format!(
                        "it wasn't made generic: {}{}{}; it is left running, so the work a step waited for goes on",
                        problems.join(", "),
                        if done.is_empty() {
                            String::new()
                        } else {
                            format!(" (done before: {done})")
                        },
                        if said.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", said.join("; "))
                        }
                    )));
                }
                progress(92.0, "shutting down");
                Ok(report)
            }
            SignIn::Winrm { account, password_id } => {
                let fingerprint = self.read_fingerprint(&m.serial).await.ok_or_else(|| {
                    CoreError::InvalidInput("its serial port holds no WinRM certificate to check".into())
                })?;
                let password = self
                    .vault_item(
                        ctx,
                        *password_id,
                        approved,
                        progress,
                        "sign in to make it generic",
                        token,
                    )
                    .await?;
                let (probe_host, probe_port) = match &tuning.probe {
                    Some((h, _, winrm)) => (h.clone(), *winrm),
                    None => (host.clone(), *port),
                };
                let tools = self.install_tools()?;
                let winrm_spec = WinrmSpec {
                    id: Uuid::new_v4(),
                    name: vm.name.clone(),
                    host: probe_host,
                    port: probe_port,
                    username: Some(account.clone()),
                    password_id: None,
                    options: WinrmOptions {
                        transport: WinrmTransport::Https,
                        sign_in: WinrmSignIn::Ntlm,
                        certificate: WinrmCertificate::Fingerprint,
                    },
                    environment: build.deploy.environment,
                };
                let pinned = Arc::new(PinnedCertificate::new(&fingerprint));
                let verifier: Arc<dyn HostKeyVerifier> = pinned.clone();
                let session = tools
                    .winrm
                    .connect(WinrmConnect {
                        spec: &winrm_spec,
                        password: Some(password),
                        verifier,
                        tuning: WinrmTuning::default(),
                    })
                    .await
                    .map_err(|err| match pinned.mismatch() {
                        Some(other) => CoreError::InvalidInput(format!(
                            "WinRM showed the certificate {other}, not the one the VM wrote to its serial port ({fingerprint}): Remotely didn't sign in"
                        )),
                        None => err,
                    })?;
                let ran = session.run(&generic::windows_script(), MAX_REPORT).await;
                session.close().await;
                let out = ran?;
                let report = Report::parse(&out.output.stdout);
                if out.exit_code != Some(0) || !report.has("scheduled") {
                    return Err(CoreError::InvalidInput(format!(
                        "the task that runs sysprep wasn't made: {}",
                        out.output.stderr.lines().last().unwrap_or("no answer")
                    )));
                }
                progress(90.0, "sysprep runs (it shuts Windows down)");
                Ok(report)
            }
        }
    }

    fn guest_shell(&self) -> Result<Arc<dyn GuestShell>> {
        self.install_tools()?
            .guests
            .ok_or(CoreError::NotImplemented("signing in to a build VM"))
    }

    /// Whether the VM is powered off now (a VM the hypervisor can't say about counts as on). A4 of PR 100's review: a
    /// VirtualBox VM that aborted (its process crashed or was killed) didn't shut down, so it is an error: its disk
    /// may hold a half-written system. Workstation's list of running VMs can't tell the two apart.
    async fn powered_off(&self, hypervisor: Hypervisor, key: &str) -> Result<bool> {
        Ok(match hypervisor {
            Hypervisor::Vmware => match self.hypervisors.vmware().list_running().await {
                Ok(running) => {
                    let wanted = crate::adapters::vmware::path_key(Path::new(key));
                    !running.iter().any(|p| crate::adapters::vmware::path_key(p) == wanted)
                }
                Err(_) => false,
            },
            Hypervisor::VirtualBox => match self.hypervisors.virtualbox().vm_info(key).await {
                Ok(info) if info.state.trim().eq_ignore_ascii_case("aborted") => {
                    return Err(CoreError::InvalidInput(
                        "VirtualBox says the VM aborted instead of shutting down: it isn't sealed".into(),
                    ))
                }
                Ok(info) => info.power_state() == PowerState::NotRunning,
                Err(_) => false,
            },
        })
    }

    /// Waits for the guest to power itself off once it is generic, at most the build's `seal_minutes`. Windows'
    /// task writes its steps to COM1: a task that stopped (a removal that didn't go, or sysprep's failure) fails the
    /// build at once, and (A4, N8 of PR 100's reviews) a power-off counts as sysprep's only once the task said it
    /// removed the build's listener, ran sysprep and found it sealed ([`generic::WINDOWS_STEPS`]): a power-off while
    /// sysprep runs isn't.
    async fn wait_powered_off(
        &self,
        build: &BuildSpec,
        key: &str,
        m: &InstallMade,
        progress: &DeployProgress<'_>,
        token: &CancellationToken,
    ) -> Result<()> {
        let tuning = self.tuning();
        let limit = Duration::from_secs(u64::from(build.seal_minutes) * 60);
        let limit = tuning.install_cap.map_or(limit, |cap| limit.min(cap));
        let deadline = tokio::time::Instant::now() + limit;
        let mut at = 0u64;
        let mut seen = String::new();
        let mut report = Report::default();
        loop {
            let off = self.powered_off(build.deploy.hypervisor, key).await?;
            if build.os.windows() {
                // Read after the power state, so lines the task wrote before Windows went down are in.
                let bytes = install::read_to_end_now(&m.serial, &mut at).await;
                seen.push_str(&crate::deploy::watch::strip_escapes(&bytes));
                report = Report::parse(&seen);
                // With /quit, sysprep's failure is its own (no shutdown ends it first), so it comes first.
                if let Some(failed) = report.windows_failure() {
                    return Err(CoreError::InvalidInput(failed));
                }
                let missing = report.windows_missing();
                if off && !missing.is_empty() {
                    return Err(CoreError::InvalidInput(format!(
                        "Windows went off before the task that runs sysprep said '{}': it isn't sealed",
                        missing.join("' and '")
                    )));
                }
                if report.has("sealed") {
                    progress(94.0, "sealed: the task shuts Windows down");
                } else if report.has("sysprep") {
                    progress(92.0, "sysprep runs");
                }
            }
            if off {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                let minutes = limit.as_secs().div_ceil(60);
                return Err(CoreError::InvalidInput(if !build.os.windows() {
                    format!("it didn't shut down within {minutes} minutes of being made generic")
                } else {
                    // N6 of PR 100's second review: worded by what COM1 showed last.
                    match report.last() {
                        None => format!(
                            "the task that runs sysprep wrote nothing to COM1 within {minutes} minutes: see Task Scheduler's history for '{}'",
                            generic::WINDOWS_TASK
                        ),
                        Some("sysprep") => format!(
                            "sysprep didn't finish within {minutes} minutes: its log is C:\\Windows\\System32\\Sysprep\\Panther\\setupact.log"
                        ),
                        Some("sealed") => format!(
                            "sysprep finished, but Windows didn't shut down within {minutes} minutes"
                        ),
                        Some(last) => format!(
                            "it didn't shut down within {minutes} minutes; the task's last word on COM1 was '{last}'"
                        ),
                    }
                }));
            }
            tokio::select! {
                _ = token.cancelled() => return Err(CoreError::Cancelled),
                _ = tokio::time::sleep(tuning.install_poll) => {}
            }
        }
    }

    /// VM-30: a clone of a sysprepped Windows image on Workstation: its seed (the config's specialize and oobeSystem
    /// passes, rendered for it) in a CD drive of its own on the first free SATA slot, and COM1 to its serial log.
    pub(super) async fn clone_install_workstation(&self, vmx: &Path, made: &mut Made) -> Result<()> {
        let Some(m) = made.install.as_mut() else {
            return Ok(());
        };
        let vmware = self.hypervisors.vmware();
        let mut file = VmxFile::parse(&vmware.vmx_bytes(vmx).await?)?;
        let slot = (0..30)
            .map(|n| format!("sata0:{n}"))
            .find(|slot| !file.is_true(&format!("{slot}.present")))
            .ok_or_else(|| CoreError::InvalidInput("The clone has no free SATA slot for its seed.".into()))?;
        file.set("sata0.present", "TRUE")?;
        file.set(&format!("{slot}.present"), "TRUE")?;
        file.set(&format!("{slot}.deviceType"), "cdrom-image")?;
        file.set(&format!("{slot}.fileName"), &m.seed.display().to_string())?;
        file.set(&format!("{slot}.startConnected"), "TRUE")?;
        for (key, value) in crate::deploy::vmx::serial_file_keys(&m.serial) {
            file.set(key, &value)?;
        }
        vmware.write_vmx(vmx, &file.to_bytes()).await?;
        m.seed_drive = Some(Drive::Workstation(slot));
        Ok(())
    }

    /// VM-30: the same on VirtualBox: the seed in a drive on the clone's boot disk's controller, COM1 to its serial
    /// log, and on NAT the rule to its WinRM port while it is watched.
    pub(super) async fn clone_install_virtualbox(&self, uuid: &str, made: &mut Made) -> Result<()> {
        let (controller, port, device) = self.dvd_slot(uuid).await?;
        let Some(m) = made.install.as_mut() else {
            return Ok(());
        };
        self.vbox(
            vb::attach_named(uuid, &controller, port, device, true, &m.seed.display().to_string()),
            SHORT,
        )
        .await?;
        self.vbox(vb::uart_args(uuid, &m.serial), SHORT).await?;
        if let Some(host_port) = m.nat_port {
            self.vbox(
                vec![
                    "modifyvm".into(),
                    uuid.into(),
                    "--natpf1".into(),
                    crate::deploy::install::nat_rule(host_port, m.flavor.port()),
                ],
                SHORT,
            )
            .await?;
        }
        m.seed_drive = Some(Drive::VirtualBox(controller, port));
        Ok(())
    }

    /// The powered-off VM keeps nothing of its install: the ISO copy's and the seed's drives out of its settings, its
    /// serial port off, VirtualBox's NAT rule gone, and the seed, the ISO link and the serial log deleted. Every change
    /// to its settings is tried (VirtualBox's asked again while VBoxHeadless still holds the VM's session lock just
    /// after the power-off: N2 of PR 100's second review); `Err` (A6) when one didn't go, with what it couldn't do, so
    /// the build stops before the snapshot, and then the files stay, since the settings still name them and the serial
    /// log is what to look at. A file that couldn't be deleted after the settings went is only noted: the settings no
    /// longer name it, so no clone copies it.
    async fn seal(
        &self,
        job_id: Uuid,
        spec: &DeploySpec,
        key: &str,
        m: &InstallMade,
    ) -> std::result::Result<Vec<String>, Vec<String>> {
        let mut out = Vec::new();
        let mut settings_failed = false;
        self.isos.forget(job_id, &m.iso).await;
        match spec.hypervisor {
            Hypervisor::Vmware => {
                let vmware = self.hypervisors.vmware();
                let vmx = Path::new(key);
                let changed = async {
                    let mut file = VmxFile::parse(&vmware.vmx_bytes(vmx).await?)?;
                    for drive in m.iso_drive.iter().chain(&m.seed_drive) {
                        if let Drive::Workstation(slot) = drive {
                            file.remove_prefix(&format!("{slot}."));
                        }
                    }
                    file.remove_prefix("serial0.");
                    vmware.write_vmx(vmx, &file.to_bytes()).await
                }
                .await;
                if let Err(err) = changed {
                    settings_failed = true;
                    out.push(format!(
                        "its install drives and serial port are still in its settings ({err}): remove them in Settings"
                    ));
                }
            }
            Hypervisor::VirtualBox => {
                for drive in m.iso_drive.iter().chain(&m.seed_drive) {
                    if let Drive::VirtualBox(controller, port) = drive {
                        let args = vb::attach_named(key, controller, *port, 0, true, "none");
                        if let Err(err) = self.vbox_unlocked(args).await {
                            settings_failed = true;
                            out.push(format!("its drive {controller} port {port} stays ({err})"));
                        }
                    }
                }
                for file in [&m.iso, &m.seed] {
                    let close = vec!["closemedium".into(), "dvd".into(), file.display().to_string()];
                    let _ = self.vbox(close, SHORT).await;
                }
                if let Err(err) = self
                    .vbox_unlocked(vec!["modifyvm".into(), key.into(), "--uart1".into(), "off".into()])
                    .await
                {
                    settings_failed = true;
                    out.push(format!("its serial port stays on ({err})"));
                }
                if m.nat_port.is_some() {
                    let rule = vec![
                        "modifyvm".into(),
                        key.into(),
                        "--natpf1".into(),
                        "delete".into(),
                        crate::deploy::install::NAT_RULE.into(),
                    ];
                    if let Err(err) = self.vbox_unlocked(rule).await {
                        settings_failed = true;
                        out.push(format!(
                            "its NAT rule {} stays ({err})",
                            crate::deploy::install::NAT_RULE
                        ));
                    }
                }
            }
        }
        if settings_failed {
            out.push(format!(
                "its seed, its ISO link and its serial log {} stay with it, as its settings still name them",
                m.serial.display()
            ));
            return Err(out);
        }
        for file in [&m.seed, &m.iso, &m.serial] {
            if let Err(err) = tokio::fs::remove_file(file).await {
                if err.kind() != std::io::ErrorKind::NotFound {
                    out.push(format!(
                        "{} couldn't be deleted ({err}): delete it by hand",
                        file.display()
                    ));
                }
            }
        }
        let _ = tokio::fs::remove_dir(&m.seed_folder).await;
        Ok(out)
    }

    /// A VBoxManage change asked again while VirtualBox says the VM's session lock is held (VBoxHeadless lets go of
    /// it a moment after the guest powered off: N2 of PR 100's second review).
    async fn vbox_unlocked(&self, args: Vec<String>) -> Result<String> {
        let mut waits = SESSION_RETRIES.iter();
        loop {
            match self.vbox(args.clone(), SHORT).await {
                Err(err) if session_locked(&err) => match waits.next() {
                    Some(wait) => tokio::time::sleep(*wait).await,
                    None => return Err(err),
                },
                other => return other,
            }
        }
    }
}

/// How long to wait before each new try while VirtualBox holds the VM's session lock.
const SESSION_RETRIES: [Duration; 5] = [
    Duration::from_millis(200),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

/// VirtualBox's answer while another process holds the VM's session lock, or is letting go of it.
fn session_locked(err: &CoreError) -> bool {
    if crate::adapters::host_networks::vbox_busy(err) {
        return true;
    }
    let CoreError::VboxManage { message, .. } = err else {
        return false;
    };
    let message = message.to_ascii_lowercase();
    message.contains("already locked for a session") || message.contains("is already locked by a session")
}
