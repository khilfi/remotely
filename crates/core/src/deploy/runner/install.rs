//! VM-29 (G6): the deploy runner's part of an unattended install from an install config. Before the VM is made:
//! the address claimed from its pool (VM-32), the config checked against the one approved, the VM's answer file
//! rendered with the vault's secrets onto a seed in a folder only this Windows user can open, and the VM's copy of the
//! install ISO (a hard link to the one copy the deploy makes, so a deploy of ten VMs copies the ISO once). Once it is
//! on: the install watcher (the serial log, Windows' resets, the hang a reset gets past on VirtualBox under Hyper-V),
//! the first sign-in (SSH's banner; WinRM over HTTPS with the certificate the VM wrote to its serial port, where the
//! one-time password becomes the vault's), then the ISO and the seed out, the "clean install" snapshot and the session.
//!
//! Rule 7: the rendered file, the one-time passwords and the vault's passwords never reach a log, a note, an error or
//! the journal; notes name the config and the file's SHA-256.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{Deployer, Made, SHORT};
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::remote::HostKeyVerifier;
use crate::adapters::winrm::{http::CERT_KEY_TYPE, WinrmAdapter, WinrmConnect, WinrmSpec, WinrmTuning};
use crate::catalog::install::render::{self, OsRandom, RenderSecrets, VmValues};
use crate::catalog::install::{self, SecretRefKind};
use crate::catalog::templates::Network;
use crate::command_bus::SnapshotOp;
use crate::deploy::install::{self as plan, Flavor};
use crate::deploy::spec::{DeploySource, DeploySpec, DeployVm, InstallSpec};
use crate::deploy::watch::{SerialWatcher, Stage, WatchEvent};
use crate::deploy::{iso, seed, virtualbox as vb, DeployProgress};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::known_hosts::{HostKey, KnownHosts};
use crate::sessions::kinds::{SessionKind, WinrmCertificate, WinrmOptions, WinrmSignIn, WinrmTransport};
use crate::sessions::{SessionAuth, SessionInput};
use crate::vault::{SecretId, SecretString};

/// The most of the serial log read at a time.
const MAX_SERIAL_READ: usize = 256 * 1024;
/// The most of Workstation's DHCP leases file read.
const MAX_LEASES_BYTES: u64 = 4 * 1024 * 1024;
/// What an after-install script may print.
const MAX_SCRIPT_OUTPUT: usize = 64 * 1024;
/// Workstation's line for each reset the guest asks for (S3).
const WORKSTATION_RESET: &str = "requested that the virtual machine be hard reset";
/// VirtualBox's count of the guest's resets (S3), with no Guest Additions needed.
const VBOX_RESET_COUNTER: &str = "/VirtualBox/VMInfo/ResetCounter";

/// What an install needs from the rest of Remotely (set once the core is put together).
#[derive(Clone)]
pub struct InstallTools {
    pub catalog: crate::catalog::Catalog,
    pub winrm: Arc<dyn WinrmAdapter>,
    pub known_hosts: Arc<KnownHosts>,
    /// VM-32: where the addresses of a deploy with a pool are claimed.
    pub pools: Option<Arc<crate::address_pools::AddressPools>>,
}

/// One account whose one-time password (Windows) becomes its vault password once the install is done.
pub(super) struct OneTime {
    account: String,
    password: SecretString,
    vault: SecretId,
}

/// Where an install's CD drives are, to take them out once it is done.
#[derive(Debug, Clone)]
pub(super) enum Drive {
    /// Workstation's slot, `sata0:1`.
    Workstation(String),
    /// VirtualBox's controller and port.
    VirtualBox(String, u32),
}

/// What an install made for one VM.
pub(super) struct InstallMade {
    flavor: Flavor,
    config_name: String,
    /// The VM's own copy of the install ISO (a hard link to the deploy's).
    pub(super) iso: PathBuf,
    pub(super) seed: PathBuf,
    seed_folder: PathBuf,
    pub(super) serial: PathBuf,
    sha256: String,
    one_time: Vec<OneTime>,
    /// The user the config makes (Linux), for the session.
    user: Option<String>,
    pub(super) iso_drive: Option<Drive>,
    pub(super) seed_drive: Option<Drive>,
    /// VirtualBox's NAT: the port on 127.0.0.1 forwarded to the guest's SSH or WinRM port while it is watched.
    pub(super) nat_port: Option<u16>,
}

/// The ISO copies of the deploys running now, by job: the files holding the copy (each VM's hard link), so the next
/// VM links one instead of copying again, and links that couldn't be emptied yet because another VM still reads them.
#[derive(Default)]
pub(super) struct IsoCopies {
    jobs: std::sync::Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<JobIsos>>>>,
}

#[derive(Default)]
struct JobIsos {
    living: Vec<PathBuf>,
    active: usize,
    /// (path, Workstation: an empty disc goes in its place).
    pending: Vec<(PathBuf, bool)>,
}

impl IsoCopies {
    fn job(&self, job_id: Uuid) -> Arc<tokio::sync::Mutex<JobIsos>> {
        let mut jobs = crate::locks::lock(&self.jobs);
        Arc::clone(jobs.entry(job_id).or_default())
    }

    pub(super) async fn enter(&self, job_id: Uuid) {
        self.job(job_id).lock().await.active += 1;
    }

    /// A VM's step ends: the links waiting to be emptied are tried again; the job's entry goes with its last VM.
    pub(super) async fn leave(&self, job_id: Uuid) {
        let job = self.job(job_id);
        let mut state = job.lock().await;
        state.active = state.active.saturating_sub(1);
        let pending = std::mem::take(&mut state.pending);
        for (path, empty_disc) in pending {
            if let Err(err) = empty_link(&path, empty_disc).await {
                tracing::debug!(error = %err, "an install ISO link is still in use");
                state.pending.push((path, empty_disc));
            }
        }
        if state.active == 0 {
            if !state.pending.is_empty() {
                tracing::warn!(
                    left = state.pending.len(),
                    "install ISO copies stay while a VM whose install failed still holds them"
                );
            }
            drop(state);
            crate::locks::lock(&self.jobs).remove(&job_id);
        }
    }

    /// The VM no longer offers its link to the next VM (it is emptied, or its VM failed and is kept).
    async fn forget(&self, job_id: Uuid, path: &Path) {
        let job = self.job(job_id);
        job.lock().await.living.retain(|p| p != path);
    }

    async fn later(&self, job_id: Uuid, path: PathBuf, empty_disc: bool) {
        let job = self.job(job_id);
        job.lock().await.pending.push((path, empty_disc));
    }
}

/// An empty disc (a seed with no files) for Workstation's drives once an install is done: its `.vmx` keeps the
/// drives and connects them at the next power-on, so their files stay, holding nothing.
fn empty_disc() -> Result<Vec<u8>> {
    seed::write_seed(&[], time::OffsetDateTime::now_utc())
}

/// The link out of the way, and on Workstation an empty disc in its place. Fails while another VM reads the copy.
async fn empty_link(path: &Path, empty_disc_after: bool) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    if empty_disc_after {
        tokio::fs::write(path, empty_disc()?).await?;
    }
    Ok(())
}

/// Trusts only the certificate the VM wrote to its own serial port.
struct PinnedCertificate {
    fingerprint: String,
}

#[async_trait::async_trait]
impl HostKeyVerifier for PinnedCertificate {
    async fn verify(&self, key: &HostKey, _jump: Option<&str>) -> Result<()> {
        if key.key_type == CERT_KEY_TYPE && key.fingerprint == self.fingerprint {
            Ok(())
        } else {
            Err(CoreError::Winrm(format!(
                "the VM's WinRM certificate ({}) isn't the one it wrote to its serial port",
                key.fingerprint
            )))
        }
    }
}

/// A free TCP port on 127.0.0.1 for VirtualBox's NAT rule.
fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

/// Whether an SSH server answers at `host:port` (its `SSH-` banner): the installed system is up.
async fn ssh_answers(host: &str, port: u16, wait: Duration) -> bool {
    let Ok(Ok(mut stream)) = tokio::time::timeout(wait, tokio::net::TcpStream::connect((host, port))).await else {
        return false;
    };
    let mut banner = [0u8; 255];
    matches!(tokio::time::timeout(wait, stream.read(&mut banner)).await, Ok(Ok(n)) if n >= 4 && banner.starts_with(b"SSH-"))
}

/// What `path` grew by since `offset` (at most [`MAX_SERIAL_READ`]); a file that shrank was replaced: from its start.
async fn read_new(path: &Path, offset: &mut u64) -> Vec<u8> {
    let Ok(mut file) = tokio::fs::File::open(path).await else {
        return Vec::new();
    };
    let Ok(meta) = file.metadata().await else {
        return Vec::new();
    };
    if meta.len() < *offset {
        *offset = 0;
    }
    if meta.len() == *offset || file.seek(std::io::SeekFrom::Start(*offset)).await.is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let read = (&mut file).take(MAX_SERIAL_READ as u64).read_to_end(&mut out).await;
    if read.is_ok() {
        *offset += out.len() as u64;
    }
    out
}

impl Deployer {
    pub fn set_install_tools(&self, tools: InstallTools) {
        *crate::locks::write(&self.install_tools) = Some(tools);
    }

    /// The WinRM client a deploy signs in to a new Windows VM with (tests give a fake).
    pub fn set_install_winrm(&self, winrm: Arc<dyn WinrmAdapter>) {
        if let Some(tools) = crate::locks::write(&self.install_tools).as_mut() {
            tools.winrm = winrm;
        }
    }

    fn install_tools(&self) -> Result<InstallTools> {
        crate::locks::read(&self.install_tools)
            .clone()
            .ok_or(CoreError::NotImplemented("unattended installs"))
    }

    /// Before the VM is made: its address, its rendered answer file on a seed, and its copy of the ISO.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn prepare_install(
        &self,
        ctx: &Context,
        job_id: Uuid,
        spec: &DeploySpec,
        vm: &DeployVm,
        folder: &Path,
        made: &mut Made,
        progress: &DeployProgress<'_>,
        token: &CancellationToken,
    ) -> Result<()> {
        let (Some(install), DeploySource::Iso { path: source }) = (&spec.install, &spec.source) else {
            return Ok(());
        };
        let tools = self.install_tools()?;
        let flavor = Flavor::of(install.kind).ok_or_else(|| {
            CoreError::InvalidInput(format!(
                "Remotely doesn't deliver {} installs yet.",
                install.kind.label()
            ))
        })?;
        let values = vm
            .install
            .clone()
            .ok_or_else(|| CoreError::InvalidInput(format!("{} has no values for its answer file.", vm.name)))?;
        // What was approved is what runs: the config as it was then, else nothing.
        let config = tools
            .catalog
            .install_config(ctx, &install.config_id.to_string())
            .await?;
        if crate::deploy::spec::config_fingerprint(&config.spec) != install.fingerprint {
            return Err(CoreError::InvalidInput(format!(
                "The install config '{}' changed since the deploy was approved: deploy again.",
                install.config_name
            )));
        }
        // VM-32: the address is the VM's from now on; one taken or answering since the approval refuses.
        if let (Some(pool), Some(ip)) = (&install.pool, &values.ip) {
            let pools = tools.pools.clone().ok_or(CoreError::NotImplemented("address pools"))?;
            let ip: Ipv4Addr = ip
                .parse()
                .map_err(|_| CoreError::InvalidInput(format!("'{ip}' isn't an IPv4 address.")))?;
            pools.claim(ctx, pool.id, ip, &vm.name, job_id).await?;
            made.pool_claim = Some((pool.id, ip));
        }
        progress(1.0, "rendering the answer file");
        let secrets = self.render_secrets(ctx, &config.spec).await?;
        let vm_values = VmValues {
            hostname: vm.hostname.clone(),
            ip: values.ip.clone(),
            n: vm.number,
            template: match &spec.origin {
                crate::deploy::DeployOrigin::Template { name, .. } | crate::deploy::DeployOrigin::Custom { name } => {
                    name.clone()
                }
                _ => vm.name.clone(),
            },
            date: crate::catalog::today(),
            values: values.values.clone(),
        };
        let rendered = render::render(&config.spec, &vm_values, &secrets, &mut OsRandom)?;
        drop(secrets);
        let accounts = install::unattend::password_accounts(&config.spec.body);
        let mut one_time = Vec::new();
        for item in rendered.one_time {
            let account = accounts
                .iter()
                .find(|(name, _)| *name == item.name)
                .map(|(_, account)| account.clone())
                .unwrap_or_else(|| "Administrator".to_owned());
            let vault = config
                .spec
                .secrets
                .iter()
                .find(|s| s.kind == SecretRefKind::Password && s.name == item.name)
                .and_then(|s| s.secret_id)
                .ok_or_else(|| {
                    CoreError::InvalidInput(format!("{{{{password.{}}}}} isn't picked from the vault.", item.name))
                })?;
            one_time.push(OneTime {
                account,
                password: item.password,
                vault,
            });
        }
        let user = install::read_form(install.kind, rendered.text.expose())
            .form
            .users
            .first()
            .map(|u| u.name.clone())
            .filter(|n| !n.contains("{{"));
        // The seed, into a folder only this Windows user can open; the file nowhere else.
        let seed_folder = folder.join(plan::SEED_FOLDER);
        crate::private_folder::make(&seed_folder)?;
        let seed_file = seed_folder.join(format!("{}-seed.iso", vm.name));
        {
            let mut files = plan::seed_files(
                flavor,
                rendered.file_name,
                rendered.text.expose(),
                &format!("iid-remotely-{}", Uuid::new_v4()),
                &vm.hostname,
            );
            let named: Vec<(&str, &[u8])> = files.iter().map(|(n, b)| (*n, b.as_slice())).collect();
            let image = seed::write_seed(&named, time::OffsetDateTime::now_utc()).map(Zeroizing::new);
            drop(named);
            for (_, bytes) in &mut files {
                zeroize::Zeroize::zeroize(bytes);
            }
            tokio::fs::write(&seed_file, image?.as_slice()).await?;
        }
        made.notes.push(format!(
            "answer file from '{}' (SHA-256 {})",
            install.config_name, rendered.sha256
        ));
        let iso_file = folder.join(format!("{}-install.iso", vm.name));
        self.vm_iso(job_id, source, flavor, &iso_file, progress, token).await?;
        let nat_port = match (spec.hypervisor, &spec.network) {
            (Hypervisor::VirtualBox, Some(Network::Nat) | None) => Some(free_port()?),
            _ => None,
        };
        made.install = Some(InstallMade {
            flavor,
            config_name: install.config_name.clone(),
            iso: iso_file,
            seed: seed_file,
            seed_folder,
            serial: folder.join(format!("{}-serial.log", vm.name)),
            sha256: rendered.sha256,
            one_time,
            user,
            iso_drive: None,
            seed_drive: None,
            nat_port,
        });
        Ok(())
    }

    /// The vault's passwords and keys' public halves the config names, by reference name.
    async fn render_secrets(&self, ctx: &Context, config: &install::InstallConfigInput) -> Result<RenderSecrets> {
        let mut secrets = RenderSecrets::default();
        let keys = self.store.ssh_key_rows(ctx).await?;
        for item in &config.secrets {
            let Some(id) = item.secret_id else {
                continue;
            };
            match item.kind {
                SecretRefKind::Password => {
                    secrets
                        .passwords
                        .insert(item.name.clone(), self.vault.get(ctx, id).await?);
                }
                SecretRefKind::SshKey => {
                    let line = keys.get(&id).map(|k| k.public.line.clone()).ok_or_else(|| {
                        CoreError::InvalidInput(format!(
                            "The SSH key for {{{{ssh_key.{}}}}} isn't read yet: unlock the vault once.",
                            item.name
                        ))
                    })?;
                    secrets.ssh_keys.insert(item.name.clone(), line);
                }
            }
        }
        Ok(secrets)
    }

    /// The VM's copy of the install ISO at `target`: a hard link to a copy another VM of this deploy made, else a new
    /// copy of `source` (read only) with its boot menu changed. Other VMs of the deploy wait while one copies.
    async fn vm_iso(
        &self,
        job_id: Uuid,
        source: &str,
        flavor: Flavor,
        target: &Path,
        progress: &DeployProgress<'_>,
        token: &CancellationToken,
    ) -> Result<()> {
        let job = self.isos.job(job_id);
        let mut state = job.lock().await;
        for living in state.living.clone() {
            if tokio::fs::hard_link(&living, target).await.is_ok() {
                state.living.push(target.to_path_buf());
                progress(9.0, "the install ISO's copy linked");
                return Ok(());
            }
        }
        progress(1.0, "checking the install ISO");
        let path = PathBuf::from(source);
        let iso_flavor = flavor.iso();
        let planned = tokio::task::spawn_blocking(move || iso::plan_file(&path, iso_flavor))
            .await
            .map_err(|err| CoreError::InvalidInput(format!("the ISO couldn't be read: {err}")))??;
        let done = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(planned.iso_bytes.max(1)));
        let cancel = Arc::new(AtomicBool::new(false));
        let copy = {
            let (source, target) = (PathBuf::from(source), target.to_path_buf());
            let (done, total, cancel) = (Arc::clone(&done), Arc::clone(&total), Arc::clone(&cancel));
            tokio::task::spawn_blocking(move || {
                iso::make_copy(
                    &source,
                    &target,
                    &planned,
                    &|d, t| {
                        done.store(d, Ordering::Relaxed);
                        total.store(t.max(1), Ordering::Relaxed);
                    },
                    &cancel,
                )
            })
        };
        tokio::pin!(copy);
        let made = loop {
            tokio::select! {
                finished = &mut copy => break finished,
                _ = token.cancelled() => cancel.store(true, Ordering::Relaxed),
                _ = tokio::time::sleep(Duration::from_millis(500)) => {
                    let pct = done.load(Ordering::Relaxed) as f64 / total.load(Ordering::Relaxed) as f64;
                    progress(1.0 + pct * 8.0, &format!("copying the install ISO ({:.0}%)", pct * 100.0));
                }
            }
        };
        made.map_err(|err| CoreError::InvalidInput(format!("the ISO copy stopped: {err}")))??;
        state.living.push(target.to_path_buf());
        progress(9.0, "the install ISO is copied");
        Ok(())
    }

    /// VirtualBox: the serial port to a file, the seed's drive and (NAT) the rule to the guest's port.
    pub(super) async fn virtualbox_install_settings(
        &self,
        uuid: &str,
        (controller, port): (crate::catalog::sizes::DiskController, u32),
        m: &mut InstallMade,
    ) -> Result<()> {
        let name = vb::controller_name(controller).to_owned();
        self.vbox(
            vb::attach_args(uuid, controller, port + 1, true, &m.seed.display().to_string()),
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
                    plan::nat_rule(host_port, m.flavor.port()),
                ],
                SHORT,
            )
            .await?;
        }
        m.iso_drive = Some(Drive::VirtualBox(name.clone(), port));
        m.seed_drive = Some(Drive::VirtualBox(name, port + 1));
        Ok(())
    }

    /// Where the installed system is reached: VirtualBox's NAT rule, the VM's own address (typed or the pool's), a
    /// Workstation DHCP lease by its MAC, or the guest tools' report.
    async fn install_address(
        &self,
        spec: &DeploySpec,
        vm: &DeployVm,
        key: &str,
        m: &InstallMade,
    ) -> Option<(String, u16)> {
        let port = m.flavor.port();
        if let Some(host_port) = m.nat_port {
            return Some((Ipv4Addr::LOCALHOST.to_string(), host_port));
        }
        if let Some(ip) = vm.install.as_ref().and_then(|v| v.ip.clone()) {
            return Some((ip, port));
        }
        let ip = match spec.hypervisor {
            Hypervisor::Vmware => {
                let vmware = self.hypervisors.vmware();
                let lease = match vmware.vmx_bytes(Path::new(key)).await {
                    Ok(bytes) => match plan::vmx_mac(&String::from_utf8_lossy(&bytes)) {
                        Some(mac) => self.lease_for(&mac).await,
                        None => None,
                    },
                    Err(_) => None,
                };
                match lease {
                    Some(ip) => Some(ip),
                    None => vmware.guest_ip(Path::new(key)).await.ok().flatten(),
                }
            }
            Hypervisor::VirtualBox => {
                let vbox = self.hypervisors.virtualbox();
                let props = vbox.guest_properties(key).await.ok()?;
                let info = vbox.vm_info(key).await.ok()?;
                crate::adapters::virtualbox::guest_ip(&props, &info.nics)
            }
        }?;
        Some((ip, port))
    }

    async fn lease_for(&self, mac: &str) -> Option<String> {
        let path = self.tuning().leases_file.clone()?;
        let file = tokio::fs::File::open(&path).await.ok()?;
        let mut text = Vec::new();
        file.take(MAX_LEASES_BYTES).read_to_end(&mut text).await.ok()?;
        plan::dhcp_lease(&String::from_utf8_lossy(&text), mac)
    }

    /// Windows: the guest's resets so far (Setup restarts twice), from Workstation's log or VirtualBox's counter.
    async fn resets(&self, spec: &DeploySpec, key: &str, folder: &Path, log_at: &mut u64, seen: &mut u32) -> u32 {
        match spec.hypervisor {
            Hypervisor::Vmware => {
                let bytes = read_new(&folder.join("vmware.log"), log_at).await;
                *seen += String::from_utf8_lossy(&bytes).matches(WORKSTATION_RESET).count() as u32;
                *seen
            }
            Hypervisor::VirtualBox => {
                let counted = self
                    .hypervisors
                    .virtualbox()
                    .guest_properties(key)
                    .await
                    .ok()
                    .and_then(|p| p.get(VBOX_RESET_COUNTER).and_then(|c| c.trim().parse().ok()));
                if let Some(count) = counted {
                    *seen = (*seen).max(count);
                }
                *seen
            }
        }
    }

    /// Watches the install until the installed system answers (and, on Windows, its one-time password is the vault's),
    /// the install fails, or the time limit passes. The VM stays either way.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn watch_install(
        &self,
        ctx: &Context,
        spec: &DeploySpec,
        install: &InstallSpec,
        vm: &DeployVm,
        key: &str,
        m: &InstallMade,
        notes: &mut Vec<String>,
        progress: &DeployProgress<'_>,
        token: &CancellationToken,
    ) -> Result<Option<(String, u16)>> {
        let tuning = self.tuning();
        let folder = spec.vm_folder(vm);
        let limit = Duration::from_secs(u64::from(install.time_limit_minutes) * 60);
        let limit = tuning.install_cap.map_or(limit, |cap| limit.min(cap));
        let start = tokio::time::Instant::now();
        let deadline = start + limit;
        let mut watcher = SerialWatcher::new(m.flavor.os(), &vm.hostname);
        let mut detail = String::from("starting");
        let report = |events: Vec<WatchEvent>, watcher: &SerialWatcher, detail: &mut String| -> Option<String> {
            let mut failed = None;
            for event in events {
                match event {
                    WatchEvent::Stage(_, d) | WatchEvent::Detail(d) => *detail = d,
                    WatchEvent::LoginPrompt => *detail = "the installed system's login prompt".into(),
                    WatchEvent::Fingerprint(_) => *detail = "WinRM is on".into(),
                    WatchEvent::Failed(why) => failed = Some(why),
                }
            }
            let stage = watcher.stage();
            progress(10.0 + stage.percent() * 0.85, &format!("{}: {}", stage.label(), detail));
            failed
        };
        let events = watcher.started();
        report(events, &watcher, &mut detail);
        let (mut serial_at, mut log_at, mut reset_seen) = (0u64, 0u64, 0u32);
        let mut last_growth = tokio::time::Instant::now();
        let mut hang_resets = 0u32;
        let mut login_at: Option<tokio::time::Instant> = None;
        loop {
            if token.is_cancelled() {
                return Err(CoreError::Cancelled);
            }
            let bytes = read_new(&m.serial, &mut serial_at).await;
            if !bytes.is_empty() {
                last_growth = tokio::time::Instant::now();
            }
            let events = watcher.feed(&bytes);
            if let Some(why) = report(events, &watcher, &mut detail) {
                return Err(self.install_failed(spec, vm, key, m, watcher.stage(), &why).await);
            }
            if m.flavor.windows() {
                let count = self.resets(spec, key, &folder, &mut log_at, &mut reset_seen).await;
                let events = watcher.resets(count);
                report(events, &watcher, &mut detail);
            }
            // VirtualBox under Hyper-V (S1, S2): a silent port at a known point is a hang a reset gets past.
            if spec.hypervisor == Hypervisor::VirtualBox
                && watcher.hang_point().is_some()
                && last_growth.elapsed() >= tuning.hang_silence
                && hang_resets < tuning.max_hang_resets
            {
                let point = watcher.hang_point().unwrap_or_default();
                if self
                    .vbox(vec!["controlvm".into(), key.into(), "reset".into()], SHORT)
                    .await
                    .is_ok()
                {
                    hang_resets += 1;
                    notes.push(format!("reset once it hung at {point} (VirtualBox under Hyper-V)"));
                }
                last_growth = tokio::time::Instant::now();
            }
            if watcher.login_seen() && login_at.is_none() {
                login_at = Some(tokio::time::Instant::now());
            }
            let ready = if m.flavor.windows() {
                watcher.fingerprint().is_some()
            } else {
                watcher.login_seen()
            };
            if ready {
                match self.install_address(spec, vm, key, m).await {
                    Some((host, port)) if m.flavor.windows() => {
                        let fingerprint = watcher.fingerprint().unwrap_or_default().to_owned();
                        report(watcher.signing_in("WinRM over HTTPS"), &watcher, &mut detail);
                        let (probe_host, probe_port) = match &tuning.probe {
                            Some((h, _, winrm)) => (h.clone(), *winrm),
                            None => (host.clone(), port),
                        };
                        match self
                            .windows_first_sign_in(ctx, spec, vm, m, &probe_host, probe_port, &fingerprint)
                            .await
                        {
                            Err(err @ CoreError::InstallFailed { .. }) => return Err(err),
                            Ok(note) => {
                                notes.push(note);
                                report(watcher.done("installed"), &watcher, &mut detail);
                                return Ok(Some((host, port)));
                            }
                            Err(CoreError::AuthFailed(why)) => {
                                return Err(self
                                    .install_failed(
                                        spec,
                                        vm,
                                        key,
                                        m,
                                        watcher.stage(),
                                        &format!("Windows refused the sign-in: {why}"),
                                    )
                                    .await)
                            }
                            Err(err) => tracing::debug!(error = %err, "WinRM isn't ready yet"),
                        }
                    }
                    Some((host, port)) => {
                        report(watcher.signing_in("SSH"), &watcher, &mut detail);
                        let (probe_host, probe_port) = match &tuning.probe {
                            Some((h, ssh, _)) => (h.clone(), *ssh),
                            None => (host.clone(), port),
                        };
                        if ssh_answers(&probe_host, probe_port, tuning.connect_wait).await {
                            report(watcher.done("installed"), &watcher, &mut detail);
                            return Ok(Some((host, port)));
                        }
                    }
                    None if !m.flavor.windows()
                        && login_at
                            .is_some_and(|at| at.elapsed() >= Duration::from_secs(u64::from(spec.ip_wait_secs))) =>
                    {
                        notes.push(format!(
                            "its login prompt showed, but no address did within {} minutes ({} report none): find it in the guest",
                            spec.ip_wait_secs.div_ceil(60),
                            spec.hypervisor.tools_name()
                        ));
                        report(watcher.done("installed"), &watcher, &mut detail);
                        return Ok(None);
                    }
                    None => {}
                }
            }
            if tokio::time::Instant::now() >= deadline {
                let why = format!(
                    "not done within {} minutes (it was at: {}, {})",
                    limit.as_secs().div_ceil(60),
                    watcher.stage().label(),
                    detail
                );
                return Err(self.install_failed(spec, vm, key, m, watcher.stage(), &why).await);
            }
            tokio::select! {
                _ = token.cancelled() => return Err(CoreError::Cancelled),
                _ = tokio::time::sleep(tuning.install_poll) => {}
            }
        }
    }

    /// The install failed: a screenshot where the hypervisor takes one (VirtualBox), and the error, which says the
    /// VM is kept for a look.
    async fn install_failed(
        &self,
        spec: &DeploySpec,
        vm: &DeployVm,
        key: &str,
        m: &InstallMade,
        stage: Stage,
        why: &str,
    ) -> CoreError {
        let mut message = format!("the install failed ({}): {why}", stage.label());
        if spec.hypervisor == Hypervisor::VirtualBox {
            if let Ok(png) = self.hypervisors.virtualbox().screenshot(key).await {
                let file = spec.vm_folder(vm).join(format!("{}-install-failed.png", vm.name));
                if tokio::fs::write(&file, png).await.is_ok() {
                    message.push_str(&format!("; its screen is in {}", file.display()));
                }
            }
        }
        message.push_str(&format!(
            "; the VM is kept as it is for a look (its serial log is {}): delete it from the VMs page when done",
            m.serial.display()
        ));
        CoreError::InstallFailed {
            vm: vm.name.clone(),
            message,
        }
    }

    /// Windows (S3): WinRM over HTTPS with the certificate the VM wrote to COM1 and the one-time password; each
    /// account's password set to the vault's (the script on stdin); then, signed in with the vault's, the autologon
    /// session signed out and Setup's copy of the answer file deleted.
    #[allow(clippy::too_many_arguments)]
    async fn windows_first_sign_in(
        &self,
        ctx: &Context,
        spec: &DeploySpec,
        vm: &DeployVm,
        m: &InstallMade,
        host: &str,
        port: u16,
        fingerprint: &str,
    ) -> Result<String> {
        let tools = self.install_tools()?;
        let first = m
            .one_time
            .first()
            .ok_or_else(|| CoreError::InvalidInput("The answer file gives no account a password.".into()))?;
        let connect = |account: &str, password: SecretString| {
            let winrm_spec = WinrmSpec {
                id: Uuid::new_v4(),
                name: vm.name.clone(),
                host: host.to_owned(),
                port,
                username: Some(account.to_owned()),
                password_id: None,
                options: WinrmOptions {
                    transport: WinrmTransport::Https,
                    sign_in: WinrmSignIn::Ntlm,
                    certificate: WinrmCertificate::Fingerprint,
                },
                environment: spec.environment,
            };
            let tools = tools.clone();
            let verifier: Arc<dyn HostKeyVerifier> = Arc::new(PinnedCertificate {
                fingerprint: fingerprint.to_owned(),
            });
            async move {
                tools
                    .winrm
                    .connect(WinrmConnect {
                        spec: &winrm_spec,
                        password: Some(password),
                        verifier,
                        tuning: WinrmTuning::default(),
                    })
                    .await
            }
        };
        let session = connect(&first.account, first.password.clone()).await?;
        for one in &m.one_time {
            let password = self.vault.get(ctx, one.vault).await?;
            let script = Zeroizing::new(plan::set_password_script(&one.account, password.expose()));
            drop(password);
            let ran = session.run(&script, MAX_SCRIPT_OUTPUT).await;
            drop(script);
            match ran {
                Ok(result) if result.exit_code == Some(0) => {}
                Ok(_) | Err(_) => {
                    session.close().await;
                    return Err(CoreError::InstallFailed {
                        vm: vm.name.clone(),
                        message: format!(
                            "{}'s password couldn't be set to the vault's over WinRM; it is still the one-time password only this deploy knew, so deploy the VM again",
                            one.account
                        ),
                    });
                }
            }
        }
        session.close().await;
        let vault_password = self.vault.get(ctx, first.vault).await?;
        let session = connect(&first.account, vault_password).await?;
        let after = session.run(plan::AFTER_INSTALL_SCRIPT, MAX_SCRIPT_OUTPUT).await;
        session.close().await;
        let mut note = format!(
            "WinRM over HTTPS answers with the certificate it wrote to its serial port ({fingerprint}); {} password{} set to the vault's",
            m.one_time.iter().map(|o| o.account.as_str()).collect::<Vec<_>>().join(", "),
            if m.one_time.len() == 1 { "" } else { "s" }
        );
        match after {
            Ok(result) => {
                let out = result.output.stdout;
                if let Some(hash) = out.lines().find_map(|l| l.trim().strip_prefix("answer-file ")) {
                    if hash.trim().eq_ignore_ascii_case(&m.sha256) {
                        note.push_str("; Setup read this deploy's answer file, and its copy in Panther is deleted");
                    } else {
                        note.push_str(
                            "; Setup's copy of an answer file in Panther is deleted (not this deploy's file)",
                        );
                    }
                }
                if out.lines().any(|l| l.trim().starts_with("signed-out ")) {
                    note.push_str("; the autologon session is signed out");
                }
            }
            Err(err) => note.push_str(&format!("; the after-install script didn't run ({err})")),
        }
        Ok(note)
    }

    /// Once the install is done: the ISO and the seed out of the VM (Workstation keeps its drives with empty discs,
    /// VirtualBox's are emptied), VirtualBox's NAT rule gone, the "clean install" snapshot, and the session.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn finish_install(
        &self,
        ctx: &Context,
        job_id: Uuid,
        spec: &DeploySpec,
        vm: &DeployVm,
        key: &str,
        m: &InstallMade,
        address: Option<(String, u16)>,
        notes: &mut Vec<String>,
    ) {
        let mut out: Vec<String> = Vec::new();
        self.isos.forget(job_id, &m.iso).await;
        let mut cds_out = true;
        for (drive, file) in [(&m.iso_drive, &m.iso), (&m.seed_drive, &m.seed)] {
            let Some(drive) = drive else { continue };
            let ejected = match drive {
                Drive::Workstation(slot) => self
                    .hypervisors
                    .vmware()
                    .vmrun_change(vec!["disconnectNamedDevice".into(), key.into(), slot.into()], SHORT)
                    .await
                    .map(drop),
                Drive::VirtualBox(controller, port) => {
                    let out = self
                        .vbox(vb::attach_named(key, controller, *port, 0, true, "emptydrive"), SHORT)
                        .await;
                    let _ = self
                        .vbox(
                            vec!["closemedium".into(), "dvd".into(), file.display().to_string()],
                            SHORT,
                        )
                        .await;
                    out.map(drop)
                }
            };
            if let Err(err) = ejected {
                cds_out = false;
                out.push(format!("{} is still in its drive ({err})", file.display()));
            }
        }
        let workstation = spec.hypervisor == Hypervisor::Vmware;
        // The seed (with the answer file's hashes) goes now; Workstation's drive keeps an empty disc.
        if let Err(err) = empty_link(&m.seed, workstation).await {
            out.push(format!(
                "the seed {} couldn't be emptied ({err}): delete it",
                m.seed.display()
            ));
        } else if !workstation {
            let _ = tokio::fs::remove_dir(&m.seed_folder).await;
        }
        if cds_out {
            if empty_link(&m.iso, workstation).await.is_err() {
                // Another VM of the deploy still installs from the same copy: emptied once it is done.
                self.isos.later(job_id, m.iso.clone(), workstation).await;
            }
            out.push(if workstation {
                "the install ISO and the seed are out (their drives keep empty discs: remove them in Settings when the VM is off)".into()
            } else {
                "the install ISO and the seed are ejected and deleted".into()
            });
        }
        if let Some(_port) = m.nat_port {
            match self
                .vbox(
                    vec![
                        "controlvm".into(),
                        key.into(),
                        "natpf1".into(),
                        "delete".into(),
                        plan::NAT_RULE.into(),
                    ],
                    SHORT,
                )
                .await
            {
                Ok(_) => out.push("the NAT rule to its port is gone".into()),
                Err(err) => out.push(format!("its NAT rule {} stays ({err})", plan::NAT_RULE)),
            }
        }
        if spec.after_deploy.clean_snapshot {
            match self
                .hypervisors
                .snapshot(
                    key,
                    &SnapshotOp::Take {
                        name: plan::CLEAN_INSTALL_SNAPSHOT_NAME.into(),
                    },
                )
                .await
            {
                Ok(()) => out.push(format!("snapshot '{}' taken", plan::CLEAN_INSTALL_SNAPSHOT_NAME)),
                Err(err) => out.push(format!(
                    "the '{}' snapshot wasn't taken: {err}",
                    plan::CLEAN_INSTALL_SNAPSHOT_NAME
                )),
            }
        }
        if spec.after_deploy.create_session {
            match (&address, m.nat_port) {
                (_, Some(_)) => {
                    out.push("no session: on VirtualBox's NAT the guest can't be reached from this PC".into())
                }
                (None, _) => out.push("no session: its address isn't known".into()),
                (Some((host, port)), None) if m.flavor.windows() => {
                    out.push(self.winrm_session(ctx, spec, vm, key, m, host, *port).await);
                }
                (Some((host, _)), None) => {
                    out.push(self.make_session(ctx, spec, vm, key, host, m.user.clone()).await);
                }
            }
        }
        if spec.after_deploy.open_console {
            let opened = match spec.hypervisor {
                Hypervisor::Vmware => self.hypervisors.vmware().open_console(Path::new(key)).await,
                Hypervisor::VirtualBox => self.hypervisors.virtualbox().open_console(key).await,
            };
            out.push(match opened {
                Ok(()) => "console opened".into(),
                Err(err) => format!("the console didn't open: {err}"),
            });
        }
        let _ = &m.config_name;
        notes.extend(out);
    }

    /// The WinRM session to the new VM, its certificate trusted as the VM wrote it, with the vault's password when no
    /// approval is needed to send it there now (else without, and the note says so).
    #[allow(clippy::too_many_arguments)]
    async fn winrm_session(
        &self,
        ctx: &Context,
        spec: &DeploySpec,
        vm: &DeployVm,
        key: &str,
        m: &InstallMade,
        host: &str,
        port: u16,
    ) -> String {
        let Some(first) = m.one_time.first() else {
            return "no session: the answer file gives no account a password".into();
        };
        let Ok(tools) = self.install_tools() else {
            return "no session".into();
        };
        let vm_id = if spec.after_deploy.link_session {
            self.store.find_vm(ctx, key).await.ok().flatten().map(|r| r.id)
        } else {
            None
        };
        // The fingerprint came from the VM's own serial port; trusted for the saved session's host and port.
        let read = self.read_fingerprint(&m.serial).await;
        if let Some(fingerprint) = read {
            let trusted = tools
                .known_hosts
                .trust(
                    ctx,
                    &HostKey {
                        host: host.to_owned(),
                        port,
                        key_type: CERT_KEY_TYPE.into(),
                        fingerprint,
                    },
                    None,
                )
                .await;
            if let Err(err) = trusted {
                tracing::warn!(error = %err, "the new VM's WinRM certificate couldn't be trusted");
            }
        }
        let input = SessionInput {
            name: vm.name.clone(),
            folder_id: None,
            host: host.to_owned(),
            port,
            username: Some(first.account.clone()),
            auth: SessionAuth::Password {
                password_id: Some(first.vault),
            },
            jump_session_id: None,
            jump_direct: true,
            startup_command: None,
            startup_on_reconnect: false,
            prompt_hook: None,
            environment: spec.environment,
            color: None,
            tags: spec.tags.clone(),
            vm_id,
            kind: SessionKind::Winrm(WinrmOptions {
                transport: WinrmTransport::Https,
                sign_in: WinrmSignIn::Ntlm,
                certificate: WinrmCertificate::Fingerprint,
            }),
        };
        let without = SessionInput {
            auth: SessionAuth::Password { password_id: None },
            ..input.clone()
        };
        match self.sessions.create(ctx, input).await {
            Ok(session) => format!("WinRM session '{}' made", session.name),
            Err(CoreError::ReauthRequired { .. }) => match self.sessions.create(ctx, without).await {
                Ok(session) => format!(
                    "WinRM session '{}' made without its password (sending the vault's there needs the vault password): pick it in the session",
                    session.name
                ),
                Err(err) => format!("the WinRM session wasn't made: {err}"),
            },
            Err(err) => format!("the WinRM session wasn't made: {err}"),
        }
    }

    async fn read_fingerprint(&self, serial: &Path) -> Option<String> {
        let mut at = 0u64;
        let mut watcher = SerialWatcher::new(crate::deploy::watch::Os::Windows, "");
        loop {
            let bytes = read_new(serial, &mut at).await;
            if bytes.is_empty() {
                return watcher.fingerprint().map(str::to_owned);
            }
            watcher.feed(&bytes);
            if let Some(found) = watcher.fingerprint() {
                return Some(found.to_owned());
            }
        }
    }

    /// The VM's link to the ISO copy isn't offered to the next VM any more.
    pub(super) async fn isos_forget(&self, job_id: Uuid, m: &InstallMade) {
        self.isos.forget(job_id, &m.iso).await;
    }

    /// A step that failed before its VM was made gives its address back.
    pub(super) async fn release_claim(&self, ctx: &Context, made: &Made) {
        if let (Some((pool, ip)), Ok(tools)) = (made.pool_claim, self.install_tools()) {
            if let Some(pools) = tools.pools {
                if let Err(err) = pools.release(ctx, pool, ip).await {
                    tracing::warn!(error = %err, "deploy cleanup: an address couldn't go back to its pool");
                }
            }
        }
    }

    /// The VM keeps its address once it is made.
    pub(super) async fn assign_claim(&self, ctx: &Context, made: &Made, key: &str) {
        if let (Some((pool, ip)), Ok(tools)) = (made.pool_claim, self.install_tools()) {
            if let Some(pools) = tools.pools {
                if let Err(err) = pools.assign(ctx, pool, ip, key).await {
                    tracing::warn!(error = %err, "an address couldn't be recorded as the new VM's");
                }
            }
        }
    }
}
