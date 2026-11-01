//! FD-04: support bundles. One job (`Command::SupportBundle` on the bus) collects the same commands' output and files
//! from many hosts into one zip: `remotely-bundle-<workspace>-<UTC time>.zip`, a folder per host and a
//! `manifest.json` with every command, exit code, size, SHA-256 and what was redacted or cut.
//!
//! * Hosts are BX-01's targets (saved sessions; a VM only through a chosen or confirmed link), picked in the UI.
//!   SS-12: SSH sessions only ([`HOSTS_NEED`]); an RDP, VNC, Telnet or serial session is refused, named.
//! * What is collected: presets ([`presets`]: System, Logs, Containers, Network) and custom commands and files, all
//!   expanded into the spec before the bus rates it, so what is approved is what runs ([`spec::BundleSpec`]).
//! * The policy engine rates the commands as in Compare hosts: the presets only read, so they are Low (Medium on
//!   Prod); a custom command that changes something or is dangerous rates the bundle as such. Files are read over
//!   SFTP as the login user, never with sudo; commands run with sudo through BX-07 when asked.
//! * BX-02's parallelism and H9's rollout options apply as to a Compare hosts run.
//! * The zip's place comes from the shell's save dialog (never the UI: `Command::check_from_ui`), never in a Git
//!   working tree; it is written as hosts give their files and takes its name at the end ([`writer`]).
//! * Caps, scrubbing and redaction: [`collect`]. The job's end audits `data_exported`.
//! * F8 adds Windows hosts: a [`collect::BundleHost`] over WinRM and presets of [`presets::HostKind`] Windows.

pub mod collect;
pub mod presets;
pub mod runner;
pub mod spec;
pub mod writer;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use collect::{BundleHost, FileRead, HostReport, ItemLimits, SshHost};
pub use presets::{HostKind, PresetId, PresetView};
pub use runner::{BundleActions, BundleRunner};
pub use spec::{BundleItem, BundleSpec, MAX_BUNDLE_BYTES, MAX_FILE_BYTES, MAX_HOST_BYTES, MAX_ITEMS};

use crate::command_bus::{Command, CommandBus, CommandPreview, Rollout, SubmitOutcome};
use crate::domain::{Context, TargetRef};
use crate::error::{CoreError, Result};
use crate::save_guard::{self, Saved};
use crate::store::Store;
use crate::vault::SecretId;

/// SS-12: why a session of another kind can't be a host: "'console' is a Telnet session, and <this>". F8 widens the
/// rule for WinRM sessions.
pub const HOSTS_NEED: &str = "a support bundle collects from SSH sessions only";

/// What the dialog asks for: the hosts (sessions BX-01 resolved), presets, custom commands and files, and how to run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BundleRequest {
    pub session_ids: Vec<Uuid>,
    pub presets: Vec<PresetId>,
    /// One command each; blank ones are left out.
    pub commands: Vec<String>,
    /// Full paths on the hosts; blank ones are left out.
    pub files: Vec<String>,
    pub sudo: bool,
    pub sudo_password_id: Option<SecretId>,
    pub trust_new_host_keys: bool,
    pub timeout_secs: Option<u64>,
    pub rollout: Rollout,
}

/// The caps, for the dialog's words.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleLimits {
    pub file_bytes: u64,
    pub host_bytes: u64,
    pub bundle_bytes: u64,
    pub max_items: usize,
}

pub const LIMITS: BundleLimits = BundleLimits {
    file_bytes: MAX_FILE_BYTES,
    host_bytes: MAX_HOST_BYTES,
    bundle_bytes: MAX_BUNDLE_BYTES,
    max_items: MAX_ITEMS,
};

/// FD-04: the dialog's side of support bundles (`Core.bundles`). Running is the bus.
#[derive(Clone)]
pub struct SupportBundles {
    store: Store,
    bus: Arc<CommandBus>,
}

impl SupportBundles {
    pub fn new(store: Store, bus: Arc<CommandBus>) -> Self {
        Self { store, bus }
    }

    pub fn presets(&self) -> Vec<PresetView> {
        presets::views()
    }

    /// The shown workspace's name.
    async fn workspace_name(&self, ctx: &Context) -> Result<String> {
        Ok(self
            .store
            .workspace(ctx.user_id, ctx.workspace_id)
            .await?
            .map(|w| w.name)
            .unwrap_or_default())
    }

    /// The zip's name the save dialog offers: `remotely-bundle-<workspace>-<UTC time>.zip`.
    pub async fn default_file_name(&self, ctx: &Context) -> Result<String> {
        Ok(spec::default_file_name(
            &self.workspace_name(ctx).await?,
            time::OffsetDateTime::now_utc(),
        ))
    }

    /// The command the request becomes, saving to `output`.
    async fn command(&self, ctx: &Context, request: &BundleRequest, output: &Path) -> Result<Command> {
        // SS-12: refused before the bus rates anything. The job's login refuses one again (`Store::session_spec`)
        // if a session changed kind after the approval.
        let sessions = self.store.list_sessions(ctx).await?;
        for session in sessions.iter().filter(|s| request.session_ids.contains(&s.id)) {
            session.require_ssh(HOSTS_NEED)?;
        }
        let mut presets = request.presets.clone();
        presets.sort();
        presets.dedup();
        let spec = BundleSpec {
            items: presets::expand(&presets, &request.commands, &request.files),
            presets,
            sudo: request.sudo,
            sudo_password_id: request.sudo.then_some(request.sudo_password_id).flatten(),
            trust_new_host_keys: request.trust_new_host_keys,
            timeout_secs: request.timeout_secs,
            rollout: request.rollout,
            output: output.display().to_string(),
            workspace: self.workspace_name(ctx).await?,
        };
        let targets: Vec<TargetRef> = request
            .session_ids
            .iter()
            .map(|id| TargetRef::Session { session_id: *id })
            .collect();
        Ok(Command::SupportBundle {
            targets,
            spec: Box::new(spec),
        })
    }

    /// The tier and steps the bundle would get now, and the dangerous-command rules its commands match. A read.
    pub async fn preview(&self, ctx: &Context, request: &BundleRequest) -> Result<CommandPreview> {
        let command = self.command(ctx, request, Path::new("bundle.zip")).await?;
        self.bus.preview(ctx, &command).await
    }

    /// What the dialog asked for is complete, before the save dialog opens: hosts, something to collect, nothing
    /// refused, and the read-only lock off.
    pub async fn check(&self, ctx: &Context, request: &BundleRequest) -> Result<()> {
        crate::policy::read_only_refusal(
            self.bus.read_only().is_locked(),
            crate::policy::ActionKind::ExecReadOnly,
        )?;
        if request.session_ids.is_empty() {
            return Err(CoreError::NoTargets);
        }
        let output = std::env::temp_dir().join("bundle.zip");
        let command = self.command(ctx, request, &output).await?;
        command.validate()
    }

    /// Submits the bundle, saving to `output` (the shell's save dialog chose it; never in a Git working tree).
    pub async fn submit(&self, ctx: &Context, request: &BundleRequest, output: &Path) -> Result<SubmitOutcome> {
        save_guard::refuse_repository(output, Saved::Bundle)?;
        if !output.parent().is_some_and(Path::is_dir) {
            return Err(CoreError::InvalidInput(format!(
                "The folder of {} is not there.",
                output.display()
            )));
        }
        let command = self.command(ctx, request, output).await?;
        self.bus.submit(ctx, command).await
    }

    /// Where a finished bundle of the shown workspace was saved, if it is still there (Show folder).
    pub async fn saved_at(&self, ctx: &Context, job_id: Uuid) -> Result<PathBuf> {
        let (job, command) = self
            .store
            .job_detail(ctx, job_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("job {job_id}")))?;
        let Command::SupportBundle { spec, .. } = command else {
            return Err(CoreError::InvalidInput("That job is not a support bundle.".into()));
        };
        if job.is_open() {
            return Err(CoreError::InvalidInput("The bundle is still being collected.".into()));
        }
        let path = PathBuf::from(&spec.output);
        if !path.is_file() {
            return Err(CoreError::InvalidInput(format!(
                "{} is not there: the job saved no bundle, or it was moved or deleted since.",
                path.display()
            )));
        }
        Ok(path)
    }
}
