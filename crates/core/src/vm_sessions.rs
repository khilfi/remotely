//! QL-29: an SSH session made from a VM, for a VM that has none linked: one from the VM panel or the command
//! palette (the session editor opens filled in from [`Core::vm_session_drafts`]), or many from the VMs page's
//! selection ([`Core::create_vm_sessions`] saves them together after a preview).
//!
//! A draft is the VM's display name, the guest address its hypervisor reports, port 22, no folder and no jump host
//! (the VM is on this PC's own network, as the deploy's own session), the VM's environment and tags, and a link to
//! the VM made by hand (QL-01: [`crate::sessions::SessionLibrary::create`] marks a session saved with its `vm_id`
//! linked manually, since the user chose it). The user and key come from the deploy that made the VM, when Remotely made it: the
//! newest deploy or stack deploy in this workspace's job journal whose VM folder holds the VM's settings file
//! (`.vmx`, or `.vbox` for VirtualBox), so VMs deployed before this change get them too (the journal keeps a
//! deploy's spec; retention purges only scripts, typed lines and bundles' items). The user is picked as the deploy
//! picks it ([`crate::deploy::runner::session_user`]); the install config's user only while the config is the one
//! approved (its fingerprint), and never for a Windows answer file. A key the vault no longer has is left out, with
//! a note. A VM Remotely didn't make leaves the user and key for the user to fill in.
//!
//! A VM gets no draft (the reason says why) when it has an SSH session linked already, isn't running, has no guest
//! address (VMware Tools, open-vm-tools on a Linux guest, or VirtualBox's Guest Additions report it), or is only on
//! VirtualBox's NAT, which this PC can't reach.
//!
//! The app's own data (rule 3 for the reads; saving is a session edit: no tier, audited, refused by the read-only
//! lock). Rule 8: the VMs are read in the shown workspace and each is checked with [`Store::require_vm_here`]; the
//! bulk save takes only VM ids from the window and works every draft out again.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Serialize;
use uuid::Uuid;

use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::vm_hardware::VmHardware;
use crate::catalog::install::InstallKind;
use crate::catalog::templates::Network;
use crate::command_bus::Command;
use crate::deploy::runner::{session_auth, session_user};
use crate::deploy::spec::{config_fingerprint, DeploySpec};
use crate::domain::{Context, Environment, PowerState};
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::sessions::{SessionAuth, SessionInput, SessionKind};
use crate::stacks::StackOp;
use crate::store::{Store, VmRecord};
use crate::Core;

/// The deploy's note when it couldn't make a VM's session for want of its address.
pub const MAKE_IT_LATER: &str = "once its address shows, Create SSH session on the VM makes it";

/// Most VMs one call works on (the VMs page's selection).
pub const MAX_VMS: usize = 200;

/// How many of the workspace's newest deploy and stack jobs are searched for the deploy that made a VM.
const DEPLOY_JOBS: u32 = 500;

/// One VM's session as it would be made, or why none can be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmSessionDraft {
    pub vm_id: String,
    /// The VM's display name (its id when the VM isn't listed in this workspace).
    pub vm_name: String,
    /// The session to save; `None` when `refused` says why there is none.
    pub session: Option<SessionDraft>,
    pub refused: Option<String>,
    /// Where the user and key came from, a key left out, a session to the same address already saved.
    pub notes: Vec<String>,
}

/// The fields a draft fills in; the rest are a new session's defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDraft {
    pub name: String,
    pub host: String,
    pub port: u16,
    /// `None`: not known (the terminal asks when it connects).
    pub username: Option<String>,
    /// The deploy's key, else a password asked when connecting.
    pub auth: SessionAuth,
    pub environment: Environment,
    pub tags: Vec<String>,
    /// The VM, linked by hand once saved.
    pub vm_id: String,
    /// How the deploy that made the VM was described ("launch template 'web'"), when one did.
    pub deploy: Option<String>,
}

impl SessionDraft {
    fn into_input(self) -> SessionInput {
        SessionInput {
            name: self.name,
            folder_id: None,
            host: self.host,
            port: self.port,
            username: self.username,
            auth: self.auth,
            jump_session_id: None,
            // The VM is on this PC's own network: no jump host, whatever a folder says.
            jump_direct: true,
            startup_command: None,
            startup_on_reconnect: false,
            prompt_hook: None,
            environment: self.environment,
            color: None,
            tags: self.tags,
            vm_id: Some(self.vm_id),
            kind: SessionKind::Ssh,
        }
    }
}

/// What the bulk save did for one VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmSessionMade {
    pub vm_id: String,
    pub vm_name: String,
    /// The saved session's id and name.
    pub session_id: Option<Uuid>,
    pub session_name: Option<String>,
    /// Why no session was saved (the draft's refusal, or the save's error).
    pub error: Option<String>,
}

/// What a deploy says about the session of one VM it made.
struct FromDeploy {
    spec: DeploySpec,
    /// The deploy's description, for the draft.
    describe: String,
}

impl Core {
    /// QL-29: each VM's session as it would be made, in the order asked (a VM asked twice once). A read.
    pub async fn vm_session_drafts(&self, vm_ids: &[String]) -> Result<Vec<VmSessionDraft>> {
        let ctx = self.ctx();
        self.drafts(&ctx, vm_ids).await
    }

    /// QL-29: saves the session of each VM that gets one, together, as [`crate::sessions::SessionLibrary::create`]
    /// saves any (audited one by one, linked to its VM by hand). Every draft is worked out again here; a VM that gets
    /// none is reported with the reason and nothing is saved for it.
    pub async fn create_vm_sessions(&self, vm_ids: &[String]) -> Result<Vec<VmSessionMade>> {
        self.store.read_only().check(Change::Sessions)?;
        let ctx = self.ctx();
        let drafts = self.drafts(&ctx, vm_ids).await?;
        let mut made = Vec::with_capacity(drafts.len());
        for draft in drafts {
            let mut out = VmSessionMade {
                vm_id: draft.vm_id,
                vm_name: draft.vm_name,
                session_id: None,
                session_name: None,
                error: draft.refused,
            };
            if let Some(session) = draft.session {
                match self.sessions.create(&ctx, session.into_input()).await {
                    Ok(saved) => {
                        out.session_id = Some(saved.id);
                        out.session_name = Some(saved.name);
                    }
                    // The lock may have come on since; nothing after it saves either.
                    Err(err @ CoreError::ReadOnlyLock { .. }) => return Err(err),
                    Err(err) => out.error = Some(err.to_string()),
                }
            }
            made.push(out);
        }
        Ok(made)
    }

    async fn drafts(&self, ctx: &Context, vm_ids: &[String]) -> Result<Vec<VmSessionDraft>> {
        let mut ids: Vec<&str> = Vec::with_capacity(vm_ids.len());
        for id in vm_ids {
            if !ids.contains(&id.as_str()) {
                ids.push(id);
            }
        }
        if ids.is_empty() {
            return Err(CoreError::InvalidInput("Pick at least one VM.".into()));
        }
        if ids.len() > MAX_VMS {
            return Err(CoreError::InvalidInput(format!(
                "Make sessions for at most {MAX_VMS} VMs at a time."
            )));
        }
        let sessions = self.store.list_sessions(ctx).await?;
        // The vault's private keys (listed while it is locked too), whether or not their public half is known.
        let keys: HashSet<_> = self.keys.list(ctx).await?.into_iter().map(|k| k.id).collect();
        // Read once for every VM asked; only when one gets a draft.
        let mut deploys: Option<Vec<DeploySpec>> = None;
        let mut hardware: Option<HashMap<String, VmHardware>> = None;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(vm) = self.store.vm_by_id(ctx, id).await? else {
                out.push(refused(id, id, "this VM isn't in this workspace's list".into()));
                continue;
            };
            // Rule 8: another workspace's VM, or one no workspace has, is refused by name.
            if let Err(err) = self.store.require_vm_here(ctx, &vm.vmx_path).await {
                out.push(refused(id, &vm.display_name, err.to_string()));
                continue;
            }
            let linked = sessions
                .iter()
                .filter(|s| s.vm_id.as_deref() == Some(vm.id.as_str()) && matches!(s.kind, SessionKind::Ssh))
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>();
            if let Some(first) = linked.first() {
                out.push(refused(
                    id,
                    &vm.display_name,
                    format!("it has an SSH session already: '{first}'"),
                ));
                continue;
            }
            if vm.power_state != PowerState::Running {
                out.push(refused(
                    id,
                    &vm.display_name,
                    "it isn't running: start it, and its address shows once the guest is up".into(),
                ));
                continue;
            }
            let Some(ip) = vm.ip_address.clone().filter(|ip| !ip.trim().is_empty()) else {
                out.push(refused(id, &vm.display_name, no_address(&vm)));
                continue;
            };
            let found = match &deploys {
                Some(specs) => from_deploy(specs, &vm),
                None => {
                    let specs = self.deploy_specs(ctx).await?;
                    let found = from_deploy(&specs, &vm);
                    deploys = Some(specs);
                    found
                }
            };
            if vm.hypervisor == Hypervisor::VirtualBox {
                if hardware.is_none() {
                    hardware = Some(stored_hardware(&self.store, ctx).await?);
                }
                let nics = hardware.as_ref().and_then(|h| h.get(&vm.id)).map(|h| h.nics.as_slice());
                if let Some(reason) = virtualbox_nat(nics, found.as_ref().map(|f| &f.spec)) {
                    out.push(refused(id, &vm.display_name, reason.into()));
                    continue;
                }
            }
            let mut notes = Vec::new();
            let (username, auth, deploy) = match found {
                Some(found) => {
                    let install_user = self.install_user(ctx, &found.spec).await;
                    let username = session_user(&found.spec, install_user);
                    let mut auth = session_auth(&found.spec);
                    if let SessionAuth::Key { key_id: Some(key), .. } = &auth {
                        if !keys.contains(key) {
                            notes.push("the deploy's SSH key is no longer in the vault: pick a login".into());
                            auth = SessionAuth::Password { password_id: None };
                        }
                    }
                    notes.push(format!("the user and login come from the deploy of {}", found.describe));
                    (username, auth, Some(found.describe))
                }
                None => (None, SessionAuth::Password { password_id: None }, None),
            };
            if let Some(same) = sessions
                .iter()
                .find(|s| matches!(s.kind, SessionKind::Ssh) && s.host.eq_ignore_ascii_case(&ip))
            {
                notes.push(format!(
                    "the session '{}' goes to this address already: link it instead if it is this VM's",
                    same.name
                ));
            }
            out.push(VmSessionDraft {
                vm_id: vm.id.clone(),
                vm_name: vm.display_name.clone(),
                session: Some(SessionDraft {
                    name: vm.display_name.clone(),
                    host: ip,
                    port: 22,
                    username,
                    auth,
                    environment: vm.environment,
                    tags: vm.tags.clone(),
                    vm_id: vm.id.clone(),
                    deploy,
                }),
                refused: None,
                notes,
            });
        }
        Ok(out)
    }

    /// The deploy specs of this workspace's newest deploy and stack deploy jobs, newest first.
    async fn deploy_specs(&self, ctx: &Context) -> Result<Vec<DeploySpec>> {
        let commands = self.store.deploy_commands(ctx, DEPLOY_JOBS).await?;
        let mut specs = Vec::new();
        for command in commands {
            match command {
                Command::Deploy { spec, .. } => specs.push(*spec),
                Command::Stack {
                    op: StackOp::Deploy { spec },
                    ..
                } => specs.extend(spec.steps.into_iter().map(|s| s.spec)),
                _ => {}
            }
        }
        Ok(specs)
    }

    /// The user the deploy's install config makes, read from the config as saved now while it is still the one
    /// approved (its fingerprint); never a Windows answer file's (its session is WinRM's).
    async fn install_user(&self, ctx: &Context, spec: &DeploySpec) -> Option<String> {
        let install = spec.install.as_ref()?;
        if install.kind == InstallKind::Unattend {
            return None;
        }
        let config = self
            .catalog
            .install_config(ctx, &install.config_id.to_string())
            .await
            .ok()?;
        if config_fingerprint(&config.spec) != install.fingerprint {
            return None;
        }
        crate::catalog::install::read_form(install.kind, &config.spec.body)
            .form
            .users
            .first()
            .map(|u| u.name.clone())
            .filter(|n| !n.is_empty() && !n.contains("{{"))
    }
}

fn refused(vm_id: &str, vm_name: &str, reason: String) -> VmSessionDraft {
    VmSessionDraft {
        vm_id: vm_id.to_owned(),
        vm_name: vm_name.to_owned(),
        session: None,
        refused: Some(reason),
        notes: Vec::new(),
    }
}

/// Why a running VM has no address, and what reports one.
fn no_address(vm: &VmRecord) -> String {
    let windows = vm
        .guest_os
        .as_deref()
        .is_some_and(|os| os.trim().to_ascii_lowercase().starts_with("win"));
    match vm.hypervisor {
        Hypervisor::Vmware if windows => {
            "Workstation reports no address for it: install VMware Tools in the guest (Install or upgrade on its Settings tab)".into()
        }
        Hypervisor::Vmware => "Workstation reports no address for it: install open-vm-tools in the guest (for example sudo apt install open-vm-tools, or sudo dnf install open-vm-tools)".into(),
        Hypervisor::VirtualBox => {
            "VirtualBox reports no address for it: install the Guest Additions in the guest".into()
        }
    }
}

/// The settings file's folder, as a deploy's [`DeploySpec::vm_folder`] names it, for comparing without letter case.
fn settings_folder(vm: &VmRecord) -> Option<String> {
    let file = match vm.hypervisor {
        Hypervisor::Vmware => Some(vm.vmx_path.as_str()),
        Hypervisor::VirtualBox => vm.config_path.as_deref(),
    }?;
    Path::new(file).parent().map(|p| folder_key(&p.display().to_string()))
}

fn folder_key(path: &str) -> String {
    path.replace('/', "\\").trim_end_matches('\\').to_lowercase()
}

/// The newest deploy (first in `specs`) on the VM's hypervisor that made a VM in the VM's folder.
fn from_deploy(specs: &[DeploySpec], vm: &VmRecord) -> Option<FromDeploy> {
    let folder = settings_folder(vm)?;
    specs.iter().find_map(|spec| {
        (spec.hypervisor == vm.hypervisor
            && spec
                .vms
                .iter()
                .any(|v| folder_key(&spec.vm_folder(v).display().to_string()) == folder))
        .then(|| FromDeploy {
            spec: spec.clone(),
            describe: spec.origin.describe(),
        })
    })
}

async fn stored_hardware(store: &Store, ctx: &Context) -> Result<HashMap<String, VmHardware>> {
    Ok(store
        .all_vm_specs(ctx)
        .await?
        .into_iter()
        .filter_map(|(id, stored)| Some((id, serde_json::from_str::<VmHardware>(&stored.specs).ok()?)))
        .collect())
}

/// A VirtualBox VM whose every adapter is on NAT (or a NAT network) can't be reached from this PC. The stored
/// adapters say, else the deploy's network; with neither, the address is tried.
fn virtualbox_nat(
    nics: Option<&[crate::adapters::vm_hardware::VirtualNic]>,
    deploy: Option<&DeploySpec>,
) -> Option<&'static str> {
    const NAT: &str = "it is on VirtualBox's NAT, which this PC can't reach: give it a host-only or bridged adapter";
    let nat = |c: &str| matches!(c.trim().to_ascii_lowercase().as_str(), "nat" | "natnetwork");
    match nics {
        Some(nics) if !nics.is_empty() => {
            let known: Vec<&str> = nics.iter().filter_map(|n| n.connection.as_deref()).collect();
            (!known.is_empty() && known.iter().all(|c| nat(c))).then_some(NAT)
        }
        _ => match deploy {
            Some(spec) if matches!(spec.network, Some(Network::Nat | Network::NatNetwork { .. }) | None) => Some(NAT),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::vm_hardware::VirtualNic;

    fn nic(connection: &str) -> VirtualNic {
        VirtualNic {
            slot: "nic1".into(),
            connection: Some(connection.into()),
            model: None,
            mac: None,
            connected: None,
            network_name: None,
            connected_now: None,
            static_mac: false,
        }
    }

    #[test]
    fn only_a_virtualbox_vm_on_nat_alone_is_refused() {
        assert!(virtualbox_nat(Some(&[nic("nat")]), None).is_some());
        assert!(virtualbox_nat(Some(&[nic("natnetwork"), nic("NAT")]), None).is_some());
        assert_eq!(virtualbox_nat(Some(&[nic("nat"), nic("hostonly")]), None), None);
        assert_eq!(virtualbox_nat(Some(&[nic("bridged")]), None), None);
        // Nothing known: the address is tried.
        assert_eq!(virtualbox_nat(None, None), None);
        assert_eq!(virtualbox_nat(Some(&[]), None), None);
    }

    #[test]
    fn folders_compare_without_letter_case_or_a_trailing_separator() {
        assert_eq!(folder_key(r"C:\VMs\Lab\web-1\"), folder_key("c:/vms/lab/WEB-1"));
        assert_ne!(folder_key(r"C:\VMs\Lab\web-1"), folder_key(r"C:\VMs\Lab\web-10"));
    }
}
