//! VM-30: what a golden image build is. [`BuildRecipe`] is what an image Remotely builds keeps (the image's
//! `build` column): the ISO image, the install config, the size, the hypervisor and its network, the folder, the
//! config's own values and how many versions to keep. [`BuildSpec`] is what [`crate::command_bus::Command::ImageBuild`]
//! carries: one build of one version, with the build VM's whole [`DeploySpec`] (one VM, installed from the config as
//! G6 installs it), so what is approved is what runs. [`BuildSpec::fingerprint`] is what a standing approval (VM-27) is
//! given for: a scheduled rebuild whose recipe, install config or ISO changed since asks again.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::adapters::hypervisor::Hypervisor;
use crate::catalog::install::InstallKind;
use crate::catalog::templates::{self, Network};
use crate::deploy::spec::{DeploySource, DeploySpec, IsoSeen, MAX_INSTALL_MINUTES};
use crate::domain::TargetRef;
use crate::error::{CoreError, Result};
use crate::vault::SecretId;

/// The most versions an image keeps when it keeps a number of them.
pub const MAX_KEEP_VERSIONS: u32 = 20;
/// The highest version number (a build past it is refused).
pub const MAX_VERSION: u32 = 9999;
/// How long the build waits for the guest to power itself off once it is made generic (sysprep takes minutes).
pub const DEFAULT_SEAL_MINUTES: u32 = 30;
/// The snapshot each version's clones are made from, beside its number: `Remotely image v3`.
pub const SNAPSHOT_PREFIX: &str = "Remotely image";
/// Windows' computer names are at most 15 characters, and the build VM's hostname is its name.
const WINDOWS_NAME_CHARS: usize = 15;
/// The longest base of a version VM's name (`<base>-v<N>`).
const MAX_BASE_CHARS: usize = 40;

/// What an image Remotely builds is built from (the image's `build` column), and what a rebuild builds again.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildRecipe {
    /// The catalogue's ISO image the system is installed from; its OS profile is the image's.
    pub iso_image_id: Uuid,
    /// An own install config of a kind Remotely delivers (Ubuntu autoinstall, Debian preseed, Windows unattend).
    pub install_config_id: Uuid,
    /// A built-in size's name or an own size's id: the build VM's, and so its clones' disk.
    pub size_id: String,
    pub hypervisor: Hypervisor,
    pub network: Network,
    /// VirtualBox's host-only or bridged adapter (`None`: the first VirtualBox lists).
    #[serde(default)]
    pub host_adapter: Option<String>,
    /// Where each version's VM folder goes (`None`: the hypervisor's default folder).
    #[serde(default)]
    pub vm_folder: Option<String>,
    /// The config's own variables (`{{name}}`); a missing one takes its default.
    #[serde(default)]
    pub values: BTreeMap<String, String>,
    /// VM-32: the build VM's `{{ip}}` from this address pool.
    #[serde(default)]
    pub address_pool_id: Option<Uuid>,
    /// How long the install watcher waits.
    #[serde(default = "default_install_minutes")]
    pub install_minutes: u32,
    /// Keep the newest this many versions, deleting the older ones' VMs that no linked clone uses (`None`: keep all).
    #[serde(default)]
    pub keep: Option<u32>,
}

fn default_install_minutes() -> u32 {
    crate::deploy::spec::DEFAULT_INSTALL_MINUTES
}

/// The system a build makes generic, by its install config's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BuildOs {
    /// Ubuntu Server from its autoinstall (S1).
    Ubuntu,
    /// Debian from its preseed (S2).
    Debian,
    /// Windows Server from its unattend (S3): sysprep.
    Windows,
}

impl BuildOs {
    /// The system a config kind installs, when Remotely delivers it (G6's flavors).
    pub fn of(kind: InstallKind) -> Option<Self> {
        match crate::deploy::install::Flavor::of(kind)? {
            crate::deploy::install::Flavor::Ubuntu => Some(BuildOs::Ubuntu),
            crate::deploy::install::Flavor::Debian => Some(BuildOs::Debian),
            crate::deploy::install::Flavor::Windows => Some(BuildOs::Windows),
        }
    }

    pub fn windows(self) -> bool {
        self == BuildOs::Windows
    }

    pub fn label(self) -> &'static str {
        match self {
            BuildOs::Ubuntu => "Ubuntu",
            BuildOs::Debian => "Debian",
            BuildOs::Windows => "Windows",
        }
    }

    /// What making it generic does, in words, for the approval and the audit log.
    pub fn generic_steps(self) -> Vec<&'static str> {
        match self {
            BuildOs::Windows => vec![
                "the build's WinRM over HTTPS listener and its certificate are deleted, so each clone makes its own at its first sign-in",
                "Setup's copies of the answer file, PowerShell's history and the event logs are cleared",
                "sysprep /generalize /oobe /shutdown",
            ],
            BuildOs::Ubuntu | BuildOs::Debian => vec![
                "cloud-init is turned back on and cleaned (cloud-init clean), so each clone's first boot sets it up",
                "/etc/machine-id is emptied and /var/lib/dbus/machine-id deleted, so each clone gets its own",
                "the SSH host keys are deleted and made again at each clone's first boot",
                "the installer's logs (which hold the answer file) are deleted, other logs, shell history and DHCP leases cleared",
                "the system is shut down",
            ],
        }
    }
}

/// The base of a version VM's name: the image's name as a hostname would have it, short enough for Windows' 15
/// characters with `-v<N>` after it.
pub fn vm_base(image_name: &str, os: BuildOs) -> String {
    let base = templates::hostname(image_name, 1);
    let max = if os.windows() {
        WINDOWS_NAME_CHARS - "-v999".len()
    } else {
        MAX_BASE_CHARS
    };
    let mut base: String = base.chars().take(max).collect();
    while base.ends_with('-') {
        base.pop();
    }
    if base.is_empty() {
        "golden".into()
    } else {
        base
    }
}

/// A version's VM: `ubuntu-golden-v3`.
pub fn version_vm_name(image_name: &str, os: BuildOs, version: u32) -> String {
    format!("{}-v{version}", vm_base(image_name, os))
}

/// A version's snapshot: `Remotely image v3`.
pub fn snapshot_name(version: u32) -> String {
    format!("{SNAPSHOT_PREFIX} v{version}")
}

/// What a standing approval of an image's build is given for: the image, its OS profile, the recipe, the install
/// config's content and the ISO as it is on disk. A build that hashes differently isn't the one approved.
pub fn build_fingerprint(
    image_id: Uuid,
    os_profile: &str,
    recipe: &BuildRecipe,
    config_fingerprint: &str,
    iso_seen: Option<IsoSeen>,
) -> String {
    let mut hash = Sha256::new();
    hash.update(image_id.as_bytes());
    hash.update([0]);
    hash.update(os_profile.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(recipe).unwrap_or_default());
    hash.update([0]);
    hash.update(config_fingerprint.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(&iso_seen).unwrap_or_default());
    hex::encode(hash.finalize())
}

/// How the build signs in to its VM to make it generic, with which vault items (read when it does).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SignIn {
    /// Linux: SSH as the config's first user with the config's key; sudo with that user's vault password (`None`: the
    /// user's password is locked, and sudo must need none).
    Ssh {
        user: String,
        key_id: SecretId,
        #[serde(default)]
        sudo_password_id: Option<SecretId>,
    },
    /// Windows: WinRM over HTTPS as this account with its vault password (G6 set it), and the certificate the VM
    /// wrote to its serial port.
    Winrm { account: String, password_id: SecretId },
}

impl SignIn {
    /// For the approval and the audit log.
    pub fn describe(&self) -> String {
        match self {
            SignIn::Ssh {
                user,
                sudo_password_id: Some(_),
                ..
            } => format!(
                "Remotely signs in over SSH as {user} with the install config's key and runs the steps as root through sudo with {user}'s vault password; the new VM's host key is taken on first use (a VM this build just made on this PC's own network) and deleted with the rest"
            ),
            SignIn::Ssh { user, .. } => format!(
                "Remotely signs in over SSH as {user} with the install config's key and runs the steps as root through sudo (no password); the new VM's host key is taken on first use (a VM this build just made on this PC's own network) and deleted with the rest"
            ),
            SignIn::Winrm { account, .. } => format!(
                "Remotely signs in over WinRM as {account} with the vault's password and only the certificate the VM wrote to its serial port"
            ),
        }
    }
}

/// One build: version `version` of an image, as approved (what [`crate::command_bus::Command::ImageBuild`] carries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildSpec {
    /// The image's id; for its first build an id given now, the image made under it once the build is done.
    pub image_id: Uuid,
    /// The first build: the image doesn't exist yet and is made by this build.
    pub image_new: bool,
    pub image_name: String,
    /// The OS profile its clones deploy with (the ISO image's).
    pub os_profile: String,
    pub version: u32,
    pub os: BuildOs,
    pub recipe: BuildRecipe,
    pub config_name: String,
    /// The install config's content as approved ([`crate::deploy::spec::config_fingerprint`]).
    pub config_fingerprint: String,
    pub iso_path: String,
    /// The ISO's size and time as approved.
    #[serde(default)]
    pub iso_seen: Option<IsoSeen>,
    /// How long the build waits for the guest to power itself off once it is made generic.
    pub seal_minutes: u32,
    /// How the build signs in to make the VM generic.
    pub sign_in: SignIn,
    /// The build VM: one VM, installed from the config through G6's path, no session, console or snapshot of its own.
    pub deploy: DeploySpec,
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

impl BuildSpec {
    /// The build's one target: the version's new VM.
    pub fn targets(&self) -> Vec<TargetRef> {
        self.deploy.targets()
    }

    /// The version's VM, as the deploy makes it.
    pub fn vm(&self) -> Option<&crate::deploy::spec::DeployVm> {
        self.deploy.vms.first()
    }

    pub fn vm_name(&self) -> &str {
        self.vm().map_or("", |vm| vm.name.as_str())
    }

    /// [`build_fingerprint`] of what this build is.
    pub fn fingerprint(&self) -> String {
        build_fingerprint(
            self.image_id,
            &self.os_profile,
            &self.recipe,
            &self.config_fingerprint,
            self.iso_seen,
        )
    }

    /// What differs between an approved build and this one, in words ("its install config 'X' changed"). Empty when
    /// they build the same (the version and the VM's name aside).
    pub fn differences(&self, approved: &BuildSpec) -> Vec<String> {
        let mut out = Vec::new();
        if self.image_id != approved.image_id {
            out.push(format!("it builds image '{}' now", self.image_name));
        }
        if self.config_fingerprint != approved.config_fingerprint || self.config_name != approved.config_name {
            out.push(format!("the install config '{}' changed", self.config_name));
        }
        if self.iso_path != approved.iso_path || self.iso_seen != approved.iso_seen {
            out.push(format!("the ISO {} changed", self.iso_path));
        }
        if self.os_profile != approved.os_profile {
            out.push("the image's OS profile changed".into());
        }
        if self.recipe.keep != approved.recipe.keep {
            out.push(match self.recipe.keep {
                Some(n) => format!("it keeps the newest {n} versions now"),
                None => "it keeps every version now".into(),
            });
        }
        let settings = BuildRecipe {
            keep: approved.recipe.keep,
            ..self.recipe.clone()
        };
        if settings != approved.recipe {
            out.push(format!("image '{}''s build settings changed", self.image_name));
        }
        if out.is_empty() && self.fingerprint() != approved.fingerprint() {
            out.push(format!("image '{}''s build changed", self.image_name));
        }
        out
    }

    /// "Build image 'Ubuntu golden' version 3".
    pub fn summary(&self) -> String {
        format!("Build image '{}' version {}", self.image_name, self.version)
    }

    /// What the audit log says the build is (names and SHA-256s, never a rendered file).
    pub fn describe(&self) -> String {
        let mut parts = vec![
            format!(
                "version {} of {} image '{}'",
                self.version,
                if self.image_new { "the new" } else { "the" },
                self.image_name
            ),
            format!(
                "installed from the install config '{}' (SHA-256 {}) and the ISO {}",
                self.config_name, self.config_fingerprint, self.iso_path
            ),
            format!(
                "as the VM '{}' on {} in {}",
                self.vm_name(),
                templates::hypervisor_label(self.recipe.hypervisor),
                self.deploy.folder
            ),
            format!("made generic ({})", self.os.generic_steps().join("; ")),
            self.sign_in.describe(),
            format!(
                "then shut down and snapshotted as '{}' (powered off, no memory)",
                snapshot_name(self.version)
            ),
        ];
        if let Some(keep) = self.recipe.keep {
            parts.push(format!(
                "keeping the newest {keep} version{}: older versions' VMs are deleted unless a linked clone uses them",
                if keep == 1 { "" } else { "s" }
            ));
        }
        parts.join("; ")
    }

    /// Checked on the bus, whoever built it: one VM installed from the config as G6 installs it, with no session,
    /// console or snapshot of its own, agreeing with the recipe.
    pub fn validate(&self) -> Result<()> {
        self.deploy.validate()?;
        crate::catalog::images::clean_image_name(&self.image_name)?;
        if self.deploy.vms.len() != 1 {
            return invalid("A build makes one VM.");
        }
        let Some(install) = &self.deploy.install else {
            return invalid("A build installs from an install config.");
        };
        let DeploySource::Iso { path } = &self.deploy.source else {
            return invalid("A build installs from an ISO image.");
        };
        if *path != self.iso_path || install.iso_seen != self.iso_seen {
            return invalid("The build's ISO isn't the one its install is approved for.");
        }
        if install.fingerprint != self.config_fingerprint || install.config_id != self.recipe.install_config_id {
            return invalid("The build's install config isn't the one its install is approved for.");
        }
        if BuildOs::of(install.kind) != Some(self.os) {
            return invalid("The build's system isn't its install config's.");
        }
        if self.deploy.hypervisor != self.recipe.hypervisor || self.deploy.unattended.is_some() {
            return invalid("The build's VM isn't the recipe's.");
        }
        let after = self.deploy.after_deploy;
        if after.create_session || after.link_session || after.clean_snapshot || after.open_console {
            return invalid("A build makes no session, console or snapshot of its own.");
        }
        if self.deploy.stack.is_some() {
            return invalid("A build isn't a stack's step.");
        }
        if !(1..=MAX_VERSION).contains(&self.version) {
            return invalid(format!("A version is 1 to {MAX_VERSION}."));
        }
        if !self.vm_name().ends_with(&format!("-v{}", self.version)) {
            return invalid("A version's VM is named after its number.");
        }
        if self.recipe.keep.is_some_and(|k| !(1..=MAX_KEEP_VERSIONS).contains(&k)) {
            return invalid(format!("Keep 1 to {MAX_KEEP_VERSIONS} versions, or every version."));
        }
        if !(1..=MAX_INSTALL_MINUTES).contains(&self.recipe.install_minutes) {
            return invalid(format!(
                "The install's time limit is 1 to {MAX_INSTALL_MINUTES} minutes."
            ));
        }
        let picked = |id: &SecretId| install.password_ids.contains(id);
        match &self.sign_in {
            SignIn::Ssh {
                key_id,
                sudo_password_id,
                user,
            } => {
                if self.os.windows() || install.key_id != Some(*key_id) || !sudo_password_id.as_ref().is_none_or(picked)
                {
                    return invalid("The build signs in with the install config's own key and password.");
                }
                templates::check_guest_user(Some(user))?;
            }
            SignIn::Winrm { password_id, .. } => {
                if !self.os.windows() || !picked(password_id) {
                    return invalid("The build signs in with the install config's own password.");
                }
            }
        }
        if !(1..=MAX_INSTALL_MINUTES).contains(&self.seal_minutes) {
            return invalid(format!(
                "The wait for the VM to shut down is 1 to {MAX_INSTALL_MINUTES} minutes."
            ));
        }
        Ok(())
    }

    /// The same build for only these targets (BX-04's retry): a build's one VM, or nothing.
    pub fn only(&self, targets: &[TargetRef]) -> Self {
        let mut spec = self.clone();
        spec.deploy = self.deploy.only(targets);
        spec
    }
}

/// VM-30: a build as the approval dialog shows it, besides its VM's deploy preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildDetails {
    pub image_name: String,
    /// The first build makes the image.
    pub new_image: bool,
    pub version: u32,
    pub os: BuildOs,
    pub vm_name: String,
    pub config_name: String,
    pub iso_path: String,
    pub snapshot_name: String,
    /// What making it generic does.
    pub steps: Vec<String>,
    /// How Remotely signs in to do it.
    pub sign_in: String,
    /// The newest versions it keeps (`None`: every version).
    pub keep: Option<u32>,
}

impl BuildDetails {
    pub fn of(spec: &BuildSpec) -> Self {
        Self {
            image_name: spec.image_name.clone(),
            new_image: spec.image_new,
            version: spec.version,
            os: spec.os,
            vm_name: spec.vm_name().to_owned(),
            config_name: spec.config_name.clone(),
            iso_path: spec.iso_path.clone(),
            snapshot_name: snapshot_name(spec.version),
            steps: spec.os.generic_steps().into_iter().map(str::to_owned).collect(),
            sign_in: spec.sign_in.describe(),
            keep: spec.recipe.keep,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe() -> BuildRecipe {
        BuildRecipe {
            iso_image_id: Uuid::from_u128(1),
            install_config_id: Uuid::from_u128(2),
            size_id: "gp.medium".into(),
            hypervisor: Hypervisor::Vmware,
            network: Network::Nat,
            host_adapter: None,
            vm_folder: Some(r"C:\VMs\golden".into()),
            values: BTreeMap::new(),
            address_pool_id: None,
            install_minutes: 60,
            keep: None,
        }
    }

    #[test]
    fn version_vms_are_named_after_the_image_and_fit_windows_names() {
        assert_eq!(
            version_vm_name("Ubuntu 24.04 golden", BuildOs::Ubuntu, 3),
            "ubuntu-24-04-golden-v3"
        );
        let windows = version_vm_name("Windows Server 2025 Datacenter", BuildOs::Windows, 12);
        assert!(windows.len() <= 15, "{windows}");
        assert_eq!(windows, "windows-se-v12");
        assert_eq!(version_vm_name("!!!", BuildOs::Debian, 1), "vm-1-v1");
        assert_eq!(snapshot_name(3), "Remotely image v3");
    }

    #[test]
    fn the_fingerprint_follows_the_recipe_the_config_and_the_iso() {
        let id = Uuid::from_u128(9);
        let seen = Some(IsoSeen {
            bytes: 10,
            modified_ms: 20,
        });
        let base = build_fingerprint(id, "ubuntu", &recipe(), "abc", seen);
        assert_eq!(base, build_fingerprint(id, "ubuntu", &recipe(), "abc", seen));
        let kept = BuildRecipe {
            keep: Some(2),
            ..recipe()
        };
        let other_iso = Some(IsoSeen {
            bytes: 11,
            modified_ms: 20,
        });
        for changed in [
            build_fingerprint(id, "ubuntu", &kept, "abc", seen),
            build_fingerprint(id, "ubuntu", &recipe(), "abd", seen),
            build_fingerprint(id, "ubuntu", &recipe(), "abc", other_iso),
            build_fingerprint(id, "debian", &recipe(), "abc", seen),
            build_fingerprint(Uuid::from_u128(8), "ubuntu", &recipe(), "abc", seen),
        ] {
            assert_ne!(changed, base);
        }
    }

    /// A build of version 1 as the service makes it: one VM from an ISO, installed from the config, nothing after.
    fn built_spec() -> BuildSpec {
        use crate::catalog::images::ImageSource;
        use crate::deploy::spec::{InstallSpec, VmInstall};
        use crate::deploy::DeployOrigin;
        let key = SecretId(Uuid::from_u128(3));
        let password = SecretId(Uuid::from_u128(4));
        let iso = r"C:\ISOs\noble.iso".to_owned();
        let mut deploy = DeploySpec::from_plan(
            &crate::deploy::spec::tests::plan(ImageSource::Iso { path: iso.clone() }, "ubuntu", Hypervisor::Vmware, 1),
            DeployOrigin::Custom {
                name: "Ubuntu golden".into(),
            },
            r"C:\VMs\golden".into(),
            None,
        );
        deploy.vms[0].name = "ubuntu-golden-v1".into();
        deploy.vms[0].hostname = "ubuntu-golden-v1".into();
        deploy.vms[0].install = Some(VmInstall::default());
        deploy.after_deploy = crate::catalog::templates::AfterDeploy {
            create_session: false,
            link_session: false,
            clean_snapshot: false,
            open_console: false,
        };
        deploy.install = Some(InstallSpec {
            config_id: Uuid::from_u128(2),
            config_name: "lab".into(),
            kind: InstallKind::Autoinstall,
            fingerprint: "0".repeat(64),
            password_ids: vec![password],
            key_id: Some(key),
            time_limit_minutes: 60,
            pool: None,
            iso_seen: None,
        });
        BuildSpec {
            image_id: Uuid::from_u128(30),
            image_new: true,
            image_name: "Ubuntu golden".into(),
            os_profile: "ubuntu".into(),
            version: 1,
            os: BuildOs::Ubuntu,
            recipe: recipe(),
            config_name: "lab".into(),
            config_fingerprint: "0".repeat(64),
            iso_path: iso,
            iso_seen: None,
            seal_minutes: DEFAULT_SEAL_MINUTES,
            sign_in: SignIn::Ssh {
                user: "alice".into(),
                key_id: key,
                sudo_password_id: Some(password),
            },
            deploy,
        }
    }

    #[test]
    fn a_build_is_one_vm_from_the_config_with_nothing_of_its_own_after() {
        let ok = built_spec();
        ok.validate().unwrap();
        assert_eq!(ok.summary(), "Build image 'Ubuntu golden' version 1");
        let text = ok.describe();
        assert!(text.contains("snapshotted as 'Remotely image v1'"), "{text}");
        assert!(text.contains("sudo with alice's vault password"), "{text}");
        let bad = |change: &dyn Fn(&mut BuildSpec), why: &str| {
            let mut s = ok.clone();
            change(&mut s);
            let err = s.validate().unwrap_err().to_string();
            assert!(err.contains(why), "{why}: {err}");
        };
        bad(&|s| s.deploy.after_deploy.create_session = true, "no session");
        bad(&|s| s.deploy.after_deploy.clean_snapshot = true, "no session");
        bad(&|s| s.version = 2, "named after its number");
        bad(&|s| s.recipe.keep = Some(0), "Keep 1 to");
        bad(&|s| s.config_fingerprint = "1".repeat(64), "install config");
        bad(&|s| s.iso_path = r"C:\ISOs\other.iso".into(), "ISO");
        bad(
            &|s| {
                s.sign_in = SignIn::Ssh {
                    user: "alice".into(),
                    key_id: SecretId(Uuid::from_u128(99)),
                    sudo_password_id: None,
                }
            },
            "own key",
        );
        bad(&|s| s.os = BuildOs::Windows, "system");
        // A round trip through the journal keeps it whole.
        let text = serde_json::to_string(&ok).unwrap();
        assert_eq!(serde_json::from_str::<BuildSpec>(&text).unwrap(), ok);
    }

    #[test]
    fn a_rebuild_differs_from_its_approval_only_in_what_it_builds() {
        let approved = built_spec();
        // The next version, its own VM: the same build.
        let mut next = approved.clone();
        next.version = 2;
        next.image_new = false;
        next.deploy.vms[0].name = "ubuntu-golden-v2".into();
        assert!(next.differences(&approved).is_empty());
        assert_eq!(next.fingerprint(), approved.fingerprint());
        let changed = |change: &dyn Fn(&mut BuildSpec), want: &str| {
            let mut s = next.clone();
            change(&mut s);
            let found = s.differences(&approved).join("; ");
            assert!(found.contains(want), "{want}: {found}");
        };
        changed(
            &|s| s.config_fingerprint = "1".repeat(64),
            "the install config 'lab' changed",
        );
        changed(
            &|s| {
                s.iso_seen = Some(IsoSeen {
                    bytes: 1,
                    modified_ms: 2,
                })
            },
            "the ISO C:\\ISOs\\noble.iso changed",
        );
        changed(&|s| s.recipe.keep = Some(2), "keeps the newest 2 versions now");
        changed(&|s| s.recipe.size_id = "gp.large".into(), "build settings changed");
        changed(&|s| s.os_profile = "debian".into(), "OS profile changed");
    }
    #[test]
    fn os_by_config_kind() {
        assert_eq!(BuildOs::of(InstallKind::Autoinstall), Some(BuildOs::Ubuntu));
        assert_eq!(BuildOs::of(InstallKind::Preseed), Some(BuildOs::Debian));
        assert_eq!(BuildOs::of(InstallKind::Unattend), Some(BuildOs::Windows));
        assert_eq!(
            BuildOs::of(InstallKind::Kickstart),
            None,
            "Kickstart isn't delivered (no spike)"
        );
        assert_eq!(BuildOs::of(InstallKind::CloudInit), None);
        assert!(BuildOs::Windows.generic_steps().iter().any(|s| s.contains("sysprep")));
        assert!(BuildOs::Debian.generic_steps().iter().any(|s| s.contains("machine-id")));
    }
}
