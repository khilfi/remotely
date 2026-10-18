//! Inventory reads (VM-01, VM-02). Reads skip the command bus: they go to the adapter and the store only.
//!
//! A refresh finds every VM, not only running ones: Workstation's library (`inventory.vmls`), the
//! folders chosen in Settings (scanned for .vmx files) and `vmrun list`. For running VMs it also asks
//! vmrun for the VMware Tools state and the guest's IP address.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::adapters::vmware::{path_key, ToolsState, VmwareAdapter, VmxInfo};
use crate::command_bus::TargetDirectory;
use crate::domain::{Context, Environment, PowerState, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::store::{self, DiscoveredVm, Store, VmRecord};

/// How the app names itself in dialogs, jobs and the audit log.
pub const APP_NAME: &str = "Remotely";

/// vmrun calls at once while asking running VMs for Tools state and IP address.
const GUEST_QUERY_PARALLELISM: usize = 4;

/// Something a refresh could not read. The rest of the list is still shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryWarning {
    /// [`CoreError::code`] of the cause, e.g. `vmrun_not_found`.
    pub code: String,
    pub message: String,
}

impl InventoryWarning {
    fn new(context: &str, err: &CoreError) -> Self {
        Self {
            code: err.code().to_owned(),
            message: format!("{context}: {err}"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshReport {
    pub vms: Vec<VmRecord>,
    pub warnings: Vec<InventoryWarning>,
}

/// Which VMs to show or select (VM-02). Empty fields match everything; a VM must match every field
/// that is set, and any one of the values listed in a field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VmFilter {
    /// Case-insensitive text in the name, .vmx path, guest OS, IP address or a tag.
    pub text: String,
    pub tags: Vec<String>,
    pub power_states: Vec<PowerState>,
    pub environments: Vec<Environment>,
    /// `Some(true)`: only protected VMs; `Some(false)`: only unprotected ones.
    pub protected: Option<bool>,
}

impl VmFilter {
    pub fn matches(&self, vm: &VmRecord) -> bool {
        let text = self.text.trim().to_lowercase();
        if !text.is_empty() {
            let fields = [
                Some(&vm.display_name),
                Some(&vm.vmx_path),
                vm.guest_os.as_ref(),
                vm.guest_os_name.as_ref(),
                vm.ip_address.as_ref(),
            ];
            let hit = fields
                .into_iter()
                .flatten()
                .chain(&vm.tags)
                .any(|f| f.to_lowercase().contains(&text));
            if !hit {
                return false;
            }
        }
        if !self.tags.is_empty()
            && !self
                .tags
                .iter()
                .any(|want| vm.tags.iter().any(|t| t.eq_ignore_ascii_case(want.trim())))
        {
            return false;
        }
        if !self.power_states.is_empty() && !self.power_states.contains(&vm.power_state) {
            return false;
        }
        if !self.environments.is_empty() && !self.environments.contains(&vm.environment) {
            return false;
        }
        self.protected.is_none_or(|p| vm.protected == p)
    }
}

pub struct Inventory {
    store: Store,
    vmware: Arc<dyn VmwareAdapter>,
}

/// A .vmx path found by one of the sources, before its file is read.
struct Candidate {
    path: PathBuf,
    library_name: Option<String>,
}

impl Inventory {
    pub fn new(store: Store, vmware: Arc<dyn VmwareAdapter>) -> Self {
        Self { store, vmware }
    }

    /// VM-01: folders scanned for .vmx files, as saved in Settings.
    pub async fn scan_folders(&self, ctx: &Context) -> Result<Vec<PathBuf>> {
        let saved = self
            .store
            .get_setting::<Vec<String>>(ctx, store::SCAN_FOLDERS_KEY)
            .await?;
        Ok(saved.unwrap_or_default().into_iter().map(PathBuf::from).collect())
    }

    /// VM-01: finds every VM, saves what it found and returns the full list. A source that cannot be
    /// read (vmrun missing, a folder gone) becomes a warning instead of failing the refresh.
    pub async fn refresh(&self, ctx: &Context) -> Result<RefreshReport> {
        let mut warnings = Vec::new();
        let mut candidates: Vec<Candidate> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut add = |path: PathBuf, library_name: Option<String>| {
            if seen.insert(path_key(&path)) {
                candidates.push(Candidate { path, library_name });
            }
        };

        match self.vmware.library().await {
            Ok(entries) => entries.into_iter().for_each(|e| add(e.vmx_path, e.display_name)),
            Err(err) => warnings.push(InventoryWarning::new("Could not read the Workstation library", &err)),
        }
        for folder in self.scan_folders(ctx).await? {
            match self.vmware.scan_folder(&folder).await {
                Ok(paths) => paths.into_iter().for_each(|p| add(p, None)),
                Err(err) => warnings.push(InventoryWarning::new(
                    &format!("Could not scan {}", folder.display()),
                    &err,
                )),
            }
        }
        let running: Option<HashSet<String>> = match self.vmware.list_running().await {
            Ok(paths) => {
                let keys = paths.iter().map(|p| path_key(p)).collect();
                paths.into_iter().for_each(|p| add(p, None));
                Some(keys)
            }
            Err(err) => {
                warnings.push(InventoryWarning::new(
                    "Could not ask Workstation which VMs are running",
                    &err,
                ));
                None
            }
        };

        let previous = self.store.vm_power_states(ctx).await?;
        let mut found = Vec::with_capacity(candidates.len());
        let mut to_query = Vec::new();
        for candidate in candidates {
            let key = path_key(&candidate.path);
            let is_running = running.as_ref().map(|r| r.contains(&key));
            let info = match self.vmware.read_vmx(&candidate.path).await {
                Ok(info) => info,
                Err(err) if is_running == Some(true) => {
                    tracing::warn!(vmx = %candidate.path.display(), error = %err, "could not read a running VM's .vmx");
                    VmxInfo::default()
                }
                // Listed in the library but gone from disk, or an unreadable file: not found.
                Err(err) => {
                    tracing::debug!(vmx = %candidate.path.display(), error = %err, "skipping unreadable .vmx");
                    continue;
                }
            };
            let power_state = match is_running {
                Some(true) => PowerState::Running,
                _ if info.suspended => PowerState::Suspended,
                Some(false) => PowerState::NotRunning,
                None => PowerState::Unknown,
            };
            // A paused guest cannot answer; it keeps its last Tools state and IP until unpaused.
            let paused = previous.get(&key) == Some(&PowerState::Paused);
            if power_state == PowerState::Running && !paused {
                to_query.push(found.len());
            }
            let display_name = info
                .display_name
                .clone()
                .filter(|n| !n.trim().is_empty())
                .or(candidate.library_name)
                .unwrap_or_else(|| file_stem(&candidate.path));
            found.push(DiscoveredVm {
                vmx_path: candidate.path.to_string_lossy().into_owned(),
                display_name,
                info,
                power_state,
                tools_state: None,
                ip_address: None,
            });
        }

        self.query_guests(&mut found, &to_query).await;
        self.store.record_inventory(ctx, &found).await?;
        Ok(RefreshReport {
            vms: self.store.list_vms(ctx).await?,
            warnings,
        })
    }

    /// Tools state, then the IP address when Tools is running, for each VM in `indexes`. A failing
    /// query leaves the field empty; it never fails the refresh.
    async fn query_guests(&self, found: &mut [DiscoveredVm], indexes: &[usize]) {
        let limit = Arc::new(Semaphore::new(GUEST_QUERY_PARALLELISM));
        let mut tasks = JoinSet::new();
        for &index in indexes {
            let vmware = Arc::clone(&self.vmware);
            let limit = Arc::clone(&limit);
            let vmx = PathBuf::from(&found[index].vmx_path);
            tasks.spawn(async move {
                let _permit = limit.acquire_owned().await.ok();
                let tools = match vmware.tools_state(&vmx).await {
                    Ok(state) => state,
                    Err(err) => {
                        tracing::debug!(vmx = %vmx.display(), error = %err, "checkToolsState failed");
                        ToolsState::Unknown
                    }
                };
                let ip = if tools == ToolsState::Running {
                    vmware.guest_ip(&vmx).await.unwrap_or_else(|err| {
                        tracing::debug!(vmx = %vmx.display(), error = %err, "getGuestIPAddress failed");
                        None
                    })
                } else {
                    None
                };
                (index, tools, ip)
            });
        }
        while let Some(joined) = tasks.join_next().await {
            if let Ok((index, tools, ip)) = joined {
                found[index].tools_state = Some(tools.as_str().to_owned());
                found[index].ip_address = ip;
            }
        }
    }

    /// The VMs the last refresh found that match `filter` (VM-02).
    pub async fn list(&self, ctx: &Context, filter: &VmFilter) -> Result<Vec<VmRecord>> {
        let mut vms = self.store.list_vms(ctx).await?;
        vms.retain(|vm| filter.matches(vm));
        Ok(vms)
    }
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Resolves targets from the store so the policy engine sees their labels and protection.
pub struct StoreDirectory {
    store: Store,
}

impl StoreDirectory {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

#[async_trait]
impl TargetDirectory for StoreDirectory {
    async fn resolve(&self, ctx: &Context, target: &TargetRef) -> Result<Target> {
        match target {
            TargetRef::Vm { vmx_path } => {
                let known = self.store.find_vm(ctx, vmx_path).await?;
                Ok(match known {
                    Some(vm) => Target {
                        target: target.clone(),
                        name: vm.display_name,
                        environment: vm.environment,
                        protected: vm.protected,
                    },
                    // Not in the inventory yet: no label, not protected.
                    None => Target {
                        target: target.clone(),
                        name: file_stem(Path::new(vmx_path)),
                        environment: Environment::None,
                        protected: false,
                    },
                })
            }
            TargetRef::Session { session_id } => {
                let (name, environment, protected) = self
                    .store
                    .find_session_target(ctx, *session_id)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(session_id.to_string()))?;
                Ok(Target {
                    target: target.clone(),
                    name,
                    environment,
                    protected,
                })
            }
            TargetRef::App => Ok(Target {
                target: TargetRef::App,
                name: APP_NAME.to_owned(),
                environment: Environment::None,
                protected: false,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(name: &str) -> VmRecord {
        VmRecord {
            id: name.into(),
            vmx_path: format!(r"C:\VMs\{name}\{name}.vmx"),
            display_name: name.into(),
            guest_os: Some("ubuntu-64".into()),
            guest_os_name: Some("Ubuntu 24.04 LTS".into()),
            num_vcpus: Some(2),
            memsize_mb: Some(2048),
            power_state: PowerState::NotRunning,
            ip_address: None,
            tools_state: None,
            environment: Environment::Lab,
            protected: false,
            tags: vec![],
            last_seen_at: None,
        }
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        assert!(VmFilter::default().matches(&vm("web01")));
    }

    #[test]
    fn text_matches_name_path_os_ip_and_tags_without_case() {
        let mut web = vm("web01");
        web.ip_address = Some("192.0.2.10".into());
        web.tags = vec!["Frontend".into()];
        for text in ["WEB", r"c:\vms", "ubuntu 24", "192.0.2.10", "frontend"] {
            let f = VmFilter {
                text: text.into(),
                ..Default::default()
            };
            assert!(f.matches(&web), "{text}");
        }
        let miss = VmFilter {
            text: "db".into(),
            ..Default::default()
        };
        assert!(!miss.matches(&web));
    }

    #[test]
    fn fields_are_and_values_are_or() {
        let mut web = vm("web01");
        web.tags = vec!["lab-a".into()];
        web.power_state = PowerState::Running;

        let tag_or = VmFilter {
            tags: vec!["lab-b".into(), "LAB-A".into()],
            ..Default::default()
        };
        assert!(tag_or.matches(&web));

        let tag_and_state = VmFilter {
            tags: vec!["lab-a".into()],
            power_states: vec![PowerState::NotRunning, PowerState::Suspended],
            ..Default::default()
        };
        assert!(!tag_and_state.matches(&web), "right tag, wrong state");

        let env = VmFilter {
            environments: vec![Environment::Prod],
            ..Default::default()
        };
        assert!(!env.matches(&web));

        let protected = VmFilter {
            protected: Some(true),
            ..Default::default()
        };
        assert!(!protected.matches(&web));
        web.protected = true;
        assert!(protected.matches(&web));
    }

    #[test]
    fn filters_round_trip_through_json_and_default_missing_fields() {
        let f: VmFilter = serde_json::from_str(r#"{"tags":["lab"],"powerStates":["not_running"]}"#).unwrap();
        assert_eq!(f.tags, ["lab"]);
        assert_eq!(f.power_states, [PowerState::NotRunning]);
        assert_eq!(f.text, "");
        assert_eq!(
            serde_json::from_str::<VmFilter>(&serde_json::to_string(&f).unwrap()).unwrap(),
            f
        );
    }
}
