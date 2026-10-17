//! Inventory reads (VM-01). Reads skip the command bus: they go to the adapter and the store only.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;

use crate::adapters::vmware::VmwareAdapter;
use crate::command_bus::TargetDirectory;
use crate::domain::{Context, Environment, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::store::{DiscoveredVm, Store, VmRecord};

/// How the app names itself in dialogs, jobs and the audit log.
pub const APP_NAME: &str = "Remotely";

pub struct Inventory {
    store: Store,
    vmware: Arc<dyn VmwareAdapter>,
}

impl Inventory {
    pub fn new(store: Store, vmware: Arc<dyn VmwareAdapter>) -> Self {
        Self { store, vmware }
    }

    /// Asks Workstation which VMs are running (`vmrun list`), reads each .vmx, saves the result and
    /// returns the running VMs. A .vmx that cannot be read still lists, with its file name.
    pub async fn refresh_running(&self, ctx: &Context) -> Result<Vec<VmRecord>> {
        let paths = self.vmware.list_running().await?;
        let mut found = Vec::with_capacity(paths.len());
        for path in paths {
            let info = match self.vmware.read_vmx(&path).await {
                Ok(info) => info,
                Err(err) => {
                    tracing::warn!(vmx = %path.display(), error = %err, "could not read .vmx");
                    Default::default()
                }
            };
            found.push(DiscoveredVm {
                vmx_path: path.to_string_lossy().into_owned(),
                info,
            });
        }
        self.store.record_running_vms(ctx, &found).await
    }

    pub async fn list(&self, ctx: &Context) -> Result<Vec<VmRecord>> {
        self.store.list_vms(ctx, None).await
    }
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
                        name: Path::new(vmx_path)
                            .file_stem()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| vmx_path.clone()),
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
