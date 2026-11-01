//! FD-04: what the job runner calls for a `Command::SupportBundle` ([`BundleActions`]): the job's bundle opens when
//! it starts, each host's items go into it as its target runs ([`super::collect::collect_host`], on a connection the
//! job runner made), each host's end is noted, and at the job's end the manifest goes in and the zip takes its name,
//! audited `data_exported`. A cancelled job, or one where no host gave a file, saves nothing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use uuid::Uuid;

use super::collect::{collect_host, BundleHost, HostReport};
use super::spec::{entry_names, BundleSpec};
use super::writer::{blocking, OpenBundle, Saved};
use crate::adapters::exec_output::human_bytes;
use crate::domain::{Context, Target};
use crate::error::{CoreError, Result};
use crate::jobs::TargetStatus;
use crate::locks;
use crate::save_guard::{self, Saved as SavedKind};
use crate::store::{NewAuditEntry, Store};

/// FD-04: the job runner's side of a support bundle.
#[async_trait]
pub trait BundleActions: Send + Sync {
    /// Opens the job's zip beside the chosen path and names each host's folder.
    async fn begin(&self, job_id: Uuid, spec: &BundleSpec, hosts: &[Target]) -> Result<()>;
    /// Collects the bundle's items from one host, on a connection the job runner made and checked.
    async fn collect(&self, job_id: Uuid, target: &Target, host: &dyn BundleHost) -> Result<HostReport>;
    /// Notes how the job ended for a host (for the manifest).
    fn host_finished(&self, job_id: Uuid, target: &str, status: TargetStatus, error: Option<&str>);
    /// Saves the bundle (or not, when `cancelled` or nothing was collected) and says what became of it.
    async fn end(&self, ctx: &Context, job_id: Uuid, targets: &[Target], cancelled: bool) -> Option<String>;
}

/// The bundles of the jobs running now.
pub struct BundleRunner {
    store: Store,
    open: Mutex<HashMap<Uuid, Arc<OpenBundle>>>,
}

impl BundleRunner {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            open: Mutex::new(HashMap::new()),
        }
    }

    fn bundle(&self, job_id: Uuid) -> Result<Arc<OpenBundle>> {
        locks::lock(&self.open)
            .get(&job_id)
            .cloned()
            .ok_or_else(|| CoreError::InvalidInput("the job's bundle is not open".into()))
    }

    async fn audit_saved(&self, ctx: &Context, job_id: Uuid, targets: &[Target], saved: &Saved) {
        let mut detail = format!(
            "{} from {}, {}",
            plural(saved.files, "file"),
            plural(saved.hosts, "host"),
            human_bytes(usize::try_from(saved.bytes).unwrap_or(usize::MAX))
        );
        if saved.redacted_files > 0 {
            detail.push_str(&format!(
                "; {} with something redacted",
                plural(saved.redacted_files, "file")
            ));
        }
        if saved.cut > 0 {
            detail.push_str(&format!("; {} cut or left out", plural(saved.cut, "item")));
        }
        detail.push_str(&format!(", to {}", saved.path.display()));
        let written = self
            .store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "data_exported",
                    action: "Saved a support bundle",
                    tier: None,
                    job_id: Some(job_id),
                    targets,
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await;
        if let Err(err) = written {
            tracing::error!(%job_id, error = %err, "could not audit a support bundle being saved");
        }
    }
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

#[async_trait]
impl BundleActions for BundleRunner {
    async fn begin(&self, job_id: Uuid, spec: &BundleSpec, hosts: &[Target]) -> Result<()> {
        let output = std::path::PathBuf::from(&spec.output);
        // Checked when it was asked for; the folder could have become a working tree since.
        save_guard::refuse_repository(&output, SavedKind::Bundle)?;
        let spec = spec.clone();
        let hosts = hosts.to_vec();
        let bundle = tokio::task::spawn_blocking(move || OpenBundle::create(job_id, &spec, &hosts))
            .await
            .map_err(|err| CoreError::InvalidInput(format!("the bundle could not be opened: {err}")))??;
        locks::lock(&self.open).insert(job_id, Arc::new(bundle));
        Ok(())
    }

    async fn collect(&self, job_id: Uuid, target: &Target, host: &dyn BundleHost) -> Result<HostReport> {
        let bundle = self.bundle(job_id)?;
        let items = bundle.spec().items.clone();
        let names = entry_names(&items);
        collect_host(&bundle, &target.target.key(), host, &items, &names).await
    }

    fn host_finished(&self, job_id: Uuid, target: &str, status: TargetStatus, error: Option<&str>) {
        if let Ok(bundle) = self.bundle(job_id) {
            bundle.record_end(target, status.as_str(), error);
        }
    }

    async fn end(&self, ctx: &Context, job_id: Uuid, targets: &[Target], cancelled: bool) -> Option<String> {
        let bundle = locks::lock(&self.open).remove(&job_id)?;
        if cancelled {
            let _ = blocking(&bundle, |b| {
                b.discard();
                Ok(())
            })
            .await;
            return Some("the job was cancelled, so no support bundle was saved".into());
        }
        match blocking(&bundle, |b| b.finish()).await {
            Ok(Some(saved)) => {
                self.audit_saved(ctx, job_id, targets, &saved).await;
                Some(format!(
                    "saved the support bundle ({}, {}) to {}",
                    plural(saved.files, "file"),
                    human_bytes(usize::try_from(saved.bytes).unwrap_or(usize::MAX)),
                    saved.path.display()
                ))
            }
            Ok(None) => Some("no host gave a file, so no support bundle was saved".into()),
            Err(err) => {
                tracing::error!(%job_id, error = %err, "could not save a support bundle");
                let _ = blocking(&bundle, |b| {
                    b.discard();
                    Ok(())
                })
                .await;
                Some(format!("the support bundle could not be saved: {err}"))
            }
        }
    }
}
