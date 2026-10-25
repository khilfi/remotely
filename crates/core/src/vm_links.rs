//! QL-01: links saved sessions to the VMs they reach (`sessions.vm_id`, BX-01). A link lets a bulk
//! run pick the VM and run commands through the session, and lets the dashboard show the guest's
//! own metrics (MO-02) on the VM's row.
//!
//! Auto-linking links a session when its host, or an address its host name resolves to, is a VM's
//! guest IP address (read through VMware Tools by the inventory refresh). It runs after every
//! inventory refresh, after a session is created or its host changes, and after an import. It
//! leaves a session alone when:
//! * the user chose, confirmed or removed its link (`manual`): a manual link is never overwritten;
//! * several VMs have the matching address: the user picks one ([`VmLinks::ambiguous`]);
//! * nothing matches now, while its VM has no address (stopped, or Tools not running).
//!
//! Host names are looked up gently (P3): a name is resolved once at a time and kept for
//! [`VmLinks::RESOLVED_FOR`] (one that did not resolve for [`VmLinks::FAILED_FOR`]); a pass waits at
//! most [`VmLinks::LOOKUPS_DEADLINE`] for its lookups and keeps every one that finished by then, while
//! the rest finish in the background for the next pass. A session behind a jump host (SS-07) is never
//! looked up: its name is one the far network knows, and asking this PC's resolvers would send it out
//! on the customer's LAN (LLMNR, NetBIOS). It still links when its host is an IP address.
//!
//! An automatic link follows the addresses: it moves when another VM now has the session's address,
//! and goes when its VM has another address now. Linking is the app's own data: it skips the command
//! bus, has no approval tier and every change is audited like a setting. A link can only make a
//! session stricter: a Prod or protected VM makes its sessions count as Prod or protected
//! (`Store::find_session_target`).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::adapters::network::{ip_literal, NetworkAdapter};
use crate::domain::{Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::presentation::Change;
use crate::sessions::SessionRecord;
use crate::store::{NewAuditEntry, Store, VmRecord};

/// How a session's VM link was made (`sessions.vm_link`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmLink {
    /// Made by auto-linking and not confirmed; auto-linking keeps it up to date.
    Auto,
    /// Chosen, confirmed or removed by the user; auto-linking never changes it.
    Manual,
}

impl VmLink {
    pub fn as_str(self) -> &'static str {
        match self {
            VmLink::Auto => "auto",
            VmLink::Manual => "manual",
        }
    }

    /// Unknown values read as `None` (no decision) rather than failing a read.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(VmLink::Auto),
            "manual" => Some(VmLink::Manual),
            _ => None,
        }
    }
}

/// A link auto-linking made, moved or removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkChange {
    pub session_id: Uuid,
    pub session_name: String,
    pub vm_id: String,
    pub vm_name: String,
}

/// A session whose address several VMs have: auto-linking leaves the choice to the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AmbiguousLink {
    pub session_id: Uuid,
    /// The matching VMs' ids, by name.
    pub vm_ids: Vec<String>,
}

/// What one auto-linking pass changed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoLinkReport {
    pub linked: Vec<LinkChange>,
    pub unlinked: Vec<LinkChange>,
    pub ambiguous: Vec<AmbiguousLink>,
}

/// A VM auto-linking can match: its id and the guest IP address the last refresh read, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VmAddress {
    pub vm_id: String,
    pub ip: Option<IpAddr>,
}

/// What auto-linking does with one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    Keep,
    /// Link (or move the link) to this VM, which has `ip`.
    Link {
        vm_id: String,
        ip: IpAddr,
    },
    /// Remove the automatic link: its VM has another address now.
    Unlink,
    /// Several VMs have the session's address. `unlink`: its automatic link goes too (stale).
    Ambiguous {
        vm_ids: Vec<String>,
        unlink: bool,
    },
}

/// The rules for one session. `addresses`: what its host is or resolves to, or `None` when that is
/// not known right now (the name did not resolve in time), which changes nothing.
pub(crate) fn decide(
    vm_id: Option<&str>,
    link: Option<VmLink>,
    addresses: Option<&[IpAddr]>,
    vms: &[VmAddress],
) -> Decision {
    // A link without a kind predates auto-linking: the user chose it.
    let automatic = match link {
        Some(VmLink::Manual) => return Decision::Keep,
        Some(VmLink::Auto) => true,
        None if vm_id.is_some() => return Decision::Keep,
        None => false,
    };
    let Some(addresses) = addresses else {
        return Decision::Keep;
    };
    let mut seen = HashSet::new();
    let matches: Vec<(&str, IpAddr)> = vms
        .iter()
        .filter_map(|vm| Some((vm.vm_id.as_str(), vm.ip.filter(|ip| addresses.contains(ip))?)))
        .filter(|(id, _)| seen.insert(*id))
        .collect();
    let current = vm_id.and_then(|id| vms.iter().find(|vm| vm.vm_id == id));
    // The automatic link's VM has an address now, and it is not the session's.
    let stale = automatic && current.and_then(|vm| vm.ip).is_some_and(|ip| !addresses.contains(&ip));
    match matches.as_slice() {
        [] if stale => Decision::Unlink,
        [] => Decision::Keep,
        [(id, _)] if Some(*id) == vm_id => Decision::Keep,
        [(id, ip)] => Decision::Link {
            vm_id: (*id).to_owned(),
            ip: *ip,
        },
        many if many.iter().any(|(id, _)| Some(*id) == vm_id) => Decision::Keep,
        // Linked to a VM that has no address now: nothing says the link is wrong.
        _ if automatic && vm_id.is_some() && !stale => Decision::Keep,
        many => Decision::Ambiguous {
            vm_ids: many.iter().map(|(id, _)| (*id).to_owned()).collect(),
            unlink: stale,
        },
    }
}

/// A host's addresses, as last resolved. `None`: it did not resolve.
struct Resolved {
    at: Instant,
    addresses: Option<Vec<IpAddr>>,
}

impl Resolved {
    fn fresh(&self) -> bool {
        let keep = if self.addresses.is_some() {
            VmLinks::RESOLVED_FOR
        } else {
            VmLinks::FAILED_FOR
        };
        self.at.elapsed() < keep
    }
}

/// Names looked up lately, by lower-case name, and those being looked up now.
#[derive(Default)]
struct Lookups {
    resolved: HashMap<String, Resolved>,
    in_flight: HashSet<String>,
}

/// A lookup in progress. It counts as in flight until it is dropped, even if its task is aborted.
struct InFlight {
    lookups: Arc<Mutex<Lookups>>,
    key: String,
}

impl InFlight {
    /// Keeps what the lookup found (or that it found nothing) for the next passes.
    fn finish(&self, addresses: Option<Vec<IpAddr>>) {
        locks::lock(&self.lookups).resolved.insert(
            self.key.clone(),
            Resolved {
                at: Instant::now(),
                addresses,
            },
        );
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        locks::lock(&self.lookups).in_flight.remove(&self.key);
    }
}

/// Saved sessions' links to VMs: automatic ones and the user's choices.
pub struct VmLinks {
    store: Store,
    /// Forward DNS lookups of session host names.
    network: Arc<dyn NetworkAdapter>,
    /// Shared with lookups that outlive their pass.
    cache: Arc<Mutex<Lookups>>,
    /// Sessions whose address several VMs have, from the latest pass.
    ambiguous: Mutex<HashMap<Uuid, Vec<String>>>,
    /// One pass at a time, so two passes can't each link the same session.
    pass: tokio::sync::Mutex<()>,
    /// [`Self::LOOKUPS_DEADLINE`], unless a test shortens it.
    deadline: Mutex<Duration>,
}

impl VmLinks {
    /// How long a resolved name is reused before it is looked up again.
    pub const RESOLVED_FOR: Duration = Duration::from_secs(10 * 60);
    /// How long a name that did not resolve waits before it is tried again.
    pub const FAILED_FOR: Duration = Duration::from_secs(2 * 60);
    /// One lookup's limit.
    pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
    /// A whole pass's lookups together, so many names that don't resolve can't hold up a refresh.
    pub const LOOKUPS_DEADLINE: Duration = Duration::from_secs(3);
    const LOOKUPS_AT_ONCE: usize = 16;

    pub fn new(store: Store, network: Arc<dyn NetworkAdapter>) -> Self {
        Self {
            store,
            network,
            cache: Arc::default(),
            ambiguous: Mutex::default(),
            pass: tokio::sync::Mutex::new(()),
            deadline: Mutex::new(Self::LOOKUPS_DEADLINE),
        }
    }

    /// Tests shorten how long a pass waits for its lookups.
    pub fn set_lookups_deadline(&self, deadline: Duration) {
        *locks::lock(&self.deadline) = deadline;
    }

    /// Links every session the rules allow (see the module docs). Never fails a refresh over a name
    /// that does not resolve: that session is left as it is.
    pub async fn auto_link(&self, ctx: &Context) -> Result<AutoLinkReport> {
        self.run(ctx, None).await
    }

    /// The same for one session, after it was created or its host changed.
    pub async fn auto_link_session(&self, ctx: &Context, session_id: Uuid) -> Result<AutoLinkReport> {
        self.run(ctx, Some(session_id)).await
    }

    /// Sessions several VMs match, as the latest pass found them.
    pub fn ambiguous(&self) -> Vec<AmbiguousLink> {
        let mut out: Vec<AmbiguousLink> = locks::lock(&self.ambiguous)
            .iter()
            .map(|(id, vm_ids)| AmbiguousLink {
                session_id: *id,
                vm_ids: vm_ids.clone(),
            })
            .collect();
        out.sort_by_key(|a| a.session_id);
        out
    }

    async fn run(&self, ctx: &Context, only: Option<Uuid>) -> Result<AutoLinkReport> {
        let _pass = self.pass.lock().await;
        let sessions: Vec<SessionRecord> = self
            .store
            .list_sessions(ctx)
            .await?
            .into_iter()
            .filter(|s| only.is_none_or(|id| s.id == id))
            .filter(|s| !matches!(s.vm_link, Some(VmLink::Manual)) && (s.vm_link.is_some() || s.vm_id.is_none()))
            .collect();
        let vms = self.store.list_vms(ctx).await?;
        let addresses: Vec<VmAddress> = vms
            .iter()
            .map(|vm| VmAddress {
                vm_id: vm.id.clone(),
                ip: vm.ip_address.as_deref().and_then(ip_literal),
            })
            .collect();
        let by_id: HashMap<&str, &VmRecord> = vms.iter().map(|vm| (vm.id.as_str(), vm)).collect();
        // No VM has an address (none running, or the VM list not read yet): nothing can match or go
        // stale, so no name is looked up. SS-07: nor is the name of a session behind a jump host.
        let hosts: Vec<String> = if addresses.iter().any(|vm| vm.ip.is_some()) {
            sessions
                .iter()
                .filter(|s| s.jump_session_id.is_none() || ip_literal(&s.host).is_some())
                .map(|s| s.host.clone())
                .collect()
        } else {
            Vec::new()
        };
        let resolved = self.resolve(hosts).await;

        let mut report = AutoLinkReport::default();
        let mut ambiguous: HashMap<Uuid, Vec<String>> = HashMap::new();
        for session in &sessions {
            let found = resolved.get(&session.host).and_then(|a| a.as_deref());
            let decision = decide(session.vm_id.as_deref(), session.vm_link, found, &addresses);
            match decision {
                Decision::Keep => {}
                Decision::Link { vm_id, ip } => {
                    let Some(vm) = by_id.get(vm_id.as_str()) else { continue };
                    if self
                        .store
                        .set_auto_vm_link(ctx, session.id, session.vm_id.as_deref(), Some(&vm_id))
                        .await?
                    {
                        let previous = session.vm_id.as_deref().and_then(|id| by_id.get(id)).copied();
                        self.audit_auto_link(ctx, session, vm, ip, previous).await?;
                        report.linked.push(change(session, vm));
                    }
                }
                Decision::Unlink => self.unlink_stale(ctx, session, &by_id, &mut report).await?,
                Decision::Ambiguous { vm_ids, unlink } => {
                    if unlink {
                        self.unlink_stale(ctx, session, &by_id, &mut report).await?;
                    }
                    let mut names: Vec<(&str, String)> = vm_ids
                        .iter()
                        .map(|id| {
                            (
                                by_id.get(id.as_str()).map_or("", |v| v.display_name.as_str()),
                                id.clone(),
                            )
                        })
                        .collect();
                    names.sort_by_key(|(name, _)| name.to_lowercase());
                    let vm_ids: Vec<String> = names.into_iter().map(|(_, id)| id).collect();
                    report.ambiguous.push(AmbiguousLink {
                        session_id: session.id,
                        vm_ids: vm_ids.clone(),
                    });
                    ambiguous.insert(session.id, vm_ids);
                }
            }
        }
        let mut kept = locks::lock(&self.ambiguous);
        match only {
            Some(id) => {
                kept.remove(&id);
                kept.extend(ambiguous);
            }
            None => *kept = ambiguous,
        }
        Ok(report)
    }

    async fn unlink_stale(
        &self,
        ctx: &Context,
        session: &SessionRecord,
        by_id: &HashMap<&str, &VmRecord>,
        report: &mut AutoLinkReport,
    ) -> Result<()> {
        let Some(vm) = session.vm_id.as_deref().and_then(|id| by_id.get(id)).copied() else {
            return Ok(());
        };
        if !self.store.set_auto_vm_link(ctx, session.id, Some(&vm.id), None).await? {
            return Ok(());
        }
        let detail = format!(
            "the VM's IP address is now {}, and {} does not reach it",
            vm.ip_address.as_deref().unwrap_or("unknown"),
            session.host
        );
        self.audit(
            ctx,
            &format!(
                "Unlinked session {} from VM {} automatically",
                quoted(&session.name),
                quoted(&vm.display_name)
            ),
            session,
            Some(vm),
            &detail,
        )
        .await?;
        report.unlinked.push(change(session, vm));
        Ok(())
    }

    /// What each host is or resolves to. IP literals need no lookup; names come from the cache while
    /// it is fresh, otherwise from DNS, many at once, within [`Self::LOOKUPS_DEADLINE`]. Every lookup
    /// that finished by then counts; a name still being looked up maps to `None` (unknown this time),
    /// and its lookup goes on in the background and keeps its answer for the next pass. A name
    /// another pass is looking up already is not looked up again.
    async fn resolve(&self, hosts: Vec<String>) -> HashMap<String, Option<Vec<IpAddr>>> {
        let mut out = HashMap::new();
        let mut lookups: Vec<(String, InFlight)> = Vec::new();
        {
            let mut cache = locks::lock(&self.cache);
            for host in hosts {
                if out.contains_key(&host) || lookups.iter().any(|(h, _)| h == &host) {
                    continue;
                }
                if let Some(ip) = ip_literal(&host) {
                    out.insert(host, Some(vec![ip]));
                    continue;
                }
                let key = host.to_ascii_lowercase();
                match cache.resolved.get(&key) {
                    Some(hit) if hit.fresh() => {
                        out.insert(host, hit.addresses.clone());
                    }
                    _ if cache.in_flight.contains(&key) => {}
                    _ => {
                        cache.in_flight.insert(key.clone());
                        let guard = InFlight {
                            lookups: Arc::clone(&self.cache),
                            key,
                        };
                        lookups.push((host, guard));
                    }
                }
            }
        }
        if lookups.is_empty() {
            return out;
        }
        let limit = Arc::new(Semaphore::new(Self::LOOKUPS_AT_ONCE));
        let mut tasks = JoinSet::new();
        for (host, guard) in lookups {
            let network = Arc::clone(&self.network);
            let limit = Arc::clone(&limit);
            tasks.spawn(async move {
                let _permit = limit.acquire_owned().await.ok();
                let found = tokio::time::timeout(Self::LOOKUP_TIMEOUT, network.resolve(&host)).await;
                let addresses = match found {
                    Ok(Ok(addresses)) if !addresses.is_empty() => Some(addresses),
                    Ok(Ok(_)) => None,
                    Ok(Err(err)) => {
                        tracing::debug!(host = %host, error = %err, "host name did not resolve");
                        None
                    }
                    Err(_) => {
                        tracing::debug!(host = %host, "host name lookup timed out");
                        None
                    }
                };
                guard.finish(addresses.clone());
                (host, addresses)
            });
        }
        let deadline = tokio::time::Instant::now() + *locks::lock(&self.deadline);
        loop {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(Ok((host, addresses)))) => {
                    out.insert(host, addresses);
                }
                Ok(Some(Err(_))) => {}
                Ok(None) => break,
                Err(_) => {
                    // Names still looking up are unknown this time. Their lookups finish on their own,
                    // each within its timeout, and keep the answer for the next pass.
                    tracing::debug!(
                        unfinished = tasks.len(),
                        "host name lookups ran out of time; the rest finish in the background"
                    );
                    tasks.detach_all();
                    break;
                }
            }
        }
        out
    }

    /// The user's choice: links the session to `vm_id`, or removes its link with `None`. Auto-linking
    /// never changes it afterwards (until the session's host changes). Audited.
    pub async fn link(&self, ctx: &Context, session_id: Uuid, vm_id: Option<String>) -> Result<SessionRecord> {
        self.store.read_only().check(Change::VmLinks)?;
        let _pass = self.pass.lock().await;
        let session = self.session(ctx, session_id).await?;
        let vm = match vm_id.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            Some(id) => Some(self.store.vm_by_id(ctx, id).await?.ok_or_else(|| {
                CoreError::InvalidInput("That VM is not in the VM list. Refresh the VMs and choose it again.".into())
            })?),
            None => None,
        };
        let new_id = vm.as_ref().map(|v| v.id.clone());
        if session.vm_id == new_id && session.vm_link == Some(VmLink::Manual) {
            return Ok(session);
        }
        self.store
            .set_manual_vm_link(ctx, session_id, new_id.as_deref())
            .await?;
        locks::lock(&self.ambiguous).remove(&session_id);
        let before = match session.vm_id.as_deref() {
            Some(id) => self.store.vm_by_id(ctx, id).await?,
            None => None,
        };
        match (&vm, &before) {
            (Some(vm), before) => {
                let detail = match before {
                    Some(old) if old.id == vm.id => "confirmed by hand; auto-linking won't change it".to_owned(),
                    Some(old) => format!(
                        "chosen by hand instead of VM {}; auto-linking won't change it",
                        quoted(&old.display_name)
                    ),
                    None => "chosen by hand; auto-linking won't change it".to_owned(),
                };
                self.audit(
                    ctx,
                    &format!(
                        "Linked session {} to VM {}",
                        quoted(&session.name),
                        quoted(&vm.display_name)
                    ),
                    &session,
                    Some(vm),
                    &detail,
                )
                .await?;
            }
            (None, Some(old)) => {
                self.audit(
                    ctx,
                    &format!(
                        "Unlinked session {} from VM {}",
                        quoted(&session.name),
                        quoted(&old.display_name)
                    ),
                    &session,
                    Some(old),
                    "auto-linking won't link it again until its host changes",
                )
                .await?;
            }
            (None, None) => {
                self.audit(
                    ctx,
                    &format!("Turned off auto-linking for session {}", quoted(&session.name)),
                    &session,
                    None,
                    "it stays without a VM until one is chosen or its host changes",
                )
                .await?;
            }
        }
        self.session(ctx, session_id).await
    }

    /// The user keeps an automatic link: it becomes manual, so auto-linking never changes it.
    pub async fn confirm(&self, ctx: &Context, session_id: Uuid) -> Result<SessionRecord> {
        self.store.read_only().check(Change::VmLinks)?;
        let session = self.session(ctx, session_id).await?;
        match (&session.vm_id, session.vm_link) {
            (Some(id), Some(VmLink::Auto)) => self.link(ctx, session_id, Some(id.clone())).await,
            (Some(_), _) => Ok(session),
            (None, _) => Err(CoreError::InvalidInput(format!(
                "{} is not linked to a VM, so there is nothing to confirm.",
                quoted(&session.name)
            ))),
        }
    }

    async fn session(&self, ctx: &Context, id: Uuid) -> Result<SessionRecord> {
        self.store
            .get_session(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("session {id}")))
    }

    async fn audit_auto_link(
        &self,
        ctx: &Context,
        session: &SessionRecord,
        vm: &VmRecord,
        ip: IpAddr,
        previous: Option<&VmRecord>,
    ) -> Result<()> {
        let mut detail = if ip_literal(&session.host).is_some() {
            format!("{ip} is the VM's IP address (VMware Tools)")
        } else {
            format!("{} resolves to {ip}, the VM's IP address (VMware Tools)", session.host)
        };
        if let Some(previous) = previous {
            detail.push_str(&format!("; it was linked to VM {}", quoted(&previous.display_name)));
        }
        self.audit(
            ctx,
            &format!(
                "Linked session {} to VM {} automatically",
                quoted(&session.name),
                quoted(&vm.display_name)
            ),
            session,
            Some(vm),
            &detail,
        )
        .await
    }

    async fn audit(
        &self,
        ctx: &Context,
        action: &str,
        session: &SessionRecord,
        vm: Option<&VmRecord>,
        detail: &str,
    ) -> Result<()> {
        let mut targets = vec![session.target()];
        if let Some(vm) = vm {
            targets.push(Target {
                target: TargetRef::Vm {
                    vmx_path: vm.vmx_path.clone(),
                },
                name: vm.display_name.clone(),
                environment: vm.environment,
                protected: vm.protected,
            });
        }
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "session_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: &targets,
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }
}

fn change(session: &SessionRecord, vm: &VmRecord) -> LinkChange {
    LinkChange {
        session_id: session.id,
        session_name: session.name.clone(),
        vm_id: vm.id.clone(),
        vm_name: vm.display_name.clone(),
    }
}

fn quoted(name: &str) -> String {
    format!("'{name}'")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn vm(id: &str, address: Option<&str>) -> VmAddress {
        VmAddress {
            vm_id: id.into(),
            ip: address.map(ip),
        }
    }

    fn lab() -> Vec<VmAddress> {
        vec![
            vm("web", Some("192.0.2.10")),
            vm("db", Some("192.0.2.20")),
            vm("off", None),
            // A clone that came up with web's address on another virtual network.
            vm("web-clone", Some("198.51.100.10")),
        ]
    }

    #[test]
    fn one_matching_vm_is_linked() {
        let found = [ip("192.0.2.20")];
        assert_eq!(
            decide(None, None, Some(&found), &lab()),
            Decision::Link {
                vm_id: "db".into(),
                ip: ip("192.0.2.20")
            }
        );
        // Any of the addresses a name resolves to.
        let found = [ip("203.0.113.5"), ip("192.0.2.10")];
        assert!(matches!(decide(None, None, Some(&found), &lab()), Decision::Link { vm_id, .. } if vm_id == "web"));
        // Already linked there: nothing to do.
        assert_eq!(
            decide(Some("web"), Some(VmLink::Auto), Some(&found), &lab()),
            Decision::Keep
        );
    }

    #[test]
    fn no_match_links_nothing() {
        let found = [ip("203.0.113.99")];
        assert_eq!(decide(None, None, Some(&found), &lab()), Decision::Keep);
        // The name did not resolve: nothing is known, nothing changes.
        assert_eq!(decide(None, None, None, &lab()), Decision::Keep);
        assert_eq!(decide(Some("web"), Some(VmLink::Auto), None, &lab()), Decision::Keep);
    }

    #[test]
    fn several_matches_leave_the_choice_to_the_user() {
        let mut vms = lab();
        vms[3].ip = Some(ip("192.0.2.10"));
        let found = [ip("192.0.2.10")];
        assert_eq!(
            decide(None, None, Some(&found), &vms),
            Decision::Ambiguous {
                vm_ids: vec!["web".into(), "web-clone".into()],
                unlink: false
            }
        );
        // Already linked to one of them: it stays.
        assert_eq!(
            decide(Some("web-clone"), Some(VmLink::Auto), Some(&found), &vms),
            Decision::Keep
        );
        // Linked automatically to a VM that has another address now: that link goes too.
        assert_eq!(
            decide(Some("db"), Some(VmLink::Auto), Some(&found), &vms),
            Decision::Ambiguous {
                vm_ids: vec!["web".into(), "web-clone".into()],
                unlink: true
            }
        );
        // Linked to a VM with no address now (stopped): nothing says it is wrong.
        assert_eq!(
            decide(Some("off"), Some(VmLink::Auto), Some(&found), &vms),
            Decision::Keep
        );
    }

    #[test]
    fn manual_links_are_never_changed() {
        let found = [ip("192.0.2.10")];
        for vm_id in [None, Some("db"), Some("off")] {
            assert_eq!(
                decide(vm_id, Some(VmLink::Manual), Some(&found), &lab()),
                Decision::Keep,
                "{vm_id:?}"
            );
        }
        // A link from before auto-linking existed counts as manual.
        assert_eq!(decide(Some("db"), None, Some(&found), &lab()), Decision::Keep);
    }

    #[test]
    fn automatic_links_follow_the_addresses() {
        let found = [ip("192.0.2.10")];
        // Another VM has the session's address now.
        assert_eq!(
            decide(Some("db"), Some(VmLink::Auto), Some(&found), &lab()),
            Decision::Link {
                vm_id: "web".into(),
                ip: ip("192.0.2.10")
            }
        );
        // Its VM is off and another one has the address: the session reaches that one.
        assert!(matches!(
            decide(Some("off"), Some(VmLink::Auto), Some(&found), &lab()),
            Decision::Link { vm_id, .. } if vm_id == "web"
        ));
        // Nothing matches; its VM has another address now: the link goes.
        let elsewhere = [ip("203.0.113.7")];
        assert_eq!(
            decide(Some("db"), Some(VmLink::Auto), Some(&elsewhere), &lab()),
            Decision::Unlink
        );
        // Nothing matches; its VM has no address (stopped): the link stays for when it starts.
        assert_eq!(
            decide(Some("off"), Some(VmLink::Auto), Some(&elsewhere), &lab()),
            Decision::Keep
        );
    }

    #[test]
    fn link_kinds_round_trip() {
        for link in [VmLink::Auto, VmLink::Manual] {
            assert_eq!(VmLink::parse(link.as_str()), Some(link));
        }
        assert_eq!(VmLink::parse("other"), None);
        assert_eq!(serde_json::to_string(&VmLink::Auto).unwrap(), r#""auto""#);
    }
}
