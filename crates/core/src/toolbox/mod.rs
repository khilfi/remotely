//! FD-09 toolbox: ping, trace route, DNS lookups, port checks, the certificate viewer and Wake-on-LAN, run from this
//! PC. The subnet calculator is the UI's own (pure TypeScript).
//!
//! Every tool but Wake-on-LAN only reads: no tier, not audited, allowed while presenting with the read-only lock
//! (FD-03), like QL-04's checks. Wake-on-LAN sends a packet to the network, so it is
//! [`crate::command_bus::Command::WakeOnLan`] on the bus: Low, Medium on a Prod target, audited.
//!
//! * **Targets.** A host typed in, a saved session (its host), or a VM (its guest IP) ([`ProbeTarget`]).
//! * **Jump hosts (SS-07).** A session behind a jump host is reached from that jump host: port and certificate checks
//!   open a direct-tcpip channel on its connection (an open terminal's, else a kept one of the toolbox's own, logged in
//!   through [`crate::login_guard`]'s parks and caps, closed when idle, when the vault locks or the workspace
//!   switches). Ping and trace route go from this PC only, so for such a session they say why they can't.
//! * **One probe on its own.** Each tool is a function of the core with a timeout and a cancel token, and reports
//!   each reply, hop or port as it comes ([`ProbeProgress`]). F2's health checks (MO-08) schedule the same probes.
//! * **Caps.** A port check takes at most [`ports::MAX_PORTS`] ports (it isn't a scanner: FD-10's subnet discovery
//!   stays out); a ping at most [`icmp::MAX_COUNT`] requests, at least a second apart; a trace 30 hops.

pub mod certs;
pub mod dns;
pub mod icmp;
mod jump;
pub mod ports;
pub mod wake;
pub mod x509;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::adapters::net_tools::{BoxedStream, ConnectFailure, NetworkTools};
use crate::adapters::network::NetworkAdapter;
use crate::adapters::remote::{ExecSession, RemoteAdapter};
use crate::domain::{Context, TargetRef};
use crate::error::{CoreError, Result};
use crate::host_details::HostDetails;
use crate::known_hosts::KnownHosts;
use crate::login_guard::LoginGuard;
use crate::store::Store;
use crate::terminal::Terminals;
use crate::vault::Vault;

pub use certs::{CertRequest, CertificateReport};
pub use dns::{DnsRequest, DnsResult};
pub use icmp::{PingReply, PingRequest, PingSummary, TraceHop, TraceRequest, TraceSummary};
pub use ports::{PortRequest, PortResult, PortSummary};
pub use wake::{KnownMac, WakeAdapter, WakeDestination, WakeSpec};

/// What a tool is pointed at.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ProbeTarget {
    /// A host name or IP address typed in.
    Address { host: String },
    /// A saved session: its host, through its jump host when it has one.
    Session { session_id: Uuid },
    /// A VM, by its key (.vmx path or VirtualBox UUID): its guest IP address.
    Vm { vm_key: String },
}

/// Where a probe goes, after the target was looked up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    /// The host name or address probed.
    pub host: String,
    /// For the result's title: the session's or VM's name, else the host.
    pub label: String,
    /// SS-07: the session's own jump host, which opens the connection to `host`.
    pub via: Option<JumpHost>,
    /// The session's port (its kind's: SSH, RDP, VNC or Telnet), for a port check that names none.
    pub port: Option<u16>,
}

/// A jump host a probe goes through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JumpHost {
    pub session_id: Uuid,
    pub name: String,
}

/// One reply, hop or port, as it comes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ProbeProgress {
    Ping { reply: PingReply },
    Hop { hop: TraceHop },
    Port { result: PortResult },
}

/// Where a run's progress goes (the shell sends it to the window).
pub type Progress<'a> = &'a (dyn Fn(ProbeProgress) + Send + Sync);

/// What the toolbox needs from the rest of the core.
pub struct ToolboxParts {
    pub store: Store,
    pub tools: Arc<dyn NetworkTools>,
    pub network: Arc<dyn NetworkAdapter>,
    /// Kept connections to jump hosts (the core's tracked adapter, so QL-04 skips their hosts).
    pub remote: Arc<dyn RemoteAdapter>,
    pub vault: Arc<dyn Vault>,
    pub known_hosts: Arc<KnownHosts>,
    pub login_guard: LoginGuard,
    pub terminals: Terminals,
    /// MO-13: a VM's MACs for Wake-on-LAN.
    pub host_details: HostDetails,
}

/// The toolbox. Cloning gives another handle to the same one.
#[derive(Clone)]
pub struct Toolbox {
    inner: Arc<Inner>,
}

struct Inner {
    store: Store,
    tools: Arc<dyn NetworkTools>,
    network: Arc<dyn NetworkAdapter>,
    host_details: HostDetails,
    jumps: jump::JumpConnections,
}

/// How a probe that connects reaches the host: from this PC to an address, or from a jump host to a name.
#[derive(Clone)]
pub(crate) enum Reach {
    Direct {
        tools: Arc<dyn NetworkTools>,
        address: IpAddr,
    },
    Jump {
        connection: Arc<dyn ExecSession>,
        jump: String,
        host: String,
    },
}

impl Reach {
    /// Opens a connection to `port`, within `timeout`.
    pub(crate) async fn open(&self, port: u16, timeout: Duration) -> std::result::Result<BoxedStream, ConnectFailure> {
        match self {
            Reach::Direct { tools, address } => tools.connect(std::net::SocketAddr::new(*address, port), timeout).await,
            Reach::Jump { connection, host, .. } => {
                match tokio::time::timeout(timeout, connection.open_direct(host, port)).await {
                    Ok(opened) => opened,
                    Err(_) => Err(ConnectFailure::TimedOut),
                }
            }
        }
    }

    /// The address probed from this PC, or `None` behind a jump host (it resolves the name itself).
    pub(crate) fn address(&self) -> Option<IpAddr> {
        match self {
            Reach::Direct { address, .. } => Some(*address),
            Reach::Jump { .. } => None,
        }
    }

    pub(crate) fn via(&self) -> Option<String> {
        match self {
            Reach::Direct { .. } => None,
            Reach::Jump { jump, .. } => Some(jump.clone()),
        }
    }
}

impl Toolbox {
    pub fn new(parts: ToolboxParts) -> Self {
        let jumps = jump::JumpConnections::new(jump::JumpParts {
            store: parts.store.clone(),
            remote: parts.remote,
            vault: parts.vault,
            known_hosts: parts.known_hosts,
            guard: parts.login_guard,
            terminals: parts.terminals,
        });
        let inner = Arc::new(Inner {
            store: parts.store,
            tools: parts.tools,
            network: parts.network,
            host_details: parts.host_details,
            jumps,
        });
        // Kept connections to jump hosts close on their own when idle, like host details' (QL-04 then checks the
        // jump host again).
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(&inner);
            let wake = inner.jumps.wake();
            runtime.spawn(async move {
                // Ends once the toolbox is gone.
                while let Some(every) = weak.upgrade().map(|inner| inner.jumps.sweep_every()) {
                    tokio::select! {
                        () = tokio::time::sleep(every) => {}
                        () = wake.notified() => {}
                    }
                    let Some(inner) = weak.upgrade() else {
                        break;
                    };
                    inner.jumps.close_idle().await;
                }
            });
        }
        Self { inner }
    }

    /// The probes, for F2's health checks and the job runner.
    pub fn tools(&self) -> Arc<dyn NetworkTools> {
        Arc::clone(&self.inner.tools)
    }

    /// SS-04, FD-02: the kept connections to jump hosts close (the vault locked, or the workspace changed).
    pub async fn close_all(&self) {
        self.inner.jumps.close_all().await;
    }

    /// How long a kept connection to a jump host may sit unused (2 minutes); tests shorten it.
    pub fn set_jump_idle(&self, idle: Duration) {
        self.inner.jumps.set_idle(idle);
    }

    /// The toolbox's own kept connections to jump hosts open now (an open terminal's are not counted).
    pub fn kept_jump_connections(&self) -> usize {
        self.inner.jumps.kept_open()
    }

    /// Where `target` is: a typed host as it is, a session's host (with its jump host), a VM's guest IP.
    pub async fn route(&self, ctx: &Context, target: &ProbeTarget) -> Result<Route> {
        match target {
            ProbeTarget::Address { host } => {
                let host = check_host(host)?;
                Ok(Route {
                    label: host.clone(),
                    host,
                    via: None,
                    port: None,
                })
            }
            ProbeTarget::Session { session_id } => {
                let session = self
                    .inner
                    .store
                    .get_session(ctx, *session_id)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(format!("session {session_id}")))?;
                // SS-12: a serial session's host is its COM port, no network address to probe.
                if !session.kind.has_port() {
                    return Err(CoreError::WrongSessionKind {
                        session: session.name.clone(),
                        kind: session.kind.label(),
                        needs: "it has no network address to check".into(),
                    });
                }
                let via = match session.jump_session_id {
                    Some(jump_id) => {
                        let jump = self.inner.store.get_session(ctx, jump_id).await?;
                        Some(JumpHost {
                            session_id: jump_id,
                            name: jump.map_or_else(|| "its jump host".to_owned(), |j| j.name),
                        })
                    }
                    None => None,
                };
                Ok(Route {
                    host: check_host(&session.host)?,
                    label: session.name,
                    via,
                    port: Some(session.port),
                })
            }
            ProbeTarget::Vm { vm_key } => {
                self.inner.store.require_vm_here(ctx, vm_key).await?;
                let vm = self
                    .inner
                    .store
                    .find_vm(ctx, vm_key)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(vm_key.clone()))?;
                let Some(ip) = vm.ip_address.filter(|ip| !ip.trim().is_empty()) else {
                    return Err(CoreError::InvalidInput(format!(
                        "'{}' has no IP address yet: start it, and its guest tools report one.",
                        vm.display_name
                    )));
                };
                Ok(Route {
                    host: check_host(&ip)?,
                    label: vm.display_name,
                    via: None,
                    port: None,
                })
            }
        }
    }

    /// The address this PC probes for a host, in the resolver's order (IPv4 first when it has both: what `ping` does
    /// with a name).
    pub(crate) async fn address_of(&self, host: &str) -> Result<IpAddr> {
        let found = self.inner.network.resolve(host).await?;
        found
            .iter()
            .find(|ip| ip.is_ipv4())
            .or_else(|| found.first())
            .copied()
            .ok_or_else(|| CoreError::Network(format!("{host} has no address")))
    }

    /// How a connecting probe reaches the route: from this PC, or through the session's jump host.
    pub(crate) async fn reach(&self, ctx: &Context, route: &Route) -> Result<Reach> {
        match &route.via {
            None => Ok(Reach::Direct {
                tools: Arc::clone(&self.inner.tools),
                address: self.address_of(&route.host).await?,
            }),
            Some(jump) => Ok(Reach::Jump {
                connection: self.inner.jumps.connection(ctx, jump.session_id).await?,
                jump: jump.name.clone(),
                host: route.host.clone(),
            }),
        }
    }

    /// Ping: echo requests from this PC, each reply reported as it comes.
    pub async fn ping(
        &self,
        ctx: &Context,
        request: &PingRequest,
        cancel: &CancellationToken,
        progress: Progress<'_>,
    ) -> Result<PingSummary> {
        request.validate()?;
        let route = self.route(ctx, &request.target).await?;
        icmp::refuse_jump(&route, "ping")?;
        let address = self.address_of(&route.host).await?;
        Ok(icmp::ping(self.inner.tools.as_ref(), &route, address, request, cancel, progress).await)
    }

    /// Trace route: echo requests with a rising TTL, each hop reported as it comes.
    pub async fn trace(
        &self,
        ctx: &Context,
        request: &TraceRequest,
        cancel: &CancellationToken,
        progress: Progress<'_>,
    ) -> Result<TraceSummary> {
        request.validate()?;
        let route = self.route(ctx, &request.target).await?;
        icmp::refuse_jump(&route, "trace the route to")?;
        let address = self.address_of(&route.host).await?;
        let network = request.resolve_names.then(|| Arc::clone(&self.inner.network));
        Ok(icmp::trace(
            self.inner.tools.as_ref(),
            network.as_deref(),
            &route,
            address,
            request,
            cancel,
            progress,
        )
        .await)
    }

    /// A DNS lookup.
    pub async fn dns(&self, request: &DnsRequest, cancel: &CancellationToken) -> Result<DnsResult> {
        tokio::select! {
            result = dns::lookup(self.inner.tools.as_ref(), request) => result,
            () = cancel.cancelled() => Err(CoreError::Cancelled),
        }
    }

    /// A port check: a TCP connection to each port, each result reported as it comes.
    pub async fn ports(
        &self,
        ctx: &Context,
        request: &PortRequest,
        cancel: &CancellationToken,
        progress: Progress<'_>,
    ) -> Result<PortSummary> {
        let route = self.route(ctx, &request.target).await?;
        let list = ports::parse_ports(&request.ports, route.port)?;
        let reach = self.reach(ctx, &route).await?;
        Ok(ports::check(&route, &reach, &list, request, cancel, progress).await)
    }

    /// The certificate a TLS server presents, checked against Windows' trust store and the name.
    pub async fn certificate(
        &self,
        ctx: &Context,
        request: &CertRequest,
        cancel: &CancellationToken,
    ) -> Result<CertificateReport> {
        let route = self.route(ctx, &request.target).await?;
        let reach = self.reach(ctx, &route).await?;
        tokio::select! {
            report = certs::from_server(self.inner.tools.as_ref(), &route, &reach, request) => report,
            () = cancel.cancelled() => Err(CoreError::Cancelled),
        }
    }

    /// A certificate file (`.crt`, `.cer`, `.pem`) picked in the shell's dialog. A path on a share or a device is
    /// refused before the file system sees it (A3), and the file is read up to 1 MB.
    pub async fn certificate_file(&self, path: &std::path::Path) -> Result<CertificateReport> {
        certs::from_file(self.inner.tools.as_ref(), path).await
    }

    /// Wake-on-LAN: this PC's adapters a packet can leave from, and the MACs known for `target`.
    pub async fn wake_options(
        &self,
        ctx: &Context,
        target: Option<&TargetRef>,
    ) -> Result<(Vec<WakeAdapter>, Vec<KnownMac>)> {
        let adapters = wake::wake_adapters(&self.inner.tools.adapters().await.unwrap_or_default());
        let macs = match target {
            Some(TargetRef::Vm { vmx_path }) => self.vm_macs(ctx, vmx_path).await?,
            Some(TargetRef::Session { session_id }) => {
                let session = self
                    .inner
                    .store
                    .get_session(ctx, *session_id)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(format!("session {session_id}")))?;
                // QL-01: a session linked to a VM wakes that VM's cards. Linux hosts' facts (MO-13) hold no MAC.
                match session.vm_id {
                    Some(vm_id) => match self.inner.store.vm_by_id(ctx, &vm_id).await? {
                        Some(vm) => self.vm_macs(ctx, &vm.vmx_path).await.unwrap_or_default(),
                        None => Vec::new(),
                    },
                    None => Vec::new(),
                }
            }
            _ => Vec::new(),
        };
        Ok((adapters, macs))
    }

    /// The MACs of a VM's network cards, from its hardware (MO-13).
    async fn vm_macs(&self, ctx: &Context, vm_key: &str) -> Result<Vec<KnownMac>> {
        let specs = self.inner.host_details.vm_specs(ctx, vm_key).await?;
        let name = self
            .inner
            .store
            .find_vm(ctx, vm_key)
            .await?
            .map_or_else(|| "the VM".to_owned(), |vm| format!("the VM '{}'", vm.display_name));
        Ok(specs
            .hardware
            .nics
            .iter()
            .filter_map(|nic| {
                let mac = wake::parse_mac(nic.mac.as_deref()?).ok()?;
                Some(KnownMac {
                    mac: wake::format_mac(&mac),
                    source: format!("{} of {name}", nic.slot),
                })
            })
            .collect())
    }
}

/// A host a probe may take: a name or an address, 1 to 253 characters, nothing that isn't one.
pub fn check_host(host: &str) -> Result<String> {
    let host = host.trim();
    let bare = crate::adapters::network::bare_host(host);
    if bare.is_empty() {
        return Err(CoreError::InvalidInput("Type a host name or an IP address.".into()));
    }
    let fits = bare.len() <= 253
        && bare
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '%'));
    if !fits {
        return Err(CoreError::InvalidInput(format!(
            "'{host}' isn't a host name or an IP address."
        )));
    }
    Ok(bare.to_owned())
}

/// Milliseconds as a whole number, for results.
pub(crate) fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_names_or_addresses() {
        assert_eq!(check_host(" web01.example.com ").unwrap(), "web01.example.com");
        assert_eq!(check_host("[2001:db8::1]").unwrap(), "2001:db8::1");
        assert_eq!(check_host("192.0.2.10").unwrap(), "192.0.2.10");
        assert!(check_host("").is_err());
        assert!(check_host("web01 example").is_err());
        assert!(check_host("web01.example.com/admin").is_err());
        assert!(check_host("$(reboot)").is_err());
    }
}
