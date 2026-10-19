//! SS-07: port forwards on a logged-in connection (a terminal's own), PuTTY and OpenSSH style:
//!
//! * **local**: a port on this PC. Each connection to it opens a direct-tcpip channel to
//!   `dest_host:dest_port`, reached from the session's host.
//! * **remote**: the host listens on a port (tcpip-forward). Each connection to it comes back as a
//!   forwarded-tcpip channel and goes on to `dest_host:dest_port`, reached from this PC.
//! * **dynamic** (SOCKS 4, 4a and 5): a port on this PC where each client names where it wants to
//!   go; the channel goes there from the session's host.
//!
//! Every connection is a channel of the session's own connection, so a forward needs no second login,
//! and behind jump hosts it starts from the session's host. Nothing about the traffic is logged or
//! kept: only how many connections a forward carried and why the last one that failed did.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use russh::client;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{dial_host, socks, Handler, Shared};
use crate::error::{CoreError, Result};
use crate::known_hosts::address;
use crate::locks;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ForwardKind {
    /// A port on this PC to a host the session's host reaches (`ssh -L`).
    Local,
    /// A port on the session's host back to a host this PC reaches (`ssh -R`).
    Remote,
    /// A SOCKS proxy on this PC whose clients go anywhere the session's host reaches (`ssh -D`).
    Dynamic,
}

impl ForwardKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ForwardKind::Local => "local",
            ForwardKind::Remote => "remote",
            ForwardKind::Dynamic => "dynamic",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [ForwardKind::Local, ForwardKind::Remote, ForwardKind::Dynamic]
            .into_iter()
            .find(|k| k.as_str() == s)
    }

    /// "local", "remote" or "SOCKS", for messages and the audit log.
    pub fn label(self) -> &'static str {
        match self {
            ForwardKind::Local => "local",
            ForwardKind::Remote => "remote",
            ForwardKind::Dynamic => "SOCKS",
        }
    }
}

/// What a forward does. The core checks it before it gets here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardSpec {
    pub kind: ForwardKind,
    /// Where it listens: on this PC for local and SOCKS forwards, on the session's host for remote
    /// ones. Loopback (`127.0.0.1`, `localhost`) unless the user chose otherwise.
    pub bind_address: String,
    /// 0: any free port, shown once it listens.
    pub bind_port: u16,
    /// Where connections go: reached from the session's host (local), or from this PC (remote).
    /// Empty for SOCKS, whose clients say where.
    #[serde(default)]
    pub dest_host: String,
    #[serde(default)]
    pub dest_port: u16,
}

impl ForwardSpec {
    /// Only programs on the machine that listens can use it.
    pub fn loopback_only(&self) -> bool {
        is_loopback(&self.bind_address)
    }

    /// Where it listens, as `127.0.0.1:8080` (port 0 as "any port").
    pub fn listen_address(&self) -> String {
        match self.bind_port {
            0 => format!("{} (any free port)", self.bind_address),
            port => address(&self.bind_address, port),
        }
    }

    /// Where it leads.
    pub fn destination(&self) -> String {
        match self.kind {
            ForwardKind::Dynamic => "wherever each SOCKS client asks".into(),
            _ => address(&self.dest_host, self.dest_port),
        }
    }

    /// `local 127.0.0.1:8080 -> db01.example.com:5432`, `SOCKS on 127.0.0.1:1080`, or
    /// `remote localhost:9000 on the host -> 127.0.0.1:3000`, for the UI and the audit log. Never
    /// traffic.
    pub fn describe(&self) -> String {
        match self.kind {
            ForwardKind::Local => format!("local {} -> {}", self.listen_address(), self.destination()),
            ForwardKind::Remote => format!("remote {} on the host -> {}", self.listen_address(), self.destination()),
            ForwardKind::Dynamic => format!("SOCKS on {}", self.listen_address()),
        }
    }
}

/// `localhost`, `127.x.x.x` or `::1`.
pub fn is_loopback(address: &str) -> bool {
    let bare = dial_host(address.trim());
    bare.eq_ignore_ascii_case("localhost") || bare.parse::<IpAddr>().is_ok_and(|ip| ip.to_canonical().is_loopback())
}

/// How busy a running forward has been. Counts only: nothing about what it carried.
#[derive(Debug, Default)]
pub struct ForwardStats {
    connections: AtomicU64,
    open: AtomicU64,
    last_error: Mutex<Option<String>>,
}

impl ForwardStats {
    /// Connections it took so far.
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::SeqCst)
    }

    /// Connections open now.
    pub fn open(&self) -> u64 {
        self.open.load(Ordering::SeqCst)
    }

    /// Why the last connection that failed did, e.g. "db01.example.com:5432 refused the connection".
    pub fn last_error(&self) -> Option<String> {
        locks::lock(&self.last_error).clone()
    }

    fn failed(&self, why: String) {
        *locks::lock(&self.last_error) = Some(why);
    }
}

/// A forward that listens. Cancelling `stop` closes the listener and cuts the connections it carries.
pub struct RunningForward {
    /// Where it listens now, e.g. `127.0.0.1:8080`, or `localhost:9000 on the host`.
    pub listening: String,
    pub stop: CancellationToken,
    pub stats: Arc<ForwardStats>,
}

/// SS-07: port forwards on one connection.
#[async_trait]
pub trait RemoteForwards: Send + Sync {
    /// Starts a forward. Returns once it listens, or fails saying why (the port is in use, the host
    /// refused to listen).
    async fn start(&self, spec: &ForwardSpec) -> Result<RunningForward>;
}

/// A byte stream both ways: a TCP connection or an SSH channel.
pub(crate) trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// Opens a stream to `host:port` from the far end of a forward (the session's host, over SSH).
#[async_trait]
pub(crate) trait Opener: Send + Sync + 'static {
    /// `from`: who connected to the forward on this PC, as SSH reports the originator.
    async fn open(&self, host: &str, port: u16, from: SocketAddr) -> std::result::Result<Box<dyn Duplex>, String>;
}

/// How long reaching a forward's destination may take.
const OPEN_WAIT: Duration = Duration::from_secs(15);

/// The address a listener on this PC binds: `localhost` is 127.0.0.1 (not ::1 as well), IPv6
/// without brackets.
fn bind_host(address: &str) -> &str {
    let bare = dial_host(address.trim());
    if bare.eq_ignore_ascii_case("localhost") {
        "127.0.0.1"
    } else {
        bare
    }
}

/// Why a listener on this PC could not start, in words.
fn bind_error(spec: &ForwardSpec, err: &std::io::Error) -> CoreError {
    let at = spec.listen_address();
    let why = match err.kind() {
        std::io::ErrorKind::AddrInUse => format!("{at} is in use by another program on this PC. Choose another port"),
        std::io::ErrorKind::AddrNotAvailable => {
            format!("{} is not an address of this PC", spec.bind_address)
        }
        // Windows reserves port ranges (Hyper-V, WinNAT) and refuses them with "access denied".
        std::io::ErrorKind::PermissionDenied => {
            format!("Windows does not allow listening on {at}; the port may be reserved. Choose another port")
        }
        _ => format!("can't listen on {at}: {err}"),
    };
    CoreError::Tunnel(why)
}

/// Words for a channel the host would not open.
pub(crate) fn open_failure(err: &russh::Error) -> String {
    match err {
        russh::Error::ChannelOpenFailure(reason) => match reason {
            russh::ChannelOpenFailure::AdministrativelyProhibited => {
                "the host does not allow it (TCP forwarding is turned off there)".into()
            }
            russh::ChannelOpenFailure::ConnectFailed => {
                "the connection failed: nothing listens there, or it can't be reached from there".into()
            }
            russh::ChannelOpenFailure::UnknownChannelType => "the host does not support forwarding".into(),
            russh::ChannelOpenFailure::ResourceShortage => "the host is short of resources".into(),
            russh::ChannelOpenFailure::Other { reason, .. } => reason.clone(),
        },
        other => other.to_string(),
    }
}

/// A local or SOCKS forward: listens on this PC and sends each connection through `opener`.
pub(crate) async fn listen_here(spec: &ForwardSpec, opener: Arc<dyn Opener>) -> Result<RunningForward> {
    let listener = TcpListener::bind((bind_host(&spec.bind_address), spec.bind_port))
        .await
        .map_err(|err| bind_error(spec, &err))?;
    let local = listener.local_addr()?;
    let stop = CancellationToken::new();
    let stats = Arc::new(ForwardStats::default());
    let destination = (spec.kind == ForwardKind::Local).then(|| (spec.dest_host.clone(), spec.dest_port));
    {
        let stop = stop.clone();
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = stop.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((socket, from)) => {
                            let _ = socket.set_nodelay(true);
                            tokio::spawn(carry(
                                socket,
                                from,
                                destination.clone(),
                                Arc::clone(&opener),
                                Arc::clone(&stats),
                                stop.child_token(),
                            ));
                        }
                        Err(err) => {
                            // Out of sockets, for one: try again in a moment.
                            stats.failed(format!("could not take a connection: {err}"));
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    },
                }
            }
        });
    }
    Ok(RunningForward {
        listening: local.to_string(),
        stop,
        stats,
    })
}

/// One connection to a local or SOCKS forward. `destination`: `None` asks the SOCKS client.
async fn carry(
    mut socket: TcpStream,
    from: SocketAddr,
    destination: Option<(String, u16)>,
    opener: Arc<dyn Opener>,
    stats: Arc<ForwardStats>,
    stop: CancellationToken,
) {
    stats.connections.fetch_add(1, Ordering::SeqCst);
    stats.open.fetch_add(1, Ordering::SeqCst);
    let carried = async {
        let (host, port, socks) = match destination {
            Some((host, port)) => (host, port, None),
            None => {
                let request = socks::handshake(&mut socket).await?;
                (request.host.clone(), request.port, Some(request))
            }
        };
        let opened = tokio::time::timeout(OPEN_WAIT, opener.open(&host, port, from))
            .await
            .unwrap_or_else(|_| Err(format!("no answer in {} s", OPEN_WAIT.as_secs())));
        if let Some(request) = &socks {
            let _ = socks::reply(&mut socket, request, opened.is_ok()).await;
        }
        let mut stream = opened.map_err(|why| format!("could not reach {}: {why}", address(&host, port)))?;
        tokio::select! {
            () = stop.cancelled() => {}
            _ = tokio::io::copy_bidirectional(&mut socket, &mut stream) => {}
        }
        Ok::<(), String>(())
    }
    .await;
    if let Err(why) = carried {
        stats.failed(why);
    }
    stats.open.fetch_sub(1, Ordering::SeqCst);
}

/// SS-07: a remote forward the host listens for, so the handler can hand its connections over.
pub(super) struct Route {
    id: u64,
    address: String,
    port: u32,
    to: mpsc::UnboundedSender<russh::Channel<client::Msg>>,
}

/// Where a forwarded connection goes: the route the host named, or the one on that port (servers
/// may name the address differently, e.g. `127.0.0.1` for `localhost`).
pub(super) fn find_route(
    routes: &[Route],
    connected_address: &str,
    connected_port: u32,
) -> Option<mpsc::UnboundedSender<russh::Channel<client::Msg>>> {
    routes
        .iter()
        .find(|r| r.port == connected_port && r.address == connected_address)
        .or_else(|| routes.iter().find(|r| r.port == connected_port))
        .map(|r| r.to.clone())
}

/// Port forwards over a russh connection.
pub(super) struct RusshForwards {
    handle: Arc<client::Handle<Handler>>,
    shared: Arc<Mutex<Shared>>,
}

impl RusshForwards {
    pub(super) fn new(handle: Arc<client::Handle<Handler>>, shared: Arc<Mutex<Shared>>) -> Self {
        Self { handle, shared }
    }

    /// A remote forward: the host listens, and each connection comes back over the connection.
    async fn listen_there(&self, spec: &ForwardSpec) -> Result<RunningForward> {
        let bind = spec.bind_address.trim().to_owned();
        let asked = u32::from(spec.bind_port);
        let granted = self.handle.tcpip_forward(bind.clone(), asked).await.map_err(|err| {
            let why = match err {
                russh::Error::RequestDenied => {
                    "it refused (remote forwarding may be turned off there, or the port is taken)".to_owned()
                }
                other => other.to_string(),
            };
            CoreError::Tunnel(format!("the host did not listen on {}: {why}", spec.listen_address()))
        })?;
        // Port 0 asks the host to choose; it says which.
        let port = if asked == 0 { granted } else { asked };
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let (to, mut incoming) = mpsc::unbounded_channel();
        locks::lock(&self.shared).routes.push(Route {
            id,
            address: bind.clone(),
            port,
            to,
        });
        let stop = CancellationToken::new();
        let stats = Arc::new(ForwardStats::default());
        {
            let stop = stop.clone();
            let stats = Arc::clone(&stats);
            let handle = Arc::clone(&self.handle);
            let shared = Arc::clone(&self.shared);
            let destination = (spec.dest_host.clone(), spec.dest_port);
            let bind = bind.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        () = stop.cancelled() => break,
                        channel = incoming.recv() => match channel {
                            Some(channel) => {
                                tokio::spawn(carry_back(
                                    channel,
                                    destination.clone(),
                                    Arc::clone(&stats),
                                    stop.child_token(),
                                ));
                            }
                            None => break,
                        },
                    }
                }
                locks::lock(&shared).routes.retain(|r| r.id != id);
                if !handle.is_closed() {
                    let _ = handle.cancel_tcpip_forward(bind, port).await;
                }
            });
        }
        Ok(RunningForward {
            listening: format!("{} on the host", address(&bind, u16::try_from(port).unwrap_or(0))),
            stop,
            stats,
        })
    }
}

/// One connection to a remote forward: on to the destination, reached from this PC.
async fn carry_back(
    channel: russh::Channel<client::Msg>,
    (host, port): (String, u16),
    stats: Arc<ForwardStats>,
    stop: CancellationToken,
) {
    stats.connections.fetch_add(1, Ordering::SeqCst);
    stats.open.fetch_add(1, Ordering::SeqCst);
    let target = address(&host, port);
    let connected = tokio::time::timeout(OPEN_WAIT, TcpStream::connect((bind_host(&host), port))).await;
    match connected {
        Ok(Ok(mut socket)) => {
            let _ = socket.set_nodelay(true);
            let mut stream = channel.into_stream();
            tokio::select! {
                () = stop.cancelled() => {}
                _ = tokio::io::copy_bidirectional(&mut stream, &mut socket) => {}
            }
        }
        Ok(Err(err)) => stats.failed(format!("could not reach {target} from this PC: {err}")),
        Err(_) => stats.failed(format!(
            "could not reach {target} from this PC: no answer in {} s",
            OPEN_WAIT.as_secs()
        )),
    }
    stats.open.fetch_sub(1, Ordering::SeqCst);
}

/// Opens direct-tcpip channels: connections that start from the session's host.
struct ChannelOpener {
    handle: Arc<client::Handle<Handler>>,
}

#[async_trait]
impl Opener for ChannelOpener {
    async fn open(&self, host: &str, port: u16, from: SocketAddr) -> std::result::Result<Box<dyn Duplex>, String> {
        let channel = self
            .handle
            .channel_open_direct_tcpip(
                dial_host(host),
                u32::from(port),
                from.ip().to_string(),
                u32::from(from.port()),
            )
            .await
            .map_err(|err| open_failure(&err))?;
        Ok(Box::new(channel.into_stream()))
    }
}

#[async_trait]
impl RemoteForwards for RusshForwards {
    async fn start(&self, spec: &ForwardSpec) -> Result<RunningForward> {
        if self.handle.is_closed() {
            return Err(CoreError::Tunnel("the terminal's connection is closed".into()));
        }
        match spec.kind {
            ForwardKind::Local | ForwardKind::Dynamic => {
                let opener = Arc::new(ChannelOpener {
                    handle: Arc::clone(&self.handle),
                });
                listen_here(spec, opener).await
            }
            ForwardKind::Remote => self.listen_there(spec).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: ForwardKind, bind: &str, port: u16) -> ForwardSpec {
        ForwardSpec {
            kind,
            bind_address: bind.into(),
            bind_port: port,
            dest_host: "db01.example.com".into(),
            dest_port: 5432,
        }
    }

    #[test]
    fn loopback_binds_are_told_apart_from_network_ones() {
        for local in ["127.0.0.1", "localhost", "LOCALHOST", "::1", "[::1]", "127.0.0.2"] {
            assert!(is_loopback(local), "{local}");
        }
        for shared in ["0.0.0.0", "::", "192.0.2.10", "[2001:db8::1]", "web01.example.com", ""] {
            assert!(!is_loopback(shared), "{shared}");
        }
    }

    #[test]
    fn forwards_describe_themselves_without_traffic() {
        assert_eq!(
            spec(ForwardKind::Local, "127.0.0.1", 8080).describe(),
            "local 127.0.0.1:8080 -> db01.example.com:5432"
        );
        assert_eq!(
            spec(ForwardKind::Remote, "localhost", 9000).describe(),
            "remote localhost:9000 on the host -> db01.example.com:5432"
        );
        assert_eq!(
            spec(ForwardKind::Dynamic, "::1", 0).describe(),
            "SOCKS on ::1 (any free port)"
        );
        assert_eq!(ForwardKind::parse("dynamic"), Some(ForwardKind::Dynamic));
        assert_eq!(ForwardKind::Dynamic.label(), "SOCKS");
    }

    #[test]
    fn routes_match_the_address_then_the_port() {
        let (a, mut a_rx) = mpsc::unbounded_channel();
        let (b, mut b_rx) = mpsc::unbounded_channel();
        let routes = vec![
            Route {
                id: 1,
                address: "localhost".into(),
                port: 9000,
                to: a,
            },
            Route {
                id: 2,
                address: "0.0.0.0".into(),
                port: 9001,
                to: b,
            },
        ];
        assert!(find_route(&routes, "localhost", 9000).is_some());
        assert!(find_route(&routes, "127.0.0.1", 9001).is_some(), "same port");
        assert!(find_route(&routes, "localhost", 9002).is_none());
        drop(routes);
        assert!(a_rx.try_recv().is_err() && b_rx.try_recv().is_err());
    }

    #[test]
    fn listeners_bind_loopback_for_localhost() {
        assert_eq!(bind_host("localhost"), "127.0.0.1");
        assert_eq!(bind_host("[::1]"), "::1");
        assert_eq!(bind_host("0.0.0.0"), "0.0.0.0");
    }
}
