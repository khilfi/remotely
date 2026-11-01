//! FD-09: the toolbox's network probes, sent from this PC: ICMP echo (ping and trace route), DNS queries, TCP
//! connections (port checks, and the stream a certificate's TLS handshake runs over), the trust check of a
//! certificate chain against Windows' store, this PC's network adapters, and one UDP datagram (a Wake-on-LAN magic
//! packet). Everything but the datagram only reads, so it skips the command bus; the datagram is sent only by the job
//! runner, for [`crate::command_bus::Command::WakeOnLan`].
//!
//! [`SystemNetworkTools`] uses Windows' own APIs: `IcmpSendEcho2` and `Icmp6SendEcho2` (no administrator rights),
//! `DnsQueryEx` (Windows' resolver, or a chosen server), `CertGetCertificateChain` with only what this PC already
//! has (no download of roots, intermediates or revocation lists, so a check sends nothing past the host it reads),
//! and `GetAdaptersAddresses`. Tests use [`crate::fakes::FakeNetworkTools`] or servers on 127.0.0.1.
//!
//! F2's health checks (MO-08) schedule these same probes through [`crate::toolbox::Toolbox`].

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{CoreError, Result};

#[cfg(windows)]
mod win;

/// A byte stream both ways: a TCP connection from this PC, or an SSH channel from a jump host (SS-07).
pub trait ProbeStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProbeStream for T {}

/// A stream a probe reads and writes.
pub type BoxedStream = Box<dyn ProbeStream>;

/// One ICMP echo request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoRequest {
    pub to: IpAddr,
    /// Time to live (IPv6: hop limit). Trace route raises it one hop at a time.
    pub ttl: u8,
    /// Bytes of data in the request.
    pub size: u16,
    pub timeout: Duration,
}

/// What came back for one echo request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Echo {
    /// The host answered.
    Reply {
        from: IpAddr,
        rtt_ms: u32,
        /// The reply's TTL; IPv6 doesn't report it.
        ttl: Option<u8>,
    },
    /// A router on the way dropped it: its TTL ran out there (what trace route looks for).
    TtlExpired { from: IpAddr, rtt_ms: u32 },
    /// A router or the host said it can't be reached.
    Unreachable { from: Option<IpAddr>, reason: String },
    /// No answer within the timeout.
    TimedOut,
}

/// The record types the DNS tool asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Soa,
    Ptr,
    Srv,
    Caa,
}

impl RecordType {
    pub const ALL: [RecordType; 10] = [
        RecordType::A,
        RecordType::Aaaa,
        RecordType::Cname,
        RecordType::Mx,
        RecordType::Txt,
        RecordType::Ns,
        RecordType::Soa,
        RecordType::Ptr,
        RecordType::Srv,
        RecordType::Caa,
    ];

    /// The type's number on the wire.
    pub fn code(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Ns => 2,
            RecordType::Cname => 5,
            RecordType::Soa => 6,
            RecordType::Ptr => 12,
            RecordType::Mx => 15,
            RecordType::Txt => 16,
            RecordType::Aaaa => 28,
            RecordType::Srv => 33,
            RecordType::Caa => 257,
        }
    }

    /// "A", "AAAA"...
    pub fn as_str(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Cname => "CNAME",
            RecordType::Mx => "MX",
            RecordType::Txt => "TXT",
            RecordType::Ns => "NS",
            RecordType::Soa => "SOA",
            RecordType::Ptr => "PTR",
            RecordType::Srv => "SRV",
            RecordType::Caa => "CAA",
        }
    }

    /// A type's name for a number an answer holds (a CNAME in an A query's answer), or `TYPE<n>`.
    pub fn name_of(code: u16) -> String {
        RecordType::ALL
            .into_iter()
            .find(|t| t.code() == code)
            .map_or_else(|| format!("TYPE{code}"), |t| t.as_str().to_owned())
    }
}

/// One DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// The name, without a trailing dot (a PTR query's name is already `<reversed>.in-addr.arpa`).
    pub name: String,
    pub record_type: RecordType,
    /// `None`: Windows' resolver (its cache, the hosts file and this PC's DNS servers).
    pub server: Option<IpAddr>,
    pub timeout: Duration,
}

/// One record of an answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecord {
    pub name: String,
    /// "A", "CNAME", or `TYPE<n>` for one the tool doesn't name.
    pub record_type: String,
    pub ttl: u32,
    /// The record's data as text: an address, a name, `10 mail.example.com`, a TXT's strings in quotes...
    pub data: String,
}

/// Why a query got no records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum DnsFailure {
    /// The name doesn't exist (NXDOMAIN).
    NoSuchName,
    /// The name exists but has no record of this type.
    NoRecords,
    /// The server failed, refused, or didn't answer.
    Failed { message: String },
}

/// One TCP connection that didn't open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectFailure {
    /// The host answered that nothing listens there.
    Refused,
    /// No answer within the timeout: a firewall drops it, or the host is off.
    TimedOut,
    /// Something else (no route, the address is not valid here...), in words.
    Other(String),
}

impl ConnectFailure {
    pub fn describe(&self) -> String {
        match self {
            ConnectFailure::Refused => "closed (connection refused)".into(),
            ConnectFailure::TimedOut => "no answer".into(),
            ConnectFailure::Other(why) => why.clone(),
        }
    }
}

/// What Windows makes of a certificate chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TrustVerdict {
    /// Windows trusts it for the use asked (a TLS server, or any use for a file).
    pub trusted: bool,
    /// Why not, in words; empty when trusted.
    pub problems: Vec<String>,
    /// The chain Windows built, leaf first, each certificate's DER: what the server sent plus the root from this
    /// PC's store when it has it.
    #[serde(skip)]
    pub built: Vec<Vec<u8>>,
}

/// What a chain is checked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustUse {
    /// A TLS server's certificate (server authentication).
    TlsServer,
    /// A certificate opened from a file: any use.
    Any,
}

/// One of this PC's network adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalAdapter {
    /// Windows' name for it ("Ethernet", "Wi-Fi").
    pub name: String,
    /// `aa:bb:cc:dd:ee:ff`, lower case, when it has one.
    pub mac: Option<String>,
    pub up: bool,
    pub loopback: bool,
    pub addresses: Vec<AdapterAddress>,
    /// The DNS servers it uses.
    pub dns_servers: Vec<IpAddr>,
}

/// An address of an adapter, with its on-link prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterAddress {
    pub address: IpAddr,
    pub prefix: u8,
}

#[async_trait]
pub trait NetworkTools: Send + Sync {
    /// Sends one ICMP echo request and waits for its answer. `Err` only when Windows couldn't send it at all.
    async fn echo(&self, request: EchoRequest) -> Result<Echo>;

    /// One DNS query. `Ok(Err(..))` when the server answered without records.
    async fn dns(&self, query: &DnsQuery) -> Result<std::result::Result<Vec<DnsRecord>, DnsFailure>>;

    /// Opens a TCP connection from this PC.
    async fn connect(&self, to: SocketAddr, timeout: Duration) -> std::result::Result<BoxedStream, ConnectFailure>;

    /// Checks a chain (leaf first, as the server sent it) against Windows' trust store, with only what this PC has:
    /// nothing is downloaded. The name is checked apart from this.
    async fn check_chain(&self, chain: &[Vec<u8>], usage: TrustUse) -> Result<TrustVerdict>;

    /// This PC's network adapters with their addresses.
    async fn adapters(&self) -> Result<Vec<LocalAdapter>>;

    /// Sends one UDP datagram from `from` (an address of this PC, or any), to a broadcast address when `broadcast`.
    async fn send_datagram(&self, from: Option<IpAddr>, to: SocketAddr, broadcast: bool, payload: &[u8]) -> Result<()>;
}

/// Windows' ICMP, DNS, certificate and adapter APIs, and tokio's sockets.
pub struct SystemNetworkTools;

#[async_trait]
impl NetworkTools for SystemNetworkTools {
    async fn echo(&self, request: EchoRequest) -> Result<Echo> {
        blocking(move || system_echo(request)).await
    }

    async fn dns(&self, query: &DnsQuery) -> Result<std::result::Result<Vec<DnsRecord>, DnsFailure>> {
        let query = query.clone();
        let timeout = query.timeout;
        // DnsQueryEx has its own timeouts; a query still running after ours is left to finish on its thread.
        match tokio::time::timeout(timeout, blocking(move || system_dns(&query))).await {
            Ok(answer) => answer,
            Err(_) => Ok(Err(DnsFailure::Failed {
                message: format!("no answer within {} s", timeout.as_secs().max(1)),
            })),
        }
    }

    async fn connect(&self, to: SocketAddr, timeout: Duration) -> std::result::Result<BoxedStream, ConnectFailure> {
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(to)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                Ok(Box::new(stream))
            }
            Ok(Err(err)) => Err(connect_failure(&err)),
            Err(_) => Err(ConnectFailure::TimedOut),
        }
    }

    async fn check_chain(&self, chain: &[Vec<u8>], usage: TrustUse) -> Result<TrustVerdict> {
        let chain = chain.to_vec();
        blocking(move || system_check_chain(&chain, usage)).await
    }

    async fn adapters(&self) -> Result<Vec<LocalAdapter>> {
        blocking(system_adapters).await
    }

    async fn send_datagram(&self, from: Option<IpAddr>, to: SocketAddr, broadcast: bool, payload: &[u8]) -> Result<()> {
        let bind: SocketAddr = match (from, to) {
            (Some(ip), _) => SocketAddr::new(ip, 0),
            (None, SocketAddr::V4(_)) => SocketAddr::from(([0, 0, 0, 0], 0)),
            (None, SocketAddr::V6(_)) => SocketAddr::from(([0u16; 8], 0)),
        };
        let socket = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(|err| CoreError::Network(format!("can't send from {}: {err}", bind.ip())))?;
        if broadcast {
            socket
                .set_broadcast(true)
                .map_err(|err| CoreError::Network(format!("can't send a broadcast: {err}")))?;
        }
        let sent = socket
            .send_to(payload, to)
            .await
            .map_err(|err| CoreError::Network(format!("can't send to {to}: {err}")))?;
        if sent != payload.len() {
            return Err(CoreError::Network(format!(
                "only {sent} of {} bytes went to {to}",
                payload.len()
            )));
        }
        Ok(())
    }
}

/// Runs a Windows call on a blocking thread.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| CoreError::Network(format!("the probe stopped: {err}")))?
}

/// Plain words for a TCP connection that failed.
pub fn connect_failure(err: &std::io::Error) -> ConnectFailure {
    match err.kind() {
        std::io::ErrorKind::ConnectionRefused => ConnectFailure::Refused,
        std::io::ErrorKind::TimedOut => ConnectFailure::TimedOut,
        _ => ConnectFailure::Other(err.to_string()),
    }
}

#[cfg(windows)]
fn system_echo(request: EchoRequest) -> Result<Echo> {
    win::echo(request)
}

#[cfg(not(windows))]
fn system_echo(_request: EchoRequest) -> Result<Echo> {
    Err(CoreError::Network("ping needs Windows".into()))
}

#[cfg(windows)]
fn system_dns(query: &DnsQuery) -> Result<std::result::Result<Vec<DnsRecord>, DnsFailure>> {
    win::dns(query)
}

#[cfg(not(windows))]
fn system_dns(_query: &DnsQuery) -> Result<std::result::Result<Vec<DnsRecord>, DnsFailure>> {
    Err(CoreError::Network("DNS lookups need Windows".into()))
}

#[cfg(windows)]
fn system_check_chain(chain: &[Vec<u8>], usage: TrustUse) -> Result<TrustVerdict> {
    win::check_chain(chain, usage)
}

#[cfg(not(windows))]
fn system_check_chain(_chain: &[Vec<u8>], _usage: TrustUse) -> Result<TrustVerdict> {
    Err(CoreError::Network("the trust check needs Windows".into()))
}

#[cfg(windows)]
fn system_adapters() -> Result<Vec<LocalAdapter>> {
    win::adapters()
}

#[cfg(not(windows))]
fn system_adapters() -> Result<Vec<LocalAdapter>> {
    Ok(Vec::new())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn record_types_have_their_wire_numbers_and_names() {
        assert_eq!(RecordType::Aaaa.code(), 28);
        assert_eq!(RecordType::Caa.code(), 257);
        assert_eq!(RecordType::name_of(5), "CNAME");
        assert_eq!(RecordType::name_of(99), "TYPE99");
        assert_eq!(serde_json::to_string(&RecordType::Aaaa).unwrap(), "\"AAAA\"");
        assert_eq!(
            serde_json::from_str::<RecordType>("\"CNAME\"").unwrap(),
            RecordType::Cname
        );
    }

    // Loopback only: nothing leaves this PC.
    #[tokio::test]
    async fn a_ping_of_this_pc_gets_a_reply() {
        let echo = SystemNetworkTools
            .echo(EchoRequest {
                to: "127.0.0.1".parse().unwrap(),
                ttl: 64,
                size: 32,
                timeout: Duration::from_secs(2),
            })
            .await
            .unwrap();
        assert!(
            matches!(echo, Echo::Reply { from, .. } if from.is_loopback()),
            "{echo:?}"
        );
    }

    #[tokio::test]
    async fn an_ipv6_ping_of_this_pc_gets_a_reply() {
        let echo = SystemNetworkTools
            .echo(EchoRequest {
                to: "::1".parse().unwrap(),
                ttl: 64,
                size: 32,
                timeout: Duration::from_secs(2),
            })
            .await
            .unwrap();
        assert!(
            matches!(echo, Echo::Reply { from, .. } if from.is_loopback()),
            "{echo:?}"
        );
    }

    // Windows answers `localhost` itself: no query leaves this PC.
    #[tokio::test]
    async fn windows_resolver_answers_localhost() {
        let answer = SystemNetworkTools
            .dns(&DnsQuery {
                name: "localhost".into(),
                record_type: RecordType::A,
                server: None,
                timeout: Duration::from_secs(5),
            })
            .await
            .unwrap()
            .unwrap();
        assert!(
            answer
                .iter()
                .any(|r| r.record_type == "A" && r.data.starts_with("127.")),
            "{answer:?}"
        );
    }

    #[tokio::test]
    async fn a_connection_to_a_closed_port_is_refused_and_an_open_one_opens() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let open = listener.local_addr().unwrap();
        assert!(SystemNetworkTools.connect(open, Duration::from_secs(3)).await.is_ok());
        drop(listener);
        let refused = SystemNetworkTools
            .connect(open, Duration::from_secs(5))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(refused, ConnectFailure::Refused | ConnectFailure::TimedOut),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn a_datagram_reaches_a_listener_on_this_pc() {
        let listener = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let to = listener.local_addr().unwrap();
        SystemNetworkTools
            .send_datagram(Some("127.0.0.1".parse().unwrap()), to, false, b"hello")
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), listener.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn this_pc_lists_its_loopback_adapter() {
        let adapters = SystemNetworkTools.adapters().await.unwrap();
        assert!(
            adapters
                .iter()
                .any(|a| a.loopback && a.addresses.iter().any(|x| x.address.is_loopback())),
            "{adapters:?}"
        );
    }
}
