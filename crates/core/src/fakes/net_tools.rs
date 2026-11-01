//! FD-09: [`FakeNetworkTools`], the toolbox's probes in memory. No packet leaves this PC: echoes follow routes set by
//! the test, DNS answers come from a table, a connection either fails as told, gives a banner, or is passed on to a
//! server the test runs on 127.0.0.1 (for the certificate viewer's TLS handshake), and a datagram is only recorded.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use crate::adapters::net_tools::{
    AdapterAddress, BoxedStream, ConnectFailure, DnsFailure, DnsQuery, DnsRecord, Echo, EchoRequest, LocalAdapter,
    NetworkTools, RecordType, TrustUse, TrustVerdict,
};
use crate::error::Result;
use crate::locks;

/// What a connection to an address and port does.
#[derive(Debug, Clone)]
pub enum FakePort {
    Refused,
    /// Nothing answers: the connect waits its timeout.
    Silent,
    /// It opens and the service sends these bytes first.
    Banner(Vec<u8>),
    /// It opens, and the connection goes to this server on 127.0.0.1.
    Forward(SocketAddr),
}

/// A datagram that would have been sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentDatagram {
    pub from: Option<IpAddr>,
    pub to: SocketAddr,
    pub broadcast: bool,
    pub payload: Vec<u8>,
}

/// What a DNS query of a name and type gets.
type DnsAnswer = std::result::Result<Vec<DnsRecord>, DnsFailure>;

#[derive(Default)]
pub struct FakeNetworkTools {
    /// The routers on the way to each address, before it answers.
    routes: Mutex<HashMap<IpAddr, Vec<Option<IpAddr>>>>,
    /// Addresses that never answer.
    silent: Mutex<Vec<IpAddr>>,
    dns: Mutex<HashMap<(String, RecordType), DnsAnswer>>,
    ports: Mutex<HashMap<SocketAddr, FakePort>>,
    verdict: Mutex<Option<TrustVerdict>>,
    adapters: Mutex<Vec<LocalAdapter>>,
    sent: Mutex<Vec<SentDatagram>>,
    echoes: Mutex<Vec<EchoRequest>>,
    dns_queries: Mutex<Vec<DnsQuery>>,
    connects: Mutex<Vec<SocketAddr>>,
    checked: Mutex<Vec<(usize, TrustUse)>>,
}

impl FakeNetworkTools {
    pub fn new() -> Self {
        Self::default()
    }

    /// Echoes to `to` answer from it, after passing these routers (`None`: one that doesn't answer).
    pub fn with_route(self, to: &str, hops: &[Option<&str>]) -> Self {
        let parsed = hops.iter().map(|h| h.and_then(|h| h.parse().ok())).collect();
        if let Ok(ip) = to.parse() {
            locks::lock(&self.routes).insert(ip, parsed);
        }
        self
    }

    /// Echoes to `to` get no answer.
    pub fn with_silent(self, to: &str) -> Self {
        if let Ok(ip) = to.parse() {
            locks::lock(&self.silent).push(ip);
        }
        self
    }

    /// A DNS query of `name` (any letter case) and `kind` gets these records.
    pub fn with_records(self, name: &str, kind: RecordType, records: &[(&str, u32, &str)]) -> Self {
        let records = records
            .iter()
            .map(|(name, ttl, data)| DnsRecord {
                name: (*name).to_owned(),
                record_type: kind.as_str().to_owned(),
                ttl: *ttl,
                data: (*data).to_owned(),
            })
            .collect();
        locks::lock(&self.dns).insert((name.to_ascii_lowercase(), kind), Ok(records));
        self
    }

    /// A DNS query of `name` and `kind` fails like this.
    pub fn with_dns_failure(self, name: &str, kind: RecordType, failure: DnsFailure) -> Self {
        locks::lock(&self.dns).insert((name.to_ascii_lowercase(), kind), Err(failure));
        self
    }

    /// A connection to `ip:port` does this. Unlisted ones are refused.
    pub fn with_port(self, ip: &str, port: u16, behaviour: FakePort) -> Self {
        if let Ok(ip) = ip.parse() {
            locks::lock(&self.ports).insert(SocketAddr::new(ip, port), behaviour);
        }
        self
    }

    /// What the trust check says (by default: not trusted, "the fake trusts nothing").
    pub fn with_verdict(self, verdict: TrustVerdict) -> Self {
        *locks::lock(&self.verdict) = Some(verdict);
        self
    }

    /// MO-08: a connection to `ip:port` does this from now on (a service going down and up between runs).
    pub fn set_port(&self, ip: &str, port: u16, behaviour: FakePort) {
        if let Ok(ip) = ip.parse() {
            locks::lock(&self.ports).insert(SocketAddr::new(ip, port), behaviour);
        }
    }

    /// MO-08: what the trust check says from now on.
    pub fn set_verdict(&self, verdict: TrustVerdict) {
        *locks::lock(&self.verdict) = Some(verdict);
    }

    /// Echoes to `to` get no answer from now on, or answer again.
    pub fn set_silent(&self, to: &str, silent: bool) {
        if let Ok(ip) = to.parse::<IpAddr>() {
            let mut list = locks::lock(&self.silent);
            list.retain(|a| *a != ip);
            if silent {
                list.push(ip);
            }
        }
    }

    /// An adapter of this PC: up, not loopback, with one address.
    pub fn with_adapter(self, name: &str, address: &str, prefix: u8, dns: &[&str]) -> Self {
        let adapter = LocalAdapter {
            name: name.to_owned(),
            mac: Some("02:00:00:00:00:01".into()),
            up: true,
            loopback: false,
            addresses: address
                .parse()
                .map(|address| vec![AdapterAddress { address, prefix }])
                .unwrap_or_default(),
            dns_servers: dns.iter().filter_map(|d| d.parse().ok()).collect(),
        };
        locks::lock(&self.adapters).push(adapter);
        self
    }

    /// The datagrams that would have gone out.
    pub fn sent(&self) -> Vec<SentDatagram> {
        locks::lock(&self.sent).clone()
    }

    pub fn echoes(&self) -> Vec<EchoRequest> {
        locks::lock(&self.echoes).clone()
    }

    pub fn dns_queries(&self) -> Vec<DnsQuery> {
        locks::lock(&self.dns_queries).clone()
    }

    pub fn connects(&self) -> Vec<SocketAddr> {
        locks::lock(&self.connects).clone()
    }

    /// Each trust check: how many certificates, for what use.
    pub fn checked(&self) -> Vec<(usize, TrustUse)> {
        locks::lock(&self.checked).clone()
    }
}

#[async_trait]
impl NetworkTools for FakeNetworkTools {
    async fn echo(&self, request: EchoRequest) -> Result<Echo> {
        locks::lock(&self.echoes).push(request);
        if locks::lock(&self.silent).contains(&request.to) {
            return Ok(Echo::TimedOut);
        }
        let hops = locks::lock(&self.routes).get(&request.to).cloned().unwrap_or_default();
        let ttl = usize::from(request.ttl);
        if ttl == 0 {
            return Ok(Echo::TimedOut);
        }
        Ok(match hops.get(ttl - 1) {
            Some(Some(router)) => Echo::TtlExpired {
                from: *router,
                rtt_ms: u32::from(request.ttl),
            },
            Some(None) => Echo::TimedOut,
            None => Echo::Reply {
                from: request.to,
                rtt_ms: u32::try_from(hops.len()).unwrap_or(0) + 1,
                ttl: Some(64),
            },
        })
    }

    async fn dns(&self, query: &DnsQuery) -> Result<std::result::Result<Vec<DnsRecord>, DnsFailure>> {
        locks::lock(&self.dns_queries).push(query.clone());
        Ok(locks::lock(&self.dns)
            .get(&(query.name.to_ascii_lowercase(), query.record_type))
            .cloned()
            .unwrap_or(Err(DnsFailure::NoSuchName)))
    }

    async fn connect(&self, to: SocketAddr, timeout: Duration) -> std::result::Result<BoxedStream, ConnectFailure> {
        locks::lock(&self.connects).push(to);
        let behaviour = locks::lock(&self.ports).get(&to).cloned().unwrap_or(FakePort::Refused);
        match behaviour {
            FakePort::Refused => Err(ConnectFailure::Refused),
            FakePort::Silent => {
                tokio::time::sleep(timeout).await;
                Err(ConnectFailure::TimedOut)
            }
            FakePort::Banner(bytes) => {
                let (mut ours, theirs) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let _ = ours.write_all(&bytes).await;
                    // Holds the connection open a moment, like a service waiting for the client.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    drop(ours);
                });
                Ok(Box::new(theirs))
            }
            FakePort::Forward(server) => match tokio::net::TcpStream::connect(server).await {
                Ok(stream) => Ok(Box::new(stream)),
                Err(err) => Err(crate::adapters::net_tools::connect_failure(&err)),
            },
        }
    }

    async fn check_chain(&self, chain: &[Vec<u8>], usage: TrustUse) -> Result<TrustVerdict> {
        locks::lock(&self.checked).push((chain.len(), usage));
        Ok(locks::lock(&self.verdict).clone().unwrap_or_else(|| TrustVerdict {
            trusted: false,
            problems: vec!["the fake trusts nothing".into()],
            built: chain.to_vec(),
        }))
    }

    async fn adapters(&self) -> Result<Vec<LocalAdapter>> {
        Ok(locks::lock(&self.adapters).clone())
    }

    async fn send_datagram(&self, from: Option<IpAddr>, to: SocketAddr, broadcast: bool, payload: &[u8]) -> Result<()> {
        locks::lock(&self.sent).push(SentDatagram {
            from,
            to,
            broadcast,
            payload: payload.to_vec(),
        });
        Ok(())
    }
}
