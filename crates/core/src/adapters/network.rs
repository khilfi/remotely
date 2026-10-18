//! Network adapter: DNS lookups (QL-03: the address or name a session is missing, before connecting)
//! and a cheap TCP reachability probe (QL-04, MO-08 lite: the dots in the Terminal page's session tree).
//!
//! The probe opens a TCP connection to the session's port and closes it at once: no SSH handshake,
//! nothing sent, nothing logged in. Reads only, so it skips the command bus.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::error::{CoreError, Result};

/// The longest a DNS lookup may take before it counts as failed.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

#[async_trait]
pub trait NetworkAdapter: Send + Sync {
    /// The addresses `host` resolves to, in the resolver's order. An IP address resolves to itself.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>>;

    /// The name reverse DNS gives `ip`, if it has one.
    async fn reverse(&self, ip: IpAddr) -> Option<String>;

    /// Opens a TCP connection to `host:port` and closes it again. How long connecting took, or why
    /// it failed.
    async fn probe(&self, host: &str, port: u16, timeout: Duration) -> Result<Duration>;
}

/// The host as a socket address wants it: IPv6 without brackets.
pub fn bare_host(host: &str) -> &str {
    host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
}

/// The IP address `host` already is, if it is one.
pub fn ip_literal(host: &str) -> Option<IpAddr> {
    bare_host(host).parse().ok()
}

/// The operating system's resolver and sockets.
pub struct SystemNetwork;

#[async_trait]
impl NetworkAdapter for SystemNetwork {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        if let Some(ip) = ip_literal(host) {
            return Ok(vec![ip]);
        }
        let found = tokio::time::timeout(LOOKUP_TIMEOUT, tokio::net::lookup_host((bare_host(host), 0)))
            .await
            .map_err(|_| CoreError::Network(format!("looking up {host} took too long")))?
            .map_err(|err| CoreError::Network(format!("{host} could not be found: {err}")))?;
        let mut ips: Vec<IpAddr> = Vec::new();
        for addr in found {
            if !ips.contains(&addr.ip()) {
                ips.push(addr.ip());
            }
        }
        if ips.is_empty() {
            return Err(CoreError::Network(format!("{host} has no address")));
        }
        Ok(ips)
    }

    async fn reverse(&self, ip: IpAddr) -> Option<String> {
        let lookup = tokio::task::spawn_blocking(move || reverse_lookup(ip));
        match tokio::time::timeout(LOOKUP_TIMEOUT, lookup).await {
            Ok(Ok(name)) => name,
            _ => None,
        }
    }

    async fn probe(&self, host: &str, port: u16, timeout: Duration) -> Result<Duration> {
        let started = Instant::now();
        let stream = tokio::time::timeout(timeout, TcpStream::connect((bare_host(host), port)))
            .await
            .map_err(|_| CoreError::Network(format!("no answer within {} s", timeout.as_secs().max(1))))?
            .map_err(|err| CoreError::Network(probe_failure(&err)))?;
        let took = started.elapsed();
        drop(stream);
        Ok(took)
    }
}

/// Plain words for a failed probe.
fn probe_failure(err: &std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::ConnectionRefused => "the port is closed (connection refused)".into(),
        std::io::ErrorKind::TimedOut => "no answer".into(),
        _ => err.to_string(),
    }
}

/// Reverse DNS through Windows' resolver (hosts file, DNS, NetBIOS). `None` when the address has no name.
#[cfg(windows)]
fn reverse_lookup(ip: IpAddr) -> Option<String> {
    use windows::Win32::Networking::WinSock::{
        socklen_t, GetNameInfoW, WSACleanup, WSAStartup, AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0,
        NI_MAXHOST, NI_NAMEREQD, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, WSADATA,
    };

    let mut data = WSADATA::default();
    // SAFETY: `data` is a live WSADATA for the call to fill; a successful start is paired with the
    // WSACleanup below (Winsock counts them).
    if unsafe { WSAStartup(0x0202, &mut data) } != 0 {
        return None;
    }
    let mut name = [0u16; NI_MAXHOST as usize];
    // NI_NAMEREQD: fail rather than hand back the address itself when it has no name.
    let flags = NI_NAMEREQD as i32;
    let status = match ip {
        IpAddr::V4(v4) => {
            let addr = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    // Network byte order: the octets as they are in memory.
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.octets()),
                    },
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `addr` is a live SOCKADDR_IN and the length passed is its size; `name` is a
            // writable buffer whose length the wrapper passes along.
            unsafe {
                GetNameInfoW(
                    std::ptr::from_ref(&addr).cast::<SOCKADDR>(),
                    socklen_t(std::mem::size_of::<SOCKADDR_IN>() as i32),
                    Some(&mut name),
                    None,
                    flags,
                )
            }
        }
        IpAddr::V6(v6) => {
            let addr = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                ..Default::default()
            };
            // SAFETY: as above, for a SOCKADDR_IN6.
            unsafe {
                GetNameInfoW(
                    std::ptr::from_ref(&addr).cast::<SOCKADDR>(),
                    socklen_t(std::mem::size_of::<SOCKADDR_IN6>() as i32),
                    Some(&mut name),
                    None,
                    flags,
                )
            }
        }
    };
    // SAFETY: pairs the successful WSAStartup above.
    unsafe { WSACleanup() };
    if status != 0 {
        return None;
    }
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let name = String::from_utf16_lossy(&name[..len]);
    let name = name.trim().trim_end_matches('.');
    (!name.is_empty() && name.parse::<IpAddr>().is_err()).then(|| name.to_owned())
}

#[cfg(not(windows))]
fn reverse_lookup(_ip: IpAddr) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_literals_are_recognised_with_or_without_brackets() {
        assert_eq!(ip_literal("192.0.2.10"), Some("192.0.2.10".parse().unwrap()));
        assert_eq!(ip_literal("[2001:db8::1]"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(ip_literal("2001:db8::1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(ip_literal("web01.example.com"), None);
        assert_eq!(bare_host("[2001:db8::1]"), "2001:db8::1");
    }

    #[tokio::test]
    async fn an_ip_address_resolves_to_itself_without_a_lookup() {
        let ips = SystemNetwork.resolve("192.0.2.10").await.unwrap();
        assert_eq!(ips, vec!["192.0.2.10".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn a_probe_reaches_a_listening_port_on_this_machine() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let took = SystemNetwork
            .probe("127.0.0.1", port, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(took < Duration::from_secs(2));
    }
}
