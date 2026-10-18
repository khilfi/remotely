//! Name resolution adapter (QL-01): the IP addresses a session's host name stands for, so a session
//! can be linked to the VM whose guest IP it reaches. Reads only.
//!
//! [`SystemResolver`] asks Windows (the same resolver `ssh` and the browser use, hosts file included)
//! through `tokio::net::lookup_host`. A lookup never connects to the host itself.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::error::{CoreError, Result};

#[async_trait]
pub trait Resolver: Send + Sync {
    /// Every address `host` resolves to, without duplicates. `host` is a name, not an IP literal.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>>;
}

/// The operating system's resolver.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let found = tokio::net::lookup_host((host, 0)).await.map_err(|err| {
            CoreError::Io(std::io::Error::new(
                err.kind(),
                format!("could not resolve {host}: {err}"),
            ))
        })?;
        let mut addresses: Vec<IpAddr> = Vec::new();
        for address in found {
            let ip = address.ip().to_canonical();
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        Ok(addresses)
    }
}

/// `host` as an IP address, when it is one: `192.0.2.10`, `2001:db8::1`, `[2001:db8::1]` or
/// `fe80::1%eth0` (the zone is dropped). IPv4 written as IPv6 (`::ffff:192.0.2.10`) becomes IPv4.
pub fn ip_literal(host: &str) -> Option<IpAddr> {
    let host = host.trim();
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let host = host.split('%').next().unwrap_or(host);
    host.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_literals_are_recognised_in_every_spelling() {
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(ip_literal("192.0.2.10"), Some(v4));
        assert_eq!(ip_literal(" 192.0.2.10 "), Some(v4));
        assert_eq!(ip_literal("::ffff:192.0.2.10"), Some(v4));
        assert_eq!(ip_literal("2001:db8::1"), Some(v6));
        assert_eq!(ip_literal("[2001:db8::1]"), Some(v6));
        assert_eq!(ip_literal("fe80::1%eth0"), "fe80::1".parse().ok());
        assert_eq!(ip_literal("web01.example.com"), None);
        assert_eq!(ip_literal("192.0.2"), None);
    }

    // Resolves a name the hosts file always has; no network needed.
    #[tokio::test]
    async fn the_system_resolver_resolves_localhost() {
        let found = SystemResolver.resolve("localhost").await.unwrap();
        assert!(found.iter().all(|ip| ip.is_loopback()), "{found:?}");
        assert!(!found.is_empty());
    }
}
