//! FD-09 DNS lookups: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV and CAA, through Windows' resolver or a chosen
//! server, with each record's TTL and which server was asked. A read: no tier, not audited.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::adapters::net_tools::{DnsFailure, DnsQuery, DnsRecord, NetworkTools, RecordType};
use crate::error::{CoreError, Result};

/// The longest a lookup waits.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(10);

/// What the DNS tab asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsRequest {
    /// A name, or for PTR an IP address (turned into its `in-addr.arpa` or `ip6.arpa` name).
    pub name: String,
    pub record_type: RecordType,
    /// An IP address of the server to ask; empty or `None` for Windows' resolver.
    #[serde(default)]
    pub server: Option<String>,
}

/// Which server answered: Windows' resolver (with the servers this PC is set up with: Windows doesn't say which of
/// them answered, and an answer may come from its cache or the hosts file), or the one chosen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum DnsServerUsed {
    Windows { servers: Vec<IpAddr> },
    Chosen { address: IpAddr },
}

/// The DNS tab's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsResult {
    /// The name asked for (a PTR's `arpa` name). FD-03: `queryName` is a field the presentation masker learns.
    pub query_name: String,
    pub record_type: RecordType,
    pub records: Vec<DnsRecord>,
    /// Why there are no records.
    pub failure: Option<DnsFailure>,
    pub server: DnsServerUsed,
    pub took_ms: u64,
}

/// Checks a name a lookup may take: 1 to 253 characters, no spaces or control characters.
pub fn check_name(name: &str) -> Result<String> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() {
        return Err(CoreError::InvalidInput("Type a name to look up.".into()));
    }
    if name.len() > 253 || name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(CoreError::InvalidInput(format!(
            "'{name}' isn't a name DNS can look up."
        )));
    }
    Ok(name.to_owned())
}

/// The name a PTR lookup asks for: `10.2.0.192.in-addr.arpa` for `192.0.2.10`, the nibbles of an IPv6 address
/// under `ip6.arpa`. A name that isn't an address is asked as it is.
pub fn ptr_name(name: &str) -> String {
    match crate::adapters::network::ip_literal(name) {
        Some(IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        Some(IpAddr::V6(v6)) => {
            let nibbles: Vec<String> = v6
                .octets()
                .iter()
                .rev()
                .flat_map(|b| [b & 0x0f, b >> 4])
                .map(|n| format!("{n:x}"))
                .collect();
            format!("{}.ip6.arpa", nibbles.join("."))
        }
        None => name.to_owned(),
    }
}

/// A CAA record's text: `0 issue "letsencrypt.org"` (flags, tag, value).
pub fn caa_text(bytes: &[u8]) -> String {
    let (Some(&flags), Some(&tag_len)) = (bytes.first(), bytes.get(1)) else {
        return raw_text(bytes);
    };
    let tag_end = 2 + usize::from(tag_len);
    let Some(tag) = bytes.get(2..tag_end) else {
        return raw_text(bytes);
    };
    let value = bytes.get(tag_end..).unwrap_or_default();
    format!(
        "{flags} {} \"{}\"",
        clean(&String::from_utf8_lossy(tag)),
        clean(&String::from_utf8_lossy(value))
    )
}

/// The raw data of a record type the tool doesn't read, in RFC 3597's form: `\# <length> <hex>`.
pub fn raw_text(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().take(512).map(|b| format!("{b:02x}")).collect();
    format!("\\# {} {hex}", bytes.len())
}

/// Text from a DNS answer without control or format characters.
fn clean(text: &str) -> String {
    crate::toolbox::x509::clean(text)
}

/// Runs one lookup.
pub async fn lookup(tools: &dyn NetworkTools, request: &DnsRequest) -> Result<DnsResult> {
    let typed = check_name(&request.name)?;
    let name = if request.record_type == RecordType::Ptr {
        ptr_name(&typed)
    } else {
        typed
    };
    let server = match request.server.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(text) => Some(crate::adapters::network::ip_literal(text).ok_or_else(|| {
            CoreError::InvalidInput(format!("'{text}' isn't an IP address: type the DNS server's address."))
        })?),
    };
    let used = match server {
        Some(address) => DnsServerUsed::Chosen { address },
        None => {
            let mut servers: Vec<IpAddr> = Vec::new();
            for adapter in tools.adapters().await.unwrap_or_default() {
                if adapter.up {
                    for server in adapter.dns_servers {
                        if !servers.contains(&server) {
                            servers.push(server);
                        }
                    }
                }
            }
            DnsServerUsed::Windows { servers }
        }
    };
    let started = Instant::now();
    let answer = tools
        .dns(&DnsQuery {
            name: name.clone(),
            record_type: request.record_type,
            server,
            timeout: DNS_TIMEOUT,
        })
        .await?;
    let took_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (records, failure) = match answer {
        Ok(records) => (
            records
                .into_iter()
                .map(|r| DnsRecord {
                    name: clean(&r.name),
                    record_type: r.record_type,
                    ttl: r.ttl,
                    data: clean(&r.data),
                })
                .collect(),
            None,
        ),
        Err(failure) => (Vec::new(), Some(failure)),
    };
    Ok(DnsResult {
        query_name: name,
        record_type: request.record_type,
        records,
        failure,
        server: used,
        took_ms,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ptr_lookups_ask_for_the_arpa_name() {
        assert_eq!(ptr_name("192.0.2.10"), "10.2.0.192.in-addr.arpa");
        assert_eq!(
            ptr_name("2001:db8::1"),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        assert_eq!(ptr_name("10.2.0.192.in-addr.arpa"), "10.2.0.192.in-addr.arpa");
    }

    #[test]
    fn names_are_checked() {
        assert_eq!(check_name(" web01.example.com. ").unwrap(), "web01.example.com");
        assert!(check_name("").is_err());
        assert!(check_name("web 01").is_err());
        assert!(check_name(&"a".repeat(254)).is_err());
    }

    #[test]
    fn caa_records_read_as_flags_tag_and_value() {
        let mut bytes = vec![0u8, 5];
        bytes.extend_from_slice(b"issue");
        bytes.extend_from_slice(b"ca.example.net");
        assert_eq!(caa_text(&bytes), "0 issue \"ca.example.net\"");
        assert_eq!(caa_text(&[0]), "\\# 1 00");
        assert_eq!(caa_text(&[128, 9, b'i']), "\\# 3 800969");
        assert_eq!(raw_text(&[0xab, 0x01]), "\\# 2 ab01");
    }
}
