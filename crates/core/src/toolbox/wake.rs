//! FD-09 Wake-on-LAN: a magic packet (six 0xFF bytes, then the MAC sixteen times) in one UDP datagram, port 9 by
//! default, to the subnet broadcast of an adapter of this PC or to an address typed in (a directed broadcast such as
//! `192.0.2.255`). Sending it is [`crate::command_bus::Command::WakeOnLan`]: Low, a Prod target Medium, audited. The
//! MAC comes from a VM's hardware (MO-13), the VM a session is linked to (QL-01), or what the user typed.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::adapters::net_tools::{LocalAdapter, NetworkTools};
use crate::domain::TargetRef;
use crate::error::{CoreError, Result};

/// Wake-on-LAN's usual port (the discard service); some cards listen on 7.
pub const DEFAULT_PORT: u16 = 9;

/// What a [`crate::command_bus::Command::WakeOnLan`] sends, and where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeSpec {
    /// The machine's MAC, in any common spelling; it is checked and written `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    pub destination: WakeDestination,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

/// Where the packet goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum WakeDestination {
    /// The subnet broadcast of the adapter of this PC that has this IPv4 address, sent from it.
    Adapter { address: Ipv4Addr },
    /// This address: a directed broadcast (`192.0.2.255`) for a subnet behind a router, or one host.
    Address { address: Ipv4Addr },
}

impl WakeSpec {
    /// The MAC as six bytes, or why it isn't one a machine can have.
    pub fn mac_bytes(&self) -> Result<[u8; 6]> {
        parse_mac(&self.mac)
    }

    /// Checks what was typed: a machine's MAC, a port, an address a packet can go to.
    pub fn validate(&self) -> Result<()> {
        self.mac_bytes()?;
        if self.port == 0 {
            return Err(CoreError::InvalidInput(
                "Choose a port from 1 to 65535 (9 is usual).".into(),
            ));
        }
        let address = match self.destination {
            WakeDestination::Adapter { address } | WakeDestination::Address { address } => address,
        };
        if address.is_unspecified() || address.is_multicast() {
            return Err(CoreError::InvalidInput(format!(
                "{address} isn't an address a magic packet can go to."
            )));
        }
        Ok(())
    }

    /// "Wake up aa:bb:cc:dd:ee:ff (to 192.0.2.255, port 9)".
    pub fn summary(&self) -> String {
        let mac = parse_mac(&self.mac).map_or_else(|_| self.mac.clone(), |b| format_mac(&b));
        let place = match self.destination {
            WakeDestination::Adapter { address } => format!("the broadcast of the adapter {address}"),
            WakeDestination::Address { address } => address.to_string(),
        };
        format!("Wake up {mac} (to {place}, port {})", self.port)
    }

    /// One target: the session or VM it wakes, or this app for a MAC typed on its own.
    pub fn check_targets(targets: &[TargetRef]) -> Result<()> {
        match targets {
            [TargetRef::Vm { .. } | TargetRef::Session { .. } | TargetRef::App] => Ok(()),
            _ => Err(CoreError::InvalidInput(
                "Wake-on-LAN wakes one machine: a session, a VM, or a MAC typed in.".into(),
            )),
        }
    }
}

/// `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF`, `aabb.ccdd.eeff` or `aabbccddeeff`. Refuses all zeros, the broadcast
/// MAC and group (multicast) MACs: no network card has one.
pub fn parse_mac(text: &str) -> Result<[u8; 6]> {
    let hex: String = text
        .trim()
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
        .collect();
    let refuse = || {
        CoreError::InvalidInput(format!(
            "'{}' isn't a MAC address (like aa:bb:cc:dd:ee:ff).",
            text.trim()
        ))
    };
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(refuse());
    }
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| refuse())?;
    }
    if mac == [0; 6] || mac == [0xff; 6] || mac[0] & 1 == 1 {
        return Err(CoreError::InvalidInput(format!(
            "{} is not a network card's own MAC address.",
            format_mac(&mac)
        )));
    }
    Ok(mac)
}

/// `aa:bb:cc:dd:ee:ff`.
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// The magic packet: six 0xFF bytes, then the MAC sixteen times (102 bytes).
pub fn magic_packet(mac: &[u8; 6]) -> Vec<u8> {
    let mut packet = vec![0xffu8; 6];
    for _ in 0..16 {
        packet.extend_from_slice(mac);
    }
    packet
}

/// The broadcast address of `address/prefix`.
pub fn broadcast_of(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let prefix = u32::from(prefix.min(32));
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Ipv4Addr::from(u32::from(address) | !mask)
}

/// An adapter of this PC a magic packet can leave from: up, not loopback, with an IPv4 address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeAdapter {
    pub name: String,
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub broadcast: Ipv4Addr,
}

/// The adapters a magic packet can leave from, each IPv4 address once.
pub fn wake_adapters(adapters: &[LocalAdapter]) -> Vec<WakeAdapter> {
    let mut out = Vec::new();
    for adapter in adapters.iter().filter(|a| a.up && !a.loopback) {
        for address in &adapter.addresses {
            if let IpAddr::V4(v4) = address.address {
                // APIPA (169.254.x.x) addresses mean no DHCP answer: a subnet nothing else is on.
                if v4.is_link_local() || v4.is_loopback() {
                    continue;
                }
                out.push(WakeAdapter {
                    name: adapter.name.clone(),
                    address: v4,
                    prefix: address.prefix,
                    broadcast: broadcast_of(v4, address.prefix),
                });
            }
        }
    }
    out
}

/// Sends the packet: what the job's step does. Returns the note for the job ("sent to 192.0.2.255:9 from ...").
pub async fn send(tools: &dyn NetworkTools, spec: &WakeSpec) -> Result<String> {
    spec.validate()?;
    let mac = spec.mac_bytes()?;
    let packet = magic_packet(&mac);
    let (from, to) = match spec.destination {
        WakeDestination::Adapter { address } => {
            let adapters = wake_adapters(&tools.adapters().await?);
            let Some(adapter) = adapters.iter().find(|a| a.address == address) else {
                return Err(CoreError::Network(format!(
                    "this PC has no adapter with the address {address} now"
                )));
            };
            (Some(IpAddr::V4(address)), adapter.broadcast)
        }
        WakeDestination::Address { address } => (None, address),
    };
    let target = SocketAddr::new(IpAddr::V4(to), spec.port);
    tools.send_datagram(from, target, true, &packet).await?;
    let from = from.map(|ip| format!(" from {ip}")).unwrap_or_default();
    Ok(format!(
        "magic packet for {} sent to {target}{from}; the machine wakes if its card and firmware allow it",
        format_mac(&mac)
    ))
}

/// A MAC the Wake up tab offers for a target, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownMac {
    pub mac: String,
    /// "ethernet0 of the VM 'web01'".
    pub source: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn macs_are_read_in_every_common_spelling() {
        let mac = [0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef];
        for text in [
            "00:0c:29:ab:cd:ef",
            "00-0C-29-AB-CD-EF",
            "000c.29ab.cdef",
            "000c29abcdef",
            " 00:0C:29:ab:cd:EF ",
        ] {
            assert_eq!(parse_mac(text).unwrap(), mac, "{text}");
        }
        assert_eq!(format_mac(&mac), "00:0c:29:ab:cd:ef");
    }

    #[test]
    fn macs_no_card_has_are_refused() {
        for text in [
            "",
            "00:0c:29:ab:cd",
            "00:0c:29:ab:cd:ef:01",
            "zz:0c:29:ab:cd:ef",
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:01",
        ] {
            assert!(parse_mac(text).is_err(), "{text}");
        }
    }

    #[test]
    fn the_magic_packet_is_six_ff_then_the_mac_sixteen_times() {
        let mac = [0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef];
        let packet = magic_packet(&mac);
        assert_eq!(packet.len(), 102);
        assert_eq!(&packet[..6], &[0xff; 6]);
        for i in 0..16 {
            assert_eq!(&packet[6 + i * 6..12 + i * 6], &mac);
        }
    }

    #[test]
    fn broadcasts_are_worked_out_from_the_prefix() {
        let ip: Ipv4Addr = "192.0.2.10".parse().unwrap();
        assert_eq!(broadcast_of(ip, 24), "192.0.2.255".parse::<Ipv4Addr>().unwrap());
        assert_eq!(broadcast_of(ip, 30), "192.0.2.11".parse::<Ipv4Addr>().unwrap());
        assert_eq!(broadcast_of(ip, 32), ip);
        assert_eq!(broadcast_of(ip, 0), Ipv4Addr::BROADCAST);
    }

    #[test]
    fn a_spec_is_checked_before_it_is_sent() {
        let spec = |mac: &str, address: &str, port: u16| WakeSpec {
            mac: mac.into(),
            destination: WakeDestination::Address {
                address: address.parse().unwrap(),
            },
            port,
        };
        assert!(spec("00:0c:29:ab:cd:ef", "192.0.2.255", 9).validate().is_ok());
        assert!(spec("00:0c:29:ab:cd:ef", "192.0.2.255", 0).validate().is_err());
        assert!(spec("00:0c:29:ab:cd:ef", "0.0.0.0", 9).validate().is_err());
        assert!(spec("00:0c:29:ab:cd:ef", "224.0.0.1", 9).validate().is_err());
        assert!(spec("nope", "192.0.2.255", 9).validate().is_err());
        assert_eq!(
            spec("000C29ABCDEF", "192.0.2.255", 9).summary(),
            "Wake up 00:0c:29:ab:cd:ef (to 192.0.2.255, port 9)"
        );
        assert!(WakeSpec::check_targets(&[TargetRef::App]).is_ok());
        assert!(WakeSpec::check_targets(&[]).is_err());
        assert!(WakeSpec::check_targets(&[TargetRef::App, TargetRef::App]).is_err());
    }

    #[test]
    fn only_up_adapters_with_a_routable_ipv4_address_can_send() {
        use crate::adapters::net_tools::AdapterAddress;
        let adapter = |name: &str, up: bool, loopback: bool, ip: &str, prefix: u8| LocalAdapter {
            name: name.into(),
            mac: None,
            up,
            loopback,
            addresses: vec![AdapterAddress {
                address: ip.parse().unwrap(),
                prefix,
            }],
            dns_servers: Vec::new(),
        };
        let found = wake_adapters(&[
            adapter("Ethernet", true, false, "192.0.2.10", 24),
            adapter("Wi-Fi", false, false, "198.51.100.7", 24),
            adapter("Loopback", true, true, "127.0.0.1", 8),
            adapter("Ethernet 2", true, false, "169.254.3.4", 16),
            adapter("Ethernet 3", true, false, "2001:db8::1", 64),
        ]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].broadcast, "192.0.2.255".parse::<Ipv4Addr>().unwrap());
    }
}
