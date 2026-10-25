//! VM-11: what a [`crate::command_bus::Command::HostNetwork`] does, and the checks before any target is looked up.
//!
//! One operation adds or removes one NAT port forward. Its one target says where:
//! - [`TargetRef::Network`] on Workstation: a NAT vmnet's forward (`setPortForwarding`); the guest's address is
//!   needed, the host address is not (Workstation listens on every address of this PC), and the name is an optional
//!   description;
//! - [`TargetRef::Network`] on VirtualBox: a NAT network's rule (`natnetwork modify --port-forward-4`); a name and
//!   the guest's address are needed;
//! - [`TargetRef::Vm`] on VirtualBox: a VM's NAT adapter rule (`--natpfN`); a name and the adapter (1 to 8) are
//!   needed, the guest's address is optional (VirtualBox's own DHCP address).
//!
//! A removal names the forward as the list showed it, so what is approved is what goes.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::adapters::host_networks::{ForwardProtocol, VboxRule, VmnetForward, MAX_RULE_NAME};
use crate::adapters::hypervisor::Hypervisor;
use crate::domain::TargetRef;
use crate::error::{CoreError, Result};

/// VM-11: one NAT port forward, as the UI sends it and the approval shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NatForward {
    /// VirtualBox's rule name (needed there); Workstation's description (optional).
    #[serde(default)]
    pub name: Option<String>,
    pub protocol: ForwardProtocol,
    /// VirtualBox: the address of this PC it listens on; `None` is every address. Workstation always listens on
    /// every address.
    #[serde(default)]
    pub host_ip: Option<String>,
    pub host_port: u16,
    #[serde(default)]
    pub guest_ip: Option<String>,
    pub guest_port: u16,
    /// A VirtualBox VM's NAT adapter, 1 to 8.
    #[serde(default)]
    pub slot: Option<u32>,
}

impl NatForward {
    /// `tcp 8080 → 203.0.113.10:80 'web'`, `'ssh': tcp 127.0.0.1:2222 → guest:22`.
    pub fn describe(&self) -> String {
        let host = match &self.host_ip {
            Some(ip) => format!("{ip}:{}", self.host_port),
            None => self.host_port.to_string(),
        };
        let guest = format!(
            "{}:{}",
            self.guest_ip.as_deref().unwrap_or("the guest"),
            self.guest_port
        );
        let line = format!("{} {host} → {guest}", self.protocol.as_str());
        match self.name.as_deref().filter(|n| !n.is_empty()) {
            Some(name) => format!("'{name}': {line}"),
            None => line,
        }
    }

    /// The forward as Workstation takes it.
    pub fn vmnet(&self) -> VmnetForward {
        VmnetForward {
            protocol: self.protocol,
            host_port: self.host_port,
            guest_ip: self.guest_ip.clone().unwrap_or_default(),
            guest_port: self.guest_port,
            description: self.name.clone().filter(|n| !n.is_empty()),
        }
    }

    /// The rule as VirtualBox takes it.
    pub fn vbox(&self) -> VboxRule {
        VboxRule {
            name: self.name.clone().unwrap_or_default(),
            protocol: self.protocol,
            host_ip: self.host_ip.clone(),
            host_port: self.host_port,
            guest_ip: self.guest_ip.clone(),
            guest_port: self.guest_port,
        }
    }

    /// A Workstation forward as the bus names it.
    pub fn from_vmnet(forward: &VmnetForward) -> Self {
        Self {
            name: forward.description.clone(),
            protocol: forward.protocol,
            host_ip: None,
            host_port: forward.host_port,
            guest_ip: Some(forward.guest_ip.clone()),
            guest_port: forward.guest_port,
            slot: None,
        }
    }

    /// A VirtualBox rule as the bus names it; `slot` for a VM's NAT adapter.
    pub fn from_vbox(rule: &VboxRule, slot: Option<u32>) -> Self {
        Self {
            name: Some(rule.name.clone()),
            protocol: rule.protocol,
            host_ip: rule.host_ip.clone(),
            host_port: rule.host_port,
            guest_ip: rule.guest_ip.clone(),
            guest_port: rule.guest_port,
            slot,
        }
    }
}

/// VM-11: add or remove one NAT port forward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum HostNetworkOp {
    AddForward { forward: NatForward },
    RemoveForward { forward: NatForward },
}

impl HostNetworkOp {
    pub fn forward(&self) -> &NatForward {
        match self {
            HostNetworkOp::AddForward { forward } | HostNetworkOp::RemoveForward { forward } => forward,
        }
    }

    /// For dialogs, job lists and the audit log: `Add the port forward tcp 8080 → 203.0.113.10:80 on vmnet8`.
    pub fn summary(&self, targets: &[TargetRef]) -> String {
        let place = match targets.first() {
            Some(TargetRef::Network {
                hypervisor: Hypervisor::Vmware,
                name,
            }) => format!(" on {name}"),
            Some(TargetRef::Network { name, .. }) => format!(" on the NAT network '{name}'"),
            Some(TargetRef::Vm { .. }) => match self.forward().slot {
                Some(slot) => format!(" on NAT adapter {slot}"),
                None => String::new(),
            },
            _ => String::new(),
        };
        match self {
            HostNetworkOp::AddForward { forward } => format!("Add the port forward {}{place}", forward.describe()),
            HostNetworkOp::RemoveForward { forward } => {
                format!("Remove the port forward {}{place}", forward.describe())
            }
        }
    }
}

/// Where a forward goes, from its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardPlace<'a> {
    /// A Workstation NAT vmnet.
    Vmnet(&'a str),
    /// A VirtualBox NAT network.
    NatNetwork(&'a str),
    /// A VirtualBox VM (its UUID) and its NAT adapter.
    VboxVm(&'a str, u32),
}

/// The one target's place; an error says what fits.
pub fn place<'a>(targets: &'a [TargetRef], forward: &NatForward) -> Result<ForwardPlace<'a>> {
    let invalid = |m: &str| Err(CoreError::InvalidInput(m.to_owned()));
    let [target] = targets else {
        return invalid("A port forward changes on one network or VM at a time.");
    };
    match target {
        TargetRef::Network {
            hypervisor: Hypervisor::Vmware,
            name,
        } => Ok(ForwardPlace::Vmnet(name)),
        TargetRef::Network {
            hypervisor: Hypervisor::VirtualBox,
            name,
        } => Ok(ForwardPlace::NatNetwork(name)),
        TargetRef::Vm { vmx_path } if Hypervisor::of_key(vmx_path) == Hypervisor::VirtualBox => match forward.slot {
            Some(slot) => Ok(ForwardPlace::VboxVm(vmx_path, slot)),
            None => invalid("Say which of the VM's NAT adapters (1 to 8) the rule is for."),
        },
        TargetRef::Vm { .. } => {
            invalid("Workstation's port forwards belong to its NAT network (vmnet8), not to one VM.")
        }
        _ => invalid("Port forwards change on a host network or a VirtualBox VM."),
    }
}

/// `vmnet` and up to three digits.
fn valid_vmnet(name: &str) -> bool {
    name.strip_prefix("vmnet")
        .is_some_and(|n| (1..=3).contains(&n.len()) && n.chars().all(|c| c.is_ascii_digit()))
}

/// A VirtualBox NAT network's name, as `natnetwork add --netname` took it: no control characters, and not one
/// that VBoxManage could read as an option.
fn valid_network_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_RULE_NAME
        && !name.starts_with('-')
        && name.trim() == name
        && !name.chars().any(char::is_control)
}

/// A rule name VirtualBox can list and delete again: letters, digits, spaces, `-`, `_` and `.` (its separators `,`,
/// `:`, `[` and `]` can't be in it).
fn check_rule_name(name: Option<&str>) -> Result<&str> {
    let invalid = |m: String| Err(CoreError::InvalidInput(m));
    let Some(name) = name.filter(|n| !n.trim().is_empty()) else {
        return invalid("Give the rule a name.".into());
    };
    if name.trim() != name {
        return invalid("A rule name can't start or end with a space.".into());
    }
    if name.chars().count() > MAX_RULE_NAME {
        return invalid(format!("A rule name can be at most {MAX_RULE_NAME} characters."));
    }
    if name.starts_with('-') {
        return invalid("A rule name can't start with '-'.".into());
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
    {
        return invalid("A rule name can hold letters, digits, spaces, '-', '_' and '.'.".into());
    }
    Ok(name)
}

/// An IPv4 address a forward can listen on or lead to.
fn check_ip(ip: &str, what: &str) -> Result<()> {
    let parsed: Ipv4Addr = ip
        .parse()
        .map_err(|_| CoreError::InvalidInput(format!("'{ip}' is not an IPv4 address ({what}).")))?;
    if parsed.is_unspecified() || parsed.is_broadcast() || parsed.is_multicast() {
        return Err(CoreError::InvalidInput(format!(
            "{ip} can't be the {what}: give one host's address."
        )));
    }
    Ok(())
}

/// VM-11: the checks before any target is looked up.
pub fn validate(targets: &[TargetRef], op: &HostNetworkOp) -> Result<()> {
    let forward = op.forward();
    let invalid = |m: &str| Err(CoreError::InvalidInput(m.to_owned()));
    if forward.host_port == 0 || forward.guest_port == 0 {
        return invalid("Ports are 1 to 65535.");
    }
    if let Some(ip) = &forward.guest_ip {
        check_ip(ip, "guest's address")?;
    }
    if let Some(ip) = &forward.host_ip {
        check_ip(ip, "address of this PC")?;
    }
    match place(targets, forward)? {
        ForwardPlace::Vmnet(vmnet) => {
            if !valid_vmnet(vmnet) {
                return invalid("That is not a Workstation network (vmnet0 to vmnet255).");
            }
            if forward.guest_ip.is_none() {
                return invalid("Give the guest's address on the NAT network.");
            }
            if forward.host_ip.is_some() {
                return invalid("Workstation's forwards listen on every address of this PC: leave the address empty.");
            }
            if forward.slot.is_some() {
                return invalid("Workstation's forwards belong to the network, not to a VM's adapter.");
            }
            if let Some(description) = forward.name.as_deref().filter(|d| !d.is_empty()) {
                if description.chars().count() > MAX_RULE_NAME {
                    return Err(CoreError::InvalidInput(format!(
                        "A description can be at most {MAX_RULE_NAME} characters."
                    )));
                }
                if description.chars().any(|c| c.is_control() || c == '"') {
                    return invalid("A description can't hold quotes, line breaks or tabs.");
                }
            }
        }
        ForwardPlace::NatNetwork(network) => {
            if !valid_network_name(network) {
                return invalid("That is not a NAT network name VirtualBox lists.");
            }
            check_rule_name(forward.name.as_deref())?;
            if forward.guest_ip.is_none() {
                return invalid("Give the guest's address on the NAT network.");
            }
            if forward.slot.is_some() {
                return invalid("A NAT network's rules belong to the network, not to a VM's adapter.");
            }
        }
        ForwardPlace::VboxVm(_, slot) => {
            check_rule_name(forward.name.as_deref())?;
            if !(1..=8).contains(&slot) {
                return invalid("VirtualBox numbers a VM's adapters 1 to 8.");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vmnet8() -> Vec<TargetRef> {
        vec![TargetRef::Network {
            hypervisor: Hypervisor::Vmware,
            name: "vmnet8".into(),
        }]
    }

    fn lab_net() -> Vec<TargetRef> {
        vec![TargetRef::Network {
            hypervisor: Hypervisor::VirtualBox,
            name: "lab-net".into(),
        }]
    }

    fn vbox_vm() -> Vec<TargetRef> {
        vec![TargetRef::Vm {
            vmx_path: "00000000-0000-4000-8000-0000000000aa".into(),
        }]
    }

    fn web() -> NatForward {
        NatForward {
            name: Some("web".into()),
            protocol: ForwardProtocol::Tcp,
            host_ip: None,
            host_port: 8080,
            guest_ip: Some("203.0.113.10".into()),
            guest_port: 80,
            slot: None,
        }
    }

    fn add(forward: NatForward) -> HostNetworkOp {
        HostNetworkOp::AddForward { forward }
    }

    #[test]
    fn a_workstation_forward_needs_a_guest_address_and_no_host_address() {
        assert!(validate(&vmnet8(), &add(web())).is_ok());
        let no_guest = NatForward {
            guest_ip: None,
            ..web()
        };
        assert!(validate(&vmnet8(), &add(no_guest)).is_err());
        let host = NatForward {
            host_ip: Some("127.0.0.1".into()),
            ..web()
        };
        assert!(validate(&vmnet8(), &add(host)).is_err());
        let quote = NatForward {
            name: Some("a \"quoted\" one".into()),
            ..web()
        };
        assert!(validate(&vmnet8(), &add(quote)).is_err());
        let bad_net = vec![TargetRef::Network {
            hypervisor: Hypervisor::Vmware,
            name: "lab".into(),
        }];
        assert!(validate(&bad_net, &add(web())).is_err());
    }

    #[test]
    fn virtualbox_rules_need_a_name_virtualbox_can_list_again() {
        assert!(validate(&lab_net(), &add(web())).is_ok());
        for name in [
            None,
            Some(""),
            Some("a:b"),
            Some("a,b"),
            Some("[x]"),
            Some(" pad"),
            Some("-x"),
        ] {
            let forward = NatForward {
                name: name.map(String::from),
                ..web()
            };
            assert!(validate(&lab_net(), &add(forward)).is_err(), "{name:?}");
        }
        let long = NatForward {
            name: Some("x".repeat(MAX_RULE_NAME + 1)),
            ..web()
        };
        assert!(validate(&lab_net(), &add(long)).is_err());
    }

    #[test]
    fn a_vms_rule_needs_its_adapter_and_may_leave_the_guest_out() {
        let rule = NatForward {
            slot: Some(1),
            guest_ip: None,
            host_ip: Some("127.0.0.1".into()),
            ..web()
        };
        assert!(validate(&vbox_vm(), &add(rule.clone())).is_ok());
        assert!(validate(
            &vbox_vm(),
            &add(NatForward {
                slot: None,
                ..rule.clone()
            })
        )
        .is_err());
        assert!(validate(
            &vbox_vm(),
            &add(NatForward {
                slot: Some(9),
                ..rule.clone()
            })
        )
        .is_err());
        let workstation_vm = vec![TargetRef::Vm {
            vmx_path: r"C:\VMs\web01\web01.vmx".into(),
        }];
        assert!(validate(&workstation_vm, &add(rule)).is_err());
    }

    #[test]
    fn ports_and_addresses_are_checked() {
        for (host_port, guest_port, guest_ip) in [
            (0, 80, "203.0.113.10"),
            (8080, 0, "203.0.113.10"),
            (8080, 80, "0.0.0.0"),
            (8080, 80, "255.255.255.255"),
            (8080, 80, "224.0.0.1"),
            (8080, 80, "web01.example.com"),
        ] {
            let forward = NatForward {
                host_port,
                guest_port,
                guest_ip: Some(guest_ip.into()),
                ..web()
            };
            assert!(
                validate(&vmnet8(), &add(forward)).is_err(),
                "{host_port} {guest_port} {guest_ip}"
            );
        }
        assert!(validate(&[], &add(web())).is_err(), "one target");
        assert!(
            validate(&[vmnet8(), lab_net()].concat(), &add(web())).is_err(),
            "one target"
        );
        assert!(validate(&[TargetRef::App], &add(web())).is_err());
    }

    #[test]
    fn summaries_name_the_forward_and_where() {
        assert_eq!(
            add(web()).summary(&vmnet8()),
            "Add the port forward 'web': tcp 8080 → 203.0.113.10:80 on vmnet8"
        );
        let remove = HostNetworkOp::RemoveForward {
            forward: NatForward {
                slot: Some(2),
                guest_ip: None,
                ..web()
            },
        };
        assert_eq!(
            remove.summary(&vbox_vm()),
            "Remove the port forward 'web': tcp 8080 → the guest:80 on NAT adapter 2"
        );
        assert_eq!(
            add(NatForward {
                name: None,
                host_ip: Some("127.0.0.1".into()),
                ..web()
            })
            .summary(&lab_net()),
            "Add the port forward tcp 127.0.0.1:8080 → 203.0.113.10:80 on the NAT network 'lab-net'"
        );
    }

    #[test]
    fn forwards_convert_to_and_from_the_tools_forms() {
        let rule = web().vbox();
        assert_eq!(NatForward::from_vbox(&rule, None), web());
        let vmnet = web().vmnet();
        assert_eq!(vmnet.description.as_deref(), Some("web"));
        assert_eq!(NatForward::from_vmnet(&vmnet), web());
    }
}
