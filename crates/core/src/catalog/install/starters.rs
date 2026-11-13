//! VM-28: the starter library, part of the app (not rows in the store): read only, copied to change. Each picks its
//! admin password and SSH key from the vault once copied (`{{password.admin}}`, `{{ssh_key.admin}}`), and each renders
//! and passes its own checks (the tests below).

use super::vars::VariableDef;
use super::{check, CheckFacts, InstallConfig, InstallConfigInput, InstallKind, SecretRef, SecretRefKind};

/// A starter's id starts with this; own configs' ids are UUIDs.
pub const PREFIX: &str = "starter.";

pub struct Starter {
    pub id: &'static str,
    pub name: &'static str,
    pub kind: InstallKind,
    pub body: &'static str,
    /// Own variables and their defaults.
    pub variables: &'static [(&'static str, &'static str)],
    pub notes: &'static str,
}

pub const STARTERS: [Starter; 8] = [
    Starter {
        id: "starter.ubuntu-24.04-minimal",
        name: "Ubuntu 24.04 server, minimal",
        kind: InstallKind::Autoinstall,
        body: include_str!("starters/ubuntu-24.04-minimal.yaml"),
        variables: &[],
        notes: "One admin user with sudo and your SSH key, OpenSSH, LVM, DHCP.",
    },
    Starter {
        id: "starter.ubuntu-24.04-docker",
        name: "Ubuntu 24.04 server with Docker",
        kind: InstallKind::Autoinstall,
        body: include_str!("starters/ubuntu-24.04-docker.yaml"),
        variables: &[],
        notes: "The minimal server with Docker from Ubuntu's archive; the admin user is in the docker group.",
    },
    Starter {
        id: "starter.rocky-9-minimal",
        name: "Rocky Linux 9, minimal",
        kind: InstallKind::Kickstart,
        body: include_str!("starters/rocky-9-minimal.ks"),
        variables: &[],
        notes: "One admin user in wheel with your SSH key, root locked, LVM, DHCP; installs from the ISO.",
    },
    Starter {
        id: "starter.alma-9-minimal",
        name: "AlmaLinux 9, minimal",
        kind: InstallKind::Kickstart,
        body: include_str!("starters/alma-9-minimal.ks"),
        variables: &[],
        notes: "One admin user in wheel with your SSH key, root locked, LVM, DHCP; installs from the ISO.",
    },
    Starter {
        id: "starter.debian-12-minimal",
        name: "Debian 12, minimal",
        kind: InstallKind::Preseed,
        body: include_str!("starters/debian-12-minimal.cfg"),
        variables: &[],
        notes: "One admin user with sudo and your SSH key, root can't sign in, LVM, DHCP, the SSH server.",
    },
    Starter {
        id: "starter.windows-server-2022",
        name: "Windows Server 2022 with WinRM over HTTPS",
        kind: InstallKind::Unattend,
        body: include_str!("starters/windows-server-2022.xml"),
        variables: &[("image_index", "2"), ("organization", "IT")],
        notes: "UEFI, the whole disk, the Administrator with a one-time password, WinRM over HTTPS on port 5986.",
    },
    Starter {
        id: "starter.windows-server-2025",
        name: "Windows Server 2025 with WinRM over HTTPS",
        kind: InstallKind::Unattend,
        body: include_str!("starters/windows-server-2025.xml"),
        variables: &[("image_index", "2"), ("organization", "IT")],
        notes: "UEFI, the whole disk, the Administrator with a one-time password, WinRM over HTTPS on port 5986.",
    },
    Starter {
        id: "starter.cloud-first-boot",
        name: "Cloud image first boot",
        kind: InstallKind::CloudInit,
        body: include_str!("starters/cloud-first-boot.yaml"),
        variables: &[],
        notes: "A cloud image's hostname, an admin user with sudo and your SSH key, packages, the disk grown.",
    },
];

pub fn is_starter(id: &str) -> bool {
    id.starts_with(PREFIX)
}

/// A starter's fields, as a copy starts from.
pub fn spec(starter: &Starter) -> InstallConfigInput {
    let secrets = super::placeholders_of(starter.body)
        .into_iter()
        .filter_map(|p| match p {
            super::Placeholder::Password(name) => Some(SecretRef {
                name,
                kind: SecretRefKind::Password,
                secret_id: None,
            }),
            super::Placeholder::SshKey(name) => Some(SecretRef {
                name,
                kind: SecretRefKind::SshKey,
                secret_id: None,
            }),
            _ => None,
        })
        .collect();
    InstallConfigInput {
        name: starter.name.to_owned(),
        kind: starter.kind,
        body: starter.body.replace("\r\n", "\n"),
        variables: starter
            .variables
            .iter()
            .map(|(name, default)| VariableDef {
                name: (*name).to_owned(),
                default: Some((*default).to_owned()),
            })
            .collect(),
        secrets,
        notes: Some(starter.notes.to_owned()),
    }
}

pub fn find(id: &str) -> Option<&'static Starter> {
    STARTERS.iter().find(|s| s.id == id)
}

/// Every starter, checked.
pub fn all() -> Vec<InstallConfig> {
    STARTERS
        .iter()
        .map(|s| {
            let spec = spec(s);
            let problems = check(&spec, &CheckFacts::default());
            let disk_need_mb = super::sample_text(&spec)
                .ok()
                .and_then(|t| super::disk_need(spec.kind, &t));
            InstallConfig {
                id: s.id.to_owned(),
                built_in: true,
                spec,
                created_at: None,
                updated_at: None,
                problems,
                disk_need_mb,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::{BTreeMap, HashMap};

    use time::macros::date;

    use super::super::render::{render, OsRandom, RenderSecrets, VmValues};
    use super::super::{read_form, Severity};
    use super::*;
    use crate::vault::SecretString;

    fn password() -> String {
        let mut bytes = [0u8; 12];
        super::super::render::Random::fill(&mut OsRandom, &mut bytes);
        format!("Pw-{}", hex::encode(bytes))
    }

    #[test]
    fn every_starter_passes_its_own_checks_and_renders() {
        for starter in &STARTERS {
            let spec = spec(starter);
            let problems = check(&spec, &CheckFacts::default());
            let errors: Vec<_> = problems.iter().filter(|p| p.severity == Severity::Error).collect();
            assert!(errors.is_empty(), "{}: {errors:?}", starter.id);
            // The only warnings: the vault picks a copy makes.
            let other: Vec<_> = problems
                .iter()
                .filter(|p| !p.message.contains("isn't picked from the vault yet"))
                .collect();
            assert!(other.is_empty(), "{}: {other:?}", starter.id);
            assert!(
                read_form(spec.kind, &spec.body).unreadable.is_none(),
                "{} reads in the form",
                starter.id
            );
            let mut secrets = RenderSecrets::default();
            secrets.passwords.insert("admin".into(), SecretString::new(password()));
            secrets.ssh_keys.insert(
                "admin".into(),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@example.com".into(),
            );
            let vm = VmValues {
                hostname: "web-1".into(),
                ip: Some("192.0.2.31".into()),
                n: 1,
                template: "web".into(),
                date: date!(2026 - 11 - 12),
                values: BTreeMap::new(),
            };
            let rendered = render(&spec, &vm, &secrets, &mut OsRandom).unwrap();
            assert!(!rendered.text.expose().contains("{{"), "{}", starter.id);
            assert!(rendered.text.expose().contains("web-1"), "{}", starter.id);
            if starter.kind.windows() {
                assert_eq!(rendered.one_time.len(), 1, "{}", starter.id);
            } else if spec.secrets.iter().any(|s| s.kind == SecretRefKind::Password) {
                assert!(rendered.text.expose().contains("$6$rounds=5000$"), "{}", starter.id);
            }
        }
    }

    #[test]
    fn starters_are_listed_with_their_picks_to_make() {
        let all = all();
        assert_eq!(all.len(), 8);
        assert!(all.iter().all(|c| c.built_in && is_starter(&c.id)));
        let ubuntu = all.iter().find(|c| c.id == "starter.ubuntu-24.04-minimal").unwrap();
        assert_eq!(ubuntu.spec.secrets.len(), 2);
        assert!(ubuntu.spec.secrets.iter().all(|s| s.secret_id.is_none()));
        let windows = all.iter().find(|c| c.id == "starter.windows-server-2025").unwrap();
        assert_eq!(windows.disk_need_mb, Some(276));
        assert_eq!(windows.spec.variables.len(), 2);
        let _ = HashMap::<String, String>::new();
    }
}
