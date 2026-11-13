//! VM-22: first-boot setup with cloud-init. What a new VM gets on its first boot: its hostname, the guest user
//! (with sudo and the template's SSH **public** key), and the packages to install.
//!
//! * Workstation: `guestinfo.metadata` and `guestinfo.userdata` in the `.vmx`, base64 with their `.encoding`
//!   keys, which cloud-init's VMware datasource reads through open-vm-tools ([`guestinfo_keys`]).
//! * VirtualBox: a NoCloud seed, a small ISO with the volume label `cidata` and the files `user-data` and
//!   `meta-data` ([`super::seed`]), attached as a DVD and ejected after the first boot.
//!
//! * CV-04, an imported disk (a cloud server's export, a KVM or OpenStack image): a NoCloud seed on both
//!   hypervisors, since a disk from another hypervisor has no open-vm-tools to read Workstation's guestinfo, with
//!   a `network-config` ([`FirstBoot::network_config`]) that takes DHCP on whichever network card the guest has:
//!   the server's own settings name the cloud's card (its MAC, or `eth0` where this PC's VM says `ens160`).
//!   sshd's password setting is left as the server had it (`ssh_pwauth` isn't written).
//!
//! The user data never holds a password: the `.vmx` and the seed are readable on this PC. The guest user has a
//! locked password and logs in with the key; sudo needs no password, as on the clouds' own images. Every value
//! is written as a double-quoted YAML scalar (JSON's escapes, which YAML reads the same), and names and packages
//! are checked before they get here ([`crate::catalog::templates::check_guest_user`], `check_packages`).

use base64::Engine;
use serde::Serialize;

/// What cloud-init sets on one VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirstBoot {
    /// A new value per VM, so cloud-init runs its per-instance setup again on a clone of a VM it already set up.
    pub instance_id: String,
    pub hostname: String,
    /// `None`: the image's default user gets the key.
    pub user: Option<String>,
    /// The `authorized_keys` line, public half only.
    pub public_key: Option<String>,
    pub packages: Vec<String>,
    /// CV-04: an imported disk's first boot: the NoCloud seed on both hypervisors, with [`Self::network_config`].
    pub imported: bool,
}

/// CV-04: network-config version 2: DHCP on every network card whose name starts with `e` (`eth0`, `ens160`,
/// `enp0s3`), which netplan matches by name. Renderers that can't match a name (sysconfig, ENI) configure the
/// entry's own name, `eth0`, the name most cloud images give their card (`net.ifnames=0`).
pub const DHCP_ANY_NIC: &str =
    "version: 2\nethernets:\n  eth0:\n    match:\n      name: \"e*\"\n    dhcp4: true\n    dhcp6: false\n";

/// A YAML scalar that reads back as `text` whatever it holds.
fn quoted(text: &str) -> String {
    // A JSON string is a YAML double-quoted scalar with the same escapes. Serialising a &str can't fail.
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned())
}

impl FirstBoot {
    /// NoCloud's `meta-data`, and the VMware datasource's `guestinfo.metadata`.
    pub fn meta_data(&self) -> String {
        format!(
            "instance-id: {}\nlocal-hostname: {}\n",
            quoted(&self.instance_id),
            quoted(&self.hostname)
        )
    }

    /// The `#cloud-config` user data.
    pub fn user_data(&self) -> String {
        let mut out =
            String::from("#cloud-config\n# Written by Remotely for this VM's first boot. It holds no password.\n");
        out.push_str(&format!("hostname: {}\n", quoted(&self.hostname)));
        out.push_str("preserve_hostname: false\n");
        match &self.user {
            Some(user) => {
                out.push_str("users:\n");
                out.push_str(&format!("  - name: {}\n", quoted(user)));
                out.push_str("    shell: /bin/bash\n");
                out.push_str("    lock_passwd: true\n");
                out.push_str(&format!("    sudo: {}\n", quoted("ALL=(ALL) NOPASSWD:ALL")));
                if let Some(key) = &self.public_key {
                    out.push_str("    ssh_authorized_keys:\n");
                    out.push_str(&format!("      - {}\n", quoted(key)));
                }
            }
            None => {
                if let Some(key) = &self.public_key {
                    // The image's default user (ubuntu, debian...) gets it.
                    out.push_str("ssh_authorized_keys:\n");
                    out.push_str(&format!("  - {}\n", quoted(key)));
                }
            }
        }
        if !self.imported {
            out.push_str("ssh_pwauth: false\n");
        }
        if !self.packages.is_empty() {
            out.push_str("package_update: true\n");
            out.push_str("packages:\n");
            for package in &self.packages {
                out.push_str(&format!("  - {}\n", quoted(package)));
            }
        }
        // The guest's disk may be larger than the image's: grow its root partition into the rest.
        out.push_str("growpart:\n  mode: auto\n  devices: [\"/\"]\nresize_rootfs: true\n");
        out
    }

    /// CV-04: the seed's `network-config` for an imported disk; none for a template's cloud image, whose own
    /// settings fit (cloud-init's fallback takes DHCP on its first card).
    pub fn network_config(&self) -> Option<&'static str> {
        self.imported.then_some(DHCP_ANY_NIC)
    }

    /// The NoCloud seed's files: `user-data`, `meta-data`, and `network-config` for an import.
    pub fn seed_files(&self) -> Vec<(&'static str, Vec<u8>)> {
        let mut files = vec![
            ("user-data", self.user_data().into_bytes()),
            ("meta-data", self.meta_data().into_bytes()),
        ];
        if let Some(network) = self.network_config() {
            files.push(("network-config", network.as_bytes().to_vec()));
        }
        files
    }
}

/// Workstation: the `.vmx` keys cloud-init's VMware datasource reads, in the order they are written.
pub fn guestinfo_keys(first_boot: &FirstBoot) -> Vec<(&'static str, String)> {
    let encode = |text: String| base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
    vec![
        ("guestinfo.metadata", encode(first_boot.meta_data())),
        ("guestinfo.metadata.encoding", "base64".to_owned()),
        ("guestinfo.userdata", encode(first_boot.user_data())),
        ("guestinfo.userdata.encoding", "base64".to_owned()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_boot() -> FirstBoot {
        FirstBoot {
            instance_id: "iid-remotely-1".into(),
            hostname: "web-1".into(),
            user: Some("alice".into()),
            public_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@example.com".into()),
            packages: vec!["nginx".into(), "libstdc++6".into()],
            imported: false,
        }
    }

    #[test]
    fn an_imported_disk_gets_dhcp_on_any_card_and_keeps_its_sshd_setting() {
        let imported = FirstBoot {
            imported: true,
            packages: Vec::new(),
            ..first_boot()
        };
        let text = imported.user_data();
        assert!(!text.contains("ssh_pwauth"), "{text}");
        assert!(text.contains("    sudo: \"ALL=(ALL) NOPASSWD:ALL\""));
        assert!(text.contains("      - \"ssh-ed25519 "));
        assert!(text.contains("hostname: \"web-1\""));
        for key in [
            "plain_text_passwd",
            "hashed_passwd",
            "chpasswd",
            "password:",
            " passwd:",
        ] {
            assert!(!text.contains(key), "{key}");
        }
        let names: Vec<&str> = imported.seed_files().iter().map(|(n, _)| *n).collect();
        assert_eq!(names, ["user-data", "meta-data", "network-config"]);
        let network = imported.network_config().unwrap();
        assert!(network.starts_with("version: 2\n"), "{network}");
        assert!(network.contains("      name: \"e*\"\n    dhcp4: true"), "{network}");
        // A template's cloud image: its own network settings, and password logins off as before.
        assert_eq!(first_boot().network_config(), None);
        assert_eq!(first_boot().seed_files().len(), 2);
        assert!(first_boot().user_data().contains("ssh_pwauth: false"));
    }

    #[test]
    fn user_data_sets_the_hostname_user_key_and_packages() {
        let text = first_boot().user_data();
        assert!(text.starts_with("#cloud-config\n"), "{text}");
        for line in [
            "hostname: \"web-1\"",
            "  - name: \"alice\"",
            "    lock_passwd: true",
            "    sudo: \"ALL=(ALL) NOPASSWD:ALL\"",
            "      - \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@example.com\"",
            "ssh_pwauth: false",
            "package_update: true",
            "  - \"nginx\"",
            "  - \"libstdc++6\"",
        ] {
            assert!(text.lines().any(|l| l == line), "{line} in\n{text}");
        }
        // No password of any kind: only the locked one.
        for key in [
            "plain_text_passwd",
            "hashed_passwd",
            "chpasswd",
            "password:",
            " passwd:",
        ] {
            assert!(!text.contains(key), "{key}");
        }
    }

    #[test]
    fn without_a_user_the_images_default_user_gets_the_key() {
        let text = FirstBoot {
            user: None,
            packages: Vec::new(),
            ..first_boot()
        }
        .user_data();
        assert!(!text.contains("users:"), "{text}");
        assert!(text.contains("ssh_authorized_keys:\n  - \"ssh-ed25519 "), "{text}");
        assert!(!text.contains("packages:"));
        let no_key = FirstBoot {
            user: None,
            public_key: None,
            ..first_boot()
        }
        .user_data();
        assert!(!no_key.contains("ssh_authorized_keys"), "{no_key}");
    }

    #[test]
    fn a_hostile_key_comment_stays_one_quoted_scalar() {
        let text = FirstBoot {
            public_key: Some("ssh-ed25519 AAAA x\"\n  runcmd: [reboot] #".into()),
            ..first_boot()
        }
        .user_data();
        assert!(
            text.contains("      - \"ssh-ed25519 AAAA x\\\"\\n  runcmd: [reboot] #\"\n"),
            "{text}"
        );
        assert!(!text.lines().any(|l| l.trim_start().starts_with("runcmd")), "{text}");
    }

    #[test]
    fn meta_data_names_the_instance_and_host() {
        assert_eq!(
            first_boot().meta_data(),
            "instance-id: \"iid-remotely-1\"\nlocal-hostname: \"web-1\"\n"
        );
    }

    #[test]
    fn guestinfo_is_base64_with_its_encoding() {
        let keys = guestinfo_keys(&first_boot());
        let names: Vec<&str> = keys.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            names,
            [
                "guestinfo.metadata",
                "guestinfo.metadata.encoding",
                "guestinfo.userdata",
                "guestinfo.userdata.encoding"
            ]
        );
        let decode =
            |text: &str| String::from_utf8(base64::engine::general_purpose::STANDARD.decode(text).unwrap()).unwrap();
        assert_eq!(decode(&keys[0].1), first_boot().meta_data());
        assert_eq!(keys[1].1, "base64");
        assert_eq!(decode(&keys[2].1), first_boot().user_data());
        assert!(keys[2]
            .1
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)));
    }
}
