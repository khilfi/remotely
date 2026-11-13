//! VM-29 (G6): what an unattended install from an install config needs besides the deploy itself, pure so it is tested
//! without a hypervisor. The job's work is the deploy runner's (`runner::install`); the ISO copy is [`super::iso`]'s and
//! the serial log's reading [`super::watch`]'s.
//!
//! One delivery on both hypervisors, as spikes S1 to S3 saw work (CLAUDE.md, "Unattended installs"): a copy of the
//! install ISO with its boot menu changed (made once per deploy and shared by its VMs, the original only read), and each
//! VM's rendered answer file on a seed CD in a second drive, the VM booting its disk first. The seed is written into a
//! folder only this Windows user can open (`private_folder`), and the rendered file never touches the disk anywhere
//! else; the journal and the audit log keep the config's name and the file's SHA-256 only.

use crate::catalog::install::InstallKind;

use super::iso;
use super::watch::Os;

/// The seed's volume label (Ubuntu's NoCloud looks for it; Debian and Windows find their file by content).
pub const SEED_LABEL: &str = super::seed::LABEL;
/// The snapshot taken once an install is done, when the template asks for its clean snapshot.
pub const CLEAN_INSTALL_SNAPSHOT_NAME: &str = "clean install";
/// The subfolder of a VM's folder that holds its seed, which only this Windows user can open.
pub const SEED_FOLDER: &str = "install-seed";
/// Each serial port speed the installers' kernels are told (`console=ttyS0,115200n8`).
pub const SERIAL_SPEED: u32 = 115_200;
/// Workstation's DHCP leases for its NAT and host-only networks (S1, S3).
pub const WORKSTATION_LEASES: &str = r"C:\ProgramData\VMware\vmnetdhcp.leases";
/// The NAT rule an install on VirtualBox's NAT adds, so this PC reaches the guest's SSH or WinRM port while it is
/// watched; taken away once the install is done.
pub const NAT_RULE: &str = "remotely-install";
/// WinRM over HTTPS, which the Windows starters turn on.
pub const WINRM_HTTPS_PORT: u16 = 5986;

/// The installers Remotely delivers an answer file to, one per install config kind seen working by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// Subiquity's autoinstall (S1): `user-data` and `meta-data` on a `cidata` seed.
    Ubuntu,
    /// debian-installer's preseed (S2, the "a2" path): `preseed.cfg` on a seed the boot line's early command finds.
    Debian,
    /// Windows Setup (S3): `autounattend.xml` on a seed.
    Windows,
}

impl Flavor {
    /// The flavor of a config kind, when Remotely delivers it. Kickstart wasn't tried by hand yet, and cloud-init user
    /// data goes on cloud images (VM-22), not ISO installs.
    pub fn of(kind: InstallKind) -> Option<Self> {
        match kind {
            InstallKind::Autoinstall => Some(Flavor::Ubuntu),
            InstallKind::Preseed => Some(Flavor::Debian),
            InstallKind::Unattend => Some(Flavor::Windows),
            InstallKind::Kickstart | InstallKind::CloudInit => None,
        }
    }

    pub fn os(self) -> Os {
        match self {
            Flavor::Ubuntu => Os::Ubuntu,
            Flavor::Debian => Os::Debian,
            Flavor::Windows => Os::Windows,
        }
    }

    pub fn iso(self) -> iso::Flavor {
        match self {
            Flavor::Ubuntu => iso::Flavor::Ubuntu,
            Flavor::Debian => iso::Flavor::Debian,
            Flavor::Windows => iso::Flavor::WindowsServer,
        }
    }

    pub fn windows(self) -> bool {
        self == Flavor::Windows
    }

    /// The preview's words for how the install gets its file.
    pub fn delivery(self) -> &'static str {
        match self {
            Flavor::Ubuntu => "a copy of the ISO with 'autoinstall' and the serial console added to its boot menu, and each VM's user-data on a seed CD",
            Flavor::Debian => "a copy of the ISO with a one-entry boot menu that loads the preseed from the seed CD, and each VM's preseed.cfg on a seed CD",
            Flavor::Windows => "a copy of the ISO that boots Setup without \"Press any key\" on UEFI, and each VM's autounattend.xml on a seed CD",
        }
    }

    /// The port the installed system is reached on to say the install is done: SSH, or WinRM over HTTPS.
    pub fn port(self) -> u16 {
        if self.windows() {
            WINRM_HTTPS_PORT
        } else {
            22
        }
    }
}

/// The files of one VM's seed: the rendered answer file, and Ubuntu's NoCloud `meta-data` beside it.
pub fn seed_files(
    flavor: Flavor,
    file_name: &'static str,
    text: &str,
    instance_id: &str,
    hostname: &str,
) -> Vec<(&'static str, Vec<u8>)> {
    let mut files = vec![(file_name, text.as_bytes().to_vec())];
    if flavor == Flavor::Ubuntu {
        files.push((
            "meta-data",
            format!("instance-id: {instance_id}\nlocal-hostname: {hostname}\n").into_bytes(),
        ));
    }
    files
}

/// The address Workstation's DHCP server last leased to `mac` (`00:0c:29:...`, any case), from `vmnetdhcp.leases`
/// (ISC dhcpd's format: `lease <ip> { ... hardware ethernet <mac>; ... }`). The file is read as untrusted text.
pub fn dhcp_lease(leases: &str, mac: &str) -> Option<String> {
    let want = mac.trim().to_ascii_lowercase().replace('-', ":");
    if want.len() != 17 {
        return None;
    }
    let mut found = None;
    for block in leases.split("lease ").skip(1).take(100_000) {
        let Some((ip, body)) = block.split_once('{') else {
            continue;
        };
        let body = body.split('}').next().unwrap_or_default();
        let matches = body.split(';').any(|statement| {
            let statement = statement.trim().to_ascii_lowercase();
            statement
                .strip_prefix("hardware ethernet")
                .is_some_and(|m| m.trim() == want)
        });
        if matches && ip.trim().parse::<std::net::Ipv4Addr>().is_ok() {
            // The file appends: the last lease for the MAC is the current one.
            found = Some(ip.trim().to_owned());
        }
    }
    found
}

/// A `.vmx`'s `ethernet0.generatedAddress` (or `.address` for a static one), as `00:0c:29:..`.
pub fn vmx_mac(vmx: &str) -> Option<String> {
    let mut generated = None;
    let mut fixed = None;
    for line in vmx.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().trim_matches('"').to_owned();
        match key.as_str() {
            "ethernet0.generatedaddress" => generated = Some(value),
            "ethernet0.address" => fixed = Some(value),
            _ => {}
        }
    }
    fixed.or(generated).filter(|m| m.len() == 17)
}

/// VirtualBox's `macaddress1` (12 hex digits) as `08:00:27:..`.
pub fn colon_mac(mac: &str) -> Option<String> {
    let mac = mac.trim();
    if mac.len() != 12 || !mac.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let pairs: Vec<&str> = (0..6).map(|i| &mac[i * 2..i * 2 + 2]).collect();
    Some(pairs.join(":").to_ascii_lowercase())
}

/// VirtualBox's NAT rule for an install: `remotely-install,tcp,127.0.0.1,<host port>,,<guest port>`.
pub fn nat_rule(host_port: u16, guest_port: u16) -> String {
    format!("{NAT_RULE},tcp,127.0.0.1,{host_port},,{guest_port}")
}

/// A PowerShell single-quoted string of `text`: `'` and the quotes PowerShell also ends one with doubled.
pub fn ps_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// The script that sets `account`'s password, sent on WinRM's stdin (never a command line). It holds the password, so
/// it is never logged or kept.
pub fn set_password_script(account: &str, password: &str) -> String {
    format!(
        "$p = ConvertTo-SecureString {} -AsPlainText -Force; Set-LocalUser -Name {} -Password $p",
        ps_quote(password),
        ps_quote(account)
    )
}

/// After the password is the vault's (S3): the autologon session signed out, and the copy of the answer file Windows
/// Server 2025 keeps (`unattend-original.xml`, with the one-time password, readable by Users) deleted. It prints the
/// copy's SHA-256 first, so the job can say Setup read this deploy's file.
pub const AFTER_INSTALL_SCRIPT: &str = "$f = 'C:\\Windows\\Panther\\unattend-original.xml'; if (Test-Path -LiteralPath $f) { 'answer-file ' + (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash; Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }; $p = Get-Process explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -gt 0 } | Select-Object -First 1; if ($p) { logoff $p.SessionId; 'signed-out ' + $p.SessionId }";

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn kinds_have_a_delivery_only_where_one_was_seen_to_work() {
        assert_eq!(Flavor::of(InstallKind::Autoinstall), Some(Flavor::Ubuntu));
        assert_eq!(Flavor::of(InstallKind::Preseed), Some(Flavor::Debian));
        assert_eq!(Flavor::of(InstallKind::Unattend), Some(Flavor::Windows));
        assert_eq!(Flavor::of(InstallKind::Kickstart), None);
        assert_eq!(Flavor::of(InstallKind::CloudInit), None);
        assert_eq!(Flavor::Windows.port(), 5986);
        assert_eq!(Flavor::Debian.port(), 22);
    }

    #[test]
    fn ubuntu_seeds_get_meta_data() {
        let files = seed_files(Flavor::Ubuntu, "user-data", "#cloud-config\n", "iid-1", "web-1");
        assert_eq!(files.len(), 2);
        assert_eq!(files[1].0, "meta-data");
        assert_eq!(files[1].1, b"instance-id: iid-1\nlocal-hostname: web-1\n");
        assert_eq!(seed_files(Flavor::Debian, "preseed.cfg", "x", "i", "h").len(), 1);
    }

    #[test]
    fn workstation_leases_are_read_by_mac() {
        let leases = "# comment\nlease 192.0.2.130 {\n\tstarts 3 2026/11/13 10:00:00;\n\thardware ethernet 00:0c:29:aa:bb:cc;\n}\nlease 192.0.2.131 {\n\thardware ethernet 00:0c:29:dd:ee:ff;\n}\nlease 192.0.2.140 {\n\thardware ethernet 00:0C:29:AA:BB:CC;\n\tclient-hostname \"web-1\";\n}\nlease junk { hardware ethernet 00:0c:29:aa:bb:cc; }\n";
        assert_eq!(dhcp_lease(leases, "00:0c:29:aa:bb:cc").as_deref(), Some("192.0.2.140"));
        assert_eq!(dhcp_lease(leases, "00-0C-29-DD-EE-FF").as_deref(), Some("192.0.2.131"));
        assert_eq!(dhcp_lease(leases, "00:0c:29:00:00:00"), None);
        assert_eq!(dhcp_lease("lease {{{{", "00:0c:29:aa:bb:cc"), None);
        let vmx = "displayName = \"web-1\"\r\nethernet0.generatedAddress = \"00:0c:29:aa:bb:cc\"\r\n";
        assert_eq!(vmx_mac(vmx).as_deref(), Some("00:0c:29:aa:bb:cc"));
        assert_eq!(colon_mac("080027AABBCC").as_deref(), Some("08:00:27:aa:bb:cc"));
        assert_eq!(colon_mac("08002"), None);
    }

    #[test]
    fn the_password_goes_quoted_into_a_script_on_stdin() {
        assert_eq!(ps_quote("it's"), "'it''s'");
        assert_eq!(ps_quote("a\u{2019}b"), "'a\u{2019}\u{2019}b'");
        let script = set_password_script("Administrator", "p'w");
        assert_eq!(
            script,
            "$p = ConvertTo-SecureString 'p''w' -AsPlainText -Force; Set-LocalUser -Name 'Administrator' -Password $p"
        );
        assert_eq!(nat_rule(50123, 5986), "remotely-install,tcp,127.0.0.1,50123,,5986");
    }
}
