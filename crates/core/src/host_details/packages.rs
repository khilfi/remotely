//! FD-05: a Linux host's installed packages, for the inventory's optional package list. MO-14 reads pending updates
//! but never the installed list, so this is its own read: one exec of [`PACKAGES_SCRIPT`] on the host details'
//! connection ([`super::HostDetails::inventory_read`]), never stored, read again for each export that asks for it.
//!
//! Only reads, as the login user: `dpkg-query -W` (Debian, Ubuntu) or `rpm -qa` (RHEL and its kin, SUSE), whichever
//! the host has (dpkg first: some Debian hosts have rpm installed too, with an empty database). Every command
//! classifies as read-only under the default policy rules (`tests::every_command_only_reads`).

use serde::Serialize;

use super::linux::sections;

/// `dpkg-query`'s `Status` field says whether a package is installed (`install ok installed`) or only left its
/// configuration behind (`deinstall ok config-files`); the format's `\t` and `\n` are dpkg-query's own escapes. rpm's
/// default output (`name-version-release.arch`) is split here, so no query format is passed to it.
pub const PACKAGES_SCRIPT: &str = "echo @@dpkg; type dpkg-query >/dev/null 2>&1 && echo present && dpkg-query -W -f='${Status}\\t${Package}\\t${Version}\\t${Architecture}\\n' 2>/dev/null; \
echo @@rpm; type rpm >/dev/null 2>&1 && echo present && rpm -qa 2>/dev/null";

/// Output kept: a host with 5,000 packages prints about 300 KB.
pub const MAX_OUTPUT: usize = 4 * 1024 * 1024;

/// Packages kept for one host, at most; the count says how many there are.
pub const MAX_PACKAGES: usize = 20_000;

/// The package database a host's list came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PackageDatabase {
    Dpkg,
    Rpm,
}

impl PackageDatabase {
    pub fn label(self) -> &'static str {
        match self {
            PackageDatabase::Dpkg => "dpkg",
            PackageDatabase::Rpm => "rpm",
        }
    }
}

/// One installed package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    /// `amd64`, `x86_64`, `noarch`; empty when the database doesn't say (rpm's `gpg-pubkey` entries).
    pub arch: String,
}

/// What [`PACKAGES_SCRIPT`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackagesReport {
    /// `None`: the host has neither dpkg nor rpm.
    pub database: Option<PackageDatabase>,
    /// Installed packages by name, at most [`MAX_PACKAGES`].
    pub packages: Vec<InstalledPackage>,
    /// How many are installed (more than `packages` holds when the list was cut).
    pub count: usize,
}

/// Parses everything [`PACKAGES_SCRIPT`] printed.
pub fn parse_packages(output: &str) -> PackagesReport {
    let parts = sections(output);
    let part = |name: &str| parts.get(name).map(Vec::as_slice).unwrap_or(&[]);
    let present = |lines: &[&str]| lines.first().is_some_and(|l| l.trim() == "present");
    let mut report = PackagesReport::default();
    let mut packages: Vec<InstalledPackage> = if present(part("dpkg")) {
        report.database = Some(PackageDatabase::Dpkg);
        part("dpkg")[1..].iter().filter_map(|l| parse_dpkg_line(l)).collect()
    } else if present(part("rpm")) {
        report.database = Some(PackageDatabase::Rpm);
        part("rpm")[1..].iter().filter_map(|l| parse_rpm_line(l)).collect()
    } else {
        Vec::new()
    };
    packages.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.arch.cmp(&b.arch)));
    packages.dedup();
    report.count = packages.len();
    packages.truncate(MAX_PACKAGES);
    report.packages = packages;
    report
}

/// `install ok installed<TAB>bash<TAB>5.2.21-2ubuntu4<TAB>amd64`; a package that only left its configuration
/// behind is not installed.
fn parse_dpkg_line(line: &str) -> Option<InstalledPackage> {
    let mut fields = line.trim_end().split('\t');
    let status = fields.next()?;
    if !status.split_whitespace().last().is_some_and(|s| s == "installed") {
        return None;
    }
    let name = fields.next()?.trim();
    let version = fields.next().unwrap_or("").trim();
    let arch = fields.next().unwrap_or("").trim();
    if name.is_empty() {
        return None;
    }
    Some(InstalledPackage {
        name: name.to_owned(),
        version: version.to_owned(),
        arch: arch.to_owned(),
    })
}

/// Architectures rpm names after the release's last `.`.
const RPM_ARCHES: [&str; 14] = [
    "x86_64", "noarch", "i686", "i586", "i386", "aarch64", "ppc64le", "ppc64", "s390x", "armv7hl", "armhfp", "riscv64",
    "src", "(none)",
];

/// `bash-5.1.8-9.el9.x86_64`: the version and release never hold a `-`, so the last two `-` split them off the
/// name; the architecture is after the last `.` when it is one rpm knows.
fn parse_rpm_line(line: &str) -> Option<InstalledPackage> {
    let line = line.trim();
    if line.is_empty() || line.contains(char::is_whitespace) {
        return None;
    }
    let (rest, arch) = match line.rsplit_once('.') {
        Some((rest, arch)) if RPM_ARCHES.contains(&arch) => (rest, arch.trim_matches(['(', ')'])),
        _ => (line, ""),
    };
    let arch = if arch == "none" { "" } else { arch };
    let (name_version, release) = rest.rsplit_once('-')?;
    let (name, version) = name_version.rsplit_once('-')?;
    if name.is_empty() || version.is_empty() || release.is_empty() {
        return None;
    }
    Some(InstalledPackage {
        name: name.to_owned(),
        version: format!("{version}-{release}"),
        arch: arch.to_owned(),
    })
}

/// Test data: what real hosts print for [`PACKAGES_SCRIPT`], for tests and the test SSH server.
#[cfg(any(test, feature = "fakes"))]
pub mod samples {
    /// `dpkg-query -W -f=...` on Ubuntu: installed packages, and one that left only its configuration.
    pub const DPKG: &str = "install ok installed\tadduser\t3.137ubuntu1\tall
install ok installed\tbash\t5.2.21-2ubuntu4\tamd64
deinstall ok config-files\tlinux-image-6.8.0-31-generic\t6.8.0-31.31\tamd64
install ok installed\tnginx\t1.24.0-2ubuntu7.1\tamd64
install ok installed\topenssh-server\t1:9.6p1-3ubuntu13.5\tamd64
";

    /// `rpm -qa` on RHEL 9.
    pub const RPM: &str = "bash-5.1.8-9.el9.x86_64
gpg-pubkey-fd431d51-4ae0493b
kernel-core-5.14.0-427.13.1.el9_4.x86_64
python3-libs-3.9.18-3.el9.x86_64
tzdata-2024a-1.el9.noarch
";
}

#[cfg(test)]
mod tests {
    use super::samples::*;
    use super::*;
    use crate::policy::{ActionKind, PolicyEngine, PolicyRules};

    #[test]
    fn every_command_only_reads() {
        let policy = PolicyEngine::new(PolicyRules::default()).unwrap();
        assert_eq!(
            policy.classify_script(PACKAGES_SCRIPT),
            ActionKind::ExecReadOnly,
            "{PACKAGES_SCRIPT}"
        );
        for part in PACKAGES_SCRIPT.split(';') {
            assert_eq!(policy.classify_script(part), ActionKind::ExecReadOnly, "{part}");
        }
        // What installs or removes is never read-only, so it can't hide in here.
        for change in ["rpm -e bash", "rpm -i x.rpm", "dpkg -i x.deb", "dpkg -r nginx"] {
            assert_ne!(policy.classify_script(change), ActionKind::ExecReadOnly, "{change}");
        }
    }

    #[test]
    fn reads_dpkg_without_packages_that_left_only_their_configuration() {
        let output = format!("@@dpkg\npresent\n{DPKG}@@rpm\n");
        let report = parse_packages(&output);
        assert_eq!(report.database, Some(PackageDatabase::Dpkg));
        assert_eq!(report.count, 4);
        let names: Vec<&str> = report.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["adduser", "bash", "nginx", "openssh-server"]);
        assert_eq!(report.packages[3].version, "1:9.6p1-3ubuntu13.5");
        assert_eq!(report.packages[1].arch, "amd64");
    }

    #[test]
    fn reads_rpm_names_versions_and_architectures() {
        let output = format!("@@dpkg\n@@rpm\npresent\n{RPM}");
        let report = parse_packages(&output);
        assert_eq!(report.database, Some(PackageDatabase::Rpm));
        assert_eq!(report.count, 5);
        let rows: Vec<(&str, &str, &str)> = report
            .packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.arch.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("bash", "5.1.8-9.el9", "x86_64"),
                ("gpg-pubkey", "fd431d51-4ae0493b", ""),
                ("kernel-core", "5.14.0-427.13.1.el9_4", "x86_64"),
                ("python3-libs", "3.9.18-3.el9", "x86_64"),
                ("tzdata", "2024a-1.el9", "noarch"),
            ]
        );
    }

    #[test]
    fn dpkg_wins_over_an_empty_rpm_and_a_host_with_neither_has_none() {
        let both = format!("@@dpkg\npresent\n{DPKG}@@rpm\npresent\n");
        assert_eq!(parse_packages(&both).database, Some(PackageDatabase::Dpkg));
        let neither = parse_packages("@@dpkg\n@@rpm\n");
        assert_eq!(neither, PackagesReport::default());
        // Odd lines are left out, never a panic.
        let odd = parse_packages("@@rpm\npresent\nnot a package\n-\n--\na-b\n\u{e9}-1-2\n");
        assert_eq!(odd.count, 1, "{odd:?}");
        assert_eq!(odd.packages[0].name, "\u{e9}");
    }

    #[test]
    fn a_huge_list_is_cut_but_counted() {
        let mut output = String::from("@@dpkg\npresent\n");
        for n in 0..(MAX_PACKAGES + 5) {
            output.push_str(&format!("install ok installed\tpkg{n:06}\t1.0\tamd64\n"));
        }
        let report = parse_packages(&output);
        assert_eq!(report.count, MAX_PACKAGES + 5);
        assert_eq!(report.packages.len(), MAX_PACKAGES);
    }
}
