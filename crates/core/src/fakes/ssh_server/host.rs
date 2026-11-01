//! MO-13, MO-14: the test server's view of itself, for host details. With
//! [`super::TestSshServer::with_host_facts`] its exec shell has `uname`, `lscpu`, `lsblk`, `df -PT`,
//! `systemd-detect-virt`, `systemctl list-units` and `is-active` (MO-08), `ss`, `who`, `last`, `ps`, `stat` and `apt` or `dnf`,
//! printing what a real host prints (the samples in `host_details::linux` and `host_details::admin`),
//! and files `/etc/os-release`, `/proc/cpuinfo` and `/proc/swaps`.

use super::docker::Ran;
use crate::host_details::{admin::samples as admin, linux::samples as linux};

/// What `apt` or `dnf` says is pending.
#[derive(Debug, Clone)]
pub enum Packages {
    None,
    /// `apt list --upgradable`, and when its lists were refreshed (Unix seconds).
    Apt {
        list: String,
        refreshed_unix: i64,
    },
    /// `dnf check-update -q`, and its exit status (100: updates, 0: none, 1: failed).
    Dnf {
        list: String,
        status: u32,
    },
}

/// What the host's programs print.
#[derive(Debug, Clone)]
pub struct HostFixture {
    pub os_release: String,
    /// `uname -srm`.
    pub uname: String,
    /// `None`: no lscpu, so the script reads /proc/cpuinfo.
    pub lscpu: Option<String>,
    pub cpuinfo: String,
    pub swaps: String,
    /// `None`: an lsblk without `-J` (util-linux before 2.27), which fails on it.
    pub lsblk_json: Option<String>,
    pub lsblk_pairs: String,
    /// `df -PT -B1`.
    pub df: String,
    pub virt: String,
    pub running: String,
    pub failed: String,
    pub ss: String,
    pub who: String,
    pub boot: String,
    pub last: String,
    pub ps: String,
    pub packages: Packages,
}

impl HostFixture {
    /// An Ubuntu 24.04 VM on VMware with apt updates pending.
    pub fn ubuntu() -> Self {
        Self {
            os_release: linux::OS_RELEASE_UBUNTU.into(),
            uname: "Linux 6.8.0-45-generic x86_64".into(),
            lscpu: Some(linux::LSCPU_NEW.into()),
            cpuinfo: linux::CPUINFO.into(),
            swaps: linux::SWAPS.into(),
            lsblk_json: Some(linux::LSBLK_JSON.into()),
            lsblk_pairs: linux::LSBLK_PAIRS.into(),
            df: linux::DF_TYPED.into(),
            virt: "vmware".into(),
            running: admin::SYSTEMCTL_RUNNING.into(),
            failed: admin::SYSTEMCTL_FAILED.into(),
            ss: admin::SS.into(),
            who: admin::WHO.into(),
            boot: "         system boot  2026-10-18 08:12\n".into(),
            last: admin::LAST.into(),
            ps: admin::PS.into(),
            packages: Packages::Apt {
                list: admin::APT.trim_start_matches("present\n").into(),
                refreshed_unix: 1_792_600_000,
            },
        }
    }

    /// An older RHEL-like host: no lscpu, lsblk without JSON, dnf with updates.
    pub fn rhel() -> Self {
        Self {
            os_release: linux::OS_RELEASE_RHEL.into(),
            uname: "Linux 5.14.0-427.13.1.el9_4.x86_64 x86_64".into(),
            lscpu: None,
            lsblk_json: None,
            virt: "kvm".into(),
            packages: Packages::Dnf {
                list: admin::DNF.trim_start_matches("present\n").into(),
                status: 100,
            },
            ..Self::ubuntu()
        }
    }

    /// Files the fixture serves.
    pub fn files(&self) -> Vec<(&'static str, String)> {
        vec![
            ("/etc/os-release", self.os_release.clone()),
            ("/proc/cpuinfo", self.cpuinfo.clone()),
            ("/proc/swaps", self.swaps.clone()),
        ]
    }

    /// Whether `program` is one of the host's (for `type` and `command -v`).
    pub fn has(&self, program: &str) -> bool {
        match program {
            "lscpu" => self.lscpu.is_some(),
            "apt" => matches!(self.packages, Packages::Apt { .. }),
            "dnf" => matches!(self.packages, Packages::Dnf { .. }),
            "uname" | "lsblk" | "systemd-detect-virt" | "systemctl" | "ss" | "who" | "last" | "ps" | "stat" => true,
            _ => false,
        }
    }
}

fn ok(stdout: impl Into<String>) -> Ran {
    Ran {
        stdout: stdout.into(),
        stderr: String::new(),
        status: 0,
    }
}

fn fail(stderr: &str, status: u32) -> Ran {
    Ran {
        stdout: String::new(),
        stderr: format!("{stderr}\n"),
        status,
    }
}

/// Runs one of the host's programs; `None` when it is not one (or, for `df`, not a form it answers).
pub fn run(host: &HostFixture, program: &str, args: &[String]) -> Option<Ran> {
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let ran = match program {
        "uname" => ok(format!("{}\n", host.uname)),
        "lscpu" => ok(host.lscpu.clone()?),
        "lsblk" if has("-J") => match &host.lsblk_json {
            Some(json) => ok(json.clone()),
            None => fail("lsblk: invalid option -- 'J'", 1),
        },
        "lsblk" if has("-P") => ok(host.lsblk_pairs.clone()),
        "lsblk" => fail("lsblk: only -J and -P here", 1),
        "df" if has("-PT") => ok(host.df.clone()),
        "df" => return None,
        "systemd-detect-virt" => ok(format!("{}\n", host.virt)),
        "systemctl" if args.first().is_some_and(|a| a == "list-units") => {
            if args.iter().any(|a| a == "--state=failed") {
                ok(host.failed.clone())
            } else {
                ok(host.running.clone())
            }
        }
        // MO-08: a service check's `systemctl is-active <unit>`, from the running units (`nginx` names
        // `nginx.service`); systemctl's exit status 3 for a unit that isn't active.
        "systemctl" if args.first().is_some_and(|a| a == "is-active") && args.len() == 2 => {
            let unit = &args[1];
            let full = if unit.contains('.') {
                unit.clone()
            } else {
                format!("{unit}.service")
            };
            let failed = host.failed.lines().any(|l| l.split_whitespace().any(|w| w == full));
            let running = host
                .running
                .lines()
                .any(|l| l.split_whitespace().next() == Some(full.as_str()));
            match (running, failed) {
                (true, _) => ok("active\n"),
                (false, true) => Ran {
                    stdout: "failed\n".into(),
                    stderr: String::new(),
                    status: 3,
                },
                (false, false) => Ran {
                    stdout: "inactive\n".into(),
                    stderr: String::new(),
                    status: 3,
                },
            }
        }
        "systemctl" => fail("systemctl: only list-units and is-active here", 1),
        "ss" => ok(host.ss.clone()),
        "who" if has("-b") => ok(host.boot.clone()),
        "who" => ok(host.who.clone()),
        "last" => ok(host.last.clone()),
        "ps" => ok(host.ps.clone()),
        "stat" => match &host.packages {
            Packages::Apt { refreshed_unix, .. } if args.iter().any(|a| a.contains("pkgcache")) => {
                ok(format!("{refreshed_unix}\n"))
            }
            _ => fail("stat: cannot statx: No such file or directory", 1),
        },
        "apt" => match &host.packages {
            Packages::Apt { list, .. } if args.first().is_some_and(|a| a == "list") => ok(list.clone()),
            Packages::Apt { .. } => fail("E: only apt list here", 100),
            _ => return None,
        },
        "dnf" => match &host.packages {
            Packages::Dnf { list, status } => Ran {
                stdout: list.clone(),
                stderr: String::new(),
                status: *status,
            },
            _ => return None,
        },
        _ => return None,
    };
    Some(ran)
}
