//! MO-02: what a Linux guest says about itself in /proc and `df`, read in one command per round and
//! parsed here. Pure functions, so they are tested against real-world samples without a host.
//!
//! Counters (CPU jiffies, disk sectors, network bytes) only mean something as the difference between
//! two rounds, so [`rates`] compares a reading with the previous one from the same connection.

use std::time::Instant;

use serde::Serialize;

/// The rounds between two `df`s: the /proc files a round reads, all with one `grep`, which starts each
/// line with its file's name when it reads several (POSIX; GNU, BSD and busybox grep do). `-v` leaves
/// out /proc/stat's `intr` and `softirq` lines, which run to thousands of numbers on many-CPU hosts.
/// One process instead of six (`head` and five `cat`s), so a SIEM that logs every execve on a watched
/// host sees two a round (the login shell and `grep`), not eight. Disk space changes slowly, so the
/// mounts of the last `df` stand in ([`DF_EVERY`]).
pub const GUEST_SCRIPT_WITHOUT_DF: &str =
    "grep -v -e '^intr ' -e '^softirq ' /proc/stat /proc/meminfo /proc/loadavg /proc/uptime /proc/diskstats /proc/net/dev";

/// Everything in one exec: the /proc files, then `df` after a marker line. Plain commands and `;`
/// only, so any login shell runs it the same way. `df -l` leaves out network mounts, which can hang.
/// Reads only; changes nothing on the guest.
pub const GUEST_SCRIPT: &str = concat!(
    "grep -v -e '^intr ' -e '^softirq ' /proc/stat /proc/meminfo /proc/loadavg /proc/uptime /proc/diskstats /proc/net/dev",
    "; echo @@df; df -k -P -l"
);

/// How often a watched host runs `df` (that round's script is [`GUEST_SCRIPT`]).
pub const DF_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// Which section a line `grep` named after its file belongs to.
const FILES: [(&str, &str); 6] = [
    ("/proc/stat:", "stat"),
    ("/proc/meminfo:", "meminfo"),
    ("/proc/loadavg:", "loadavg"),
    ("/proc/uptime:", "uptime"),
    ("/proc/diskstats:", "diskstats"),
    ("/proc/net/dev:", "netdev"),
];

/// Output kept per round and stream. A busy host's /proc/diskstats can run to a few hundred lines.
pub const MAX_OUTPUT: usize = 256 * 1024;

/// One disk's (or mount's) space, from `df`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MountUsage {
    /// Where it is mounted, e.g. `/` or `/var/lib/data`.
    pub mount: String,
    /// The device, e.g. `/dev/sda1`.
    pub filesystem: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    /// Used of what is usable (used + available), as `df` counts it.
    pub used_pct: f64,
}

/// CPU time in jiffies, summed over every CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuJiffies {
    pub busy: u64,
    pub total: u64,
}

/// One round's raw reading.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GuestReading {
    pub cpu: Option<CpuJiffies>,
    pub mem_total_bytes: Option<u64>,
    pub mem_available_bytes: Option<u64>,
    /// MO-15: SwapTotal and SwapFree.
    pub swap_total_bytes: Option<u64>,
    pub swap_free_bytes: Option<u64>,
    pub load: Option<[f64; 3]>,
    pub uptime_secs: Option<f64>,
    /// The guest's own clock for rates, finer than its uptime where it has one: a Windows host's
    /// `Timestamp_Sys100NS`, read with the CPU counter, in seconds. Linux's uptime has hundredths.
    pub clock_secs: Option<f64>,
    /// Sectors (512 bytes each, whatever the disk's own sector size) read and written by whole disks.
    pub disk_sectors: Option<(u64, u64)>,
    /// Bytes received and sent by the network interfaces, loopback and container links left out.
    pub net_bytes: Option<(u64, u64)>,
    pub mounts: Vec<MountUsage>,
}

impl GuestReading {
    /// Nothing a Linux host would print: no /proc at all (e.g. a Windows or BSD host).
    pub fn is_empty(&self) -> bool {
        self.cpu.is_none() && self.mem_total_bytes.is_none() && self.uptime_secs.is_none()
    }

    pub fn mem_used_bytes(&self) -> Option<u64> {
        Some(self.mem_total_bytes?.saturating_sub(self.mem_available_bytes?))
    }

    /// MO-15: swap in use.
    pub fn swap_used_bytes(&self) -> Option<u64> {
        Some(self.swap_total_bytes?.saturating_sub(self.swap_free_bytes?))
    }
}

/// Rates between two readings.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GuestRates {
    pub cpu_pct: Option<f64>,
    pub disk_read_bps: Option<f64>,
    pub disk_write_bps: Option<f64>,
    pub net_rx_bps: Option<f64>,
    pub net_tx_bps: Option<f64>,
}

/// Splits the script's output at its markers and parses each part. A part that is missing or can't
/// be read leaves its fields empty; the rest still count.
pub fn parse(output: &str) -> GuestReading {
    let mut reading = GuestReading::default();
    let flush = |section: &str, lines: &[&str], reading: &mut GuestReading| match section {
        "stat" => reading.cpu = lines.iter().find_map(|l| parse_cpu(l)),
        "meminfo" => {
            let (total, available) = parse_meminfo(lines);
            reading.mem_total_bytes = total;
            reading.mem_available_bytes = available;
            reading.swap_total_bytes = meminfo_bytes(lines, "SwapTotal");
            reading.swap_free_bytes = meminfo_bytes(lines, "SwapFree");
        }
        "loadavg" => reading.load = lines.first().and_then(|l| parse_loadavg(l)),
        "uptime" => reading.uptime_secs = lines.first().and_then(|l| first_number(l)),
        "diskstats" => reading.disk_sectors = parse_diskstats(lines),
        "netdev" => reading.net_bytes = parse_netdev(lines),
        "df" => reading.mounts = parse_df(lines),
        _ => {}
    };
    // Lines `grep` named after their file (before any marker), and lines after a marker (`@@df`;
    // before 0.4.3 every part had one).
    let mut sections: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut marked: Option<&str> = None;
    for line in output.lines() {
        if let Some(name) = line.trim().strip_prefix("@@") {
            marked = Some(name);
            continue;
        }
        let (section, line) = match marked {
            Some(name) => (name, line),
            None => match FILES
                .iter()
                .find_map(|(prefix, name)| line.strip_prefix(prefix).map(|rest| (*name, rest)))
            {
                Some(found) => found,
                None => continue,
            },
        };
        match sections.iter_mut().find(|(name, _)| *name == section) {
            Some((_, lines)) => lines.push(line),
            None => sections.push((section, vec![line])),
        }
    }
    for (section, lines) in &sections {
        flush(section, lines, &mut reading);
    }
    reading
}

fn first_number(line: &str) -> Option<f64> {
    line.split_whitespace().next()?.parse().ok()
}

/// The `cpu` line of /proc/stat: user nice system idle iowait irq softirq steal (guest time is
/// already inside user and nice). Idle and iowait count as not busy.
fn parse_cpu(line: &str) -> Option<CpuJiffies> {
    let mut fields = line.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let values: Vec<u64> = fields.take(8).map_while(|f| f.parse().ok()).collect();
    if values.len() < 4 {
        return None;
    }
    let total: u64 = values.iter().sum();
    let idle = values[3] + values.get(4).copied().unwrap_or(0);
    Some(CpuJiffies {
        busy: total.saturating_sub(idle),
        total,
    })
}

/// MemTotal and MemAvailable (kernels before 3.14 lack it: free + buffers + cached instead), in bytes.
fn parse_meminfo(lines: &[&str]) -> (Option<u64>, Option<u64>) {
    let kb = |key: &str| -> Option<u64> {
        lines.iter().find_map(|line| {
            let rest = line.strip_prefix(key)?.strip_prefix(':')?;
            let value: u64 = rest.split_whitespace().next()?.parse().ok()?;
            Some(value.saturating_mul(1024))
        })
    };
    let total = kb("MemTotal");
    let available =
        kb("MemAvailable").or_else(|| Some(kb("MemFree")? + kb("Buffers").unwrap_or(0) + kb("Cached").unwrap_or(0)));
    (total, available)
}

/// One /proc/meminfo value (kB), in bytes.
fn meminfo_bytes(lines: &[&str], key: &str) -> Option<u64> {
    lines.iter().find_map(|line| {
        let rest = line.strip_prefix(key)?.strip_prefix(':')?;
        let value: u64 = rest.split_whitespace().next()?.parse().ok()?;
        Some(value.saturating_mul(1024))
    })
}

fn parse_loadavg(line: &str) -> Option<[f64; 3]> {
    let mut fields = line.split_whitespace().map(|f| f.parse::<f64>());
    Some([fields.next()?.ok()?, fields.next()?.ok()?, fields.next()?.ok()?])
}

/// Whole disks only: partitions, device-mapper and md devices sit on top of disks that are counted
/// already, and loop, ram, zram and optical devices aren't disks.
fn is_whole_disk(name: &str) -> bool {
    let tail_is = |prefix: &str, rest: &dyn Fn(&str) -> bool| name.strip_prefix(prefix).is_some_and(rest);
    let letters = |r: &str| !r.is_empty() && r.chars().all(|c| c.is_ascii_lowercase());
    let digits = |r: &str| !r.is_empty() && r.chars().all(|c| c.is_ascii_digit());
    tail_is("sd", &letters)
        || tail_is("vd", &letters)
        || tail_is("xvd", &letters)
        || tail_is("hd", &letters)
        || tail_is("mmcblk", &digits)
        || name.strip_prefix("nvme").is_some_and(|r| {
            // nvme0n1, not nvme0n1p1 or nvme0c0n1.
            r.split_once('n')
                .is_some_and(|(controller, namespace)| digits(controller) && digits(namespace))
        })
}

/// /proc/diskstats: major minor name reads merged sectors_read ms writes merged sectors_written ...
fn parse_diskstats(lines: &[&str]) -> Option<(u64, u64)> {
    let mut found = false;
    let (mut read, mut written) = (0u64, 0u64);
    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 || !is_whole_disk(fields[2]) {
            continue;
        }
        if let (Ok(r), Ok(w)) = (fields[5].parse::<u64>(), fields[9].parse::<u64>()) {
            read = read.saturating_add(r);
            written = written.saturating_add(w);
            found = true;
        }
    }
    found.then_some((read, written))
}

/// Interfaces that only carry traffic counted elsewhere too, or none.
fn is_virtual_interface(name: &str) -> bool {
    name == "lo"
        || ["veth", "docker", "br-", "virbr", "cni", "flannel"]
            .iter()
            .any(|p| name.starts_with(p))
}

/// /proc/net/dev: `iface: rx_bytes packets errs drop fifo frame compressed multicast tx_bytes ...`.
fn parse_netdev(lines: &[&str]) -> Option<(u64, u64)> {
    let mut found = false;
    let (mut rx, mut tx) = (0u64, 0u64);
    for line in lines {
        let Some((name, counters)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.contains('|') || is_virtual_interface(name) {
            continue;
        }
        let fields: Vec<u64> = counters.split_whitespace().map_while(|f| f.parse().ok()).collect();
        if fields.len() >= 9 {
            rx = rx.saturating_add(fields[0]);
            tx = tx.saturating_add(fields[8]);
            found = true;
        }
    }
    found.then_some((rx, tx))
}

/// Memory and pseudo file systems, and snap images: not where data runs out.
fn is_pseudo_filesystem(fs: &str) -> bool {
    ["tmpfs", "devtmpfs", "udev", "overlay", "none", "shm", "run", "efivarfs"].contains(&fs)
        || fs.starts_with("/dev/loop")
}

/// `df -k -P`: Filesystem 1024-blocks Used Available Capacity Mounted-on, one line per file system.
/// The mount point is everything after the fifth field, so it may contain spaces.
fn parse_df(lines: &[&str]) -> Vec<MountUsage> {
    let mut mounts = Vec::new();
    for line in lines
        .iter()
        .skip_while(|l| !l.trim_start().starts_with("Filesystem"))
        .skip(1)
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 || is_pseudo_filesystem(fields[0]) {
            continue;
        }
        let (Ok(blocks), Ok(used), Ok(available)) = (
            fields[1].parse::<u64>(),
            fields[2].parse::<u64>(),
            fields[3].parse::<u64>(),
        ) else {
            continue;
        };
        if blocks == 0 {
            continue;
        }
        let usable = used + available;
        mounts.push(MountUsage {
            mount: fields[5..].join(" "),
            filesystem: fields[0].to_owned(),
            total_bytes: blocks.saturating_mul(1024),
            used_bytes: used.saturating_mul(1024),
            used_pct: if usable == 0 {
                0.0
            } else {
                used as f64 * 100.0 / usable as f64
            },
        });
    }
    mounts
}

/// Rates between `previous` (read at `then`) and `now` (read at `at`). The guest's own uptime times
/// the interval when both readings have it, so network delays don't skew the rates. A counter that
/// went back (the guest restarted) gives no rate this round.
pub fn rates(previous: Option<(&GuestReading, Instant)>, now: &GuestReading, at: Instant) -> GuestRates {
    let Some((before, then)) = previous else {
        return GuestRates::default();
    };
    // Review F4 #11: a guest clock finer than whole seconds first (Windows' uptime is whole seconds, which would
    // skew a 5 s round's rates by up to a fifth), then the uptime, then this PC's clock.
    let secs = match (now.clock_secs, before.clock_secs, now.uptime_secs, before.uptime_secs) {
        (Some(a), Some(b), _, _) if a > b => a - b,
        (_, _, Some(a), Some(b)) if a > b => a - b,
        _ => at.saturating_duration_since(then).as_secs_f64(),
    };
    let per_sec = |a: u64, b: u64| -> Option<f64> { (secs > 0.0).then_some(a.checked_sub(b)? as f64 / secs) };
    let cpu_pct = match (now.cpu, before.cpu) {
        (Some(a), Some(b)) => {
            let total = a.total.checked_sub(b.total).filter(|t| *t > 0);
            let busy = a.busy.checked_sub(b.busy);
            total
                .zip(busy)
                .map(|(t, b)| (b as f64 * 100.0 / t as f64).clamp(0.0, 100.0))
        }
        _ => None,
    };
    let disk = now.disk_sectors.zip(before.disk_sectors);
    let net = now.net_bytes.zip(before.net_bytes);
    GuestRates {
        cpu_pct,
        disk_read_bps: disk.and_then(|((r, _), (r0, _))| per_sec(r, r0)).map(|s| s * 512.0),
        disk_write_bps: disk.and_then(|((_, w), (_, w0))| per_sec(w, w0)).map(|s| s * 512.0),
        net_rx_bps: net.and_then(|((rx, _), (rx0, _))| per_sec(rx, rx0)),
        net_tx_bps: net.and_then(|((_, tx), (_, tx0))| per_sec(tx, tx0)),
    }
}

/// Test data: what an Ubuntu guest prints for [`GUEST_SCRIPT`], with counters a round apart.
#[cfg(any(test, feature = "fakes"))]
pub mod samples {
    /// /proc files and `df` output a guest prints, `round` 0 or later. Each later round adds 5 s of
    /// uptime, 2 s of busy CPU out of 8 (4 CPUs), 10 MB read, 5 MB written, 1 MB received and 0.5 MB
    /// sent.
    pub struct Sample {
        pub stat: String,
        pub meminfo: String,
        pub loadavg: String,
        pub uptime: String,
        pub diskstats: String,
        pub netdev: String,
        pub df: String,
    }

    pub fn ubuntu(round: u64) -> Sample {
        // 100 jiffies a second: 5 s on 4 CPUs is 2000 jiffies, 500 of them busy.
        let user = 10_000 + round * 400;
        let system = 2_000 + round * 100;
        let idle = 80_000 + round * 1_500;
        let read_sectors = 1_000_000 + round * 20_480;
        let written_sectors = 500_000 + round * 10_240;
        let rx = 9_000_000 + round * 1_048_576;
        let tx = 4_000_000 + round * 524_288;
        Sample {
            stat: format!("cpu  {user} 20 {system} {idle} 300 0 50 0 0 0\ncpu0 1 2 3 4 5 6 7 8 0 0\nintr 12345 0 0\n"),
            meminfo: "MemTotal:        4028180 kB\nMemFree:          512000 kB\nMemAvailable:    1007045 kB\nBuffers:           10000 kB\nCached:           400000 kB\nSwapTotal:       2097148 kB\nSwapFree:        1572860 kB\n".into(),
            loadavg: "0.52 0.48 0.40 2/310 12345\n".into(),
            uptime: format!("{}.25 {}.10\n", 3600 + round * 5, 10_000 + round * 15),
            diskstats: format!(
                "   8       0 sda 12000 300 {read_sectors} 4000 6000 200 {written_sectors} 9000 0 7000 13000\n   8       1 sda1 11000 290 999999 3900 5900 190 499999 8900 0 6900 12800\n 253       0 dm-0 9000 0 888888 3000 5000 0 444444 8000 0 6000 11000\n   7       0 loop0 50 0 400 10 0 0 0 0 0 10 10\n"
            ),
            netdev: format!(
                "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo:  777777     100    0    0    0     0          0         0   777777     100    0    0    0     0       0          0\n  ens33: {rx}  9000    0    0    0     0          0         0 {tx}  6000    0    0    0     0       0          0\ndocker0: 5555 10 0 0 0 0 0 0 6666 10 0 0 0 0 0 0\n"
            ),
            df: "Filesystem     1024-blocks     Used Available Capacity Mounted on\ntmpfs               402820     1636    401184       1% /run\n/dev/sda2         40000000 30000000   8000000      79% /\n/dev/sda1           524288     6220    518068       2% /boot/efi\n/dev/sdb1        100000000 95000000   5000000      95% /var/lib/my data\n/dev/loop0           65536    65536         0     100% /snap/core20/1974\n".into(),
        }
    }

    impl Sample {
        /// The whole output of [`super::GUEST_SCRIPT`]: each file's lines after its name, as `grep`
        /// prints them, then `df`.
        pub fn output(&self) -> String {
            let mut out = self.proc_output();
            out.push_str("@@df\n");
            out.push_str(&self.df);
            out
        }

        /// The output of [`super::GUEST_SCRIPT_WITHOUT_DF`].
        pub fn proc_output(&self) -> String {
            let files = [
                ("/proc/stat", &self.stat),
                ("/proc/meminfo", &self.meminfo),
                ("/proc/loadavg", &self.loadavg),
                ("/proc/uptime", &self.uptime),
                ("/proc/diskstats", &self.diskstats),
                ("/proc/net/dev", &self.netdev),
            ];
            let mut out = String::new();
            for (path, text) in files {
                for line in text.lines() {
                    if !line.starts_with("intr ") && !line.starts_with("softirq ") {
                        out.push_str(&format!("{path}:{line}\n"));
                    }
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn reads_every_part_of_an_ubuntu_guest() {
        let reading = parse(&samples::ubuntu(0).output());
        assert_eq!(
            reading.cpu,
            Some(CpuJiffies {
                busy: 10_000 + 20 + 2_000 + 50,
                total: 10_000 + 20 + 2_000 + 80_000 + 300 + 50
            })
        );
        assert_eq!(reading.mem_total_bytes, Some(4_028_180 * 1024));
        assert_eq!(reading.mem_available_bytes, Some(1_007_045 * 1024));
        assert_eq!(reading.mem_used_bytes(), Some((4_028_180 - 1_007_045) * 1024));
        assert_eq!(reading.swap_total_bytes, Some(2_097_148 * 1024));
        assert_eq!(reading.swap_used_bytes(), Some((2_097_148 - 1_572_860) * 1024));
        assert_eq!(reading.load, Some([0.52, 0.48, 0.40]));
        assert_eq!(reading.uptime_secs, Some(3600.25));
        assert_eq!(
            reading.disk_sectors,
            Some((1_000_000, 500_000)),
            "sda only: not sda1, dm-0 or loop0"
        );
        assert_eq!(
            reading.net_bytes,
            Some((9_000_000, 4_000_000)),
            "ens33 only: not lo or docker0"
        );
        let mounts: Vec<(&str, f64)> = reading
            .mounts
            .iter()
            .map(|m| (m.mount.as_str(), (m.used_pct * 10.0).round() / 10.0))
            .collect();
        assert_eq!(mounts, [("/", 78.9), ("/boot/efi", 1.2), ("/var/lib/my data", 95.0)]);
        assert_eq!(reading.mounts[0].total_bytes, 40_000_000 * 1024);
        assert_eq!(reading.mounts[0].filesystem, "/dev/sda2");
        assert!(!reading.is_empty());
    }

    #[test]
    fn the_older_marked_output_still_reads() {
        let s = samples::ubuntu(0);
        let marked = format!(
            "@@stat\n{}@@meminfo\n{}@@loadavg\n{}@@uptime\n{}@@diskstats\n{}@@netdev\n{}@@df\n{}",
            s.stat, s.meminfo, s.loadavg, s.uptime, s.diskstats, s.netdev, s.df
        );
        assert_eq!(parse(&marked), parse(&s.output()));
    }

    #[test]
    fn a_round_without_df_reads_everything_but_the_mounts() {
        let reading = parse(&samples::ubuntu(0).proc_output());
        assert!(reading.cpu.is_some() && reading.mem_total_bytes.is_some() && reading.load.is_some());
        assert!(reading.disk_sectors.is_some() && reading.net_bytes.is_some());
        assert!(reading.mounts.is_empty());
    }

    #[test]
    fn a_round_runs_one_program_and_df_once_a_minute() {
        // P8, MO-02: what a SIEM logging every execve sees each round, besides the login shell. It was
        // seven: `head`, five `cat`s and `df`.
        let programs = |script: &str| {
            script
                .split(';')
                .filter_map(|command| command.split_whitespace().next())
                .filter(|program| *program != "echo")
                .count()
        };
        assert_eq!(programs(GUEST_SCRIPT_WITHOUT_DF), 1);
        assert_eq!(programs(GUEST_SCRIPT), 2);
        assert!(GUEST_SCRIPT.starts_with(GUEST_SCRIPT_WITHOUT_DF));
    }

    #[test]
    fn rates_compare_two_rounds_by_the_guest_clock() {
        let first = parse(&samples::ubuntu(0).output());
        let second = parse(&samples::ubuntu(1).output());
        let at = Instant::now();
        assert_eq!(
            rates(None, &first, at),
            GuestRates::default(),
            "one reading has no rates"
        );

        // The local clock says 7 s (network delay); the guest's uptime says 5 s, and wins.
        let r = rates(Some((&first, at)), &second, at + Duration::from_secs(7));
        assert_eq!(r.cpu_pct, Some(25.0));
        assert_eq!(r.disk_read_bps, Some(20_480.0 * 512.0 / 5.0));
        assert_eq!(r.disk_write_bps, Some(10_240.0 * 512.0 / 5.0));
        assert_eq!(r.net_rx_bps, Some(1_048_576.0 / 5.0));
        assert_eq!(r.net_tx_bps, Some(524_288.0 / 5.0));

        // The guest restarted: counters went back, so no rates this round.
        let r = rates(Some((&second, at)), &first, at + Duration::from_secs(5));
        assert_eq!(r.cpu_pct, None);
        assert_eq!(r.disk_read_bps, None);
        assert_eq!(r.net_rx_bps, None);
    }

    #[test]
    fn whole_disks_are_told_from_partitions_and_stacked_devices() {
        for disk in ["sda", "sdab", "vdb", "xvda", "hda", "nvme0n1", "nvme12n3", "mmcblk0"] {
            assert!(is_whole_disk(disk), "{disk}");
        }
        for not in [
            "sda1",
            "nvme0n1p1",
            "nvme0c0n1",
            "mmcblk0p1",
            "dm-0",
            "md0",
            "loop3",
            "sr0",
            "zram0",
            "ram0",
        ] {
            assert!(!is_whole_disk(not), "{not}");
        }
    }

    #[test]
    fn older_kernels_without_memavailable_count_free_buffers_and_cache() {
        let (total, available) = parse_meminfo(&[
            "MemTotal:        2000000 kB",
            "MemFree:          100000 kB",
            "Buffers:           20000 kB",
            "Cached:           300000 kB",
        ]);
        assert_eq!(total, Some(2_000_000 * 1024));
        assert_eq!(available, Some(420_000 * 1024));
    }

    #[test]
    fn a_host_without_proc_reads_as_empty() {
        let output = "@@stat\n@@meminfo\n@@loadavg\n@@uptime\n@@diskstats\n@@netdev\n@@df\nFilesystem 1024-blocks Used Available Capacity Mounted on\n";
        let reading = parse(output);
        assert!(reading.is_empty());
        assert!(reading.mounts.is_empty());
        assert!(parse("").is_empty());
    }
}
