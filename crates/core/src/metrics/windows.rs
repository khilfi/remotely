//! MO-05: what a Windows guest says about itself through CIM, read over WinRM in the PowerShell a watched host keeps
//! open ([`crate::adapters::winrm::WinrmSession::read`]) and parsed here into the same reading a Linux guest gives
//! ([`super::procfs::GuestReading`]), so the grid, the history (MO-06) and alerts (MO-07) treat both alike.
//!
//! * CPU: `Win32_PerfRawData_PerfOS_Processor` `_Total`: `PercentProcessorTime` counts idle time in 100 ns units
//!   (an inverse timer averaged over the CPUs) beside `Timestamp_Sys100NS`, so busy is the timestamp's growth less
//!   the idle counter's between two rounds.
//! * Memory: `Win32_OperatingSystem`'s visible memory and free memory (what Windows calls available), and its paging
//!   files' size and free space (as swap).
//! * Disks and network: the raw byte counters of `Win32_PerfRawData_PerfDisk_PhysicalDisk` `_Total` and the sum over
//!   `Win32_PerfRawData_Tcpip_NetworkInterface`, made rates between rounds.
//! * Fixed volumes (`Win32_LogicalDisk`, drive type 3) and uptime from the last boot.
//!
//! Every line is one statement (the kept PowerShell reads its stdin a statement at a time) and only reads: CIM queries
//! and `Get-Date` (`tests::the_script_only_reads`).

use super::procfs::{CpuJiffies, GuestReading, MountUsage};

/// One round's read. The first line names it (the fake host answers by it).
pub const METRICS_SCRIPT: &str = "# remotely:guest-metrics
$os = Get-CimInstance -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize,FreePhysicalMemory,SizeStoredInPagingFiles,FreeSpaceInPagingFiles,LastBootUpTime
$cpu = Get-CimInstance -ClassName Win32_PerfRawData_PerfOS_Processor -Filter \"Name='_Total'\" -Property PercentProcessorTime,Timestamp_Sys100NS
$disk = Get-CimInstance -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk -Filter \"Name='_Total'\" -Property DiskReadBytesPersec,DiskWriteBytesPersec
$rx = [decimal]0; $tx = [decimal]0; Get-CimInstance -ClassName Win32_PerfRawData_Tcpip_NetworkInterface -Property BytesReceivedPersec,BytesSentPersec | ForEach-Object { $rx += $_.BytesReceivedPersec; $tx += $_.BytesSentPersec }
'@@cpu ' + $cpu.PercentProcessorTime + ' ' + $cpu.Timestamp_Sys100NS
'@@mem ' + $os.TotalVisibleMemorySize + ' ' + $os.FreePhysicalMemory + ' ' + $os.SizeStoredInPagingFiles + ' ' + $os.FreeSpaceInPagingFiles
'@@up ' + [long]((Get-Date) - $os.LastBootUpTime).TotalSeconds
'@@disk ' + $disk.DiskReadBytesPersec + ' ' + $disk.DiskWriteBytesPersec
'@@net ' + $rx + ' ' + $tx
Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -Property DeviceID,FileSystem,Size,FreeSpace | ForEach-Object { '@@vol ' + $_.DeviceID + '|' + $_.FileSystem + '|' + $_.Size + '|' + $_.FreeSpace }";

/// Output kept per read: a few hundred bytes, more with many volumes.
pub const MAX_OUTPUT: usize = 64 * 1024;
/// Volumes kept per read.
const MAX_VOLUMES: usize = 64;

fn numbers<const N: usize>(rest: &str) -> Option<[u64; N]> {
    let mut out = [0u64; N];
    let mut words = rest.split_whitespace();
    for slot in &mut out {
        let word = words.next()?;
        // `[decimal]` sums print as whole numbers; anything after a point is dropped.
        let whole = word.split('.').next()?;
        *slot = whole.parse().ok()?;
    }
    Some(out)
}

/// Reads the script's output. A part missing or unreadable leaves its fields empty.
pub fn parse(output: &str) -> GuestReading {
    let mut reading = GuestReading::default();
    for line in output.lines() {
        let line = line.trim();
        let Some((tag, rest)) = line.split_once(' ') else {
            continue;
        };
        match tag {
            "@@cpu" => {
                let pair = numbers::<2>(rest);
                reading.cpu = pair.and_then(|[idle, stamp]| {
                    Some(CpuJiffies {
                        busy: stamp.checked_sub(idle)?,
                        total: stamp,
                    })
                });
                // 100 ns units: the rates' clock, finer than the uptime's whole seconds.
                reading.clock_secs = pair.map(|[_, stamp]| stamp as f64 / 10_000_000.0);
            }
            "@@mem" => {
                if let Some([total, free, page_total, page_free]) = numbers::<4>(rest) {
                    reading.mem_total_bytes = Some(total.saturating_mul(1024));
                    reading.mem_available_bytes = Some(free.saturating_mul(1024));
                    reading.swap_total_bytes = Some(page_total.saturating_mul(1024));
                    reading.swap_free_bytes = Some(page_free.saturating_mul(1024));
                }
            }
            "@@up" => reading.uptime_secs = numbers::<1>(rest).map(|[u]| u as f64),
            // Bytes, kept as 512-byte sectors as Linux's counters are.
            "@@disk" => reading.disk_sectors = numbers::<2>(rest).map(|[r, w]| (r / 512, w / 512)),
            "@@net" => reading.net_bytes = numbers::<2>(rest).map(|[rx, tx]| (rx, tx)),
            "@@vol" if reading.mounts.len() < MAX_VOLUMES => {
                let parts: Vec<&str> = rest.split('|').collect();
                if let [device, fs, size, free] = parts.as_slice() {
                    let (Ok(total), Ok(free)) = (size.trim().parse::<u64>(), free.trim().parse::<u64>()) else {
                        continue;
                    };
                    if total == 0 {
                        continue;
                    }
                    let used = total.saturating_sub(free);
                    reading.mounts.push(MountUsage {
                        mount: clean(device),
                        filesystem: clean(fs),
                        total_bytes: total,
                        used_bytes: used,
                        used_pct: used as f64 * 100.0 / total as f64,
                    });
                }
            }
            _ => {}
        }
    }
    reading
}

fn clean(text: &str) -> String {
    text.trim()
        .chars()
        .filter(|c| !c.is_control() && !crate::untrusted::is_format_char(*c))
        .take(64)
        .collect()
}

/// Test data: what a Windows guest prints for [`METRICS_SCRIPT`], `round` 0 or later, a round 5 s apart: 25% busy,
/// 10 MB read and 5 MB written, 1 MB received and 0.5 MB sent each round.
#[cfg(any(test, feature = "fakes"))]
pub fn sample(round: u64) -> String {
    let stamp = 134_000_000_000_000_000u64 + round * 50_000_000;
    let idle = 1_900_000_000_000u64 + round * 37_500_000;
    format!(
        "@@cpu {idle} {stamp}\r\n@@mem 8388608 2097152 1310720 1048576\r\n@@up {}\r\n@@disk {} {}\r\n@@net {} {}\r\n\
@@vol C:|NTFS|64424509440|21474836480\r\n@@vol D:|ReFS|107374182400|85899345920\r\n",
        86_400 + round * 5,
        1_048_576_000 + round * 10_485_760,
        524_288_000 + round * 5_242_880,
        9_000_000 + round * 1_048_576,
        4_000_000 + round * 524_288,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::procfs::rates;
    use std::time::{Duration, Instant};

    #[test]
    fn a_reading_becomes_rates_like_a_linux_guest() {
        let first = parse(&sample(0));
        assert_eq!(first.mem_total_bytes, Some(8 * 1024 * 1024 * 1024));
        assert_eq!(first.mem_used_bytes(), Some(6 * 1024 * 1024 * 1024));
        assert_eq!(first.swap_total_bytes, Some(1_342_177_280));
        assert_eq!(first.uptime_secs, Some(86_400.0));
        assert_eq!(first.mounts.len(), 2);
        assert_eq!(first.mounts[0].mount, "C:");
        assert!((first.mounts[0].used_pct - 66.666).abs() < 0.01);
        assert_eq!(first.load, None);
        let second = parse(&sample(1));
        let at = Instant::now();
        let r = rates(Some((&first, at)), &second, at + Duration::from_secs(5));
        assert!((r.cpu_pct.unwrap() - 25.0).abs() < 0.001, "{r:?}");
        assert!((r.disk_read_bps.unwrap() - 2_097_152.0).abs() < 1.0);
        assert!((r.net_rx_bps.unwrap() - 209_715.2).abs() < 1.0);
        // The uptime is whole seconds (rounded to 6 s here, and this PC's clock says 7 s): the rates still use the
        // 5 s the CPU counter's own timestamp grew.
        let mut rounded = parse(&sample(1));
        rounded.uptime_secs = Some(86_406.0);
        let r = rates(Some((&first, at)), &rounded, at + Duration::from_secs(7));
        assert!((r.disk_read_bps.unwrap() - 2_097_152.0).abs() < 1.0, "{r:?}");
        assert!((r.net_tx_bps.unwrap() - 104_857.6).abs() < 1.0, "{r:?}");
    }

    #[test]
    fn junk_reads_as_nothing() {
        let reading = parse("The term 'Get-CimInstance' is not recognized\r\n@@cpu x y\r\n@@vol |||\r\n");
        assert!(reading.is_empty());
        assert!(reading.mounts.is_empty());
    }

    #[test]
    fn the_script_only_reads() {
        crate::host_details::windows::assert_only_reads(METRICS_SCRIPT);
        for line in METRICS_SCRIPT.lines() {
            let mut syntax = crate::adapters::winrm::console::Syntax::default();
            syntax.feed(line);
            assert!(syntax.complete(), "each line is a whole statement: {line}");
        }
    }
}
