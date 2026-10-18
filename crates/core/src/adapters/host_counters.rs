//! Host counters adapter (MO-01, MO-04, VM-07): what Windows knows about this machine and about the
//! `vmware-vmx.exe` process behind each running VM. Reads only, no login needed.
//!
//! [`WindowsCounters`] reads physical RAM (`GlobalMemoryStatusEx`), logical CPUs
//! (`GetActiveProcessorCount`), the host's CPU times (`GetSystemTimes`) and free disk space
//! (`GetDiskFreeSpaceExW`) through the `windows` crate. MO-01: each running VM is a `vmware-vmx.exe`
//! process (found with a Toolhelp snapshot) whose command line ends with its .vmx path
//! (`NtQueryInformationProcess`, read once per process). Its CPU time (`GetProcessTimes`), working
//! set (`GetProcessMemoryInfo`) and I/O bytes (`GetProcessIoCounters`) are read every round, and the
//! rates come from the difference to the previous round. Process APIs rather than PDH counters: PDH
//! names processes `vmware-vmx#3`, which says nothing about which VM it is, and costs more per read.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;

use crate::error::{CoreError, Result};
use crate::locks;

/// The process behind each running Workstation VM.
pub const VMX_PROCESS: &str = "vmware-vmx.exe";

/// One `vmware-vmx.exe` process.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmProcess {
    pub pid: u32,
    /// Taken from the process command line; `None` when it could not be read.
    pub vmx_path: Option<String>,
    /// Share of the host's whole CPU (every logical processor), as Task Manager shows it. `None` on
    /// the first read of a process: a rate needs two.
    pub cpu_pct: Option<f64>,
    pub working_set_bytes: Option<u64>,
    /// Bytes per second the process read and wrote (its virtual disks, mostly).
    pub read_bps: Option<f64>,
    pub write_bps: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostTotals {
    pub physical_ram_mb: u64,
    /// RAM free for use right now (MO-04).
    pub available_ram_mb: u64,
    pub logical_cpus: u32,
}

/// The host's CPU time since it started, summed over every logical processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SystemCpuTimes {
    pub idle: Duration,
    /// Idle plus busy.
    pub total: Duration,
}

impl SystemCpuTimes {
    /// Busy share of the host's CPU between two readings, in percent.
    pub fn busy_pct_since(&self, earlier: &SystemCpuTimes) -> Option<f64> {
        let total = self.total.checked_sub(earlier.total)?.as_secs_f64();
        let idle = self.idle.checked_sub(earlier.idle)?.as_secs_f64();
        (total > 0.0).then(|| ((total - idle) * 100.0 / total).clamp(0.0, 100.0))
    }
}

/// Size and free space of a drive (MO-04, VM-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskSpace {
    pub free_bytes: u64,
    pub total_bytes: u64,
}

impl DiskSpace {
    pub fn free_pct(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            self.free_bytes as f64 * 100.0 / self.total_bytes as f64
        }
    }
}

#[async_trait]
pub trait HostCounters: Send + Sync {
    /// MO-01: counters for every running VM's process. Rates compare with the previous call.
    async fn vm_processes(&self) -> Result<Vec<VmProcess>>;
    /// MO-04, VM-07: physical and available RAM, logical CPUs.
    async fn host_totals(&self) -> Result<HostTotals>;
    /// MO-04: the host's CPU times, for its busy share between two readings.
    async fn system_cpu_times(&self) -> Result<SystemCpuTimes>;
    /// MO-01 NFR: CPU time this app's own process has used so far, so the dashboard can show what
    /// collecting costs.
    async fn own_cpu_time(&self) -> Result<Duration>;
    /// MO-04, VM-07: size and free space of the drive holding `path` (an existing file or folder).
    async fn disk_space(&self, path: &Path) -> Result<DiskSpace>;

    /// VM-07: free space on the drive holding `path`, as a percentage.
    async fn free_disk_pct(&self, path: &Path) -> Result<f64> {
        let space = self.disk_space(path).await?;
        if space.total_bytes == 0 {
            return Err(CoreError::Io(std::io::Error::other(format!(
                "{} reports a size of 0 bytes",
                path.display()
            ))));
        }
        Ok(space.free_pct())
    }
}

/// Windows APIs through the `windows` crate. Keeps the previous reading of each VM process, so it
/// can report rates.
#[derive(Default)]
pub struct WindowsCounters {
    tracker: Arc<Mutex<ProcessTracker>>,
}

impl WindowsCounters {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Runs a blocking Windows call off the async threads (a network drive can take a while to answer;
/// the process reads are many small system calls).
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| CoreError::Io(std::io::Error::other(err)))?
}

#[async_trait]
impl HostCounters for WindowsCounters {
    async fn vm_processes(&self) -> Result<Vec<VmProcess>> {
        let tracker = Arc::clone(&self.tracker);
        blocking(move || {
            let cpus = win::host_totals()?.logical_cpus;
            let mut tracker = locks::lock(&tracker);
            let raw = win::read_processes(VMX_PROCESS, &tracker)?;
            Ok(tracker.update(Instant::now(), raw, cpus))
        })
        .await
    }

    async fn host_totals(&self) -> Result<HostTotals> {
        win::host_totals()
    }

    async fn system_cpu_times(&self) -> Result<SystemCpuTimes> {
        win::system_cpu_times()
    }

    async fn own_cpu_time(&self) -> Result<Duration> {
        win::own_cpu_time()
    }

    async fn disk_space(&self, path: &Path) -> Result<DiskSpace> {
        let path = path.to_path_buf();
        blocking(move || win::disk_space(&path)).await
    }
}

/// One process as read this round, before rates.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RawProcess {
    pub pid: u32,
    /// Creation time (100 ns units). With the pid, it tells a process from a later one that reused
    /// its pid.
    pub created: u64,
    pub vmx_path: Option<String>,
    /// Kernel plus user time, in 100 ns units.
    pub cpu_time: u64,
    pub working_set: Option<u64>,
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
}

/// The previous reading of each VM process, for rates, and its .vmx path, so each command line is
/// read only once.
#[derive(Default)]
pub(crate) struct ProcessTracker {
    last: HashMap<u32, (RawProcess, Instant)>,
}

impl ProcessTracker {
    /// The .vmx path read earlier for this process, if it is the same process.
    pub fn known_path(&self, pid: u32, created: u64) -> Option<Option<String>> {
        self.last
            .get(&pid)
            .filter(|(raw, _)| raw.created == created)
            .map(|(raw, _)| raw.vmx_path.clone())
    }

    /// Rates against the previous reading; forgets processes that are gone.
    pub fn update(&mut self, now: Instant, raw: Vec<RawProcess>, logical_cpus: u32) -> Vec<VmProcess> {
        let cpus = f64::from(logical_cpus.max(1));
        let mut next = HashMap::with_capacity(raw.len());
        let mut out = Vec::with_capacity(raw.len());
        for process in raw {
            let previous = self
                .last
                .get(&process.pid)
                .filter(|(p, _)| p.created == process.created);
            let (cpu_pct, read_bps, write_bps) = match previous {
                Some((before, at)) => {
                    let secs = now.saturating_duration_since(*at).as_secs_f64();
                    let rate = |now: Option<u64>, then: Option<u64>| -> Option<f64> {
                        let delta = now?.checked_sub(then?)?;
                        (secs > 0.0).then(|| delta as f64 / secs)
                    };
                    let cpu = process
                        .cpu_time
                        .checked_sub(before.cpu_time)
                        .filter(|_| secs > 0.0)
                        // 100 ns units -> seconds of CPU per second of wall time, over every CPU.
                        .map(|delta| (delta as f64 / 1e7 / secs / cpus * 100.0).clamp(0.0, 100.0));
                    (
                        cpu,
                        rate(process.read_bytes, before.read_bytes),
                        rate(process.write_bytes, before.write_bytes),
                    )
                }
                None => (None, None, None),
            };
            out.push(VmProcess {
                pid: process.pid,
                vmx_path: process.vmx_path.clone(),
                cpu_pct,
                working_set_bytes: process.working_set,
                read_bps,
                write_bps,
            });
            next.insert(process.pid, (process, now));
        }
        self.last = next;
        out
    }
}

/// MO-01: the .vmx path in a `vmware-vmx.exe` command line: the last argument ending in `.vmx`,
/// split the way Windows programs split their command line (quotes, and backslashes before a quote).
pub fn vmx_from_command_line(command_line: &str) -> Option<String> {
    split_command_line(command_line)
        .into_iter()
        .rev()
        .find(|arg| arg.len() > 4 && arg.to_ascii_lowercase().ends_with(".vmx"))
}

/// The Microsoft C runtime's rules: whitespace splits arguments outside quotes; `2n` backslashes
/// before a quote are `n` backslashes and the quote toggles quoting; `2n+1` are `n` and a literal
/// quote; `""` inside quotes is a literal quote; other backslashes are literal.
fn split_command_line(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_arg = false;
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let mut slashes = 1;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    slashes += 1;
                }
                in_arg = true;
                if chars.peek() == Some(&'"') {
                    current.extend(std::iter::repeat_n('\\', slashes / 2));
                    if slashes % 2 == 1 {
                        chars.next();
                        current.push('"');
                    }
                } else {
                    current.extend(std::iter::repeat_n('\\', slashes));
                }
            }
            '"' => {
                in_arg = true;
                if quoted && chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    quoted = !quoted;
                }
            }
            c if c.is_whitespace() && !quoted => {
                if in_arg {
                    args.push(std::mem::take(&mut current));
                    in_arg = false;
                }
            }
            c => {
                in_arg = true;
                current.push(c);
            }
        }
    }
    if in_arg {
        args.push(current);
    }
    args
}

#[cfg(windows)]
mod win {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::time::Duration;

    use windows::core::PCWSTR;
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
    use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, UNICODE_STRING};
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows::Win32::System::Threading::{
        GetActiveProcessorCount, GetCurrentProcess, GetProcessIoCounters, GetProcessTimes, GetSystemTimes, OpenProcess,
        ALL_PROCESSOR_GROUPS, IO_COUNTERS, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{vmx_from_command_line, DiskSpace, HostTotals, ProcessTracker, RawProcess, SystemCpuTimes};
    use crate::error::{CoreError, Result};

    fn os_error(call: &str, err: windows::core::Error) -> CoreError {
        CoreError::Io(std::io::Error::other(format!("{call}: {}", err.message())))
    }

    /// Closes the handle when dropped.
    struct Owned(HANDLE);

    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful open call and is closed only here.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    fn ticks(time: FILETIME) -> u64 {
        (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
    }

    /// 100 ns ticks as a duration.
    fn duration(ticks: u64) -> Duration {
        Duration::from_nanos(ticks.saturating_mul(100))
    }

    pub fn host_totals() -> Result<HostTotals> {
        let mut status = MEMORYSTATUSEX {
            dwLength: u32::try_from(std::mem::size_of::<MEMORYSTATUSEX>()).unwrap_or(u32::MAX),
            ..Default::default()
        };
        // SAFETY: `status` is a live, writable MEMORYSTATUSEX whose dwLength is set, as the API requires.
        unsafe { GlobalMemoryStatusEx(&mut status) }.map_err(|e| os_error("GlobalMemoryStatusEx", e))?;
        // SAFETY: takes no pointers; ALL_PROCESSOR_GROUPS counts the processors of every group.
        let cpus = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
        Ok(HostTotals {
            physical_ram_mb: status.ullTotalPhys / (1024 * 1024),
            available_ram_mb: status.ullAvailPhys / (1024 * 1024),
            logical_cpus: cpus,
        })
    }

    pub fn system_cpu_times() -> Result<SystemCpuTimes> {
        let (mut idle, mut kernel, mut user) = (FILETIME::default(), FILETIME::default(), FILETIME::default());
        // SAFETY: the three out pointers point at live FILETIMEs.
        unsafe { GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)) }
            .map_err(|e| os_error("GetSystemTimes", e))?;
        // Kernel time includes idle time.
        Ok(SystemCpuTimes {
            idle: duration(ticks(idle)),
            total: duration(ticks(kernel).saturating_add(ticks(user))),
        })
    }

    pub fn own_cpu_time() -> Result<Duration> {
        // SAFETY: the pseudo handle needs no closing.
        let process = unsafe { GetCurrentProcess() };
        let (_, cpu) = process_times(process).map_err(|e| os_error("GetProcessTimes", e))?;
        Ok(duration(cpu))
    }

    /// Creation time and kernel plus user time, in 100 ns units.
    fn process_times(process: HANDLE) -> windows::core::Result<(u64, u64)> {
        let mut times = [FILETIME::default(); 4];
        let [created, exited, kernel, user] = &mut times;
        // SAFETY: `process` is open with query rights; the four out pointers point at live FILETIMEs.
        unsafe { GetProcessTimes(process, created, exited, kernel, user) }?;
        Ok((ticks(times[0]), ticks(times[2]).saturating_add(ticks(times[3]))))
    }

    pub fn disk_space(path: &Path) -> Result<DiskSpace> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let (mut total, mut free) = (0u64, 0u64);
        // SAFETY: `wide` is NUL-terminated and outlives the call; both out pointers point at live u64s.
        unsafe { GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), None, Some(&mut total), Some(&mut free)) }
            .map_err(|e| os_error("GetDiskFreeSpaceExW", e))?;
        Ok(DiskSpace {
            free_bytes: free,
            total_bytes: total,
        })
    }

    /// Process ids of every process whose executable is named `exe` (any letter case).
    pub fn pids_named(exe: &str) -> Result<Vec<u32>> {
        // SAFETY: takes no pointers; the snapshot handle is closed by `Owned`.
        let snapshot = Owned(
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
                .map_err(|e| os_error("CreateToolhelp32Snapshot", e))?,
        );
        let mut entry = PROCESSENTRY32W {
            dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(u32::MAX),
            ..Default::default()
        };
        let mut pids = Vec::new();
        // SAFETY: `entry` is a live PROCESSENTRY32W with dwSize set, as both calls require.
        let mut found = unsafe { Process32FirstW(snapshot.0, &mut entry) };
        while found.is_ok() {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            if String::from_utf16_lossy(&entry.szExeFile[..len]).eq_ignore_ascii_case(exe) {
                pids.push(entry.th32ProcessID);
            }
            // SAFETY: as above.
            found = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }
        Ok(pids)
    }

    /// Every running process named `exe`, read now. The command line is read only for processes the
    /// tracker has not seen. Processes that can't be opened (gone, or another user's) are left out.
    pub fn read_processes(exe: &str, tracker: &ProcessTracker) -> Result<Vec<RawProcess>> {
        Ok(pids_named(exe)?
            .into_iter()
            .filter_map(|pid| read_process(pid, |created| tracker.known_path(pid, created)))
            .collect())
    }

    /// One process's counters; `known_path` returns the .vmx path read earlier for the same process.
    pub fn read_process(pid: u32, known_path: impl FnOnce(u64) -> Option<Option<String>>) -> Option<RawProcess> {
        // SAFETY: takes no pointers; the handle is closed by `Owned`.
        let process = Owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?);
        let (created, cpu_time) = process_times(process.0).ok()?;
        let vmx_path =
            known_path(created).unwrap_or_else(|| command_line(process.0).and_then(|l| vmx_from_command_line(&l)));

        let mut memory = PROCESS_MEMORY_COUNTERS {
            cb: u32::try_from(std::mem::size_of::<PROCESS_MEMORY_COUNTERS>()).unwrap_or(u32::MAX),
            ..Default::default()
        };
        // SAFETY: `memory` is live and `cb` is its size.
        let working_set = unsafe { GetProcessMemoryInfo(process.0, &mut memory, memory.cb) }
            .ok()
            .map(|()| memory.WorkingSetSize as u64);
        let mut io = IO_COUNTERS::default();
        // SAFETY: `io` is a live IO_COUNTERS.
        let io = unsafe { GetProcessIoCounters(process.0, &mut io) }.ok().map(|()| io);
        Some(RawProcess {
            pid,
            created,
            vmx_path,
            cpu_time,
            working_set,
            read_bytes: io.map(|io| io.ReadTransferCount),
            write_bytes: io.map(|io| io.WriteTransferCount),
        })
    }

    /// The process's command line (Windows 8.1 and later; query rights are enough).
    fn command_line(process: HANDLE) -> Option<String> {
        // u64s, so the UNICODE_STRING at the start is aligned.
        let mut buffer = vec![0u64; 512];
        for _ in 0..3 {
            let size = u32::try_from(buffer.len() * 8).ok()?;
            let mut needed = 0u32;
            // SAFETY: the buffer is `size` bytes, writable and 8-byte aligned; `needed` is a live u32.
            let status = unsafe {
                NtQueryInformationProcess(
                    process,
                    ProcessCommandLineInformation,
                    buffer.as_mut_ptr().cast(),
                    size,
                    &mut needed,
                )
            };
            if status.is_ok() {
                // SAFETY: on success the buffer starts with a UNICODE_STRING whose Buffer points at
                // `Length` bytes inside the same buffer, which is still alive.
                let text = unsafe {
                    let header = &*buffer.as_ptr().cast::<UNICODE_STRING>();
                    if header.Buffer.is_null() {
                        return None;
                    }
                    std::slice::from_raw_parts(header.Buffer.0, usize::from(header.Length) / 2)
                };
                return Some(String::from_utf16_lossy(text));
            }
            let needed = usize::try_from(needed).ok()?;
            if needed <= buffer.len() * 8 {
                return None;
            }
            buffer = vec![0u64; needed.div_ceil(8) + 1];
        }
        None
    }
}

#[cfg(not(windows))]
mod win {
    use std::path::Path;
    use std::time::Duration;

    use super::{DiskSpace, HostTotals, ProcessTracker, RawProcess, SystemCpuTimes};
    use crate::error::{CoreError, Result};

    pub fn host_totals() -> Result<HostTotals> {
        Err(CoreError::NotImplemented("host totals outside Windows"))
    }

    pub fn system_cpu_times() -> Result<SystemCpuTimes> {
        Err(CoreError::NotImplemented("host CPU times outside Windows"))
    }

    pub fn own_cpu_time() -> Result<Duration> {
        Err(CoreError::NotImplemented("process CPU time outside Windows"))
    }

    pub fn disk_space(_path: &Path) -> Result<DiskSpace> {
        Err(CoreError::NotImplemented("free disk space outside Windows"))
    }

    pub fn read_processes(_exe: &str, _tracker: &ProcessTracker) -> Result<Vec<RawProcess>> {
        Err(CoreError::NotImplemented("VM processes outside Windows"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vmx_path_is_the_last_vmx_argument() {
        // The shape Workstation starts vmware-vmx.exe with.
        let line = r#""C:\Program Files\VMware\VMware Workstation\x64\vmware-vmx.exe" -s vmx.stdio.keep=TRUE -# "product=1;name=VMware Workstation;version=17.6.0;" -@ "pipe=\\.\pipe\vmx1234;msgs=ui" "D:\Labs\web 01\web 01.vmx""#;
        assert_eq!(
            vmx_from_command_line(line).as_deref(),
            Some(r"D:\Labs\web 01\web 01.vmx")
        );
        assert_eq!(
            vmx_from_command_line(r"vmware-vmx.exe C:\VMs\db\db.VMX").as_deref(),
            Some(r"C:\VMs\db\db.VMX"),
            "unquoted, any letter case"
        );
        assert_eq!(vmx_from_command_line(r#""vmware-vmx.exe" -s x=1"#), None);
    }

    #[test]
    fn command_lines_split_like_windows_programs_do() {
        assert_eq!(
            split_command_line(r#"a "b c" d\\"e f" g\"h "i""j" k\l"#),
            ["a", "b c", r"d\e f", r#"g"h"#, r#"i"j"#, r"k\l"]
        );
        assert_eq!(split_command_line(r#"  "" x "#), ["", "x"]);
    }

    fn raw(pid: u32, created: u64, cpu_time: u64, read: u64) -> RawProcess {
        RawProcess {
            pid,
            created,
            vmx_path: Some(format!(r"C:\VMs\vm{pid}\vm{pid}.vmx")),
            cpu_time,
            working_set: Some(512 << 20),
            read_bytes: Some(read),
            write_bytes: Some(0),
        }
    }

    #[test]
    fn rates_come_from_the_previous_reading_of_the_same_process() {
        let mut tracker = ProcessTracker::default();
        let start = Instant::now();
        let first = tracker.update(start, vec![raw(7, 1, 0, 0)], 4);
        assert_eq!(first[0].cpu_pct, None, "one reading has no rate");
        assert_eq!(first[0].read_bps, None);
        assert_eq!(tracker.known_path(7, 1), Some(Some(r"C:\VMs\vm7\vm7.vmx".into())));
        assert_eq!(tracker.known_path(7, 2), None, "a new process that reused the pid");

        // 5 s later: 10 s of CPU over 4 CPUs is 50% of the host; 50 MB read is 10 MB/s.
        let later = start + Duration::from_secs(5);
        let second = tracker.update(later, vec![raw(7, 1, 100_000_000, 50_000_000)], 4);
        assert_eq!(second[0].cpu_pct, Some(50.0));
        assert_eq!(second[0].read_bps, Some(10_000_000.0));
        assert_eq!(second[0].write_bps, Some(0.0));
        assert_eq!(second[0].working_set_bytes, Some(512 << 20));

        // The pid now belongs to another process: no rate against the old one.
        let third = tracker.update(later + Duration::from_secs(5), vec![raw(7, 9, 1, 1)], 4);
        assert_eq!(third[0].cpu_pct, None);
        // Gone processes are forgotten.
        tracker.update(later + Duration::from_secs(10), Vec::new(), 4);
        assert_eq!(tracker.known_path(7, 9), None);
    }

    #[test]
    fn host_cpu_share_comes_from_two_readings() {
        let earlier = SystemCpuTimes {
            idle: Duration::from_secs(30),
            total: Duration::from_secs(40),
        };
        let now = SystemCpuTimes {
            idle: Duration::from_secs(45),
            total: Duration::from_secs(60),
        };
        assert_eq!(now.busy_pct_since(&earlier), Some(25.0));
        assert_eq!(earlier.busy_pct_since(&now), None, "counters went back");
    }

    #[cfg(windows)]
    mod windows_host {
        use super::*;

        // Reads this machine's totals; touches no VM.
        #[tokio::test]
        async fn reads_host_ram_cpus_and_free_disk() {
            let counters = WindowsCounters::new();
            let totals = counters.host_totals().await.unwrap();
            assert!(totals.physical_ram_mb >= 512, "{totals:?}");
            assert!(totals.available_ram_mb <= totals.physical_ram_mb, "{totals:?}");
            assert!(totals.logical_cpus >= 1, "{totals:?}");

            let free = counters.free_disk_pct(&std::env::temp_dir()).await.unwrap();
            assert!((0.0..=100.0).contains(&free), "{free}");

            let missing = std::env::temp_dir().join(format!("remotely-missing-{}", uuid::Uuid::new_v4()));
            assert!(counters.free_disk_pct(&missing).await.is_err());

            let first = counters.system_cpu_times().await.unwrap();
            assert!(first.total >= first.idle);
            assert!(counters.own_cpu_time().await.unwrap() > Duration::ZERO);
        }

        // Lists whatever VMs run on this machine (none in CI); only reads.
        #[tokio::test]
        async fn lists_vm_processes_without_failing() {
            let counters = WindowsCounters::new();
            for process in counters.vm_processes().await.unwrap() {
                assert!(process.vmx_path.is_some(), "{process:?}");
            }
        }

        // This test's own process stands in for a VM: its command line is readable, and it has CPU
        // time and a working set.
        #[test]
        fn reads_a_process_command_line_and_counters() {
            let me = std::process::id();
            let read = win::read_process(me, |_| None).unwrap();
            assert_eq!(read.pid, me);
            assert!(read.working_set.unwrap() > 0);
            assert!(read.read_bytes.is_some());
            let exe = std::env::current_exe().unwrap();
            let name = exe.file_name().unwrap().to_string_lossy().into_owned();
            assert!(win::pids_named(&name).unwrap().contains(&me));
        }

        /// MO-01 NFR (a 50-VM dashboard at a 5 s refresh under 5% host CPU): reads 50 processes the
        /// way a round reads 50 VMs, with the command lines already known as after the first round, and
        /// measures this process's CPU time for it. Prints the cost per round (`--nocapture`).
        #[test]
        fn fifty_processes_cost_well_under_the_cpu_budget() {
            let pids: Vec<u32> = {
                let mut all = Vec::new();
                for name in ["svchost.exe", "RuntimeBroker.exe", "conhost.exe", "msedgewebview2.exe"] {
                    all.extend(win::pids_named(name).unwrap());
                }
                all.push(std::process::id());
                all
            };
            let readable: Vec<u32> = pids
                .into_iter()
                .filter(|pid| win::read_process(*pid, |_| None).is_some())
                .collect();
            assert!(!readable.is_empty());
            let fifty: Vec<u32> = readable.iter().copied().cycle().take(50).collect();

            let mut tracker = ProcessTracker::default();
            let rounds = 40u32;
            let before = win::own_cpu_time().unwrap();
            let wall = Instant::now();
            for _ in 0..rounds {
                // A round: one process list, then each VM process's counters.
                let _ = win::pids_named(VMX_PROCESS).unwrap();
                let raw: Vec<RawProcess> = fifty
                    .iter()
                    .filter_map(|&pid| win::read_process(pid, |created| tracker.known_path(pid, created)))
                    .collect();
                tracker.update(Instant::now(), raw, 8);
            }
            let cpu = win::own_cpu_time().unwrap() - before;
            let per_round = cpu / rounds;
            let cpus = win::host_totals().unwrap().logical_cpus;
            // At one round per 5 s, as a share of the whole host.
            let host_pct = per_round.as_secs_f64() / 5.0 / f64::from(cpus) * 100.0;
            println!(
                "MO-01 cost: {:.2} ms CPU per 50-process round ({:.2} ms wall), {:.4}% of this {cpus}-CPU host at a 5 s refresh",
                per_round.as_secs_f64() * 1000.0,
                wall.elapsed().as_secs_f64() * 1000.0 / f64::from(rounds),
                host_pct
            );
            // 5% of one CPU, far below the NFR's 5% of the whole host.
            assert!(per_round < Duration::from_millis(250), "{per_round:?} per round");
        }
    }
}
