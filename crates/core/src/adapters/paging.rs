//! MO-15: this PC's paging files and commit charge, for the dashboard's memory chart. Part of the host
//! counters adapter ([`super::host_counters::HostCounters::paging`]); reads only.
//!
//! Two cheap calls, made once per metrics round: `GlobalMemoryStatusEx` (the commit charge and its
//! limit: RAM plus paging files) and `NtQuerySystemInformation(SystemPageFileInformation)`, which lists
//! each paging file with its size, use and peak in pages (what Performance Monitor's
//! `\Paging File(_Total)\% Usage` counts), without the cost of a PDH query.

use serde::Serialize;

/// One paging file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PagingFile {
    /// E.g. `C:\pagefile.sys`.
    pub path: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub peak_bytes: u64,
}

/// This PC's paging files and commit charge.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PagingInfo {
    pub files: Vec<PagingFile>,
    /// All paging files together.
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub peak_bytes: u64,
    /// Memory Windows has promised to programs, and the most it can promise (RAM plus paging files).
    pub commit_used_bytes: u64,
    pub commit_limit_bytes: u64,
}

impl PagingInfo {
    /// Totals of `files`, with the commit charge.
    pub fn new(files: Vec<PagingFile>, commit_used_bytes: u64, commit_limit_bytes: u64) -> Self {
        Self {
            total_bytes: files.iter().map(|f| f.total_bytes).sum(),
            used_bytes: files.iter().map(|f| f.used_bytes).sum(),
            peak_bytes: files.iter().map(|f| f.peak_bytes).sum(),
            files,
            commit_used_bytes,
            commit_limit_bytes,
        }
    }
}

/// `\??\C:\pagefile.sys` as `C:\pagefile.sys`.
pub fn clean_path(name: &str) -> String {
    name.strip_prefix(r"\??\").unwrap_or(name).to_owned()
}

#[cfg(windows)]
pub use win::read;

#[cfg(not(windows))]
pub fn read() -> crate::error::Result<PagingInfo> {
    Err(crate::error::CoreError::NotImplemented("paging files outside Windows"))
}

#[cfg(windows)]
mod win {
    use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
    use windows::Win32::Foundation::UNICODE_STRING;
    use windows::Win32::System::SystemInformation::{GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO};

    use super::{clean_path, PagingFile, PagingInfo};
    use crate::error::{CoreError, Result};

    /// `SystemPageFileInformation`.
    const PAGE_FILE_INFORMATION: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(18);
    /// `STATUS_INFO_LENGTH_MISMATCH`: the buffer is too small.
    const LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;

    /// `SYSTEM_PAGEFILE_INFORMATION`, as ntdll fills it (sizes in pages).
    #[repr(C)]
    struct PageFileEntry {
        next_entry_offset: u32,
        total_size: u32,
        total_in_use: u32,
        peak_usage: u32,
        name: UNICODE_STRING,
    }

    fn os_error(call: &str, message: String) -> CoreError {
        CoreError::Io(std::io::Error::other(format!("{call}: {message}")))
    }

    pub fn read() -> Result<PagingInfo> {
        let mut status = MEMORYSTATUSEX {
            dwLength: u32::try_from(std::mem::size_of::<MEMORYSTATUSEX>()).unwrap_or(u32::MAX),
            ..Default::default()
        };
        // SAFETY: `status` is a live, writable MEMORYSTATUSEX whose dwLength is set, as the API requires.
        unsafe { GlobalMemoryStatusEx(&mut status) }.map_err(|e| os_error("GlobalMemoryStatusEx", e.message()))?;
        let mut system = SYSTEM_INFO::default();
        // SAFETY: `system` is a live, writable SYSTEM_INFO.
        unsafe { GetSystemInfo(&mut system) };
        let page = u64::from(system.dwPageSize.max(1));
        let files = page_files(page)?;
        Ok(PagingInfo::new(
            files,
            status.ullTotalPageFile.saturating_sub(status.ullAvailPageFile),
            status.ullTotalPageFile,
        ))
    }

    fn page_files(page: u64) -> Result<Vec<PagingFile>> {
        // u64s, so the entries (8-byte aligned) start aligned.
        let mut buffer = vec![0u64; 512];
        let mut returned = 0u32;
        for _ in 0..4 {
            let size = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
            // SAFETY: the buffer is `size` bytes, writable and 8-byte aligned; `returned` is a live u32.
            let status = unsafe {
                NtQuerySystemInformation(PAGE_FILE_INFORMATION, buffer.as_mut_ptr().cast(), size, &mut returned)
            };
            if status.0 == LENGTH_MISMATCH {
                let needed = usize::try_from(returned).unwrap_or(0).max(buffer.len() * 16);
                buffer = vec![0u64; needed.div_ceil(8) + 1];
                continue;
            }
            if status.is_err() {
                return Err(os_error("NtQuerySystemInformation", format!("status {:#x}", status.0)));
            }
            break;
        }
        let bytes = usize::try_from(returned).unwrap_or(0).min(buffer.len() * 8);
        let base = buffer.as_ptr().cast::<u8>();
        let entry_size = std::mem::size_of::<PageFileEntry>();
        let mut files = Vec::new();
        let mut offset = 0usize;
        // No paging file: nothing is returned.
        while offset + entry_size <= bytes {
            // SAFETY: `offset + entry_size` is inside the bytes the call filled, and every entry starts
            // 8-byte aligned (the kernel aligns NextEntryOffset), so this reads a whole, aligned entry.
            let entry = unsafe { &*base.add(offset).cast::<PageFileEntry>() };
            let name_len = usize::from(entry.name.Length) / 2;
            let name_ptr = entry.name.Buffer.0.cast_const();
            let start = base as usize;
            let end = start + bytes;
            let name_at = name_ptr as usize;
            let name = if !name_ptr.is_null() && name_at >= start && name_at + name_len * 2 <= end {
                // SAFETY: the name lies inside the filled buffer (checked above), which is still alive.
                String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(name_ptr, name_len) })
            } else {
                String::new()
            };
            files.push(PagingFile {
                path: clean_path(&name),
                total_bytes: u64::from(entry.total_size) * page,
                used_bytes: u64::from(entry.total_in_use) * page,
                peak_bytes: u64::from(entry.peak_usage) * page,
            });
            let next = usize::try_from(entry.next_entry_offset).unwrap_or(0);
            if next == 0 {
                break;
            }
            offset += next;
        }
        Ok(files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_add_up_each_paging_file() {
        let info = PagingInfo::new(
            vec![
                PagingFile {
                    path: clean_path(r"\??\C:\pagefile.sys"),
                    total_bytes: 8 << 30,
                    used_bytes: 1 << 30,
                    peak_bytes: 2 << 30,
                },
                PagingFile {
                    path: r"D:\pagefile.sys".into(),
                    total_bytes: 4 << 30,
                    used_bytes: 0,
                    peak_bytes: 0,
                },
            ],
            20 << 30,
            44 << 30,
        );
        assert_eq!(info.files[0].path, r"C:\pagefile.sys");
        assert_eq!(
            (info.total_bytes, info.used_bytes, info.peak_bytes),
            (12 << 30, 1 << 30, 2 << 30)
        );
        assert_eq!(info.commit_limit_bytes, 44 << 30);
    }

    /// MO-15: this PC's paging files, read the way each metrics round reads them, at no noticeable
    /// cost: well under a millisecond a read, so far below the round's 5 s.
    #[cfg(windows)]
    #[test]
    fn reading_this_pcs_paging_files_is_cheap() {
        let first = read().unwrap();
        assert!(first.commit_limit_bytes > 0);
        assert!(first.commit_used_bytes <= first.commit_limit_bytes);
        for file in &first.files {
            assert!(file.used_bytes <= file.total_bytes, "{file:?}");
            assert!(!file.path.is_empty());
        }
        let reads = 200u32;
        let started = std::time::Instant::now();
        for _ in 0..reads {
            std::hint::black_box(read().unwrap());
        }
        let each = started.elapsed() / reads;
        println!("MO-15 paging file read: {each:?} each");
        // Wall time (not this process's CPU time), so other tests running beside it don't skew it much.
        assert!(each < std::time::Duration::from_millis(5), "{each:?} a read");
    }
}
