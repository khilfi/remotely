//! R4's commands: VM-25 a VM's Log and Timeline tabs, VM-11 the host networks view, VM-16 and VM-14 the waste
//! finder. All are reads (no approval, not audited, allowed by the read-only lock); adding or removing a port
//! forward is a `hostNetwork` command the UI submits to the bus like any other. Open folder shows Explorer at a
//! folder the core names (a known VM's, or one the last waste report listed), never a path from the UI as it is.

use remotely_core::host_networks::HostNetworksReport;
use remotely_core::vm_insight::{LogChunk, LogListing, TimelinePage};
use remotely_core::waste::{WasteOptions, WasteReport};
use remotely_core::CoreError;
use tauri::State;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

fn check_key(vmx_path: &str) -> Result<(), CoreError> {
    if vmx_path.is_empty() || vmx_path.len() > 1024 {
        return Err(CoreError::InvalidInput("Choose a VM.".into()));
    }
    Ok(())
}

/// VM-25: the VM's log files, current first.
#[tauri::command]
pub async fn vm_logs(state: State<'_, AppState>, vmx_path: String) -> IpcResult<LogListing> {
    check_key(&vmx_path)?;
    Ok(state.core.insight.logs(&vmx_path).await?)
}

/// VM-25: part of one of the VM's logs, by a name its listing gave: its tail, or what was added after `from`.
#[tauri::command]
pub async fn vm_log_read(
    state: State<'_, AppState>,
    vmx_path: String,
    file: String,
    from: Option<u64>,
    tail: Option<u64>,
) -> IpcResult<LogChunk> {
    check_key(&vmx_path)?;
    if file.is_empty() || file.len() > 64 {
        return Err(CoreError::InvalidInput("Choose one of the VM's log files.".into()).into());
    }
    Ok(state.core.insight.read_log(&vmx_path, &file, from, tail).await?)
}

/// VM-25: what Remotely did to the VM, newest first, a page at a time.
#[tauri::command]
pub async fn vm_timeline(
    state: State<'_, AppState>,
    vmx_path: String,
    before: Option<i64>,
    limit: Option<u32>,
) -> IpcResult<TimelinePage> {
    check_key(&vmx_path)?;
    Ok(state.core.insight.timeline(&vmx_path, before, limit).await?)
}

/// VM-11: both hypervisors' host networks, the VMs on each and their NAT port forwards, read now.
#[tauri::command]
pub async fn host_networks(state: State<'_, AppState>) -> IpcResult<HostNetworksReport> {
    let core = &state.core;
    Ok(core.networks.report(&core.ctx()).await?)
}

/// VM-11, QL-21: the host networks alone, without VMs or forwards: the topology map's network nodes.
#[tauri::command]
pub async fn host_network_list(state: State<'_, AppState>) -> IpcResult<HostNetworksReport> {
    Ok(state.core.networks.networks_only().await)
}

/// VM-16, VM-14: the waste finder's report, read now.
#[tauri::command]
pub async fn waste_report(state: State<'_, AppState>, options: Option<WasteOptions>) -> IpcResult<WasteReport> {
    Ok(state.core.waste.report(options.unwrap_or_default()).await?)
}

/// VM-16: Explorer at a known VM's folder (`vmx_path`) or a folder the last waste report listed (`folder`).
#[tauri::command]
pub async fn waste_open_folder(
    state: State<'_, AppState>,
    folder: Option<String>,
    vmx_path: Option<String>,
) -> IpcResult<()> {
    let path = state
        .core
        .waste
        .folder_to_open(folder.as_deref(), vmx_path.as_deref())
        .await?;
    open(&path)
}

#[cfg(windows)]
fn open(path: &std::path::Path) -> IpcResult<()> {
    use std::os::windows::process::CommandExt;
    // Explorer reads the folder from its one argument; Rust's own quoting would wrap it again.
    std::process::Command::new("explorer.exe")
        .raw_arg(format!("\"{}\"", path.display()))
        .spawn()
        .map(drop)
        .map_err(|err| IpcError::new("io", format!("Explorer did not open: {err}")))
}

#[cfg(not(windows))]
fn open(_path: &std::path::Path) -> IpcResult<()> {
    Err(IpcError::new("unsupported", "Opening a folder needs Windows."))
}
