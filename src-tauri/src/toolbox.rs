//! FD-09: the Toolbox page's IPC. The logic is in `remotely_core::toolbox`; this is the IPC around it.
//!
//! * Ping, trace route, DNS, port checks and the certificate viewer only read: no tier, not audited, allowed by the
//!   read-only lock. Each run has an id the UI chose: what it finds comes as `toolbox://progress` events under it,
//!   and `toolbox_cancel` stops it.
//! * A certificate file is picked in a dialog opened here (Downloads by default); the core refuses a share or a
//!   device path before the file system sees it.
//! * Wake-on-LAN is a command on the bus (`command_submit` with a `wakeOnLan` command); `toolbox_wake_options` lists
//!   this PC's adapters and the MACs known for a session or VM.

use std::collections::HashMap;
use std::sync::Mutex;

use remotely_core::domain::TargetRef;
use remotely_core::toolbox::{
    CertRequest, CertificateReport, DnsRequest, DnsResult, KnownMac, PingRequest, PingSummary, PortRequest,
    PortSummary, ProbeProgress, TraceRequest, TraceSummary, WakeAdapter,
};
use remotely_core::CoreError;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The runs going on now, by the id the UI gave each.
#[derive(Default)]
pub struct ToolRuns(Mutex<HashMap<Uuid, CancellationToken>>);

impl ToolRuns {
    /// Stops every run: the page that started them reloaded, or another workspace opened. Returns how many.
    pub fn cancel_all(&self) -> usize {
        let Ok(map) = self.0.lock() else {
            return 0;
        };
        for token in map.values() {
            token.cancel();
        }
        map.len()
    }
}

/// A run's entry, taken out when the run ends.
struct Running<'a> {
    runs: &'a ToolRuns,
    id: Uuid,
    token: CancellationToken,
}

impl<'a> Running<'a> {
    fn start(runs: &'a ToolRuns, id: Uuid) -> Self {
        let token = CancellationToken::new();
        if let Ok(mut map) = runs.0.lock() {
            map.insert(id, token.clone());
        }
        Self { runs, id, token }
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        if let Ok(mut map) = self.runs.0.lock() {
            map.remove(&self.id);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressEvent {
    run: Uuid,
    progress: ProbeProgress,
}

fn emitter(app: AppHandle, run: Uuid) -> impl Fn(ProbeProgress) + Send + Sync {
    move |progress| {
        let _ = app.emit("toolbox://progress", ProgressEvent { run, progress });
    }
}

/// Ping from this PC. A read.
#[tauri::command]
pub async fn toolbox_ping(
    app: AppHandle,
    state: State<'_, AppState>,
    runs: State<'_, ToolRuns>,
    run: Uuid,
    request: PingRequest,
) -> IpcResult<PingSummary> {
    let core = &state.core;
    let running = Running::start(&runs, run);
    let progress = emitter(app, run);
    Ok(core
        .toolbox
        .ping(&core.ctx(), &request, &running.token, &progress)
        .await?)
}

/// Trace route from this PC. A read.
#[tauri::command]
pub async fn toolbox_trace(
    app: AppHandle,
    state: State<'_, AppState>,
    runs: State<'_, ToolRuns>,
    run: Uuid,
    request: TraceRequest,
) -> IpcResult<TraceSummary> {
    let core = &state.core;
    let running = Running::start(&runs, run);
    let progress = emitter(app, run);
    Ok(core
        .toolbox
        .trace(&core.ctx(), &request, &running.token, &progress)
        .await?)
}

/// A DNS lookup. A read.
#[tauri::command]
pub async fn toolbox_dns(
    state: State<'_, AppState>,
    runs: State<'_, ToolRuns>,
    run: Uuid,
    request: DnsRequest,
) -> IpcResult<DnsResult> {
    let running = Running::start(&runs, run);
    Ok(state.core.toolbox.dns(&request, &running.token).await?)
}

/// A port check, through the session's jump host when it has one. A read.
#[tauri::command]
pub async fn toolbox_ports(
    app: AppHandle,
    state: State<'_, AppState>,
    runs: State<'_, ToolRuns>,
    run: Uuid,
    request: PortRequest,
) -> IpcResult<PortSummary> {
    let core = &state.core;
    let running = Running::start(&runs, run);
    let progress = emitter(app, run);
    Ok(core
        .toolbox
        .ports(&core.ctx(), &request, &running.token, &progress)
        .await?)
}

/// The certificate a TLS server presents, checked. A read.
#[tauri::command]
pub async fn toolbox_certificate(
    state: State<'_, AppState>,
    runs: State<'_, ToolRuns>,
    run: Uuid,
    request: CertRequest,
) -> IpcResult<CertificateReport> {
    let core = &state.core;
    let running = Running::start(&runs, run);
    Ok(core.toolbox.certificate(&core.ctx(), &request, &running.token).await?)
}

/// Asks for a certificate file and reads it. `None` when the dialog was closed. A read.
#[tauri::command]
pub async fn toolbox_certificate_file(
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> IpcResult<Option<CertificateReport>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Choose a certificate file")
        .add_filter("Certificates", &["crt", "cer", "pem", "der"]);
    if let Ok(downloads) = window.path().download_dir() {
        dialog = dialog.set_directory(downloads);
    }
    dialog.pick_file(move |path| {
        let _ = tx.send(path);
    });
    let Some(chosen) = rx.await.ok().flatten() else {
        return Ok(None);
    };
    let path = chosen
        .into_path()
        .map_err(|err| CoreError::InvalidInput(format!("can't use that file: {err}")))?;
    Ok(Some(state.core.toolbox.certificate_file(&path).await?))
}

/// Stops the run `run`. False when it wasn't running.
#[tauri::command]
pub fn toolbox_cancel(runs: State<'_, ToolRuns>, run: Uuid) -> bool {
    let token = runs.0.lock().ok().and_then(|map| map.get(&run).cloned());
    match token {
        Some(token) => {
            token.cancel();
            true
        }
        None => false,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeOptions {
    adapters: Vec<WakeAdapter>,
    macs: Vec<KnownMac>,
}

/// This PC's adapters a magic packet can leave from, and the MACs known for `target`. A read.
#[tauri::command]
pub async fn toolbox_wake_options(state: State<'_, AppState>, target: Option<TargetRef>) -> IpcResult<WakeOptions> {
    let core = &state.core;
    let (adapters, macs) = core.toolbox.wake_options(&core.ctx(), target.as_ref()).await?;
    Ok(WakeOptions { adapters, macs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_all_stops_every_run_and_a_finished_run_leaves_the_list() {
        let runs = ToolRuns::default();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let first = Running::start(&runs, a);
        let second = Running::start(&runs, b);
        assert_eq!(runs.cancel_all(), 2);
        assert!(first.token.is_cancelled() && second.token.is_cancelled());
        drop(first);
        drop(second);
        assert_eq!(runs.cancel_all(), 0, "ended runs are gone");
    }
}
