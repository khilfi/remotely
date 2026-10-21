//! CT-01, CT-02: the Containers page. Hosts and their marks, reads (each one call to the core, which
//! keeps a host's SSH connection for the next read), and "Open a shell" in a container: a terminal pane,
//! forwarded like any other. Changes are commands on the bus through `command_submit`.

use remotely_core::adapters::containers::{
    ContainerDetails, ContainerId, ContainerStats, EngineKind, EngineVersion, ImageSummary, LogQuery, Logs,
    NetworkSummary, VolumeSummary,
};
use remotely_core::adapters::remote::PtySize;
use remotely_core::containers::{ContainerHostInfo, ContainerList, ContainerMark, Detection, MarkInput};
use remotely_core::domain::ContainerHost;
use remotely_core::terminal::TerminalEvent;
use remotely_core::vault::SecretId;
use serde::Serialize;
use std::sync::Arc;
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::State;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The marked sessions, then this PC when Docker Desktop's CLI is there. No connection is made.
#[tauri::command]
pub async fn containers_hosts(state: State<'_, AppState>) -> IpcResult<Vec<ContainerHostInfo>> {
    let core = &state.core;
    Ok(core.containers.hosts(&core.ctx).await?)
}

#[tauri::command]
pub async fn containers_marks(state: State<'_, AppState>, session_id: Uuid) -> IpcResult<Vec<ContainerMark>> {
    let core = &state.core;
    Ok(core.containers.marks().list(&core.ctx, Some(session_id)).await?)
}

/// Replaces a session's engines (an empty list: no container host any more). Audited.
#[tauri::command]
pub async fn containers_set_marks(
    state: State<'_, AppState>,
    session_id: Uuid,
    marks: Vec<MarkInput>,
) -> IpcResult<Vec<ContainerMark>> {
    let core = &state.core;
    let saved = core.containers.marks().set(&core.ctx, session_id, &marks).await?;
    // How the engines run may have changed: the next read connects afresh.
    core.containers.release(session_id).await;
    Ok(saved)
}

/// Which CLIs the session's host has, and whether they need sudo. A read: nothing is marked.
#[tauri::command]
pub async fn containers_detect(
    state: State<'_, AppState>,
    session_id: Uuid,
    sudo_password_id: Option<SecretId>,
) -> IpcResult<Detection> {
    let core = &state.core;
    Ok(core.containers.detect(&core.ctx, session_id, sudo_password_id).await?)
}

#[tauri::command]
pub async fn containers_version(
    state: State<'_, AppState>,
    host: ContainerHost,
    engine: EngineKind,
) -> IpcResult<EngineVersion> {
    let core = &state.core;
    Ok(core.containers.version(&core.ctx, host, engine).await?)
}

#[tauri::command]
pub async fn containers_list(
    state: State<'_, AppState>,
    host: ContainerHost,
    engine: EngineKind,
) -> IpcResult<ContainerList> {
    let core = &state.core;
    Ok(core.containers.containers(&core.ctx, host, engine).await?)
}

#[tauri::command]
pub async fn containers_stats(
    state: State<'_, AppState>,
    host: ContainerHost,
    engine: EngineKind,
) -> IpcResult<Vec<ContainerStats>> {
    let core = &state.core;
    Ok(core.containers.stats(&core.ctx, host, engine).await?)
}

#[tauri::command]
pub async fn containers_details(
    state: State<'_, AppState>,
    host: ContainerHost,
    engine: EngineKind,
    id: ContainerId,
) -> IpcResult<ContainerDetails> {
    let core = &state.core;
    Ok(core.containers.details(&core.ctx, host, engine, &id).await?)
}

#[tauri::command]
pub async fn containers_logs(
    state: State<'_, AppState>,
    host: ContainerHost,
    engine: EngineKind,
    id: ContainerId,
    query: LogQuery,
) -> IpcResult<Logs> {
    let core = &state.core;
    Ok(core.containers.logs(&core.ctx, host, engine, &id, &query).await?)
}

#[tauri::command]
pub async fn containers_images(
    state: State<'_, AppState>,
    host: ContainerHost,
    engine: EngineKind,
) -> IpcResult<Vec<ImageSummary>> {
    let core = &state.core;
    Ok(core.containers.images(&core.ctx, host, engine).await?)
}

#[tauri::command]
pub async fn containers_volumes(
    state: State<'_, AppState>,
    host: ContainerHost,
    engine: EngineKind,
) -> IpcResult<Vec<VolumeSummary>> {
    let core = &state.core;
    Ok(core.containers.volumes(&core.ctx, host, engine).await?)
}

#[tauri::command]
pub async fn containers_networks(
    state: State<'_, AppState>,
    host: ContainerHost,
    engine: EngineKind,
) -> IpcResult<Vec<NetworkSummary>> {
    let core = &state.core;
    Ok(core.containers.networks(&core.ctx, host, engine).await?)
}

/// Closes a host's kept connection (the page went away from it).
#[tauri::command]
pub async fn containers_release(state: State<'_, AppState>, session_id: Uuid) -> IpcResult<()> {
    state.core.containers.release(session_id).await;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerShellOpened {
    id: Uuid,
    /// The tab's title: the container and its host.
    title: String,
}

/// "Open a shell": a terminal pane to the session that enters the running container (`docker exec -it`,
/// or podman). Audited like opening a terminal, naming the container.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn container_shell_open(
    state: State<'_, AppState>,
    session_id: Uuid,
    engine: EngineKind,
    container_id: ContainerId,
    cols: u16,
    rows: u16,
    on_output: Channel<InvokeResponseBody>,
    on_event: Channel<TerminalEvent>,
) -> IpcResult<ContainerShellOpened> {
    let core = &state.core;
    let shell = core
        .containers
        .shell(&core.ctx, session_id, engine, &container_id)
        .await?;
    let title = shell.title.clone();
    let handle = core
        .terminals
        .open_container_shell(&core.ctx, session_id, shell, PtySize { cols, rows })
        .await?;
    let id = crate::terminal::forward(Arc::clone(core), handle, on_output, on_event);
    Ok(ContainerShellOpened { id, title })
}
