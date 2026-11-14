//! VM-30 (0.8.0 G7): golden image builds, for the Templates page's Images tab. The logic is in
//! `remotely_core::golden`; this is the IPC around it. A build or a rebuild is a command on the bus (Medium; Critical
//! while the image keeps only its newest versions), approved in the approval dialog like a deploy; the build settings
//! are the catalogue's own data (audited, refused by the read-only lock). Every call works in the shown workspace.

use remotely_core::catalog::Image;
use remotely_core::command_bus::SubmitOutcome;
use remotely_core::golden::{BuildCheck, BuildRecipe, BuildRequest, ImageVersion};
use tauri::State;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The build dialog's check while it is filled in: why it can't build, or what it would build. A read.
#[tauri::command]
pub async fn golden_build_check(state: State<'_, AppState>, request: BuildRequest) -> IpcResult<BuildCheck> {
    let core = &state.core;
    Ok(core.golden.check(&core.ctx(), &request).await?)
}

/// Submits a build of a new image or of an image's next version: approval, then one job.
#[tauri::command]
pub async fn golden_build_submit(state: State<'_, AppState>, request: BuildRequest) -> IpcResult<SubmitOutcome> {
    let core = &state.core;
    Ok(core.golden.submit(&core.ctx(), &request).await?)
}

/// "Rebuild": the image's next version from its build settings as they are saved.
#[tauri::command]
pub async fn golden_rebuild(state: State<'_, AppState>, image_id: Uuid) -> IpcResult<SubmitOutcome> {
    let core = &state.core;
    Ok(core.golden.rebuild(&core.ctx(), image_id).await?)
}

/// What a rebuild would send, for the build settings dialog (its image's recipe as saved).
#[tauri::command]
pub async fn golden_rebuild_request(state: State<'_, AppState>, image_id: Uuid) -> IpcResult<BuildRequest> {
    let core = &state.core;
    Ok(core.golden.rebuild_request(&core.ctx(), image_id).await?)
}

/// The image's build settings, saved (checked as a build of its next version would be). Audited.
#[tauri::command]
pub async fn golden_set_recipe(state: State<'_, AppState>, image_id: Uuid, recipe: BuildRecipe) -> IpcResult<Image> {
    let core = &state.core;
    Ok(core.golden.set_recipe(&core.ctx(), image_id, recipe).await?)
}

/// The image's versions, newest first, each with the linked clones made from it (read now).
#[tauri::command]
pub async fn golden_versions(state: State<'_, AppState>, image_id: Uuid) -> IpcResult<Vec<ImageVersion>> {
    let core = &state.core;
    Ok(core.golden.versions(&core.ctx(), image_id).await?)
}
