//! Tauri shell: window, IPC commands and event forwarding. All logic lives in `remotely-core`; the UI
//! reaches it only through the commands in [`ipc`], [`terminal`], [`multiexec`], [`command_panel`],
//! [`files`] and [`clipboard`], never vmrun or SSH directly.

mod clipboard;
mod command_panel;
mod files;
mod ipc;
mod multiexec;
mod terminal;
mod tunnels;
pub mod updater;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use remotely_core::adapters::updater::{DisabledUpdater, UpdaterAdapter};
use remotely_core::{Core, CoreConfig};
use tauri::utils::config::AppDirectoriesOverride;
use tauri::{DragDropEvent, Emitter, Manager, WindowEvent};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;

pub struct AppState {
    pub core: Arc<Core>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn,tao=warn,wry=warn".into()),
        )
        .init();

    let mut context = tauri::generate_context!();
    match app_directories_override(
        std::env::var_os("REMOTELY_DATA_DIR"),
        &context.config().identifier,
        cfg!(debug_assertions),
    ) {
        Ok(Some(dirs)) => context.config_mut().app.app_directories_override = Some(dirs),
        Ok(None) => {}
        Err(err) => {
            tracing::error!(error = err, "the app can't choose its data folder");
            std::process::exit(1);
        }
    }

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        // AP-05: the audit export's save dialog, opened from Rust (no dialog permission for the UI).
        .plugin(tauri_plugin_dialog::init())
        // QL-07: notifications, shown from Rust (no notification permission for the UI).
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            // %LOCALAPPDATA%\com.remotely.desktop, its `.dev` sibling for a debug build, or
            // REMOTELY_DATA_DIR (see `app_directories_override`). Never the working directory, so nothing
            // private can land in the public repo (CLAUDE.md).
            let data_dir = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            // FD-14: signed updates from the private repo's GitHub Releases, with the token from the vault.
            let updater: Arc<dyn UpdaterAdapter> = match updater::TauriUpdater::new(app.handle().clone()) {
                Ok(updater) => Arc::new(updater),
                Err(err) => {
                    tracing::error!(error = %err, "update checks are unavailable");
                    Arc::new(DisabledUpdater)
                }
            };
            let config = CoreConfig {
                db_path: data_dir.join("remotely.db"),
                vmrun_path: None,
                account: windows_account(),
                display_name: std::env::var("USERNAME").unwrap_or_else(|_| "user".into()),
                updater,
            };
            tracing::info!(data_dir = %data_dir.display(), "starting core");
            let core = Arc::new(tauri::async_runtime::block_on(Core::init(config))?);

            // Job progress -> UI.
            let mut job_events = core.jobs.subscribe();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    match job_events.recv().await {
                        Ok(event) => {
                            let _ = handle.emit("job://event", &event);
                        }
                        Err(RecvError::Lagged(missed)) => tracing::warn!(missed, "UI missed job events"),
                        Err(RecvError::Closed) => break,
                    }
                }
            });

            // SS-04: vault status -> UI, so the idle lock shows at once.
            let mut vault_status = core.vault.watch();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                while vault_status.changed().await.is_ok() {
                    let status = *vault_status.borrow_and_update();
                    let _ = handle.emit("vault://status", status);
                }
            });

            // MO-01 to MO-04: host-side and guest metrics every 5 s; each round's cost -> UI, which then
            // reads what it shows.
            let metrics = Arc::clone(&core.metrics);
            tauri::async_runtime::spawn(async move { metrics.run(CancellationToken::new()).await });
            let mut rounds = core.metrics.subscribe();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    match rounds.recv().await {
                        Ok(cost) => {
                            let _ = handle.emit("metrics://round", &cost);
                        }
                        Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => break,
                    }
                }
            });

            // SS-10: MultiExec lines that finished, and lines held while waiting keys were sent -> UI.
            let mut lines = core.multiexec.subscribe();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    match lines.recv().await {
                        Ok(event) => {
                            let _ = handle.emit("multiexec://event", &event);
                        }
                        Err(RecvError::Lagged(missed)) => tracing::warn!(missed, "UI missed MultiExec events"),
                        Err(RecvError::Closed) => break,
                    }
                }
            });

            // SS-08: file transfers (queued, progress, done) -> UI.
            let mut transfers = core.terminals.subscribe_transfers();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    match transfers.recv().await {
                        Ok(transfer) => {
                            let _ = handle.emit("files://transfer", &transfer);
                        }
                        Err(RecvError::Lagged(missed)) => tracing::warn!(missed, "UI missed transfer events"),
                        Err(RecvError::Closed) => break,
                    }
                }
            });

            // QL-04: reachability checks of the sessions the Terminal page's tree shows -> UI.
            let reachability = Arc::clone(&core.reachability);
            tauri::async_runtime::spawn(async move { reachability.run(CancellationToken::new()).await });
            let mut reach = core.reachability.subscribe();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    match reach.recv().await {
                        Ok(update) => {
                            let _ = handle.emit("reachability://update", &update);
                        }
                        Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => break,
                    }
                }
            });

            app.manage(AppState { core });
            Ok(())
        })
        // SS-08: files dropped on the window are staged in Rust; the UI only learns where they fell.
        .on_window_event(|window, event| {
            if let WindowEvent::DragDrop(DragDropEvent::Drop { paths, position }) = event {
                if !paths.is_empty() {
                    files::dropped(window, paths, *position);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            ipc::app_info,
            ipc::vm_refresh,
            ipc::vm_list,
            ipc::tags_list,
            ipc::vm_tag,
            ipc::vm_untag,
            ipc::vm_set_environment,
            ipc::tag_delete,
            ipc::filters_list,
            ipc::filter_save,
            ipc::filter_delete,
            ipc::command_submit,
            ipc::command_approve,
            ipc::command_cancel_approval,
            ipc::job_cancel,
            ipc::jobs_recent,
            ipc::job_targets,
            ipc::snapshots_list,
            ipc::snapshot_limits,
            ipc::policy_rules,
            ipc::policy_catalog,
            ipc::policy_set_rules,
            ipc::audit_recent,
            ipc::audit_verify,
            ipc::audit_export_csv,
            ipc::settings_get,
            ipc::settings_set_vmrun_path,
            ipc::settings_set_scan_folders,
            ipc::settings_set_power_on_limit,
            ipc::settings_set_shutdown_wait,
            ipc::settings_set_update_checks,
            ipc::settings_set_bulk_parallel,
            ipc::presentation_get,
            ipc::presentation_set,
            ipc::update_check,
            ipc::update_token_set,
            ipc::update_token_test,
            ipc::update_token_remove,
            ipc::vault_info,
            ipc::vault_setup,
            ipc::vault_unlock,
            ipc::vault_lock,
            ipc::vault_change_password,
            ipc::vault_set_windows_login,
            ipc::secrets_list,
            ipc::secret_add,
            ipc::secret_import_key,
            ipc::secret_replace,
            ipc::secret_rename,
            ipc::secret_delete,
            ipc::sessions_list,
            ipc::session_folders,
            ipc::session_create,
            ipc::session_update,
            ipc::session_duplicate,
            ipc::session_delete,
            ipc::session_link_vm,
            ipc::session_confirm_vm_link,
            ipc::vm_links_ambiguous,
            ipc::sessions_move,
            ipc::folder_create,
            ipc::folder_rename,
            ipc::folder_move,
            ipc::folder_delete,
            ipc::import_preview,
            ipc::import_guide,
            ipc::import_save_sample,
            ipc::import_commit,
            ipc::transfer_export,
            ipc::transfer_choose,
            ipc::transfer_open,
            ipc::transfer_refresh,
            ipc::transfer_close,
            ipc::transfer_commit,
            ipc::ssh_keys_list,
            ipc::ssh_key_generate,
            ipc::ssh_key_public,
            ipc::ssh_key_attach,
            ipc::ssh_public_key_parse,
            ipc::bulk_limits,
            ipc::bulk_targets,
            ipc::bulk_preview,
            ipc::bulk_runs,
            ipc::bulk_results,
            ipc::bulk_host_output,
            ipc::bulk_diff,
            ipc::bulk_retry_failed,
            ipc::bulk_export,
            ipc::command_preview,
            ipc::metrics_overview,
            ipc::metrics_series,
            ipc::metrics_host_usage,
            ipc::metrics_capacity,
            ipc::metrics_watch,
            terminal::terminal_open,
            terminal::terminal_quick_connect,
            terminal::terminal_open_like,
            terminal::terminal_write,
            terminal::terminal_resize,
            terminal::terminal_reconnect,
            terminal::terminal_close,
            terminal::terminal_host_key_answer,
            terminal::terminal_host_key_replace,
            terminal::terminal_settings,
            terminal::terminal_set_settings,
            terminal::known_hosts_list,
            terminal::known_host_remove,
            terminal::quick_connect_history,
            terminal::quick_connect_forget,
            terminal::sessions_recent,
            terminal::session_tree,
            terminal::reachability_watch,
            terminal::terminal_output_text,
            terminal::terminal_output_print,
            terminal::terminal_output_save,
            terminal::terminal_log_start,
            terminal::terminal_log_stop,
            tunnels::forwards_list,
            tunnels::forwards_all,
            tunnels::forwards_save,
            tunnels::terminal_tunnels,
            tunnels::terminal_tunnel_start,
            tunnels::terminal_tunnel_request,
            tunnels::terminal_tunnel_approve,
            tunnels::terminal_tunnel_decline,
            tunnels::terminal_tunnel_stop,
            multiexec::multiexec_set_targets,
            multiexec::multiexec_stop,
            multiexec::multiexec_status,
            multiexec::multiexec_input,
            multiexec::multiexec_approve,
            multiexec::multiexec_cancel,
            command_panel::favourites_list,
            command_panel::favourite_add,
            command_panel::favourite_update,
            command_panel::favourite_delete,
            command_panel::favourites_reorder,
            command_panel::command_library,
            command_panel::command_inspect,
            command_panel::command_fill,
            command_panel::terminal_type_secret,
            command_panel::notify_command_finished,
            clipboard::clipboard_read_text,
            files::files_folder,
            files::files_list,
            files::files_back,
            files::files_look_up,
            files::files_pick_upload,
            files::files_upload,
            files::files_unstage,
            files::files_download,
            files::files_transfers,
            files::files_cancel,
            files::files_retry,
            files::files_open_folder,
        ])
        .build(context);

    let app = match result {
        Ok(app) => app,
        Err(err) => {
            tracing::error!(error = %err, "the app stopped with an error");
            std::process::exit(1);
        }
    };
    app.run(|handle, event| {
        // SS-03: terminals still open are closed (and their closing audited) before the app exits.
        if let tauri::RunEvent::Exit = event {
            if let Some(state) = handle.try_state::<AppState>() {
                tauri::async_runtime::block_on(state.core.terminals.close_all());
            }
        }
    });
}

/// DOMAIN\user, which keys the local user record.
fn windows_account() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".into());
    match std::env::var("USERDOMAIN") {
        Ok(domain) if !domain.is_empty() => format!("{domain}\\{user}"),
        _ => user,
    }
}

/// Moves Tauri's app directories (the database and WebView2's profile) for this build.
///
/// A debug build (`npm run tauri dev`) uses `%LOCALAPPDATA%\com.remotely.desktop.dev`. Otherwise it would share the
/// installed app's folder: a migration it adds would reach the installed app's database, which the older release then
/// refuses to open, and its window would join the installed app's WebView2 browser process, which ignores
/// `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`. A release build keeps Tauri's default, `%LOCALAPPDATA%\com.remotely.desktop`.
/// `REMOTELY_DATA_DIR` overrides both. It must be absolute: Tauri resolves a relative override next to the executable,
/// which for a dev build is inside the working directory.
fn app_directories_override(
    data_dir: Option<OsString>,
    identifier: &str,
    debug_build: bool,
) -> Result<Option<AppDirectoriesOverride>, &'static str> {
    match data_dir.filter(|dir| !dir.is_empty()).map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => Ok(Some(AppDirectoriesOverride::Root(dir))),
        Some(_) => Err("REMOTELY_DATA_DIR must be an absolute path outside the repository"),
        None if debug_build => Ok(Some(AppDirectoriesOverride::Root(
            Path::new("$LOCALDATA").join(format!("{identifier}.dev")),
        ))),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTIFIER: &str = "com.remotely.desktop";

    #[test]
    fn release_build_keeps_the_default_folder() {
        assert_eq!(app_directories_override(None, IDENTIFIER, false), Ok(None));
    }

    #[test]
    fn debug_build_uses_a_dev_folder_next_to_it() {
        assert_eq!(
            app_directories_override(None, IDENTIFIER, true),
            Ok(Some(AppDirectoriesOverride::Root(
                Path::new("$LOCALDATA").join("com.remotely.desktop.dev")
            )))
        );
    }

    #[test]
    fn remotely_data_dir_overrides_both_builds() {
        let dir = std::env::temp_dir().join("remotely-data");
        for debug_build in [false, true] {
            assert_eq!(
                app_directories_override(Some(dir.clone().into()), IDENTIFIER, debug_build),
                Ok(Some(AppDirectoriesOverride::Root(dir.clone())))
            );
        }
    }

    #[test]
    fn empty_remotely_data_dir_counts_as_unset() {
        assert_eq!(
            app_directories_override(Some(OsString::new()), IDENTIFIER, false),
            Ok(None)
        );
        assert_eq!(
            app_directories_override(Some(OsString::new()), IDENTIFIER, true),
            app_directories_override(None, IDENTIFIER, true)
        );
    }

    #[test]
    fn relative_remotely_data_dir_is_refused() {
        assert!(app_directories_override(Some("data".into()), IDENTIFIER, true).is_err());
        assert!(app_directories_override(Some("data".into()), IDENTIFIER, false).is_err());
    }
}
