//! Tauri shell: window, IPC commands and event forwarding. All logic lives in `remotely-core`; the UI
//! reaches it only through the commands in [`ipc`] and [`terminal`], never vmrun or SSH directly.

mod ipc;
mod terminal;
mod updater;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use remotely_core::{Core, CoreConfig};
use tauri::utils::config::AppDirectoriesOverride;
use tauri::{Emitter, Manager};
use tokio::sync::broadcast::error::RecvError;

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
        .setup(|app| {
            // %LOCALAPPDATA%\com.remotely.desktop, its `.dev` sibling for a debug build, or
            // REMOTELY_DATA_DIR (see `app_directories_override`). Never the working directory, so nothing
            // private can land in the public repo (CLAUDE.md).
            let data_dir = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let config = CoreConfig {
                db_path: data_dir.join("remotely.db"),
                vmrun_path: None,
                account: windows_account(),
                display_name: std::env::var("USERNAME").unwrap_or_else(|_| "user".into()),
                // FD-14: signed updates from the public repo's GitHub Releases.
                updater: Arc::new(updater::TauriUpdater::new(app.handle().clone())),
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

            app.manage(AppState { core });
            Ok(())
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
            ipc::update_check,
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
            ipc::sessions_move,
            ipc::folder_create,
            ipc::folder_rename,
            ipc::folder_move,
            ipc::folder_delete,
            ipc::import_preview,
            ipc::import_commit,
            terminal::terminal_open,
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
