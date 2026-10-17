//! Tauri shell: window, IPC commands and event forwarding. All logic lives in `remotely-core`; the UI
//! reaches it only through the commands in [`ipc`] and [`terminal`], never vmrun or SSH directly.

mod ipc;
mod terminal;

use std::sync::Arc;

use remotely_core::adapters::updater::DisabledUpdater;
use remotely_core::{Core, CoreConfig};
use tauri::{Emitter, Manager};
use tokio::sync::broadcast::error::RecvError;

pub struct AppState {
    pub core: Arc<Core>,
    pub terminals: terminal::Terminals,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn,tao=warn,wry=warn".into()),
        )
        .init();

    let result = tauri::Builder::default()
        .setup(|app| {
            // %LOCALAPPDATA%\com.remotely.desktop: app data never lives in the working directory, so
            // nothing private can land in the public repo (CLAUDE.md).
            let data_dir = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let config = CoreConfig {
                db_path: data_dir.join("remotely.db"),
                vmrun_path: None,
                account: windows_account(),
                display_name: std::env::var("USERNAME").unwrap_or_else(|_| "user".into()),
                // FD-14: replaced by the signed GitHub Releases updater once the repo exists.
                updater: Arc::new(DisabledUpdater),
            };
            tracing::info!("starting core");
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

            app.manage(AppState {
                core,
                terminals: terminal::Terminals::default(),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc::app_info,
            ipc::vm_list_running,
            ipc::vm_list,
            ipc::command_submit,
            ipc::command_approve,
            ipc::command_cancel_approval,
            ipc::job_cancel,
            ipc::jobs_recent,
            ipc::policy_rules,
            ipc::audit_recent,
            ipc::audit_verify,
            ipc::settings_get,
            ipc::settings_set_vmrun_path,
            terminal::terminal_open,
            terminal::terminal_write,
            terminal::terminal_resize,
            terminal::terminal_close,
        ])
        .run(tauri::generate_context!());

    if let Err(err) = result {
        tracing::error!(error = %err, "the app stopped with an error");
        std::process::exit(1);
    }
}

/// DOMAIN\user, which keys the local user record.
fn windows_account() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".into());
    match std::env::var("USERDOMAIN") {
        Ok(domain) if !domain.is_empty() => format!("{domain}\\{user}"),
        _ => user,
    }
}
