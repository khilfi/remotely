//! Tauri shell: window, IPC commands and event forwarding. All logic lives in `remotely-core`; the UI
//! reaches it only through the commands in [`ipc`], [`terminal`], [`multiexec`], [`command_panel`], [`navigation`],
//! [`files`], [`clipboard`] and [`dashboard`], never vmrun or SSH directly.

mod catalog;
mod clipboard;
mod command_panel;
mod containers;
mod convert;
mod dashboard;
pub mod data_dirs;
mod deploy;
pub mod diagnostics;
mod file_server;
mod files;
mod groups;
mod host_details;
mod ipc;
mod multiexec;
mod navigation;
mod schedules;
mod stacks;
mod terminal;
mod terminal_rules;
mod toolbox;
mod tunnels;
pub mod updater;
mod vm_insight;
mod vm_settings;
mod wake;
mod workspaces;

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use remotely_core::adapters::updater::{DisabledUpdater, UpdaterAdapter};
use remotely_core::store::NewAuditEntry;
use remotely_core::{Core, CoreConfig};
use tauri::webview::{PageLoadEvent, PageLoadPayload};
use tauri::{App, AppHandle, DragDropEvent, Emitter, Manager, Runtime, Webview, WindowEvent};
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;

use crate::data_dirs::{app_directories_override, data_root};

pub struct AppState {
    pub core: Arc<Core>,
}

/// QL-15: how many times the main window's page has started loading; every load after the first is a reload.
#[derive(Default)]
struct PageLoads(AtomicU32);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut context = tauri::generate_context!();
    let identifier = context.config().identifier.clone();
    let data_env = std::env::var_os("REMOTELY_DATA_DIR");
    let debug_build = cfg!(debug_assertions);

    // QL-15: the log file and the panic hook come first, so even a start that fails leaves a trace.
    let log_dir = data_root(data_env.clone(), &identifier, debug_build)
        .ok()
        .map(|root| root.join(diagnostics::LOG_FOLDER));
    let no_log_file = diagnostics::init_logging(log_dir.as_deref());
    diagnostics::install_panic_hook(log_dir.clone());
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Remotely is starting");
    if let Some(problem) = no_log_file {
        tracing::warn!(problem, "logging to stdout only");
    }

    match app_directories_override(data_env, &identifier, debug_build) {
        Ok(Some(dirs)) => context.config_mut().app.app_directories_override = Some(dirs),
        Ok(None) => {}
        Err(err) => {
            tracing::error!(error = err, "the app can't choose its data folder");
            diagnostics::explain_startup_failure(err, log_dir.as_deref());
            std::process::exit(1);
        }
    }

    let builder = tauri::Builder::default();
    // QL-15: a second launch brings this window forward and exits before it opens the database, so it can't
    // mark this one's running jobs as interrupted or race its audit writes. Release builds only: a debug build
    // shares the identifier, and must be able to run beside the installed app (its data folder is its own).
    #[cfg(not(debug_assertions))]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| focus_main(app)));
    let setup_logs = log_dir.clone();
    let result = builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        // AP-05: the audit export's save dialog, opened from Rust (no dialog permission for the UI).
        .plugin(tauri_plugin_dialog::init())
        // QL-07: notifications, shown from Rust (no notification permission for the UI).
        .plugin(tauri_plugin_notification::init())
        .manage(diagnostics::LogsFolder(log_dir.clone()))
        .manage(PageLoads::default())
        // FD-09: the toolbox's runs going on, so the UI can stop one.
        .manage(toolbox::ToolRuns::default())
        .setup(move |app| {
            // Tauri turns a setup error into a panic, so a failed start is explained here and ends here.
            if let Err(err) = start(app, setup_logs.as_deref()) {
                tracing::error!(error = %err, "the app could not start");
                diagnostics::explain_startup_failure(&err.to_string(), setup_logs.as_deref());
                app.cleanup_before_exit();
                std::process::exit(1);
            }
            Ok(())
        })
        .on_page_load(page_loaded)
        // SS-08: files dropped on the window are staged in Rust; the UI only learns where they fell.
        .on_window_event(|window, event| {
            if let WindowEvent::DragDrop(DragDropEvent::Drop { paths, position }) = event {
                if !paths.is_empty() {
                    files::dropped(window, paths, *position);
                }
            }
        })
        .invoke_handler(commands())
        .build(context);

    let app = match result {
        Ok(app) => app,
        Err(err) => {
            tracing::error!(error = %err, "the app stopped with an error");
            diagnostics::explain_startup_failure(&err.to_string(), log_dir.as_deref());
            std::process::exit(1);
        }
    };
    app.run(|handle, event| {
        // SS-03: terminals still open are closed (and their closing audited) before the app exits.
        if let tauri::RunEvent::Exit = event {
            if let Some(state) = handle.try_state::<AppState>() {
                tauri::async_runtime::block_on(state.core.shutdown());
            }
            tracing::info!("Remotely stopped");
        }
    });
}

/// QL-15: the running window, brought forward for a second launch.
#[cfg_attr(debug_assertions, allow(dead_code))]
fn focus_main<R: Runtime>(app: &AppHandle<R>) {
    tracing::info!("Remotely was started again; showing the running window");
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// QL-15: the page started loading again (F5 in a debug build, "Reload" after a UI crash, or WebView2 itself).
/// What the old page had open can no longer be seen or answered, so it is closed: terminals with their tunnels,
/// MultiExec, and approvals still waiting. Running jobs go on (Activity shows them).
fn page_loaded<R: Runtime>(webview: &Webview<R>, payload: &PageLoadPayload<'_>) {
    if payload.event() != PageLoadEvent::Started || webview.label() != "main" {
        return;
    }
    let loads = webview.state::<PageLoads>().0.fetch_add(1, Ordering::SeqCst);
    if loads == 0 {
        return;
    }
    // FD-09: the old page's toolbox runs (a ping of 1000 requests, say) stop with it.
    if let Some(runs) = webview.try_state::<toolbox::ToolRuns>() {
        let stopped = runs.cancel_all();
        if stopped > 0 {
            tracing::info!(stopped, "the window reloaded; stopped its toolbox runs");
        }
    }
    let Some(state) = webview.try_state::<AppState>() else {
        return;
    };
    let core = Arc::clone(&state.core);
    // Taken now, so what the new page opens is left alone.
    let shown = core.ui_snapshot();
    if shown.is_empty() {
        return;
    }
    tauri::async_runtime::spawn(async move {
        let released = core.release_ui(shown).await;
        tracing::warn!(
            terminals = released.terminals,
            approvals = released.approvals,
            file_servers = released.file_servers,
            "the window reloaded; closed what it had open"
        );
    });
}

/// Opens the database (offering a fresh one when it can't be opened), starts the core and wires its events to the
/// UI. An error here ends the app with a message box (see `run`).
fn start(app: &mut App, log_dir: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    // %LOCALAPPDATA%\com.remotely.desktop, its `.dev` sibling for a debug build, or
    // REMOTELY_DATA_DIR (see `app_directories_override`). Never the working directory, so nothing
    // private can land in the public repo (CLAUDE.md).
    let data_dir = app.path().app_local_data_dir()?;
    if let (Ok(tauri_logs), Some(ours)) = (app.path().app_log_dir(), log_dir) {
        if tauri_logs != ours {
            tracing::warn!(tauri = %tauri_logs.display(), ours = %ours.display(), "two different log folders");
        }
    }
    std::fs::create_dir_all(&data_dir)?;
    // FD-14: signed updates from the private repo's GitHub Releases, with the token from the vault.
    let updater: Arc<dyn UpdaterAdapter> = match updater::TauriUpdater::new(app.handle().clone()) {
        Ok(updater) => Arc::new(updater),
        Err(err) => {
            tracing::error!(error = %err, "update checks are unavailable");
            Arc::new(DisabledUpdater)
        }
    };
    let db_path = data_dir.join("remotely.db");
    let config = || CoreConfig {
        db_path: db_path.clone(),
        vmrun_path: None,
        vboxmanage_path: None,
        account: windows_account(),
        display_name: std::env::var("USERNAME").unwrap_or_else(|_| "user".into()),
        updater: Arc::clone(&updater),
    };
    tracing::info!(data_dir = %data_dir.display(), "starting core");
    let core = match tauri::async_runtime::block_on(Core::init(config())) {
        Ok(core) => core,
        // QL-15: a database that won't open or migrate (damaged, or from a newer version) is set aside and
        // replaced by an empty one only if the user says so; otherwise the app quits and nothing changes.
        Err(err) if err.is_database() => {
            tracing::error!(error = %err, "the database can't be opened");
            if !diagnostics::offer_fresh_database(&err.to_string(), err.is_newer_database(), &db_path, log_dir) {
                diagnostics::mark_explained();
                return Err(err.into());
            }
            let aside = diagnostics::set_database_aside(&db_path)
                .map_err(|io| format!("the database could not be set aside: {io}"))?;
            tracing::warn!(backup = %aside.display(), "the database was set aside; starting with an empty one");
            let core = tauri::async_runtime::block_on(Core::init(config()))?;
            let name = aside
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            let detail = format!("the database could not be opened ({err}); it was kept as {name}");
            let noted = tauri::async_runtime::block_on(core.store.append_audit(
                &core.ctx(),
                NewAuditEntry {
                    event: "database_set_aside",
                    action: "Started with an empty database",
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            ));
            if let Err(err) = noted {
                tracing::error!(error = %err, "could not audit the fresh start");
            }
            core
        }
        Err(err) => return Err(err.into()),
    };
    let core = Arc::new(core);
    forward_events(app, &core);
    // QL-15: no F5, Ctrl+R or DevTools keys in a release build: a reload would leave the core's work unseen.
    #[cfg(all(windows, not(debug_assertions)))]
    turn_off_browser_keys(app);
    app.manage(AppState { core });
    Ok(())
}

/// QL-15: WebView2's own browser keys off (reload, find, print, zoom, DevTools); editing keys stay.
#[cfg(all(windows, not(debug_assertions)))]
fn turn_off_browser_keys(app: &App) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let asked = window.with_webview(|webview| {
        use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings3;
        use windows::core::Interface;
        // SAFETY: COM calls on the window's own WebView2 controller, on the thread `with_webview` runs us on.
        let turned_off = unsafe {
            webview
                .controller()
                .CoreWebView2()
                .and_then(|core| core.Settings())
                .and_then(|settings| settings.cast::<ICoreWebView2Settings3>())
                .and_then(|settings| settings.SetAreBrowserAcceleratorKeysEnabled(false))
        };
        if let Err(err) = turned_off {
            tracing::warn!(error = %err, "the browser keys stay on");
        }
    });
    if let Err(err) = asked {
        tracing::warn!(error = %err, "the browser keys stay on");
    }
}

/// Core events -> UI, and the background readers (metrics, reachability).
fn forward_events(app: &App, core: &Arc<Core>) {
    {
        // Job progress -> UI. FD-02: only the shown workspace's jobs (another's schedule runs go on unseen).
        let mut job_events = core.jobs.subscribe();
        let handle = app.handle().clone();
        let jobs = Arc::clone(&core.jobs);
        let shown = core.current().clone();
        tauri::async_runtime::spawn(async move {
            loop {
                match job_events.recv().await {
                    Ok(event) => {
                        if jobs.workspace_of(event.job_id()) == Some(shown.get().workspace_id) {
                            let _ = handle.emit("job://event", &event);
                        }
                    }
                    Err(RecvError::Lagged(missed)) => tracing::warn!(missed, "UI missed job events"),
                    Err(RecvError::Closed) => break,
                }
            }
        });

        // FD-09: the file server's start, requests and stop -> UI (the shown workspace's).
        file_server::forward(app.handle(), core);

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

        // SS-03 (R9): Windows resuming or a new network address wakes terminals waiting to reconnect.
        wake::watch(Arc::clone(core));

        // BX-02: the job journal's retention purge, at start and daily.
        let retention = Arc::clone(&core.retention);
        tauri::async_runtime::spawn(async move { retention.run(CancellationToken::new()).await });

        // MO-06: the dashboard history's prune, at start and daily.
        let history = Arc::clone(&core.history);
        tauri::async_runtime::spawn(async move { history.run(CancellationToken::new()).await });

        // MO-07: alerts firing, resolving and acknowledged -> UI (its notifications, the alert list).
        let mut alerts = core.alerts.subscribe();
        let handle = app.handle().clone();
        tauri::async_runtime::spawn(async move {
            loop {
                match alerts.recv().await {
                    Ok(event) => {
                        let _ = handle.emit("alerts://event", &event);
                    }
                    Err(RecvError::Lagged(missed)) => tracing::warn!(missed, "UI missed alert events"),
                    Err(RecvError::Closed) => break,
                }
            }
        });

        // VM-14, VM-27: the scheduler on the wall clock; its runs and pauses -> UI.
        schedules::start(app, core);

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
    }
}

/// Every IPC command the UI may call.
fn commands() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        ipc::app_info,
        diagnostics::logs_info,
        diagnostics::logs_open,
        diagnostics::ui_error,
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
        ipc::journal_retention,
        ipc::journal_retention_set,
        ipc::journal_purge_now,
        ipc::audit_export_csv,
        ipc::settings_get,
        ipc::settings_set_vmrun_path,
        ipc::settings_set_ovftool_path,
        ipc::settings_set_qemu_img_path,
        ipc::settings_set_vboxmanage_path,
        ipc::settings_set_scan_folders,
        ipc::settings_set_power_on_limit,
        ipc::settings_set_shutdown_wait,
        ipc::settings_set_update_checks,
        ipc::settings_set_guest_poll,
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
        ipc::vault_turn_off_windows_login,
        ipc::vault_activity,
        ipc::password_strength,
        ipc::passphrase_generate,
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
        ipc::folder_set_defaults,
        ipc::session_inherited,
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
        ipc::bulk_go_on,
        ipc::bulk_export,
        ipc::command_preview,
        ipc::metrics_overview,
        ipc::metrics_series,
        ipc::metrics_host_usage,
        ipc::metrics_capacity,
        ipc::metrics_watch,
        ipc::background_login_retry,
        ipc::session_startup_rating,
        host_details::metrics_this_pc,
        host_details::host_specs,
        host_details::host_specs_refresh,
        host_details::host_admin,
        host_details::host_updates,
        host_details::host_details_release,
        host_details::vm_specs,
        vm_settings::vm_pick_iso,
        vm_settings::vm_attach_dropped_iso,
        vm_settings::vm_pick_shared_folder,
        vm_settings::vm_pick_existing,
        vm_settings::vm_open_console,
        vm_settings::vm_screenshot,
        vm_settings::vm_guest_os_types,
        vm_settings::vm_workstation_open,
        vm_insight::vm_logs,
        vm_insight::vm_log_read,
        vm_insight::vm_timeline,
        vm_insight::host_networks,
        vm_insight::host_network_list,
        vm_insight::waste_report,
        vm_insight::waste_open_folder,
        dashboard::metrics_history,
        dashboard::history_info,
        dashboard::history_retention_set,
        dashboard::alerts_list,
        dashboard::alerts_acknowledge,
        dashboard::alert_rules,
        dashboard::alert_rule_create,
        dashboard::alert_rule_update,
        dashboard::alert_rule_delete,
        dashboard::alert_rule_reset,
        dashboard::alert_notify,
        dashboard::dashboard_layout,
        dashboard::dashboard_layout_set,
        dashboard::dashboard_layout_reset,
        dashboard::host_services,
        schedules::schedules_list,
        schedules::schedule_get,
        schedules::schedule_runs,
        schedules::schedule_preview,
        schedules::schedule_save,
        schedules::schedule_approve,
        schedules::schedule_ask_approval,
        schedules::schedule_pause,
        schedules::schedule_resume,
        schedules::schedule_delete,
        schedules::schedules_for_vm,
        schedules::schedule_chain_limits,
        schedules::schedule_chain_limits_set,
        navigation::notifications_list,
        navigation::notifications_add,
        navigation::notifications_mark_read,
        navigation::notifications_clear,
        navigation::topology_vm_networks,
        navigation::vm_folder_pick,
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
        terminal::terminal_output_print,
        terminal::terminal_output_save,
        terminal::terminal_log_start,
        terminal::terminal_log_stop,
        containers::containers_hosts,
        containers::containers_marks,
        containers::containers_set_marks,
        containers::containers_detect,
        containers::containers_version,
        containers::containers_list,
        containers::containers_stats,
        containers::containers_details,
        containers::containers_logs,
        containers::containers_images,
        containers::containers_volumes,
        containers::containers_networks,
        containers::containers_release,
        containers::container_shell_open,
        ipc::settings_set_docker_path,
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
        multiexec::multiexec_recordings,
        multiexec::multiexec_recorded,
        multiexec::multiexec_recorded_output,
        multiexec::multiexec_recorded_diff,
        multiexec::multiexec_export,
        groups::multiexec_groups_list,
        groups::multiexec_group_create,
        groups::multiexec_group_update,
        groups::multiexec_group_delete,
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
        command_panel::notify_terminal_alert,
        command_panel::open_manual,
        terminal_rules::terminal_rules_list,
        terminal_rules::terminal_rule_validate,
        terminal_rules::terminal_rule_add,
        terminal_rules::terminal_rule_update,
        terminal_rules::terminal_rule_delete,
        terminal_rules::terminal_rules_reorder,
        terminal_rules::terminal_rule_set_builtin,
        catalog::catalog_profiles,
        catalog::catalog_sites,
        catalog::catalog_sizes,
        catalog::catalog_size_add,
        catalog::catalog_size_update,
        catalog::catalog_size_delete,
        catalog::catalog_images,
        catalog::catalog_image_pick,
        catalog::catalog_folder_pick,
        catalog::catalog_image_add,
        catalog::catalog_image_cancel,
        catalog::catalog_image_update,
        catalog::catalog_image_delete,
        catalog::catalog_templates,
        catalog::catalog_template_preview,
        catalog::catalog_template_add,
        catalog::catalog_template_update,
        catalog::catalog_template_delete,
        catalog::catalog_open_site,
        deploy::deploy_check,
        deploy::deploy_submit,
        deploy::deploy_clone_check,
        deploy::deploy_clone_submit,
        deploy::deploy_host_adapters,
        deploy::deploy_default_folder,
        stacks::stacks_list,
        stacks::stacks_check,
        stacks::stacks_add,
        stacks::stacks_update,
        stacks::stacks_delete,
        stacks::stacks_deploy_check,
        stacks::stacks_deploy,
        stacks::stacks_instances,
        stacks::stacks_instance_power,
        stacks::stacks_teardown,
        stacks::stacks_add_vm,
        stacks::stacks_remove_vm,
        stacks::stacks_forget_instance,
        convert::convert_tools,
        convert::convert_pick,
        convert::convert_inspect,
        convert::convert_options,
        convert::convert_submit,
        convert::convert_verify,
        convert::convert_verify_cancel,
        convert::export_options,
        convert::export_submit,
        convert::import_analyze,
        convert::import_check,
        convert::import_submit,
        convert::convert_open_qemu_site,
        clipboard::clipboard_read_text,
        clipboard::terminal_copy_selection,
        clipboard::terminal_output_copy,
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
        // FD-02 workspaces, AP-08 change ID rule.
        workspaces::workspaces_list,
        workspaces::workspace_current,
        workspaces::workspace_create,
        workspaces::workspace_rename,
        workspaces::workspace_set_color,
        workspaces::workspace_archive,
        workspaces::workspace_restore,
        workspaces::workspace_switch_preview,
        workspaces::workspace_switch,
        workspaces::vm_unassigned,
        workspaces::vm_claim,
        workspaces::vm_release,
        workspaces::change_id_rules,
        workspaces::change_id_rules_set,
        workspaces::transfer_commit_new_workspace,
        // FD-09 the toolbox.
        toolbox::toolbox_ping,
        toolbox::toolbox_trace,
        toolbox::toolbox_dns,
        toolbox::toolbox_ports,
        toolbox::toolbox_certificate,
        toolbox::toolbox_certificate_file,
        toolbox::toolbox_cancel,
        toolbox::toolbox_wake_options,
        // FD-09 the quick file server.
        file_server::file_server_options,
        file_server::file_server_status,
        file_server::file_server_pick,
        file_server::file_server_start,
        file_server::file_server_stop,
    ]
}

/// DOMAIN\user, which keys the local user record.
fn windows_account() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".into());
    match std::env::var("USERDOMAIN") {
        Ok(domain) if !domain.is_empty() => format!("{domain}\\{user}"),
        _ => user,
    }
}
