//! MO-06 history on disk, MO-16 layouts and the services widget, end to end through the core with fakes and
//! the test SSH server.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{vmx, Setup};
use remotely_core::adapters::host_counters::VmProcess;
use remotely_core::adapters::remote::AgentSource;
use remotely_core::adapters::vmware::VmxInfo;
use remotely_core::alerts::{Alert, AlertMetric, AlertTarget, AlertTargetKind, Severity};
use remotely_core::dashboard::{ChartMetric, ChartRange, DashboardLayout, Widget, WidgetKind, LAYOUT_KEY};
use remotely_core::domain::{Environment, THIS_PC_KEY};
use remotely_core::fakes::ssh_server::host::HostFixture;
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::FakeVmware;
use remotely_core::host_details::admin::ServiceManager;
use remotely_core::host_details::ServicesRead;
use remotely_core::known_hosts::HostKey;
use remotely_core::metrics::history::{
    HistoryRange, HistoryRetention, HistorySource, MinuteRow, HISTORY_RETENTION_KEY, MINUTE_MS,
};
use remotely_core::metrics::procfs::samples;
use remotely_core::metrics::GuestTuning;
use remotely_core::presentation::Presentation;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::store::Store;
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use uuid::Uuid;

const GB: u64 = 1024 * 1024 * 1024;
const ROUND: i64 = 5_000;

/// The start of a minute, a few minutes ago.
fn minute_start() -> i64 {
    (remotely_core::metrics::history::now_ms() / MINUTE_MS - 10) * MINUTE_MS
}

fn process(name: &str, host_cpu: f64) -> VmProcess {
    VmProcess {
        pid: 1,
        vmx_path: Some(vmx(name)),
        name: None,
        cpu_pct: Some(host_cpu),
        working_set_bytes: Some(GB),
        read_bps: Some(1_000.0),
        write_bps: Some(3_000.0),
    }
}

async fn core_with_web() -> (Core, Arc<std::sync::Mutex<Vec<VmProcess>>>) {
    let fake = FakeVmware::with_running([vmx("web")])
        .in_library(&vmx("web"), Some("web"))
        .with_vmx(
            &vmx("web"),
            VmxInfo {
                display_name: Some("web".into()),
                num_vcpus: Some(2),
                memsize_mb: Some(4096),
                ..Default::default()
            },
        );
    let setup = Setup::new(fake);
    let processes = Arc::clone(&setup.host.processes);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    (core, processes)
}

// ---- MO-06: history on disk ---------------------------------------------------------------------

#[tokio::test]
async fn rounds_are_written_once_a_minute_in_one_go_and_read_back_in_buckets() {
    let (core, processes) = core_with_web().await;
    let start = minute_start();
    // 2 vCPUs on 16 CPUs: 1.25% of the host is 10% of the VM, 2.5% is 20%.
    let mut t = start;
    for i in 0..12 {
        let host_cpu = if i % 2 == 0 { 1.25 } else { 2.5 };
        *processes.lock().unwrap() = vec![process("web", host_cpu)];
        core.metrics.collect_once_at(t).await;
        t += ROUND;
        let size = core.store.history_size(&core.ctx()).await.unwrap();
        assert_eq!(size.minutes, 0, "nothing written while the minute is open (round {i})");
    }
    // The first round of the next minute writes the last one: the VM's and this PC's.
    *processes.lock().unwrap() = vec![process("web", 5.0)];
    core.metrics.collect_once_at(t).await;
    let size = core.store.history_size(&core.ctx()).await.unwrap();
    assert_eq!((size.series, size.minutes), (2, 2));
    assert!(size.bytes.is_some_and(|b| b > 0), "{size:?}");

    let series = core
        .history
        .series(
            &core.ctx(),
            HistorySource::Host,
            &vmx("web").to_lowercase(),
            HistoryRange::Hour,
            t,
        )
        .await
        .unwrap();
    assert_eq!(series.bucket_secs, 60);
    assert_eq!(series.points.len(), 1);
    let p = series.points[0];
    assert_eq!(p.t, start);
    assert_eq!(p.samples, 12);
    assert_eq!(p.cpu_pct, Some(15.0));
    assert_eq!(p.cpu_min, Some(10.0));
    assert_eq!(p.cpu_max, Some(20.0));
    assert_eq!(p.mem_bytes, Some(GB));
    assert_eq!(p.mem_total_bytes, Some(4 * GB));
    assert_eq!(p.disk_write_bps, Some(3_000.0));
    assert_eq!(
        series.stored_until,
        Some(start + MINUTE_MS),
        "live rounds take over from here"
    );
    // This PC: 8 GB of 32 in use, and its paging file.
    let pc = core
        .history
        .series(&core.ctx(), HistorySource::ThisPc, THIS_PC_KEY, HistoryRange::Hour, t)
        .await
        .unwrap();
    assert_eq!(pc.points[0].mem_bytes, Some(8 * GB));
    assert_eq!(pc.points[0].mem_total_bytes, Some(32 * GB));
    assert_eq!(pc.points[0].swap_total_bytes, Some(4 * GB));

    // The open minute is written when the app closes.
    core.shutdown().await;
    assert_eq!(core.store.history_size(&core.ctx()).await.unwrap().minutes, 4);
    // Reads only: no job and no audit entry.
    assert!(core.store.recent_jobs(&core.ctx(), 10).await.unwrap().is_empty());
    assert!(core
        .store
        .recent_audit(&core.ctx(), 20)
        .await
        .unwrap()
        .iter()
        .all(|e| e.event != "history_pruned"));
}

fn minute_row(key: &str, minute: i64, samples: u32, cpu: f64) -> MinuteRow {
    MinuteRow {
        source: HistorySource::Guest,
        key: key.into(),
        minute,
        samples,
        cpu_avg: Some(cpu),
        cpu_min: Some(cpu),
        cpu_max: Some(cpu),
        mem_avg: Some(GB),
        mem_max: Some(GB),
        mem_total: Some(2 * GB),
        swap_avg: None,
        swap_total: None,
        read_avg: Some(100),
        write_avg: Some(200),
        rx_avg: None,
        tx_avg: None,
        load_avg: Some(0.5),
        load_max: Some(0.5),
        disk_used_max: Some(40.0),
    }
}

#[tokio::test]
async fn a_minute_written_twice_keeps_both_parts_weighed_by_their_rounds() {
    let store = Store::open_in_memory().await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let key = Uuid::new_v4().to_string();
    store
        .write_history(&ctx, &[minute_row(&key, 1000, 3, 10.0)])
        .await
        .unwrap();
    // The app closed and started again within that minute.
    store
        .write_history(&ctx, &[minute_row(&key, 1000, 1, 50.0)])
        .await
        .unwrap();
    let rows = store
        .read_history(&ctx, HistorySource::Guest, &key.to_uppercase(), 0, 2000)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "one series, one minute, whatever the key's case");
    let row = &rows[0];
    assert_eq!(row.samples, 4);
    assert_eq!(row.cpu_avg, Some(20.0));
    assert_eq!(row.cpu_min, Some(10.0));
    assert_eq!(row.cpu_max, Some(50.0));
    assert_eq!(row.mem_avg, Some(GB));
    assert_eq!(row.read_avg, Some(100));
    assert_eq!(row.swap_avg, None);
}

fn alert(fired_at: &str, resolved_at: Option<&str>) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        rule_id: Uuid::new_v4(),
        rule_name: "CPU".into(),
        metric: AlertMetric::Cpu,
        severity: Severity::Warning,
        target: AlertTarget {
            kind: AlertTargetKind::Vm,
            key: vmx("web"),
            name: "web".into(),
        },
        threshold: Some(90.0),
        for_secs: 300,
        value: Some(95.0),
        peak: Some(95.0),
        message: "CPU at 95%".into(),
        fired_at: fired_at.into(),
        resolved_at: resolved_at.map(str::to_owned),
        resolution: None,
        acknowledged_at: None,
    }
}

#[tokio::test]
async fn the_daily_prune_removes_old_minutes_series_and_resolved_alerts_and_is_audited() {
    let (core, _) = core_with_web().await;
    let now_minute = remotely_core::metrics::history::now_ms() / MINUTE_MS;
    let day = 24 * 60;
    let old = Uuid::new_v4().to_string();
    let kept = Uuid::new_v4().to_string();
    let mut rows = Vec::new();
    for m in 0..10 {
        // A host watched 8 days ago only, and one watched until now.
        rows.push(minute_row(&old, now_minute - 8 * day - m, 12, 5.0));
        rows.push(minute_row(&kept, now_minute - 8 * day - m, 12, 5.0));
        rows.push(minute_row(&kept, now_minute - m, 12, 5.0));
    }
    core.store.write_history(&core.ctx(), &rows).await.unwrap();
    let old_alert = alert("2026-01-01T00:00:00Z", Some("2026-01-01T00:05:00Z"));
    let still_open = alert("2026-01-02T00:00:00Z", None);
    let recent = alert(
        &remotely_core::alerts::eval::rfc3339(remotely_core::metrics::history::now_ms()),
        Some(&remotely_core::alerts::eval::rfc3339(
            remotely_core::metrics::history::now_ms(),
        )),
    );
    for a in [&old_alert, &still_open, &recent] {
        core.store.insert_alert(&core.ctx(), a).await.unwrap();
    }
    if let Some(r) = &recent.resolved_at {
        core.store
            .resolve_alert(
                &core.ctx(),
                recent.id,
                remotely_core::alerts::Resolution::Cleared,
                None,
                r,
            )
            .await
            .unwrap();
    }
    core.store
        .resolve_alert(
            &core.ctx(),
            old_alert.id,
            remotely_core::alerts::Resolution::Cleared,
            None,
            "2026-01-01T00:05:00Z",
        )
        .await
        .unwrap();

    let report = core.history.prune().await.unwrap();
    assert_eq!(report.retention, HistoryRetention::Days7);
    assert_eq!(report.removed.minutes, 20);
    assert_eq!(report.removed.series, 1, "the host no longer watched");
    assert_eq!(report.removed.alerts, 1, "an open alert stays, however old");
    let size = core.store.history_size(&core.ctx()).await.unwrap();
    assert_eq!((size.series, size.minutes), (1, 10));
    let audit = core.store.recent_audit(&core.ctx(), 1).await.unwrap();
    assert_eq!(audit[0].event, "history_pruned");
    assert!(
        audit[0].detail.as_deref().unwrap().starts_with("older than 7 days"),
        "{:?}",
        audit[0].detail
    );
    let ids: Vec<Uuid> = core
        .alerts
        .list(Default::default())
        .await
        .unwrap()
        .alerts
        .iter()
        .map(|a| a.id)
        .collect();
    assert!(ids.contains(&still_open.id) && ids.contains(&recent.id) && !ids.contains(&old_alert.id));

    // Nothing left to remove: no audit entry.
    let again = core.history.prune().await.unwrap();
    assert!(!again.removed.removed_any());
    assert_eq!(
        core.store.recent_audit(&core.ctx(), 1).await.unwrap()[0].id,
        audit[0].id
    );
}

#[tokio::test]
async fn the_retention_setting_is_audited_prunes_at_once_when_shorter_and_is_locked_while_presenting() {
    let (core, _) = core_with_web().await;
    let now_minute = remotely_core::metrics::history::now_ms() / MINUTE_MS;
    let key = Uuid::new_v4().to_string();
    let rows: Vec<MinuteRow> = [now_minute - 3 * 24 * 60, now_minute - 5]
        .into_iter()
        .map(|m| minute_row(&key, m, 12, 1.0))
        .collect();
    core.store.write_history(&core.ctx(), &rows).await.unwrap();

    let info = core.history.set_retention(HistoryRetention::Day1).await.unwrap();
    assert_eq!(info.retention, HistoryRetention::Day1);
    assert_eq!(info.size.minutes, 1, "3 days old: pruned at once");
    let audit = core.store.recent_audit(&core.ctx(), 2).await.unwrap();
    assert_eq!(audit[1].event, "setting_changed");
    assert_eq!(audit[1].action, "Set how long the dashboard keeps its history");
    assert_eq!(
        audit[1].detail.as_deref(),
        Some("7 days -> 1 day; kept on this PC only, pruned daily")
    );
    assert_eq!(audit[0].event, "history_pruned");

    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let err = core.history.set_retention(HistoryRetention::Days30).await.unwrap_err();
    assert_eq!(err.code(), "read_only_lock");
    // The schedule still prunes.
    assert!(core.history.prune().await.is_ok());
}

#[tokio::test]
async fn settings_this_version_cant_read_are_set_aside_and_get_their_defaults() {
    let store = Store::open_in_memory().await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    store
        .put_setting(&ctx, HISTORY_RETENTION_KEY, &"days365")
        .await
        .unwrap();
    store
        .put_setting(
            &ctx,
            LAYOUT_KEY,
            &serde_json::json!({"version": 1, "widgets": [{"id": "x", "w": 1, "h": 1, "kind": "weather"}]}),
        )
        .await
        .unwrap();
    let reset = remotely_core::settings::repair(&store, &ctx).await.unwrap();
    assert_eq!(reset, [HISTORY_RETENTION_KEY, LAYOUT_KEY]);
    let aside: Option<String> = store
        .get_setting(&ctx, &format!("{HISTORY_RETENTION_KEY}.unreadable"))
        .await
        .unwrap();
    assert_eq!(aside.as_deref(), Some("days365"));
    assert_eq!(
        store
            .get_setting::<HistoryRetention>(&ctx, HISTORY_RETENTION_KEY)
            .await
            .unwrap(),
        None
    );
}

/// What the history takes for 50 VMs and 20 watched hosts over 7 days. Run by hand for the numbers (it writes
/// 705,600 rows): `cargo test -p remotely-core --features fakes --test dashboard -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "writes a week of history for 70 series; run by hand for the size estimate"]
async fn size_of_a_week_for_50_vms_and_20_hosts() {
    let dir = std::env::temp_dir().join(format!("remotely-history-size-{}", Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("history.db");
    let store = Store::open(&path).await.unwrap();
    let ctx = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
    let base = store.space().await.unwrap().0;
    let now_minute = remotely_core::metrics::history::now_ms() / MINUTE_MS;
    let week = 7 * 24 * 60;
    let vms: Vec<String> = (0..50)
        .map(|i| format!(r"D:\Virtual Machines\lab-vm-{i:02}\lab-vm-{i:02}.vmx"))
        .collect();
    let hosts: Vec<String> = (0..20).map(|_| Uuid::new_v4().to_string()).collect();
    let started = std::time::Instant::now();
    for chunk in (0..week).collect::<Vec<i64>>().chunks(60) {
        let mut rows = Vec::new();
        for &m in chunk {
            let minute = now_minute - week + m;
            #[allow(clippy::cast_precision_loss)]
            let wave = (m % 97) as f64;
            for vm in &vms {
                rows.push(MinuteRow {
                    source: HistorySource::Host,
                    key: vm.clone(),
                    minute,
                    samples: 12,
                    cpu_avg: Some(12.34 + wave / 3.0),
                    cpu_min: Some(3.21),
                    cpu_max: Some(45.67 + wave / 2.0),
                    mem_avg: Some(3 * GB + 123_456_789),
                    mem_max: Some(3 * GB + 223_456_789),
                    mem_total: Some(4 * GB),
                    swap_avg: None,
                    swap_total: None,
                    read_avg: Some(1_234_567),
                    write_avg: Some(2_345_678),
                    rx_avg: None,
                    tx_avg: None,
                    load_avg: None,
                    load_max: None,
                    disk_used_max: None,
                });
            }
            for host in &hosts {
                rows.push(MinuteRow {
                    source: HistorySource::Guest,
                    key: host.clone(),
                    minute,
                    samples: 12,
                    cpu_avg: Some(7.89 + wave / 4.0),
                    cpu_min: Some(1.23),
                    cpu_max: Some(34.56),
                    mem_avg: Some(5 * GB + 987_654),
                    mem_max: Some(5 * GB + 1_987_654),
                    mem_total: Some(8 * GB),
                    swap_avg: Some(123_456_789),
                    swap_total: Some(2 * GB),
                    read_avg: Some(345_678),
                    write_avg: Some(456_789),
                    rx_avg: Some(56_789),
                    tx_avg: Some(67_890),
                    load_avg: Some(0.42),
                    load_max: Some(1.37),
                    disk_used_max: Some(61.5),
                });
            }
        }
        store.write_history(&ctx, &rows).await.unwrap();
    }
    let size = store.history_size(&ctx).await.unwrap();
    store.checkpoint().await.unwrap();
    let file = store.space().await.unwrap().0;
    #[allow(clippy::cast_precision_loss)]
    let per_row = size.bytes.unwrap_or(0) as f64 / size.minutes as f64;
    println!(
        "history for 50 VMs and 20 hosts over 7 days: {} rows in {} series, tables {} bytes ({per_row:.0} bytes a row), \
         database file {} bytes (empty: {base}), written in {:?}",
        size.minutes,
        size.series,
        size.bytes.unwrap_or(0),
        file,
        started.elapsed()
    );
    store.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- MO-16: the layout ----------------------------------------------------------------------------

#[tokio::test]
async fn a_layout_is_saved_per_workspace_audited_reset_and_locked_while_presenting() {
    let core = Setup::new(FakeVmware::default()).build().await;
    let info = core.layouts.get().await.unwrap();
    assert!(!info.custom);
    assert_eq!(info.layout, DashboardLayout::default());
    assert_eq!((info.columns, info.max_rows), (4, 6));

    let mut layout = DashboardLayout::default();
    layout.widgets.reverse();
    layout.widgets.push(Widget {
        id: "chart-1".into(),
        w: 2,
        h: 2,
        kind: WidgetKind::Chart {
            source: Some(HistorySource::Host),
            key: Some(vmx("web")),
            name: Some("web".into()),
            metric: ChartMetric::Cpu,
            range: ChartRange::Day,
        },
    });
    layout.widgets.push(Widget {
        id: "services-1".into(),
        w: 1,
        h: 3,
        kind: WidgetKind::Services { session_id: None },
    });
    let saved = core.layouts.set(layout.clone()).await.unwrap();
    assert!(saved.custom);
    assert_eq!(core.layouts.get().await.unwrap().layout, layout);
    let audit = core.store.recent_audit(&core.ctx(), 1).await.unwrap();
    assert_eq!(audit[0].event, "dashboard_layout_changed");
    assert_eq!(
        audit[0].detail.as_deref(),
        Some("overview 4x5, alerts 2x2, this PC's memory 2x2, capacity 4x2, cpu chart of web 2x2, services (no host chosen) 1x3")
    );

    // One that can't be drawn is refused and changes nothing.
    let mut broken = layout.clone();
    broken.widgets[0].w = 9;
    assert_eq!(core.layouts.set(broken).await.unwrap_err().code(), "invalid_input");
    assert_eq!(core.layouts.get().await.unwrap().layout, layout);

    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    assert_eq!(core.layouts.reset().await.unwrap_err().code(), "read_only_lock");
    assert_eq!(core.layouts.set(layout).await.unwrap_err().code(), "read_only_lock");
    core.presentation
        .set(Presentation {
            enabled: false,
            read_only: true,
        })
        .await
        .unwrap();
    let reset = core.layouts.reset().await.unwrap();
    assert!(!reset.custom);
    assert_eq!(reset.layout, DashboardLayout::default());
    assert_eq!(
        core.store.recent_audit(&core.ctx(), 1).await.unwrap()[0].action,
        "Reset the dashboard layout"
    );
}

// ---- MO-16: the services widget ---------------------------------------------------------------------

fn tuning() -> GuestTuning {
    GuestTuning {
        connect_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        round_budget: Duration::from_secs(10),
        backoff_min: Duration::ZERO,
        backoff_max: Duration::ZERO,
        parallel: 4,
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
    }
}

#[tokio::test]
async fn the_services_widget_reads_on_the_dashboards_connection_and_never_logs_in_itself() {
    let password = format!("pw-{}", Uuid::new_v4().simple());
    let server = TestSshServer::start()
        .await
        .with_password("alice", &password)
        .with_host_facts(HostFixture::ubuntu());
    let s = samples::ubuntu(0);
    for (path, text) in [
        ("/proc/stat", s.stat.clone()),
        ("/proc/meminfo", s.meminfo.clone()),
        ("/proc/loadavg", s.loadavg.clone()),
        ("/proc/uptime", s.uptime.clone()),
        ("/proc/diskstats", s.diskstats.clone()),
        ("/proc/net/dev", s.netdev.clone()),
    ] {
        server.set_file(path, &text);
    }
    let server = server.with_program("df", &s.df);
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.metrics.guest().set_tuning(tuning());
    core.metrics.guest().set_interval(Duration::ZERO);
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx(), &key, None).await.unwrap();
    let password_id = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "web01 login",
            SecretString::new(&password),
        )
        .await
        .unwrap()
        .id;
    let id = core
        .sessions
        .create(
            &core.ctx(),
            SessionInput {
                name: "web01".into(),
                folder_id: None,
                host: "127.0.0.1".into(),
                port: server.port(),
                username: Some("alice".into()),
                auth: SessionAuth::Password {
                    password_id: Some(password_id),
                },
                jump_session_id: None,
                jump_direct: false,
                startup_command: None,
                startup_on_reconnect: false,
                prompt_hook: None,
                environment: Environment::Lab,
                color: None,
                tags: vec![],
                vm_id: None,
                kind: Default::default(),
            },
        )
        .await
        .unwrap()
        .id;

    // Not watched: nothing is read and nobody logs in.
    let read = core.host_details.services(id).await.unwrap();
    assert_eq!(read, ServicesRead::NotConnected { watched: false });
    assert_eq!(server.connections(), 0);

    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();
    core.metrics.collect_once().await;
    let ServicesRead::Read { report } = core.host_details.services(id).await.unwrap() else {
        panic!("not read")
    };
    assert_eq!(report.service_manager, ServiceManager::Systemd);
    assert!(report.running.iter().any(|s| s.name == "nginx.service"), "{report:?}");
    assert!(!report.failed.is_empty());
    // Again: the same one connection, the dashboard's.
    assert!(matches!(
        core.host_details.services(id).await.unwrap(),
        ServicesRead::Read { .. }
    ));
    assert_eq!(server.connections(), 1);
}
