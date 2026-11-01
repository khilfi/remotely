//! Monitoring (MO-01, MO-02, MO-04) end to end: the metrics collector with the fake host counters
//! standing in for `vmware-vmx.exe` processes, and the real russh adapter against SSH servers on
//! 127.0.0.1 that serve /proc files (MO-02). No real VM or host is read, and nothing goes through the
//! command bus: metrics are reads.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{vmx, Setup, VAULT_PASSWORD};
use remotely_core::adapters::host_counters::VmProcess;
use remotely_core::adapters::remote::AgentSource;
use remotely_core::adapters::vmware::VmxInfo;
use remotely_core::capacity::CapacityWarning;
use remotely_core::domain::{Environment, PowerState};
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::{FakeRemote, FakeVmware};
use remotely_core::known_hosts::HostKey;
use remotely_core::metrics::procfs::samples;
use remotely_core::metrics::{GuestState, GuestTuning, MetricSource, RowKind};
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::vault::{SecretKind, SecretString, UnlockMethod};
use remotely_core::Core;
use uuid::Uuid;

const GB: u64 = 1024 * 1024 * 1024;

fn process(pid: u32, vmx_path: &str, cpu_pct: Option<f64>) -> VmProcess {
    VmProcess {
        pid,
        vmx_path: Some(vmx_path.into()),
        name: None,
        cpu_pct,
        working_set_bytes: Some(GB),
        read_bps: Some(1_000_000.0),
        write_bps: Some(2_000_000.0),
    }
}

fn sized(fake: FakeVmware, name: &str, vcpus: u32, gb: u32) -> FakeVmware {
    fake.in_library(&vmx(name), Some(name)).with_vmx(
        &vmx(name),
        VmxInfo {
            display_name: Some(name.into()),
            num_vcpus: Some(vcpus),
            memsize_mb: Some(gb * 1024),
            ..Default::default()
        },
    )
}

// ---- MO-01: host-side metrics for every running VM ---------------------------------------------

#[tokio::test]
async fn running_vms_get_host_side_metrics_without_a_login_or_the_bus() {
    let fake = sized(
        sized(
            sized(FakeVmware::with_running([vmx("web"), vmx("db")]), "web", 2, 4),
            "db",
            4,
            8,
        ),
        "off",
        1,
        1,
    );
    let mut setup = Setup::new(fake);
    let remote = Arc::new(FakeRemote::default());
    setup.remote = remote.clone();
    let processes = Arc::clone(&setup.host.processes);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    let audit_before = core.store.recent_audit(&core.ctx(), 100).await.unwrap().len();

    // The command line's letter case differs from the library's; FD-02: a VM the workspace doesn't list (another
    // workspace's, or one none has) is left out, and so is a process whose command line could not be read.
    *processes.lock().unwrap() = vec![
        process(100, &vmx("web").to_uppercase(), Some(6.25)),
        process(200, &vmx("db"), None),
        process(300, r"E:\Other\tmp\tmp.vmx", Some(1.0)),
        VmProcess {
            vmx_path: None,
            ..process(400, "", None)
        },
    ];
    let cost = core.metrics.collect_once().await;
    assert_eq!(cost.vms, 2);
    assert_eq!(cost.interval_secs, 5, "MO-01: every 5 seconds");

    let overview = core.metrics.overview(&core.ctx()).await.unwrap();
    let names: Vec<&str> = overview.rows.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["db", "web"], "'off' is not running; 'tmp' isn't listed here");
    let web = overview.rows.iter().find(|r| r.name == "web").unwrap();
    assert_eq!(web.kind, RowKind::Vm);
    assert_eq!(web.key, vmx("web"), "the inventory's spelling");
    assert_eq!(web.power_state, Some(PowerState::Running));
    let host = web.host.as_ref().unwrap();
    assert_eq!(host.host_cpu_pct, Some(6.25), "share of the 16-CPU host");
    assert_eq!(host.cpu_pct, Some(50.0), "share of its own 2 vCPUs");
    assert_eq!(host.mem_bytes, Some(GB));
    assert_eq!(host.mem_total_bytes, Some(4 * GB));
    assert_eq!(host.host_mem_pct, Some(3.125), "1 GB working set of the 32 GB host");
    assert_eq!(host.disk_read_bps, Some(1_000_000.0));
    assert_eq!(host.disk_write_bps, Some(2_000_000.0));
    // MO-01 for the VM list: each running VM's share of the host, from the same round.
    let usage = core.metrics.hub().host_usage();
    let shares: Vec<(&str, Option<f64>, Option<f64>)> = usage
        .iter()
        .map(|u| (u.vmx_path.as_str(), u.host_cpu_pct, u.host_mem_pct))
        .collect();
    assert_eq!(
        shares,
        [
            (vmx("db").as_str(), None, Some(3.125)),
            (vmx("web").as_str(), Some(6.25), Some(3.125)),
        ],
        "by path; a first reading has no CPU rate yet; 'off' is not running"
    );
    // ...but it counts for this PC's capacity, as every VM process does.
    assert_eq!(core.metrics.hub().running().map(|r| r.len()), Some(3));

    // db stopped outside the app: the next round no longer lists it, though the inventory still
    // says running. Its history stays for the drill-down.
    *processes.lock().unwrap() = vec![process(100, &vmx("web"), Some(3.125))];
    let cost = core.metrics.collect_once().await;
    assert_eq!(cost.rounds, 2);
    assert!(
        cost.app_cpu_pct.is_some(),
        "the app's own CPU share once two rounds compare"
    );
    let overview = core.metrics.overview(&core.ctx()).await.unwrap();
    let names: Vec<&str> = overview.rows.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["web"]);
    let history = core.metrics.hub().series(MetricSource::Host, &vmx("web"));
    let cpu: Vec<Option<f64>> = history.iter().map(|p| p.cpu_pct).collect();
    assert_eq!(cpu, [Some(50.0), Some(25.0)]);
    assert_eq!(core.metrics.hub().series(MetricSource::Host, &vmx("db")).len(), 1);

    // Reads skip the bus: no job, no audit entry, no remote call.
    assert!(core.store.recent_jobs(&core.ctx(), 10).await.unwrap().is_empty());
    assert_eq!(
        core.store.recent_audit(&core.ctx(), 100).await.unwrap().len(),
        audit_before
    );
    assert!(remote.calls().is_empty());
}

// ---- MO-04: host capacity panel ----------------------------------------------------------------

#[cfg(windows)]
#[tokio::test]
async fn capacity_panel_compares_running_vms_with_the_host() {
    let mut fake = FakeVmware::with_running([vmx("a"), vmx("b")]);
    for (name, vcpus, gb) in [("a", 4, 16), ("b", 2, 20), ("c", 8, 8)] {
        fake = sized(fake, name, vcpus, gb);
    }
    let fake = fake.in_library(r"D:\Labs\x\x.vmx", Some("x"));
    let mut setup = Setup::new(fake); // 32 GB, 16 CPUs
    setup.host.free_disk_pct = 5.0;
    let processes = Arc::clone(&setup.host.processes);
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    *processes.lock().unwrap() = vec![process(1, &vmx("a"), None), process(2, &vmx("b"), None)];
    core.metrics.collect_once().await;
    core.metrics.collect_once().await;

    let capacity = core.metrics.capacity(&core.ctx()).await;
    assert_eq!(capacity.running_vms, 2);
    assert_eq!(capacity.assigned_ram_mb, 36 * 1024, "c is not running");
    assert_eq!(capacity.physical_ram_mb, 32 * 1024);
    assert_eq!(capacity.available_ram_mb, Some(24 * 1024));
    assert_eq!(capacity.assigned_vcpus, 6);
    assert_eq!(capacity.logical_cpus, 16);
    assert_eq!(capacity.host_cpu_pct, Some(25.0));
    assert_eq!(capacity.unsized_vms, 0);
    let drives: Vec<(&str, usize, bool)> = capacity
        .drives
        .iter()
        .map(|d| (d.drive.as_str(), d.vms, d.low))
        .collect();
    assert_eq!(drives, [("C:", 3, true), ("D:", 1, true)]);
    assert!(capacity.warnings.contains(&CapacityWarning::Ram {
        assigned_mb: 36 * 1024,
        physical_mb: 32 * 1024
    }));
    assert!(capacity
        .warnings
        .iter()
        .any(|w| matches!(w, CapacityWarning::Disk { drive, .. } if drive == "D:")));
}

#[tokio::test]
async fn capacity_says_what_it_could_not_read() {
    let mut setup = Setup::new(sized(FakeVmware::with_running([vmx("a")]), "a", 2, 4));
    setup.host.unavailable = true;
    let core = setup.build().await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    let capacity = core.metrics.capacity(&core.ctx()).await;
    assert_eq!(capacity.running_vms, 1, "from vmrun when no round has run");
    assert_eq!(capacity.assigned_ram_mb, 4 * 1024);
    assert!(capacity.drives.is_empty());
    let unchecked = capacity
        .warnings
        .iter()
        .filter(|w| matches!(w, CapacityWarning::Unchecked { .. }))
        .count();
    assert_eq!(unchecked, 2, "{:?}", capacity.warnings);
}

// ---- MO-02: Linux guest metrics over SSH -------------------------------------------------------

fn tuning() -> GuestTuning {
    GuestTuning {
        connect_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        // Long enough that every local poll lands in its own round.
        round_budget: Duration::from_secs(20),
        backoff_min: Duration::ZERO,
        backoff_max: Duration::ZERO,
        parallel: 8,
        agent: AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4())),
    }
}

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

/// An SSH server that looks like an Ubuntu guest at `round` 0.
async fn linux_server(password: &str) -> TestSshServer {
    let server = TestSshServer::start().await.with_password("alice", password);
    serve_round(&server, 0);
    let df = samples::ubuntu(0).df;
    server.with_program("df", &df)
}

/// Moves the guest's counters on to `round`.
fn serve_round(server: &TestSshServer, round: u64) {
    let s = samples::ubuntu(round);
    server.set_file("/proc/stat", &s.stat);
    server.set_file("/proc/meminfo", &s.meminfo);
    server.set_file("/proc/loadavg", &s.loadavg);
    server.set_file("/proc/uptime", &s.uptime);
    server.set_file("/proc/diskstats", &s.diskstats);
    server.set_file("/proc/net/dev", &s.netdev);
}

async fn ssh_core() -> Core {
    let core = Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.metrics.guest().set_tuning(tuning());
    // Rounds here follow each other at once; each one polls (the interval has its own test).
    core.metrics.guest().set_interval(Duration::ZERO);
    core
}

async fn trust(core: &Core, server: &TestSshServer, fingerprint: Option<&str>) {
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: fingerprint.map_or_else(|| server.host_key_fingerprint(), str::to_owned),
    };
    core.known_hosts.trust(&core.ctx(), &key, None).await.unwrap();
}

async fn session(core: &Core, name: &str, port: u16, password: Option<&str>) -> Uuid {
    linked_session(core, name, port, password, None).await
}

/// A session on 127.0.0.1 that logs in as alice, with `password` saved in the vault, reaching the VM
/// `vm_id` if given.
async fn linked_session(core: &Core, name: &str, port: u16, password: Option<&str>, vm_id: Option<String>) -> Uuid {
    let password_id = match password {
        Some(p) => Some(
            core.vault
                .add(
                    &core.ctx(),
                    SecretKind::Password,
                    &format!("{name} login"),
                    SecretString::new(p),
                )
                .await
                .unwrap()
                .id,
        ),
        None => None,
    };
    core.sessions
        .create(
            &core.ctx(),
            SessionInput {
                name: name.into(),
                folder_id: None,
                host: "127.0.0.1".into(),
                port,
                username: Some("alice".into()),
                auth: SessionAuth::Password { password_id },
                jump_session_id: None,
                jump_direct: false,
                startup_command: None,
                startup_on_reconnect: false,
                prompt_hook: None,
                environment: Environment::Lab,
                color: None,
                tags: vec![],
                vm_id,
                kind: Default::default(),
            },
        )
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn a_watched_host_is_polled_at_its_interval_with_one_grep_and_df_once_a_minute() {
    // MO-02, P8: the polling interval from Settings, and what each poll runs on the host.
    let password = new_password();
    let server = linux_server(&password).await;
    let core = ssh_core().await;
    trust(&core, &server, None).await;
    let id = session(&core, "web01", server.port(), Some(&password)).await;
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();
    // The collector's rounds come every 5 s; a host is polled once its interval (less 1 s) has passed.
    core.metrics.guest().set_interval(Duration::from_millis(1500));
    let execs = || {
        server
            .log()
            .into_iter()
            .filter(|l| l.starts_with("exec grep"))
            .collect::<Vec<_>>()
    };

    let cost = core.metrics.collect_once().await;
    assert_eq!(cost.guest_interval_secs, 1);
    assert_eq!(execs().len(), 1);
    assert!(
        execs()[0].contains("df -k -P -l"),
        "the first poll reads the mounts too"
    );
    core.metrics.collect_once().await;
    assert_eq!(execs().len(), 1, "polled less than an interval ago");
    tokio::time::sleep(Duration::from_millis(600)).await;
    serve_round(&server, 1);
    core.metrics.collect_once().await;
    let polls = execs();
    assert_eq!(polls.len(), 2);
    assert!(!polls[1].contains("df"), "df waits for its minute: {}", polls[1]);
    let guest = core.metrics.hub().latest(MetricSource::Guest, &id.to_string()).unwrap();
    assert_eq!(guest.cpu_pct, Some(25.0));
    let mounts: Vec<&str> = guest.mounts.iter().map(|m| m.mount.as_str()).collect();
    assert_eq!(
        mounts,
        ["/", "/boot/efi", "/var/lib/my data"],
        "the last df's mounts stand in"
    );

    // Saved in Settings: only the offered intervals, audited.
    let refused = core.set_guest_poll_secs(7).await.unwrap_err().to_string();
    assert!(refused.contains("every 5, 15, 30 or 60 seconds"), "{refused}");
    core.set_guest_poll_secs(30).await.unwrap();
    assert_eq!(core.guest_poll_secs(), 30);
    let audit = core.store.recent_audit(&core.ctx(), 1).await.unwrap();
    assert_eq!(audit[0].action, "Set how often the dashboard polls watched hosts");
    assert_eq!(audit[0].detail.as_deref(), Some("every 30 s"));
}

#[tokio::test]
async fn a_watched_linux_host_reports_guest_metrics_over_one_kept_connection() {
    let password = new_password();
    let server = linux_server(&password).await;
    let core = ssh_core().await;
    trust(&core, &server, None).await;
    let id = session(&core, "web01", server.port(), Some(&password)).await;

    // Not watched: nothing is read.
    core.metrics.collect_once().await;
    assert_eq!(server.connections(), 0);
    assert!(core.metrics.overview(&core.ctx()).await.unwrap().rows.is_empty());

    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();
    let audit = core.store.recent_audit(&core.ctx(), 1).await.unwrap();
    assert_eq!(audit[0].event, "setting_changed");
    assert_eq!(audit[0].action, "Started guest metrics");

    let cost = core.metrics.collect_once().await;
    assert_eq!(cost.guests, 1);
    let overview = core.metrics.overview(&core.ctx()).await.unwrap();
    let row = &overview.rows[0];
    assert_eq!((row.kind, row.name.as_str()), (RowKind::Session, "web01"));
    assert_eq!(
        row.address.as_deref(),
        Some(&*format!("alice@127.0.0.1:{}", server.port()))
    );
    assert_eq!(row.guest_status.as_ref().unwrap().state, GuestState::Ok);
    let guest = row.guest.as_ref().unwrap();
    assert_eq!(guest.cpu_pct, None, "a rate needs two readings");
    assert_eq!(guest.mem_total_bytes, Some(4_028_180 * 1024));
    assert_eq!(guest.mem_bytes, Some((4_028_180 - 1_007_045) * 1024));
    assert_eq!(
        (guest.load1, guest.load5, guest.load15),
        (Some(0.52), Some(0.48), Some(0.40))
    );
    assert_eq!(guest.uptime_secs, Some(3600));
    let mounts: Vec<&str> = guest.mounts.iter().map(|m| m.mount.as_str()).collect();
    assert_eq!(mounts, ["/", "/boot/efi", "/var/lib/my data"]);

    // The guest's counters move on; the same connection reads them.
    serve_round(&server, 1);
    core.metrics.collect_once().await;
    serve_round(&server, 2);
    core.metrics.collect_once().await;
    let guest = core.metrics.hub().latest(MetricSource::Guest, &id.to_string()).unwrap();
    assert_eq!(guest.cpu_pct, Some(25.0));
    assert_eq!(guest.disk_read_bps, Some(20_480.0 * 512.0 / 5.0));
    assert_eq!(guest.disk_write_bps, Some(10_240.0 * 512.0 / 5.0));
    assert_eq!(guest.net_rx_bps, Some(1_048_576.0 / 5.0));
    assert_eq!(guest.net_tx_bps, Some(524_288.0 / 5.0));
    assert_eq!(server.connections(), 1, "logged in once for three rounds");
    let logins = server.log().iter().filter(|l| l.starts_with("password alice")).count();
    assert_eq!(logins, 1);
    assert_eq!(core.metrics.hub().series(MetricSource::Guest, &id.to_string()).len(), 3);

    // Reads skip the bus, and the password is nowhere in what the UI gets.
    assert!(core.store.recent_jobs(&core.ctx(), 10).await.unwrap().is_empty());
    let shown = serde_json::to_string(&core.metrics.overview(&core.ctx()).await.unwrap()).unwrap();
    assert!(!shown.contains(&password));

    // A dropped connection is noticed and made again in a later round.
    server.drop_connections();
    for _ in 0..3 {
        core.metrics.collect_once().await;
    }
    let status = core.metrics.guest().statuses()[&id].clone();
    assert_eq!(status.state, GuestState::Ok, "{status:?}");
    assert_eq!(server.connections(), 2);

    // Unwatched: the connection closes and the row, state and history go.
    core.metrics.set_watched(&core.ctx(), id, false).await.unwrap();
    core.metrics.collect_once().await;
    assert!(core.metrics.overview(&core.ctx()).await.unwrap().rows.is_empty());
    assert!(core
        .metrics
        .hub()
        .series(MetricSource::Guest, &id.to_string())
        .is_empty());
    let audit = core.store.recent_audit(&core.ctx(), 1).await.unwrap();
    assert_eq!(audit[0].action, "Stopped guest metrics");
}

#[tokio::test]
async fn a_vm_with_a_linked_session_shows_host_and_guest_metrics_in_one_row() {
    let password = new_password();
    let server = linux_server(&password).await;
    let mut setup = Setup::new(sized(FakeVmware::with_running([vmx("web")]), "web", 2, 4))
        .with_real_vault()
        .with_ssh();
    let processes = Arc::clone(&setup.host.processes);
    setup.host.free_disk_pct = 40.0;
    let core = setup.build().await;
    core.metrics.guest().set_interval(Duration::ZERO);
    core.metrics.guest().set_tuning(tuning());
    core.inventory.refresh(&core.ctx()).await.unwrap();
    *processes.lock().unwrap() = vec![process(1, &vmx("web"), Some(2.0))];
    trust(&core, &server, None).await;
    let vm_id = core.store.find_vm(&core.ctx(), &vmx("web")).await.unwrap().unwrap().id;
    let id = linked_session(&core, "web guest", server.port(), Some(&password), Some(vm_id)).await;
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();

    core.metrics.collect_once().await;
    let overview = core.metrics.overview(&core.ctx()).await.unwrap();
    assert_eq!(
        overview.rows.len(),
        1,
        "the session shows on its VM's row, not on its own"
    );
    let row = &overview.rows[0];
    assert_eq!(row.kind, RowKind::Vm);
    assert_eq!(row.watched_session, Some(id));
    assert_eq!(row.sessions.len(), 1);
    assert!(row.host.is_some());
    assert!(row.guest.is_some());
    assert_eq!(row.guest_status.as_ref().unwrap().state, GuestState::Ok);
}

#[tokio::test]
async fn a_locked_vault_waits_without_connecting_then_polling_resumes() {
    let password = new_password();
    let server = linux_server(&password).await;
    let core = ssh_core().await;
    trust(&core, &server, None).await;
    let id = session(&core, "web01", server.port(), Some(&password)).await;
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();
    core.vault.lock(&core.ctx()).await.unwrap();

    core.metrics.collect_once().await;
    let status = core.metrics.guest().statuses()[&id].clone();
    assert_eq!(status.state, GuestState::VaultLocked);
    assert!(status.message.unwrap().contains("vault is locked"));
    assert_eq!(status.retry_in_secs, None, "tried again every round, at no cost");
    assert_eq!(server.connections(), 0, "no login attempt without the password");

    core.vault
        .unlock(
            &core.ctx(),
            UnlockMethod::MasterPassword(SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
    core.metrics.collect_once().await;
    assert_eq!(core.metrics.guest().statuses()[&id].state, GuestState::Ok);
}

#[tokio::test]
async fn unreachable_hosts_back_off_and_say_why() {
    // A port nothing listens on.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let core = ssh_core().await;
    core.metrics.guest().set_tuning(GuestTuning {
        backoff_min: Duration::from_secs(5),
        backoff_max: Duration::from_secs(300),
        ..tuning()
    });
    let id = session(&core, "gone", port, Some(&new_password())).await;
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();

    core.metrics.collect_once().await;
    let status = core.metrics.guest().statuses()[&id].clone();
    assert_eq!(status.state, GuestState::Unreachable, "{status:?}");
    assert!(
        status.message.as_deref().unwrap().contains("can't connect"),
        "{status:?}"
    );
    let wait = status.retry_in_secs.unwrap();
    assert!((1..=5).contains(&wait), "{wait}");

    // The next round is within the wait: no new try, same state.
    core.metrics.collect_once().await;
    assert_eq!(core.metrics.guest().statuses()[&id].state, GuestState::Unreachable);
    let overview = core.metrics.overview(&core.ctx()).await.unwrap();
    assert_eq!(
        overview.rows[0].guest_status.as_ref().unwrap().state,
        GuestState::Unreachable
    );
    assert!(overview.rows[0].guest.is_none());
}

#[tokio::test]
async fn untrusted_and_changed_host_keys_stop_guest_polling() {
    let password = new_password();
    let server = linux_server(&password).await;
    let core = ssh_core().await;
    let id = session(&core, "web01", server.port(), Some(&password)).await;
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();

    // Never trusted: no one is there to ask, so it fails and says where to trust it.
    core.metrics.collect_once().await;
    let status = core.metrics.guest().statuses()[&id].clone();
    assert_eq!(status.state, GuestState::HostKey);
    assert!(status.message.unwrap().contains("in a terminal"));
    assert!(
        core.known_hosts.list(&core.ctx()).await.unwrap().is_empty(),
        "not trusted by polling"
    );
    assert!(
        !server.log().iter().any(|l| l.starts_with("password")),
        "no login offered"
    );

    // A different key was trusted before: blocked, and audited once however often it retries.
    trust(
        &core,
        &server,
        Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    )
    .await;
    for _ in 0..3 {
        core.metrics.collect_once().await;
    }
    let status = core.metrics.guest().statuses()[&id].clone();
    assert_eq!(status.state, GuestState::HostKey);
    assert!(status.parked, "a blocked key parks the host");
    assert!(status.message.unwrap().contains("has changed"));
    let blocked = core
        .store
        .recent_audit(&core.ctx(), 50)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.event == "host_key_changed")
        .count();
    assert_eq!(blocked, 1);
}

#[tokio::test]
async fn logins_that_need_something_typed_say_what_to_save() {
    let password = new_password();
    let server = linux_server(&password).await;
    let core = ssh_core().await;
    trust(&core, &server, None).await;
    let no_password = session(&core, "asks", server.port(), None).await;
    let wrong = session(&core, "wrong", server.port(), Some("not-the-password")).await;
    core.metrics.set_watched(&core.ctx(), no_password, true).await.unwrap();
    core.metrics.set_watched(&core.ctx(), wrong, true).await.unwrap();

    core.metrics.collect_once().await;
    let statuses = core.metrics.guest().statuses();
    assert_eq!(statuses[&no_password].state, GuestState::LoginFailed);
    assert!(statuses[&no_password]
        .message
        .as_deref()
        .unwrap()
        .contains("no password is saved"));
    assert_eq!(statuses[&wrong].state, GuestState::LoginFailed);
    assert!(!statuses[&wrong]
        .message
        .as_deref()
        .unwrap()
        .contains("not-the-password"));
    assert!(statuses[&no_password].parked && statuses[&wrong].parked);
}

/// A login the host refused is not tried again on its own: a rotated password must not lock the
/// account (pam_faillock, AD) or get this PC banned (fail2ban). Retry, a new password in the vault or
/// an edited session give it one more try.
#[tokio::test]
async fn a_refused_login_parks_until_retry_or_a_new_password() {
    let password = new_password();
    let server = linux_server(&password).await;
    let core = ssh_core().await;
    trust(&core, &server, None).await;
    let id = session(&core, "web01", server.port(), Some("the-old-password")).await;
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();
    let refused = |server: &TestSshServer| {
        server
            .log()
            .iter()
            .filter(|l| l.starts_with("password") && l.ends_with("refused"))
            .count()
    };

    // Backoff is zero in these tests, so without parking every round would log in again.
    for _ in 0..4 {
        core.metrics.collect_once().await;
    }
    let status = core.metrics.guest().statuses()[&id].clone();
    assert_eq!(status.state, GuestState::LoginFailed);
    assert!(status.parked, "{status:?}");
    assert_eq!(status.retry_in_secs, None, "no automatic retry");
    assert!(status.message.as_deref().unwrap().contains("press Retry"), "{status:?}");
    let tried = refused(&server);
    assert!(tried >= 1);
    assert_eq!(server.connections(), 1, "one login, then parked");

    // Retry: one more try (still wrong), then parked again.
    core.retry_background_logins(id);
    for _ in 0..3 {
        core.metrics.collect_once().await;
    }
    assert_eq!(server.connections(), 2);
    assert!(core.metrics.guest().statuses()[&id].parked);

    // The password is replaced in the vault: tried again, and it works.
    let secret = core
        .vault
        .list(&core.ctx())
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.label == "web01 login")
        .unwrap()
        .id;
    core.vault
        .replace(&core.ctx(), secret, SecretString::new(&password))
        .await
        .unwrap();
    core.metrics.collect_once().await;
    let status = core.metrics.guest().statuses()[&id].clone();
    assert_eq!(status.state, GuestState::Ok, "{status:?}");
    assert!(!status.parked);
    assert_eq!(refused(&server), tried * 2, "no refused login after the new password");
}

/// Every background login counts against a cap per host per hour, whatever its outcome.
#[tokio::test]
async fn background_logins_are_capped_per_host_per_hour() {
    let password = new_password();
    let server = linux_server(&password).await;
    let core = ssh_core().await;
    core.login_guard.set_limits(remotely_core::login_guard::LoginLimits {
        per_hour: 2,
        window: Duration::from_secs(3600),
    });
    trust(&core, &server, None).await;
    let id = session(&core, "web01", server.port(), Some(&password)).await;
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();
    for _ in 0..2 {
        core.metrics.collect_once().await;
        assert_eq!(core.metrics.guest().statuses()[&id].state, GuestState::Ok);
        server.drop_connections();
        // The next round notices the dropped connection.
        core.metrics.collect_once().await;
    }
    for _ in 0..3 {
        core.metrics.collect_once().await;
    }
    let status = core.metrics.guest().statuses()[&id].clone();
    assert_eq!(status.state, GuestState::Paused, "{status:?}");
    assert!(
        status.message.as_deref().unwrap().contains("2 background logins"),
        "{status:?}"
    );
    assert!(status.retry_in_secs.unwrap() > 3000, "{status:?}");
    assert_eq!(server.connections(), 2);

    // Retry gets one login past the cap.
    core.retry_background_logins(id);
    core.metrics.collect_once().await;
    assert_eq!(core.metrics.guest().statuses()[&id].state, GuestState::Ok);
    assert_eq!(server.connections(), 3);
}

#[tokio::test]
async fn hosts_without_proc_are_not_linux() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = ssh_core().await;
    trust(&core, &server, None).await;
    let id = session(&core, "bsd", server.port(), Some(&password)).await;
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();
    core.metrics.collect_once().await;
    let status = core.metrics.guest().statuses()[&id].clone();
    assert_eq!(status.state, GuestState::NoData);
    assert!(status.message.unwrap().contains("Linux"));
}

#[tokio::test]
async fn watching_an_unknown_session_fails() {
    let core = ssh_core().await;
    assert!(core
        .metrics
        .set_watched(&core.ctx(), Uuid::new_v4(), true)
        .await
        .is_err());
    assert!(core.metrics.watched().await.unwrap().is_empty());
}
