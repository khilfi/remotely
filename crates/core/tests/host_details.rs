//! Host details (MO-13, MO-14) and memory charts (MO-15), end to end: the real russh adapter against
//! SSH servers on 127.0.0.1 that describe an Ubuntu or RHEL host (`fakes::ssh_server::host`), the fake
//! hypervisors for VM hardware, and the fake host counters for this PC's paging files. No real host or
//! VM is read, and nothing goes through the command bus: these are reads.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::{vmx, Setup};
use remotely_core::adapters::remote::{AgentSource, PtySize};
use remotely_core::adapters::vm_hardware::{VirtualDisk, VirtualNic, VmHardware};
use remotely_core::adapters::vmware::VmxInfo;
use remotely_core::domain::{Environment, PowerState};
use remotely_core::fakes::ssh_server::host::HostFixture;
use remotely_core::fakes::ssh_server::TestSshServer;
use remotely_core::fakes::{FakeVirtualBox, FakeVmware};
use remotely_core::host_details::admin::{PackageManager, ServiceManager};
use remotely_core::host_details::{CollectedBy, SpecsTuning, Via};
use remotely_core::known_hosts::HostKey;
use remotely_core::metrics::procfs::samples;
use remotely_core::metrics::{GuestTuning, MetricSource};
use remotely_core::policy::{ActionKind, PolicyEngine, PolicyRules};
use remotely_core::presentation::Presentation;
use remotely_core::sessions::{SessionAuth, SessionInput};
use remotely_core::terminal::{TerminalEvent, TerminalStatus, TerminalTuning};
use remotely_core::vault::{SecretKind, SecretString};
use remotely_core::Core;
use tokio::time::timeout;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);
const SIZE: PtySize = PtySize { cols: 80, rows: 24 };
const VBOX: &str = "3f0c1a2b-1111-4222-8333-444455556666";

fn new_password() -> String {
    format!("pw-{}", Uuid::new_v4().simple())
}

fn no_agent() -> AgentSource {
    AgentSource::NamedPipe(format!(r"\\.\pipe\remotely-test-none-{}", Uuid::new_v4()))
}

async fn core_with(vmware: FakeVmware, virtualbox: FakeVirtualBox) -> Core {
    let core = Setup::new(vmware)
        .with_virtualbox(virtualbox)
        .with_real_vault()
        .with_ssh()
        .build()
        .await;
    core.terminals.set_tuning(TerminalTuning {
        connect_timeout: Duration::from_secs(5),
        first_retry: Duration::from_millis(50),
        max_retry: Duration::from_millis(200),
        max_attempts: 3,
        slow_retry: Duration::from_millis(200),
        slow_attempts: 0,
        wake_spread: Duration::from_millis(50),
        keepalive_interval: None,
        keepalive_max: 2,
        agent: no_agent(),
        host_key_wait: Duration::from_secs(10),
        notify_timing: None,
    });
    core.metrics.guest().set_interval(Duration::ZERO);
    core.metrics.guest().set_tuning(GuestTuning {
        connect_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(5),
        round_budget: Duration::from_secs(5),
        backoff_min: Duration::from_millis(50),
        backoff_max: Duration::from_millis(200),
        parallel: 4,
        agent: no_agent(),
    });
    core.host_details.collector().set_tuning(SpecsTuning {
        agent: no_agent(),
        ..SpecsTuning::default()
    });
    core
}

async fn core() -> Core {
    core_with(FakeVmware::default(), FakeVirtualBox::new()).await
}

/// An SSH server describing `fixture`, with alice's password.
async fn server(password: &str, fixture: HostFixture) -> TestSshServer {
    TestSshServer::start()
        .await
        .with_password("alice", password)
        .with_hostname("web01")
        .with_host_facts(fixture)
}

async fn trust(core: &Core, server: &TestSshServer) {
    let key = HostKey {
        host: "127.0.0.1".into(),
        port: server.port(),
        key_type: "ssh-ed25519".into(),
        fingerprint: server.host_key_fingerprint(),
    };
    core.known_hosts.trust(&core.ctx(), &key, None).await.unwrap();
}

/// A session on 127.0.0.1 logging in as alice with `password` from the vault.
async fn session(core: &Core, server: &TestSshServer, password: &str, vm_id: Option<String>) -> Uuid {
    let id = core
        .vault
        .add(
            &core.ctx(),
            SecretKind::Password,
            "lab login",
            SecretString::new(password),
        )
        .await
        .unwrap()
        .id;
    core.sessions
        .create(
            &core.ctx(),
            SessionInput {
                name: "web01".into(),
                folder_id: None,
                host: "127.0.0.1".into(),
                port: server.port(),
                username: Some("alice".into()),
                auth: SessionAuth::Password { password_id: Some(id) },
                jump_session_id: None,
                jump_direct: false,
                startup_command: None,
                startup_on_reconnect: false,
                prompt_hook: None,
                environment: Environment::Lab,
                color: None,
                tags: vec![],
                vm_id,
            },
        )
        .await
        .unwrap()
        .id
}

/// Waits until the session's facts are stored (or the wait runs out).
async fn stored_specs(core: &Core, id: Uuid) -> remotely_core::host_details::SessionSpecs {
    timeout(WAIT, async {
        loop {
            if let Some(specs) = core.host_details.session_specs(&core.ctx(), id).await.unwrap() {
                return specs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the facts were never stored")
}

#[tokio::test]
async fn a_terminal_reads_the_hosts_facts_beside_its_shell_without_showing_them() {
    let password = new_password();
    let server = server(&password, HostFixture::ubuntu()).await;
    let core = core().await;
    trust(&core, &server).await;
    let id = session(&core, &server, &password, None).await;

    let handle = core.terminals.open(&core.ctx(), id, SIZE).await.unwrap();
    let mut output = handle.output;
    let mut events = handle.events;
    timeout(WAIT, async {
        while let Some(event) = events.recv().await {
            if matches!(
                event,
                TerminalEvent::Status {
                    status: TerminalStatus::Connected
                }
            ) {
                break;
            }
        }
    })
    .await
    .unwrap();

    let read = stored_specs(&core, id).await;
    assert_eq!(read.collected_by, CollectedBy::Terminal);
    assert_eq!(read.specs.os_name().as_deref(), Some("Ubuntu 24.04.1 LTS"));
    assert_eq!(read.specs.kernel.as_deref(), Some("6.8.0-45-generic"));
    assert_eq!(read.specs.hostname.as_deref(), Some("web01"));
    assert_eq!(read.specs.cpu.logical_cpus, Some(4));
    assert_eq!(read.specs.memory.total_bytes, Some(8_131_116 * 1024));
    assert_eq!(read.specs.filesystems.len(), 3);
    assert_eq!(read.specs.virtualization.as_deref(), Some("vmware"));
    assert!(read.booted_at.is_some());

    // The terminal showed none of it: it ran on an exec channel, never in the shell.
    let mut shown = Vec::new();
    while let Ok(Some(chunk)) = timeout(Duration::from_millis(300), output.recv()).await {
        shown.extend_from_slice(&chunk);
    }
    let shown = String::from_utf8_lossy(&shown);
    for leak in [
        "@@",
        "lscpu",
        "os-release",
        "lsblk",
        "Ubuntu 24.04",
        "systemd-detect-virt",
    ] {
        assert!(!shown.contains(leak), "{leak:?} in the terminal: {shown:?}");
    }
    let log = server.log();
    assert!(
        !log.iter().any(|l| l.starts_with("line ") && l.contains("lscpu")),
        "nothing typed into the shell: {log:?}"
    );

    // A second terminal within ten minutes reads nothing again.
    let second = core.terminals.open(&core.ctx(), id, SIZE).await.unwrap();
    let mut second_events = second.events;
    timeout(WAIT, async {
        while let Some(event) = second_events.recv().await {
            if matches!(
                event,
                TerminalEvent::Status {
                    status: TerminalStatus::Connected
                }
            ) {
                break;
            }
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let again = core.host_details.session_specs(&core.ctx(), id).await.unwrap().unwrap();
    assert_eq!(again.collected_at, read.collected_at, "not read twice in ten minutes");

    // MO-14 on the open terminal's connection: no new login.
    let logins = server.connections();
    let admin = core.host_details.admin(&core.ctx(), id).await.unwrap();
    assert_eq!(admin.via, Via::Terminal);
    assert_eq!(server.connections(), logins);
    assert_eq!(admin.details.service_manager, ServiceManager::Systemd);
    assert_eq!(admin.details.failed.len(), 1);
    assert!(admin
        .details
        .ports
        .iter()
        .any(|p| p.port == 22 && p.processes == ["sshd"]));
    assert!(admin.details.ports_need_root);
    assert_eq!(admin.details.users.len(), 4);
    assert_eq!(admin.details.top_cpu[0].command, "java");
    core.terminals.close_all().await;
}

#[tokio::test]
async fn refresh_without_a_connection_logs_in_once_and_keeps_it_for_the_next_reads() {
    let password = new_password();
    let server = server(&password, HostFixture::rhel()).await;
    let core = core().await;
    trust(&core, &server).await;
    let id = session(&core, &server, &password, None).await;
    assert!(core
        .host_details
        .session_specs(&core.ctx(), id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(server.connections(), 0, "nothing reads on its own");

    let read = core.host_details.refresh_session(&core.ctx(), id).await.unwrap();
    assert_eq!(read.collected_by, CollectedBy::Refresh);
    assert_eq!(read.specs.os.id.as_deref(), Some("rhel"));
    // No lscpu here: /proc/cpuinfo; no lsblk JSON: its KEY="value" form.
    assert_eq!(read.specs.cpu.logical_cpus, Some(4));
    assert_eq!(read.specs.cpu.sockets, Some(1));
    assert!(read.specs.disks.iter().any(|d| d.name == "centos-root" && d.depth == 2));
    assert_eq!(server.connections(), 1);

    let admin = core.host_details.admin(&core.ctx(), id).await.unwrap();
    assert_eq!(admin.via, Via::OwnConnection);
    let updates = core.host_details.updates(&core.ctx(), id).await.unwrap();
    assert_eq!(updates.report.manager, Some(PackageManager::Dnf));
    assert_eq!(updates.report.packages.len(), 3);
    assert_eq!(updates.report.error, None);
    core.host_details.refresh_session(&core.ctx(), id).await.unwrap();
    assert_eq!(server.connections(), 1, "one login for every read the panel asked for");

    core.host_details.release(id).await;
    core.host_details.admin(&core.ctx(), id).await.unwrap();
    assert_eq!(
        server.connections(),
        2,
        "after the panel let go, a new read logs in again"
    );
}

#[tokio::test]
async fn pending_apt_updates_say_which_are_security_ones_and_when_the_lists_were_refreshed() {
    let password = new_password();
    let server = server(&password, HostFixture::ubuntu()).await;
    let core = core().await;
    trust(&core, &server).await;
    let id = session(&core, &server, &password, None).await;
    let updates = core.host_details.updates(&core.ctx(), id).await.unwrap();
    assert_eq!(updates.report.manager, Some(PackageManager::Apt));
    assert_eq!(updates.report.packages.len(), 2);
    assert_eq!(updates.report.security_count, 1);
    assert_eq!(updates.report.lists_refreshed_unix, Some(1_792_600_000));
}

#[tokio::test]
async fn the_dashboard_reads_old_facts_on_its_kept_connection_and_shares_it() {
    let password = new_password();
    let server = server(&password, HostFixture::ubuntu()).await;
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
    let core = core().await;
    trust(&core, &server).await;
    let id = session(&core, &server, &password, None).await;
    core.metrics.set_watched(&core.ctx(), id, true).await.unwrap();

    core.metrics.collect_once().await;
    let read = stored_specs(&core, id).await;
    assert_eq!(read.collected_by, CollectedBy::Dashboard);
    assert_eq!(server.connections(), 1);

    // MO-15: swap from /proc/meminfo, and the guest's total as the memory there is.
    let guest = core.metrics.hub().latest(MetricSource::Guest, &id.to_string()).unwrap();
    assert_eq!(guest.swap_total_bytes, Some(2_097_148 * 1024));
    assert_eq!(guest.swap_used_bytes, Some((2_097_148 - 1_572_860) * 1024));
    let point = core.metrics.hub().series(MetricSource::Guest, &id.to_string())[0];
    assert_eq!(point.mem_total_bytes, Some(4_028_180 * 1024));
    assert_eq!(point.swap_total_bytes, Some(2_097_148 * 1024));

    // The dashboard row carries the one-line summary.
    let overview = core.metrics.overview(&core.ctx()).await.unwrap();
    let row = &overview.rows[0];
    assert_eq!(row.vcpus, Some(4));
    assert_eq!(row.memsize_mb, Some(3933), "the MO-02 sample's MemTotal");
    assert_eq!(row.guest_os.as_deref(), Some("Ubuntu 24.04"));
    assert!(row.specs_at.is_some());

    // Refresh and admin reads use the dashboard's connection.
    let refreshed = core.host_details.refresh_session(&core.ctx(), id).await.unwrap();
    assert_eq!(refreshed.collected_by, CollectedBy::Refresh);
    assert_eq!(
        core.host_details.admin(&core.ctx(), id).await.unwrap().via,
        Via::Dashboard
    );
    assert_eq!(server.connections(), 1);
}

#[tokio::test]
async fn a_host_that_is_not_linux_stores_nothing() {
    let password = new_password();
    let server = TestSshServer::start().await.with_password("alice", &password);
    let core = core().await;
    trust(&core, &server).await;
    let id = session(&core, &server, &password, None).await;
    let err = core.host_details.refresh_session(&core.ctx(), id).await.unwrap_err();
    assert!(err.to_string().contains("not like Linux"), "{err}");
    assert!(core
        .host_details
        .session_specs(&core.ctx(), id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_refresh_that_needs_the_vault_says_so_without_connecting() {
    let password = new_password();
    let server = server(&password, HostFixture::ubuntu()).await;
    let core = core().await;
    trust(&core, &server).await;
    let id = session(&core, &server, &password, None).await;
    core.vault.lock(&core.ctx()).await.unwrap();
    let err = core.host_details.refresh_session(&core.ctx(), id).await.unwrap_err();
    assert_eq!(err.code(), "vault_locked");
    assert_eq!(server.connections(), 0);
}

#[tokio::test]
async fn the_read_only_lock_does_not_stop_host_details() {
    let password = new_password();
    let server = server(&password, HostFixture::ubuntu()).await;
    let core = core().await;
    trust(&core, &server).await;
    let id = session(&core, &server, &password, None).await;
    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    assert!(core.host_details.refresh_session(&core.ctx(), id).await.is_ok());
    assert!(core.host_details.admin(&core.ctx(), id).await.is_ok());
}

#[test]
fn every_command_host_details_runs_classifies_as_read_only() {
    use remotely_core::host_details::{admin, linux};
    let policy = PolicyEngine::new(PolicyRules::default()).unwrap();
    for script in [linux::SPECS_SCRIPT, admin::ADMIN_SCRIPT, admin::UPDATES_SCRIPT] {
        assert_eq!(policy.classify_script(script), ActionKind::ExecReadOnly, "{script}");
    }
}

fn web_hardware() -> VmHardware {
    VmHardware {
        guest_os: Some("ubuntu-64".into()),
        guest_os_name: Some("Ubuntu 24.04.1 LTS".into()),
        guest_kernel: Some("6.8.0-45-generic".into()),
        vcpus: Some(4),
        cores_per_socket: Some(2),
        memory_mb: Some(8192),
        firmware: Some("UEFI".into()),
        hardware_version: Some("21".into()),
        disks: vec![VirtualDisk {
            slot: "scsi0:0".into(),
            path: r"C:\VMs\web\web.vmdk".into(),
            format: Some("monolithicSparse".into()),
            provisioned_bytes: Some(40 << 30),
            on_disk_bytes: Some(12 << 30),
            files: 1,
            delta: false,
            problem: None,
            ..VirtualDisk::default()
        }],
        nics: vec![VirtualNic {
            slot: "ethernet0".into(),
            connection: Some("nat".into()),
            model: Some("vmxnet3".into()),
            mac: Some("00:0c:29:ab:cd:ef".into()),
            connected: None,
            ..VirtualNic::default()
        }],
        ..VmHardware::default()
    }
}

#[tokio::test]
async fn vm_hardware_is_read_from_its_files_and_kept_for_when_they_cant_be() {
    let fake = FakeVmware::with_running([vmx("web")])
        .in_library(&vmx("web"), Some("web"))
        .with_vmx(
            &vmx("web"),
            VmxInfo {
                display_name: Some("web".into()),
                num_vcpus: Some(4),
                memsize_mb: Some(8192),
                ..Default::default()
            },
        )
        .with_hardware(&vmx("web"), web_hardware());
    let fake = std::sync::Arc::new(fake);
    let core = Setup {
        vmware: std::sync::Arc::clone(&fake),
        ..Setup::new(FakeVmware::default())
    }
    .build()
    .await;
    core.inventory.refresh(&core.ctx()).await.unwrap();

    let read = core.host_details.vm_specs(&core.ctx(), &vmx("web")).await.unwrap();
    assert!(!read.stored);
    assert_eq!(read.problem, None);
    assert_eq!(read.hardware, web_hardware());
    assert_eq!(read.hardware.sockets(), Some(2));
    assert!(read.guest.is_none());

    // The files can't be read now: what was read before shows, with why.
    fake.set_hardware_failing(true);
    let offline = core.host_details.vm_specs(&core.ctx(), &vmx("web")).await.unwrap();
    assert!(offline.stored);
    assert_eq!(offline.collected_at, read.collected_at);
    assert_eq!(offline.hardware, web_hardware());
    assert!(offline.problem.unwrap().contains("not there"));
    assert!(core
        .host_details
        .vm_specs(&core.ctx(), r"C:\VMs\nope\nope.vmx")
        .await
        .is_err());
}

#[tokio::test]
async fn the_topology_map_reads_each_vms_networks_once_then_uses_what_was_read() {
    // QL-21: R3's adapters (connection and network name) for every VM, Workstation and VirtualBox alike.
    let mut hardware = web_hardware();
    hardware.nics.push(VirtualNic {
        slot: "ethernet1".into(),
        connection: Some("custom (VMnet2)".into()),
        network_name: Some("VMnet2".into()),
        ..VirtualNic::default()
    });
    let fake = FakeVmware::with_running([vmx("web")])
        .in_library(&vmx("web"), Some("web"))
        .with_hardware(&vmx("web"), hardware.clone());
    let fake = std::sync::Arc::new(fake);
    let vbox = FakeVirtualBox::new().with_vm(VBOX, "vbox-web", PowerState::Running);
    let core = Setup {
        vmware: std::sync::Arc::clone(&fake),
        virtualbox: std::sync::Arc::new(vbox),
        ..Setup::new(FakeVmware::default())
    }
    .build()
    .await;
    core.inventory.refresh(&core.ctx()).await.unwrap();

    let first = core.host_details.vm_networks(&core.ctx(), false).await.unwrap();
    assert_eq!(first.len(), 2);
    let web = first.iter().find(|v| v.vmx_path == vmx("web")).unwrap();
    assert!(!web.stored, "never read before: read now");
    assert_eq!(web.nics, hardware.nics);
    assert_eq!(web.nics[1].network_name.as_deref(), Some("VMnet2"));
    let vb = first.iter().find(|v| v.vmx_path == VBOX).unwrap();
    assert_eq!(vb.nics[0].connection.as_deref(), Some("nat"));

    // Opening the map again reads nothing: the files may be gone and it still shows what was read.
    fake.set_hardware_failing(true);
    let again = core.host_details.vm_networks(&core.ctx(), false).await.unwrap();
    let web = again.iter().find(|v| v.vmx_path == vmx("web")).unwrap();
    assert!(web.stored);
    assert_eq!(web.problem, None, "nothing was read");
    assert_eq!(web.nics, hardware.nics);

    // A Refresh reads every VM; one that can't be read keeps what was read before, and says why.
    let fresh = core.host_details.vm_networks(&core.ctx(), true).await.unwrap();
    let web = fresh.iter().find(|v| v.vmx_path == vmx("web")).unwrap();
    assert!(web.stored);
    assert!(web.problem.as_deref().unwrap().contains("not there"));
    assert_eq!(web.nics, hardware.nics);
    let vb = fresh.iter().find(|v| v.vmx_path == VBOX).unwrap();
    assert!(!vb.stored && vb.problem.is_none());
}

#[tokio::test]
async fn a_virtualbox_vm_shows_its_disks_adapters_and_guest_os() {
    let fake = FakeVirtualBox::new()
        .with_vm(VBOX, "vbox-web", PowerState::Running)
        .with_guest_property(VBOX, "/VirtualBox/GuestInfo/OS/Product", "Linux");
    let fake = fake.with_guest_property(VBOX, "/VirtualBox/GuestInfo/OS/Release", "6.8.0-45-generic");
    let core = core_with(FakeVmware::default(), fake).await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    let read = core.host_details.vm_specs(&core.ctx(), VBOX).await.unwrap();
    assert_eq!(read.hardware.vcpus, Some(2));
    assert_eq!(read.hardware.memory_mb, Some(2048));
    assert_eq!(read.hardware.firmware.as_deref(), Some("BIOS"));
    assert_eq!(read.hardware.guest_kernel.as_deref(), Some("6.8.0-45-generic"));
    assert_eq!(
        read.hardware.guest_os_name, None,
        "\"Linux\" says less than the OS type"
    );
    assert_eq!(read.hardware.guest_os.as_deref(), Some("Ubuntu (64-bit)"));
    assert_eq!(read.hardware.nics[0].mac.as_deref(), Some("08:00:27:00:00:01"));
    assert_eq!(read.hardware.nics[0].model.as_deref(), Some("82540EM"));
    assert_eq!(read.hardware.disks[0].slot, "SATA-0-0");
    assert_eq!(
        read.hardware.disks[0].problem.as_deref(),
        Some("the disk file is not there"),
        "the fake's disk image isn't on this PC"
    );
}

#[tokio::test]
async fn a_vm_shows_its_guests_facts_from_a_linked_session() {
    let password = new_password();
    let server = server(&password, HostFixture::ubuntu()).await;
    let fake = FakeVmware::with_running([vmx("web")])
        .in_library(&vmx("web"), Some("web"))
        .with_hardware(&vmx("web"), web_hardware());
    let core = core_with(fake, FakeVirtualBox::new()).await;
    core.inventory.refresh(&core.ctx()).await.unwrap();
    let vm = core.store.find_vm(&core.ctx(), &vmx("web")).await.unwrap().unwrap();
    trust(&core, &server).await;
    let id = session(&core, &server, &password, Some(vm.id.clone())).await;
    core.host_details.refresh_session(&core.ctx(), id).await.unwrap();

    let read = core.host_details.vm_specs(&core.ctx(), &vmx("web")).await.unwrap();
    let guest = read.guest.expect("the linked session's facts");
    assert_eq!(guest.session_id, id);
    assert_eq!(read.guest_session_name.as_deref(), Some("web01"));
    assert_eq!(guest.specs.filesystems[0].mount, "/");
}

#[tokio::test]
async fn this_pcs_ram_and_paging_files_are_kept_round_by_round() {
    let core = core().await;
    core.metrics.collect_once().await;
    core.metrics.collect_once().await;
    let points = core.metrics.hub().this_pc_series();
    assert_eq!(points.len(), 2);
    assert_eq!(points[0].mem_total_bytes, Some(32 << 30));
    assert_eq!(points[0].mem_bytes, Some(8 << 30));
    assert_eq!(points[0].swap_total_bytes, Some(4 << 30));
    assert_eq!(points[0].swap_used_bytes, Some(1 << 30));
    let capacity = core.metrics.capacity(&core.ctx()).await;
    let paging = capacity.paging.expect("the paging files");
    assert_eq!(paging.files[0].path, r"C:\pagefile.sys");
    assert_eq!(paging.commit_limit_bytes, 36 << 30);
}
