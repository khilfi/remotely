//! QL-01: linking saved sessions to the VMs they reach, by IP address, end to end. Guest IPs come from
//! the fake VMware adapter (as VMware Tools would report them) and host names resolve through the fake
//! network adapter, so no DNS server, VM or SSH host is touched. Linking is the app's own data: no job, no
//! approval, an audit entry per change.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{temp_folder, vmx, Setup};
use remotely_core::bulk::TargetPicks;
use remotely_core::domain::Environment;
use remotely_core::fakes::{FakeNetwork, FakeVmware};
use remotely_core::import::{ImportRequest, ImportSource};
use remotely_core::sessions::{SessionAuth, SessionInput, SessionRecord};
use remotely_core::vm_links::VmLink;
use remotely_core::{Core, CoreError};
use uuid::Uuid;

/// web and db each have their own address; clone-a and clone-b came up with the same one (two
/// virtual networks); off is not running, so it has none.
fn lab() -> FakeVmware {
    let mut fake = FakeVmware::with_running([vmx("web"), vmx("db"), vmx("clone-a"), vmx("clone-b")]);
    for name in ["web", "db", "clone-a", "clone-b", "off"] {
        fake = fake.in_library(&vmx(name), Some(name));
    }
    fake.with_ip(&vmx("web"), "192.0.2.10")
        .with_ip(&vmx("db"), "192.0.2.20")
        .with_ip(&vmx("clone-a"), "198.51.100.7")
        .with_ip(&vmx("clone-b"), "198.51.100.7")
}

async fn lab_core(network: FakeNetwork) -> (Core, Arc<FakeNetwork>) {
    let network = Arc::new(network);
    let core = Setup::new(lab()).with_network(network.clone()).build().await;
    (core, network)
}

fn session(name: &str, host: &str) -> SessionInput {
    SessionInput {
        name: name.into(),
        folder_id: None,
        host: host.into(),
        port: 22,
        username: Some("alice".into()),
        auth: SessionAuth::Agent,
        jump_session_id: None,
        startup_command: None,
        startup_on_reconnect: false,
        prompt_hook: None,
        environment: Environment::None,
        color: None,
        tags: vec![],
        vm_id: None,
    }
}

async fn vm_id(core: &Core, name: &str) -> String {
    core.store.find_vm(&core.ctx, &vmx(name)).await.unwrap().unwrap().id
}

async fn get(core: &Core, id: Uuid) -> SessionRecord {
    core.sessions.get(&core.ctx, id).await.unwrap()
}

async fn audit_count(core: &Core) -> usize {
    core.store.recent_audit(&core.ctx, 1000).await.unwrap().len()
}

#[tokio::test]
async fn sessions_whose_host_is_or_resolves_to_a_vm_ip_are_linked_by_a_refresh() {
    let (core, network) =
        lab_core(FakeNetwork::default().with_addresses("db01.example.com", &["203.0.113.9", "192.0.2.20"])).await;
    let ctx = &core.ctx;
    // Saved before the VMs were ever listed: nothing to link to yet.
    let web = core.sessions.create(ctx, session("web", "192.0.2.10")).await.unwrap();
    let db = core
        .sessions
        .create(ctx, session("db", "DB01.example.com"))
        .await
        .unwrap();
    assert_eq!((web.vm_id.as_deref(), web.vm_link), (None, None));
    assert_eq!(db.vm_id, None);

    let report = core.inventory.refresh(ctx).await.unwrap();
    let mut linked: Vec<(&str, &str)> = report
        .links
        .linked
        .iter()
        .map(|c| (c.session_name.as_str(), c.vm_name.as_str()))
        .collect();
    linked.sort();
    assert_eq!(linked, [("db", "db"), ("web", "web")]);
    assert!(report.links.unlinked.is_empty() && report.links.ambiguous.is_empty());
    let web = get(&core, web.id).await;
    assert_eq!(web.vm_id, Some(vm_id(&core, "web").await));
    assert_eq!(web.vm_link, Some(VmLink::Auto));
    assert_eq!(get(&core, db.id).await.vm_id, Some(vm_id(&core, "db").await));

    // Audited like a setting: no tier, no job, the session and the VM as targets, and why.
    let audit = core.store.recent_audit(ctx, 2).await.unwrap();
    let mut actions: Vec<&str> = audit.iter().map(|e| e.action.as_str()).collect();
    actions.sort();
    assert_eq!(
        actions,
        [
            "Linked session 'db' to VM 'db' automatically",
            "Linked session 'web' to VM 'web' automatically"
        ]
    );
    for entry in &audit {
        assert_eq!(entry.event, "session_changed");
        assert_eq!(entry.tier, None);
        assert_eq!(entry.job_id, None);
        assert!(entry.targets_json.contains(r"C:\\VMs\\"), "{}", entry.targets_json);
    }
    let details: Vec<&str> = audit.iter().filter_map(|e| e.detail.as_deref()).collect();
    assert!(
        details.contains(&"192.0.2.10 is the VM's IP address (VMware Tools)"),
        "{details:?}"
    );
    assert!(
        details.contains(&"DB01.example.com resolves to 192.0.2.20, the VM's IP address (VMware Tools)"),
        "{details:?}"
    );
    assert!(
        core.store.recent_jobs(ctx, 10).await.unwrap().is_empty(),
        "no job: not a command"
    );

    // VMs with linked sessions now work in bulk runs, without linking by hand.
    let resolved = core
        .bulk
        .resolve(
            ctx,
            &TargetPicks {
                vm_paths: vec![vmx("web"), vmx("db"), vmx("off")],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let hosts: Vec<&str> = resolved.hosts.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(hosts, ["db", "web"]);
    let without: Vec<&str> = resolved.vms_without_session.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(without, ["off"]);

    // ...and in guest metrics: the dashboard row offers the session, marked as automatic.
    let overview = core.metrics.overview(ctx).await.unwrap();
    let row = overview.rows.iter().find(|r| r.name == "web").unwrap();
    assert_eq!(row.sessions.len(), 1);
    assert_eq!(row.sessions[0].id, web.id);
    assert!(row.sessions[0].auto);

    // Nothing changed since: the next refresh writes nothing, and the name is not looked up again.
    let before = audit_count(&core).await;
    let lookups = network.lookups().len();
    let again = core.inventory.refresh(ctx).await.unwrap();
    assert!(again.links.linked.is_empty() && again.links.unlinked.is_empty());
    assert_eq!(audit_count(&core).await, before);
    assert_eq!(network.lookups().len(), lookups, "resolved names are kept for a while");
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn a_session_is_linked_as_soon_as_it_is_saved_and_follows_its_host() {
    let (core, _) = lab_core(FakeNetwork::default().with_addresses("web01.example.com", &["192.0.2.10"])).await;
    let ctx = &core.ctx;
    core.inventory.refresh(ctx).await.unwrap();

    let by_name = core
        .sessions
        .create(ctx, session("web01", "web01.example.com"))
        .await
        .unwrap();
    assert_eq!(by_name.vm_id, Some(vm_id(&core, "web").await));
    assert_eq!(by_name.vm_link, Some(VmLink::Auto));

    // A new host: the automatic link moves with it.
    let mut input = session("web01", "192.0.2.20");
    input.vm_id = by_name.vm_id.clone();
    let moved = core.sessions.update(ctx, by_name.id, input).await.unwrap();
    assert_eq!(moved.vm_id, Some(vm_id(&core, "db").await));
    assert_eq!(moved.vm_link, Some(VmLink::Auto));

    // A host no VM has: the stale automatic link goes with the edit.
    let mut input = session("web01", "203.0.113.50");
    input.vm_id = moved.vm_id.clone();
    let elsewhere = core.sessions.update(ctx, by_name.id, input).await.unwrap();
    assert_eq!((elsewhere.vm_id, elsewhere.vm_link), (None, None));

    // A copy of an automatically linked session is linked automatically too.
    let web = core.sessions.create(ctx, session("web", "192.0.2.10")).await.unwrap();
    let copy = core.sessions.duplicate(ctx, web.id).await.unwrap();
    assert_eq!(copy.vm_id, web.vm_id);
    assert_eq!(copy.vm_link, Some(VmLink::Auto));
}

#[tokio::test]
async fn hosts_that_match_no_vm_are_not_linked() {
    let (core, network) = lab_core(FakeNetwork::default().with_addresses("mail.example.org", &["203.0.113.25"])).await;
    let ctx = &core.ctx;
    let ids = [
        core.sessions
            .create(ctx, session("outside", "203.0.113.50"))
            .await
            .unwrap()
            .id,
        core.sessions
            .create(ctx, session("mail", "mail.example.org"))
            .await
            .unwrap()
            .id,
        core.sessions
            .create(ctx, session("gone", "nowhere.example.org"))
            .await
            .unwrap()
            .id,
        core.sessions
            .create(ctx, session("local", "127.0.0.1"))
            .await
            .unwrap()
            .id,
    ];
    let before = audit_count(&core).await;
    let report = core.inventory.refresh(ctx).await.unwrap();
    assert_eq!(report.links, Default::default());
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    for id in ids {
        let s = get(&core, id).await;
        assert_eq!((s.vm_id, s.vm_link), (None, None), "{}", s.name);
    }
    assert_eq!(audit_count(&core).await, before, "nothing changed, nothing audited");
    // IP addresses are never looked up; names that don't resolve wait a while before another try.
    let mut asked = network.lookups();
    asked.sort();
    asked.dedup();
    assert_eq!(asked, ["mail.example.org", "nowhere.example.org"]);
    let lookups = network.lookups().len();
    core.inventory.refresh(ctx).await.unwrap();
    assert_eq!(network.lookups().len(), lookups);
}

#[tokio::test]
async fn several_matching_vms_are_left_for_the_user_to_pick() {
    let (core, _) = lab_core(FakeNetwork::default()).await;
    let ctx = &core.ctx;
    let clone = core
        .sessions
        .create(ctx, session("clone", "198.51.100.7"))
        .await
        .unwrap();
    let before = audit_count(&core).await;

    let report = core.inventory.refresh(ctx).await.unwrap();
    assert!(report.links.linked.is_empty());
    let (a, b) = (vm_id(&core, "clone-a").await, vm_id(&core, "clone-b").await);
    assert_eq!(report.links.ambiguous.len(), 1);
    assert_eq!(report.links.ambiguous[0].session_id, clone.id);
    assert_eq!(report.links.ambiguous[0].vm_ids, [a.clone(), b.clone()], "by name");
    assert_eq!(core.links.ambiguous(), report.links.ambiguous);
    let unlinked = get(&core, clone.id).await;
    assert_eq!((unlinked.vm_id, unlinked.vm_link), (None, None));
    assert_eq!(audit_count(&core).await, before);

    // The user picks one: a manual link, which no refresh changes.
    let picked = core.links.link(ctx, clone.id, Some(b.clone())).await.unwrap();
    assert_eq!(picked.vm_id.as_deref(), Some(b.as_str()));
    assert_eq!(picked.vm_link, Some(VmLink::Manual));
    assert!(core.links.ambiguous().is_empty());
    let entry = core.store.recent_audit(ctx, 1).await.unwrap().remove(0);
    assert_eq!(entry.action, "Linked session 'clone' to VM 'clone-b'");
    assert_eq!(entry.event, "session_changed");
    let report = core.inventory.refresh(ctx).await.unwrap();
    assert!(report.links.ambiguous.is_empty());
    assert_eq!(get(&core, clone.id).await.vm_id, Some(b));
}

#[tokio::test]
async fn a_manual_link_is_never_overwritten() {
    let (core, _) = lab_core(FakeNetwork::default()).await;
    let ctx = &core.ctx;
    core.inventory.refresh(ctx).await.unwrap();
    let (web_vm, db_vm) = (vm_id(&core, "web").await, vm_id(&core, "db").await);

    // Chosen in the editor: kept although the host is web's address.
    let mut chosen = session("chosen", "192.0.2.10");
    chosen.vm_id = Some(db_vm.clone());
    let chosen = core.sessions.create(ctx, chosen).await.unwrap();
    assert_eq!(chosen.vm_link, Some(VmLink::Manual));

    // Linked automatically, then confirmed.
    let confirmed = core
        .sessions
        .create(ctx, session("confirmed", "192.0.2.10"))
        .await
        .unwrap();
    assert_eq!(confirmed.vm_link, Some(VmLink::Auto));
    let confirmed = core.links.confirm(ctx, confirmed.id).await.unwrap();
    assert_eq!(confirmed.vm_link, Some(VmLink::Manual));
    assert_eq!(confirmed.vm_id.as_deref(), Some(web_vm.as_str()));
    assert_eq!(
        core.store.recent_audit(ctx, 1).await.unwrap()[0].action,
        "Linked session 'confirmed' to VM 'web'"
    );

    // Linked automatically, then moved by hand to another VM.
    let moved = core.sessions.create(ctx, session("moved", "192.0.2.10")).await.unwrap();
    let moved = core.links.link(ctx, moved.id, Some(db_vm.clone())).await.unwrap();

    // Linked automatically, then removed: stays unlinked.
    let removed = core
        .sessions
        .create(ctx, session("removed", "192.0.2.10"))
        .await
        .unwrap();
    let removed = core.links.link(ctx, removed.id, None).await.unwrap();
    assert_eq!(
        (removed.vm_id.as_deref(), removed.vm_link),
        (None, Some(VmLink::Manual))
    );
    assert_eq!(
        core.store.recent_audit(ctx, 1).await.unwrap()[0].action,
        "Unlinked session 'removed' from VM 'web'"
    );

    let before = audit_count(&core).await;
    let report = core.inventory.refresh(ctx).await.unwrap();
    assert_eq!(report.links, Default::default());
    assert_eq!(audit_count(&core).await, before);
    assert_eq!(get(&core, chosen.id).await.vm_id, Some(db_vm.clone()));
    assert_eq!(get(&core, confirmed.id).await.vm_id, Some(web_vm.clone()));
    assert_eq!(get(&core, moved.id).await.vm_id, Some(db_vm.clone()));
    assert_eq!(get(&core, removed.id).await.vm_id, None);

    // Saving other fields keeps the user's choice too.
    let mut input = session("chosen (renamed)", "192.0.2.10");
    input.vm_id = Some(db_vm.clone());
    let renamed = core.sessions.update(ctx, chosen.id, input).await.unwrap();
    assert_eq!((renamed.vm_id, renamed.vm_link), (Some(db_vm), Some(VmLink::Manual)));

    // A removal applies to the host it was made for: a new host can be linked again.
    let mut input = session("removed", "192.0.2.10");
    input.port = 2222;
    let same_host = core.sessions.update(ctx, removed.id, input).await.unwrap();
    assert_eq!(same_host.vm_id, None);
    let new_host = core
        .sessions
        .update(ctx, removed.id, session("removed", "192.0.2.20"))
        .await
        .unwrap();
    assert_eq!(new_host.vm_link, Some(VmLink::Auto));

    // Only an automatic link can be confirmed, and only a listed VM chosen.
    let plain = core
        .sessions
        .create(ctx, session("plain", "203.0.113.50"))
        .await
        .unwrap();
    assert!(matches!(
        core.links.confirm(ctx, plain.id).await,
        Err(CoreError::InvalidInput(_))
    ));
    assert!(matches!(
        core.links.link(ctx, plain.id, Some("no-such-vm".into())).await,
        Err(CoreError::InvalidInput(_))
    ));
    assert!(core.store.verify_audit_chain().await.unwrap().ok);
}

#[tokio::test]
async fn imported_sessions_are_linked_in_one_pass() {
    let (core, network) = lab_core(FakeNetwork::default().with_addresses("web.example.com", &["192.0.2.10"])).await;
    let ctx = &core.ctx;
    core.inventory.refresh(ctx).await.unwrap();
    let dir = temp_folder("vm-links-import");
    let config = dir.join("config");
    std::fs::write(
        &config,
        "Host web\n  HostName web.example.com\n  User alice\n\nHost db\n  HostName 192.0.2.20\n  User bob\n\nHost other\n  HostName 203.0.113.50\n",
    )
    .unwrap();
    let preview = core
        .import
        .preview_file(ctx, ImportSource::Openssh, &config)
        .await
        .unwrap();
    let report = core
        .import
        .commit(
            ctx,
            &ImportRequest {
                preview_id: preview.id,
                rows: preview.rows.iter().map(|r| r.index).collect(),
                folder_id: None,
                add_keys: false,
                keep_startup: vec![],
            },
            &core.sessions,
            &core.vault,
        )
        .await
        .unwrap();
    assert_eq!(report.created, 3);
    let sessions = core.sessions.list(ctx, &Default::default()).await.unwrap();
    let links: Vec<(&str, Option<VmLink>)> = sessions.iter().map(|s| (s.name.as_str(), s.vm_link)).collect();
    assert_eq!(
        links,
        [("db", Some(VmLink::Auto)), ("other", None), ("web", Some(VmLink::Auto))]
    );
    assert_eq!(network.lookups(), ["web.example.com"], "one lookup for the batch");
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_dns_server_that_does_not_answer_does_not_hold_up_a_refresh() {
    let network = FakeNetwork::default()
        .with_addresses("web01.example.com", &["192.0.2.10"])
        .with_lookup_delay(Duration::from_secs(60));
    let (core, network) = lab_core(network).await;
    let ctx = &core.ctx;
    // Saved before any VM has an address: nothing could match, so nothing is looked up.
    let started = Instant::now();
    let mut ids = Vec::new();
    for n in 0..20 {
        let name = format!("web{n:02}.example.com");
        ids.push(core.sessions.create(ctx, session(&name, &name)).await.unwrap().id);
    }
    assert!(network.lookups().is_empty());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );

    // 20 names, each waiting for an answer that never comes: the refresh gives up on them together.
    let started = Instant::now();
    let report = core.inventory.refresh(ctx).await.unwrap();
    let took = started.elapsed();
    assert!(took < Duration::from_secs(10), "took {took:?}");
    assert_eq!(network.lookups().len(), 20);
    assert!(report.links.linked.is_empty());
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    for id in ids {
        assert_eq!(get(&core, id).await.vm_id, None, "unknown this time; tried again later");
    }
}

#[tokio::test]
async fn lookups_done_in_time_count_and_a_slow_one_is_kept_for_the_next_pass() {
    // P3: web answers at once, db only after the pass stopped waiting.
    let network = FakeNetwork::default()
        .with_addresses("web.lab.test", &["192.0.2.10"])
        .with_addresses("db.lab.test", &["192.0.2.20"])
        .with_slow_name("db.lab.test", Duration::from_millis(800));
    let (core, network) = lab_core(network).await;
    let ctx = &core.ctx;
    core.links.set_lookups_deadline(Duration::from_millis(200));
    let web = core
        .sessions
        .create(ctx, session("web", "web.lab.test"))
        .await
        .unwrap()
        .id;
    let db = core
        .sessions
        .create(ctx, session("db", "db.lab.test"))
        .await
        .unwrap()
        .id;

    core.inventory.refresh(ctx).await.unwrap();
    assert_eq!(
        get(&core, web).await.vm_id,
        Some(vm_id(&core, "web").await),
        "a lookup that finished in time counts, though another one did not"
    );
    assert_eq!(get(&core, db).await.vm_id, None, "unknown this time");
    let looked_up = network.lookups().len();

    // While db's lookup is still out, another pass asks no one: web comes from the cache, db waits.
    core.inventory.refresh(ctx).await.unwrap();
    assert_eq!(network.lookups().len(), looked_up, "{:?}", network.lookups());

    // Once it has finished, its answer links db without a new lookup.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    core.inventory.refresh(ctx).await.unwrap();
    assert_eq!(get(&core, db).await.vm_id, Some(vm_id(&core, "db").await));
    assert_eq!(network.lookups().len(), looked_up);
}

#[tokio::test]
async fn a_session_behind_a_jump_host_is_never_looked_up() {
    // SS-07: its name means something on the far side only; asking this PC's resolvers would send it
    // out on the local network.
    let network = FakeNetwork::default()
        .with_addresses("bastion.lab.test", &["203.0.113.5"])
        .with_addresses("db.internal.test", &["192.0.2.20"]);
    let (core, network) = lab_core(network).await;
    let ctx = &core.ctx;
    let bastion = core
        .sessions
        .create(ctx, session("bastion", "bastion.lab.test"))
        .await
        .unwrap()
        .id;
    let behind = SessionInput {
        jump_session_id: Some(bastion),
        ..session("db behind bastion", "db.internal.test")
    };
    let db = core.sessions.create(ctx, behind).await.unwrap().id;
    let by_ip = SessionInput {
        jump_session_id: Some(bastion),
        ..session("web behind bastion", "192.0.2.10")
    };
    let web = core.sessions.create(ctx, by_ip).await.unwrap().id;

    core.inventory.refresh(ctx).await.unwrap();
    assert!(
        !network.lookups().iter().any(|h| h == "db.internal.test"),
        "{:?}",
        network.lookups()
    );
    assert_eq!(get(&core, db).await.vm_id, None);
    // An IP address needs no lookup, so it still links.
    assert_eq!(get(&core, web).await.vm_id, Some(vm_id(&core, "web").await));
}
