//! FD-14: updates from the repository's GitHub Releases, which are public, so checks and installs need
//! no token; the read-only token from the vault is optional (a higher API limit, and a repository
//! that went private again). The GitHub client runs against `fakes::github_server::FakeGithub` on
//! 127.0.0.1, and the core's token handling against `FakeUpdater`; tokens are made up at run time
//! and never committed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io;
use std::sync::{Arc, Mutex};

use common::{wait_finished, Setup, VAULT_PASSWORD};
use remotely_core::adapters::github::{GithubReleases, GithubRepo};
use remotely_core::command_bus::{ApprovalAnswers, Command, SubmitOutcome};
use remotely_core::fakes::github_server::{FakeGithub, TokenAccess};
use remotely_core::fakes::{FakeUpdater, FakeVmware};
use remotely_core::jobs::JobStatus;
use remotely_core::updates::{UpdateCheck, UpdateTokenInfo, UPDATE_TOKEN_LABEL};
use remotely_core::vault::{SecretKind, SecretString, UnlockMethod, VaultStatus};
use remotely_core::{Core, CoreError};
use sqlx::{Column, Row};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Shaped like a fine-grained token, new on every call (gitleaks never sees one in the source).
fn new_token() -> String {
    format!("github_pat_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn day(offset: i64) -> String {
    (OffsetDateTime::now_utc().date() + Duration::days(offset)).to_string()
}

fn secret(token: &str) -> SecretString {
    SecretString::new(token)
}

/// A private repository with a release, as from 0.2.0 to 0.4.0; `set_public(true)` for today's.
async fn github() -> (FakeGithub, GithubReleases) {
    let fake = FakeGithub::start("alice", "remotely").await;
    fake.publish(
        "v0.9.0",
        "Remotely 0.9.0",
        vec![
            ("latest.json", b"{}".to_vec()),
            ("Remotely_0.9.0_x64-setup.exe", b"installer".to_vec()),
        ],
    );
    let client = GithubReleases::new(fake.api_url(), fake.repo())
        .unwrap()
        .with_web(fake.web_url());
    (fake, client)
}

/// Every text and blob in every table, as text.
async fn database_text(core: &Core) -> String {
    let pool = core.store.pool();
    let tables: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table'")
        .fetch_all(pool)
        .await
        .unwrap();
    let mut out = String::new();
    for table in tables {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT * FROM \"{table}\"")))
            .fetch_all(pool)
            .await
            .unwrap();
        for row in &rows {
            for column in row.columns() {
                let i = column.ordinal();
                if let Ok(Some(text)) = row.try_get::<Option<String>, _>(i) {
                    out.push_str(&text);
                } else if let Ok(Some(bytes)) = row.try_get::<Option<Vec<u8>>, _>(i) {
                    out.push_str(&String::from_utf8_lossy(&bytes));
                }
                out.push('\n');
            }
        }
    }
    out
}

// ---- The GitHub client without a token -----------------------------------------------------------------

#[tokio::test]
async fn a_public_repository_is_read_without_a_token() {
    let (fake, client) = github().await;
    fake.set_public(true);

    let lookup = client.latest_release(None).await.unwrap();
    let release = lookup.release.unwrap();
    assert_eq!(release.tag_name, "v0.9.0");
    assert_eq!(lookup.token_expires_on, None);
    let installer = release.asset("Remotely_0.9.0_x64-setup.exe").unwrap();
    let link = client.public_url(&release, &installer.url).unwrap();
    assert_eq!(link, fake.download_link("v0.9.0", "Remotely_0.9.0_x64-setup.exe"));

    // What tauri-plugin-updater does without a token: the download link redirects to the storage.
    let http = reqwest::Client::builder()
        .user_agent("tauri-plugin-updater")
        .build()
        .unwrap();
    let response = http
        .get(link)
        .headers(client.download_headers(None).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"installer");

    let requests = fake.requests();
    let servers: Vec<&str> = requests.iter().map(|r| r.server).collect();
    assert_eq!(servers, ["api", "web", "storage"], "{requests:?}");
    for r in &requests {
        assert_eq!(r.authorization(), None, "{r:?}");
    }
    assert_eq!(requests[0].headers["x-github-api-version"], "2022-11-28");
    assert!(requests[0].headers["user-agent"].starts_with("Remotely/"));
}

#[tokio::test]
async fn without_a_token_a_public_repository_with_no_release_yet_is_not_an_error() {
    let fake = FakeGithub::start("alice", "remotely").await;
    fake.set_public(true);
    let client = GithubReleases::new(fake.api_url(), fake.repo()).unwrap();
    let lookup = client.latest_release(None).await.unwrap();
    assert!(lookup.release.is_none());
}

#[tokio::test]
async fn without_a_token_a_private_repository_needs_one() {
    let (fake, client) = github().await;
    let err = client.latest_release(None).await.unwrap_err();
    assert!(
        matches!(&err, CoreError::UpdateTokenNeeded { repo } if repo == "alice/remotely"),
        "{err:?}"
    );
    assert!(err.to_string().contains("private again"), "{err}");
    // GitHub answers 404 to both the latest release and the list, as for a repository that doesn't exist.
    let paths: Vec<String> = fake.requests().into_iter().map(|r| r.path).collect();
    assert_eq!(
        paths,
        [
            "/repos/alice/remotely/releases/latest",
            "/repos/alice/remotely/releases?per_page=1"
        ]
    );
    // Its download links are 404 too.
    let link = fake.download_link("v0.9.0", "latest.json");
    let http = reqwest::Client::builder().user_agent("test").build().unwrap();
    assert_eq!(http.get(link).send().await.unwrap().status(), 404);
}

#[tokio::test]
async fn without_a_token_a_used_up_limit_waits_for_githubs_reset() {
    let (fake, client) = github().await;
    fake.set_public(true);
    fake.set_anonymous_rate_limited(true);

    let err = client.latest_release(None).await.unwrap_err();
    assert_eq!(err.code(), "update_rate_limited");
    let CoreError::UpdateRateLimited { until, with_token } = &err else {
        panic!("{err:?}");
    };
    assert!(!with_token);
    let until = OffsetDateTime::parse(until, &time::format_description::well_known::Rfc3339).unwrap();
    assert!(until > OffsetDateTime::now_utc() + Duration::minutes(55), "{until}");
    assert!(err.to_string().contains("60 an hour"), "{err}");

    // No call until the reset, even though GitHub would answer again.
    fake.set_anonymous_rate_limited(false);
    assert_eq!(
        client.latest_release(None).await.unwrap_err().code(),
        "update_rate_limited"
    );
    assert_eq!(fake.requests().len(), 1, "no call during the backoff");

    // A token has a limit of its own.
    let token = new_token();
    fake.add_token(&token, TokenAccess::Releases, None);
    assert!(client
        .latest_release(Some(&secret(&token)))
        .await
        .unwrap()
        .release
        .is_some());
}

#[tokio::test]
async fn a_secondary_limit_waits_for_retry_after() {
    let (fake, client) = github().await;
    fake.set_public(true);
    fake.set_secondary_limit(Some(90));
    let err = client.latest_release(None).await.unwrap_err();
    let CoreError::UpdateRateLimited { until, .. } = &err else {
        panic!("{err:?}");
    };
    let until = OffsetDateTime::parse(until, &time::format_description::well_known::Rfc3339).unwrap();
    let wait = until - OffsetDateTime::now_utc();
    assert!(wait > Duration::seconds(80) && wait <= Duration::seconds(90), "{wait}");
    fake.set_secondary_limit(None);
    assert!(client.latest_release(None).await.is_err(), "still backing off");
    assert_eq!(fake.requests().len(), 1);
}

// ---- The GitHub client with a token ----------------------------------------------------------------------

#[tokio::test]
async fn the_private_repository_is_invisible_without_a_token() {
    let (fake, _) = github().await;
    let client = reqwest::Client::builder().user_agent("test").build().unwrap();
    let url = fake.api_url().join("repos/alice/remotely/releases/latest").unwrap();
    assert_eq!(client.get(url).send().await.unwrap().status(), 404);
}

#[tokio::test]
async fn a_good_token_finds_the_latest_release_and_its_expiry() {
    let (fake, client) = github().await;
    let token = new_token();
    fake.add_token(&token, TokenAccess::Releases, Some("2027-01-17 00:00:00 UTC"));

    let lookup = client.latest_release(Some(&secret(&token))).await.unwrap();
    let release = lookup.release.unwrap();
    assert_eq!(release.tag_name, "v0.9.0");
    assert_eq!(lookup.token_expires_on.as_deref(), Some("2027-01-17"));
    let manifest = release.asset("latest.json").unwrap();
    assert_eq!(manifest.url, fake.asset_api_url(manifest.id));

    // Only the API saw the token, as a bearer token, with the headers GitHub asks for.
    let requests = fake.requests();
    assert!(!requests.is_empty());
    for r in &requests {
        assert_eq!(r.server, "api");
        assert_eq!(r.authorization(), Some(format!("Bearer {token}").as_str()));
        assert_eq!(r.headers["x-github-api-version"], "2022-11-28");
        assert!(r.headers["user-agent"].starts_with("Remotely/"));
    }
}

#[tokio::test]
async fn a_token_without_an_expiry_reports_none() {
    let (fake, client) = github().await;
    let token = new_token();
    fake.add_token(&token, TokenAccess::Releases, None);
    let lookup = client.latest_release(Some(&secret(&token))).await.unwrap();
    assert!(lookup.release.is_some());
    assert_eq!(lookup.token_expires_on, None);
}

#[tokio::test]
async fn an_unknown_token_is_refused() {
    let (fake, client) = github().await;
    fake.add_token(&new_token(), TokenAccess::Releases, None);
    let bad = new_token();
    let err = client.latest_release(Some(&secret(&bad))).await.unwrap_err();
    assert!(
        matches!(err, CoreError::UpdateTokenRefused { expired_on: None }),
        "{err:?}"
    );
    assert_eq!(err.code(), "update_token_refused");
    assert!(!format!("{err} {err:?}").contains(&bad));
    assert!(err.to_string().contains("remove it"), "{err}");
}

#[tokio::test]
async fn a_revoked_or_expired_token_is_refused() {
    let (fake, client) = github().await;
    let token = new_token();
    fake.add_token(&token, TokenAccess::Releases, Some("2027-01-17 00:00:00 UTC"));
    client.latest_release(Some(&secret(&token))).await.unwrap();

    // GitHub answers 401 "Bad credentials" for both.
    fake.revoke(&token);
    let err = client.latest_release(Some(&secret(&token))).await.unwrap_err();
    assert!(matches!(err, CoreError::UpdateTokenRefused { .. }), "{err:?}");
    assert!(!format!("{err} {err:?}").contains(&token));
}

#[tokio::test]
async fn a_token_for_other_repositories_or_without_contents_has_no_access() {
    let (fake, client) = github().await;
    for access in [
        TokenAccess::OtherRepos,
        TokenAccess::NoContents,
        TokenAccess::HiddenContents,
    ] {
        let token = new_token();
        fake.add_token(&token, access, None);
        let err = client.latest_release(Some(&secret(&token))).await.unwrap_err();
        assert!(
            matches!(&err, CoreError::UpdateTokenNoAccess { repo } if repo == "alice/remotely"),
            "{access:?}: {err:?}"
        );
        assert!(err.to_string().contains("Contents: Read-only"), "{err}");
    }
}

#[tokio::test]
async fn a_repository_with_no_release_yet_is_not_an_error() {
    let fake = FakeGithub::start("alice", "remotely").await;
    let client = GithubReleases::new(fake.api_url(), fake.repo()).unwrap();
    let token = new_token();
    fake.add_token(&token, TokenAccess::Releases, Some("2027-01-17 00:00:00 UTC"));
    let lookup = client.latest_release(Some(&secret(&token))).await.unwrap();
    assert!(lookup.release.is_none());
    assert_eq!(lookup.token_expires_on.as_deref(), Some("2027-01-17"));
}

#[tokio::test]
async fn a_used_up_token_limit_says_so_and_waits() {
    let (fake, client) = github().await;
    let token = new_token();
    fake.add_token(&token, TokenAccess::Releases, None);
    fake.set_rate_limited(true);
    let err = client.latest_release(Some(&secret(&token))).await.unwrap_err();
    assert!(
        matches!(err, CoreError::UpdateRateLimited { with_token: true, .. }),
        "{err:?}"
    );
    assert!(err.to_string().contains("limit for the update token"), "{err}");
    fake.set_rate_limited(false);
    assert!(client.latest_release(Some(&secret(&token))).await.is_err());
    assert_eq!(fake.requests().len(), 1, "no call during the backoff");
}

#[tokio::test]
async fn an_unreachable_api_fails_without_the_token() {
    let token = new_token();
    // Nothing listens on port 9 (discard) on 127.0.0.1.
    let client = GithubReleases::new(
        url::Url::parse("http://127.0.0.1:9/").unwrap(),
        GithubRepo::new("alice", "remotely"),
    )
    .unwrap();
    for auth in [Some(secret(&token)), None] {
        let err = client.latest_release(auth.as_ref()).await.unwrap_err();
        assert_eq!(err.code(), "update_failed");
        assert!(err.to_string().contains("could not reach GitHub"), "{err}");
    }
    let err = client.latest_release(Some(&secret(&token))).await.unwrap_err();
    assert!(!format!("{err} {err:?}").contains(&token));
}

/// What tauri-plugin-updater does with the headers from `download_headers`: the API asset URL
/// redirects to the storage, and reqwest drops the token on the way, which the storage requires.
#[tokio::test]
async fn release_files_download_through_the_api_and_the_storage_never_sees_the_token() {
    let (fake, client) = github().await;
    let token = new_token();
    fake.add_token(&token, TokenAccess::Releases, None);
    let release = client
        .latest_release(Some(&secret(&token)))
        .await
        .unwrap()
        .release
        .unwrap();
    let installer = release.asset("Remotely_0.9.0_x64-setup.exe").unwrap();
    fake.clear_requests();

    let http = reqwest::Client::builder()
        .user_agent("tauri-plugin-updater")
        .build()
        .unwrap();
    let response = http
        .get(installer.url.clone())
        .headers(client.download_headers(Some(&secret(&token))).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"installer");

    let requests = fake.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert_eq!(requests[0].server, "api");
    assert_eq!(requests[0].headers["accept"], "application/octet-stream");
    assert_eq!(requests[0].authorization(), Some(format!("Bearer {token}").as_str()));
    assert_eq!(requests[1].server, "storage");
    assert_eq!(requests[1].authorization(), None);

    // A private repository's download link is not served to tokens; it maps to the API URL.
    let link = fake.download_link("v0.9.0", "Remotely_0.9.0_x64-setup.exe");
    assert_eq!(client.asset_url(&release, &link).unwrap(), installer.url);
}

// ---- The core: checks without a token, the optional token in the vault, statuses, audit -------------------

async fn core_with(updater: Arc<FakeUpdater>) -> Core {
    Setup::new(FakeVmware::default())
        .with_real_vault()
        .with_updater(updater)
        .build()
        .await
}

async fn token_count(core: &Core) -> usize {
    core.vault
        .list(&core.ctx())
        .await
        .unwrap()
        .into_iter()
        .filter(|m| m.label == UPDATE_TOKEN_LABEL)
        .count()
}

async fn unlock(core: &Core) {
    core.vault
        .unlock(
            &core.ctx(),
            UnlockMethod::MasterPassword(SecretString::new(VAULT_PASSWORD)),
        )
        .await
        .unwrap();
}

/// Submits and approves installing `version` (Medium: one confirm). Returns the job.
async fn install(core: &Core, version: &str) -> Uuid {
    let command = Command::AppUpdate {
        version: version.into(),
    };
    let SubmitOutcome::NeedsApproval { request } = core.bus.submit(&core.ctx(), command).await.unwrap() else {
        panic!("installing is Medium");
    };
    let answers = ApprovalAnswers {
        confirmed: true,
        ..Default::default()
    };
    core.bus.approve(request.id, answers).await.unwrap()
}

#[tokio::test]
async fn without_a_token_checks_read_the_public_releases() {
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0"));
    let core = core_with(Arc::clone(&updater)).await;

    let check = core.check_for_update().await.unwrap();
    let UpdateCheck::Available { update } = &check else {
        panic!("0.3.0 is offered: {check:?}");
    };
    assert_eq!(update.version, "0.3.0");
    assert_eq!((updater.calls(), updater.anonymous_calls()), (1, 1));
    assert_eq!(
        core.update_token_info().await.unwrap(),
        UpdateTokenInfo {
            stored: false,
            expires_on: None
        }
    );
    // Settings' Test has nothing to test, and makes no call.
    let err = core.test_update_token().await.unwrap_err();
    assert_eq!(err.code(), "update_token_missing");
    assert_eq!(updater.calls(), 1);
}

#[tokio::test]
async fn a_private_again_repository_asks_for_a_token() {
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0"));
    updater.set_private(true);
    let core = core_with(Arc::clone(&updater)).await;

    let check = core.check_for_update().await.unwrap();
    assert_eq!(
        check,
        UpdateCheck::TokenNeeded {
            repository: "alice/remotely".into()
        }
    );
    assert_eq!(
        serde_json::to_string(&check).unwrap(),
        r#"{"status":"tokenNeeded","repository":"alice/remotely"}"#
    );

    // With a token it reads them as before.
    let token = new_token();
    core.set_update_token(secret(&token)).await.unwrap();
    assert!(matches!(
        core.check_for_update().await.unwrap(),
        UpdateCheck::Available { .. }
    ));
    assert_eq!(updater.anonymous_calls(), 1);
}

#[tokio::test]
async fn a_used_up_limit_is_a_state_and_the_token_has_its_own() {
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0"));
    updater.rate_limit_anonymous(Some("2026-10-25T15:00:00Z"));
    let core = core_with(Arc::clone(&updater)).await;

    let check = core.check_for_update().await.unwrap();
    assert_eq!(
        check,
        UpdateCheck::RateLimited {
            until: "2026-10-25T15:00:00Z".into(),
            with_token: false
        }
    );
    assert_eq!(
        serde_json::to_string(&check).unwrap(),
        r#"{"status":"rateLimited","until":"2026-10-25T15:00:00Z","withToken":false}"#
    );

    core.set_update_token(secret(&new_token())).await.unwrap();
    assert!(matches!(
        core.check_for_update().await.unwrap(),
        UpdateCheck::Available { .. }
    ));
}

#[tokio::test]
async fn a_good_token_is_stored_in_the_vault_and_finds_the_update() {
    let token = new_token();
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0").accepting(&token, Some("2027-01-17")));
    let core = core_with(Arc::clone(&updater)).await;

    // Pasted with a trailing new line, as copying from GitHub often gives.
    let info = core.set_update_token(secret(&format!("{token}\n"))).await.unwrap();
    assert!(info.stored);
    assert_eq!(info.expires_on, None, "known after the first call");

    let check = core.check_for_update().await.unwrap();
    let UpdateCheck::Available { update } = &check else {
        panic!("0.3.0 is offered: {check:?}");
    };
    assert_eq!(update.version, "0.3.0");
    assert_eq!(updater.anonymous_calls(), 0, "the token goes along when there is one");
    let json = serde_json::to_value(&check).unwrap();
    assert_eq!(json["status"], "available");
    assert_eq!(json["update"]["version"], "0.3.0");
    assert_eq!(
        core.update_token_info().await.unwrap().expires_on.as_deref(),
        Some("2027-01-17")
    );

    let report = core.test_update_token().await.unwrap();
    assert_eq!(report.repository, "alice/remotely");
    assert_eq!(report.latest_release.as_deref(), Some("v0.3.0"));

    // It is a vault secret like the others: listed by label and kind, never by value.
    let listed = core.vault.list(&core.ctx()).await.unwrap();
    let item = listed.iter().find(|m| m.label == UPDATE_TOKEN_LABEL).unwrap();
    assert_eq!(item.kind, SecretKind::Password);
    assert_eq!(
        core.vault.vault().get(&core.ctx(), item.id).await.unwrap().expose(),
        token
    );
}

#[tokio::test]
async fn a_wrong_token_is_refused() {
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0").accepting(&new_token(), None));
    let core = core_with(Arc::clone(&updater)).await;
    let wrong = new_token();
    core.set_update_token(secret(&wrong)).await.unwrap();

    let err = core.check_for_update().await.unwrap_err();
    assert_eq!(err.code(), "update_token_refused");
    assert!(err.to_string().contains("revoked"), "{err}");
    assert!(!err.to_string().contains(&wrong));
    let err = core.test_update_token().await.unwrap_err();
    assert_eq!(err.code(), "update_token_refused");
}

/// QL-15: a download that stalls no longer holds the update job forever: cancelling it ends the job, and
/// nothing is installed.
#[tokio::test]
async fn cancelling_a_stalled_update_ends_the_job_and_installs_nothing() {
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0").stalling());
    let core = core_with(Arc::clone(&updater)).await;
    let mut events = core.jobs.subscribe();
    let job = install(&core, "0.3.0").await;
    // The download has started (the fake was reached) and hangs.
    for _ in 0..100 {
        if updater.calls() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(updater.calls() > 0, "the install started");
    assert!(core.jobs.cancel(job));
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Cancelled);
    assert!(updater.installed().is_empty());
    let targets = core.store.job_targets(&core.ctx(), job).await.unwrap();
    assert_eq!(targets[0].status, "cancelled");
}

#[tokio::test]
async fn an_expired_token_says_when_it_expired() {
    let token = new_token();
    let yesterday = day(-1);
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0").accepting(&token, Some(&yesterday)));
    let core = core_with(Arc::clone(&updater)).await;
    core.set_update_token(secret(&token)).await.unwrap();
    // GitHub's last answer said the token expires `yesterday`; now it refuses it.
    core.check_for_update().await.unwrap();
    updater.revoke();

    let err = core.check_for_update().await.unwrap_err();
    assert!(
        matches!(&err, CoreError::UpdateTokenRefused { expired_on: Some(d) } if *d == yesterday),
        "{err:?}"
    );
    assert!(err.to_string().contains(&format!("expired on {yesterday}")), "{err}");
    assert!(err.to_string().contains("remove it"), "{err}");
}

#[tokio::test]
async fn a_revoked_token_that_has_not_expired_says_revoked() {
    let token = new_token();
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0").accepting(&token, Some(&day(30))));
    let core = core_with(Arc::clone(&updater)).await;
    core.set_update_token(secret(&token)).await.unwrap();
    core.check_for_update().await.unwrap();
    updater.revoke();

    let err = core.check_for_update().await.unwrap_err();
    assert!(
        matches!(err, CoreError::UpdateTokenRefused { expired_on: None }),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_locked_vault_checks_without_the_token_and_keeps_its_expiry() {
    let token = new_token();
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0").accepting(&token, Some("2027-01-17")));
    let core = core_with(Arc::clone(&updater)).await;
    core.set_update_token(secret(&token)).await.unwrap();
    core.check_for_update().await.unwrap();

    core.vault.lock(&core.ctx()).await.unwrap();
    assert_eq!(core.vault.info().status, VaultStatus::Locked);
    assert!(matches!(
        core.check_for_update().await.unwrap(),
        UpdateCheck::Available { .. }
    ));
    assert_eq!(updater.anonymous_calls(), 1);
    let info = core.update_token_info().await.unwrap();
    assert!(info.stored, "known while locked");
    assert_eq!(
        info.expires_on.as_deref(),
        Some("2027-01-17"),
        "an answer without the token doesn't forget its expiry"
    );
    assert_eq!(core.test_update_token().await.unwrap_err().code(), "vault_locked");
    // Saving one needs the vault unlocked too.
    assert_eq!(
        core.set_update_token(secret(&new_token())).await.unwrap_err().code(),
        "vault_locked"
    );
}

#[tokio::test]
async fn a_private_again_repository_with_the_token_locked_away_asks_to_unlock() {
    let token = new_token();
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0").accepting(&token, None));
    updater.set_private(true);
    let core = core_with(Arc::clone(&updater)).await;
    core.set_update_token(secret(&token)).await.unwrap();

    core.vault.lock(&core.ctx()).await.unwrap();
    assert_eq!(core.check_for_update().await.unwrap(), UpdateCheck::VaultLocked);
    assert_eq!(
        serde_json::to_string(&UpdateCheck::VaultLocked).unwrap(),
        r#"{"status":"vaultLocked"}"#
    );
    // An install fails the same way, and says so.
    let mut events = core.jobs.subscribe();
    let job = install(&core, "0.3.0").await;
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Failed);
    let targets = core.store.job_targets(&core.ctx(), job).await.unwrap();
    assert_eq!(targets[0].error_code.as_deref(), Some("vault_locked"));

    // Unlocked, the token reads the releases.
    unlock(&core).await;
    assert!(matches!(
        core.check_for_update().await.unwrap(),
        UpdateCheck::Available { .. }
    ));
}

#[tokio::test]
async fn replacing_keeps_one_vault_secret_and_removing_deletes_it() {
    let first = new_token();
    let second = new_token();
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0").accepting(&second, Some("2027-01-17")));
    let core = core_with(Arc::clone(&updater)).await;

    core.set_update_token(secret(&first)).await.unwrap();
    assert_eq!(
        core.check_for_update().await.unwrap_err().code(),
        "update_token_refused"
    );
    core.set_update_token(secret(&second)).await.unwrap();
    assert!(matches!(
        core.check_for_update().await.unwrap(),
        UpdateCheck::Available { .. }
    ));
    assert_eq!(token_count(&core).await, 1);

    let info = core.remove_update_token().await.unwrap();
    assert_eq!(
        info,
        UpdateTokenInfo {
            stored: false,
            expires_on: None
        }
    );
    assert_eq!(token_count(&core).await, 0);
    // Checks go on without one.
    assert!(matches!(
        core.check_for_update().await.unwrap(),
        UpdateCheck::Available { .. }
    ));
    assert_eq!(updater.anonymous_calls(), 1);

    let audit = core.store.recent_audit(&core.ctx(), 10).await.unwrap();
    let actions: Vec<&str> = audit.iter().map(|e| e.action.as_str()).collect();
    assert!(
        actions.contains(&"Saved the GitHub update token in the vault"),
        "{actions:?}"
    );
    assert!(
        actions.contains(&"Replaced the GitHub update token in the vault"),
        "{actions:?}"
    );
    assert!(
        actions.contains(&"Removed the GitHub update token from the vault"),
        "{actions:?}"
    );
    assert!(audit.iter().filter(|e| e.event == "vault_changed").count() >= 3);
    assert!(core.store.verify_audit_chain(&core.ctx()).await.unwrap().ok);
}

#[tokio::test]
async fn a_token_deleted_on_the_vault_page_counts_as_none() {
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0"));
    let core = core_with(Arc::clone(&updater)).await;
    core.set_update_token(secret(&new_token())).await.unwrap();
    let id = core
        .vault
        .list(&core.ctx())
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.label == UPDATE_TOKEN_LABEL)
        .unwrap()
        .id;
    core.vault.delete(&core.ctx(), id).await.unwrap();
    assert!(!core.update_token_info().await.unwrap().stored);
    assert!(matches!(
        core.check_for_update().await.unwrap(),
        UpdateCheck::Available { .. }
    ));
    assert_eq!(updater.anonymous_calls(), 1);
    // Saving again makes a new one.
    core.set_update_token(secret(&new_token())).await.unwrap();
    assert!(core.update_token_info().await.unwrap().stored);
}

#[tokio::test]
async fn tokens_that_are_not_tokens_are_refused_before_the_vault() {
    let core = core_with(Arc::new(FakeUpdater::default())).await;
    for bad in ["", "   ", "two words", "line\nbreak"] {
        let err = core.set_update_token(secret(bad)).await.unwrap_err();
        assert_eq!(err.code(), "invalid_input", "{bad:?}");
    }
    assert!(!core.update_token_info().await.unwrap().stored);
}

#[tokio::test]
async fn installing_needs_no_token_and_uses_one_when_there_is_one() {
    let token = new_token();
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0").accepting(&token, None));
    let core = core_with(Arc::clone(&updater)).await;
    let mut events = core.jobs.subscribe();

    // No token: installed from the public release.
    let job = install(&core, "0.3.0").await;
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(updater.installed(), ["0.3.0"]);
    assert_eq!(updater.anonymous_calls(), 1);

    // A private repository without a token: the job fails and says why.
    updater.set_private(true);
    let job = install(&core, "0.3.0").await;
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Failed);
    let targets = core.store.job_targets(&core.ctx(), job).await.unwrap();
    assert_eq!(targets[0].error_code.as_deref(), Some("update_token_needed"));

    // With the token it installs.
    core.set_update_token(secret(&token)).await.unwrap();
    let job = install(&core, "0.3.0").await;
    assert_eq!(wait_finished(&mut events, job).await, JobStatus::Succeeded);
    assert_eq!(updater.installed(), ["0.3.0", "0.3.0"]);
    assert_eq!(updater.anonymous_calls(), 2, "the token went along");
}

/// Appends every log line to a shared buffer.
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The token reaches the vault (encrypted) and GitHub, nothing else: not the logs (every level,
/// including reqwest's and hyper's), the audit log, the database's other tables, settings, errors or
/// anything the UI is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_token_never_leaks() {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&logs);
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || Capture(Arc::clone(&writer)))
        .try_init()
        .unwrap();

    let token = new_token();
    let wrong = new_token();
    let updater = Arc::new(FakeUpdater::offering("0.2.1", "0.3.0").accepting(&token, Some("2027-01-17")));
    let core = core_with(Arc::clone(&updater)).await;
    let mut shown = String::new();

    core.set_update_token(secret(&wrong)).await.unwrap();
    let err = core.check_for_update().await.unwrap_err();
    shown.push_str(&format!("{err} {err:?}"));
    shown.push_str(&serde_json::to_string(&core.update_token_info().await.unwrap()).unwrap());
    let info = core.set_update_token(secret(&token)).await.unwrap();
    shown.push_str(&serde_json::to_string(&info).unwrap());
    let check = core.check_for_update().await.unwrap();
    shown.push_str(&serde_json::to_string(&check).unwrap());
    let report = core.test_update_token().await.unwrap();
    shown.push_str(&serde_json::to_string(&report).unwrap());

    // The real GitHub client too, against the fake API, failing and succeeding, with and without the token.
    let (fake, client) = github().await;
    fake.add_token(&token, TokenAccess::Releases, Some("2027-01-17 00:00:00 UTC"));
    client.latest_release(Some(&secret(&token))).await.unwrap();
    let err = client.latest_release(Some(&secret(&wrong))).await.unwrap_err();
    shown.push_str(&format!("{err} {err:?}"));
    fake.revoke(&token);
    let err = client.latest_release(Some(&secret(&token))).await.unwrap_err();
    shown.push_str(&format!("{err} {err:?}"));
    fake.set_public(true);
    client.latest_release(None).await.unwrap();
    fake.set_rate_limited(true);
    fake.add_token(&wrong, TokenAccess::Releases, None);
    let err = client.latest_release(Some(&secret(&wrong))).await.unwrap_err();
    shown.push_str(&format!("{err} {err:?}"));

    core.remove_update_token().await.unwrap();

    let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("hyper"),
        "the HTTP client's own trace lines are captured too"
    );
    assert!(logs.contains("GitHub's API limit is used up"), "the backoff is logged");
    let audit = core.store.recent_audit(&core.ctx(), 100).await.unwrap();
    let audit = format!("{audit:?}");
    let database = database_text(&core).await;
    for t in [&token, &wrong] {
        assert!(!logs.contains(t.as_str()), "a log line holds the token");
        assert!(!audit.contains(t.as_str()), "the audit log holds the token");
        assert!(
            !database.contains(t.as_str()),
            "the database holds the token in the clear"
        );
        assert!(!shown.contains(t.as_str()), "something the UI sees holds the token");
    }
    assert!(audit.contains("GitHub update token"));
}
