//! FD-14: the updater adapter end to end on Tauri's mock runtime, against a local fake GitHub
//! (`remotely_core::fakes::github_server`) and a signing key made at run time. Never installs.
//!
//! * Without a token (the repository is public): GitHub API -> latest.json and the installer from their
//!   public download links -> signature check, with no `Authorization` header anywhere. A private
//!   repository asks for a token; a used-up API limit backs off.
//! * With a token: GitHub API -> latest.json and the installer through their API asset URLs ->
//!   signature check, the token going only to the API.
//! * C3: an installer signed for another version is refused before it is offered, either way.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use remotely_core::adapters::updater::UpdaterAdapter;
use remotely_core::fakes::github_server::{latest_json, FakeAsset, FakeGithub, SeenRequest, TokenAccess, UpdateSigner};
use remotely_core::vault::SecretString;
use remotely_core::CoreError;
use remotely_lib::updater::TauriUpdater;
use serde_json::json;
use tauri::test::{mock_builder, mock_context, noop_assets, MockRuntime};
use url::Url;
use uuid::Uuid;

const INSTALLER: &str = "Remotely_0.9.0_x64-setup.exe";
const MANIFEST: &str = "latest.json";

fn new_token() -> String {
    format!("github_pat_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// An app on Tauri's mock runtime with the updater plugin configured like tauri.conf.json, but
/// trusting `signer`'s throwaway key. The mock app is version 0.1.0.
fn mock_app(fake: &FakeGithub, signer: &UpdateSigner) -> tauri::App<MockRuntime> {
    let mut context = mock_context(noop_assets());
    context.config_mut().product_name = Some("Remotely".into());
    context.config_mut().plugins.0.insert(
        "updater".into(),
        json!({
            "pubkey": signer.public_key(),
            "endpoints": [format!("https://github.com/{}/releases/latest/download/latest.json", fake.repo())],
            "requireSignedVersion": true,
            // The fake GitHub speaks plain HTTP on 127.0.0.1.
            "dangerousInsecureTransportProtocol": true,
        }),
    );
    mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(context)
        .unwrap()
}

struct World {
    fake: FakeGithub,
    signer: UpdateSigner,
    app: tauri::App<MockRuntime>,
    token: String,
}

impl World {
    /// A private repository, as from 0.2.0 to 0.4.0, and a token that can read its releases.
    async fn new() -> Self {
        let fake = FakeGithub::start("alice", "remotely").await;
        let signer = UpdateSigner::generate();
        let app = mock_app(&fake, &signer);
        let token = new_token();
        fake.add_token(&token, TokenAccess::Releases, Some("2027-01-17 00:00:00 UTC"));
        Self {
            fake,
            signer,
            app,
            token,
        }
    }

    /// A public repository, as now. The token still works.
    async fn public() -> Self {
        let world = Self::new().await;
        world.fake.set_public(true);
        world
    }

    fn updater(&self) -> TauriUpdater<MockRuntime> {
        TauriUpdater::with_github(self.app.handle().clone(), self.fake.api_url(), self.fake.web_url()).unwrap()
    }

    /// Publishes `version`: a signed installer, its .sig, and latest.json pointing at
    /// `url(installer)` (the release workflow writes the API asset URL). Returns the installer.
    fn publish_version(&self, version: &str, url: impl Fn(&FakeGithub, &FakeAsset) -> Url) -> Vec<u8> {
        self.publish_signed_as(version, version, url)
    }

    /// Publishes a release whose latest.json announces `announced`, with the installer the release
    /// workflow signed for `signed` (the same, unless a release was tampered with).
    fn publish_signed_as(
        &self,
        announced: &str,
        signed: &str,
        url: impl Fn(&FakeGithub, &FakeAsset) -> Url,
    ) -> Vec<u8> {
        let name = format!("Remotely_{signed}_x64-setup.exe");
        let installer = format!("MZ fake NSIS installer for {signed}").into_bytes();
        let signature = self.signer.sign(&installer, &name, signed);
        let assets = self.fake.publish(
            &format!("v{announced}"),
            &format!("Remotely {announced}"),
            vec![
                (name.as_str(), installer.clone()),
                (format!("{name}.sig").as_str(), signature.clone().into_bytes()),
            ],
        );
        let notes = format!("Remotely {announced} notes");
        let manifest = latest_json(announced, &notes, &url(&self.fake, &assets[0]), &signature);
        self.fake.add_file(MANIFEST, manifest);
        installer
    }

    fn publish(&self, url: impl Fn(&FakeGithub, &FakeAsset) -> Url) -> Vec<u8> {
        self.publish_version("0.9.0", url)
    }

    fn secret(&self) -> SecretString {
        SecretString::new(self.token.as_str())
    }

    fn requests_to(&self, server: &str) -> Vec<SeenRequest> {
        self.fake
            .requests()
            .into_iter()
            .filter(|r| r.server == server)
            .collect()
    }

    /// Every request that reached the storage or github.com came without the token, and every request
    /// with the token went to the API.
    fn assert_token_only_went_to_the_api(&self) {
        let requests = self.fake.requests();
        assert!(requests.iter().any(|r| r.server == "storage"), "{requests:?}");
        for r in &requests {
            match r.server {
                "api" => assert_eq!(r.authorization(), Some(format!("Bearer {}", self.token).as_str())),
                _ => assert_eq!(r.authorization(), None, "{r:?}"),
            }
        }
    }

    /// Nothing carried an `Authorization` header, and nothing but the latest-release lookup asked the API:
    /// the files came from github.com, which doesn't count against the API's limit.
    fn assert_no_authorization_anywhere(&self) {
        let requests = self.fake.requests();
        assert!(requests.iter().all(|r| r.authorization().is_none()), "{requests:?}");
        assert!(
            self.requests_to("api")
                .iter()
                .all(|r| r.path.ends_with("/releases/latest")),
            "{requests:?}"
        );
    }
}

fn api_url(fake: &FakeGithub, asset: &FakeAsset) -> Url {
    fake.asset_api_url(asset.id)
}

// ---- Without a token: the public repository ------------------------------------------------------------

#[test]
fn without_a_token_a_public_release_is_found_and_downloaded_from_its_download_links() {
    tauri::async_runtime::block_on(async {
        let world = World::public().await;
        let installer = world.publish(api_url);
        let updater = world.updater();

        let checked = updater.check(None).await.unwrap();
        let update = checked.update.unwrap();
        assert_eq!(update.current_version, "0.1.0");
        assert_eq!(update.version, "0.9.0");
        assert_eq!(update.notes.as_deref(), Some("Remotely 0.9.0 notes"));
        assert_eq!(checked.token_expires_on, None);

        let (offered, bytes) = updater.download(None, "0.9.0").await.unwrap();
        assert_eq!(bytes, installer, "the signature checked out");
        assert_eq!(
            offered.download_url,
            world.fake.download_link("v0.9.0", INSTALLER),
            "the public download link, not the API asset URL latest.json names"
        );

        // One API call; latest.json and the installer each came github.com -> redirect -> storage.
        assert_eq!(world.requests_to("api").len(), 1, "{:?}", world.fake.requests());
        let web: Vec<String> = world.requests_to("web").into_iter().map(|r| r.path).collect();
        assert_eq!(
            web,
            [
                "/alice/remotely/releases/download/v0.9.0/latest.json",
                "/alice/remotely/releases/download/v0.9.0/Remotely_0.9.0_x64-setup.exe"
            ]
        );
        assert_eq!(world.requests_to("storage").len(), 2);
        world.assert_no_authorization_anywhere();
    });
}

#[test]
fn without_a_token_a_tampered_installer_fails_the_signature_check() {
    tauri::async_runtime::block_on(async {
        let world = World::public().await;
        world.publish(api_url);
        let updater = world.updater();
        updater.check(None).await.unwrap().update.unwrap();

        world.fake.replace_file(INSTALLER, b"MZ something else".to_vec());
        let Err(err) = updater.download(None, "0.9.0").await else {
            panic!("the download must fail its signature check");
        };
        assert_eq!(err.code(), "update_failed");
        assert!(err.to_string().contains("signature verification failed"), "{err}");
    });
}

#[test]
fn without_a_token_an_old_signed_installer_offered_as_a_newer_version_is_refused() {
    tauri::async_runtime::block_on(async {
        let world = World::public().await;
        world.publish_signed_as("0.9.0", "0.5.0", api_url);
        let err = world.updater().check(None).await.unwrap_err();
        assert_eq!(err.code(), "update_failed");
        assert!(
            err.to_string()
                .contains("signed as Remotely_0.5.0_x64-setup.exe, not Remotely_0.9.0_x64-setup.exe"),
            "{err}"
        );
        // Only latest.json came from the storage: the old installer was never downloaded.
        assert_eq!(world.requests_to("storage").len(), 1);
    });
}

#[test]
fn without_a_token_a_download_elsewhere_is_refused() {
    tauri::async_runtime::block_on(async {
        let world = World::public().await;
        world.publish(|fake, _| fake.storage_url().join("elsewhere/other-setup.exe").unwrap());
        let err = world.updater().check(None).await.unwrap_err();
        assert_eq!(err.code(), "update_failed");
        assert!(err.to_string().contains("not a file of that release"), "{err}");
        assert!(world.fake.requests().iter().all(|r| !r.path.contains("elsewhere")));
    });
}

#[test]
fn without_a_token_a_private_repository_asks_for_one() {
    tauri::async_runtime::block_on(async {
        // The repository went private again: GitHub answers 404 to calls without a token.
        let world = World::new().await;
        world.publish(api_url);
        let updater = world.updater();
        let err = updater.check(None).await.unwrap_err();
        assert!(
            matches!(&err, CoreError::UpdateTokenNeeded { repo } if repo == "alice/remotely"),
            "{err:?}"
        );
        assert_eq!(err.code(), "update_token_needed");
        // Nothing beyond the API was asked, and with the token it works as before.
        assert!(world.fake.requests().iter().all(|r| r.server == "api"));
        assert!(updater.check(Some(&world.secret())).await.unwrap().update.is_some());
        assert!(updater.download(None, "0.9.0").await.is_err());
    });
}

#[test]
fn without_a_token_a_used_up_limit_backs_off_until_githubs_reset() {
    tauri::async_runtime::block_on(async {
        let world = World::public().await;
        world.publish(api_url);
        world.fake.set_anonymous_rate_limited(true);
        let updater = world.updater();

        let err = updater.check(None).await.unwrap_err();
        let CoreError::UpdateRateLimited { until, with_token } = &err else {
            panic!("{err:?}");
        };
        assert!(!with_token);
        // GitHub's reset an hour away, in UTC (tests/updates.rs in the core checks the wait itself).
        assert!(until.ends_with('Z'), "{until}");
        assert!(err.to_string().contains("without a token"), "{err}");
        assert_eq!(world.requests_to("api").len(), 1);

        // Until the reset, a check makes no call, even once GitHub would answer again.
        world.fake.set_anonymous_rate_limited(false);
        let again = updater.check(None).await.unwrap_err();
        assert_eq!(again.code(), "update_rate_limited");
        assert_eq!(world.requests_to("api").len(), 1, "no call during the backoff");

        // The token has a limit of its own.
        let checked = updater.check(Some(&world.secret())).await.unwrap();
        assert!(checked.update.is_some());
    });
}

#[test]
fn a_secondary_limit_waits_for_retry_after_with_or_without_a_token() {
    tauri::async_runtime::block_on(async {
        let world = World::public().await;
        world.publish(api_url);
        world.fake.set_secondary_limit(Some(300));
        let updater = world.updater();
        for token in [None, Some(world.secret())] {
            let err = updater.check(token.as_ref()).await.unwrap_err();
            let CoreError::UpdateRateLimited { with_token, .. } = &err else {
                panic!("{err:?}");
            };
            assert_eq!(*with_token, token.is_some());
            let calls = world.requests_to("api").len();
            assert_eq!(
                updater.check(token.as_ref()).await.unwrap_err().code(),
                "update_rate_limited"
            );
            assert_eq!(world.requests_to("api").len(), calls, "no call during the backoff");
        }
        assert_eq!(world.requests_to("api").len(), 2);
    });
}

// ---- Switching between the two ---------------------------------------------------------------------------

#[test]
fn an_update_found_without_a_token_installs_with_one_through_the_api() {
    tauri::async_runtime::block_on(async {
        // The vault was locked at the check and is unlocked for the install.
        let world = World::public().await;
        let installer = world.publish(api_url);
        let updater = world.updater();
        updater.check(None).await.unwrap().update.unwrap();
        world.fake.clear_requests();

        let (offered, bytes) = updater.download(Some(&world.secret()), "0.9.0").await.unwrap();
        assert_eq!(bytes, installer);
        assert!(offered.download_url.as_str().starts_with(world.fake.api_url().as_str()));
        assert!(
            world.requests_to("web").is_empty(),
            "the token never goes to github.com"
        );
        world.assert_token_only_went_to_the_api();
    });
}

#[test]
fn an_update_found_with_a_token_installs_without_one_from_the_download_link() {
    tauri::async_runtime::block_on(async {
        // The vault was unlocked at the check and has locked itself since.
        let world = World::public().await;
        let installer = world.publish(api_url);
        let updater = world.updater();
        updater.check(Some(&world.secret())).await.unwrap().update.unwrap();
        world.fake.clear_requests();

        let (offered, bytes) = updater.download(None, "0.9.0").await.unwrap();
        assert_eq!(bytes, installer);
        assert_eq!(offered.download_url, world.fake.download_link("v0.9.0", INSTALLER));
        assert!(world.requests_to("api").is_empty());
        world.assert_no_authorization_anywhere();
    });
}

// ---- With a token: as while the repository was private -----------------------------------------------------

#[test]
fn a_signed_update_is_found_and_downloaded_through_the_api() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        let installer = world.publish(api_url);
        let updater = world.updater();

        let checked = updater.check(Some(&world.secret())).await.unwrap();
        let update = checked.update.unwrap();
        assert_eq!(update.current_version, "0.1.0");
        assert_eq!(update.version, "0.9.0");
        assert_eq!(update.notes.as_deref(), Some("Remotely 0.9.0 notes"));
        assert_eq!(checked.token_expires_on.as_deref(), Some("2027-01-17"));

        let (offered, bytes) = updater.download(Some(&world.secret()), "0.9.0").await.unwrap();
        assert_eq!(bytes, installer, "the signature checked out");
        assert!(offered.download_url.as_str().starts_with(world.fake.api_url().as_str()));

        // latest.json and the installer each came API -> redirect -> storage.
        let requests = world.fake.requests();
        let downloads: Vec<_> = requests.iter().filter(|r| r.server == "storage").collect();
        assert_eq!(downloads.len(), 2, "{requests:?}");
        assert!(requests
            .iter()
            .filter(|r| r.path.contains("/releases/assets/"))
            .all(|r| r.headers["accept"] == "application/octet-stream"));
        world.assert_token_only_went_to_the_api();

        let report = updater.test_token(&world.secret()).await.unwrap();
        assert_eq!(report.repository, "alice/remotely");
        assert_eq!(report.latest_release.as_deref(), Some("v0.9.0"));
    });
}

#[test]
fn a_tampered_installer_fails_the_signature_check() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        world.publish(api_url);
        let updater = world.updater();
        updater.check(Some(&world.secret())).await.unwrap().update.unwrap();

        world.fake.replace_file(INSTALLER, b"MZ something else".to_vec());
        let Err(err) = updater.download(Some(&world.secret()), "0.9.0").await else {
            panic!("the download must fail its signature check");
        };
        assert_eq!(err.code(), "update_failed");
        assert!(err.to_string().contains("signature verification failed"), "{err}");
        assert!(!err.to_string().contains(&world.token));
    });
}

#[test]
fn an_update_signed_with_another_key_is_refused() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        world.fake.set_public(true);
        let installer = b"MZ signed by someone else".to_vec();
        let signature = UpdateSigner::generate().sign(&installer, INSTALLER, "0.9.0");
        let assets = world.fake.publish("v0.9.0", "notes", vec![(INSTALLER, installer)]);
        let manifest = latest_json("0.9.0", "notes", &world.fake.asset_api_url(assets[0].id), &signature);
        world.fake.add_file(MANIFEST, manifest);

        // Refused before it is offered, so nothing is downloaded: with the token and without one.
        for token in [Some(world.secret()), None] {
            world.fake.clear_requests();
            let err = world.updater().check(token.as_ref()).await.unwrap_err();
            assert_eq!(err.code(), "update_failed");
            assert!(err.to_string().contains("different key"), "{err}");
            assert_eq!(world.requests_to("storage").len(), 1);
        }
    });
}

#[test]
fn an_old_signed_installer_offered_as_a_newer_version_is_refused() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        // A release that says 0.9.0 but carries 0.5.0's installer and signature, both genuine: what
        // someone who can edit releases, but has no signing key, could publish to roll installs back.
        world.publish_signed_as("0.9.0", "0.5.0", api_url);
        let updater = world.updater();
        let err = updater.check(Some(&world.secret())).await.unwrap_err();
        assert_eq!(err.code(), "update_failed");
        assert!(
            err.to_string()
                .contains("signed as Remotely_0.5.0_x64-setup.exe, not Remotely_0.9.0_x64-setup.exe"),
            "{err}"
        );
        assert!(!err.to_string().contains(&world.token));
        // Only latest.json came from the storage: the old installer was never downloaded.
        assert_eq!(world.requests_to("storage").len(), 1);
        let Err(err) = updater.download(Some(&world.secret()), "0.9.0").await else {
            panic!("the old installer must not be downloaded as 0.9.0");
        };
        assert_eq!(err.code(), "update_failed");
    });
}

#[test]
fn the_plugin_checks_the_signed_version_too() {
    tauri::async_runtime::block_on(async {
        let world = World::public().await;
        world.publish(api_url);
        let updater = world.updater();
        for token in [Some(world.secret()), None] {
            let (mut update, bytes) = updater.download(token.as_ref(), "0.9.0").await.unwrap();
            // requireSignedVersion: the same bytes and signature, announced as another version.
            update.version = "0.9.1".into();
            let err = update.verify(&bytes).unwrap_err();
            assert!(err.to_string().contains("0.9.1"), "{err}");
        }
    });
}

#[test]
fn a_github_download_link_in_latest_json_is_fetched_through_the_api() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        let installer = world.publish(|fake, asset| fake.download_link("v0.9.0", &asset.name));
        let updater = world.updater();
        updater.check(Some(&world.secret())).await.unwrap().update.unwrap();
        let (_, bytes) = updater.download(Some(&world.secret()), "0.9.0").await.unwrap();
        assert_eq!(bytes, installer);
        assert!(world.requests_to("web").is_empty());
        world.assert_token_only_went_to_the_api();
    });
}

#[test]
fn a_download_elsewhere_is_refused_before_the_token_goes_there() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        // A URL on the storage host itself, which must never get the token.
        world.publish(|fake, _| fake.storage_url().join("elsewhere/other-setup.exe").unwrap());
        let err = world.updater().check(Some(&world.secret())).await.unwrap_err();
        assert_eq!(err.code(), "update_failed");
        assert!(err.to_string().contains("not a file of that release"), "{err}");
        assert!(world.fake.requests().iter().all(|r| !r.path.contains("elsewhere")));
        world.assert_token_only_went_to_the_api();
    });
}

#[test]
fn up_to_date_and_no_release_offer_nothing() {
    tauri::async_runtime::block_on(async {
        let world = World::public().await;
        let updater = world.updater();
        // Nothing published yet.
        let checked = updater.check(Some(&world.secret())).await.unwrap();
        assert_eq!(checked.update, None);
        assert_eq!(checked.token_expires_on.as_deref(), Some("2027-01-17"));
        assert_eq!(updater.check(None).await.unwrap().update, None);
        // A release that is not newer than 0.1.0.
        world.publish_version("0.1.0", api_url);
        assert_eq!(updater.check(Some(&world.secret())).await.unwrap().update, None);
        assert_eq!(updater.check(None).await.unwrap().update, None);
    });
}

#[test]
fn bad_revoked_and_unauthorised_tokens_fail_without_leaking() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        world.publish(api_url);
        let updater = world.updater();

        let wrong = new_token();
        let err = updater
            .check(Some(&SecretString::new(wrong.as_str())))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "update_token_refused");
        assert!(!format!("{err} {err:?}").contains(&wrong));

        let other = new_token();
        world.fake.add_token(&other, TokenAccess::OtherRepos, None);
        let err = updater
            .test_token(&SecretString::new(other.as_str()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "update_token_no_access");

        world.fake.revoke(&world.token);
        let err = updater.check(Some(&world.secret())).await.unwrap_err();
        assert_eq!(err.code(), "update_token_refused");
        assert!(!format!("{err} {err:?}").contains(&world.token));
        // Nothing reached the storage: no download was attempted with a refused token.
        assert!(world.fake.requests().iter().all(|r| r.server == "api"));
    });
}

#[test]
fn the_app_reads_the_repository_from_its_config() {
    let app = |endpoint: &str| {
        let mut context = mock_context(noop_assets());
        context
            .config_mut()
            .plugins
            .0
            .insert("updater".into(), json!({ "pubkey": "", "endpoints": [endpoint] }));
        mock_builder().build(context).unwrap()
    };
    let api = Url::parse("http://127.0.0.1:9/").unwrap();
    let web = Url::parse("http://127.0.0.1:9/").unwrap();
    let good = app("https://github.com/alice/remotely/releases/latest/download/latest.json");
    assert!(TauriUpdater::with_github(good.handle().clone(), api.clone(), web.clone()).is_ok());
    let other = app("https://updates.example.com/latest.json");
    assert!(TauriUpdater::with_github(other.handle().clone(), api, web).is_err());
}
