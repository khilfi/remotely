//! FD-14: the updater adapter end to end on Tauri's mock runtime: GitHub API -> latest.json and the
//! installer through their API asset URLs -> signature check, against a local fake GitHub
//! (`remotely_core::fakes::github_server`) and a signing key made at run time. Never installs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use remotely_core::adapters::updater::UpdaterAdapter;
use remotely_core::fakes::github_server::{latest_json, FakeAsset, FakeGithub, TokenAccess, UpdateSigner};
use remotely_core::vault::SecretString;
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
    context.config_mut().plugins.0.insert(
        "updater".into(),
        json!({
            "pubkey": signer.public_key(),
            "endpoints": [format!("https://github.com/{}/releases/latest/download/latest.json", fake.repo())],
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

    fn updater(&self) -> TauriUpdater<MockRuntime> {
        TauriUpdater::with_api(self.app.handle().clone(), self.fake.api_url()).unwrap()
    }

    /// Publishes `version`: a signed installer, its .sig, and latest.json pointing at
    /// `url(installer)` (tauri-action writes the API asset URL). Returns the installer.
    fn publish_version(&self, version: &str, url: impl Fn(&FakeGithub, &FakeAsset) -> Url) -> Vec<u8> {
        let installer = format!("MZ fake NSIS installer for {version}").into_bytes();
        let signature = self.signer.sign(&installer, INSTALLER, version);
        let assets = self.fake.publish(
            &format!("v{version}"),
            &format!("Remotely {version}"),
            vec![
                (INSTALLER, installer.clone()),
                ("Remotely_0.9.0_x64-setup.exe.sig", signature.clone().into_bytes()),
            ],
        );
        let notes = format!("Remotely {version} notes");
        let manifest = latest_json(version, &notes, &url(&self.fake, &assets[0]), &signature);
        self.fake.add_file(MANIFEST, manifest);
        installer
    }

    fn publish(&self, url: impl Fn(&FakeGithub, &FakeAsset) -> Url) -> Vec<u8> {
        self.publish_version("0.9.0", url)
    }

    fn secret(&self) -> SecretString {
        SecretString::new(self.token.as_str())
    }

    /// Every request that reached the storage came without the token, and every request with the
    /// token went to the API.
    fn assert_token_only_went_to_the_api(&self) {
        let requests = self.fake.requests();
        assert!(requests.iter().any(|r| r.server == "storage"), "{requests:?}");
        for r in &requests {
            match r.server {
                "storage" => assert_eq!(r.authorization(), None, "{r:?}"),
                _ => assert_eq!(r.authorization(), Some(format!("Bearer {}", self.token).as_str())),
            }
        }
    }
}

fn api_url(fake: &FakeGithub, asset: &FakeAsset) -> Url {
    fake.asset_api_url(asset.id)
}

#[test]
fn a_signed_update_is_found_and_downloaded_through_the_api() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        let installer = world.publish(api_url);
        let updater = world.updater();

        let checked = updater.check(&world.secret()).await.unwrap();
        let update = checked.update.unwrap();
        assert_eq!(update.current_version, "0.1.0");
        assert_eq!(update.version, "0.9.0");
        assert_eq!(update.notes.as_deref(), Some("Remotely 0.9.0 notes"));
        assert_eq!(checked.token_expires_on.as_deref(), Some("2027-01-17"));

        let (offered, bytes) = updater.download(&world.secret(), "0.9.0").await.unwrap();
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
        updater.check(&world.secret()).await.unwrap().update.unwrap();

        world.fake.replace_file(INSTALLER, b"MZ something else".to_vec());
        let Err(err) = updater.download(&world.secret(), "0.9.0").await else {
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
        let installer = b"MZ signed by someone else".to_vec();
        let signature = UpdateSigner::generate().sign(&installer, INSTALLER, "0.9.0");
        let assets = world.fake.publish("v0.9.0", "notes", vec![(INSTALLER, installer)]);
        let manifest = latest_json("0.9.0", "notes", &world.fake.asset_api_url(assets[0].id), &signature);
        world.fake.add_file(MANIFEST, manifest);

        let updater = world.updater();
        updater.check(&world.secret()).await.unwrap().update.unwrap();
        let Err(err) = updater.download(&world.secret(), "0.9.0").await else {
            panic!("the download must fail its signature check");
        };
        assert_eq!(err.code(), "update_failed");
        assert!(err.to_string().contains("different key"), "{err}");
    });
}

#[test]
fn a_github_download_link_in_latest_json_is_fetched_through_the_api() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        let installer = world.publish(|fake, asset| fake.download_link("v0.9.0", &asset.name));
        let updater = world.updater();
        updater.check(&world.secret()).await.unwrap().update.unwrap();
        let (_, bytes) = updater.download(&world.secret(), "0.9.0").await.unwrap();
        assert_eq!(bytes, installer);
        world.assert_token_only_went_to_the_api();
    });
}

#[test]
fn a_download_elsewhere_is_refused_before_the_token_goes_there() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        // A URL on the storage host itself, which must never get the token.
        world.publish(|fake, _| fake.storage_url().join("elsewhere/other-setup.exe").unwrap());
        let err = world.updater().check(&world.secret()).await.unwrap_err();
        assert_eq!(err.code(), "update_failed");
        assert!(err.to_string().contains("not a file of that release"), "{err}");
        assert!(world.fake.requests().iter().all(|r| !r.path.contains("elsewhere")));
        world.assert_token_only_went_to_the_api();
    });
}

#[test]
fn up_to_date_and_no_release_offer_nothing() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        let updater = world.updater();
        // Nothing published yet.
        let checked = updater.check(&world.secret()).await.unwrap();
        assert_eq!(checked.update, None);
        assert_eq!(checked.token_expires_on.as_deref(), Some("2027-01-17"));
        // A release that is not newer than 0.1.0.
        world.publish_version("0.1.0", api_url);
        assert_eq!(updater.check(&world.secret()).await.unwrap().update, None);
    });
}

#[test]
fn bad_revoked_and_unauthorised_tokens_fail_without_leaking() {
    tauri::async_runtime::block_on(async {
        let world = World::new().await;
        world.publish(api_url);
        let updater = world.updater();

        let wrong = new_token();
        let err = updater.check(&SecretString::new(wrong.as_str())).await.unwrap_err();
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
        let err = updater.check(&world.secret()).await.unwrap_err();
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
    let good = app("https://github.com/alice/remotely/releases/latest/download/latest.json");
    assert!(TauriUpdater::with_api(good.handle().clone(), api.clone()).is_ok());
    let other = app("https://updates.example.com/latest.json");
    assert!(TauriUpdater::with_api(other.handle().clone(), api).is_err());
}
