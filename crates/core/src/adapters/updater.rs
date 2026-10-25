//! Updater adapter (FD-14): checks the GitHub Releases of the app's repository for a newer signed
//! version and installs it. The repository is public, so a call needs no token; with the optional
//! read-only GitHub update token from the vault ([`crate::updates`]) it carries that token instead.
//!
//! The real implementation lives in the Tauri shell: it finds the latest release through the GitHub
//! API ([`super::github`]) and has `tauri-plugin-updater` fetch latest.json and the installer from
//! their public download links (without a token) or their API asset URLs (with one), verifying every
//! update's signature either way. Checking is a read. Installing is a state change: it is the
//! [`Command::AppUpdate`](crate::command_bus::Command::AppUpdate) command, Medium tier, and the job
//! runner starts it only once no other job is open.
//!
//! latest.json's `version` is not signed, so on its own it doesn't say which installer it points to:
//! someone who can edit a release but has no signing key could pair an old, validly signed
//! installer with a higher version and roll every install back. The signature's trusted comment
//! does say: the Tauri signer writes `timestamp:<secs>\tfile:<installer>\tversion:<version>` there
//! and covers it with the release key (minisign's global signature). [`check_signed_release`] reads
//! it only after that signature checks out against the app's public key, and refuses an update whose
//! installer was signed for another version.

use async_trait::async_trait;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;

use crate::error::{CoreError, Result};
use crate::vault::SecretString;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const TRUSTED: &str = "trusted comment: ";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current_version: String,
    pub version: String,
    /// Release notes from the GitHub Release.
    pub notes: Option<String>,
    pub pub_date: Option<String>,
}

/// What one check found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReleaseCheck {
    /// `None` when this is the latest version (or nothing is published yet).
    pub update: Option<UpdateInfo>,
    /// When the token expires (`YYYY-MM-DD`), as GitHub reported it. `None` without a token, and for
    /// a token with no expiry.
    pub token_expires_on: Option<String>,
}

/// What testing the token found. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenReport {
    /// `owner/name` of the repository whose releases the token can read.
    pub repository: String,
    /// The tag of the latest published release, if there is one.
    pub latest_release: Option<String>,
    /// When the token expires (`YYYY-MM-DD`), as GitHub reported it. `None` for a token with no expiry.
    pub expires_on: Option<String>,
}

/// `token` is the GitHub update token, or `None` to read the public releases without one. Without a
/// token, a repository GitHub doesn't show fails with [`CoreError::UpdateTokenNeeded`]; with or
/// without one, a used-up API limit fails with [`CoreError::UpdateRateLimited`].
#[async_trait]
pub trait UpdaterAdapter: Send + Sync {
    async fn check(&self, token: Option<&SecretString>) -> Result<ReleaseCheck>;
    /// Downloads, verifies and installs `version`. Only the job runner calls this.
    async fn install(&self, token: Option<&SecretString>, version: &str) -> Result<()>;
    /// Settings' "Test": can the token read the releases?
    async fn test_token(&self, token: &SecretString) -> Result<TokenReport>;
}

/// Used until the shell provides the real updater, and at air-gapped sites with checks turned off.
pub struct DisabledUpdater;

#[async_trait]
impl UpdaterAdapter for DisabledUpdater {
    async fn check(&self, _token: Option<&SecretString>) -> Result<ReleaseCheck> {
        Ok(ReleaseCheck::default())
    }

    async fn install(&self, _token: Option<&SecretString>, _version: &str) -> Result<()> {
        Err(CoreError::NotImplemented("FD-14 auto-update"))
    }

    async fn test_token(&self, _token: &SecretString) -> Result<TokenReport> {
        Err(CoreError::NotImplemented("FD-14 auto-update"))
    }
}

/// The NSIS installer's file name for `version`, as the Tauri bundler makes it and the release
/// workflow signs it: `Remotely_0.4.1_x64-setup.exe`. Windows x64 is the only platform.
pub fn installer_name(product: &str, version: &str) -> String {
    format!("{product}_{version}_x64-setup.exe")
}

/// What an update signature's trusted comment says it signed. Only [`signed_for`] makes one, after
/// the comment's signature checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFor {
    /// `file:`, the installer's file name.
    pub file: Option<String>,
    /// `version:`, the app version it was signed for (Tauri CLI 2.12 and later write it).
    pub version: Option<String>,
}

/// Reads the trusted comment of `signature` (latest.json's `signature`: base64 of the `.sig` file)
/// once its global signature checks out against `pubkey` (`plugins.updater.pubkey`: base64 of the
/// minisign public key file). This doesn't check the installer itself: the updater plugin does
/// that when it downloads it.
pub fn signed_for(pubkey: &str, signature: &str) -> Result<SignedFor> {
    let key_text = minisign_text(pubkey, "the app's update public key")?;
    let mut key_lines = key_text.lines().skip(1);
    let key = decode_line(key_lines.next(), 42, "the app's update public key")?;
    if &key[..2] != b"Ed" {
        return Err(unreadable("the app's update public key"));
    }
    let verifying_key = <[u8; 32]>::try_from(&key[10..42])
        .ok()
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        .ok_or_else(|| unreadable("the app's update public key"))?;

    let sig_text = minisign_text(signature, "the update's signature")?;
    let mut lines = sig_text.lines().skip(1);
    let sig = decode_line(lines.next(), 74, "the update's signature")?;
    if &sig[..2] != b"ED" && &sig[..2] != b"Ed" {
        return Err(unreadable("the update's signature"));
    }
    if sig[2..10] != key[2..10] {
        return Err(refused(
            "it is signed with a different key than the one this app trusts".into(),
        ));
    }
    let comment = lines
        .next()
        .and_then(|line| line.strip_prefix(TRUSTED))
        .ok_or_else(|| unreadable("the update's signature"))?;
    let global = decode_line(lines.next(), 64, "the update's signature")?;
    let global = <[u8; 64]>::try_from(global.as_slice()).map_err(|_| unreadable("the update's signature"))?;

    let mut signed = sig[10..74].to_vec();
    signed.extend_from_slice(comment.as_bytes());
    verifying_key
        .verify_strict(&signed, &Signature::from_bytes(&global))
        .map_err(|_| refused("its signature's trusted comment was not signed with the release key".into()))?;

    let field = |name: &str| {
        comment
            .split('\t')
            .find_map(|part| part.strip_prefix(name))
            .map(str::to_owned)
    };
    Ok(SignedFor {
        file: field("file:"),
        version: field("version:"),
    })
}

/// C3: refuses an update to `version` unless its signature (checked against `pubkey`) names that
/// version's installer and that version. An old signed installer offered as a higher version fails
/// here. A signature without a version is refused as well, as `requireSignedVersion` has the
/// updater plugin do when it downloads.
pub fn check_signed_release(pubkey: &str, signature: &str, product: &str, version: &str) -> Result<()> {
    let signed = signed_for(pubkey, signature)?;
    let expected = installer_name(product, version);
    match signed.file.as_deref() {
        Some(file) if file == expected => {}
        Some(file) => {
            return Err(refused(format!(
                "latest.json offers {version}, but its installer was signed as {file}, not {expected}"
            )))
        }
        None => return Err(refused("its signature doesn't name the installer it signed".into())),
    }
    match signed.version.as_deref() {
        Some(signed_version) if signed_version.trim_start_matches('v') == version.trim_start_matches('v') => Ok(()),
        Some(signed_version) => Err(refused(format!(
            "latest.json offers {version}, but its installer was signed for {signed_version}"
        ))),
        None => Err(refused(
            "its signature doesn't say which version it was signed for".into(),
        )),
    }
}

fn minisign_text(base64_text: &str, what: &str) -> Result<String> {
    BASE64
        .decode(base64_text.trim())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|text| text.starts_with("untrusted comment:"))
        .ok_or_else(|| unreadable(what))
}

fn decode_line(line: Option<&str>, len: usize, what: &str) -> Result<Vec<u8>> {
    line.and_then(|line| BASE64.decode(line.trim()).ok())
        .filter(|bytes| bytes.len() == len)
        .ok_or_else(|| unreadable(what))
}

fn unreadable(what: &str) -> CoreError {
    CoreError::Update(format!("{what} is not a minisign key or signature"))
}

fn refused(why: String) -> CoreError {
    CoreError::Update(format!("the update was refused: {why}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::fakes::github_server::UpdateSigner;

    const INSTALLER: &str = "Remotely_0.9.0_x64-setup.exe";

    /// The 0.4.0 release's signature (public, from its latest.json) and the app's public key, as
    /// `tauri signer sign` 2.12 and tauri.conf.json wrote them.
    #[test]
    fn the_real_0_4_0_signature_names_its_installer_and_version() {
        const PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDIzNTA5NjY5OEVBOUNDMjAKUldRZ3pLbU9hWlpRSStrN1Ewc1ljZitMdERyMWNBRm0zQVNMbmZtRFlhdGZmNU9jb1dBclVqM2MK";
        const SIGNATURE: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVRZ3pLbU9hWlpRSTZDTlQ5Um5UT3N4dDN4dFBLdnNRT2pFNW5GUSt2cWZzRm1RUGhFU3FaeXBSdUlaOHl3TCszUXF0VGg1bmdCOEY3M0s3eDlxL2I3UktaTllidFFYekFVPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkyNjUxMDEzCWZpbGU6UmVtb3RlbHlfMC40LjBfeDY0LXNldHVwLmV4ZQl2ZXJzaW9uOjAuNC4wCnR0NGtMUzZBSE9tTWEzeVdpQ0Nsdk9lQTArY2toOXpLUllVdmJQL2lrRGdJZWpYZ2xlNkZOb2VubnVBcFF6Q1MzR3dqT053a0NYa09KZWhKMmRlWURnPT0K";
        check_signed_release(PUBKEY, SIGNATURE, "Remotely", "0.4.0").unwrap();
        let err = check_signed_release(PUBKEY, SIGNATURE, "Remotely", "0.4.1").unwrap_err();
        assert!(
            err.to_string().contains("signed as Remotely_0.4.0_x64-setup.exe"),
            "{err}"
        );
    }

    #[test]
    fn the_installer_name_is_the_bundlers() {
        assert_eq!(installer_name("Remotely", "0.4.1"), "Remotely_0.4.1_x64-setup.exe");
    }

    #[test]
    fn a_signature_for_this_version_passes() {
        let signer = UpdateSigner::generate();
        let signature = signer.sign(b"MZ installer", INSTALLER, "0.9.0");
        let signed = signed_for(&signer.public_key(), &signature).unwrap();
        assert_eq!(signed.file.as_deref(), Some(INSTALLER));
        assert_eq!(signed.version.as_deref(), Some("0.9.0"));
        check_signed_release(&signer.public_key(), &signature, "Remotely", "0.9.0").unwrap();
    }

    #[test]
    fn an_old_installer_offered_as_a_newer_version_is_refused() {
        let signer = UpdateSigner::generate();
        let old = signer.sign(b"MZ 0.3.0", "Remotely_0.3.0_x64-setup.exe", "0.3.0");
        let err = check_signed_release(&signer.public_key(), &old, "Remotely", "0.9.0").unwrap_err();
        assert_eq!(err.code(), "update_failed");
        assert!(
            err.to_string().contains("signed as Remotely_0.3.0_x64-setup.exe"),
            "{err}"
        );

        // The right file name with another version in the comment is refused too.
        let mixed = signer.sign(b"MZ", INSTALLER, "0.3.0");
        let err = check_signed_release(&signer.public_key(), &mixed, "Remotely", "0.9.0").unwrap_err();
        assert!(err.to_string().contains("signed for 0.3.0"), "{err}");
    }

    #[test]
    fn signatures_without_the_file_name_or_version_are_refused() {
        let signer = UpdateSigner::generate();
        let signature = signer.sign_with_comment(b"MZ", "timestamp:1700000000");
        let err = check_signed_release(&signer.public_key(), &signature, "Remotely", "0.9.0").unwrap_err();
        assert!(err.to_string().contains("doesn't name the installer"), "{err}");

        // As Tauri CLIs before --app-version signed.
        let signature = signer.sign_with_comment(b"MZ", &format!("timestamp:1700000000	file:{INSTALLER}"));
        let err = check_signed_release(&signer.public_key(), &signature, "Remotely", "0.9.0").unwrap_err();
        assert!(err.to_string().contains("doesn't say which version"), "{err}");
    }

    #[test]
    fn an_edited_trusted_comment_is_refused() {
        let signer = UpdateSigner::generate();
        let old = signer.sign(b"MZ 0.3.0", "Remotely_0.3.0_x64-setup.exe", "0.3.0");
        // Rewrite the comment to name 0.9.0 without the key: the global signature no longer matches.
        let text = String::from_utf8(BASE64.decode(&old).unwrap()).unwrap();
        let forged = BASE64.encode(text.replace("0.3.0", "0.9.0"));
        let err = check_signed_release(&signer.public_key(), &forged, "Remotely", "0.9.0").unwrap_err();
        assert!(err.to_string().contains("not signed with the release key"), "{err}");
    }

    #[test]
    fn another_key_and_garbage_are_refused() {
        let signer = UpdateSigner::generate();
        let other = UpdateSigner::generate().sign(b"MZ", INSTALLER, "0.9.0");
        let err = check_signed_release(&signer.public_key(), &other, "Remotely", "0.9.0").unwrap_err();
        assert!(err.to_string().contains("different key"), "{err}");

        for bad in ["", "not base64!", &BASE64.encode("untrusted comment: x\nAAAA\n")] {
            let err = check_signed_release(&signer.public_key(), bad, "Remotely", "0.9.0").unwrap_err();
            assert!(err.to_string().contains("is not a minisign"), "{err}");
        }
        let err = check_signed_release("", &other, "Remotely", "0.9.0").unwrap_err();
        assert!(err.to_string().contains("public key"), "{err}");
    }
}
