//! SSH key manager (SS-09): generate keys straight into the vault, show and copy their public half in
//! OpenSSH format, attach a key to sessions, and push a public key to many hosts.
//!
//! * A generated key's private half is a `private_key` vault item like any other: it never leaves the
//!   vault except to the remote adapter, when a session logs in with it. The public half (the OpenSSH
//!   line, fingerprint and comment) is not secret, so it is kept beside the vault (`ssh_keys`) and
//!   shown even while the vault is locked. For a private key added another way (pasted, imported), the
//!   public half is read from it once, while the vault is unlocked.
//! * Pushing a key appends its public line to `~/.ssh/authorized_keys` on each host unless the key is
//!   already there, and makes `~/.ssh` 700 and the file 600, as sshd's StrictModes wants. It changes
//!   the hosts, so it is a command on the bus ([`Command::PushSshKey`](crate::command_bus::Command)):
//!   the policy engine rates it (Medium by default, Prod raises it), it is approved and audited like
//!   any remote command, and the job runner runs [`authorized_keys_script`] on each host over SSH.
//! * Generating a key and attaching it to sessions change only the app's own data: audited, no tier.

use std::sync::Arc;

use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData, RsaKeypair};
use russh::keys::ssh_key::{LineEnding, PrivateKey, PublicKey};
use russh::keys::HashAlg;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::adapters::remote::sh_quote;
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::sessions::{SessionAuth, SessionLibrary, SessionRecord};
use crate::store::{NewAuditEntry, Store};
use crate::vault::{clean_label, SecretId, SecretKind, SecretString, Vault, VaultStatus};

/// What kind of key to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyType {
    /// The default: short, fast and supported by every OpenSSH since 6.5 (2014).
    #[default]
    Ed25519,
    /// RSA with [`RSA_BITS`] bits, for hosts too old for Ed25519.
    Rsa,
}

impl KeyType {
    pub fn label(self) -> &'static str {
        match self {
            KeyType::Ed25519 => "Ed25519",
            KeyType::Rsa => "RSA 4096",
        }
    }
}

/// Size of generated RSA keys.
pub const RSA_BITS: usize = 4096;
/// Longest comment a key may carry.
pub const MAX_COMMENT_LEN: usize = 100;
/// Longest public key line taken (an RSA 16384 line is about 2.8 KB).
pub const MAX_PUBLIC_KEY_LEN: usize = 16 * 1024;

/// A public key in OpenSSH's one-line form. Not secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyInfo {
    /// The key's algorithm, e.g. `ssh-ed25519` or `ssh-rsa`.
    pub algorithm: String,
    /// `<algorithm> <base64> <comment>`, as it goes into `authorized_keys`.
    pub line: String,
    /// `SHA256:` and the base64 digest, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
    pub comment: String,
    /// RSA only: the modulus size in bits.
    pub bits: Option<u32>,
}

impl PublicKeyInfo {
    /// The base64 key data: what identifies the key in `authorized_keys`, whatever its comment.
    pub fn blob(&self) -> &str {
        self.line.split_whitespace().nth(1).unwrap_or_default()
    }

    /// `'alice@laptop' (SHA256:...)`, or the fingerprint alone, for summaries and the audit log.
    pub fn describe(&self) -> String {
        if self.comment.is_empty() {
            self.fingerprint.clone()
        } else {
            format!("'{}' ({})", self.comment, self.fingerprint)
        }
    }

    fn of(key: &PublicKey) -> Result<Self> {
        let comment = check_comment(key.comment().as_str_lossy())?;
        let mut key = key.clone();
        key.set_comment(comment.as_str());
        let line = key
            .to_openssh()
            .map_err(|err| CoreError::InvalidInput(format!("The public key can't be written out: {err}")))?;
        Ok(Self {
            algorithm: key.algorithm().as_str().to_owned(),
            line,
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            comment,
            bits: key.key_data().rsa().map(|rsa| rsa.key_size()),
        })
    }
}

/// A private key in the vault, as the key manager shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKey {
    pub id: SecretId,
    pub label: String,
    /// Sessions that log in with it.
    pub used_by: i64,
    pub created_at: String,
    /// Remotely generated it.
    pub generated: bool,
    /// `None` until Remotely has read it from the private key, which needs the vault unlocked.
    pub public: Option<PublicKeyInfo>,
}

/// What the "Generate key" form sends.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKey {
    /// The vault label.
    pub label: String,
    #[serde(default)]
    pub key_type: KeyType,
    /// Written after the key in `authorized_keys`, to tell keys apart there. Empty: the label.
    #[serde(default)]
    pub comment: String,
}

/// A comment, trimmed: one line of at most [`MAX_COMMENT_LEN`] characters.
fn check_comment(comment: &str) -> Result<String> {
    let comment = comment.trim();
    if comment.chars().any(char::is_control) {
        return Err(CoreError::InvalidInput(
            "A key comment can't hold line breaks, tabs or other control characters.".into(),
        ));
    }
    if comment.chars().count() > MAX_COMMENT_LEN {
        return Err(CoreError::InvalidInput(format!(
            "A key comment can be at most {MAX_COMMENT_LEN} characters."
        )));
    }
    Ok(comment.to_owned())
}

/// SS-09: checks a public key the user pasted or a command carries, and returns it in Remotely's own
/// form (only that form is ever written to a host). Messages never quote the text.
pub fn parse_public_key(text: &str) -> Result<PublicKeyInfo> {
    let text = text.trim();
    if text.is_empty() {
        return Err(CoreError::InvalidInput("Paste a public key.".into()));
    }
    if text.contains("PRIVATE KEY") || text.starts_with("PuTTY-User-Key-File-") {
        return Err(CoreError::InvalidInput(
            "That is a private key. Push the public key (the .pub file) instead.".into(),
        ));
    }
    if text.len() > MAX_PUBLIC_KEY_LEN {
        return Err(CoreError::InvalidInput(format!(
            "A public key can be at most {} KB.",
            MAX_PUBLIC_KEY_LEN / 1024
        )));
    }
    if text.contains(['\n', '\r']) {
        return Err(CoreError::InvalidInput("A public key is a single line.".into()));
    }
    let key = PublicKey::from_openssh(text).map_err(|_| {
        CoreError::InvalidInput(
            "That is not an OpenSSH public key: expected one line like 'ssh-ed25519 AAAA… comment' (the .pub file)."
                .into(),
        )
    })?;
    PublicKeyInfo::of(&key)
}

/// SS-09: the script that adds `key` to `~/.ssh/authorized_keys` on a host, as `ssh-copy-id` does.
///
/// * The key goes in once: a key whose base64 data is already in the file (with any comment or
///   options) is left alone, so pushing twice changes nothing.
/// * `~/.ssh` and the file are created with umask 077, and set to 700 and 600 even when they existed:
///   sshd ignores the file when it is writable by others (StrictModes).
/// * A file whose last line has no line break gets one first, so the key never joins that line.
/// * SELinux labels are restored when `restorecon` is there (RHEL and Fedora need them).
/// * It runs in `sh -c`, whatever the login shell is, and prints what it did.
pub fn authorized_keys_script(key: &PublicKeyInfo) -> String {
    let script = format!(
        r#"umask 077
mkdir -p ~/.ssh || exit 1
chmod 700 ~/.ssh || exit 1
touch ~/.ssh/authorized_keys || exit 1
chmod 600 ~/.ssh/authorized_keys || exit 1
grep -qF {blob} ~/.ssh/authorized_keys && echo "The key was already in ~/.ssh/authorized_keys." && exit 0
[ -z "$(tail -c 1 ~/.ssh/authorized_keys)" ] || echo >> ~/.ssh/authorized_keys || exit 1
printf '%s\n' {line} >> ~/.ssh/authorized_keys || exit 1
command -v restorecon >/dev/null 2>&1 && restorecon -F ~/.ssh ~/.ssh/authorized_keys
echo "Added the key to ~/.ssh/authorized_keys.""#,
        blob = sh_quote(key.blob()),
        line = sh_quote(&key.line),
    );
    format!("sh -c {}", sh_quote(&script))
}

/// A new key pair: the private key in OpenSSH's text form, and its public half. Slow for RSA: run it
/// off the async threads.
fn generate(key_type: KeyType, comment: &str) -> Result<(SecretString, PublicKeyInfo)> {
    // The system's random source does not fail on supported Windows versions; UnwrapErr gives key
    // generation the infallible interface it takes.
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let failed = |err: &dyn std::fmt::Display| CoreError::Vault(format!("generating the key failed: {err}"));
    let data = match key_type {
        KeyType::Ed25519 => KeypairData::from(Ed25519Keypair::random(&mut rng)),
        KeyType::Rsa => KeypairData::from(RsaKeypair::random(&mut rng, RSA_BITS).map_err(|e| failed(&e))?),
    };
    let private = PrivateKey::new(data, comment).map_err(|e| failed(&e))?;
    let public = PublicKeyInfo::of(private.public_key())?;
    let text = private.to_openssh(LineEnding::LF).map_err(|e| failed(&e))?;
    Ok((SecretString::new(text.as_str()), public))
}

/// Reads a private key's public half. `None` when it needs a passphrase that is not among `passphrases`.
fn public_half(key: &SecretString, passphrases: &[SecretString]) -> Result<Option<PublicKeyInfo>> {
    let unreadable = |err: &dyn std::fmt::Display| CoreError::InvalidInput(format!("The key can't be read: {err}"));
    match russh::keys::decode_secret_key(key.expose(), None) {
        Ok(private) => return PublicKeyInfo::of(private.public_key()).map(Some),
        Err(err) if !needs_passphrase(&err) => return Err(unreadable(&err)),
        Err(_) => {}
    }
    for passphrase in passphrases {
        if let Ok(private) = russh::keys::decode_secret_key(key.expose(), Some(passphrase.expose())) {
            return PublicKeyInfo::of(private.public_key()).map(Some);
        }
    }
    Ok(None)
}

fn needs_passphrase(err: &russh::keys::Error) -> bool {
    match err {
        russh::keys::Error::KeyIsEncrypted => true,
        russh::keys::Error::SshKey(e) => matches!(e, russh::keys::ssh_key::Error::Encrypted),
        _ => false,
    }
}

/// Runs slow work (RSA key generation, opening a passphrase-protected key) off the async threads.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| CoreError::Vault(format!("the key task stopped: {err}")))?
}

pub struct KeyManager {
    store: Store,
    vault: Arc<dyn Vault>,
}

impl KeyManager {
    pub fn new(store: Store, vault: Arc<dyn Vault>) -> Self {
        Self { store, vault }
    }

    /// Every private key in the vault, by label, with its public half when Remotely knows it. Works
    /// while the vault is locked.
    pub async fn list(&self, ctx: &Context) -> Result<Vec<SshKey>> {
        let mut rows = self.store.ssh_key_rows(ctx).await?;
        Ok(self
            .vault
            .list(ctx)
            .await?
            .into_iter()
            .filter(|m| m.kind == SecretKind::PrivateKey)
            .map(|m| {
                let row = rows.remove(&m.id);
                SshKey {
                    id: m.id,
                    label: m.label,
                    used_by: m.used_by,
                    created_at: m.created_at,
                    generated: row.as_ref().is_some_and(|r| r.generated),
                    public: row.map(|r| r.public),
                }
            })
            .collect())
    }

    pub async fn get(&self, ctx: &Context, id: SecretId) -> Result<SshKey> {
        self.list(ctx)
            .await?
            .into_iter()
            .find(|k| k.id == id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("SSH key {id}")))
    }

    /// SS-09: makes a new key pair and saves the private key in the vault, which must be unlocked.
    /// Audited with the key's type and fingerprint.
    pub async fn generate(&self, ctx: &Context, request: GenerateKey) -> Result<SshKey> {
        let label = clean_label(&request.label)?;
        let comment = match check_comment(&request.comment)? {
            empty if empty.is_empty() => check_comment(&label)?,
            comment => comment,
        };
        match self.vault.status() {
            VaultStatus::Unlocked => {}
            VaultStatus::Locked => return Err(CoreError::VaultLocked),
            VaultStatus::NotSetUp => return Err(CoreError::VaultNotSetUp),
        }
        // Checked before the slow part; the vault checks again when it saves.
        if self.store.vault_label_taken(ctx, &label, None).await? {
            return Err(CoreError::InvalidInput(format!(
                "There is already a secret labelled '{label}'."
            )));
        }
        let key_type = request.key_type;
        let (private, public) = blocking(move || generate(key_type, &comment)).await?;
        let id = self.vault.put(ctx, SecretKind::PrivateKey, &label, private).await?;
        self.store.put_ssh_key(ctx, id, &public, true).await?;
        let detail = format!("{}, {}", key_type.label(), public.fingerprint);
        self.audit(ctx, &format!("Generated the SSH key '{label}'"), Some(&detail))
            .await?;
        self.get(ctx, id).await
    }

    /// The key with its public half, read from the private key when Remotely does not know it yet
    /// (needs the vault unlocked) and kept for next time. A key with a passphrase opens with one a
    /// session saves for it.
    pub async fn read_public_key(&self, ctx: &Context, id: SecretId) -> Result<SshKey> {
        let key = self.get(ctx, id).await?;
        if key.public.is_some() {
            return Ok(key);
        }
        let private = self.vault.get(ctx, id).await?;
        let mut passphrases = Vec::new();
        for passphrase_id in self.passphrases_for(ctx, id).await? {
            passphrases.push(self.vault.get(ctx, passphrase_id).await?);
        }
        let public = blocking(move || public_half(&private, &passphrases))
            .await
            .map_err(|err| CoreError::InvalidInput(format!("'{}': {err}", key.label)))?
            .ok_or_else(|| {
                CoreError::InvalidInput(format!(
                    "The key '{}' has a passphrase, and no session saves it, so its public key can't be read.",
                    key.label
                ))
            })?;
        self.store.put_ssh_key(ctx, id, &public, false).await?;
        self.get(ctx, id).await
    }

    /// SS-09: sessions log in with this key from now on. Each change is a session edit, audited by the
    /// session library. A session that already uses the key keeps its passphrase; the others get the
    /// passphrase another session saves for the key, if any. Returns the sessions changed.
    pub async fn attach(
        &self,
        ctx: &Context,
        id: SecretId,
        session_ids: &[Uuid],
        library: &SessionLibrary,
    ) -> Result<Vec<SessionRecord>> {
        if session_ids.is_empty() {
            return Err(CoreError::NoTargets);
        }
        self.get(ctx, id).await?;
        let passphrase = self.passphrases_for(ctx, id).await?.into_iter().next();
        let mut changed = Vec::new();
        for session_id in session_ids {
            let session = library.get(ctx, *session_id).await?;
            if matches!(session.auth, SessionAuth::Key { key_id: Some(k), .. } if k == id) {
                continue;
            }
            let mut input = session.input();
            input.auth = SessionAuth::Key {
                key_id: Some(id),
                passphrase_id: passphrase,
            };
            changed.push(library.update(ctx, *session_id, input).await?);
        }
        Ok(changed)
    }

    /// Passphrases sessions save for this key.
    async fn passphrases_for(&self, ctx: &Context, id: SecretId) -> Result<Vec<SecretId>> {
        let mut found = Vec::new();
        for session in self.store.list_sessions(ctx).await? {
            if let SessionAuth::Key {
                key_id: Some(key),
                passphrase_id: Some(passphrase),
            } = session.auth
            {
                if key == id && !found.contains(&passphrase) {
                    found.push(passphrase);
                }
            }
        }
        Ok(found)
    }

    async fn audit(&self, ctx: &Context, action: &str, detail: Option<&str>) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "vault_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail,
                },
            )
            .await
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed25519(comment: &str) -> PublicKeyInfo {
        generate(KeyType::Ed25519, comment).unwrap().1
    }

    #[test]
    fn generated_keys_are_openssh_text_with_a_matching_public_half() {
        let (private, public) = generate(KeyType::Ed25519, "alice@laptop").unwrap();
        assert!(private.expose().starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        let decoded = russh::keys::decode_secret_key(private.expose(), None).unwrap();
        assert_eq!(
            decoded.public_key().fingerprint(HashAlg::Sha256).to_string(),
            public.fingerprint
        );
        assert_eq!(public.algorithm, "ssh-ed25519");
        assert_eq!(public.comment, "alice@laptop");
        assert!(public.line.starts_with("ssh-ed25519 AAAA"));
        assert!(public.line.ends_with(" alice@laptop"));
        assert!(public.fingerprint.starts_with("SHA256:"));
        assert_eq!(public.bits, None);
        // Keys are new each time.
        assert_ne!(ed25519("alice@laptop").blob(), public.blob());
    }

    #[test]
    fn public_keys_round_trip_and_bad_ones_are_refused_without_quoting_them() {
        let key = ed25519("bob@example.org");
        assert_eq!(parse_public_key(&format!("  {}\n", key.line)).unwrap(), key);
        let no_comment = key.line.rsplit_once(' ').unwrap().0;
        assert_eq!(parse_public_key(no_comment).unwrap().comment, "");

        let private_kind = "OPENSSH PRIVATE KEY";
        for bad in [
            String::new(),
            "ssh-ed25519 not-base64 bob".to_owned(),
            format!("-----BEGIN {private_kind}-----"),
            format!("{}\n{}", key.line, key.line),
            format!("ssh-rsa {}", key.blob()),
        ] {
            let err = parse_public_key(&bad).unwrap_err();
            assert_eq!(err.code(), "invalid_input", "{bad}");
            if bad.len() > 12 {
                assert!(!err.to_string().contains(&bad), "{err}");
            }
        }
    }

    #[test]
    fn comments_are_one_short_line() {
        assert_eq!(check_comment("  alice@laptop ").unwrap(), "alice@laptop");
        assert!(check_comment("a\tb").is_err());
        assert!(check_comment(&"x".repeat(MAX_COMMENT_LEN + 1)).is_err());
    }

    #[test]
    fn the_push_script_quotes_the_key_and_checks_before_it_appends() {
        let mut key = ed25519("it's alice");
        key.comment = "it's alice".into();
        let script = authorized_keys_script(&key);
        assert!(script.starts_with("sh -c '"));
        // The single quote in the comment is escaped twice: in the inner script and for sh -c.
        assert!(!script.contains("it's"));
        assert!(script.contains(key.blob()));
        let grep = script.find("grep -qF").unwrap();
        let append = script.find("printf").unwrap();
        assert!(grep < append, "checks for the key before it appends");
        assert!(script.contains("chmod 700 ~/.ssh"));
        assert!(script.contains("chmod 600 ~/.ssh/authorized_keys"));
    }

    #[test]
    fn a_key_without_its_passphrase_has_no_readable_public_half() {
        let key = crate::fakes::ssh_server::generate_key();
        let locked = crate::fakes::ssh_server::private_key_text(&key, Some("pass phrase"));
        assert_eq!(public_half(&locked, &[]).unwrap(), None);
        let wrong = [SecretString::new("wrong")];
        assert_eq!(public_half(&locked, &wrong).unwrap(), None);
        let right = [SecretString::new("wrong"), SecretString::new("pass phrase")];
        let public = public_half(&locked, &right).unwrap().unwrap();
        assert_eq!(public.fingerprint, crate::fakes::ssh_server::fingerprint(&key));
        assert_eq!(
            public_half(&SecretString::new("not a key"), &[]).unwrap_err().code(),
            "invalid_input"
        );
    }
}
