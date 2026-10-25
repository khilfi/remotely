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
//! * A push can restrict the key ([`KeyOptions`]): `expiry-time` (it stops working at the start of a day,
//!   UTC) and `from` (the hosts or networks it may log in from), written before the key in
//!   `authorized_keys`. `expiry-time` needs OpenSSH 8.2 or later on the host: an older sshd rejects the
//!   whole line, so there the key does not log in at all (never more than asked). A key that is already
//!   in the file is left alone, so a push with options fails on such a host and says to remove the key
//!   first, rather than leaving it without the restrictions asked for.
//! * Removing a key from hosts ([`Command::RemoveSshKey`](crate::command_bus::Command)) is a command on
//!   the bus too (Medium): [`remove_key_script`] drops every line holding the key's data, through a new
//!   file that replaces the old one in one step, so a failure never leaves half a file.
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
use crate::presentation::Change;
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
/// SS-09: the most `from` patterns one push may give a key.
pub const MAX_FROM_PATTERNS: usize = 32;
/// SS-09: an expiry date at most this many years ahead.
pub const MAX_EXPIRY_YEARS: i32 = 10;

/// SS-09: restrictions written before a pushed key in `authorized_keys` (sshd(8), "AUTHORIZED_KEYS
/// FILE FORMAT"). Empty: none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KeyOptions {
    /// The day the key stops working, `YYYY-MM-DD`, at 00:00 UTC (`expiry-time="YYYYMMDDZ"`, OpenSSH
    /// 8.2 or later).
    pub expires_on: Option<String>,
    /// Where the key may log in from: host names and addresses, with `*` and `?`, CIDR networks
    /// (`192.0.2.0/24`) and `!` to exclude (`from="..."`).
    pub from: Vec<String>,
}

impl KeyOptions {
    pub fn is_empty(&self) -> bool {
        self.expires_on.is_none() && self.from.is_empty()
    }

    /// Checks what the user typed, against `today` (UTC).
    pub fn validate(&self, today: time::Date) -> Result<()> {
        let invalid = |m: String| Err(CoreError::InvalidInput(m));
        if let Some(day) = &self.expires_on {
            let date = parse_day(day)?;
            if date <= today {
                return invalid("The key's expiry date must be after today.".into());
            }
            let latest = today.replace_year(today.year() + MAX_EXPIRY_YEARS).unwrap_or(today);
            if date > latest {
                return invalid(format!(
                    "The key's expiry date can be at most {MAX_EXPIRY_YEARS} years ahead."
                ));
            }
        }
        if self.from.len() > MAX_FROM_PATTERNS {
            return invalid(format!("A key takes at most {MAX_FROM_PATTERNS} 'from' patterns."));
        }
        for pattern in &self.from {
            check_from(pattern)?;
        }
        Ok(())
    }

    /// The options as they go before the key, e.g. `expiry-time="20261201Z",from="192.0.2.0/24"`, or
    /// "" for none. Only checked values are written ([`KeyOptions::validate`]).
    pub fn prefix(&self) -> String {
        let mut parts = Vec::new();
        if let Some(day) = self.expires_on.as_deref().and_then(|d| parse_day(d).ok()) {
            parts.push(format!(
                "expiry-time=\"{:04}{:02}{:02}Z\"",
                day.year(),
                u8::from(day.month()),
                day.day()
            ));
        }
        let from: Vec<&str> = self.from.iter().map(|p| p.trim()).filter(|p| !p.is_empty()).collect();
        if !from.is_empty() {
            parts.push(format!("from=\"{}\"", from.join(",")));
        }
        parts.join(",")
    }

    /// For the audit log and the approval dialog: "expires on 2026-12-01; only from 192.0.2.0/24".
    pub fn describe(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(day) = &self.expires_on {
            parts.push(format!("stops working on {day} (UTC)"));
        }
        if !self.from.is_empty() {
            parts.push(format!("logs in only from {}", self.from.join(", ")));
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

/// `YYYY-MM-DD`.
fn parse_day(day: &str) -> Result<time::Date> {
    time::Date::parse(day.trim(), time::macros::format_description!("[year]-[month]-[day]"))
        .map_err(|_| CoreError::InvalidInput("Give the key's expiry date as YYYY-MM-DD.".into()))
}

/// One `from` pattern: a host name or address with `*` and `?`, a CIDR network, `!` in front to
/// exclude. Nothing that could end the option (quotes, commas, spaces) or confuse sshd.
fn check_from(pattern: &str) -> Result<()> {
    let p = pattern.trim();
    let body = p.strip_prefix('!').unwrap_or(p);
    let ok = !body.is_empty()
        && p.len() <= 255
        && body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '*' | '?' | '/' | '%'))
        && body.matches('/').count() <= 1;
    if ok {
        Ok(())
    } else {
        Err(CoreError::InvalidInput(format!(
            "'{p}' is not a host, address or network to log in from: use names like *.example.com, addresses like 192.0.2.10 or networks like 192.0.2.0/24."
        )))
    }
}

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

/// SS-09: the script that adds `key` to `~/.ssh/authorized_keys` on a host, as `ssh-copy-id` does,
/// with `options` before it ([`KeyOptions::prefix`]).
///
/// * The key goes in once: a key whose base64 data is already in the file (with any comment or
///   options) is left alone, so pushing twice changes nothing. With options, such a host fails with
///   exit code 3 instead: the key there does not have the restrictions asked for.
/// * `~/.ssh` and the file are created with umask 077, and set to 700 and 600 even when they existed:
///   sshd ignores the file when it is writable by others (StrictModes).
/// * A file whose last line has no line break gets one first, so the key never joins that line.
/// * SELinux labels are restored when `restorecon` is there (RHEL and Fedora need them).
/// * It runs in `sh -c`, whatever the login shell is, and prints what it did.
pub fn authorized_keys_script(key: &PublicKeyInfo, options: &KeyOptions) -> String {
    let prefix = options.prefix();
    let line = if prefix.is_empty() {
        key.line.clone()
    } else {
        format!("{prefix} {}", key.line)
    };
    let already = if prefix.is_empty() {
        r#"&& echo "The key was already in ~/.ssh/authorized_keys." && exit 0"#
    } else {
        r#"&& echo "The key is already in ~/.ssh/authorized_keys, so it was left as it is, without the options asked for. Remove it from the hosts first, then push it again." >&2 && exit 3"#
    };
    let script = format!(
        r#"umask 077
mkdir -p ~/.ssh || exit 1
chmod 700 ~/.ssh || exit 1
touch ~/.ssh/authorized_keys || exit 1
chmod 600 ~/.ssh/authorized_keys || exit 1
grep -qF {blob} ~/.ssh/authorized_keys {already}
[ -z "$(tail -c 1 ~/.ssh/authorized_keys)" ] || echo >> ~/.ssh/authorized_keys || exit 1
printf '%s\n' {line} >> ~/.ssh/authorized_keys || exit 1
command -v restorecon >/dev/null 2>&1 && restorecon -F ~/.ssh ~/.ssh/authorized_keys
echo "Added the key to ~/.ssh/authorized_keys.""#,
        blob = sh_quote(key.blob()),
        line = sh_quote(&line),
    );
    format!("sh -c {}", sh_quote(&script))
}

/// SS-09: the script that removes `key` from `~/.ssh/authorized_keys` on a host: every line holding
/// its base64 data, whatever its comment or options. The other lines go to a new file beside it
/// (mode 600), which then replaces the old one in one step (`mv`), so a full disk or a dropped
/// connection never leaves half a file. A host without the key, or without the file, succeeds and
/// says so.
pub fn remove_key_script(key: &PublicKeyInfo) -> String {
    let script = format!(
        r#"umask 077
[ -f ~/.ssh/authorized_keys ] || echo "There is no ~/.ssh/authorized_keys, so the key is not there."
[ -f ~/.ssh/authorized_keys ] || exit 0
grep -qF {blob} ~/.ssh/authorized_keys || echo "The key was not in ~/.ssh/authorized_keys."
grep -qF {blob} ~/.ssh/authorized_keys || exit 0
rm -f ~/.ssh/.authorized_keys.remotely
grep -vF {blob} ~/.ssh/authorized_keys > ~/.ssh/.authorized_keys.remotely
[ $? != 2 ] || exit 1
[ -f ~/.ssh/.authorized_keys.remotely ] || exit 1
chmod 600 ~/.ssh/.authorized_keys.remotely || exit 1
mv -f ~/.ssh/.authorized_keys.remotely ~/.ssh/authorized_keys || exit 1
grep -qF {blob} ~/.ssh/authorized_keys && echo "The key is still in ~/.ssh/authorized_keys." >&2 && exit 1
command -v restorecon >/dev/null 2>&1 && restorecon -F ~/.ssh/authorized_keys
echo "Removed the key from ~/.ssh/authorized_keys.""#,
        blob = sh_quote(key.blob()),
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
        self.store.read_only().check(Change::SshKeys)?;
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
        self.store.read_only().check(Change::SshKeys)?;
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
        let script = authorized_keys_script(&key, &KeyOptions::default());
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
    fn key_options_are_checked_and_written_as_sshd_reads_them() {
        let today = time::macros::date!(2026 - 10 - 25);
        let options = KeyOptions {
            expires_on: Some("2026-12-01".into()),
            from: vec!["192.0.2.0/24".into(), "*.example.com".into(), "!198.51.100.7".into()],
        };
        options.validate(today).unwrap();
        assert_eq!(
            options.prefix(),
            r#"expiry-time="20261201Z",from="192.0.2.0/24,*.example.com,!198.51.100.7""#
        );
        assert_eq!(KeyOptions::default().prefix(), "");
        assert!(KeyOptions::default().is_empty());
        let bad = |options: KeyOptions| options.validate(today).unwrap_err().code();
        for day in ["2026-10-25", "2026-10-01", "2037-01-01", "01/12/2026", "tomorrow"] {
            let options = KeyOptions {
                expires_on: Some(day.into()),
                ..Default::default()
            };
            assert_eq!(bad(options), "invalid_input", "{day}");
        }
        for pattern in ["", "!", "a b", "a,b", "x\"y", "1.2.3.4/8/8", "host\\name"] {
            let options = KeyOptions {
                from: vec![pattern.into()],
                ..Default::default()
            };
            assert_eq!(bad(options), "invalid_input", "{pattern:?}");
        }
        let many = KeyOptions {
            from: (0..=MAX_FROM_PATTERNS).map(|i| format!("h{i}.example.com")).collect(),
            ..Default::default()
        };
        assert_eq!(bad(many), "invalid_input");
    }

    #[test]
    fn a_push_with_options_writes_them_before_the_key_and_never_leaves_an_unrestricted_key() {
        let key = ed25519("contractor");
        let options = KeyOptions {
            expires_on: Some("2026-12-01".into()),
            from: vec!["192.0.2.0/24".into()],
        };
        let script = authorized_keys_script(&key, &options);
        assert!(script.contains("expiry-time="), "{script}");
        // Already there: the host fails (exit 3) instead of keeping the key without the options.
        assert!(script.contains("exit 3"), "{script}");
        assert!(!authorized_keys_script(&key, &KeyOptions::default()).contains("exit 3"));
    }

    #[test]
    fn the_removal_script_replaces_the_file_in_one_step_and_checks_it_worked() {
        let key = ed25519("old");
        let script = remove_key_script(&key);
        assert!(script.starts_with("sh -c '"));
        assert!(script.contains(key.blob()));
        let filter = script.find("grep -vF").unwrap();
        let swap = script.find("mv -f").unwrap();
        let check = script.rfind("grep -qF").unwrap();
        assert!(filter < swap && swap < check, "filter, then swap, then check");
        assert!(
            !script.contains("> ~/.ssh/authorized_keys"),
            "never written over in place"
        );
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
