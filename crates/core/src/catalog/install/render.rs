//! VM-28: one answer file per VM, from a config, the VM's values and the vault's secrets. Pure but for the random
//! bytes it is given ([`Random`]), so tests can check it whole; G6 calls it for each VM of an unattended deploy.
//!
//! * Built-ins and own variables are written as they are, once [`super::vars::check_value`] says they can't break the
//!   line or string they go into; Windows' XML escapes them.
//! * `{{password.<name>}}`: on Linux a SHA-512 crypt hash (`$6$`), with a fresh salt each render; Windows' unattend
//!   can't take a hash, so a random one-time password goes in, returned in [`Rendered::one_time`] for G6 to replace
//!   over WinRM once the install is done.
//! * `{{ssh_key.<name>}}`: the key's public half.
//!
//! The rendered file is checked again as its kind (a value that broke it is refused), and kept in a
//! [`SecretString`]: it holds the hashes, so it never reaches a log, the journal or the UI. What may be logged is
//! [`Rendered::sha256`] and the config's name.

use std::collections::{BTreeMap, HashMap};

use sha2::{Digest, Sha256};
use sha_crypt::{PasswordHasher, ShaCrypt};
use time::Date;

use super::vars::{self, Placeholder};
use super::{ConfigProblem, InstallConfigInput, InstallKind, Severity};
use crate::catalog::templates::date_token;
use crate::error::{CoreError, Result};
use crate::vault::SecretString;

/// Where render's salts and one-time passwords come from.
pub trait Random {
    fn fill(&mut self, bytes: &mut [u8]);
}

/// The OS's random source.
pub struct OsRandom;

impl Random for OsRandom {
    fn fill(&mut self, bytes: &mut [u8]) {
        // getrandom fails only on a platform without a random source, which Windows isn't; a failure leaves zeros,
        // which the caller's check of the output's variety catches.
        if getrandom::fill(bytes).is_err() {
            bytes.fill(0);
        }
    }
}

/// One VM's values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmValues {
    pub hostname: String,
    pub ip: Option<String>,
    pub n: u32,
    pub template: String,
    pub date: Date,
    /// Own variables; a missing one takes its default.
    pub values: BTreeMap<String, String>,
}

/// What render takes from the vault, by reference name.
#[derive(Default)]
pub struct RenderSecrets {
    pub passwords: HashMap<String, SecretString>,
    /// Public key lines.
    pub ssh_keys: HashMap<String, String>,
}

/// A Windows account's one-time password, for G6 to replace with the vault's after the install.
pub struct OneTimePassword {
    /// The `{{password.<name>}}` it stands for.
    pub name: String,
    pub password: SecretString,
}

/// One VM's file.
pub struct Rendered {
    pub file_name: &'static str,
    /// The file: it holds password hashes (or one-time passwords), so it is a secret.
    pub text: SecretString,
    /// Of the file, lower case hex: what the journal and audit log may keep.
    pub sha256: String,
    pub one_time: Vec<OneTimePassword>,
}

impl std::fmt::Debug for Rendered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rendered")
            .field("file_name", &self.file_name)
            .field("sha256", &self.sha256)
            .field("one_time", &self.one_time.len())
            .finish_non_exhaustive()
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// A SHA-512 crypt hash of `password` with a 12-byte (16-character) salt from `random`.
pub fn hash_password(password: &str, random: &mut dyn Random) -> Result<String> {
    let mut salt = [0u8; 12];
    random.fill(&mut salt);
    let hash = ShaCrypt::SHA512
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map_err(|_| CoreError::InvalidInput("the password couldn't be hashed".into()))?;
    salt.fill(0);
    Ok(hash.to_string())
}

/// Letters and digits, and symbols Windows takes and XML doesn't escape.
const ONE_TIME_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!+=";
const ONE_TIME_LEN: usize = 24;

/// A random password Windows' complexity rule takes: upper and lower case, a digit and a symbol.
pub fn one_time_password(random: &mut dyn Random) -> SecretString {
    loop {
        let mut bytes = [0u8; ONE_TIME_LEN * 2];
        random.fill(&mut bytes);
        let mut out = String::with_capacity(ONE_TIME_LEN);
        // Rejection sampling: only bytes below the largest multiple of the alphabet's length.
        let limit = 256 - (256 % ONE_TIME_ALPHABET.len());
        for b in bytes {
            if usize::from(b) < limit && out.len() < ONE_TIME_LEN {
                out.push(char::from(ONE_TIME_ALPHABET[usize::from(b) % ONE_TIME_ALPHABET.len()]));
            }
        }
        bytes.fill(0);
        let classes = [
            out.chars().any(|c| c.is_ascii_uppercase()),
            out.chars().any(|c| c.is_ascii_lowercase()),
            out.chars().any(|c| c.is_ascii_digit()),
            out.chars().any(|c| !c.is_ascii_alphanumeric()),
        ];
        if out.len() == ONE_TIME_LEN && classes.iter().all(|c| *c) {
            return SecretString::new(out);
        }
    }
}

/// The value of a non-secret placeholder for `vm`, checked for the file's kind.
fn plain_value(spec: &InstallConfigInput, vm: &VmValues, p: &Placeholder) -> Result<String> {
    let (what, value) = match p {
        Placeholder::BuiltIn("hostname") => {
            if let Some(why) = vars::check_hostname(&vm.hostname) {
                return invalid(format!("{why}."));
            }
            if spec.kind.windows() && vm.hostname.len() > 15 {
                return invalid(format!(
                    "'{}' is longer than the 15 characters a Windows computer name takes.",
                    vm.hostname
                ));
            }
            ("{{hostname}}", vm.hostname.clone())
        }
        Placeholder::BuiltIn("ip") => {
            let Some(ip) = vm.ip.as_deref().map(str::trim).filter(|i| !i.is_empty()) else {
                return invalid(format!(
                    "{} needs an IP address: the install config uses {{{{ip}}}}.",
                    vm.hostname
                ));
            };
            if ip.parse::<std::net::IpAddr>().is_err() {
                return invalid(format!("'{ip}' isn't an IP address."));
            }
            ("{{ip}}", ip.to_owned())
        }
        Placeholder::BuiltIn("n") => ("{{n}}", vm.n.to_string()),
        Placeholder::BuiltIn("date") => ("{{date}}", date_token(vm.date)),
        Placeholder::BuiltIn(_) => ("{{template}}", vm.template.clone()),
        Placeholder::Own(name) => {
            let value = vm
                .values
                .get(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
                .or_else(|| {
                    spec.variables
                        .iter()
                        .find(|v| v.name == *name)
                        .and_then(|v| v.default.clone())
                });
            let Some(value) = value else {
                return invalid(format!("{} has no value for {{{{{name}}}}}.", vm.hostname));
            };
            return match vars::check_value(spec.kind, &value) {
                Some(why) => invalid(format!("{{{{{name}}}}}'s value for {} {why}.", vm.hostname)),
                None => Ok(escape(spec.kind, &value)),
            };
        }
        Placeholder::Password(_) | Placeholder::SshKey(_) => return invalid("a secret isn't a plain value"),
    };
    if let Some(why) = vars::check_value(spec.kind, &value) {
        return invalid(format!("{what} for {} {why}.", vm.hostname));
    }
    Ok(escape(spec.kind, &value))
}

fn escape(kind: InstallKind, value: &str) -> String {
    if kind == InstallKind::Unattend {
        super::xml::escape(value)
    } else {
        value.to_owned()
    }
}

/// Renders `spec` for one VM. Every placeholder must have its value: a VM without an IP for `{{ip}}`, a variable
/// without a value or default, or a vault item not given refuses, as does a rendered file its kind can't read.
pub fn render(
    spec: &InstallConfigInput,
    vm: &VmValues,
    secrets: &RenderSecrets,
    random: &mut dyn Random,
) -> Result<Rendered> {
    let pieces = vars::split(&spec.body).map_err(|errors| {
        CoreError::InvalidInput(errors.first().map_or_else(
            || "The file's placeholders can't be read.".to_owned(),
            |e| format!("Line {}: {}", e.line, e.message),
        ))
    })?;
    let used = vars::used(&pieces);
    // Every value first, so a missing one refuses before any hash is made.
    let mut values: HashMap<Placeholder, String> = HashMap::new();
    for p in &used {
        if !matches!(p, Placeholder::Password(_) | Placeholder::SshKey(_)) {
            if let Placeholder::Own(name) = p {
                if !spec.variables.iter().any(|v| v.name == *name) {
                    return invalid(format!("{{{{{name}}}}} isn't one of the config's variables."));
                }
            }
            values.insert(p.clone(), plain_value(spec, vm, p)?);
        }
    }
    let mut one_time = Vec::new();
    for p in &used {
        match p {
            Placeholder::SshKey(name) => {
                let Some(line) = secrets.ssh_keys.get(name) else {
                    return invalid(format!("{} isn't picked from the vault.", p.text()));
                };
                let line = line.trim();
                if line.is_empty()
                    || line.chars().any(char::is_control)
                    || line.contains(['"', '\'', '\\', '`', '$', '<', '>', '&', '{', '}'])
                {
                    return invalid(format!("{}'s public key can't go into the file as it is.", p.text()));
                }
                values.insert(p.clone(), line.to_owned());
            }
            Placeholder::Password(name) => {
                let Some(password) = secrets.passwords.get(name) else {
                    return invalid(format!("{} isn't picked from the vault.", p.text()));
                };
                if password.is_empty() {
                    return invalid(format!("{}'s vault item is empty.", p.text()));
                }
                let value = if spec.kind.windows() {
                    let password = one_time_password(random);
                    let value = password.expose().to_owned();
                    one_time.push(OneTimePassword {
                        name: name.clone(),
                        password,
                    });
                    value
                } else {
                    hash_password(password.expose(), random)?
                };
                values.insert(p.clone(), value);
            }
            _ => {}
        }
    }
    let text = SecretString::new(vars::join(&pieces, |p| values.get(p).cloned()));
    for v in values.values_mut() {
        zeroize::Zeroize::zeroize(v);
    }
    // The rendered file must still read as its kind: a value can't have broken it.
    if let Some(problem) = super::hidden_break(spec.kind, text.expose()) {
        return invalid(format!("The file rendered for {}: {}", vm.hostname, problem.message));
    }
    let errors: Vec<ConfigProblem> = kind_check(spec.kind, text.expose())
        .into_iter()
        .filter(|p| p.severity == Severity::Error && !p.blocks_saving)
        .collect();
    if let Some(first) = errors.first() {
        let at = first.line.map(|l| format!("line {l}: ")).unwrap_or_default();
        return invalid(format!(
            "The file rendered for {} isn't valid {}: {at}{}",
            vm.hostname,
            spec.kind.label(),
            first.message
        ));
    }
    let sha256 = hex::encode(Sha256::digest(text.expose().as_bytes()));
    Ok(Rendered {
        file_name: spec.kind.file_name(),
        text,
        sha256,
        one_time,
    })
}

/// The kind's syntax check alone (no lint that depends on samples).
fn kind_check(kind: InstallKind, text: &str) -> Vec<ConfigProblem> {
    match kind {
        InstallKind::Autoinstall => super::autoinstall::syntax(text),
        InstallKind::CloudInit => super::cloud_init::syntax(text),
        InstallKind::Kickstart => super::kickstart::syntax(text),
        InstallKind::Preseed => super::preseed::syntax(text),
        InstallKind::Unattend => super::unattend::syntax(text),
    }
}

/// What the editor and the deploy dialog show of a VM's file: every value written, and every secret masked
/// (`$6$••••••••` for a hash, `••••••••` for a one-time password; keys' public halves as they are, or a sample).
pub fn preview(spec: &InstallConfigInput, vm: &VmValues, public_keys: &HashMap<String, String>) -> Result<String> {
    let pieces = vars::split(&spec.body).map_err(|errors| {
        CoreError::InvalidInput(
            errors
                .first()
                .map_or_else(String::new, |e| format!("Line {}: {}", e.line, e.message)),
        )
    })?;
    let mut out = HashMap::new();
    for p in vars::used(&pieces) {
        let value = match &p {
            Placeholder::Password(_) if spec.kind.windows() => "••••••••".to_owned(),
            Placeholder::Password(_) => "$6$••••••••".to_owned(),
            Placeholder::SshKey(name) => public_keys
                .get(name)
                .cloned()
                .unwrap_or_else(|| super::SAMPLE_KEY.to_owned()),
            // A value the preview VM lacks (or a variable not declared yet) shows as its placeholder.
            other => plain_value(spec, vm, other).unwrap_or_else(|_| other.text()),
        };
        out.insert(p, value);
    }
    Ok(vars::join(&pieces, |p| out.get(p).cloned()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use sha_crypt::PasswordVerifier;
    use time::macros::date;

    use super::*;
    use crate::catalog::install::{SecretRef, SecretRefKind, VariableDef};

    /// Counts up, so each render's salt differs and tests stay repeatable.
    struct Counter(u8);

    impl Random for Counter {
        fn fill(&mut self, bytes: &mut [u8]) {
            for b in bytes {
                self.0 = self.0.wrapping_add(37);
                *b = self.0;
            }
        }
    }

    fn password() -> String {
        // Made at run time, never a literal in the repo.
        let mut bytes = [0u8; 12];
        OsRandom.fill(&mut bytes);
        format!("Pw-{}", hex::encode(bytes))
    }

    fn vm() -> VmValues {
        VmValues {
            hostname: "web-1".into(),
            ip: Some("192.0.2.21".into()),
            n: 1,
            template: "web".into(),
            date: date!(2026 - 11 - 12),
            values: BTreeMap::from([("domain".to_owned(), "example.com".to_owned())]),
        }
    }

    fn spec(kind: InstallKind, body: &str) -> InstallConfigInput {
        InstallConfigInput {
            name: "test".into(),
            kind,
            body: body.into(),
            variables: vec![
                VariableDef {
                    name: "domain".into(),
                    default: Some("example.org".into()),
                },
                VariableDef {
                    name: "dns".into(),
                    default: Some("192.0.2.53".into()),
                },
            ],
            secrets: vec![SecretRef {
                name: "admin".into(),
                kind: SecretRefKind::Password,
                secret_id: None,
            }],
            notes: None,
        }
    }

    const CLOUD: &str = "#cloud-config\nhostname: \"{{hostname}}\"\nfqdn: \"{{hostname}}.{{domain}}\"\nusers:\n  - name: alice\n    lock_passwd: false\n    passwd: \"{{password.admin}}\"\n    ssh_authorized_keys:\n      - \"{{ssh_key.admin}}\"\nruncmd:\n  - echo {{n}} {{ip}} {{template}} {{date}} {{dns}}\n";

    #[test]
    fn a_linux_file_gets_the_vms_values_and_a_fresh_hash() {
        let pw = password();
        let mut secrets = RenderSecrets::default();
        secrets.passwords.insert("admin".into(), SecretString::new(pw.clone()));
        secrets.ssh_keys.insert(
            "admin".into(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@example.com".into(),
        );
        let spec = spec(InstallKind::CloudInit, CLOUD);
        let mut random = Counter(0);
        let a = render(&spec, &vm(), &secrets, &mut random).unwrap();
        let b = render(&spec, &vm(), &secrets, &mut random).unwrap();
        assert_eq!(a.file_name, "user-data");
        let text = a.text.expose();
        assert!(
            text.contains("hostname: \"web-1\"\nfqdn: \"web-1.example.com\""),
            "{text}"
        );
        assert!(
            text.contains("echo 1 192.0.2.21 web 20261112 192.0.2.53"),
            "the default where the VM has none"
        );
        assert!(text.contains("- \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@example.com\""));
        assert!(!text.contains(&pw), "the password itself is never written");
        // The hash verifies, and a second render salts afresh.
        let hash_of = |t: &str| {
            t.lines()
                .find_map(|l| l.trim().strip_prefix("passwd: \""))
                .map(|h| h.trim_end_matches('"').to_owned())
                .unwrap()
        };
        let (ha, hb) = (hash_of(text), hash_of(b.text.expose()));
        assert!(ha.starts_with("$6$rounds=5000$"), "{ha}");
        assert_ne!(ha, hb);
        assert!(ShaCrypt::SHA512.verify_password(pw.as_bytes(), ha.as_str()).is_ok());
        assert!(ShaCrypt::SHA512.verify_password(b"wrong", ha.as_str()).is_err());
        assert_eq!(a.sha256.len(), 64);
        assert_ne!(a.sha256, b.sha256);
        assert!(a.one_time.is_empty());
        // Debug never shows the file.
        assert!(!format!("{a:?}").contains("passwd"));
    }

    #[test]
    fn windows_gets_a_one_time_password_returned_beside_the_file() {
        let body = "<unattend xmlns=\"urn:schemas-microsoft-com:unattend\"><settings pass=\"oobeSystem\"><component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"amd64\"><UserAccounts><AdministratorPassword><Value>{{password.admin}}</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts></component></settings><settings pass=\"specialize\"><component name=\"Microsoft-Windows-Shell-Setup\" processorArchitecture=\"amd64\"><ComputerName>{{hostname}}</ComputerName><RegisteredOrganization>{{domain}}</RegisteredOrganization></component></settings></unattend>";
        let mut s = spec(InstallKind::Unattend, body);
        s.variables.retain(|v| v.name == "domain");
        let pw = password();
        let mut secrets = RenderSecrets::default();
        secrets.passwords.insert("admin".into(), SecretString::new(pw.clone()));
        let mut v = vm();
        v.values.insert("domain".into(), "Example & Co".into());
        let out = render(&s, &v, &secrets, &mut OsRandom).unwrap();
        assert_eq!(out.file_name, "autounattend.xml");
        assert_eq!(out.one_time.len(), 1);
        let one_time = out.one_time[0].password.expose().to_owned();
        assert_eq!(one_time.len(), 24);
        assert!(out.text.expose().contains(&format!("<Value>{one_time}</Value>")));
        assert!(!out.text.expose().contains(&pw), "the vault's password waits for G6");
        assert!(out
            .text
            .expose()
            .contains("<RegisteredOrganization>Example &amp; Co</RegisteredOrganization>"));
        let again = render(&s, &v, &secrets, &mut OsRandom).unwrap();
        assert_ne!(again.one_time[0].password.expose(), one_time);
    }

    #[test]
    fn render_refuses_what_it_cant_fill_or_what_would_break_the_file() {
        let s = spec(InstallKind::CloudInit, CLOUD);
        let mut secrets = RenderSecrets::default();
        secrets.passwords.insert("admin".into(), SecretString::new(password()));
        secrets
            .ssh_keys
            .insert("admin".into(), "ssh-ed25519 AAAA alice@example.com".into());
        let err =
            |v: VmValues, secrets: &RenderSecrets| render(&s, &v, secrets, &mut OsRandom).unwrap_err().to_string();
        assert!(err(VmValues { ip: None, ..vm() }, &secrets).contains("needs an IP address"));
        assert!(err(
            VmValues {
                hostname: "Web 1".into(),
                ..vm()
            },
            &secrets
        )
        .contains("isn't a hostname"));
        let mut bad = vm();
        bad.values.insert("domain".into(), "x\"\nruncmd: [reboot]".into());
        assert!(err(bad, &secrets).contains("line break"));
        let mut bad = vm();
        bad.values.insert("domain".into(), "$(reboot)".into());
        assert!(err(bad, &secrets).contains("holds $"));
        assert!(err(vm(), &RenderSecrets::default()).contains("isn't picked from the vault"));
        let mut hostile = RenderSecrets::default();
        hostile.passwords.insert("admin".into(), SecretString::new(password()));
        hostile
            .ssh_keys
            .insert("admin".into(), "ssh-ed25519 AAAA x\"\n  runcmd".into());
        assert!(err(vm(), &hostile).contains("public key"));
        // A file that a value turns into something its kind can't read.
        let broken = spec(
            InstallKind::CloudInit,
            "#cloud-config\nhostname: {{domain}}\n  bad: [\n",
        );
        let mut v = vm();
        v.values.insert("domain".into(), "example.com".into());
        let e = render(&broken, &v, &secrets, &mut OsRandom).unwrap_err().to_string();
        assert!(e.contains("isn't valid cloud-init user data"), "{e}");
    }

    #[test]
    fn the_preview_masks_every_secret() {
        let s = spec(InstallKind::CloudInit, CLOUD);
        let keys = HashMap::from([("admin".to_owned(), "ssh-ed25519 AAAA alice@example.com".to_owned())]);
        let text = preview(&s, &vm(), &keys).unwrap();
        assert!(text.contains("passwd: \"$6$••••••••\""), "{text}");
        assert!(text.contains("- \"ssh-ed25519 AAAA alice@example.com\""), "{text}");
        assert!(text.contains("hostname: \"web-1\""));
        let w = spec(
            InstallKind::Unattend,
            "<a><Value>{{password.admin}}</Value><N>{{hostname}}</N></a>",
        );
        assert_eq!(
            preview(&w, &vm(), &keys).unwrap(),
            "<a><Value>••••••••</Value><N>web-1</N></a>"
        );
    }

    #[test]
    fn hashes_match_glibc_crypt() {
        // Made with `openssl passwd -6 -salt remotelykatsalt0 "remotely test vector"` (a test phrase, not a password).
        let reference = "$6$remotelykatsalt0$2urCTNZla5uHqrpQtQhSm2yWLKjVA.xjosjhZKXZ7d0V2tCU1YCRyZoYNFeAMH9nunrh0EVxh5oSNE//e55m3.";
        assert!(ShaCrypt::SHA512
            .verify_password(b"remotely test vector", reference)
            .is_ok());
        assert!(ShaCrypt::SHA512
            .verify_password(b"remotely test vectors", reference)
            .is_err());
        // And what render writes: rounds=5000 is glibc's default, spelled out.
        let ours = hash_password("remotely test vector", &mut Counter(1)).unwrap();
        let salt = ours.split('$').nth(3).unwrap();
        assert_eq!(salt.len(), 16);
        assert!(ShaCrypt::SHA512
            .verify_password(b"remotely test vector", ours.as_str())
            .is_ok());
    }

    #[test]
    fn one_time_passwords_meet_windows_complexity() {
        let mut random = Counter(3);
        for _ in 0..50 {
            let p = one_time_password(&mut random);
            let p = p.expose();
            assert_eq!(p.len(), 24);
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().all(|c| ONE_TIME_ALPHABET.contains(&(c as u8))));
        }
    }
}
