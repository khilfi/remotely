//! SS-07 saved port forwards: each session keeps a list of local, remote and SOCKS forwards that
//! start with its terminal ("starts with the terminal") or by hand.
//!
//! Editing the list changes the app's own data, so it skips the command bus like the session library
//! and is audited the same way, with what changed. Opening a forward is a command on the bus
//! ([`crate::command_bus::Command::OpenTunnel`]): the terminal's tunnels ([`crate::terminal::tunnels`])
//! rate, approve, open, show and close it.
//!
//! Listeners on this PC take `127.0.0.1` unless another address is typed; anything but loopback lets
//! other computers use the tunnel, which the policy engine rates higher (`TunnelShared`).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::adapters::network::ip_literal;
use crate::adapters::remote::forward::{ForwardKind, ForwardSpec};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::store::{NewAuditEntry, Store};

/// Forwards one session keeps.
pub const MAX_FORWARDS: usize = 20;
pub const MAX_LABEL: usize = 60;
/// What a listener on this PC binds to when no address is typed.
pub const DEFAULT_LOCAL_BIND: &str = "127.0.0.1";
/// What the host listens on for a remote forward when no address is typed, as OpenSSH sends it.
pub const DEFAULT_REMOTE_BIND: &str = "localhost";

/// A saved forward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortForward {
    pub id: Uuid,
    pub session_id: Uuid,
    /// What the user calls it, e.g. "Postgres".
    #[serde(default)]
    pub label: Option<String>,
    #[serde(flatten)]
    pub spec: ForwardSpec,
    /// Opens when the session's terminal connects (through the command bus, so it may ask first).
    pub auto_start: bool,
}

impl PortForward {
    /// `local 127.0.0.1:8080 -> db01.example.com:5432`, with the label when there is one.
    pub fn describe(&self) -> String {
        let what = self.spec.describe();
        match &self.label {
            Some(label) => format!("'{label}' ({what})"),
            None => what,
        }
    }
}

/// What the session editor sends for one forward.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardInput {
    /// The forward this edits; `None` for a new one.
    #[serde(default)]
    pub id: Option<Uuid>,
    #[serde(default)]
    pub label: Option<String>,
    pub kind: ForwardKind,
    /// Empty: `127.0.0.1` on this PC, `localhost` on the host.
    #[serde(default)]
    pub bind_address: String,
    #[serde(default)]
    pub bind_port: u16,
    #[serde(default)]
    pub dest_host: String,
    #[serde(default)]
    pub dest_port: u16,
    #[serde(default = "yes")]
    pub auto_start: bool,
}

fn yes() -> bool {
    true
}

impl From<&PortForward> for ForwardInput {
    fn from(f: &PortForward) -> Self {
        Self {
            id: Some(f.id),
            label: f.label.clone(),
            kind: f.spec.kind,
            bind_address: f.spec.bind_address.clone(),
            bind_port: f.spec.bind_port,
            dest_host: f.spec.dest_host.clone(),
            dest_port: f.spec.dest_port,
            auto_start: f.auto_start,
        }
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// An address to listen on: `localhost`, or an IP address (IPv6 with or without brackets). Names
/// are not taken: a listener needs to know which of this PC's addresses it gets.
fn clean_bind(address: &str, kind: ForwardKind) -> Result<String> {
    let address = address.trim();
    if address.is_empty() {
        return Ok(match kind {
            ForwardKind::Remote => DEFAULT_REMOTE_BIND,
            ForwardKind::Local | ForwardKind::Dynamic => DEFAULT_LOCAL_BIND,
        }
        .to_owned());
    }
    if address.eq_ignore_ascii_case("localhost") {
        return Ok("localhost".into());
    }
    let bare = address
        .strip_prefix('[')
        .and_then(|a| a.strip_suffix(']'))
        .unwrap_or(address);
    match bare.parse::<IpAddr>() {
        Ok(ip) => Ok(ip.to_string()),
        Err(_) => invalid(format!(
            "'{address}' is not an address to listen on. Use 127.0.0.1 (this computer only), localhost, or an IP address such as 0.0.0.0"
        )),
    }
}

/// A destination host, checked like a session's host.
fn clean_dest_host(host: &str) -> Result<String> {
    let host = host.trim();
    if host.is_empty() {
        return invalid("Enter where the forward leads: a host name or IP address.");
    }
    if host.chars().count() > crate::sessions::MAX_HOST_LEN {
        return invalid(format!(
            "A host name can be at most {} characters.",
            crate::sessions::MAX_HOST_LEN
        ));
    }
    let ok = host
        .chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '%' | '[' | ']'));
    if !ok {
        return invalid("A host can only hold letters, digits and . - _ : (for IPv6) [ ] %.");
    }
    Ok(match ip_literal(host) {
        Some(ip) => ip.to_string(),
        None => host.to_owned(),
    })
}

/// Checks and tidies one forward of `session_id`. `id`: the one it keeps.
fn check(session_id: Uuid, id: Uuid, input: &ForwardInput) -> Result<PortForward> {
    let label = input.label.as_deref().map(str::trim).filter(|l| !l.is_empty());
    if let Some(label) = label {
        if label.chars().count() > MAX_LABEL {
            return invalid(format!("A forward's name can be at most {MAX_LABEL} characters."));
        }
        if label.chars().any(char::is_control) {
            return invalid("A forward's name can't hold line breaks or tabs.");
        }
    }
    let kind = input.kind;
    let bind_address = clean_bind(&input.bind_address, kind)?;
    let (dest_host, dest_port) = match kind {
        ForwardKind::Dynamic => (String::new(), 0),
        ForwardKind::Local | ForwardKind::Remote => {
            if input.dest_port == 0 {
                return invalid("Enter the port the forward leads to (1 to 65535).");
            }
            (clean_dest_host(&input.dest_host)?, input.dest_port)
        }
    };
    Ok(PortForward {
        id,
        session_id,
        label: label.map(str::to_owned),
        spec: ForwardSpec {
            kind,
            bind_address,
            bind_port: input.bind_port,
            dest_host,
            dest_port,
        },
        auto_start: input.auto_start,
    })
}

/// Which side a forward listens on, for "two forwards listen on one port".
fn listens_here(kind: ForwardKind) -> bool {
    kind != ForwardKind::Remote
}

/// Checks a session's whole list: each forward, how many, and no two listening on one port on one
/// side. Ids of forwards the session does not have are replaced with new ones.
pub(crate) fn check_all(
    session_id: Uuid,
    existing: &[PortForward],
    inputs: &[ForwardInput],
) -> Result<Vec<PortForward>> {
    if inputs.len() > MAX_FORWARDS {
        return invalid(format!("A session can keep at most {MAX_FORWARDS} port forwards."));
    }
    let mine: HashSet<Uuid> = existing.iter().map(|f| f.id).collect();
    let mut seen_ids = HashSet::new();
    let mut listeners: HashMap<(bool, String, u16), String> = HashMap::new();
    let mut out = Vec::with_capacity(inputs.len());
    for input in inputs {
        let id = match input.id {
            Some(id) if mine.contains(&id) && seen_ids.insert(id) => id,
            _ => Uuid::new_v4(),
        };
        let forward = check(session_id, id, input)?;
        if forward.spec.bind_port != 0 {
            let key = (
                listens_here(forward.spec.kind),
                forward.spec.bind_address.to_lowercase(),
                forward.spec.bind_port,
            );
            let place = forward.spec.listen_address();
            if let Some(other) = listeners.insert(key, forward.describe()) {
                return invalid(format!(
                    "Two forwards listen on {place}: {other} and {}. Give one of them another port.",
                    forward.describe()
                ));
            }
        }
        out.push(forward);
    }
    Ok(out)
}

/// What changed between two lists of a session's forwards, for the audit log.
fn changes(before: &[PortForward], after: &[PortForward]) -> Vec<String> {
    let starts = |f: &PortForward| {
        if f.auto_start {
            " (starts with the terminal)"
        } else {
            " (started by hand)"
        }
    };
    let mut out = Vec::new();
    for f in after {
        match before.iter().find(|b| b.id == f.id) {
            None => out.push(format!("added {}{}", f.describe(), starts(f))),
            Some(b) if b.spec != f.spec || b.label != f.label => {
                out.push(format!("changed {} to {}{}", b.describe(), f.describe(), starts(f)));
            }
            Some(b) if b.auto_start != f.auto_start => out.push(format!(
                "{} now {}",
                f.describe(),
                if f.auto_start {
                    "starts with the terminal"
                } else {
                    "starts by hand"
                }
            )),
            Some(_) => {}
        }
    }
    for b in before {
        if !after.iter().any(|f| f.id == b.id) {
            out.push(format!("removed {}", b.describe()));
        }
    }
    let order = |list: &[PortForward]| list.iter().map(|f| f.id).collect::<Vec<_>>();
    let kept_before: Vec<Uuid> = order(before)
        .into_iter()
        .filter(|id| after.iter().any(|f| f.id == *id))
        .collect();
    let kept_after: Vec<Uuid> = order(after)
        .into_iter()
        .filter(|id| before.iter().any(|b| b.id == *id))
        .collect();
    if out.is_empty() && kept_before != kept_after {
        out.push("reordered".into());
    }
    out
}

/// The sessions' saved forwards (`Core.forwards`).
pub struct Forwards {
    store: Store,
}

impl Forwards {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// A session's forwards, in its order.
    pub async fn list(&self, ctx: &Context, session_id: Uuid) -> Result<Vec<PortForward>> {
        self.store.list_forwards(ctx, session_id).await
    }

    /// Every session's forwards, by session.
    pub async fn all(&self, ctx: &Context) -> Result<HashMap<Uuid, Vec<PortForward>>> {
        self.store.all_forwards(ctx).await
    }

    pub async fn get(&self, ctx: &Context, id: Uuid) -> Result<PortForward> {
        self.store
            .forward(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("port forward {id}")))
    }

    /// Replaces a session's forwards with `inputs` (the session editor's whole list). Audited with
    /// what changed; a save that changes nothing writes nothing. Tunnels open in a terminal keep
    /// running as they were opened until they are stopped.
    pub async fn save(&self, ctx: &Context, session_id: Uuid, inputs: &[ForwardInput]) -> Result<Vec<PortForward>> {
        self.save_as(ctx, session_id, inputs, "Changed").await
    }

    /// FD-07: a session's forwards from an export, audited as imported.
    pub(crate) async fn restore(
        &self,
        ctx: &Context,
        session_id: Uuid,
        inputs: &[ForwardInput],
    ) -> Result<Vec<PortForward>> {
        self.save_as(ctx, session_id, inputs, "Imported").await
    }

    async fn save_as(
        &self,
        ctx: &Context,
        session_id: Uuid,
        inputs: &[ForwardInput],
        verb: &str,
    ) -> Result<Vec<PortForward>> {
        let session = self
            .store
            .get_session(ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("session {session_id}")))?;
        let before = self.store.list_forwards(ctx, session_id).await?;
        let after = check_all(session_id, &before, inputs)?;
        let changed = changes(&before, &after);
        if changed.is_empty() {
            return Ok(before);
        }
        self.store.replace_forwards(ctx, session_id, &after).await?;
        let detail = changed.join("; ");
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "session_changed",
                    action: &format!("{verb} the port forwards of '{}'", session.name),
                    tier: None,
                    job_id: None,
                    targets: &[session.target()],
                    approval: None,
                    result: None,
                    detail: Some(&detail),
                },
            )
            .await?;
        self.store.list_forwards(ctx, session_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(kind: ForwardKind, bind: &str, port: u16) -> ForwardInput {
        ForwardInput {
            id: None,
            label: None,
            kind,
            bind_address: bind.into(),
            bind_port: port,
            dest_host: "db01.example.com".into(),
            dest_port: 5432,
            auto_start: true,
        }
    }

    #[test]
    fn empty_bind_addresses_take_loopback() {
        let session = Uuid::new_v4();
        let local = check(session, Uuid::new_v4(), &input(ForwardKind::Local, "", 8080)).unwrap();
        assert_eq!(local.spec.bind_address, "127.0.0.1");
        assert!(local.spec.loopback_only());
        let remote = check(session, Uuid::new_v4(), &input(ForwardKind::Remote, " ", 9000)).unwrap();
        assert_eq!(remote.spec.bind_address, "localhost");
        let socks = check(session, Uuid::new_v4(), &input(ForwardKind::Dynamic, "[::1]", 1080)).unwrap();
        assert_eq!(
            (socks.spec.bind_address.as_str(), socks.spec.dest_host.as_str()),
            ("::1", "")
        );
        assert_eq!(socks.spec.dest_port, 0, "SOCKS clients name their destination");
    }

    #[test]
    fn bad_forwards_are_refused_with_a_reason() {
        let session = Uuid::new_v4();
        let bad = [
            (
                input(ForwardKind::Local, "web01.example.com", 8080),
                "not an address to listen on",
            ),
            (
                ForwardInput {
                    dest_host: " ".into(),
                    ..input(ForwardKind::Local, "", 8080)
                },
                "where the forward leads",
            ),
            (
                ForwardInput {
                    dest_port: 0,
                    ..input(ForwardKind::Remote, "", 9000)
                },
                "port the forward leads to",
            ),
            (
                ForwardInput {
                    dest_host: "db01;rm".into(),
                    ..input(ForwardKind::Local, "", 8080)
                },
                "can only hold",
            ),
            (
                ForwardInput {
                    label: Some("two\nlines".into()),
                    ..input(ForwardKind::Local, "", 8080)
                },
                "line breaks",
            ),
        ];
        for (forward, why) in bad {
            let err = check(session, Uuid::new_v4(), &forward).unwrap_err().to_string();
            assert!(err.contains(why), "{err}");
        }
    }

    #[test]
    fn two_listeners_on_one_port_and_side_are_refused() {
        let session = Uuid::new_v4();
        let clash = [
            input(ForwardKind::Local, "", 8080),
            input(ForwardKind::Dynamic, "127.0.0.1", 8080),
        ];
        assert!(check_all(session, &[], &clash)
            .unwrap_err()
            .to_string()
            .contains("Two forwards listen on 127.0.0.1:8080"));
        // A remote forward listens on the host, not here; port 0 never clashes.
        let fine = [
            input(ForwardKind::Local, "", 8080),
            input(ForwardKind::Remote, "127.0.0.1", 8080),
            input(ForwardKind::Local, "", 0),
            input(ForwardKind::Local, "", 0),
        ];
        assert_eq!(check_all(session, &[], &fine).unwrap().len(), 4);
        let many: Vec<ForwardInput> = (0..=MAX_FORWARDS as u16)
            .map(|p| input(ForwardKind::Local, "", 9000 + p))
            .collect();
        assert!(check_all(session, &[], &many).is_err());
    }

    #[test]
    fn ids_are_kept_for_the_sessions_own_forwards_only() {
        let session = Uuid::new_v4();
        let saved = check_all(session, &[], &[input(ForwardKind::Local, "", 8080)]).unwrap();
        let mut edit = ForwardInput::from(&saved[0]);
        edit.dest_port = 6543;
        let foreign = ForwardInput {
            id: Some(Uuid::new_v4()),
            ..input(ForwardKind::Dynamic, "", 1080)
        };
        let after = check_all(session, &saved, &[edit, foreign.clone()]).unwrap();
        assert_eq!(after[0].id, saved[0].id);
        assert_ne!(Some(after[1].id), foreign.id);
        let what = changes(&saved, &after);
        assert_eq!(what.len(), 2, "{what:?}");
        assert!(what[0].starts_with("changed local 127.0.0.1:8080 -> db01.example.com:5432 to local"));
        assert!(what[1].starts_with("added SOCKS on 127.0.0.1:1080"));
        assert!(changes(&after, &after).is_empty());
        let removed = changes(&after, &after[..1]);
        assert_eq!(removed, ["removed SOCKS on 127.0.0.1:1080"]);
    }
}
