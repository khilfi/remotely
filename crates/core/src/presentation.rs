//! FD-03 presentation mode, for sharing the screen on a call. The UI masks host names, IP addresses, user names and the
//! Windows user name in paths on screen (the core keeps sending the real values: masking is the screen's business, and
//! copies, saves, logs and exports keep the real text). The optional read-only lock is the core's: while presenting
//! with it on, the command bus refuses every command and the services that edit the app's data refuse every edit
//! (the rule is [`crate::policy::read_only_refusal`]). Typing into one terminal stays possible: it is the user's own
//! shell, and nothing Remotely does on its own.
//!
//! Both settings are saved, so the app starts presenting if it was presenting when it closed. A saved value that can't
//! be read starts presenting with the lock on (fail closed). Each change is audited like any setting.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::domain::Context;
use crate::error::Result;
use crate::locks;
use crate::policy;
use crate::store::{NewAuditEntry, Store};

/// Settings key: `{ "enabled": bool, "readOnly": bool }`.
pub const PRESENTATION_KEY: &str = "presentation.mode";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Presentation {
    /// Presenting: the UI masks what it shows.
    pub enabled: bool,
    /// The read-only lock. It applies while presenting, and is kept for the next time when presenting stops.
    pub read_only: bool,
}

impl Presentation {
    /// What the app starts with when the saved setting can't be read.
    pub const FAIL_CLOSED: Presentation = Presentation {
        enabled: true,
        read_only: true,
    };

    /// Whether the read-only lock applies now.
    pub fn locked(self) -> bool {
        self.enabled && self.read_only
    }

    /// The audit log's action for each change from `self` to `new`, with its detail.
    fn changes(self, new: Presentation) -> Vec<(&'static str, String)> {
        let lock_note = |p: Presentation| {
            if p.read_only {
                "the read-only lock is on"
            } else {
                "the read-only lock is off"
            }
        };
        let mut out = Vec::new();
        if self.enabled != new.enabled {
            if new.enabled {
                out.push((
                    "Started presenting",
                    format!("presentation mode on; {}", lock_note(new)),
                ));
            } else {
                out.push(("Stopped presenting", "presentation mode off".to_owned()));
            }
        }
        if self.read_only != new.read_only {
            let applies = if new.enabled {
                "applies now"
            } else {
                "applies while presenting"
            };
            if new.read_only {
                out.push(("Turned the read-only lock on", format!("read-only lock on ({applies})")));
            } else {
                out.push(("Turned the read-only lock off", "read-only lock off".to_owned()));
            }
        }
        out
    }
}

/// Edits of the app's own data, which skip the command bus (each is audited where it happens). The read-only lock
/// refuses all of them; the label says which in the refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Change {
    /// SS-01, SS-06: sessions, folders and labels; also a quick connection saved as a session.
    Sessions,
    /// VM-02, AP-04 labels: environments, tags and saved filters.
    VmLabels,
    /// QL-01: linking a session to a VM by hand, or confirming a link.
    VmLinks,
    /// SS-02: importing sessions.
    Import,
    /// FD-07: importing from another laptop.
    Transfer,
    /// SS-04: setting up the vault, its password and Windows login, and its secrets.
    Vault,
    /// SS-09: generating SSH keys and attaching them to sessions.
    SshKeys,
    /// SS-05: replacing a changed host key, or removing a trusted one. (Trusting a new host's key on first use is
    /// part of connecting, which stays possible.)
    KnownHosts,
    /// SS-07: a session's saved port forwards.
    Forwards,
    /// BX-08: favourite commands.
    Favourites,
    /// Settings, including the terminal's and the GitHub update token.
    Settings,
    /// AP-01: the approval rules.
    ApprovalRules,
    /// SS-10: turning MultiExec on (each line would be refused anyway).
    MultiExec,
}

impl Change {
    /// Every kind of edit, for tests.
    pub const ALL: [Change; 13] = [
        Change::Sessions,
        Change::VmLabels,
        Change::VmLinks,
        Change::Import,
        Change::Transfer,
        Change::Vault,
        Change::SshKeys,
        Change::KnownHosts,
        Change::Forwards,
        Change::Favourites,
        Change::Settings,
        Change::ApprovalRules,
        Change::MultiExec,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Change::Sessions => "Edit sessions and folders",
            Change::VmLabels => "Change VM labels, tags and saved filters",
            Change::VmLinks => "Link sessions to VMs",
            Change::Import => "Import sessions",
            Change::Transfer => "Import from another laptop",
            Change::Vault => "Change the vault",
            Change::SshKeys => "Generate or attach SSH keys",
            Change::KnownHosts => "Replace or remove trusted host keys",
            Change::Forwards => "Edit port forwards",
            Change::Favourites => "Edit favourite commands",
            Change::Settings => "Change settings",
            Change::ApprovalRules => "Change the approval rules",
            Change::MultiExec => "Turn MultiExec on",
        }
    }
}

/// Whether the read-only lock applies now. One flag, shared by the store (so every service that edits the app's
/// data sees it) and so by the command bus.
#[derive(Debug, Clone, Default)]
pub struct ReadOnlyLock {
    locked: Arc<AtomicBool>,
}

impl ReadOnlyLock {
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    pub(crate) fn set(&self, locked: bool) {
        self.locked.store(locked, Ordering::SeqCst);
    }

    /// Refuses an edit of the app's data while the lock is on.
    pub fn check(&self, change: Change) -> Result<()> {
        policy::read_only_edit_refusal(self.is_locked(), change)
    }
}

/// The saved setting and the lock it sets (`Core.presentation`).
pub struct PresentationMode {
    store: Store,
    ctx: Context,
    current: Mutex<Presentation>,
}

impl PresentationMode {
    /// Reads the saved setting and applies its lock. A value that can't be read starts presenting, locked.
    pub async fn load(store: Store, ctx: Context) -> Self {
        let current = match store.get_setting::<Presentation>(&ctx, PRESENTATION_KEY).await {
            Ok(saved) => saved.unwrap_or_default(),
            Err(err) => {
                tracing::error!(error = %err, "the presentation mode setting can't be read; presenting, locked");
                Presentation::FAIL_CLOSED
            }
        };
        store.read_only().set(current.locked());
        Self {
            store,
            ctx,
            current: Mutex::new(current),
        }
    }

    pub fn get(&self) -> Presentation {
        *locks::lock(&self.current)
    }

    /// Saves the new setting, applies its lock and audits each change. A lock that comes on applies before anything is
    /// saved, and one that goes off only once the change is saved, so a failure leaves the app locked rather than open.
    /// The lock never refuses this (turning it off must stay possible); the UI asks for one confirm before turning
    /// presentation or the lock off.
    pub async fn set(&self, new: Presentation) -> Result<Presentation> {
        let old = self.get();
        let changes = old.changes(new);
        if changes.is_empty() {
            return Ok(old);
        }
        let lock = self.store.read_only();
        if new.locked() {
            lock.set(true);
        }
        self.store.put_setting(&self.ctx, PRESENTATION_KEY, &new).await?;
        lock.set(new.locked());
        *locks::lock(&self.current) = new;
        for (action, detail) in changes {
            self.store
                .append_audit(
                    &self.ctx,
                    NewAuditEntry {
                        event: "setting_changed",
                        action,
                        tier: None,
                        job_id: None,
                        targets: &[],
                        approval: None,
                        result: None,
                        detail: Some(&detail),
                    },
                )
                .await?;
        }
        Ok(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_applies_only_while_presenting() {
        let both = |enabled, read_only| Presentation { enabled, read_only };
        assert!(both(true, true).locked());
        assert!(!both(true, false).locked());
        assert!(!both(false, true).locked());
        assert!(Presentation::FAIL_CLOSED.locked());
        assert!(!Presentation::default().locked());
    }

    #[test]
    fn each_change_is_one_audit_entry() {
        let off = Presentation::default();
        let on = Presentation {
            enabled: true,
            read_only: false,
        };
        let locked = Presentation {
            enabled: true,
            read_only: true,
        };
        assert_eq!(
            off.changes(on),
            vec![(
                "Started presenting",
                "presentation mode on; the read-only lock is off".to_owned()
            )]
        );
        assert_eq!(
            on.changes(locked),
            vec![(
                "Turned the read-only lock on",
                "read-only lock on (applies now)".to_owned()
            )]
        );
        let actions: Vec<_> = locked.changes(off).into_iter().map(|(a, _)| a).collect();
        assert_eq!(actions, ["Stopped presenting", "Turned the read-only lock off"]);
        assert!(on.changes(on).is_empty());
    }

    #[test]
    fn the_setting_reads_and_writes_as_camel_case() {
        let json = serde_json::to_string(&Presentation::FAIL_CLOSED).unwrap();
        assert_eq!(json, r#"{"enabled":true,"readOnly":true}"#);
        let back: Presentation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Presentation::FAIL_CLOSED);
    }
}
