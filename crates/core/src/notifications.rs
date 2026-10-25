//! QL-25 notification centre: the history of what notified, kept in memory while the app runs.
//!
//! The UI adds an entry for each notification it shows or wants kept: MO-07 metric alerts, QL-17 terminal alert
//! rules, QL-07 long commands that finished, jobs that finished or failed, an update that is available, and the
//! toasts worth keeping (protected targets skipped, a VM still running after its shutdown, a canary waiting). The
//! centre lists them newest first, with read and unread state, a link to what each is about (the UI's own
//! `AppLink`, kept as given and never shown) and a clear.
//!
//! Why memory and not the database:
//! - What an entry is about is already kept where it belongs, each with its own retention: jobs in the journal
//!   (BX-02, with Purge now), MO-07 alerts in their table (pruned with the history), every change in the audit log.
//!   A copy on disk would outlive those settings unless it followed them all.
//! - A terminal alert's sample and a long command's line are terminal output and typed text. Remotely writes
//!   terminal output to disk only when the owner turns a session log on (SS-11); a notification history on disk
//!   would write it without asking.
//! - Customer workspaces (R11) need no migration: each entry carries its [`Context`], and a list shows only the
//!   asking workspace's entries.
//!
//! So the history starts empty at each start; it survives a reload of the window (QL-15), since it lives here and
//! not in the page. Every title and body goes through [`export::redact_secrets`] and loses control and Unicode
//! format characters (A8) before it is kept, so no entry ever holds a secret that looked like one. Reading and
//! clearing are not audited: they change nothing outside this list, and the FD-03 read-only lock leaves them alone.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::{now_rfc3339, Context};
use crate::error::{CoreError, Result};
use crate::export;
use crate::locks;
use crate::untrusted;

/// Entries kept; the oldest go first.
pub const MAX_NOTIFICATIONS: usize = 500;
/// Characters of a title and of a body kept (longer ones end in "…").
pub const MAX_TITLE: usize = 200;
pub const MAX_BODY: usize = 2000;
/// A link's size as JSON, and its `kind`'s length.
pub const MAX_LINK_BYTES: usize = 4096;
const MAX_LINK_KIND: usize = 40;
/// A group or once key's length.
pub const MAX_KEY: usize = 200;

/// What notified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NotificationSource {
    /// MO-07: a metric alert fired or resolved.
    Alert,
    /// QL-17: a terminal's alert rule matched.
    TerminalAlert,
    /// QL-07: a long command (or a MultiExec line) finished.
    Command,
    /// A job finished, failed or waits for something.
    Job,
    /// FD-14: an update is available.
    Update,
    /// VM-14, VM-27: a schedule's run missed or skipped, or a schedule waiting for approval again.
    Schedule,
    /// Anything else worth keeping from a toast.
    App,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NotificationLevel {
    Info,
    Success,
    Warning,
    Error,
}

/// What the UI adds.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotificationInput {
    pub source: NotificationSource,
    pub level: NotificationLevel,
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    /// Where the entry leads: the UI's link, an object with a string `kind`. Kept as given and never shown.
    #[serde(default)]
    pub link: Option<Value>,
    /// Entries with the same group key show together in the list (one rule's alerts, one job's events).
    #[serde(default)]
    pub group: Option<String>,
    /// At most one entry with this key is kept: adding another returns the first unchanged (an update's
    /// version, say, which every check finds again).
    #[serde(default)]
    pub once: Option<String>,
}

/// One entry of the history.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    /// Counts up from 1 while the app runs.
    pub id: u64,
    pub source: NotificationSource,
    pub level: NotificationLevel,
    pub title: String,
    pub body: Option<String>,
    pub link: Option<Value>,
    pub group: Option<String>,
    /// When it was added (RFC 3339, UTC).
    pub at: String,
    pub read: bool,
    #[serde(skip)]
    ctx: Context,
    #[serde(skip)]
    once: Option<String>,
}

/// The history as the UI shows it: newest first.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationList {
    pub entries: Vec<Notification>,
    pub unread: usize,
}

#[derive(Default)]
struct State {
    next_id: u64,
    /// Oldest first.
    entries: VecDeque<Notification>,
}

/// The notification centre's history (see the module docs). Cheap to clone; clones share it.
#[derive(Clone, Default)]
pub struct Notifications {
    state: Arc<Mutex<State>>,
}

impl Notifications {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry (redacted and cleaned) and returns it, or the entry kept earlier under the same `once` key.
    pub fn add(&self, ctx: &Context, input: NotificationInput) -> Result<Notification> {
        let title = clean(&input.title, MAX_TITLE);
        if title.is_empty() {
            return Err(CoreError::InvalidInput("A notification needs a title.".into()));
        }
        let body = input
            .body
            .as_deref()
            .map(|b| clean(b, MAX_BODY))
            .filter(|b| !b.is_empty());
        let link = input.link.map(checked_link).transpose()?;
        let group = checked_key(input.group, "group")?;
        let once = checked_key(input.once, "once")?;
        let mut state = locks::lock(&self.state);
        if let Some(key) = &once {
            if let Some(kept) = state
                .entries
                .iter()
                .find(|e| e.ctx == *ctx && e.once.as_ref() == Some(key))
            {
                return Ok(kept.clone());
            }
        }
        state.next_id += 1;
        let entry = Notification {
            id: state.next_id,
            source: input.source,
            level: input.level,
            title,
            body,
            link,
            group,
            at: now_rfc3339(),
            read: false,
            ctx: *ctx,
            once,
        };
        state.entries.push_back(entry.clone());
        while state.entries.len() > MAX_NOTIFICATIONS {
            state.entries.pop_front();
        }
        Ok(entry)
    }

    /// This workspace's entries, newest first, and how many are unread.
    pub fn list(&self, ctx: &Context) -> NotificationList {
        let state = locks::lock(&self.state);
        let entries: Vec<Notification> = state.entries.iter().rev().filter(|e| e.ctx == *ctx).cloned().collect();
        let unread = entries.iter().filter(|e| !e.read).count();
        NotificationList { entries, unread }
    }

    /// Marks these entries read (all of this workspace's when `ids` is None) and returns the list.
    pub fn mark_read(&self, ctx: &Context, ids: Option<&[u64]>) -> NotificationList {
        {
            let mut state = locks::lock(&self.state);
            for entry in state.entries.iter_mut().filter(|e| e.ctx == *ctx) {
                if ids.is_none_or(|ids| ids.contains(&entry.id)) {
                    entry.read = true;
                }
            }
        }
        self.list(ctx)
    }

    /// Removes these entries (all of this workspace's when `ids` is None) and returns the list. A `once` key goes
    /// with its entry, so the same update can be noted again after a clear.
    pub fn clear(&self, ctx: &Context, ids: Option<&[u64]>) -> NotificationList {
        {
            let mut state = locks::lock(&self.state);
            state
                .entries
                .retain(|e| e.ctx != *ctx || ids.is_some_and(|ids| !ids.contains(&e.id)));
        }
        self.list(ctx)
    }
}

/// Redacted, on one line (a body keeps its line breaks), without control or format characters, at most `max`
/// characters.
fn clean(text: &str, max: usize) -> String {
    let (redacted, _) = export::redact_secrets(text);
    let mut out = String::with_capacity(redacted.len().min(max * 4));
    let mut count = 0;
    let multiline = max > MAX_TITLE;
    for c in redacted.trim().chars() {
        let c = match c {
            '\n' if multiline => '\n',
            '\r' | '\n' | '\t' => ' ',
            c if c.is_control() || untrusted::is_format_char(c) => continue,
            c => c,
        };
        if count == max {
            out.pop();
            out.push('…');
            break;
        }
        out.push(c);
        count += 1;
    }
    out.trim_end().to_owned()
}

fn checked_link(link: Value) -> Result<Value> {
    let kind_ok = link
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|k| !k.is_empty() && k.len() <= MAX_LINK_KIND);
    if !link.is_object() || !kind_ok {
        return Err(CoreError::InvalidInput(
            "A notification's link is an object with a kind.".into(),
        ));
    }
    if serde_json::to_string(&link).map_or(true, |json| json.len() > MAX_LINK_BYTES) {
        return Err(CoreError::InvalidInput("A notification's link is too long.".into()));
    }
    Ok(link)
}

fn checked_key(key: Option<String>, what: &str) -> Result<Option<String>> {
    match key.map(|k| k.trim().to_owned()).filter(|k| !k.is_empty()) {
        Some(k) if k.chars().count() > MAX_KEY => Err(CoreError::InvalidInput(format!(
            "A notification's {what} key is too long."
        ))),
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{UserId, WorkspaceId};
    use serde_json::json;
    use uuid::Uuid;

    fn ctx() -> Context {
        Context {
            workspace_id: WorkspaceId(Uuid::from_u128(1)),
            user_id: UserId(Uuid::from_u128(2)),
        }
    }

    fn input(title: &str) -> NotificationInput {
        NotificationInput {
            source: NotificationSource::Job,
            level: NotificationLevel::Success,
            title: title.into(),
            body: None,
            link: None,
            group: None,
            once: None,
        }
    }

    #[test]
    fn lists_newest_first_with_unread_counts() {
        let centre = Notifications::new();
        let first = centre.add(&ctx(), input("Job succeeded")).unwrap();
        let second = centre.add(&ctx(), input("Job failed")).unwrap();
        assert!(second.id > first.id);
        let list = centre.list(&ctx());
        assert_eq!(
            list.entries.iter().map(|e| e.id).collect::<Vec<_>>(),
            [second.id, first.id]
        );
        assert_eq!(list.unread, 2);

        let list = centre.mark_read(&ctx(), Some(&[first.id]));
        assert_eq!(list.unread, 1);
        assert!(list.entries.iter().find(|e| e.id == first.id).unwrap().read);
        assert_eq!(centre.mark_read(&ctx(), None).unread, 0);
    }

    #[test]
    fn redacts_secrets_and_strips_control_and_format_characters() {
        let centre = Notifications::new();
        let mut entry = input("Command finished in web01\u{202e}txt.exe");
        entry.body = Some("mysql --password=hunter22 -h db01.example.com\u{1b}[31m done\r\nnext line".into());
        let kept = centre.add(&ctx(), entry).unwrap();
        assert_eq!(kept.title, "Command finished in web01txt.exe");
        let body = kept.body.unwrap();
        assert!(!body.contains("hunter22"), "{body}");
        assert!(body.contains("[redacted]"), "{body}");
        assert!(!body.contains('\u{1b}'), "{body}");
        assert!(body.contains("done"), "{body}");
    }

    #[test]
    fn long_text_is_cut_with_an_ellipsis() {
        let centre = Notifications::new();
        let mut entry = input(&"a".repeat(MAX_TITLE + 50));
        entry.body = Some("b".repeat(MAX_BODY + 1));
        let kept = centre.add(&ctx(), entry).unwrap();
        assert_eq!(kept.title.chars().count(), MAX_TITLE);
        assert!(kept.title.ends_with('…'));
        assert_eq!(kept.body.unwrap().chars().count(), MAX_BODY);
    }

    #[test]
    fn titles_are_one_line_and_bodies_keep_their_lines() {
        let centre = Notifications::new();
        let mut entry = input("two\nlines");
        entry.body = Some("one\ntwo".into());
        let kept = centre.add(&ctx(), entry).unwrap();
        assert_eq!(kept.title, "two lines");
        assert_eq!(kept.body.as_deref(), Some("one\ntwo"));
    }

    #[test]
    fn an_empty_title_or_a_bad_link_is_refused() {
        let centre = Notifications::new();
        assert!(centre.add(&ctx(), input("  \u{202e} ")).is_err());
        for link in [
            json!("job"),
            json!({ "id": 1 }),
            json!({ "kind": "" }),
            json!({ "kind": "x".repeat(41) }),
        ] {
            let mut entry = input("Job");
            entry.link = Some(link);
            assert!(centre.add(&ctx(), entry).is_err());
        }
        let mut entry = input("Job");
        entry.link = Some(json!({ "kind": "job", "jobId": "x".repeat(MAX_LINK_BYTES) }));
        assert!(centre.add(&ctx(), entry).is_err());
        let mut entry = input("Job");
        entry.link = Some(json!({ "kind": "job", "jobId": "3f1c" }));
        let kept = centre.add(&ctx(), entry).unwrap();
        assert_eq!(kept.link, Some(json!({ "kind": "job", "jobId": "3f1c" })));
    }

    #[test]
    fn a_once_key_keeps_one_entry_until_it_is_cleared() {
        let centre = Notifications::new();
        let mut entry = input("Remotely 0.5.1 is available");
        entry.once = Some("update:0.5.1".into());
        let first = centre.add(&ctx(), entry.clone()).unwrap();
        let again = centre.add(&ctx(), entry.clone()).unwrap();
        assert_eq!(first.id, again.id);
        assert_eq!(centre.list(&ctx()).entries.len(), 1);
        centre.clear(&ctx(), None);
        let after = centre.add(&ctx(), entry).unwrap();
        assert_ne!(after.id, first.id);
    }

    #[test]
    fn keeps_at_most_the_newest_entries() {
        let centre = Notifications::new();
        for n in 0..MAX_NOTIFICATIONS + 5 {
            centre.add(&ctx(), input(&format!("Job {n}"))).unwrap();
        }
        let list = centre.list(&ctx());
        assert_eq!(list.entries.len(), MAX_NOTIFICATIONS);
        assert_eq!(list.entries[0].title, format!("Job {}", MAX_NOTIFICATIONS + 4));
        assert_eq!(list.entries.last().unwrap().title, "Job 5");
    }

    #[test]
    fn clear_removes_the_chosen_entries_or_all() {
        let centre = Notifications::new();
        let a = centre.add(&ctx(), input("A")).unwrap();
        let b = centre.add(&ctx(), input("B")).unwrap();
        let list = centre.clear(&ctx(), Some(&[a.id]));
        assert_eq!(list.entries.iter().map(|e| e.id).collect::<Vec<_>>(), [b.id]);
        assert!(centre.clear(&ctx(), None).entries.is_empty());
    }

    #[test]
    fn each_workspace_sees_only_its_own_entries() {
        let centre = Notifications::new();
        let other = Context {
            workspace_id: WorkspaceId(Uuid::from_u128(9)),
            ..ctx()
        };
        centre.add(&ctx(), input("Ours")).unwrap();
        centre.add(&other, input("Theirs")).unwrap();
        let ours = centre.list(&ctx());
        assert_eq!(ours.entries.len(), 1);
        assert_eq!(ours.entries[0].title, "Ours");
        centre.mark_read(&other, None);
        assert_eq!(centre.list(&ctx()).unread, 1);
        centre.clear(&other, None);
        assert_eq!(centre.list(&ctx()).entries.len(), 1);
    }

    #[test]
    fn serialises_for_the_ui_without_the_workspace() {
        let centre = Notifications::new();
        let mut entry = input("Job succeeded");
        entry.group = Some("job:1".into());
        centre.add(&ctx(), entry).unwrap();
        let json = serde_json::to_value(centre.list(&ctx())).unwrap();
        let first = &json["entries"][0];
        assert_eq!(first["source"], "job");
        assert_eq!(first["level"], "success");
        assert_eq!(first["group"], "job:1");
        assert_eq!(first["read"], false);
        assert!(first.get("ctx").is_none() && first.get("once").is_none());
        assert_eq!(json["unread"], 1);
    }

    #[test]
    fn the_input_refuses_unknown_fields() {
        let parsed: std::result::Result<NotificationInput, _> =
            serde_json::from_value(json!({ "source": "job", "level": "info", "title": "x", "html": "<b>" }));
        assert!(parsed.is_err());
        let parsed: NotificationInput =
            serde_json::from_value(json!({ "source": "terminalAlert", "level": "warning", "title": "Error in web01" }))
                .unwrap();
        assert_eq!(parsed.source, NotificationSource::TerminalAlert);
    }
}
