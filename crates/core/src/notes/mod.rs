//! FD-06 notes: one markdown note per session, VM and session folder, in this workspace.
//!
//! * A note is the user's own text: writing, changing, marking and deleting one is audited (`note_changed`) by what it
//!   is about and its length, never its text, and refused by the read-only lock (FD-03). Nothing here touches a host,
//!   so it skips the command bus, like the session library.
//! * [`render`] turns the markdown into HTML the window can show without anything in it running or reaching out; app
//!   links (sessions, VMs, vault items by name, commands, runbooks) are found by name in this workspace
//!   ([`Notes::link_names`]). F6's handover pack renders the notes marked for it ([`Notes::for_handover`]) the same
//!   way, with [`LinkMode::Static`].
//! * A note whose text looks like a secret (`export::redact_secrets` would change it) says so, and the window suggests
//!   the vault. The note is kept as written: it is the user's text, and only they can move the secret.
//! * A session's note goes to the trash with it (QL-27) and comes back with it; a folder's is deleted with the
//!   folder. A VM's note is kept by the VM's key, so it stays while the VM comes and goes from the list.
//! * Notes show in QL-20 search ([`Notes::list`]) and travel in FD-07 exports with their session, folder or VM.

pub mod render;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::snippets::library::{LibrarySection, LIBRARY, TROUBLESHOOT};
use crate::store::{NewAuditEntry, Store};
pub use render::{render, LinkMode, LinkNames, NoteLink, RenderedNote};

/// The longest note, in characters.
pub const MAX_NOTE_CHARS: usize = 50_000;

/// What a note is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NoteKind {
    Session,
    Vm,
    Folder,
}

impl NoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NoteKind::Session => "session",
            NoteKind::Vm => "vm",
            NoteKind::Folder => "folder",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "session" => Some(NoteKind::Session),
            "vm" => Some(NoteKind::Vm),
            "folder" => Some(NoteKind::Folder),
            _ => None,
        }
    }

    fn noun(self) -> &'static str {
        match self {
            NoteKind::Session => "session",
            NoteKind::Vm => "VM",
            NoteKind::Folder => "folder",
        }
    }
}

/// A session or folder by its id, a VM by its key (.vmx path or VirtualBox UUID).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteTarget {
    pub kind: NoteKind,
    pub key: String,
}

impl NoteTarget {
    pub fn session(id: Uuid) -> Self {
        Self {
            kind: NoteKind::Session,
            key: id.to_string(),
        }
    }

    pub fn folder(id: Uuid) -> Self {
        Self {
            kind: NoteKind::Folder,
            key: id.to_string(),
        }
    }

    pub fn vm(key: &str) -> Self {
        Self {
            kind: NoteKind::Vm,
            key: key.to_owned(),
        }
    }

    /// A session's and a folder's key is a UUID, kept in its usual form.
    fn checked(&self) -> Result<Self> {
        let key = self.key.trim();
        let key = match self.kind {
            NoteKind::Session | NoteKind::Folder => Uuid::parse_str(key)
                .map_err(|_| CoreError::InvalidInput(format!("'{key}' is not a {} id", self.kind.noun())))?
                .to_string(),
            NoteKind::Vm => {
                if key.is_empty() || key.chars().count() > 1024 || key.chars().any(char::is_control) {
                    return Err(CoreError::InvalidInput("That is not a VM.".into()));
                }
                key.to_owned()
            }
        };
        Ok(Self { kind: self.kind, key })
    }
}

/// A note row as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NoteRow {
    pub kind: NoteKind,
    pub key: String,
    pub body: String,
    pub handover: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// A note, as the window shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub kind: NoteKind,
    pub key: String,
    /// The name of what it is about ("web01", a VM's name, a folder's name).
    pub title: String,
    pub body: String,
    /// F6: the handover pack includes it.
    pub handover: bool,
    pub created_at: String,
    pub updated_at: String,
    /// The text has something that looks like a secret.
    pub looks_secret: bool,
}

/// What the note editor saves.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteInput {
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub handover: bool,
}

/// The text as kept: `\r\n` and `\r` as `\n`, trailing white space trimmed, checked.
pub fn clean_body(body: &str) -> Result<String> {
    let body = body.replace("\r\n", "\n").replace('\r', "\n");
    let body = body.trim_end();
    let body = body.trim_start_matches('\n');
    if body.chars().count() > MAX_NOTE_CHARS {
        return Err(CoreError::InvalidInput(format!(
            "A note can be at most {MAX_NOTE_CHARS} characters."
        )));
    }
    if body.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(CoreError::InvalidInput(
            "A note can't hold control characters, only text, tabs and line breaks.".into(),
        ));
    }
    Ok(body.to_owned())
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// What a note is about, found in the workspace: its name and, for the audit log, its target.
struct About {
    title: String,
    target: Option<Target>,
}

#[derive(Clone)]
pub struct Notes {
    store: Store,
}

impl Notes {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// What `target` names, or why there is none here. `write`: a VM must be this workspace's (FD-02).
    async fn about(&self, ctx: &Context, target: &NoteTarget, write: bool) -> Result<About> {
        match target.kind {
            NoteKind::Session => {
                let id = Uuid::parse_str(&target.key).map_err(|_| CoreError::UnknownTarget("session".into()))?;
                let session = self
                    .store
                    .get_session(ctx, id)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(format!("session {id}")))?;
                Ok(About {
                    title: session.name.clone(),
                    target: Some(session.target()),
                })
            }
            NoteKind::Folder => {
                let id = Uuid::parse_str(&target.key).map_err(|_| CoreError::UnknownTarget("folder".into()))?;
                let folder = self
                    .store
                    .list_session_folders(ctx)
                    .await?
                    .into_iter()
                    .find(|f| f.id == id)
                    .ok_or_else(|| CoreError::UnknownTarget(format!("folder {id}")))?;
                Ok(About {
                    title: folder.name,
                    target: None,
                })
            }
            NoteKind::Vm => {
                if write {
                    self.store.require_vm_here(ctx, &target.key).await?;
                }
                let vm = self
                    .store
                    .find_vm(ctx, &target.key)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget(crate::inventory::vm_named(&target.key)))?;
                Ok(About {
                    title: vm.display_name.clone(),
                    target: Some(Target {
                        target: TargetRef::Vm {
                            vmx_path: vm.vmx_path.clone(),
                        },
                        name: vm.display_name,
                        environment: vm.environment,
                        protected: vm.protected,
                    }),
                })
            }
        }
    }

    fn note(row: NoteRow, title: String) -> Note {
        Note {
            looks_secret: render::looks_secret(&row.body),
            kind: row.kind,
            key: row.key,
            title,
            body: row.body,
            handover: row.handover,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    /// The note about `target`, if it has one.
    pub async fn get(&self, ctx: &Context, target: &NoteTarget) -> Result<Option<Note>> {
        let target = target.checked()?;
        let Some(row) = self.store.note(ctx, target.kind, &target.key).await? else {
            return Ok(None);
        };
        let title = match self.about(ctx, &target, false).await {
            Ok(about) => about.title,
            Err(CoreError::UnknownTarget(_)) => target.key.clone(),
            Err(err) => return Err(err),
        };
        Ok(Some(Self::note(row, title)))
    }

    /// Saves the note about `target`; an empty text deletes it. Audited without the text; an edit that changes nothing
    /// writes nothing. Refused while presenting.
    pub async fn save(&self, ctx: &Context, target: &NoteTarget, input: NoteInput) -> Result<Option<Note>> {
        self.store.read_only().check(Change::Notes)?;
        let target = target.checked()?;
        let body = clean_body(&input.body)?;
        let about = self.about(ctx, &target, true).await?;
        let before = self.store.note(ctx, target.kind, &target.key).await?;
        let what = format!("{} '{}'", target.kind.noun(), about.title);
        if body.trim().is_empty() {
            if before.is_none() {
                return Ok(None);
            }
            self.store.delete_note(ctx, target.kind, &target.key).await?;
            self.audit(ctx, &format!("Deleted the note of {what}"), &about, "")
                .await?;
            return Ok(None);
        }
        let handover = input.handover;
        if let Some(b) = &before {
            if b.body == body && b.handover == handover {
                return Ok(Some(Self::note(b.clone(), about.title)));
            }
        }
        self.store
            .put_note(ctx, target.kind, &target.key, &body, handover)
            .await?;
        let mut detail = vec![plural(body.chars().count(), "character")];
        match &before {
            None if handover => detail.push("marked for the handover pack".into()),
            Some(b) if b.handover != handover => detail.push(if handover {
                "marked for the handover pack".into()
            } else {
                "no longer in the handover pack".into()
            }),
            _ => {}
        }
        if render::looks_secret(&body) {
            detail.push("it looks like it holds a secret".into());
        }
        let action = match &before {
            None => format!("Added a note to {what}"),
            Some(b) if b.body == body => format!("Changed the handover mark of the note of {what}"),
            Some(_) => format!("Changed the note of {what}"),
        };
        self.audit(ctx, &action, &about, &detail.join("; ")).await?;
        self.get(ctx, &target).await
    }

    /// F6: marks the note for the handover pack, or takes it out. Audited; refused while presenting.
    pub async fn set_handover(&self, ctx: &Context, target: &NoteTarget, handover: bool) -> Result<Note> {
        let target = target.checked()?;
        let note = self
            .get(ctx, &target)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget("note".into()))?;
        let saved = self
            .save(
                ctx,
                &target,
                NoteInput {
                    body: note.body,
                    handover,
                },
            )
            .await?;
        saved.ok_or_else(|| CoreError::UnknownTarget("note".into()))
    }

    /// QL-20: every note in the workspace whose session, folder or VM is here, newest first.
    pub async fn list(&self, ctx: &Context) -> Result<Vec<Note>> {
        let sessions: HashMap<String, String> = self
            .store
            .list_sessions(ctx)
            .await?
            .into_iter()
            .map(|s| (s.id.to_string(), s.name))
            .collect();
        let folders: HashMap<String, String> = self
            .store
            .list_session_folders(ctx)
            .await?
            .into_iter()
            .map(|f| (f.id.to_string(), f.name))
            .collect();
        let vms: HashMap<String, String> = self
            .store
            .list_vms(ctx)
            .await?
            .into_iter()
            .map(|vm| (vm.vmx_path.to_lowercase(), vm.display_name))
            .collect();
        let mut out = Vec::new();
        for row in self.store.list_notes(ctx).await? {
            let title = match row.kind {
                NoteKind::Session => sessions.get(&row.key).cloned(),
                NoteKind::Folder => folders.get(&row.key).cloned(),
                NoteKind::Vm => vms.get(&row.key.to_lowercase()).cloned(),
            };
            if let Some(title) = title {
                out.push(Self::note(row, title));
            }
        }
        Ok(out)
    }

    /// The names a note's app links are found by in the workspace: sessions, VMs, vault labels, saved and built-in
    /// commands, and the command library's troubleshooting runbooks.
    pub async fn link_names(&self, ctx: &Context) -> Result<LinkNames> {
        let mut names = LinkNames::default();
        for s in self.store.list_sessions(ctx).await? {
            names.add_session(&s.name, s.id);
        }
        for vm in self.store.list_vms(ctx).await? {
            names.add_vm(&vm.display_name, &vm.vmx_path);
        }
        for item in self.store.vault_items(ctx).await? {
            names.add_vault(&item.label);
        }
        for f in self.store.list_favourites(ctx).await? {
            names.add_command(&f.name);
        }
        for b in LIBRARY {
            names.add_command(b.name);
        }
        for symptom in TROUBLESHOOT {
            if symptom.group.section() == LibrarySection::Troubleshoot {
                names.add_runbook(symptom.group.label());
            }
        }
        Ok(names)
    }

    /// `body` as the window shows it, its app links found in this workspace. A read: not audited.
    pub async fn render(&self, ctx: &Context, body: &str) -> Result<RenderedNote> {
        let names = self.link_names(ctx).await?;
        Ok(render(body, &names, LinkMode::App))
    }

    /// F6: the notes marked for the handover pack, each with its HTML for a file read outside the app.
    pub async fn for_handover(&self, ctx: &Context) -> Result<Vec<(Note, String)>> {
        let names = self.link_names(ctx).await?;
        Ok(self
            .list(ctx)
            .await?
            .into_iter()
            .filter(|n| n.handover)
            .map(|n| {
                let html = render(&n.body, &names, LinkMode::Static).html;
                (n, html)
            })
            .collect())
    }

    /// FD-07: a note from an export, over the one there (`replace`) or only where there is none. Audited as imported.
    /// True when it was saved.
    pub(crate) async fn import(
        &self,
        ctx: &Context,
        target: &NoteTarget,
        body: &str,
        handover: bool,
        replace: bool,
        source: &str,
    ) -> Result<bool> {
        let target = target.checked()?;
        let body = clean_body(body)?;
        if body.trim().is_empty() {
            return Ok(false);
        }
        let before = self.store.note(ctx, target.kind, &target.key).await?;
        if let Some(b) = &before {
            if !replace || (b.body == body && b.handover == handover) {
                return Ok(false);
            }
        }
        let about = self.about(ctx, &target, true).await?;
        self.store
            .put_note(ctx, target.kind, &target.key, &body, handover)
            .await?;
        let action = format!(
            "Imported the note of {} '{}' from {source}",
            target.kind.noun(),
            about.title
        );
        self.audit(ctx, &action, &about, &plural(body.chars().count(), "character"))
            .await?;
        Ok(true)
    }

    async fn audit(&self, ctx: &Context, action: &str, about: &About, detail: &str) -> Result<()> {
        let targets: Vec<Target> = about.target.iter().cloned().collect();
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "note_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: &targets,
                    approval: None,
                    result: None,
                    detail: (!detail.is_empty()).then_some(detail),
                },
            )
            .await
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_text_is_tidied_and_checked() {
        assert_eq!(
            clean_body("\r\n\r\nline one\r\nline two  \n\n").unwrap(),
            "line one\nline two"
        );
        assert!(clean_body("bell \u{7}").is_err());
        assert!(clean_body(&"x".repeat(MAX_NOTE_CHARS + 1)).is_err());
        assert_eq!(clean_body("a\tb").unwrap(), "a\tb");
    }

    #[test]
    fn targets_are_checked() {
        assert!(NoteTarget {
            kind: NoteKind::Session,
            key: "not-a-uuid".into()
        }
        .checked()
        .is_err());
        let id = Uuid::new_v4();
        let t = NoteTarget {
            kind: NoteKind::Folder,
            key: format!(" {} ", id.to_string().to_uppercase()),
        }
        .checked()
        .unwrap();
        assert_eq!(t.key, id.to_string());
        assert!(NoteTarget::vm("").checked().is_err());
    }
}
