//! QL-19 saved MultiExec groups: a named set of saved sessions, in order ("all web servers"). The
//! Terminal page opens a terminal for each and turns MultiExec on for them ("Open group"), or picks the
//! terminals already open for them ("Select group").
//!
//! * A group only chooses MultiExec's targets. Every line typed still goes through the command bus and
//!   is rated for the terminals it reaches (SS-10), so a group never runs anything by itself.
//! * Members are saved sessions of this workspace, each once, in the user's order. A deleted session
//!   leaves its groups (the database drops the membership with the session), so a group can end up
//!   with fewer members, or none.
//! * Creating, changing and deleting a group is audited like a session edit (`multiexec_group_changed`,
//!   the member sessions as targets, what changed) and refused by the read-only lock (FD-03).
//! * FD-07 carries groups between laptops (`transfer::groups`), through this module, so an import is
//!   checked and audited as if the user had made it here.
//!
//! Nothing here touches a host, so it skips the command bus, like the session library.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{Context, Target};
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::sessions::SessionRecord;
use crate::store::{GroupRow, NewAuditEntry, Store};
use crate::terminal::Terminals;
use crate::untrusted::is_format_char;

/// Longest group name, in characters.
pub const MAX_NAME: usize = 60;
/// Sessions one group holds.
pub const MAX_MEMBERS: usize = 100;
/// Groups one workspace keeps.
pub const MAX_GROUPS: usize = 200;
/// Member names the audit log lists before "and N more".
const NAMES_LISTED: usize = 10;

/// One member: a saved session, with its name now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    pub session_id: Uuid,
    pub name: String,
}

/// A saved group, as the Terminal page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiExecGroup {
    pub id: Uuid,
    pub name: String,
    /// In the user's order.
    pub members: Vec<GroupMember>,
    pub created_at: String,
    pub updated_at: String,
}

impl MultiExecGroup {
    pub fn session_ids(&self) -> Vec<Uuid> {
        self.members.iter().map(|m| m.session_id).collect()
    }
}

impl From<GroupRow> for MultiExecGroup {
    fn from(row: GroupRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            members: row
                .members
                .into_iter()
                .map(|m| GroupMember {
                    session_id: m.session_id,
                    name: m.name,
                })
                .collect(),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// What the group editor (and "Save picked tabs as a group") sends.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupInput {
    pub name: String,
    /// Saved sessions, in order. Repeats are dropped.
    #[serde(default)]
    pub session_ids: Vec<Uuid>,
}

/// A group's open terminals now ([`MultiExecGroups::open_terminals`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupTerminals {
    /// The terminals open for the group's sessions, in the group's order (a session open in several
    /// terminals gives each).
    pub terminal_ids: Vec<Uuid>,
    /// Members with no terminal open.
    pub not_open: Vec<GroupMember>,
}

/// A group name: trimmed, 1 to [`MAX_NAME`] characters, one line, no invisible formatting characters.
pub fn clean_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CoreError::InvalidInput("Give the group a name.".into()));
    }
    if name.chars().count() > MAX_NAME {
        return Err(CoreError::InvalidInput(format!(
            "A group name can be at most {MAX_NAME} characters."
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(CoreError::InvalidInput(
            "A group name can't hold line breaks or tabs.".into(),
        ));
    }
    if name.chars().any(is_format_char) {
        return Err(CoreError::InvalidInput(
            "A group name can't hold invisible formatting characters.".into(),
        ));
    }
    Ok(name.to_owned())
}

/// The members in order, each once: 1 to [`MAX_MEMBERS`].
pub fn clean_members(ids: &[Uuid]) -> Result<Vec<Uuid>> {
    let mut seen = HashSet::new();
    let members: Vec<Uuid> = ids.iter().copied().filter(|id| seen.insert(*id)).collect();
    if members.is_empty() {
        return Err(CoreError::InvalidInput(
            "Pick at least one saved session for the group.".into(),
        ));
    }
    if members.len() > MAX_MEMBERS {
        return Err(CoreError::InvalidInput(format!(
            "A group can hold at most {MAX_MEMBERS} sessions."
        )));
    }
    Ok(members)
}

/// `'web01', 'web02' and 3 more`, for the audit log.
fn names(names: &[&str]) -> String {
    let shown: Vec<String> = names.iter().take(NAMES_LISTED).map(|n| format!("'{n}'")).collect();
    let more = names.len().saturating_sub(shown.len());
    if more > 0 {
        format!("{} and {more} more", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// `3 sessions: 'web01', 'web02', 'web03'`.
fn describe_members(members: &[&SessionRecord]) -> String {
    let listed: Vec<&str> = members.iter().map(|s| s.name.as_str()).collect();
    if listed.is_empty() {
        "no sessions".to_owned()
    } else {
        format!("{}: {}", plural(listed.len(), "session"), names(&listed))
    }
}

/// The saved MultiExec groups.
#[derive(Clone)]
pub struct MultiExecGroups {
    store: Store,
}

impl MultiExecGroups {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Every group by name, each with its members in order.
    pub async fn list(&self, ctx: &Context) -> Result<Vec<MultiExecGroup>> {
        let rows = self.store.list_multiexec_groups(ctx).await?;
        Ok(rows.into_iter().map(MultiExecGroup::from).collect())
    }

    pub async fn get(&self, ctx: &Context, id: Uuid) -> Result<MultiExecGroup> {
        self.list(ctx)
            .await?
            .into_iter()
            .find(|g| g.id == id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("MultiExec group {id}")))
    }

    /// The saved sessions by id, each one a member must be.
    async fn sessions(&self, ctx: &Context) -> Result<HashMap<Uuid, SessionRecord>> {
        let sessions = self.store.list_sessions(ctx).await?;
        Ok(sessions.into_iter().map(|s| (s.id, s)).collect())
    }

    /// The input checked against this workspace: its name free (any letter case) but for `except`, and
    /// every member a saved session here.
    async fn checked(
        &self,
        ctx: &Context,
        input: &GroupInput,
        except: Option<Uuid>,
    ) -> Result<(String, Vec<Uuid>, Vec<GroupRow>, HashMap<Uuid, SessionRecord>)> {
        let name = clean_name(&input.name)?;
        let members = clean_members(&input.session_ids)?;
        let groups = self.store.list_multiexec_groups(ctx).await?;
        let lower = name.to_lowercase();
        if groups
            .iter()
            .any(|g| Some(g.id) != except && g.name.to_lowercase() == lower)
        {
            return Err(CoreError::InvalidInput(format!(
                "There is a group named '{name}' already."
            )));
        }
        let sessions = self.sessions(ctx).await?;
        let missing = members.iter().filter(|id| !sessions.contains_key(id)).count();
        if missing > 0 {
            return Err(CoreError::InvalidInput(format!(
                "{} picked for the group {} not saved here (deleted meanwhile?). Pick the sessions again.",
                plural(missing, "session"),
                if missing == 1 { "is" } else { "are" }
            )));
        }
        // SS-12: a group is for typing in all its tabs, which SSH sessions do, and (BX-13) WinRM sessions in their
        // PowerShell tabs. Typing goes to one kind of tab at a time (their consoles read keys differently), so a group
        // is all SSH or all WinRM.
        let picked: Vec<&SessionRecord> = members.iter().filter_map(|id| sessions.get(id)).collect();
        if let Some(other) = picked.iter().find(|s| !s.kind.is_ssh() && !s.kind.is_winrm()) {
            other.require_ssh("a saved group's tabs are SSH or PowerShell terminals")?;
        }
        if picked.iter().any(|s| s.kind.is_ssh()) && picked.iter().any(|s| s.kind.is_winrm()) {
            return Err(CoreError::InvalidInput(
                "A group holds SSH sessions or WinRM sessions, not both: typing goes to SSH tabs or to PowerShell tabs \
                 at a time."
                    .into(),
            ));
        }
        Ok((name, members, groups, sessions))
    }

    /// Saves a new group. Audited with its sessions.
    pub async fn create(&self, ctx: &Context, input: GroupInput) -> Result<MultiExecGroup> {
        self.store.read_only().check(Change::MultiExecGroups)?;
        let (name, members, groups, sessions) = self.checked(ctx, &input, None).await?;
        if groups.len() >= MAX_GROUPS {
            return Err(CoreError::InvalidInput(format!(
                "There are {MAX_GROUPS} MultiExec groups already. Delete some first."
            )));
        }
        let id = Uuid::new_v4();
        self.store.insert_multiexec_group(ctx, id, &name, &members).await?;
        let records: Vec<&SessionRecord> = members.iter().filter_map(|m| sessions.get(m)).collect();
        self.audit(
            ctx,
            &format!("Created the MultiExec group '{name}'"),
            &records,
            &describe_members(&records),
        )
        .await?;
        self.get(ctx, id).await
    }

    /// Renames it and sets its members. Audited with what changed, the sessions added and removed
    /// among its targets.
    pub async fn update(&self, ctx: &Context, id: Uuid, input: GroupInput) -> Result<MultiExecGroup> {
        self.store.read_only().check(Change::MultiExecGroups)?;
        let before = self.get(ctx, id).await?;
        let (name, members, _, sessions) = self.checked(ctx, &input, Some(id)).await?;
        let was = before.session_ids();
        let mut changes = Vec::new();
        if before.name != name {
            changes.push(format!("renamed to '{name}'"));
        }
        let added: Vec<&SessionRecord> = members
            .iter()
            .filter(|m| !was.contains(m))
            .filter_map(|m| sessions.get(m))
            .collect();
        let removed: Vec<&SessionRecord> = was
            .iter()
            .filter(|m| !members.contains(m))
            .filter_map(|m| sessions.get(m))
            .collect();
        if !added.is_empty() {
            let listed: Vec<&str> = added.iter().map(|s| s.name.as_str()).collect();
            changes.push(format!("added {}", names(&listed)));
        }
        if !removed.is_empty() {
            let listed: Vec<&str> = removed.iter().map(|s| s.name.as_str()).collect();
            changes.push(format!("removed {}", names(&listed)));
        }
        let kept_was: Vec<&Uuid> = was.iter().filter(|m| members.contains(m)).collect();
        let kept_now: Vec<&Uuid> = members.iter().filter(|m| was.contains(m)).collect();
        if kept_was != kept_now {
            changes.push("reordered".to_owned());
        }
        if changes.is_empty() {
            return Ok(before);
        }
        if !self.store.update_multiexec_group(ctx, id, &name, &members).await? {
            return Err(CoreError::UnknownTarget(format!("MultiExec group {id}")));
        }
        let mut targets: Vec<&SessionRecord> = members.iter().filter_map(|m| sessions.get(m)).collect();
        targets.extend(removed.iter().copied());
        let detail = format!("{}; now {}", changes.join("; "), plural(members.len(), "session"));
        self.audit(
            ctx,
            &format!("Changed the MultiExec group '{}'", before.name),
            &targets,
            &detail,
        )
        .await?;
        self.get(ctx, id).await
    }

    /// Audited with the sessions it held. The sessions stay.
    pub async fn delete(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::MultiExecGroups)?;
        let group = self.get(ctx, id).await?;
        if !self.store.delete_multiexec_group(ctx, id).await? {
            return Err(CoreError::UnknownTarget(format!("MultiExec group {id}")));
        }
        let sessions = self.sessions(ctx).await?;
        let records: Vec<&SessionRecord> = group
            .members
            .iter()
            .filter_map(|m| sessions.get(&m.session_id))
            .collect();
        self.audit(
            ctx,
            &format!("Deleted the MultiExec group '{}'", group.name),
            &records,
            &format!("it held {}", describe_members(&records)),
        )
        .await
    }

    /// The terminals open now for a group's sessions, in the group's order, and the members with none.
    /// Reads only: what MultiExec types into is still chosen with `MultiExec::set_targets`.
    pub async fn open_terminals(&self, ctx: &Context, id: Uuid, terminals: &Terminals) -> Result<GroupTerminals> {
        let group = self.get(ctx, id).await?;
        let mut by_session: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        for terminal in terminals.open_ids() {
            if let Some(session) = terminals.pane_info(terminal).and_then(|p| p.session_id) {
                by_session.entry(session).or_default().push(terminal);
            }
        }
        let mut open = GroupTerminals {
            terminal_ids: Vec::new(),
            not_open: Vec::new(),
        };
        for member in group.members {
            match by_session.get_mut(&member.session_id) {
                Some(ids) => {
                    ids.sort();
                    open.terminal_ids.extend(ids.iter().copied());
                }
                None => open.not_open.push(member),
            }
        }
        Ok(open)
    }

    async fn audit(&self, ctx: &Context, action: &str, sessions: &[&SessionRecord], detail: &str) -> Result<()> {
        let targets: Vec<Target> = sessions.iter().map(|s| s.target()).collect();
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "multiexec_group_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: &targets,
                    approval: None,
                    result: None,
                    detail: Some(detail),
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
    fn names_are_trimmed_and_checked() {
        assert_eq!(clean_name("  web servers ").unwrap(), "web servers");
        assert!(clean_name("   ").is_err());
        assert!(clean_name("a\tb").is_err());
        assert!(clean_name("web\u{202e}srevres").is_err(), "a bidi override");
        assert!(clean_name(&"x".repeat(MAX_NAME + 1)).is_err());
        assert!(clean_name(&"é".repeat(MAX_NAME)).is_ok(), "characters, not bytes");
    }

    #[test]
    fn members_keep_their_order_once_each() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(clean_members(&[b, a, b, c, a]).unwrap(), [b, a, c]);
        assert!(clean_members(&[]).is_err());
        let many: Vec<Uuid> = (0..=MAX_MEMBERS).map(|_| Uuid::new_v4()).collect();
        assert!(clean_members(&many).is_err());
        assert_eq!(clean_members(&many[..MAX_MEMBERS]).unwrap().len(), MAX_MEMBERS);
    }

    #[test]
    fn long_member_lists_are_cut_in_the_audit_text() {
        let listed: Vec<String> = (1..=12).map(|i| format!("web{i:02}")).collect();
        let refs: Vec<&str> = listed.iter().map(String::as_str).collect();
        let text = names(&refs);
        assert!(text.starts_with("'web01', 'web02'"), "{text}");
        assert!(text.ends_with("'web10' and 2 more"), "{text}");
        assert_eq!(names(&["a"]), "'a'");
    }
}
