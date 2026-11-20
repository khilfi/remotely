//! BX-08 command panel in the Terminal page: the user's favourite commands and a built-in library of
//! common ones, both with `{{variables}}` ([`variables`]) asked when a command is pasted.
//!
//! * Favourites live in this workspace's database (`command_favourites`), in one level of folders,
//!   in the user's order. Adding, changing, reordering and deleting them is audited by name and
//!   folder, never the command text (like a session's startup command, it is the user's own text).
//! * The library ([`library`]) is part of the app. Any entry can be copied into the favourites.
//! * Every command shows what the policy engine makes of it ([`CommandRisk`]): read-only, other, or
//!   dangerous with the rules it matches (BX-06), from the user's current rules. That is the check a
//!   bulk run, and in P6 MultiExec, applies before running it on several hosts.
//! * Pasting is the terminal's job: a click pastes into the current terminal, Shift+click presses
//!   Enter too, as if the user typed it, so no approval is asked (interactive shells skip the approval
//!   flow). P6's MultiExec sends the same filled line to several terminals through its own check.
//!
//! Nothing here touches a host, so it skips the command bus, like the session library.
//!
//! QL-13: every library entry carries a link to its official manual page ([`manual`]); the desktop
//! shell opens one only after [`manual::checked`] allows its address.
//!
//! UX-20 (0.9.0): favourites are the one way to keep a command. A library row's "Add to favourites" saves it into the
//! [`STARRED_FOLDER`] ([`Snippets::add_from_library`]); the command stars 0.8.x kept (QL-26's `favourite:<id>` and
//! `library:<id>`) move into the favourites once per workspace ([`Snippets::move_command_stars`]). The library lives
//! in code, so that step is here, not a migration.

pub mod library;
pub mod manual;
pub mod variables;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use self::library::{BuiltIn, LibraryGroup, LibrarySection, LIBRARY, TROUBLESHOOT};
use self::variables::Variable;
use crate::domain::{Context, UserId};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::policy::{ActionKind, PolicyEngine};
use crate::presentation::Change;
use crate::store::{FavouriteFields, FavouriteRow, NewAuditEntry, Store};

pub const MAX_NAME: usize = 80;
pub const MAX_FOLDER: usize = 60;
pub const MAX_DESCRIPTION: usize = 500;
/// Longest command a favourite holds.
pub const MAX_COMMAND_BYTES: usize = 8 * 1024;
/// Favourites one workspace keeps.
pub const MAX_FAVOURITES: usize = 2000;
/// UX-20: the folder "Add to favourites" saves a library command in, and where 0.8.x's starred ones went.
pub const STARRED_FOLDER: &str = "Starred";

/// UX-20: what "Add to favourites" did: the favourite it saved, or (`added` false) the one already holding that
/// command, wherever it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddedFavourite {
    pub favourite: Favourite,
    pub added: bool,
}

/// UX-20: what the one-time move of a workspace's command stars did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StarsMoved {
    /// Library commands saved into [`STARRED_FOLDER`].
    pub added: usize,
    /// Starred library commands whose command a favourite held already.
    pub already: usize,
    /// Folders whose starred favourites now come first, as the panel showed them.
    pub reordered: usize,
    /// Stars deleted (every one but those left for want of room).
    pub deleted: usize,
    /// Starred library commands left as stars: the workspace has [`MAX_FAVOURITES`] already.
    pub left: usize,
}

/// What the policy engine makes of a command (BX-06), with the user's current rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandRisk {
    /// [`ActionKind::ExecReadOnly`], [`ActionKind::ExecOther`] or [`ActionKind::ExecDangerous`].
    pub action: ActionKind,
    /// The dangerous-command rules it matches, by name.
    pub dangerous: Vec<String>,
}

/// A saved command, as the panel shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Favourite {
    pub id: Uuid,
    /// `None`: at the top level.
    pub folder: Option<String>,
    pub name: String,
    pub command: String,
    pub description: Option<String>,
    pub variables: Vec<Variable>,
    pub risk: CommandRisk,
    pub created_at: String,
    pub updated_at: String,
}

/// What the favourite dialog sends.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FavouriteInput {
    #[serde(default)]
    pub folder: Option<String>,
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// A command's variables and risk, for the favourite dialog while it is typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandInfo {
    pub variables: Vec<Variable>,
    pub risk: CommandRisk,
}

/// A built-in command, as one group shows it. The same command (same `id`) can appear once in its area
/// group and again in one or more symptom (Troubleshoot) groups, so `group`/`section` say where this
/// copy sits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryEntry {
    pub id: &'static str,
    pub section: LibrarySection,
    pub section_label: &'static str,
    pub group: LibraryGroup,
    pub group_label: &'static str,
    pub name: &'static str,
    pub command: &'static str,
    pub description: &'static str,
    pub variables: Vec<Variable>,
    pub risk: CommandRisk,
    /// QL-13: the address of the command's official manual page.
    pub manual: String,
}

/// Checked fields of a favourite.
struct Clean {
    folder: String,
    name: String,
    command: String,
    description: Option<String>,
}

/// One line of text: trimmed, at most `max` characters, no control characters.
fn clean_line(what: &str, value: &str, max: usize) -> Result<String> {
    let value = value.trim();
    if value.chars().count() > max {
        return Err(CoreError::InvalidInput(format!(
            "The {what} can be at most {max} characters."
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(CoreError::InvalidInput(format!(
            "The {what} can't hold line breaks or tabs."
        )));
    }
    Ok(value.to_owned())
}

/// Trims the command and makes its line breaks `\n`. Tabs and line breaks are kept; other control
/// characters (escape sequences, Ctrl+C) are refused, since pasting them would do more than type.
fn clean_command(command: &str) -> Result<String> {
    let command = command.replace("\r\n", "\n").replace('\r', "\n");
    let command = command.trim();
    if command.is_empty() {
        return Err(CoreError::InvalidInput("Type the command.".into()));
    }
    if command.len() > MAX_COMMAND_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "A command can be at most {} KiB.",
            MAX_COMMAND_BYTES / 1024
        )));
    }
    if command.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(CoreError::InvalidInput(
            "A command can't hold control characters, only text, tabs and line breaks.".into(),
        ));
    }
    Ok(command.to_owned())
}

fn clean(input: &FavouriteInput) -> Result<Clean> {
    let name = clean_line("name", &input.name, MAX_NAME)?;
    if name.is_empty() {
        return Err(CoreError::InvalidInput("Give the command a name.".into()));
    }
    let folder = clean_line("folder name", input.folder.as_deref().unwrap_or(""), MAX_FOLDER)?;
    let description = match input.description.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(text) => {
            if text.chars().count() > MAX_DESCRIPTION {
                return Err(CoreError::InvalidInput(format!(
                    "The description can be at most {MAX_DESCRIPTION} characters."
                )));
            }
            if text.chars().any(|c| c.is_control() && c != '\n') {
                return Err(CoreError::InvalidInput(
                    "The description can't hold control characters.".into(),
                ));
            }
            Some(text.to_owned())
        }
    };
    Ok(Clean {
        folder,
        name,
        command: clean_command(&input.command)?,
        description,
    })
}

/// `'web'` or "the top level", for messages and the audit log.
fn place(folder: &str) -> String {
    if folder.is_empty() {
        "the top level".to_owned()
    } else {
        format!("the folder '{folder}'")
    }
}

/// UX-20: `name` in `folder` when no favourite there has it (any letter case), else the first free "name (2)", "name
/// (3)"…, each cut to [`MAX_NAME`] characters.
fn free_name(rows: &[FavouriteRow], folder: &str, name: &str) -> String {
    let taken = |n: &str| {
        rows.iter()
            .any(|r| r.folder.eq_ignore_ascii_case(folder) && r.name.eq_ignore_ascii_case(n))
    };
    let cut = |text: &str, room: usize| text.trim().chars().take(room).collect::<String>();
    let own = cut(name, MAX_NAME);
    if !taken(&own) {
        return own;
    }
    (2..=rows.len() + 2)
        .map(|n| {
            let suffix = format!(" ({n})");
            format!("{}{suffix}", cut(name, MAX_NAME.saturating_sub(suffix.len())))
        })
        .find(|n| !taken(n))
        .unwrap_or(own)
}

/// The favourite commands and the built-in library.
pub struct Snippets {
    store: Store,
    policy: Arc<RwLock<PolicyEngine>>,
}

impl Snippets {
    /// `policy` is the command bus's engine, so a rule change shows at once.
    pub fn new(store: Store, policy: Arc<RwLock<PolicyEngine>>) -> Self {
        Self { store, policy }
    }

    /// The policy engine's answer for a command, with the current rules.
    pub fn classify(&self, command: &str) -> CommandRisk {
        let policy = locks::read(&self.policy);
        CommandRisk {
            action: policy.classify_script(command),
            dangerous: policy.dangerous_matches(command),
        }
    }

    fn favourite(&self, row: FavouriteRow) -> Favourite {
        Favourite {
            variables: variables::variables(&row.command),
            risk: self.classify(&row.command),
            id: row.id,
            folder: Some(row.folder).filter(|f| !f.is_empty()),
            name: row.name,
            command: row.command,
            description: row.description,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    /// Folders by name (the top level first), each in the user's order.
    pub async fn favourites(&self, ctx: &Context) -> Result<Vec<Favourite>> {
        let rows = self.store.list_favourites(ctx).await?;
        Ok(rows.into_iter().map(|row| self.favourite(row)).collect())
    }

    pub async fn get(&self, ctx: &Context, id: Uuid) -> Result<Favourite> {
        let row = self.row(ctx, id).await?;
        Ok(self.favourite(row))
    }

    async fn row(&self, ctx: &Context, id: Uuid) -> Result<FavouriteRow> {
        self.store
            .favourite(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("favourite command {id}")))
    }

    /// The folder as already spelled, when one with that name (any letter case) exists; and no other
    /// favourite there with the same name.
    fn place_in(rows: &[FavouriteRow], clean: &mut Clean, except: Option<Uuid>) -> Result<()> {
        if let Some(existing) = rows
            .iter()
            .find(|r| !r.folder.is_empty() && r.folder.eq_ignore_ascii_case(&clean.folder))
        {
            clean.folder = existing.folder.clone();
        }
        let taken = rows.iter().any(|r| {
            Some(r.id) != except
                && r.folder.eq_ignore_ascii_case(&clean.folder)
                && r.name.eq_ignore_ascii_case(&clean.name)
        });
        if taken {
            return Err(CoreError::InvalidInput(format!(
                "{} already has a command named '{}'.",
                capitalized(&place(&clean.folder)),
                clean.name
            )));
        }
        Ok(())
    }

    /// Saves a new favourite at the end of its folder. Audited.
    pub async fn add(&self, ctx: &Context, input: FavouriteInput) -> Result<Favourite> {
        self.store.read_only().check(Change::Favourites)?;
        let mut clean = clean(&input)?;
        let rows = self.store.list_favourites(ctx).await?;
        if rows.len() >= MAX_FAVOURITES {
            return Err(CoreError::InvalidInput(format!(
                "There are {MAX_FAVOURITES} favourite commands already. Delete some first."
            )));
        }
        Self::place_in(&rows, &mut clean, None)?;
        let id = Uuid::new_v4();
        self.store.insert_favourite(ctx, id, &fields(&clean)).await?;
        self.audit(
            ctx,
            &format!("Added the favourite command '{}'", clean.name),
            &format!("in {}", place(&clean.folder)),
        )
        .await?;
        self.get(ctx, id).await
    }

    /// Changes a favourite; moved to another folder, it goes to that folder's end. Audited with what
    /// changed (never the command text).
    pub async fn update(&self, ctx: &Context, id: Uuid, input: FavouriteInput) -> Result<Favourite> {
        self.store.read_only().check(Change::Favourites)?;
        let before = self.row(ctx, id).await?;
        let mut clean = clean(&input)?;
        let rows = self.store.list_favourites(ctx).await?;
        Self::place_in(&rows, &mut clean, Some(id))?;
        let mut changes = Vec::new();
        if before.name != clean.name {
            changes.push(format!("renamed to '{}'", clean.name));
        }
        if !before.folder.eq_ignore_ascii_case(&clean.folder) {
            changes.push(format!("moved to {}", place(&clean.folder)));
        }
        if before.command != clean.command {
            changes.push("command changed".to_owned());
        }
        if before.description != clean.description {
            changes.push("description changed".to_owned());
        }
        if changes.is_empty() {
            return Ok(self.favourite(before));
        }
        self.store.update_favourite(ctx, id, &fields(&clean)).await?;
        self.audit(
            ctx,
            &format!("Changed the favourite command '{}'", before.name),
            &changes.join(", "),
        )
        .await?;
        self.get(ctx, id).await
    }

    /// Audited. QL-27: it goes to the trash, and can be restored for 30 days.
    pub async fn delete(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::Favourites)?;
        let row = self.row(ctx, id).await?;
        let item = crate::trash::TrashItem {
            kind: crate::trash::TrashKind::Command,
            item_id: &id.to_string(),
            name: &row.name,
            place: if row.folder.is_empty() {
                "Favourite commands".to_owned()
            } else {
                format!("Favourite commands › {}", row.folder)
            },
            sent: None,
            jump_users: Vec::new(),
        };
        if crate::trash::move_to_trash(&self.store, ctx, item).await?.is_none() {
            return Err(CoreError::UnknownTarget(format!("favourite {id}")));
        }
        self.audit(
            ctx,
            &format!("Deleted the favourite command '{}'", row.name),
            &format!(
                "from {}; moved to the trash for {} days",
                place(&row.folder),
                crate::trash::KEEP_DAYS
            ),
        )
        .await
    }

    /// Puts one folder's favourites in this order (`None`: the top level). `ids` must be exactly
    /// that folder's favourites. Audited.
    pub async fn reorder(&self, ctx: &Context, folder: Option<&str>, ids: &[Uuid]) -> Result<Vec<Favourite>> {
        self.store.read_only().check(Change::Favourites)?;
        let folder = folder.map(str::trim).unwrap_or("");
        let rows = self.store.list_favourites(ctx).await?;
        let mut current: Vec<Uuid> = rows
            .iter()
            .filter(|r| r.folder.eq_ignore_ascii_case(folder))
            .map(|r| r.id)
            .collect();
        let mut wanted = ids.to_vec();
        if current == wanted {
            return self.favourites(ctx).await;
        }
        current.sort();
        wanted.sort();
        let mut unique = wanted.clone();
        unique.dedup();
        if current != wanted || unique.len() != wanted.len() {
            return Err(CoreError::InvalidInput(format!(
                "The favourites in {} changed meanwhile. Try again.",
                place(folder)
            )));
        }
        self.store.order_favourites(ctx, ids).await?;
        let shown = rows
            .iter()
            .find(|r| r.folder.eq_ignore_ascii_case(folder))
            .map_or(folder, |r| r.folder.as_str());
        self.audit(
            ctx,
            "Reordered the favourite commands",
            &format!("{} in {}", ids.len(), place(shown)),
        )
        .await?;
        self.favourites(ctx).await
    }

    /// UX-20: a library row's "Add to favourites": its command, name and description saved at the end of
    /// [`STARRED_FOLDER`], audited as an add. When a favourite holds that command already, in any folder, that one is
    /// returned and nothing is saved.
    pub async fn add_from_library(&self, ctx: &Context, id: &str) -> Result<AddedFavourite> {
        self.store.read_only().check(Change::Favourites)?;
        let entry = LIBRARY
            .iter()
            .find(|b| b.id == id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("library command {id}")))?;
        let rows = self.store.list_favourites(ctx).await?;
        let (id, added) = self.save_from_library(ctx, entry, &rows, "from the library").await?;
        Ok(AddedFavourite {
            favourite: self.get(ctx, id).await?,
            added,
        })
    }

    /// Saves `entry` at the end of [`STARRED_FOLDER`] (spelled as it is, when it exists), under its own name or the
    /// first free "name (2)", unless a favourite holds its command already: then that one, and false. Audited as an
    /// add; `how` says where it came from.
    async fn save_from_library(
        &self,
        ctx: &Context,
        entry: &BuiltIn,
        rows: &[FavouriteRow],
        how: &str,
    ) -> Result<(Uuid, bool)> {
        let command = clean_command(entry.command)?;
        if let Some(row) = rows.iter().find(|r| r.command == command) {
            return Ok((row.id, false));
        }
        if rows.len() >= MAX_FAVOURITES {
            return Err(CoreError::InvalidInput(format!(
                "There are {MAX_FAVOURITES} favourite commands already. Delete some first."
            )));
        }
        let folder = rows
            .iter()
            .find(|r| r.folder.eq_ignore_ascii_case(STARRED_FOLDER))
            .map_or_else(|| STARRED_FOLDER.to_owned(), |r| r.folder.clone());
        let description = Some(entry.description.trim())
            .filter(|d| !d.is_empty())
            .map(|d| d.chars().take(MAX_DESCRIPTION).collect());
        let clean = Clean {
            name: free_name(rows, &folder, entry.name),
            folder,
            command,
            description,
        };
        let id = Uuid::new_v4();
        self.store.insert_favourite(ctx, id, &fields(&clean)).await?;
        self.audit(
            ctx,
            &format!("Added the favourite command '{}'", clean.name),
            &format!("in {}, {how}", place(&clean.folder)),
        )
        .await?;
        Ok((id, true))
    }

    /// UX-20: moves this workspace's command stars left from 0.8.x into the favourites. A starred library command is
    /// saved into [`STARRED_FOLDER`] by its text and name (audited as an add; nothing when a favourite holds that
    /// command already); a folder's starred favourites come first in it, as the panel showed them (audited as a
    /// reorder); then each star is deleted. Stars on sessions and VMs stay. Safe to run again: with no command star
    /// left it does nothing, and a run stopped half-way finds the favourites it added. The read-only lock refuses it,
    /// which leaves the stars for a later start.
    pub async fn move_command_stars(&self, ctx: &Context) -> Result<StarsMoved> {
        let keys = self.store.command_stars(ctx).await?;
        let mut moved = StarsMoved::default();
        if keys.is_empty() {
            return Ok(moved);
        }
        self.store.read_only().check(Change::Favourites)?;
        let mut rows = self.store.list_favourites(ctx).await?;
        let starred: HashSet<Uuid> = keys
            .iter()
            .filter_map(|k| k.strip_prefix("favourite:"))
            .filter_map(|id| Uuid::parse_str(id).ok())
            .collect();
        let mut folders: Vec<String> = Vec::new();
        for row in rows.iter().filter(|r| starred.contains(&r.id)) {
            if !folders.iter().any(|f| f.eq_ignore_ascii_case(&row.folder)) {
                folders.push(row.folder.clone());
            }
        }
        for folder in &folders {
            let now: Vec<Uuid> = rows
                .iter()
                .filter(|r| r.folder.eq_ignore_ascii_case(folder))
                .map(|r| r.id)
                .collect();
            let (first, rest): (Vec<Uuid>, Vec<Uuid>) = now.iter().copied().partition(|id| starred.contains(id));
            let wanted: Vec<Uuid> = first.into_iter().chain(rest).collect();
            if wanted != now {
                self.store.order_favourites(ctx, &wanted).await?;
                self.audit(
                    ctx,
                    "Reordered the favourite commands",
                    &format!("{} in {}: the starred ones first", wanted.len(), place(folder)),
                )
                .await?;
                moved.reordered += 1;
            }
        }
        for key in &keys {
            if let Some(entry) = key
                .strip_prefix("library:")
                .and_then(|id| LIBRARY.iter().find(|b| b.id == id))
            {
                match self
                    .save_from_library(ctx, entry, &rows, "a starred command from the library")
                    .await
                {
                    Ok((_, true)) => {
                        moved.added += 1;
                        rows = self.store.list_favourites(ctx).await?;
                    }
                    Ok((_, false)) => moved.already += 1,
                    // No room: the star stays for a later start.
                    Err(CoreError::InvalidInput(_)) if rows.len() >= MAX_FAVOURITES => {
                        moved.left += 1;
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            }
            self.store.delete_command_star(ctx, key).await?;
            moved.deleted += 1;
        }
        Ok(moved)
    }

    /// UX-20: [`Self::move_command_stars`] in every workspace of `user`, each with its own context and audited there
    /// (FD-02), at start. A workspace it can't do now (the read-only lock, an error) is logged and tried again at the
    /// next start. Returns how many stars were moved in all.
    pub async fn move_command_stars_everywhere(&self, user: UserId) -> Result<usize> {
        let mut total = 0;
        for workspace in self.store.list_workspaces(user).await? {
            let ctx = Context {
                workspace_id: workspace.id,
                user_id: user,
            };
            match self.move_command_stars(&ctx).await {
                Ok(moved) if moved.deleted > 0 || moved.left > 0 => {
                    tracing::info!(
                        added = moved.added,
                        already = moved.already,
                        reordered = moved.reordered,
                        deleted = moved.deleted,
                        left = moved.left,
                        "command stars moved into the favourites"
                    );
                    total += moved.deleted;
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(error = %err, "command stars could not move into the favourites yet"),
            }
        }
        Ok(total)
    }

    /// The built-in commands, each with what the policy engine makes of it now. The Troubleshoot
    /// section (symptom runbooks) comes first, then the area groups; a command listed in a symptom
    /// runbook appears once there (in the symptom group) and once in its own area group.
    pub fn library(&self) -> Vec<LibraryEntry> {
        let shown = |b: &BuiltIn, group: LibraryGroup| LibraryEntry {
            id: b.id,
            section: group.section(),
            section_label: group.section().label(),
            group,
            group_label: group.label(),
            name: b.name,
            command: b.command,
            description: b.description,
            variables: variables::variables(b.command),
            risk: self.classify(b.command),
            manual: b.manual.url(),
        };
        let find = |id: &str| LIBRARY.iter().find(|b| b.id == id);
        let mut out = Vec::new();
        // Troubleshoot section first, in symptom order, each runbook in its listed order.
        for symptom in TROUBLESHOOT {
            for id in symptom.steps {
                if let Some(b) = find(id) {
                    out.push(shown(b, symptom.group));
                }
            }
        }
        // Area section, in the order the entries are written (grouped by area).
        for b in LIBRARY {
            out.push(shown(b, b.group));
        }
        out
    }

    /// What the favourite dialog shows while a command is typed.
    pub fn inspect(&self, command: &str) -> CommandInfo {
        CommandInfo {
            variables: variables::variables(command),
            risk: self.classify(command),
        }
    }

    /// The command with its variables filled in, ready to paste (see [`variables::fill`]).
    pub fn fill(&self, command: &str, values: &HashMap<String, String>) -> Result<String> {
        variables::fill(command, values)
    }

    async fn audit(&self, ctx: &Context, action: &str, detail: &str) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "favourite_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }
}

fn fields(clean: &Clean) -> FavouriteFields<'_> {
    FavouriteFields {
        folder: &clean.folder,
        name: &clean.name,
        command: &clean.command,
        description: clean.description.as_deref(),
    }
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(command: &str) -> FavouriteInput {
        FavouriteInput {
            folder: None,
            name: "x".into(),
            command: command.into(),
            description: None,
        }
    }

    #[test]
    fn commands_are_trimmed_and_their_line_breaks_unified() {
        let clean = clean(&input("  uptime\r\ndf -h\rfree -h  ")).unwrap();
        assert_eq!(clean.command, "uptime\ndf -h\nfree -h");
        assert_eq!(clean_command("a\tb").unwrap(), "a\tb");
        assert!(clean_command("   ").is_err());
        assert!(clean_command("echo \x1b[2J").is_err(), "an escape sequence");
        assert!(clean_command("sleep 9\x03").is_err(), "Ctrl+C");
        assert!(clean_command(&"x".repeat(MAX_COMMAND_BYTES + 1)).is_err());
    }

    #[test]
    fn names_folders_and_descriptions_are_checked() {
        let mut bad = input("ls");
        bad.name = "  ".into();
        assert!(clean(&bad).is_err());
        bad.name = "a\nb".into();
        assert!(clean(&bad).is_err());
        bad.name = "x".repeat(MAX_NAME + 1);
        assert!(clean(&bad).is_err());
        let mut ok = input("ls");
        ok.folder = Some("  Web  ".into());
        ok.description = Some("  ".into());
        let clean_ok = clean(&ok).unwrap();
        assert_eq!(clean_ok.folder, "Web");
        assert_eq!(clean_ok.description, None);
        ok.folder = Some("x".repeat(MAX_FOLDER + 1));
        assert!(clean(&ok).is_err());
        ok.folder = None;
        ok.description = Some("two\nlines".into());
        assert_eq!(clean(&ok).unwrap().description.as_deref(), Some("two\nlines"));
        ok.description = Some("x".repeat(MAX_DESCRIPTION + 1));
        assert!(clean(&ok).is_err());
    }

    #[test]
    fn places_read_naturally() {
        assert_eq!(place(""), "the top level");
        assert_eq!(capitalized(&place("Web")), "The folder 'Web'");
    }

    // ---- UX-20: favourites only ----

    use crate::policy::PolicyRules;
    use crate::stars::{StarKind, Stars};
    use crate::store::AuditEntry;

    async fn setup() -> (Store, Snippets, Context, Context) {
        let store = Store::open_in_memory().await.unwrap();
        let home = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
        let acme = Context {
            workspace_id: crate::store::new_workspace_id(),
            user_id: home.user_id,
        };
        store
            .insert_workspace(home.user_id, acme.workspace_id, "Acme", "blue")
            .await
            .unwrap();
        let policy = Arc::new(RwLock::new(PolicyEngine::new(PolicyRules::default()).unwrap()));
        let snippets = Snippets::new(store.clone(), policy);
        (store, snippets, home, acme)
    }

    fn built_in(id: &str) -> &'static BuiltIn {
        LIBRARY.iter().find(|b| b.id == id).unwrap()
    }

    async fn audit(store: &Store, ctx: &Context) -> Vec<AuditEntry> {
        store.recent_audit(ctx, 100).await.unwrap()
    }

    fn mine(folder: Option<&str>, name: &str, command: &str) -> FavouriteInput {
        FavouriteInput {
            folder: folder.map(str::to_owned),
            name: name.into(),
            command: command.into(),
            description: None,
        }
    }

    #[tokio::test]
    async fn add_to_favourites_saves_a_library_command_into_starred_once() {
        let (store, snippets, home, _) = setup().await;
        let first = &LIBRARY[0];
        let added = snippets.add_from_library(&home, first.id).await.unwrap();
        assert!(added.added);
        assert_eq!(added.favourite.folder.as_deref(), Some(STARRED_FOLDER));
        assert_eq!(added.favourite.name, first.name);
        assert_eq!(added.favourite.command, clean_command(first.command).unwrap());
        let again = snippets.add_from_library(&home, first.id).await.unwrap();
        assert!(!again.added, "a favourite holds that command already");
        assert_eq!(again.favourite.id, added.favourite.id);
        assert_eq!(snippets.favourites(&home).await.unwrap().len(), 1);
        let adds: Vec<_> = audit(&store, &home)
            .await
            .into_iter()
            .filter(|e| e.event == "favourite_changed")
            .collect();
        assert_eq!(adds.len(), 1, "audited as one add");
        assert!(adds[0].action.starts_with("Added the favourite command"));

        // Another command with the same name in Starred gets "(2)"; an unknown id is refused.
        let other = LIBRARY.iter().find(|b| b.command != first.command).unwrap();
        snippets
            .update(
                &home,
                added.favourite.id,
                mine(Some("starred"), other.name, "echo renamed"),
            )
            .await
            .unwrap();
        let second = snippets.add_from_library(&home, other.id).await.unwrap();
        assert_eq!(second.favourite.name, format!("{} (2)", other.name));
        assert_eq!(
            second.favourite.folder.as_deref(),
            Some(STARRED_FOLDER),
            "the folder as spelled"
        );
        assert!(snippets.add_from_library(&home, "no.such").await.is_err());

        store.read_only().set(true);
        assert!(
            snippets.add_from_library(&home, LIBRARY[2].id).await.is_err(),
            "the read-only lock"
        );
    }

    #[tokio::test]
    async fn command_stars_move_into_the_favourites_once_per_workspace() {
        let (store, snippets, home, acme) = setup().await;
        let stars = Stars::new(store.clone());
        // Home: two folders' favourites, the second of "Web" starred; two starred library commands, one of which a
        // favourite holds already; a session star.
        let a = snippets.add(&home, mine(Some("Web"), "a", "echo a")).await.unwrap();
        let b = snippets.add(&home, mine(Some("Web"), "b", "echo b")).await.unwrap();
        let c = snippets.add(&home, mine(None, "c", "echo c")).await.unwrap();
        let disk = built_in("disk.free");
        let held = LIBRARY.iter().find(|x| x.command != disk.command).unwrap();
        snippets.add(&home, mine(None, "mine", held.command)).await.unwrap();
        store
            .insert_command_star(&home, &format!("favourite:{}", b.id))
            .await
            .unwrap();
        store
            .insert_command_star(&home, &format!("library:{}", disk.id))
            .await
            .unwrap();
        store
            .insert_command_star(&home, &format!("library:{}", held.id))
            .await
            .unwrap();
        store
            .insert_command_star(&home, "library:gone.from.library")
            .await
            .unwrap();
        let session = Uuid::new_v4().to_string();
        stars.set(&home, StarKind::Session, &session, true).await.unwrap();
        // Acme: one starred library command of its own.
        store
            .insert_command_star(&acme, &format!("library:{}", disk.id))
            .await
            .unwrap();
        let before_home = audit(&store, &home).await.len();
        let before_acme = audit(&store, &acme).await.len();

        let moved = snippets.move_command_stars_everywhere(home.user_id).await.unwrap();
        assert_eq!(moved, 5, "every command star of both workspaces");

        // Home: the starred favourite first in its folder, the library command in Starred, nothing twice.
        let favs = snippets.favourites(&home).await.unwrap();
        let web: Vec<Uuid> = favs
            .iter()
            .filter(|f| f.folder.as_deref() == Some("Web"))
            .map(|f| f.id)
            .collect();
        assert_eq!(web, vec![b.id, a.id]);
        let starred: Vec<&Favourite> = favs
            .iter()
            .filter(|f| f.folder.as_deref() == Some(STARRED_FOLDER))
            .collect();
        assert_eq!(starred.len(), 1);
        assert_eq!(starred[0].name, disk.name);
        assert_eq!(favs.len(), 5, "a, b, c, mine and the one added");
        assert!(favs.iter().any(|f| f.id == c.id));
        assert!(store.command_stars(&home).await.unwrap().is_empty());
        assert_eq!(stars.list(&home).await.unwrap().len(), 1, "the session's star stays");
        let entries = audit(&store, &home).await;
        let new: Vec<&AuditEntry> = entries.iter().take(entries.len() - before_home).collect();
        assert_eq!(new.len(), 2, "one add and one reorder: {new:?}");
        assert!(new.iter().all(|e| e.event == "favourite_changed"));
        assert!(new.iter().any(|e| e.action.starts_with("Added the favourite command")));

        // Acme: its own add, audited there.
        let acme_favs = snippets.favourites(&acme).await.unwrap();
        assert_eq!(acme_favs.len(), 1);
        assert_eq!(acme_favs[0].folder.as_deref(), Some(STARRED_FOLDER));
        assert_eq!(audit(&store, &acme).await.len(), before_acme + 1);
        assert!(store.command_stars(&acme).await.unwrap().is_empty());

        // Again: nothing to do, nothing audited.
        let after = audit(&store, &home).await.len();
        assert_eq!(snippets.move_command_stars_everywhere(home.user_id).await.unwrap(), 0);
        assert_eq!(audit(&store, &home).await.len(), after);
        assert_eq!(snippets.favourites(&home).await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn a_move_stopped_half_way_finishes_without_doubles_and_the_lock_waits() {
        let (store, snippets, home, _) = setup().await;
        let disk = built_in("disk.free");
        // Stopped after the add, before the star went.
        snippets.add_from_library(&home, disk.id).await.unwrap();
        store
            .insert_command_star(&home, &format!("library:{}", disk.id))
            .await
            .unwrap();
        store.read_only().set(true);
        assert!(snippets.move_command_stars(&home).await.is_err());
        assert_eq!(snippets.move_command_stars_everywhere(home.user_id).await.unwrap(), 0);
        assert_eq!(
            store.command_stars(&home).await.unwrap().len(),
            1,
            "left for a later start"
        );
        store.read_only().set(false);
        let moved = snippets.move_command_stars(&home).await.unwrap();
        assert_eq!((moved.added, moved.already, moved.deleted), (0, 1, 1));
        assert_eq!(snippets.favourites(&home).await.unwrap().len(), 1);
    }

    #[test]
    fn a_taken_name_gets_the_next_number() {
        let row = |folder: &str, name: &str| FavouriteRow {
            id: Uuid::new_v4(),
            folder: folder.into(),
            position: 0,
            name: name.into(),
            command: "x".into(),
            description: None,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let rows = vec![row("Starred", "Disk"), row("Starred", "disk (2)"), row("Web", "Free")];
        assert_eq!(free_name(&rows, "starred", "Disk"), "Disk (3)");
        assert_eq!(
            free_name(&rows, "Starred", "Free"),
            "Free",
            "another folder's name is free"
        );
        let long = "x".repeat(MAX_NAME + 5);
        assert_eq!(free_name(&[], "Starred", &long).chars().count(), MAX_NAME);
        let taken = vec![row("Starred", &"x".repeat(MAX_NAME))];
        let next = free_name(&taken, "Starred", &long);
        assert!(next.ends_with(" (2)") && next.chars().count() == MAX_NAME);
    }
}
