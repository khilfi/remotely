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

pub mod library;
pub mod variables;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use self::library::{LibraryGroup, LIBRARY};
use self::variables::Variable;
use crate::domain::Context;
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

/// A built-in command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryEntry {
    pub id: &'static str,
    pub group: LibraryGroup,
    pub group_label: &'static str,
    pub name: &'static str,
    pub command: &'static str,
    pub description: &'static str,
    pub variables: Vec<Variable>,
    pub risk: CommandRisk,
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

    /// Audited.
    pub async fn delete(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.store.read_only().check(Change::Favourites)?;
        let row = self.row(ctx, id).await?;
        self.store.delete_favourite(ctx, id).await?;
        self.audit(
            ctx,
            &format!("Deleted the favourite command '{}'", row.name),
            &format!("from {}", place(&row.folder)),
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

    /// The built-in commands, each with what the policy engine makes of it now.
    pub fn library(&self) -> Vec<LibraryEntry> {
        LIBRARY
            .iter()
            .map(|entry| LibraryEntry {
                id: entry.id,
                group: entry.group,
                group_label: entry.group.label(),
                name: entry.name,
                command: entry.command,
                description: entry.description,
                variables: variables::variables(entry.command),
                risk: self.classify(entry.command),
            })
            .collect()
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
}
