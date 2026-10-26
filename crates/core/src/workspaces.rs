//! FD-02 customer workspaces: one per engagement, each with its own sessions and folders, VM links, catalogue,
//! stacks, schedules, vault items, jobs and journal, audit log, alert and terminal rules, MultiExec groups,
//! dashboard layout, notifications, saved forwards, container marks, host facts and its own settings
//! ([`crate::settings::WORKSPACE_KEYS`]). Still one user: every record has carried `workspace_id` from day one, so a
//! workspace is the rows that carry its id.
//!
//! * **Shown workspace.** One workspace is shown at a time ([`Current`]). What the UI reads and changes goes to it;
//!   switching ([`crate::Core::switch_workspace`]) closes what the old one had open, so nothing of it shows or keeps
//!   running visibly in the new one.
//! * **This PC.** Settings that are the PC's ([`crate::settings::MACHINE_KEYS`]) are the same in every workspace.
//! * **VMs** are on this PC, shared by every engagement, so each belongs to one workspace at most (`vm_assignments`).
//!   Only that workspace lists it, and the command bus refuses any action on it from another. A VM no workspace has
//!   waits in the VMs page's Unassigned view until it is added to one; while the user has only one active workspace,
//!   every VM joins it by itself, as before workspaces. A deploy, clone, import or "Add existing VM" puts the new VM
//!   in the workspace that made it.
//! * **The vault** has one key (one master password, one Windows login), and each item is sealed with its workspace
//!   in its associated data, so an item can only be read in its own workspace. Secrets go only to their own
//!   workspace's sessions (the SS-04 bindings are per workspace).
//! * **The audit log** is one hash chain per workspace ([`crate::store::chain_start`]): a workspace's export and
//!   Verify read its entries alone. An entry never names another workspace: creating one is audited in the new one,
//!   switching as "left" in the old and "opened" in the new.
//! * **Schedules** of every active workspace run, whichever is shown, each audited in its own workspace.
//!
//! Workspace edits are audited and refused by the read-only lock ([`Change::Workspaces`]). Workspaces are archived,
//! never deleted: the audit log is kept for good.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::domain::{Context, WorkspaceId};
use crate::error::{CoreError, Result};
use crate::presentation::Change;
use crate::store::{new_workspace_id, NewAuditEntry, Store, WorkspaceRow};
use crate::untrusted::is_format_char;

/// FD-02: the workspace shown last (a setting of this PC), opened again at start.
pub const CURRENT_WORKSPACE_KEY: &str = "workspaces.current";

/// FD-02: the colours a workspace can have (the UI's tokens of the same names).
pub const COLORS: [&str; 8] = ["slate", "blue", "green", "amber", "red", "violet", "pink", "teal"];

/// FD-02: a workspace's name is 1 to this many characters.
pub const MAX_NAME_CHARS: usize = 60;

/// FD-02: at most this many workspaces, archived ones included.
pub const MAX_WORKSPACES: usize = 100;

/// FD-02: a workspace as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    /// One of [`COLORS`].
    pub color: String,
    pub archived: bool,
    pub archived_at: Option<String>,
    pub created_at: String,
    /// The workspace shown now.
    pub current: bool,
}

/// FD-02: a new workspace's name and colour.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceInput {
    pub name: String,
    #[serde(default)]
    pub color: Option<String>,
}

/// FD-02: the workspace shown now. Cheap to clone; clones share it. The services that work for what the UI shows
/// (the dashboard, the Terminal page's checks, the VM tabs...) read it each time; jobs and schedule runs carry their
/// own workspace.
#[derive(Clone)]
pub struct Current {
    tx: Arc<watch::Sender<Context>>,
}

impl Current {
    pub fn new(ctx: Context) -> Self {
        Self {
            tx: Arc::new(watch::Sender::new(ctx)),
        }
    }

    pub fn get(&self) -> Context {
        *self.tx.borrow()
    }

    /// Tells when another workspace is shown.
    pub fn subscribe(&self) -> watch::Receiver<Context> {
        self.tx.subscribe()
    }

    pub(crate) fn set(&self, ctx: Context) {
        self.tx.send_replace(ctx);
    }
}

/// FD-02: a workspace's name, trimmed, or why it can't be one.
pub fn clean_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CoreError::InvalidInput("A workspace needs a name.".into()));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(CoreError::InvalidInput(format!(
            "A workspace's name is at most {MAX_NAME_CHARS} characters."
        )));
    }
    if name.chars().any(|c| c.is_control() || is_format_char(c)) {
        return Err(CoreError::InvalidInput(
            "A workspace's name is one line of plain text.".into(),
        ));
    }
    Ok(name.to_owned())
}

/// FD-02: one of [`COLORS`] (any letter case), or why not.
pub fn clean_color(color: &str) -> Result<&'static str> {
    let color = color.trim();
    COLORS
        .iter()
        .find(|c| c.eq_ignore_ascii_case(color))
        .copied()
        .ok_or_else(|| CoreError::InvalidInput(format!("A workspace's colour is one of {}.", COLORS.join(", "))))
}

/// FD-02: the workspaces themselves (`Core.workspaces`). Switching is [`crate::Core::switch_workspace`], since it
/// closes what other services hold.
#[derive(Clone)]
pub struct Workspaces {
    store: Store,
    current: Current,
}

impl Workspaces {
    pub fn new(store: Store, current: Current) -> Self {
        Self { store, current }
    }

    /// The workspace shown now.
    pub fn current(&self) -> &Current {
        &self.current
    }

    fn view(&self, row: WorkspaceRow) -> Workspace {
        let current = self.current.get().workspace_id == row.id;
        Workspace {
            id: row.id,
            name: row.name,
            color: row.color,
            archived: row.archived_at.is_some(),
            archived_at: row.archived_at,
            created_at: row.created_at,
            current,
        }
    }

    /// Every workspace of the user, archived ones too: the user's first one, then by name.
    pub async fn list(&self) -> Result<Vec<Workspace>> {
        let user = self.current.get().user_id;
        Ok(self
            .store
            .list_workspaces(user)
            .await?
            .into_iter()
            .map(|row| self.view(row))
            .collect())
    }

    /// One of the user's workspaces.
    pub async fn get(&self, id: WorkspaceId) -> Result<Workspace> {
        let user = self.current.get().user_id;
        let row = self
            .store
            .workspace(user, id)
            .await?
            .ok_or(CoreError::UnknownWorkspace)?;
        Ok(self.view(row))
    }

    /// The shown workspace.
    pub async fn shown(&self) -> Result<Workspace> {
        self.get(self.current.get().workspace_id).await
    }

    /// The user's workspaces that aren't archived: whose schedules run.
    pub async fn active(&self) -> Result<Vec<Context>> {
        self.store.active_workspaces(self.current.get().user_id).await
    }

    async fn check_name_free(&self, name: &str, except: Option<WorkspaceId>) -> Result<()> {
        let user = self.current.get().user_id;
        if self.store.workspace_name_taken(user, name, except).await? {
            return Err(CoreError::InvalidInput(format!(
                "There is a workspace called '{name}' already (archived ones count)."
            )));
        }
        Ok(())
    }

    /// Makes a workspace (not shown yet). Audited in the new workspace, so no other workspace's log names it.
    pub async fn create(&self, input: WorkspaceInput) -> Result<Workspace> {
        self.store.read_only().check(Change::Workspaces)?;
        let name = clean_name(&input.name)?;
        let color = clean_color(input.color.as_deref().unwrap_or("blue"))?;
        let user = self.current.get().user_id;
        if self.store.list_workspaces(user).await?.len() >= MAX_WORKSPACES {
            return Err(CoreError::InvalidInput(format!(
                "There are {MAX_WORKSPACES} workspaces already, archived ones included."
            )));
        }
        self.check_name_free(&name, None).await?;
        let id = new_workspace_id();
        self.store.insert_workspace(user, id, &name, color).await?;
        let ctx = Context {
            workspace_id: id,
            user_id: user,
        };
        self.audit(
            &ctx,
            "workspace_created",
            &format!("Created this workspace, '{name}'"),
            None,
        )
        .await?;
        self.get(id).await
    }

    /// Renames a workspace. Audited in that workspace.
    pub async fn rename(&self, id: WorkspaceId, name: &str) -> Result<Workspace> {
        self.store.read_only().check(Change::Workspaces)?;
        let name = clean_name(name)?;
        let before = self.get(id).await?;
        if before.name == name {
            return Ok(before);
        }
        self.check_name_free(&name, Some(id)).await?;
        let user = self.current.get().user_id;
        self.store.rename_workspace(user, id, &name).await?;
        let ctx = Context {
            workspace_id: id,
            user_id: user,
        };
        let detail = format!("'{}' -> '{name}'", before.name);
        self.audit(&ctx, "workspace_changed", "Renamed this workspace", Some(&detail))
            .await?;
        self.get(id).await
    }

    /// Gives a workspace another colour. Audited in that workspace.
    pub async fn set_color(&self, id: WorkspaceId, color: &str) -> Result<Workspace> {
        self.store.read_only().check(Change::Workspaces)?;
        let color = clean_color(color)?;
        let before = self.get(id).await?;
        if before.color == color {
            return Ok(before);
        }
        let user = self.current.get().user_id;
        self.store.set_workspace_color(user, id, color).await?;
        let ctx = Context {
            workspace_id: id,
            user_id: user,
        };
        let detail = format!("{} -> {color}", before.color);
        self.audit(
            &ctx,
            "workspace_changed",
            "Changed this workspace's colour",
            Some(&detail),
        )
        .await?;
        self.get(id).await
    }

    /// Archives a workspace: it keeps its data and its log, can't be shown, and its schedules don't run until it is
    /// restored. Not the shown one (switch first), and not the last active one. Audited in that workspace.
    pub async fn archive(&self, id: WorkspaceId) -> Result<Workspace> {
        self.store.read_only().check(Change::Workspaces)?;
        let before = self.get(id).await?;
        if before.archived {
            return Ok(before);
        }
        if before.current {
            return Err(CoreError::InvalidInput(
                "This workspace is open: switch to another one before archiving it.".into(),
            ));
        }
        let user = self.current.get().user_id;
        self.store.set_workspace_archived(user, id, true).await?;
        let ctx = Context {
            workspace_id: id,
            user_id: user,
        };
        self.audit(
            &ctx,
            "workspace_archived",
            "Archived this workspace",
            Some("its data and log are kept; its schedules don't run until it is restored"),
        )
        .await?;
        self.get(id).await
    }

    /// Restores an archived workspace. Audited in that workspace.
    pub async fn restore(&self, id: WorkspaceId) -> Result<Workspace> {
        self.store.read_only().check(Change::Workspaces)?;
        let before = self.get(id).await?;
        if !before.archived {
            return Ok(before);
        }
        let user = self.current.get().user_id;
        self.store.set_workspace_archived(user, id, false).await?;
        let ctx = Context {
            workspace_id: id,
            user_id: user,
        };
        self.audit(&ctx, "workspace_restored", "Restored this workspace", None)
            .await?;
        self.get(id).await
    }

    pub(crate) async fn audit(&self, ctx: &Context, event: &str, action: &str, detail: Option<&str>) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event,
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

/// FD-02: the workspace to show at start: the one shown last, while it is the user's and not archived; else the home
/// workspace, or the first active one when the home one is archived.
pub async fn starting(store: &Store, home: &Context) -> Result<Context> {
    let user = home.user_id;
    let rows = store.list_workspaces(user).await?;
    let last = store
        .get_setting::<Option<uuid::Uuid>>(home, CURRENT_WORKSPACE_KEY)
        .await
        .ok()
        .flatten()
        .flatten();
    let active = |id: WorkspaceId| rows.iter().find(|w| w.id == id && w.archived_at.is_none());
    let chosen = last
        .and_then(|id| active(WorkspaceId(id)))
        .or_else(|| active(home.workspace_id))
        .or_else(|| rows.iter().find(|w| w.archived_at.is_none()))
        .map_or(home.workspace_id, |w| w.id);
    Ok(Context {
        workspace_id: chosen,
        user_id: user,
    })
}

/// FD-02: what switching to another workspace would close, for its confirm. A switch is refused while
/// `open_jobs` is not 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwitchPreview {
    pub to: Workspace,
    /// Jobs started from this workspace's UI that are still open (a schedule's runs go on and don't count).
    pub open_jobs: usize,
    /// Terminals open in this workspace; they close, with their tunnels, session logs and transfers.
    pub terminals: usize,
    /// MultiExec is on.
    pub multiexec: bool,
    /// Approvals waiting for an answer; they are cancelled.
    pub approvals: usize,
}

impl crate::Core {
    /// FD-02: what switching to `id` would close, and whether it is refused now.
    pub async fn switch_preview(&self, id: WorkspaceId) -> Result<SwitchPreview> {
        let to = self.workspaces.get(id).await?;
        Ok(SwitchPreview {
            to,
            open_jobs: self.jobs.open_user_jobs(self.ctx().workspace_id),
            terminals: self.terminals.open_count(),
            multiexec: self.multiexec.status().await.map(|s| s.on).unwrap_or(false),
            approvals: self.bus.pending_approvals().len(),
        })
    }

    /// FD-02: shows another workspace. Nothing of the old one may show or keep running visibly in the new one, so:
    ///
    /// * it is refused while jobs started from the old workspace's UI are open (a schedule's runs go on);
    /// * MultiExec stops, every terminal closes with its tunnels, session log and transfers (each audited in the
    ///   old workspace), and approvals still waiting are cancelled;
    /// * the dashboard's, the Containers page's and host details' kept connections close, the guest polling and the
    ///   readings in memory are dropped, an opened FD-07 file closes, and a vault password given in the last
    ///   minutes no longer covers the next step (AP-06);
    /// * the old workspace's history minutes are written and its open alerts close; the new one's alert and
    ///   terminal rules apply from now on.
    ///
    /// Audited as "left" in the old workspace and "opened" in the new one (neither names the other). Refused by the
    /// read-only lock, and for an archived workspace.
    pub async fn switch_workspace(&self, id: WorkspaceId) -> Result<Workspace> {
        self.store.read_only().check(Change::Workspaces)?;
        let old = self.ctx();
        let to = self.workspaces.get(id).await?;
        if to.archived {
            return Err(CoreError::InvalidInput(format!(
                "'{}' is archived: restore it before opening it.",
                to.name
            )));
        }
        if to.current {
            return Ok(to);
        }
        let open = self.jobs.open_user_jobs(old.workspace_id);
        if open > 0 {
            return Err(CoreError::WorkspaceBusy {
                open: match open {
                    1 => "A job is".to_owned(),
                    n => format!("{n} jobs are"),
                },
                them: if open == 1 { "it" } else { "them" },
            });
        }
        let new = Context {
            workspace_id: to.id,
            user_id: old.user_id,
        };

        // What the old workspace had open closes (each audited in it).
        if let Err(err) = self.multiexec.stop().await {
            tracing::warn!(error = %err, "MultiExec did not stop cleanly when the workspace was switched");
        }
        let terminals = self.terminals.open_count();
        self.terminals.close_all().await;
        let approvals = self
            .bus
            .cancel_approvals(&self.bus.pending_approvals(), "another workspace was opened")
            .await;
        self.containers.close_all().await;
        self.host_details.close_all().await;
        self.metrics.leave_workspace().await;
        self.transfer.closer().close();
        self.bindings.vault_locked();
        self.terminals.forget_logins();
        self.history.switch_to(new).await?;
        self.alerts.switch_to(new).await?;
        let detail = format!(
            "closed {} and cancelled {}",
            plural(terminals, "terminal", "terminals"),
            plural(approvals, "waiting approval", "waiting approvals")
        );
        self.workspaces
            .audit(&old, "workspace_left", "Switched to another workspace", Some(&detail))
            .await?;

        self.current.set(new);
        self.store
            .put_setting(&new, CURRENT_WORKSPACE_KEY, &Some(new.workspace_id.0))
            .await?;
        crate::settings::repair_workspace(&self.store, &new).await?;
        self.terminal_rules.switch_to(&new).await?;
        self.reachability.poke();
        self.workspaces
            .audit(&new, "workspace_opened", "Opened this workspace", None)
            .await?;
        tracing::info!("another workspace was opened");
        self.workspaces.get(id).await
    }
}

/// FD-02, FD-07: an import into a new workspace: the workspace made, and what was imported into it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewWorkspaceImport {
    pub workspace: Workspace,
    pub report: crate::transfer::TransferReport,
}

impl crate::Core {
    /// FD-02, FD-07: imports the opened file into a new workspace instead of the shown one: the workspace is made,
    /// then the file's items go into it as into an empty library (nothing to replace), each audited in the new
    /// workspace's log. The shown workspace doesn't change (the UI offers to open the new one).
    pub async fn import_into_new_workspace(
        &self,
        input: WorkspaceInput,
        request: crate::transfer::TransferCommit,
    ) -> Result<NewWorkspaceImport> {
        self.store.read_only().check(Change::Transfer)?;
        let made = self.workspaces.create(input).await?;
        let ctx = Context {
            workspace_id: made.id,
            user_id: self.ctx().user_id,
        };
        let report = self
            .transfer
            .commit(
                &ctx,
                request,
                &self.sessions,
                &self.vault,
                &self.known_hosts,
                &self.snippets,
            )
            .await?;
        Ok(NewWorkspaceImport {
            workspace: self.workspaces.get(made.id).await?,
            report,
        })
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    match n {
        1 => format!("1 {one}"),
        n => format!("{n} {many}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_one_trimmed_line_of_at_most_sixty_characters() {
        assert_eq!(clean_name("  Acme Corp ").unwrap(), "Acme Corp");
        assert!(clean_name("   ").is_err());
        assert!(clean_name(&"x".repeat(MAX_NAME_CHARS)).is_ok());
        assert!(clean_name(&"x".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert!(clean_name("Acme\nCorp").is_err());
        assert!(clean_name("Acme\u{202e}Corp").is_err());
    }

    #[test]
    fn colours_are_the_named_ones() {
        assert_eq!(clean_color("Blue").unwrap(), "blue");
        assert!(clean_color("#ff0000").is_err());
    }
}
