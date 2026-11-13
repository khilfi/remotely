//! SS-14 (0.8.0 G4): "Edit in the terminal": a host's file opened in a terminal editor on the host. The owner agreed on
//! 12 Nov 2026 (`docs/plan-0.8.md`, "Double-click a file"): double-clicking a file opens a new terminal tab at its
//! folder running the session's editor, else the first of `nano`, `micro`, `vim`, `vi` the host has; as root (root
//! browsing) it runs `sudoedit`, which edits a copy and writes it back as root.
//!
//! * **Which editor.** The host's editors are found once with [`EDITOR_PROBE`] (a read: `command -v` in `/bin/sh` on
//!   an exec channel of the terminal's connection) and kept with the session's facts (MO-13's store,
//!   [`crate::host_details::SpecsCollector::keep_editors`]); a quick connection keeps them while its terminal is open.
//!   The session's own choice is a setting of the workspace ([`HOST_EDITORS_KEY`], audited, refused by the read-only
//!   lock), and only names from [`HOST_EDITORS`] go on a command line.
//! * **A command of its own on the bus** ([`crate::command_bus::Command::EditorOpen`]): Low and audited; Medium on Prod
//!   or as root (one confirm), High as root on Prod. The shell rules don't rate it (an editor can run commands, so they
//!   would ask every time; the user could type the same line in their own terminal anyway). Its one target is the
//!   file ([`TargetRef::RemotePath`]); the journal keeps the spec with its path redacted. The job opens the tab: a new
//!   SSH connection to the session (the terminal's typed login password comes along, as for a split), whose channel
//!   is an exec request with a PTY ([`EditorSpec::exec_string`]). Nothing is typed into a shell.
//! * **The path reaches the editor byte for byte** whatever the login shell is (fish, csh): the exec string is
//!   `/bin/sh -c '<script>'`, and the script gets the folder and the path from `printf` of their octal escapes, as
//!   G2's copies do ([`crate::adapters::remote::printf_escaped`]). Paths are checked as
//!   [`super::file_ops::check_path`] checks them (no control or invisible formatting character), and are always
//!   absolute, so no editor reads one as an option.
//! * **As root**, `SUDO_EDITOR=<editor> sudoedit -p <marker> -- <path>`. sudo's prompt is a random marker the tab
//!   never shows ([`SudoWatch`]): at the first one the tab answers with the password root browsing gave sudo (BX-07's,
//!   which passed rule 7's checks when root browsing started on this session), once; a second one means sudo refused
//!   it, so the tab closes, the password parks and root browsing ends, as when root browsing's own channel is refused.
//!   Under NOPASSWD sudo asks nothing and gets nothing. Without a password held (root browsing asked for none) the
//!   prompt shows as `[sudo] password:` for the user to type.
//! * **The tab** is an editor tab ([`super::PaneKind::Editor`]): it never joins Type in all tabs or Compare hosts, has
//!   no Files drawer, tunnels, prompt hook or startup command, and never reconnects: when the editor exits, or the
//!   connection drops, it says so and waits to be closed. The job hands the new tab to the window
//!   ([`Terminals::take_editor_tab`]).

use std::time::Instant;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::file_ops::{check_path, last_part};
use super::files::parent;
use super::{quoted_name, Control, NewPane, PaneKindInfo, Source, TerminalHandle, Terminals};
use crate::adapters::exec_output::Scrubber;
use crate::adapters::remote::{printf_escaped, sh_quote, via_sh, EntryKind, PtySize};
use crate::domain::{Context, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;
use crate::locks;
use crate::policy::Tier;
use crate::presentation::Change;
use crate::store::NewAuditEntry;
use crate::vault::SecretString;

/// The terminal editors Remotely opens files in, by the name the host knows them by. Nothing else goes on a command
/// line.
pub const HOST_EDITORS: [&str; 9] = ["nano", "micro", "vim", "vi", "nvim", "emacs", "mcedit", "joe", "ne"];

/// Without the session's own choice, the first of these the host has (`docs/plan-0.8.md`), then any other it has.
pub const DEFAULT_ORDER: [&str; 4] = ["nano", "micro", "vim", "vi"];

/// SS-14: which of [`HOST_EDITORS`] the host has. A read, as the login user, run by `/bin/sh` whatever the login shell
/// is; `command -v` prints nothing for one it doesn't have. One name per line.
pub const EDITOR_PROBE: &str = "/bin/sh -c 'for e in nano micro vim vi nvim emacs mcedit joe ne; do \
command -v \"$e\" >/dev/null 2>&1 && printf \"%s\\n\" \"$e\"; done; exit 0'";

/// The session's own editor, per workspace: `{ "<session id>": "vim" }`.
pub const HOST_EDITORS_KEY: &str = "files.hostEditors";

/// What [`EDITOR_PROBE`] printed: the known names, in [`HOST_EDITORS`]' order, once each.
pub fn parse_editors(stdout: &str) -> Vec<String> {
    let found: Vec<&str> = stdout.lines().map(str::trim).collect();
    HOST_EDITORS
        .iter()
        .filter(|name| found.contains(name))
        .map(|name| (*name).to_owned())
        .collect()
}

/// The editor a file opens in: `chosen` (the session's, or the menu's) when the host has it, else the first of
/// [`DEFAULT_ORDER`] the host has, else any it has.
pub fn pick_editor(chosen: Option<&str>, found: &[String]) -> Result<String> {
    if let Some(chosen) = chosen {
        if !HOST_EDITORS.contains(&chosen) {
            return Err(CoreError::InvalidInput(format!(
                "'{chosen}' is not an editor Remotely opens files in: choose one of {}.",
                HOST_EDITORS.join(", ")
            )));
        }
        if found.iter().any(|f| f == chosen) {
            return Ok(chosen.to_owned());
        }
        return Err(CoreError::InvalidInput(format!(
            "The host has no {chosen}. Choose another editor for this session: {}.",
            if found.is_empty() {
                "it has none Remotely knows".to_owned()
            } else {
                found.join(", ")
            }
        )));
    }
    DEFAULT_ORDER
        .iter()
        .find(|name| found.iter().any(|f| f == *name))
        .map(|name| (*name).to_owned())
        .or_else(|| found.first().cloned())
        .ok_or(CoreError::NoHostEditor)
}

/// The words an editor runs as: emacs stays in the terminal with `-nw`.
fn editor_words(editor: &str) -> &'static str {
    match editor {
        "nano" => "nano",
        "micro" => "micro",
        "vim" => "vim",
        "vi" => "vi",
        "nvim" => "nvim",
        "emacs" => "emacs -nw",
        "mcedit" => "mcedit",
        "joe" => "joe",
        _ => "ne",
    }
}

/// SS-14: what [`crate::command_bus::Command::EditorOpen`] opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorSpec {
    /// The open terminal whose session the editor tab connects to (and, as root, whose root browsing gives sudo its
    /// password).
    pub terminal_id: Uuid,
    /// The host's file, absolute.
    pub path: String,
    /// One of [`HOST_EDITORS`].
    pub editor: String,
    /// `sudoedit` (root browsing must be on): one tier higher.
    #[serde(default)]
    pub as_root: bool,
}

impl EditorSpec {
    /// The one target: the file.
    pub fn targets(&self) -> Vec<TargetRef> {
        vec![TargetRef::RemotePath {
            terminal_id: self.terminal_id,
            session_id: None,
            step: 0,
        }]
    }

    /// The path as checked by [`check_path`], never `/`; an editor Remotely knows.
    pub fn validate(&self) -> Result<()> {
        check_path(&self.path)?;
        if self.path == "/" {
            return Err(CoreError::InvalidInput("The top folder (/) is not a file.".into()));
        }
        if !HOST_EDITORS.contains(&self.editor.as_str()) {
            return Err(CoreError::InvalidInput(format!(
                "'{}' is not an editor Remotely opens files in.",
                shown(&self.editor)
            )));
        }
        Ok(())
    }

    /// The file's folder, where the tab starts.
    pub fn folder(&self) -> String {
        parent(&self.path).unwrap_or_else(|| "/".into())
    }

    /// What runs, as the shell reads it, for the approval and the job: `cd '/etc' && exec nano '/etc/hosts'`, or as root
    /// `cd '/etc' && SUDO_EDITOR=nano exec sudoedit -- '/etc/hosts'`. It runs as [`Self::exec_string`] gives it, which
    /// passes the same folder and path byte for byte.
    pub fn command_line(&self) -> String {
        let words = editor_words(&self.editor);
        let cd = format!("cd {}", sh_quote(&self.folder()));
        if self.as_root {
            let words = if words.contains(' ') {
                format!("'{words}'")
            } else {
                words.to_owned()
            };
            format!("{cd} && SUDO_EDITOR={words} exec sudoedit -- {}", sh_quote(&self.path))
        } else {
            format!("{cd} && exec {words} {}", sh_quote(&self.path))
        }
    }

    /// The exec request's command: `/bin/sh -c '<script>'`, the script getting the folder and the path from printf's
    /// octal escapes, so no login shell (POSIX, fish, csh) parses either. `marker`: sudo's prompt as root (letters,
    /// digits and `-` only).
    pub fn exec_string(&self, marker: Option<&str>) -> String {
        let mut script = format!(
            "d=$(printf '{}'); p=$(printf '{}'); cd \"$d\" || exit 1; ",
            printf_escaped(&self.folder()),
            printf_escaped(&self.path)
        );
        let words = editor_words(&self.editor);
        match (self.as_root, marker) {
            (true, Some(marker)) => script.push_str(&format!(
                "SUDO_EDITOR=\"{words}\"; export SUDO_EDITOR; exec sudoedit -p {marker} -- \"$p\""
            )),
            (true, None) => script.push_str(&format!(
                "SUDO_EDITOR=\"{words}\"; export SUDO_EDITOR; exec sudoedit -- \"$p\""
            )),
            (false, _) => script.push_str(&format!("exec {words} \"$p\"")),
        }
        via_sh(&script)
    }

    /// For dialogs, job lists and the audit log.
    pub fn summary(&self) -> String {
        if self.as_root {
            format!(
                "Edit {} in {} on the host, as root (sudoedit)",
                shown(&self.path),
                self.editor
            )
        } else {
            format!("Edit {} in {} on the host", shown(&self.path), self.editor)
        }
    }

    /// BX-02: the spec as the journal keeps it, its path through [`redact_secrets`]; whether it changed.
    pub fn for_journal(&self) -> (EditorSpec, bool) {
        let (path, changed) = redact_secrets(&self.path);
        (EditorSpec { path, ..self.clone() }, changed)
    }
}

/// A path or name for a message: without control or formatting characters, and not too long.
fn shown(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || crate::untrusted::is_format_char(c) {
                '?'
            } else {
                c
            }
        })
        .take(300)
        .collect()
}

/// SS-14: what the job runner hands to the terminals for [`crate::command_bus::Command::EditorOpen`].
pub struct EditorRun<'a> {
    pub ctx: Context,
    pub job_id: Uuid,
    pub tier: Tier,
    pub target: &'a Target,
    pub spec: &'a EditorSpec,
}

/// SS-14: what an editor tab runs, kept on its pane.
pub(super) struct EditorLaunch {
    /// The exec request's command ([`EditorSpec::exec_string`]).
    pub(super) command: String,
    /// As root: sudo's prompt marker and what answers it.
    pub(super) sudo: Option<SudoAnswer>,
    /// The terminal whose root browsing gave the password (it ends if sudo refuses it now).
    pub(super) source: Uuid,
}

/// SS-14: sudoedit's prompt and the password for it, given once.
pub(super) struct SudoAnswer {
    pub(super) marker: String,
    pub(super) password: std::sync::Mutex<Option<SecretString>>,
}

impl Control {
    /// SS-14 (G4): an editor tab forgets sudoedit's password it has not given yet (the vault locked, or root browsing
    /// ended); a later prompt then asks the user.
    pub(super) fn forget_sudo_answer(&self) {
        if let Some(answer) = self.editor.as_ref().and_then(|e| e.sudo.as_ref()) {
            locks::lock(&answer.password).take();
        }
    }
}

/// SS-14: an editor tab's output while sudoedit may still ask: the marker comes out (the tab shows a plain prompt in its
/// place when it has no password to give), the first one is answered, and a second one means sudo refused it.
pub(super) struct SudoWatch {
    remover: Scrubber,
    seen: usize,
    answered: bool,
    /// The password given, to tell root browsing which one sudo refused.
    given: Option<SecretString>,
    /// What the tab showed since the password went, for sudo's own words when it refused it: read only until the
    /// editor starts drawing (its first escape sequence) or [`SUDO_SAYS`] bytes, so a file's text never counts.
    tail: Vec<u8>,
    listening: bool,
    refused: bool,
}

/// sudo's words when it refused the password and tries no more (`passwd_tries=1`, or a PAM that doesn't ask again).
const SUDO_GAVE_UP: &[&str] = &["incorrect password attempt"];
/// How much of what follows the password can be sudo's own words.
const SUDO_SAYS: usize = 512;

/// What the tab does after a piece of output.
pub(super) enum SudoStep {
    Nothing,
    /// Send this password, then Enter; never echoed, and scrubbed from what the tab saves.
    Answer(SecretString),
    /// sudo asked again after the password went: it refused it.
    Refused,
}

impl SudoWatch {
    pub(super) fn new(marker: &str) -> Self {
        Self {
            remover: Scrubber::remover(marker),
            seen: 0,
            answered: false,
            given: None,
            tail: Vec::new(),
            listening: false,
            refused: false,
        }
    }

    /// The password the tab gave sudoedit, if it gave one.
    pub(super) fn given(&self) -> Option<SecretString> {
        self.given.clone()
    }

    /// `bytes` as the tab shows them, and what to do.
    pub(super) fn output(&mut self, bytes: &[u8], answer: &SudoAnswer) -> (Vec<u8>, SudoStep) {
        let mut shown = Vec::with_capacity(bytes.len());
        self.remover.push(bytes, &mut shown);
        let found = self.remover.found();
        if found == self.seen {
            if self.listening && !self.refused {
                // A sudo that tries once says so and exits without asking again; the editor's screen ends the watch.
                let upto = shown.iter().position(|&b| b == 0x1b).unwrap_or(shown.len());
                let room = SUDO_SAYS.saturating_sub(self.tail.len());
                self.tail.extend_from_slice(&shown[..upto.min(room)]);
                if upto < shown.len() || self.tail.len() >= SUDO_SAYS {
                    self.listening = false;
                }
                let said = String::from_utf8_lossy(&self.tail);
                if SUDO_GAVE_UP.iter().any(|m| said.contains(m)) {
                    self.refused = true;
                    self.listening = false;
                    return (shown, SudoStep::Refused);
                }
            }
            return (shown, SudoStep::Nothing);
        }
        self.seen = found;
        if self.answered {
            self.refused = true;
            return (shown, SudoStep::Refused);
        }
        let password = locks::lock(&answer.password).take();
        match password {
            Some(password) => {
                self.answered = true;
                self.listening = true;
                self.given = Some(password.clone());
                (shown, SudoStep::Answer(password))
            }
            None => {
                // Nothing to give: sudo's question for the user, in words.
                shown.extend_from_slice(b"[sudo] password: ");
                (shown, SudoStep::Nothing)
            }
        }
    }
}

/// SS-14: the host's editors and the session's choice, for the Files drawer's menu.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostEditors {
    /// Of [`HOST_EDITORS`], those the host has.
    pub found: Vec<String>,
    /// The session's own choice; `None`: the first of [`DEFAULT_ORDER`] the host has.
    pub chosen: Option<String>,
    /// What a double-click opens now; `None`: the host has none.
    pub uses: Option<String>,
    /// The saved session the choice belongs to; `None` for a quick connection, which has no choice.
    pub session_id: Option<Uuid>,
}

/// How long the window may take to pick up a tab the job opened before it closes again.
const TAB_KEPT: std::time::Duration = std::time::Duration::from_secs(120);

/// SS-14: a tab the job opened, until the window takes it.
pub(super) struct Handoff {
    at: Instant,
    workspace: crate::domain::WorkspaceId,
    tab: std::result::Result<TerminalHandle, String>,
}

impl Terminals {
    /// SS-14: the editors `id`'s host has (found once and kept with the session's facts) and the session's choice.
    pub async fn host_editors(&self, ctx: &Context, id: Uuid) -> Result<HostEditors> {
        let control = self.control_here(ctx, id)?;
        let session_id = control.session_id();
        let found = self.found_editors(ctx, &control).await?;
        let chosen = match session_id {
            Some(session_id) => self.chosen_editor(ctx, session_id).await?,
            None => None,
        };
        // A choice the host doesn't have any more falls back to the default order.
        let uses = pick_editor(chosen.as_deref().filter(|c| found.iter().any(|f| f == c)), &found).ok();
        Ok(HostEditors {
            found,
            chosen,
            uses,
            session_id,
        })
    }

    /// The terminal, open and in the shown workspace.
    pub(super) fn control_here(&self, ctx: &Context, id: Uuid) -> Result<std::sync::Arc<Control>> {
        let control = self
            .control(id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {id} has closed")))?;
        if control.workspace != ctx.workspace_id {
            return Err(CoreError::NotInWorkspace(format!("Terminal {id}")));
        }
        Ok(control)
    }

    async fn chosen_editor(&self, ctx: &Context, session_id: Uuid) -> Result<Option<String>> {
        let choices = self
            .inner
            .store
            .get_setting::<std::collections::BTreeMap<String, String>>(ctx, HOST_EDITORS_KEY)
            .await?
            .unwrap_or_default();
        Ok(choices
            .get(&session_id.to_string())
            .filter(|e| HOST_EDITORS.contains(&e.as_str()))
            .cloned())
    }

    /// The host's editors: kept with the session's facts (or, for a quick connection, with its terminal), else read
    /// now on the terminal's exec channel and kept.
    async fn found_editors(&self, ctx: &Context, control: &Control) -> Result<Vec<String>> {
        if let Some(found) = locks::lock(&control.editors).clone() {
            return Ok(found);
        }
        let specs = self.inner.specs.get().cloned();
        if let (Some(session_id), Some(specs)) = (control.session_id(), &specs) {
            if let Some(found) = specs.stored_editors(ctx, session_id).await? {
                *locks::lock(&control.editors) = Some(found.clone());
                return Ok(found);
            }
        }
        let commands = locks::lock(&control.commands).clone().ok_or_else(|| {
            CoreError::InvalidInput(format!(
                "{} is not connected, so its host's editors can't be looked for. Reconnect it first.",
                quoted_name(control)
            ))
        })?;
        let probe = tokio::time::timeout(std::time::Duration::from_secs(15), commands.run(EDITOR_PROBE, 4096))
            .await
            .map_err(|_| CoreError::Timeout {
                command: "looking for the host's editors".into(),
                seconds: 15,
            })??;
        let found = parse_editors(&probe.output.stdout);
        *locks::lock(&control.editors) = Some(found.clone());
        if let (Some(session_id), Some(specs)) = (control.session_id(), &specs) {
            specs.keep_editors(ctx, session_id, &found).await?;
        }
        Ok(found)
    }

    /// SS-14: the job runner's half of [`crate::command_bus::Command::EditorOpen`]: opens the editor tab (a new
    /// connection to the terminal's session) and keeps it for the window ([`Self::take_editor_tab`]).
    pub(crate) async fn run_open_editor(&self, run: EditorRun<'_>) -> Result<String> {
        let opened = self.open_editor_tab(&run).await;
        let mut tabs = locks::lock(&self.inner.editor_tabs);
        // A tab nobody took in time closes.
        let stale: Vec<Uuid> = tabs
            .iter()
            .filter(|(_, h)| h.at.elapsed() > TAB_KEPT)
            .map(|(id, _)| *id)
            .collect();
        for job in stale {
            if let Some(Handoff { tab: Ok(handle), .. }) = tabs.remove(&job) {
                self.close_later(handle.id);
            }
        }
        let (tab, result) = match opened {
            Ok(handle) => (Ok(handle), Ok("opened in a new terminal tab".to_owned())),
            // The window learns why from the handoff too.
            Err(err) => (Err(err.to_string()), Err(err)),
        };
        tabs.insert(
            run.job_id,
            Handoff {
                at: Instant::now(),
                workspace: run.ctx.workspace_id,
                tab,
            },
        );
        drop(tabs);
        // A tab the window never takes (the page reloaded while the job ran) closes by itself.
        let this = self.clone();
        let job = run.job_id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                tokio::time::sleep(TAB_KEPT).await;
                let stale = locks::lock(&this.inner.editor_tabs).remove(&job);
                if let Some(Handoff { tab: Ok(handle), .. }) = stale {
                    this.close(handle.id).await;
                }
            });
        }
        result
    }

    fn close_later(&self, id: Uuid) {
        let this = self.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move { this.close(id).await });
        }
    }

    async fn open_editor_tab(&self, run: &EditorRun<'_>) -> Result<TerminalHandle> {
        run.spec.validate()?;
        let source = self.control_here(&run.ctx, run.spec.terminal_id)?;
        if source.kind != super::PaneKind::Ssh {
            return Err(CoreError::InvalidInput(
                "Files open in an editor from an SSH terminal only.".into(),
            ));
        }
        let sudo = if run.spec.as_root {
            let held = locks::lock(&source.root)
                .as_ref()
                .map(|r| (r.password.clone(), r.place.clone()))
                .ok_or_else(|| {
                    CoreError::InvalidInput(format!(
                        "{} is not browsing as root (any more), so nothing was opened as root. Browse as root again.",
                        quoted_name(&source)
                    ))
                })?;
            let (password, given_to) = held;
            // Rule 7: the password goes only where root browsing gave it; the tab connects to the session as it is
            // saved now, which may have changed since.
            let (place, _) = self.place_of(&run.ctx, &source, None).await?;
            if place != given_to {
                return Err(CoreError::InvalidInput(format!(
                    "{} was changed since root browsing started, so sudo's password doesn't go to it. Browse as root \
                     again.",
                    quoted_name(&source)
                )));
            }
            Some(SudoAnswer {
                marker: format!("remotely-sudo-{}", Uuid::new_v4().simple()),
                password: std::sync::Mutex::new(password),
            })
        } else {
            None
        };
        let command = run.spec.exec_string(sudo.as_ref().map(|s| s.marker.as_str()));
        let file = shown(last_part(&run.spec.path));
        let how = if run.spec.as_root {
            format!("in {} as root (sudoedit)", run.spec.editor)
        } else {
            format!("in {}", run.spec.editor)
        };
        let address = match &source.source {
            Source::Saved(session_id) => self
                .inner
                .store
                .session_spec(&run.ctx, *session_id)
                .await?
                .map(|s| s.address())
                .unwrap_or_else(|| source.name.clone()),
            Source::Unsaved(spec) => spec.address(),
        };
        let pane = NewPane {
            source: source.source.clone(),
            target: source.target.clone(),
            name: source.name.clone(),
            // A password typed for the terminal's login logs this tab in too, as for a split.
            remembered: locks::lock(&source.remembered).clone(),
            jump_passwords: locks::lock(&source.jump_passwords).clone(),
            action: format!("Opened '{file}' {how} on {}", quoted_name(&source)),
            detail: format!("{address}; {}; job {}", shown(&run.spec.path), run.job_id),
            container: None,
            kind: PaneKindInfo {
                kind: super::PaneKind::Editor,
                carrier: None,
                serial_port: None,
            },
            editor: Some(EditorLaunch {
                command,
                sudo,
                source: source.id,
            }),
        };
        self.start(&run.ctx, pane, PtySize { cols: 80, rows: 24 }).await
    }

    /// SS-14: the tab the editor job opened, for the window, once: `job_id`'s job must have ended. An error says why
    /// it didn't open.
    pub fn take_editor_tab(&self, ctx: &Context, job_id: Uuid) -> Result<TerminalHandle> {
        let mut tabs = locks::lock(&self.inner.editor_tabs);
        match tabs.get(&job_id) {
            Some(handoff) if handoff.workspace != ctx.workspace_id => {
                Err(CoreError::NotInWorkspace(format!("The editor of job {job_id}")))
            }
            Some(_) => match tabs.remove(&job_id).map(|h| h.tab) {
                Some(Ok(handle)) => Ok(handle),
                Some(Err(why)) => Err(CoreError::InvalidInput(why)),
                None => Err(CoreError::UnknownTarget(format!("the editor of job {job_id}"))),
            },
            None => Err(CoreError::UnknownTarget(format!(
                "the editor of job {job_id}: it did not open, or its tab was taken already"
            ))),
        }
    }

    /// SS-14: sudoedit in an editor tab refused the password root browsing gave it: it parks, and root browsing on
    /// `source` ends, as when its own channel is refused.
    pub(super) fn editor_sudo_refused(&self, source: Uuid, given: Option<SecretString>) {
        if let Some(control) = self.control(source) {
            self.root_refused(&control, given.as_ref());
        }
    }
}

impl super::files::FileTransfers {
    /// SS-14: opens a host's file in a terminal editor on the host ([`crate::command_bus::Command::EditorOpen`]):
    /// `editor` the menu's choice, else the session's, else the first the host has. The file is looked at first: a
    /// folder or something that isn't a file is refused, and as root a link (sudoedit edits no links).
    pub async fn open_in_editor(
        &self,
        terminal_id: Uuid,
        path: String,
        as_root: bool,
        editor: Option<String>,
    ) -> Result<crate::command_bus::SubmitOutcome> {
        let ctx = self.workspace.get();
        check_path(&path)?;
        let (_, files) = self.terminals.files_for(terminal_id, as_root)?;
        let entry = files
            .lstat(&path)
            .await?
            .ok_or_else(|| CoreError::RemoteNotFound { path: path.clone() })?;
        let target = if entry.link {
            if as_root {
                return Err(CoreError::InvalidInput(format!(
                    "{} is a link, and sudoedit edits no links: open the file it points to.",
                    shown(&path)
                )));
            }
            files.stat(&path).await?
        } else {
            Some(entry)
        };
        if target.as_ref().map(|e| e.kind) != Some(EntryKind::File) {
            return Err(CoreError::InvalidInput(format!(
                "{} is not a file, so it can't be edited.",
                shown(&path)
            )));
        }
        let editors = self.terminals.host_editors(&ctx, terminal_id).await?;
        let editor = match editor {
            Some(asked) => pick_editor(Some(&asked), &editors.found)?,
            None => editors.uses.ok_or(CoreError::NoHostEditor)?,
        };
        let spec = EditorSpec {
            terminal_id,
            path,
            editor,
            as_root,
        };
        spec.validate()?;
        let command = crate::command_bus::Command::EditorOpen {
            targets: spec.targets(),
            spec: Box::new(spec),
        };
        self.bus.submit(&ctx, command).await
    }

    /// SS-14: the session's own editor for "Edit in the terminal" (`None`: the first of [`DEFAULT_ORDER`] the host
    /// has). A setting of the workspace: audited, refused by the read-only lock.
    pub async fn set_host_editor(&self, session_id: Uuid, editor: Option<String>) -> Result<()> {
        let ctx = self.workspace.get();
        let store = &self.terminals.inner.store;
        store.read_only().check(Change::Settings)?;
        if let Some(editor) = &editor {
            if !HOST_EDITORS.contains(&editor.as_str()) {
                return Err(CoreError::InvalidInput(format!(
                    "'{}' is not an editor Remotely opens files in: choose one of {}.",
                    shown(editor),
                    HOST_EDITORS.join(", ")
                )));
            }
        }
        let session = store
            .session_spec(&ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("session {session_id}")))?;
        let mut choices = store
            .get_setting::<std::collections::BTreeMap<String, String>>(&ctx, HOST_EDITORS_KEY)
            .await?
            .unwrap_or_default();
        let key = session_id.to_string();
        let before = choices.get(&key).cloned();
        if before == editor {
            return Ok(());
        }
        match &editor {
            Some(editor) => choices.insert(key, editor.clone()),
            None => choices.remove(&key),
        };
        store.put_setting(&ctx, HOST_EDITORS_KEY, &choices).await?;
        let (_, environment, protected) = store.find_session_target(&ctx, session_id).await?.unwrap_or((
            session.name.clone(),
            session.environment,
            false,
        ));
        let target = Target {
            target: TargetRef::Session { session_id },
            name: session.name.clone(),
            environment,
            protected,
        };
        store
            .append_audit(
                &ctx,
                NewAuditEntry {
                    event: "setting_changed",
                    action: &format!("Set the editor files open in on '{}'", session.name),
                    tier: None,
                    job_id: None,
                    targets: std::slice::from_ref(&target),
                    approval: None,
                    result: None,
                    detail: Some(&format!(
                        "{} (was {})",
                        editor
                            .as_deref()
                            .unwrap_or("the first of nano, micro, vim, vi the host has"),
                        before.as_deref().unwrap_or("the first the host has")
                    )),
                },
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(path: &str, editor: &str, as_root: bool) -> EditorSpec {
        EditorSpec {
            terminal_id: Uuid::nil(),
            path: path.into(),
            editor: editor.into(),
            as_root,
        }
    }

    #[test]
    fn the_probe_names_known_editors_only_in_their_order() {
        assert_eq!(parse_editors("vi\nnano\n"), vec!["nano", "vi"]);
        assert_eq!(
            parse_editors("vim\nevil; rm -rf /\n/usr/bin/nano\n  micro  \n"),
            vec!["micro", "vim"]
        );
        assert!(parse_editors("").is_empty());
    }

    #[test]
    fn the_editor_is_the_choice_else_the_default_order() {
        let found = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        assert_eq!(pick_editor(None, &found(&["vi", "vim", "nano"])).unwrap(), "nano");
        assert_eq!(pick_editor(None, &found(&["vi", "vim"])).unwrap(), "vim");
        assert_eq!(pick_editor(None, &found(&["emacs"])).unwrap(), "emacs");
        assert_eq!(pick_editor(Some("vi"), &found(&["vi", "nano"])).unwrap(), "vi");
        assert!(matches!(pick_editor(None, &[]), Err(CoreError::NoHostEditor)));
        let missing = pick_editor(Some("micro"), &found(&["vi"])).unwrap_err().to_string();
        assert!(missing.contains("no micro") && missing.contains("vi"), "{missing}");
        assert!(
            pick_editor(Some("bash"), &found(&["bash"])).is_err(),
            "never a name it doesn't know"
        );
    }

    #[test]
    fn paths_are_checked_and_editors_known() {
        assert!(spec("/etc/hosts", "nano", false).validate().is_ok());
        for bad in [
            "/",
            "etc/hosts",
            "/etc/../shadow",
            "/srv/a\nb",
            "/srv/invoice\u{202E}fdp.exe",
            "/srv//x",
        ] {
            assert!(spec(bad, "nano", false).validate().is_err(), "{bad:?}");
        }
        assert!(spec("/etc/hosts", "sh -c id", false).validate().is_err());
    }

    #[test]
    fn the_command_line_says_what_runs_and_the_exec_string_passes_paths_byte_for_byte() {
        let s = spec("/srv/it's here/notes.txt", "vim", false);
        assert_eq!(
            s.command_line(),
            "cd '/srv/it'\\''s here' && exec vim '/srv/it'\\''s here/notes.txt'"
        );
        let run = s.exec_string(None);
        assert!(run.starts_with("/bin/sh -c '"), "{run}");
        // The folder and the path only as octal escapes: no quote of them reaches any shell.
        assert!(run.contains(r"/srv/it\047s\040here/notes.txt"), "{run}");
        assert!(!run.contains("it's"), "{run}");
        assert!(run.ends_with("exec vim \"$p\"'"), "{run}");
        // A path that would end the quotes early in fish or csh, or run a command, stays a name.
        let hostile = spec("/srv/x\\'; touch /tmp/p; #", "nano", false).exec_string(None);
        assert!(!hostile.contains("touch /tmp/p"), "{hostile}");
        assert!(
            hostile.contains(r"x\134\047\073\040touch\040/tmp/p\073\040\043"),
            "{hostile}"
        );

        let root = spec("/etc/nginx/nginx.conf", "emacs", true);
        assert_eq!(
            root.command_line(),
            "cd '/etc/nginx' && SUDO_EDITOR='emacs -nw' exec sudoedit -- '/etc/nginx/nginx.conf'"
        );
        let run = root.exec_string(Some("remotely-sudo-abc"));
        assert!(
            run.contains("SUDO_EDITOR=\"emacs -nw\"; export SUDO_EDITOR; exec sudoedit -p remotely-sudo-abc -- \"$p\""),
            "{run}"
        );
        assert_eq!(
            root.summary(),
            "Edit /etc/nginx/nginx.conf in emacs on the host, as root (sudoedit)"
        );
    }

    #[test]
    fn the_journal_keeps_the_path_redacted() {
        let (kept, changed) = spec("/srv/password=hunter2.txt", "nano", false).for_journal();
        assert!(changed && !kept.path.contains("hunter2"), "{}", kept.path);
        let (same, unchanged) = spec("/etc/hosts", "nano", false).for_journal();
        assert!(!unchanged);
        assert_eq!(same.path, "/etc/hosts");
    }

    #[test]
    fn sudo_s_marker_is_answered_once_and_a_second_one_is_a_refusal() {
        let answer = SudoAnswer {
            marker: "remotely-sudo-abc".into(),
            password: std::sync::Mutex::new(Some(SecretString::new("pw-secret"))),
        };
        let mut watch = SudoWatch::new(&answer.marker);
        // The marker split across reads, after sudo's lecture.
        let (shown, step) = watch.output(b"We trust you...\r\nremotely-su", &answer);
        assert!(matches!(step, SudoStep::Nothing));
        let (more, step) = watch.output(b"do-abc", &answer);
        let all = [shown, more].concat();
        assert!(!String::from_utf8_lossy(&all).contains("remotely-sudo"), "never shown");
        let SudoStep::Answer(password) = step else {
            panic!("the first prompt is answered");
        };
        assert_eq!(password.expose(), "pw-secret");
        assert!(locks::lock(&answer.password).is_none(), "given once");
        let (_, step) = watch.output(b"\r\nSorry, try again.\r\nremotely-sudo-abc", &answer);
        assert!(matches!(step, SudoStep::Refused));

        // No password held: sudo's question shows in words for the user.
        let none = SudoAnswer {
            marker: "remotely-sudo-xyz".into(),
            password: std::sync::Mutex::new(None),
        };
        let mut watch = SudoWatch::new(&none.marker);
        let (shown, step) = watch.output(b"remotely-sudo-xyz", &none);
        assert!(matches!(step, SudoStep::Nothing));
        assert_eq!(shown, b"[sudo] password: ");
    }

    #[test]
    fn a_sudo_that_tries_once_and_gives_up_is_a_refusal_too() {
        let answer = SudoAnswer {
            marker: "remotely-sudo-one".into(),
            password: std::sync::Mutex::new(Some(SecretString::new("pw-wrong"))),
        };
        let mut watch = SudoWatch::new(&answer.marker);
        let (_, step) = watch.output(b"remotely-sudo-one", &answer);
        assert!(matches!(step, SudoStep::Answer(_)));
        assert_eq!(
            watch.given().unwrap().expose(),
            "pw-wrong",
            "kept to tell which one was refused"
        );
        // passwd_tries=1: sudo says so (split across reads) and exits without asking again.
        let (_, step) = watch.output(b"\r\nsudo: 1 incorrect pass", &answer);
        assert!(matches!(step, SudoStep::Nothing));
        let (_, step) = watch.output(b"word attempt\r\n", &answer);
        assert!(matches!(step, SudoStep::Refused));
        // Said once.
        let (_, step) = watch.output(b"more output", &answer);
        assert!(matches!(step, SudoStep::Nothing));

        // Once the editor draws (an escape sequence), a file's text that says the same is just text.
        let shown_file = SudoAnswer {
            marker: "remotely-sudo-log".into(),
            password: std::sync::Mutex::new(Some(SecretString::new("pw"))),
        };
        let mut watch = SudoWatch::new(&shown_file.marker);
        let (_, step) = watch.output(b"remotely-sudo-log", &shown_file);
        assert!(matches!(step, SudoStep::Answer(_)));
        let (_, step) = watch.output(
            b"\r\n\x1b[?1049h\x1b[H auth.log: 3 incorrect password attempts",
            &shown_file,
        );
        assert!(matches!(step, SudoStep::Nothing));

        // Before the password went, the same words in a file's text are just text.
        let fresh = SudoAnswer {
            marker: "remotely-sudo-two".into(),
            password: std::sync::Mutex::new(Some(SecretString::new("pw"))),
        };
        let mut watch = SudoWatch::new(&fresh.marker);
        let (_, step) = watch.output(b"1 incorrect password attempt", &fresh);
        assert!(matches!(step, SudoStep::Nothing));
    }
}
