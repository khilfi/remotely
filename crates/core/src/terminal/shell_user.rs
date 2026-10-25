//! QL-09: which user the "Files here" drawer's transfers run as, and which user the shell runs as.
//!
//! * Transfers (SFTP) always run as the SSH login user, never with sudo
//!   ([`crate::adapters::remote::RemoteFiles::user`]). The drawer says so: "Transfers as alice".
//! * The prompt hook ([`super::folder`]) reports its shell's user next to the folder at every prompt.
//!   That is the login user unless the server maps logins oddly; when it is someone else, the drawer
//!   shows both.
//! * `su`, `sudo -i`, `sudo su bob`, `bash` or `ssh` start another shell, which has no hook: its prompts
//!   come without a report. So after Enter, a quiet line that looks like a shell prompt with no report
//!   since means the hook's shell is no longer the one at the prompt ([`UserInfo::stopped`]). The
//!   drawer then says the shell may have switched user and that it shows the login user's view. The
//!   next report (the user left that shell) clears it.
//! * Many prompts name their user (`alice@web01:~$`, `[root@web01 ~]#`). Where the hook can't tell
//!   (it stopped reporting, or the shell has no hook at all), that name is shown as what the prompt
//!   says, never as a fact.
//!
//! Only the cursor's line is looked at, as [`super::activity`] does; nothing is kept or logged.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Serialize;

use super::activity::is_shell_prompt;

/// Output must have paused this long at a prompt before it counts: long enough that a command's last
/// line is not taken for a prompt while the real one is on its way.
pub const USER_QUIET: Duration = Duration::from_millis(800);

/// `alice@web01:~$ `, `[root@web01 ~]# `, `(venv) bob@db01:/srv$ `: the user a prompt names.
// A constant pattern, compiled by the tests: `expect` cannot fire on input here.
#[allow(clippy::expect_used)]
static PROMPT_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\([^)]{0,40}\)\s*)?\[?([A-Za-z_][A-Za-z0-9._-]{0,31}\$?)@[A-Za-z0-9][A-Za-z0-9._-]{0,62}[: \]~]")
        .expect("valid prompt user regex")
});

/// QL-09: where the shell's user was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum UserSource {
    /// Reported by Remotely's prompt hook in that shell.
    Hook,
    /// Named by the shell's prompt (`bob@web01:~$`): what the prompt says, not a fact.
    Prompt,
}

/// QL-09: the shell's user, when it is not the login user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellUser {
    pub username: String,
    pub seen_in: UserSource,
}

/// QL-09: who transfers run as, and who the shell runs as, as far as known. The user fields are named
/// `username` so presentation mode (FD-03) learns them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    /// The SSH login user: every transfer runs as this user. `None` until connected.
    pub username: Option<String>,
    /// The shell's user, when it is known to be someone else.
    pub shell: Option<ShellUser>,
    /// The prompt hook's shell stopped reporting after a command: another shell or program is at the
    /// prompt (`su`, `sudo -i`, `bash`, `ssh`), and the drawer can't follow it.
    pub stopped: bool,
}

impl UserInfo {
    pub fn connected(login: &str) -> Self {
        Self {
            username: Some(login.to_owned()),
            ..Self::default()
        }
    }
}

/// QL-09: one connection's watch over who the shell runs as (see the module comment).
#[derive(Debug)]
pub struct UserWatch {
    info: UserInfo,
    /// The hook has reported on this connection.
    hooked: bool,
    /// Enter was pressed since the last report.
    awaiting: bool,
    /// When output last came, until its pause has been looked at.
    pending: Option<Instant>,
}

impl UserWatch {
    pub fn new(login: &str) -> Self {
        Self {
            info: UserInfo::connected(login),
            hooked: false,
            awaiting: false,
            pending: None,
        }
    }

    pub fn info(&self) -> &UserInfo {
        &self.info
    }

    /// Keys sent to the shell (typed, MultiExec, the startup command, a password typed for the user).
    pub fn input(&mut self, bytes: &[u8]) {
        if bytes.iter().any(|b| matches!(b, b'\r' | b'\n')) {
            self.awaiting = true;
        }
    }

    /// The shell printed something.
    pub fn output(&mut self, now: Instant) {
        self.pending = Some(now);
    }

    /// The prompt hook reported its shell's user. True when what the drawer shows changed.
    pub fn report(&mut self, user: &str) -> bool {
        let before = self.info.clone();
        self.hooked = true;
        self.awaiting = false;
        self.info.stopped = false;
        self.info.shell = self.other(user, UserSource::Hook);
        self.info != before
    }

    /// When [`UserWatch::tick`] should next be called, if at all.
    pub fn deadline(&self) -> Option<Instant> {
        self.pending.map(|at| at + USER_QUIET)
    }

    /// Time passed. `line` is the cursor's line and `alternate` whether a full-screen program is open.
    /// True when what the drawer shows changed.
    pub fn tick(&mut self, now: Instant, line: &str, alternate: bool) -> bool {
        let Some(deadline) = self.deadline() else {
            return false;
        };
        if now < deadline {
            return false;
        }
        self.pending = None;
        if alternate || !looks_like_prompt(line) {
            return false;
        }
        let before = self.info.clone();
        if self.hooked && self.awaiting {
            self.info.stopped = true;
        }
        if !self.hooked || self.info.stopped {
            self.info.shell = prompt_user(line).and_then(|user| self.other(&user, UserSource::Prompt));
        }
        self.info != before
    }

    /// `user` as the shell's user, unless it is the login user (letter case aside: directory logins
    /// often ignore it).
    fn other(&self, user: &str, seen_in: UserSource) -> Option<ShellUser> {
        let same = self
            .info
            .username
            .as_deref()
            .is_some_and(|login| login.eq_ignore_ascii_case(user));
        (!same).then(|| ShellUser {
            username: user.to_owned(),
            seen_in,
        })
    }
}

/// A shell waiting for a command; not bash's `> ` for a line that goes on.
pub(super) fn looks_like_prompt(line: &str) -> bool {
    line.trim() != ">" && is_shell_prompt(line)
}

/// The user a prompt line names, if it does.
pub fn prompt_user(line: &str) -> Option<String> {
    PROMPT_USER
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn prompts_name_their_user_in_the_usual_forms() {
        assert_eq!(prompt_user("alice@web01:~$ ").as_deref(), Some("alice"));
        assert_eq!(prompt_user("root@web01:/home/alice# ").as_deref(), Some("root"));
        assert_eq!(prompt_user("[root@web01 ~]# ").as_deref(), Some("root"));
        assert_eq!(prompt_user("(venv) bob@db01:/srv$ ").as_deref(), Some("bob"));
        assert_eq!(prompt_user("bob@db01 ~ % ").as_deref(), Some("bob"));
        assert_eq!(
            prompt_user("svc_backup@web01.example.com:~$ ").as_deref(),
            Some("svc_backup")
        );
        for none in [
            "$ ",
            "# ",
            "web01% ",
            "PS C:\\> ",
            "└─$ ",
            "mail me at @web01$ ",
            ">>> ",
        ] {
            assert_eq!(prompt_user(none), None, "{none}");
        }
    }

    /// The hook reports at each prompt; `su bob` starts a shell that doesn't.
    #[test]
    fn a_shell_that_stops_reporting_after_a_command_has_switched() {
        let t0 = Instant::now();
        let mut watch = UserWatch::new("alice");
        watch.output(t0);
        assert!(!watch.report("alice"));
        assert_eq!(watch.info(), &UserInfo::connected("alice"));
        assert!(!watch.tick(t0 + USER_QUIET, "$ ", false), "a prompt with a report");

        // A command, and its prompt with a report: nothing changes.
        watch.input(b"ls\r");
        watch.output(t0 + 1000 * MS);
        watch.report("alice");
        assert!(!watch.tick(t0 + 2000 * MS, "$ ", false));

        // `su bob`: a password prompt first (no prompt), then bob's shell, with no report.
        watch.input(b"su bob\r");
        watch.output(t0 + 3000 * MS);
        assert!(!watch.tick(t0 + 4000 * MS, "Password: ", false));
        watch.input(b"\r");
        watch.output(t0 + 5000 * MS);
        assert!(
            !watch.tick(t0 + 5500 * MS, "bob@web01:/home/alice$ ", false),
            "not quiet yet"
        );
        assert!(watch.tick(t0 + 5000 * MS + USER_QUIET, "bob@web01:/home/alice$ ", false));
        let info = watch.info().clone();
        assert!(info.stopped);
        assert_eq!(
            info.shell,
            Some(ShellUser {
                username: "bob".into(),
                seen_in: UserSource::Prompt
            })
        );

        // Back in alice's shell (`exit`): its prompt reports again.
        watch.input(b"exit\r");
        watch.output(t0 + 7000 * MS);
        assert!(watch.report("alice"));
        assert_eq!(watch.info(), &UserInfo::connected("alice"));
    }

    #[test]
    fn a_new_shell_whose_prompt_names_nobody_is_still_noticed() {
        let t0 = Instant::now();
        let mut watch = UserWatch::new("alice");
        watch.report("alice");
        watch.input(b"bash\r");
        watch.output(t0);
        assert!(watch.tick(t0 + USER_QUIET, "$ ", false));
        assert!(watch.info().stopped);
        assert_eq!(watch.info().shell, None, "the prompt says nothing about the user");
    }

    #[test]
    fn running_commands_full_screen_programs_and_continued_lines_are_no_switch() {
        let t0 = Instant::now();
        let mut watch = UserWatch::new("alice");
        watch.report("alice");
        watch.input(b"tail -f app.log\r");
        watch.output(t0);
        assert!(!watch.tick(t0 + USER_QUIET, "2026-10-21 10:00:00 request served", false));
        watch.output(t0 + 2000 * MS);
        assert!(!watch.tick(t0 + 3000 * MS, "alice@web01:~$ ", true), "vim, less, top");
        watch.output(t0 + 4000 * MS);
        assert!(!watch.tick(t0 + 5000 * MS, "> ", false), "for i in 1 2; do");
        assert!(!watch.info().stopped);
        // Nothing to look at without output.
        assert_eq!(watch.deadline(), None);
        assert!(!watch.tick(t0 + 9000 * MS, "bob@web01:~$ ", false));
    }

    #[test]
    fn without_the_hook_the_prompt_is_all_there_is() {
        let t0 = Instant::now();
        let mut watch = UserWatch::new("alice");
        watch.output(t0);
        assert!(!watch.tick(t0 + USER_QUIET, "alice@web01:~$ ", false));
        watch.input(b"sudo -i\r");
        watch.output(t0 + 1000 * MS);
        assert!(watch.tick(t0 + 2000 * MS, "[root@web01 ~]# ", false));
        assert_eq!(
            watch.info().shell,
            Some(ShellUser {
                username: "root".into(),
                seen_in: UserSource::Prompt
            })
        );
        assert!(!watch.info().stopped, "only a hook can stop reporting");
        watch.input(b"exit\r");
        watch.output(t0 + 3000 * MS);
        assert!(
            watch.tick(t0 + 4000 * MS, "ALICE@web01:~$ ", false),
            "letter case aside"
        );
        assert_eq!(watch.info().shell, None);
    }

    #[test]
    fn a_hook_that_reports_another_user_says_so() {
        let mut watch = UserWatch::new("alice");
        assert!(watch.report("alice.admin"));
        assert_eq!(
            watch.info().shell,
            Some(ShellUser {
                username: "alice.admin".into(),
                seen_in: UserSource::Hook
            })
        );
        let json = serde_json::to_value(watch.info()).unwrap();
        assert_eq!(json["username"], "alice");
        assert_eq!(json["shell"]["username"], "alice.admin");
        assert_eq!(json["shell"]["seenIn"], "hook");
        assert_eq!(json["stopped"], false);
    }
}
