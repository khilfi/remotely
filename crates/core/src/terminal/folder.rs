//! SS-08: the folder a terminal's shell is in, for the "Files here" drawer and uploads.
//!
//! * OSC 7 (`ESC ] 7 ; file://host/path`, ended by BEL or `ESC \`) is how shells tell a terminal their
//!   folder (VTE, iTerm2, Windows Terminal read it too). [`FolderWatch`] picks it out of the output.
//!   The sequence prints nothing in any terminal, and the line follower and the session log drop it.
//! * bash and zsh ([`PromptShell`], from the probe beside each new shell) get a prompt hook typed into
//!   them once their first prompt shows ([`PromptHook`]): a function that prints OSC 7 before each
//!   prompt (bash's `PROMPT_COMMAND`, zsh's `precmd`), keeping `$?` for the prompt. The line starts with
//!   a space, so `ignorespace` keeps it out of the history, and in bash it deletes itself from the
//!   history anyway.
//! * The hook stays invisible: from the moment it is typed, the shell's output (the echo of the line)
//!   is held back until a marker the line prints last. The prompt that follows then replaces the one
//!   already on screen (carriage return and erase line, and the lines above for a prompt of several
//!   lines), so the terminal, its scrollback, saved output, session logs and MultiExec never see the
//!   hook, and QL-07 never sees a command run. It is typed only while nothing has been typed in the new
//!   shell, and only after its output has paused at a prompt.
//! * Other shells (sh, fish, tcsh, network gear) get nothing typed; the drawer starts in the home
//!   folder there and the user picks folders by hand. So does a shell that answers the hook with
//!   nothing: after [`HIDE_WAIT`] what was held back is shown and the hook is given up.
//!
//! Nothing here is logged: output is only looked at, the way [`super::activity`] does.

use std::time::{Duration, Instant};

use serde::Serialize;

use crate::adapters::remote::PromptShell;

/// Output must have paused this long at the first prompt before the hook is typed.
pub const PROMPT_QUIET: Duration = Duration::from_millis(300);
/// How long the shell's first prompt may take before the hook is given up.
pub const PROMPT_WAIT: Duration = Duration::from_secs(10);
/// How long output stays hidden waiting for the hook's marker.
pub const HIDE_WAIT: Duration = Duration::from_secs(5);
/// After the marker, the new prompt is complete once output pauses this long.
pub const SETTLE_QUIET: Duration = Duration::from_millis(60);
/// ... or after this long at most.
pub const SETTLE_WAIT: Duration = Duration::from_millis(500);
/// Held-back output beyond this is shown, hook or not.
const MAX_HELD: usize = 256 * 1024;
/// The longest OSC 7 text read; a path is far shorter.
const MAX_OSC: usize = 8192;

/// The marker's start; the hook line prints it (via printf, so its own echo never contains it).
const MARKER_START: &str = "\x1b]7777;remotely-";

/// The line typed into bash or zsh (see the module comment). `token` makes the marker unique.
pub fn hook_line(token: &str) -> String {
    let function = concat!(
        r#"__remotely_cwd(){ local s=$? p=${PWD//\%/%25};p=${p//$'\n'/%0A};p=${p//$'\a'/%07};p=${p//$'\e'/%1B};"#,
        r#"printf '\033]7;file://%s%s\033\\' "${HOSTNAME:-${HOST:-}}" "$p";return $s;}"#,
    );
    let register = concat!(
        r#"if [ -n "${ZSH_VERSION:-}" ];then autoload -Uz add-zsh-hook;add-zsh-hook precmd __remotely_cwd;"#,
        r#"else PROMPT_COMMAND="__remotely_cwd${PROMPT_COMMAND:+;$PROMPT_COMMAND}";__remotely_h=$(history 1);"#,
        r#"case $__remotely_h in *__remotely_cwd*)read -r __remotely_h _ <<<"$__remotely_h";history -d "$__remotely_h";;esac;"#,
        r#"unset __remotely_h;fi"#,
    );
    format!(" {function};{register};printf '\\033]7777;remotely-%s\\007' {token}\r")
}

/// The bytes the hook line prints last.
fn marker(token: &str) -> Vec<u8> {
    format!("{MARKER_START}{token}\x07").into_bytes()
}

/// SS-08: how far the terminal knows its shell's folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FolderTracking {
    /// Connecting, or the shell has not said yet.
    Waiting,
    /// The shell reports its folder at each prompt (OSC 7).
    Following,
    /// Not bash or zsh (or no shell at all), and the shell reports nothing itself.
    Unsupported,
    /// bash or zsh, but the hook could not be set up: something was typed first, or the shell did not
    /// answer it. A reconnect tries again.
    Missed,
}

/// SS-08: a terminal's current folder, as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderInfo {
    /// The shell's folder, once it reported one.
    pub path: Option<String>,
    pub tracking: FolderTracking,
}

impl Default for FolderInfo {
    fn default() -> Self {
        Self {
            path: None,
            tracking: FolderTracking::Waiting,
        }
    }
}

/// Where the OSC scanner is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scan {
    Text,
    Esc,
    /// `ESC ]`: the number before `;`.
    OscNumber,
    /// OSC 7's text.
    Osc7,
    /// Another OSC (or DCS and the like): skipped to its end.
    OtherString,
    /// `ESC` inside a string: `\` ends it.
    StringEsc {
        osc7: bool,
    },
}

/// SS-08: follows the folders OSC 7 reports in a terminal's output.
pub struct FolderWatch {
    scan: Scan,
    number: Vec<u8>,
    text: Vec<u8>,
    /// The host of the first report; a report from another host (a shell on a host reached from this
    /// one, with its own OSC 7) is not this terminal's folder.
    host: Option<String>,
}

impl Default for FolderWatch {
    fn default() -> Self {
        Self::new()
    }
}

impl FolderWatch {
    pub fn new() -> Self {
        Self {
            scan: Scan::Text,
            number: Vec::new(),
            text: Vec::new(),
            host: None,
        }
    }

    /// The last folder these bytes reported, if any.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<String> {
        let mut found = None;
        for &b in bytes {
            self.scan = match (self.scan, b) {
                (Scan::Text, 0x1b) => Scan::Esc,
                (Scan::Text, _) => Scan::Text,
                (Scan::Esc, b']') => {
                    self.number.clear();
                    Scan::OscNumber
                }
                (Scan::Esc, b'P' | b'X' | b'^' | b'_') => Scan::OtherString,
                (Scan::Esc, 0x1b) => Scan::Esc,
                (Scan::Esc, _) => Scan::Text,
                (Scan::OscNumber, b';') if self.number == b"7" => {
                    self.text.clear();
                    Scan::Osc7
                }
                (Scan::OscNumber, b';') => Scan::OtherString,
                (Scan::OscNumber, 0x07) => Scan::Text,
                (Scan::OscNumber, 0x1b) => Scan::StringEsc { osc7: false },
                (Scan::OscNumber, d) if d.is_ascii_digit() && self.number.len() < 8 => {
                    self.number.push(d);
                    Scan::OscNumber
                }
                (Scan::OscNumber, _) => Scan::OtherString,
                (Scan::Osc7, 0x07) => {
                    found = self.report().or(found);
                    Scan::Text
                }
                (Scan::Osc7, 0x1b) => Scan::StringEsc { osc7: true },
                (Scan::Osc7, c) => {
                    if self.text.len() < MAX_OSC {
                        self.text.push(c);
                    }
                    Scan::Osc7
                }
                (Scan::OtherString, 0x07) => Scan::Text,
                (Scan::OtherString, 0x1b) => Scan::StringEsc { osc7: false },
                (Scan::OtherString, _) => Scan::OtherString,
                (Scan::StringEsc { osc7 }, b'\\') => {
                    if osc7 {
                        found = self.report().or(found);
                    }
                    Scan::Text
                }
                // A new escape inside a string: the string was cut short.
                (Scan::StringEsc { .. }, b']') => {
                    self.number.clear();
                    Scan::OscNumber
                }
                (Scan::StringEsc { .. }, _) => Scan::Text,
            };
        }
        found
    }

    /// The finished OSC 7 text as a folder, when it is one of this host's.
    fn report(&mut self) -> Option<String> {
        let (host, path) = parse_osc7(&self.text)?;
        match (&self.host, host) {
            (Some(known), Some(host)) if !host.eq_ignore_ascii_case(known) && !is_local(&host) => None,
            (None, Some(host)) if !is_local(&host) => {
                self.host = Some(host);
                Some(path)
            }
            _ => Some(path),
        }
    }
}

fn is_local(host: &str) -> bool {
    host.is_empty() || host.eq_ignore_ascii_case("localhost")
}

/// `file://host/path` (percent-encoded) or a bare `/path`: the host, if named, and the path.
pub fn parse_osc7(text: &[u8]) -> Option<(Option<String>, String)> {
    let text = std::str::from_utf8(text).ok()?;
    let (host, encoded) = if let Some(rest) = text.strip_prefix("file://") {
        let slash = rest.find('/')?;
        (Some(rest[..slash].to_owned()), &rest[slash..])
    } else if text.starts_with('/') {
        (None, text)
    } else {
        return None;
    };
    let path = percent_decode(encoded);
    (path.starts_with('/') && !path.contains('\0')).then_some((host, path))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let (Some(hi), Some(lo)) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2))) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: Option<&u8>) -> Option<u8> {
    let b = *b?;
    (b as char).to_digit(16).map(|d| d as u8)
}

/// What [`PromptHook::tick`] asks of the pane.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HookTick {
    /// Type this into the shell now (not seen by QL-07 or MultiExec).
    pub type_now: Option<Vec<u8>>,
    /// Show this output now.
    pub show: Vec<u8>,
}

#[derive(Debug)]
enum HookState {
    /// Waiting for the probe's answer and for the first prompt to show.
    Waiting {
        shell: Option<PromptShell>,
        probed: bool,
        last_output: Option<Instant>,
        /// The pause after the last output was looked at and was no prompt to type at: wait for more.
        checked: bool,
    },
    /// Typed; output is held back until the marker.
    Hiding { since: Instant, hidden: Vec<u8> },
    /// The marker came; the new prompt is held to see how many lines it has.
    Settling {
        since: Instant,
        last: Instant,
        held: Vec<u8>,
    },
    /// Set up, given up, or not for this shell.
    Done { tracking: FolderTracking },
}

/// SS-08: one connection's prompt hook (see the module comment). The pane feeds it the shell's output
/// and the user's keys; it says what to show and when to type the hook.
#[derive(Debug)]
pub struct PromptHook {
    state: HookState,
    token: String,
    started: Instant,
}

impl PromptHook {
    pub fn new(token: &str, now: Instant) -> Self {
        Self {
            state: HookState::Waiting {
                shell: None,
                probed: false,
                last_output: None,
                checked: false,
            },
            token: token.to_owned(),
            started: now,
        }
    }

    /// The probe beside the shell answered (`None`: not bash or zsh, or no answer).
    pub fn probe(&mut self, answer: Option<PromptShell>) {
        match &mut self.state {
            HookState::Waiting { shell, probed, .. } => {
                *probed = true;
                *shell = answer;
                if answer.is_none() {
                    self.state = HookState::Done {
                        tracking: FolderTracking::Unsupported,
                    };
                }
            }
            // Given up before the answer came: say why the right way.
            HookState::Done { tracking } if answer.is_none() => *tracking = FolderTracking::Unsupported,
            _ => {}
        }
    }

    /// The hook was set up, given up or not needed: nothing is typed any more, so the session's
    /// startup command may go.
    pub fn settled(&self) -> bool {
        matches!(self.state, HookState::Done { .. } | HookState::Settling { .. })
    }

    /// The hook is typed and its output not seen yet: typing anything else now would be read after it.
    pub fn typing(&self) -> bool {
        matches!(self.state, HookState::Hiding { .. })
    }

    /// How far the folder is known, as far as the hook goes (an OSC 7 seen makes it "following").
    pub fn tracking(&self) -> FolderTracking {
        match self.state {
            HookState::Done { tracking } => tracking,
            _ => FolderTracking::Waiting,
        }
    }

    /// Gives up before typing (the session's startup command goes instead).
    pub fn give_up(&mut self) {
        if matches!(self.state, HookState::Waiting { .. }) {
            self.state = HookState::Done {
                tracking: FolderTracking::Missed,
            };
        }
    }

    /// The user typed: before the hook went out, it is given up (it must never mix with their keys);
    /// while the new prompt is held, that is shown at once. Returns output to show first.
    pub fn input(&mut self) -> Vec<u8> {
        match &mut self.state {
            HookState::Waiting { .. } => {
                // If the probe has not answered yet and then says "not bash or zsh", that wins.
                self.state = HookState::Done {
                    tracking: FolderTracking::Missed,
                };
                Vec::new()
            }
            HookState::Settling { .. } => self.flush(),
            HookState::Hiding { .. } | HookState::Done { .. } => Vec::new(),
        }
    }

    /// The shell printed `bytes`; returns what to show.
    pub fn output(&mut self, bytes: &[u8], now: Instant) -> Vec<u8> {
        match &mut self.state {
            HookState::Waiting {
                last_output, checked, ..
            } => {
                *last_output = Some(now);
                *checked = false;
                bytes.to_vec()
            }
            HookState::Done { .. } => bytes.to_vec(),
            HookState::Hiding { hidden, .. } => {
                hidden.extend_from_slice(bytes);
                let marker = marker(&self.token);
                match find(hidden, &marker) {
                    Some(at) => {
                        let after = hidden.split_off(at + marker.len());
                        self.state = HookState::Settling {
                            since: now,
                            last: now,
                            held: after,
                        };
                        Vec::new()
                    }
                    None if hidden.len() > MAX_HELD => self.give_up_hiding(),
                    None => Vec::new(),
                }
            }
            HookState::Settling { last, held, .. } => {
                *last = now;
                held.extend_from_slice(bytes);
                if held.len() > MAX_HELD {
                    return self.flush();
                }
                Vec::new()
            }
        }
    }

    /// When [`PromptHook::tick`] should next be called, if at all.
    pub fn deadline(&self) -> Option<Instant> {
        match &self.state {
            HookState::Waiting {
                shell,
                last_output,
                checked,
                ..
            } => {
                let give_up = self.started + PROMPT_WAIT;
                match (shell, last_output) {
                    (Some(_), Some(at)) if !checked => Some((*at + PROMPT_QUIET).min(give_up)),
                    _ => Some(give_up),
                }
            }
            HookState::Hiding { since, .. } => Some(*since + HIDE_WAIT),
            HookState::Settling { since, last, .. } => Some((*last + SETTLE_QUIET).min(*since + SETTLE_WAIT)),
            HookState::Done { .. } => None,
        }
    }

    /// Time passed. `line` is the line the cursor is on and `alternate` whether a full-screen program
    /// is open, from the shown output.
    pub fn tick(&mut self, now: Instant, line: &str, alternate: bool) -> HookTick {
        let Some(deadline) = self.deadline() else {
            return HookTick::default();
        };
        if now < deadline {
            return HookTick::default();
        }
        match &self.state {
            HookState::Waiting {
                shell: Some(_),
                last_output: Some(at),
                ..
            } if now.saturating_duration_since(*at) >= PROMPT_QUIET
                && !line.trim().is_empty()
                && !alternate
                && !super::activity::is_password_prompt(line) =>
            {
                self.state = HookState::Hiding {
                    since: now,
                    hidden: Vec::new(),
                };
                HookTick {
                    type_now: Some(hook_line(&self.token).into_bytes()),
                    show: Vec::new(),
                }
            }
            HookState::Waiting { .. } if now >= self.started + PROMPT_WAIT => {
                let tracking = match self.state {
                    HookState::Waiting { probed: false, .. } => FolderTracking::Unsupported,
                    _ => FolderTracking::Missed,
                };
                self.state = HookState::Done { tracking };
                HookTick::default()
            }
            HookState::Waiting { .. } => {
                // No prompt to type at after this pause: wait for more output.
                if let HookState::Waiting { checked, .. } = &mut self.state {
                    *checked = true;
                }
                HookTick::default()
            }
            HookState::Hiding { .. } => HookTick {
                type_now: None,
                show: self.give_up_hiding(),
            },
            HookState::Settling { .. } => HookTick {
                type_now: None,
                show: self.flush(),
            },
            HookState::Done { .. } => HookTick::default(),
        }
    }

    /// No marker came: what was hidden is shown after all.
    fn give_up_hiding(&mut self) -> Vec<u8> {
        let hidden = match &mut self.state {
            HookState::Hiding { hidden, .. } => std::mem::take(hidden),
            _ => Vec::new(),
        };
        self.state = HookState::Done {
            tracking: FolderTracking::Missed,
        };
        hidden
    }

    /// The new prompt, drawn over the one on screen: carriage return and erase line, then up and erase
    /// for each line break it has (a prompt of several lines replaces as many).
    fn flush(&mut self) -> Vec<u8> {
        let held = match &mut self.state {
            HookState::Settling { held, .. } => std::mem::take(held),
            _ => Vec::new(),
        };
        self.state = HookState::Done {
            tracking: FolderTracking::Following,
        };
        let lines = held.iter().filter(|&&b| b == b'\n').count();
        let mut out = b"\r\x1b[2K".to_vec();
        for _ in 0..lines {
            out.extend_from_slice(b"\x1b[1A\x1b[2K");
        }
        out.extend_from_slice(&held);
        out
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn osc_7_reports_the_folder_split_or_whole() {
        let mut watch = FolderWatch::new();
        assert_eq!(
            watch
                .feed(b"\x1b]7;file://web01/home/alice\x07alice@web01:~$ ")
                .as_deref(),
            Some("/home/alice")
        );
        // Split across reads, ended by ESC \, percent-encoded.
        assert_eq!(watch.feed(b"\x1b]7;file://web01/srv/my%20"), None);
        assert_eq!(watch.feed(b"site%25\x1b").as_deref(), None);
        assert_eq!(watch.feed(b"\\$ ").as_deref(), Some("/srv/my site%"));
        // A title (OSC 0) and colours are not folders.
        assert_eq!(watch.feed(b"\x1b]0;alice@web01: /tmp\x07\x1b[01;32m$\x1b[0m "), None);
        // A shell on another host reached from this one.
        assert_eq!(watch.feed(b"\x1b]7;file://db01/var/lib\x07"), None);
        assert_eq!(watch.feed(b"\x1b]7;file://WEB01/etc\x07").as_deref(), Some("/etc"));
        // Without a host, or as a bare path.
        assert_eq!(watch.feed(b"\x1b]7;file:///opt\x07").as_deref(), Some("/opt"));
        assert_eq!(watch.feed(b"\x1b]7;/var/log\x07").as_deref(), Some("/var/log"));
        assert_eq!(watch.feed(b"\x1b]7;not a path\x07"), None);
        assert_eq!(watch.feed(b"\x1b]77;file://web01/x\x07"), None, "OSC 77 is not 7");
    }

    #[test]
    fn percent_decoding_keeps_what_is_not_an_escape() {
        assert_eq!(percent_decode("/a%2Fb/%e2%82%ac"), "/a/b/€");
        assert_eq!(percent_decode("/50%/x%2"), "/50%/x%2");
    }

    #[test]
    fn the_hook_line_is_one_line_with_a_unique_marker_and_no_history_expansion() {
        let line = hook_line("ab12");
        assert!(line.starts_with(' '), "a leading space keeps it out of the history");
        assert!(line.ends_with('\r'));
        assert_eq!(line.matches('\r').count(), 1);
        assert!(!line.contains('\n'));
        assert!(!line.contains('!'), "! would be history expansion in bash and zsh");
        assert!(!line.contains('\t'), "a tab would complete");
        assert!(!line.contains('\x1b'), "the escapes are printf's, not typed");
        // The echo of the line never holds the marker itself.
        let marker = String::from_utf8(marker("ab12")).unwrap();
        assert!(!line.contains(&marker));
        assert!(line.contains("remotely-%s"));
        assert!(line.contains("PROMPT_COMMAND"));
        assert!(line.contains("add-zsh-hook precmd"));
    }

    /// A bash login: banner, prompt, the probe's answer, quiet, hook typed, echo hidden, prompt redrawn.
    #[test]
    fn the_hook_is_typed_at_the_first_quiet_prompt_and_its_echo_never_shows() {
        let t0 = Instant::now();
        let mut hook = PromptHook::new("t1", t0);
        assert_eq!(
            hook.output(b"Welcome\r\nalice@web01:~$ ", t0),
            b"Welcome\r\nalice@web01:~$ "
        );
        assert_eq!(
            hook.tick(t0 + 400 * MS, "alice@web01:~$ ", false),
            HookTick::default(),
            "no probe yet"
        );
        hook.probe(Some(PromptShell::Bash));
        assert!(!hook.settled());
        let tick = hook.tick(t0 + 400 * MS, "alice@web01:~$ ", false);
        let typed = String::from_utf8(tick.type_now.unwrap()).unwrap();
        assert!(typed.starts_with(" __remotely_cwd"));
        assert!(hook.typing());
        // The echo, then the marker and the new prompt in one read.
        assert!(hook.output(typed.trim_end().as_bytes(), t0 + 410 * MS).is_empty());
        let mut rest = b"\r\n".to_vec();
        rest.extend_from_slice(&marker("t1"));
        rest.extend_from_slice(b"\x1b]7;file://web01/home/alice\x1b\\alice@web01:~$ ");
        assert!(hook.output(&rest, t0 + 420 * MS).is_empty());
        assert!(hook.settled());
        assert_eq!(
            hook.tick(t0 + 430 * MS, "", false),
            HookTick::default(),
            "still settling"
        );
        let shown = hook.tick(t0 + 500 * MS, "", false).show;
        assert_eq!(shown, b"\r\x1b[2K\x1b]7;file://web01/home/alice\x1b\\alice@web01:~$ ");
        assert_eq!(hook.tracking(), FolderTracking::Following);
        assert_eq!(
            hook.output(b"ls\r\n", t0 + SETTLE_WAIT * 2),
            b"ls\r\n",
            "passes through from now on"
        );
        assert_eq!(hook.deadline(), None);
    }

    #[test]
    fn a_prompt_of_two_lines_replaces_both() {
        let t0 = Instant::now();
        let mut hook = PromptHook::new("t2", t0);
        hook.probe(Some(PromptShell::Zsh));
        hook.output("┌──(alice㉿web01)-[~]\r\n└─$ ".as_bytes(), t0);
        assert!(hook.tick(t0 + PROMPT_QUIET, "└─$ ", false).type_now.is_some());
        let mut rest = b"echo...\r\n".to_vec();
        rest.extend_from_slice(&marker("t2"));
        hook.output(&rest, t0 + 350 * MS);
        hook.output("┌──(alice㉿web01)-[~]\r\n└─$ ".as_bytes(), t0 + 360 * MS);
        // A key typed while the prompt is held shows it at once.
        let shown = hook.input();
        assert!(shown.starts_with(b"\r\x1b[2K\x1b[1A\x1b[2K\xe2\x94\x8c"));
        assert!(hook.output(b"l", t0 + 370 * MS) == b"l");
    }

    #[test]
    fn keys_typed_first_or_a_shell_that_is_not_bash_get_no_hook() {
        let t0 = Instant::now();
        let mut hook = PromptHook::new("t3", t0);
        hook.output(b"$ ", t0);
        hook.probe(Some(PromptShell::Bash));
        assert!(hook.input().is_empty());
        assert_eq!(hook.tracking(), FolderTracking::Missed);
        assert!(hook.tick(t0 + Duration::from_secs(1), "$ ", false).type_now.is_none());

        let mut fish = PromptHook::new("t4", t0);
        fish.probe(None);
        assert!(fish.settled());
        assert_eq!(fish.tracking(), FolderTracking::Unsupported);
        assert_eq!(fish.output(b"> ", t0), b"> ");
    }

    #[test]
    fn no_hook_at_an_empty_line_a_password_prompt_or_a_full_screen_program() {
        let t0 = Instant::now();
        let mut hook = PromptHook::new("t5", t0);
        hook.probe(Some(PromptShell::Bash));
        hook.output(b"Last login: today\r\n", t0);
        assert!(
            hook.tick(t0 + PROMPT_QUIET, "", false).type_now.is_none(),
            "still printing the banner"
        );
        hook.output(b"Password: ", t0 + PROMPT_QUIET);
        assert!(hook.tick(t0 + 2 * PROMPT_QUIET, "Password: ", false).type_now.is_none());
        hook.output(b"\x1b[?1049h", t0 + 2 * PROMPT_QUIET);
        assert!(hook.tick(t0 + 3 * PROMPT_QUIET, "x", true).type_now.is_none());
        // The first prompt never came.
        hook.tick(t0 + PROMPT_WAIT, "x", true);
        assert_eq!(hook.tracking(), FolderTracking::Missed);
    }

    #[test]
    fn without_a_marker_what_was_hidden_shows_after_a_while() {
        let t0 = Instant::now();
        let mut hook = PromptHook::new("t6", t0);
        hook.probe(Some(PromptShell::Bash));
        hook.output(b"$ ", t0);
        assert!(hook.tick(t0 + PROMPT_QUIET, "$ ", false).type_now.is_some());
        assert!(hook
            .output(b"__remotely_cwd: command not found\r\n$ ", t0 + 310 * MS)
            .is_empty());
        let shown = hook.tick(t0 + PROMPT_QUIET + HIDE_WAIT, "$ ", false).show;
        assert_eq!(shown, b"__remotely_cwd: command not found\r\n$ ");
        assert_eq!(hook.tracking(), FolderTracking::Missed);
    }

    #[test]
    fn the_probe_that_never_answers_gives_up_in_time() {
        let t0 = Instant::now();
        let mut hook = PromptHook::new("t7", t0);
        hook.output(b"$ ", t0);
        assert_eq!(hook.deadline(), Some(t0 + PROMPT_WAIT));
        hook.tick(t0 + PROMPT_WAIT, "$ ", false);
        assert_eq!(hook.tracking(), FolderTracking::Unsupported);
        assert!(hook.settled());
    }
}
