//! SS-08: the folder a terminal's shell is in, for the "Files here" drawer and uploads.
//!
//! * OSC 7 (`ESC ] 7 ; file://host/path`, ended by BEL or `ESC \`) is how shells tell a terminal their
//!   folder (VTE, iTerm2, Windows Terminal read it too). [`FolderWatch`] picks it out of the output.
//!   The sequence prints nothing in any terminal, and the line follower and the session log drop it.
//! * bash and zsh ([`PromptShell`], from the probe beside each new shell) get a prompt hook typed into
//!   them once their first prompt shows ([`PromptHook`]): a function that prints OSC 7 before each
//!   prompt (bash's `PROMPT_COMMAND`, zsh's `precmd`), keeping `$?` for the prompt. The line starts with
//!   a space, so `ignorespace` (bash's `HISTCONTROL`, zsh's `HIST_IGNORE_SPACE`) keeps it out of the
//!   history; nothing deletes history entries. It is typed only at a line that looks like a shell
//!   prompt (`user@host:~$ `), never at a menu or a question such as `oraenv`'s, and the terminal audits
//!   it once per connection (`folder_hook_installed`).
//! * The hook can be turned off in Settings and per session; a Prod-labelled session has it off unless
//!   the session turns it on ([`PromptHook::off`], [`FolderTracking::Off`]). The drawer then starts in
//!   the home folder.
//! * The hook stays invisible: from the moment it is typed, the shell's output (the echo of the line)
//!   is held back until a marker the line prints last. The prompt that follows then replaces the one
//!   already on screen (carriage return and erase line, and the lines above for a prompt of several
//!   lines), so the terminal, its scrollback, saved output, session logs and MultiExec never see the
//!   hook, and QL-07 never sees a command run. It is typed only while nothing has been typed in the new
//!   shell, and only after its output has paused at a prompt.
//! * Other shells (sh, fish, tcsh, network gear) get nothing typed; the drawer starts in the home
//!   folder there and the user picks folders by hand. So does a shell that answers the hook with
//!   nothing: after [`HIDE_WAIT`] what was held back is shown and the hook is given up.
//! * QL-09: the hook also reports its shell's user next to the folder, in a private OSC
//!   (`ESC ] 7777 ; remotely-user=alice BEL`), asked once with `id -un` when the hook is set up (a
//!   shell's user never changes; a switch starts another shell, see [`super::shell_user`]). Like OSC 7
//!   it prints nothing in any terminal, and the line follower, the session log and saved output drop
//!   it.
//!
//! Nothing here is logged: output is only looked at, the way [`super::activity`] does.

use std::time::{Duration, Instant};

use serde::Serialize;

use super::shell_user::UserInfo;
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

/// The private OSC's number: the hook's marker and its user reports.
const REMOTELY_OSC: &[u8] = b"7777";
/// The marker's start; the hook line prints it (via printf, so its own echo never contains it).
const MARKER_START: &str = "\x1b]7777;remotely-";
/// QL-09: what a user report's text starts with; the user name follows, percent-encoded.
const USER_REPORT: &str = "remotely-user=";

/// The line typed into bash or zsh (see the module comment). `token` makes the marker unique.
pub fn hook_line(token: &str) -> String {
    let function = concat!(
        r#"__remotely_cwd(){ local s=$? p=${PWD//\%/%25};p=${p//$'\n'/%0A};p=${p//$'\a'/%07};p=${p//$'\e'/%1B};"#,
        r#"printf '\033]7;file://%s%s\033\\\033]7777;remotely-user=%s\007' "${HOSTNAME:-${HOST:-}}" "$p" "$__remotely_u";return $s;}"#,
    );
    // QL-09: the shell's user, asked once (it never changes in this shell) and encoded like the path.
    let user = concat!(
        r#"__remotely_u=$(id -un 2>/dev/null);__remotely_u=${__remotely_u//\%/%25};"#,
        r#"__remotely_u=${__remotely_u//$'\n'/%0A};__remotely_u=${__remotely_u//$'\a'/%07};__remotely_u=${__remotely_u//$'\e'/%1B}"#,
    );
    let register = concat!(
        r#"if [ -n "${ZSH_VERSION:-}" ];then autoload -Uz add-zsh-hook;add-zsh-hook precmd __remotely_cwd;"#,
        r#"else PROMPT_COMMAND="__remotely_cwd${PROMPT_COMMAND:+;$PROMPT_COMMAND}";fi"#,
    );
    format!(" {function};{user};{register};printf '\\033]7777;remotely-%s\\007' {token}\r")
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
    /// The hook is turned off (Settings, the session, or a Prod session by default).
    Off,
}

/// SS-08: a terminal's current folder, as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderInfo {
    /// The shell's folder, once it reported one.
    pub path: Option<String>,
    pub tracking: FolderTracking,
    /// QL-09: who transfers run as, and who the shell runs as when that differs.
    pub user: UserInfo,
}

impl Default for FolderInfo {
    fn default() -> Self {
        Self {
            path: None,
            tracking: FolderTracking::Waiting,
            user: UserInfo::default(),
        }
    }
}

/// What a piece of output reported: the folder (OSC 7) and the shell's user (QL-09), the last of each.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reports {
    pub folder: Option<String>,
    pub user: Option<String>,
}

/// Where the OSC scanner is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scan {
    Text,
    Esc,
    /// `ESC ]`: the number before `;`.
    OscNumber,
    /// The text of an OSC this reads: 7 (the folder) or Remotely's own (QL-09: the user).
    Read(Osc),
    /// Another OSC (or DCS and the like): skipped to its end.
    OtherString,
    /// `ESC` inside a string: `\` ends it.
    StringEsc {
        read: Option<Osc>,
    },
}

/// The OSCs [`FolderWatch`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Osc {
    /// OSC 7: the folder.
    Folder,
    /// Remotely's private OSC: the hook's marker or its user report.
    Remotely,
}

/// SS-08: follows the folders OSC 7 reports in a terminal's output, and (QL-09) the user the prompt
/// hook reports next to them.
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

    /// What these bytes reported, if anything.
    pub fn feed(&mut self, bytes: &[u8]) -> Reports {
        let mut found = Reports::default();
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
                (Scan::OscNumber, b';') => {
                    self.text.clear();
                    match self.number.as_slice() {
                        b"7" => Scan::Read(Osc::Folder),
                        REMOTELY_OSC => Scan::Read(Osc::Remotely),
                        _ => Scan::OtherString,
                    }
                }
                (Scan::OscNumber, 0x07) => Scan::Text,
                (Scan::OscNumber, 0x1b) => Scan::StringEsc { read: None },
                (Scan::OscNumber, d) if d.is_ascii_digit() && self.number.len() < 8 => {
                    self.number.push(d);
                    Scan::OscNumber
                }
                (Scan::OscNumber, _) => Scan::OtherString,
                (Scan::Read(osc), 0x07) => {
                    self.finish(osc, &mut found);
                    Scan::Text
                }
                (Scan::Read(osc), 0x1b) => Scan::StringEsc { read: Some(osc) },
                (Scan::Read(osc), c) => {
                    if self.text.len() < MAX_OSC {
                        self.text.push(c);
                    }
                    Scan::Read(osc)
                }
                (Scan::OtherString, 0x07) => Scan::Text,
                (Scan::OtherString, 0x1b) => Scan::StringEsc { read: None },
                (Scan::OtherString, _) => Scan::OtherString,
                (Scan::StringEsc { read }, b'\\') => {
                    if let Some(osc) = read {
                        self.finish(osc, &mut found);
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

    /// A finished OSC this reads.
    fn finish(&mut self, osc: Osc, found: &mut Reports) {
        match osc {
            Osc::Folder => {
                if let Some(folder) = self.report() {
                    found.folder = Some(folder);
                }
            }
            Osc::Remotely => {
                if let Some(user) = parse_user_report(&self.text) {
                    found.user = Some(user);
                }
            }
        }
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

/// QL-09: `remotely-user=alice` (percent-encoded): the user, unless empty or not printable.
fn parse_user_report(text: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(text).ok()?.strip_prefix(USER_REPORT)?;
    let user = percent_decode(text);
    (!user.is_empty() && !user.chars().any(char::is_control)).then_some(user)
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

    /// The hook is turned off: nothing is typed, and the folder is known only if the shell reports it
    /// itself (OSC 7).
    pub fn off(token: &str, now: Instant) -> Self {
        Self {
            state: HookState::Done {
                tracking: FolderTracking::Off,
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
            HookState::Done { tracking } if answer.is_none() && *tracking != FolderTracking::Off => {
                *tracking = FolderTracking::Unsupported;
            }
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
                && !alternate
                && super::shell_user::looks_like_prompt(line) =>
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

    fn folder(watch: &mut FolderWatch, bytes: &[u8]) -> Option<String> {
        watch.feed(bytes).folder
    }

    #[test]
    fn osc_7_reports_the_folder_split_or_whole() {
        let mut watch = FolderWatch::new();
        assert_eq!(
            folder(&mut watch, b"\x1b]7;file://web01/home/alice\x07alice@web01:~$ ").as_deref(),
            Some("/home/alice")
        );
        // Split across reads, ended by ESC \, percent-encoded.
        assert_eq!(folder(&mut watch, b"\x1b]7;file://web01/srv/my%20"), None);
        assert_eq!(folder(&mut watch, b"site%25\x1b").as_deref(), None);
        assert_eq!(folder(&mut watch, b"\\$ ").as_deref(), Some("/srv/my site%"));
        // A title (OSC 0) and colours are not folders.
        assert_eq!(
            folder(&mut watch, b"\x1b]0;alice@web01: /tmp\x07\x1b[01;32m$\x1b[0m "),
            None
        );
        // A shell on another host reached from this one.
        assert_eq!(folder(&mut watch, b"\x1b]7;file://db01/var/lib\x07"), None);
        assert_eq!(
            folder(&mut watch, b"\x1b]7;file://WEB01/etc\x07").as_deref(),
            Some("/etc")
        );
        // Without a host, or as a bare path.
        assert_eq!(folder(&mut watch, b"\x1b]7;file:///opt\x07").as_deref(), Some("/opt"));
        assert_eq!(folder(&mut watch, b"\x1b]7;/var/log\x07").as_deref(), Some("/var/log"));
        assert_eq!(folder(&mut watch, b"\x1b]7;not a path\x07"), None);
        assert_eq!(
            folder(&mut watch, b"\x1b]77;file://web01/x\x07"),
            None,
            "OSC 77 is not 7"
        );
    }

    /// QL-09: the hook's prompt prints OSC 7, then the user in Remotely's own OSC.
    #[test]
    fn the_hook_reports_the_user_next_to_the_folder() {
        let mut watch = FolderWatch::new();
        let found = watch.feed(b"\x1b]7;file://web01/home/alice\x1b\\\x1b]7777;remotely-user=alice\x07$ ");
        assert_eq!(found.folder.as_deref(), Some("/home/alice"));
        assert_eq!(found.user.as_deref(), Some("alice"));
        // Split, ended by ESC \, percent-encoded.
        assert_eq!(watch.feed(b"\x1b]7777;remotely-us"), Reports::default());
        let found = watch.feed(b"er=CORP%25bob\x1b\\");
        assert_eq!(found.user.as_deref(), Some("CORP%bob"));
        assert_eq!(found.folder, None);
        // The hook's marker, an empty user, a control character and OSC 777 are no user.
        for other in [
            &b"\x1b]7777;remotely-0123abcd\x07"[..],
            b"\x1b]7777;remotely-user=\x07",
            b"\x1b]7777;remotely-user=a%07b\x07",
            b"\x1b]777;remotely-user=mallory\x07",
            b"remotely-user=mallory",
        ] {
            assert_eq!(watch.feed(other), Reports::default(), "{other:?}");
        }
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
        // It never edits the shell's history: the leading space keeps it out where ignorespace is on.
        assert!(!line.contains("history"), "{line}");
        // QL-09: the user is asked once, and reported with the folder.
        assert_eq!(line.matches("id -un").count(), 1);
        assert!(line.contains(r"\033]7777;remotely-user=%s\007"));
        // The test server knows the hook by how it starts, and its token is the last word.
        assert!(line.trim_start().starts_with("__remotely_cwd()"));
        assert_eq!(line.split_whitespace().last(), Some("ab12"));
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

    /// Only a line that looks like a shell prompt gets the hook: never a menu or a question a login
    /// script asks (oraenv, a site's "choose a project" menu), where it would be read as an answer.
    #[test]
    fn no_hook_at_a_question_or_a_menu() {
        let t0 = Instant::now();
        let mut hook = PromptHook::new("t8", t0);
        hook.probe(Some(PromptShell::Bash));
        for (i, line) in [
            "ORACLE_SID = [orcl] ? ",
            "Choose a project [1-3]: ",
            "Continue (y/n)? ",
            "> ",
        ]
        .into_iter()
        .enumerate()
        {
            let at = t0 + PROMPT_QUIET * (i as u32 + 1);
            hook.output(line.as_bytes(), at);
            assert!(hook.tick(at + PROMPT_QUIET, line, false).type_now.is_none(), "{line}");
        }
        hook.output(
            b"
alice@web01:~$ ",
            t0 + PROMPT_QUIET * 6,
        );
        assert!(hook
            .tick(t0 + PROMPT_QUIET * 7, "alice@web01:~$ ", false)
            .type_now
            .is_some());
    }

    #[test]
    fn a_hook_turned_off_types_nothing_and_says_so() {
        let t0 = Instant::now();
        let mut hook = PromptHook::off("t9", t0);
        hook.probe(Some(PromptShell::Bash));
        assert!(hook.settled());
        assert_eq!(hook.deadline(), None);
        assert_eq!(hook.output(b"alice@web01:~$ ", t0), b"alice@web01:~$ ");
        assert!(hook.tick(t0 + PROMPT_WAIT, "alice@web01:~$ ", false).type_now.is_none());
        assert_eq!(hook.tracking(), FolderTracking::Off);
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
