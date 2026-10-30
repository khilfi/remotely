//! SS-10 MultiExec: type once into several open terminals, as in MobaXterm, without skipping the
//! approval rules (CLAUDE.md architecture rules 1, 2 and 4).
//!
//! * The UI turns MultiExec on with the terminals that receive input ([`MultiExec::set_targets`]).
//!   Keys typed into one of them come here ([`MultiExec::input`]) and go to each; every terminal shows
//!   its own output. Keys typed into a terminal that is not a target go to it alone, as usual.
//! * A line buffer follows what is typed: printable characters, Backspace, Ctrl+W and Ctrl+U; Ctrl+C
//!   clears it. Keys it can't follow (Tab completion, arrow keys and other escape sequences, Ctrl+R and
//!   the other control keys) make the line "unreliable", and so does text that was on a terminal's line
//!   before MultiExec saw it.
//! * Enter is held, and so is every other key that makes bash or zsh run the line ([`RunKey`]: Ctrl+O,
//!   Esc then Enter, Esc then A...; the table below says which and why). The line goes to the command
//!   bus as [`Command::TerminalLine`], which the policy engine rates like a bulk run's command:
//!   read-only, other or dangerous, a Prod target raises it, and an unreliable line is at least
//!   "other", never Low. Low: the job runner sends the held keys at once. Higher: the approval dialog
//!   shows the line and the terminals; the keys go once it is approved ([`MultiExec::approve`]).
//!   Cancelling ([`MultiExec::cancel`], or cancelling the job's countdown) sends Ctrl+C to every
//!   terminal instead, which clears the line. Keys typed meanwhile wait, and follow the held keys in
//!   order (or are dropped with them). The bus sends exactly the held keys, nothing else.
//! * Keys that open the line in an editor and run what is saved there (Ctrl+X Ctrl+E, `v` in vi
//!   mode), replay a keyboard macro or run a command by name are never sent: what they run is decided
//!   later, so rating the line can't cover it ([`InputOutcome::Refused`] says why).
//! * After a line that ran with another key than Enter, or one with keys after which the shell may
//!   still hold text (a history search, quoted insert, zsh's push-line), the next line is unreliable.
//! * A paste of several lines without bracketed paste is rated as one script and sent as a whole.
//!   With bracketed paste the shell waits for Enter anyway, and the whole paste is the line.
//! * Every line that is sent is audited by the bus and the job runner: the command, the terminals and
//!   their sessions, the tier, and the approval. Never the output. An empty line (Enter alone) is sent
//!   at once and not audited: it runs nothing.
//! * Two cases pass keys straight through, unrated and never logged or audited:
//!   - a password prompt: when a line starts while the terminal typed into shows a password,
//!     passphrase or one-time code prompt ([`super::activity::is_secret_prompt`]: sudo, su, ssh, PAM's
//!     two-factor modules, in English and translated), its keys and its Enter go only to the targets that
//!     show one too. So a password never lands in a shell, the journal or the audit log, and a command
//!     never at a password prompt.
//!   - a full-screen program (xterm's alternate screen buffer: vim, less, top): keys go only to the
//!     targets that have one open too. What is typed there (vim's `:!command`) is not rated.
//! * A password typed ahead of its prompt (a slow host showed the prompt only after the line started):
//!   at Enter the terminal typed into shows a password or code prompt and not what was typed, so the keys
//!   went into the prompt. The line is not rated, journaled or audited, and its Enter is not sent: Ctrl+C
//!   clears it in every terminal ([`InputOutcome::Refused`] says to type it again at the prompt).
//! * A target is left out of a line when it is not connected, its session is protected (AP-04), its
//!   screen is in another state than the terminal typed into, or it was added while the line was
//!   being typed (it joins at the next line).
//! * QL-12: every line that is sent is recorded in each of its terminals, from Enter until the prompt
//!   comes back ([`super::record`]), for the Compare panel's MultiExec view: grouped, diffed and
//!   exported like a Compare run. Recordings last until MultiExec is turned off.
//! * QL-07: a line's terminals don't notify one by one; [`MultiExecEvent::LineFinished`] comes once
//!   all of them are done, and the UI notifies once for the line.

use std::collections::HashSet;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::{broadcast, Mutex};
use uuid::Uuid;

use super::activity::{is_secret_prompt, FinishedHow};
use super::record::{RecordLimits, RecordedResults, Recorder, Recordings};
use super::Terminals;
use crate::bulk::{GroupOptions, HostOutput, OutputDiff, RecordedRun};
use crate::command_bus::{ApprovalAnswers, ApprovalRequest, Command, CommandBus, SubmitOutcome};
use crate::domain::TargetRef;
use crate::error::{CoreError, Result};
use crate::jobs::{JobRunner, JobStatus};
use crate::policy::Tier;
use crate::presentation::Change;

/// Keys that wait for a held line's Enter, at most. More are dropped (and the UI is told).
pub const MAX_QUEUED_BYTES: usize = 64 * 1024;

const CTRL_C: u8 = 0x03;
const CTRL_E: u8 = 0x05;
const CTRL_O: u8 = 0x0f;
const CTRL_Q: u8 = 0x11;
const CTRL_R: u8 = 0x12;
const CTRL_S: u8 = 0x13;
const CTRL_V: u8 = 0x16;
const CTRL_X: u8 = 0x18;
const ESC: u8 = 0x1b;

// ---- The line buffer -------------------------------------------------------------------------------
//
// Which keys run the line. MultiExec can't ask a shell how it edits, so it holds every key that runs
// the line in the default bindings of bash (readline's emacs and vi modes, checked with `bind -p` on
// bash 5.3) and zsh (its emacs, viins and vicmd keymaps, zshzle(1)), whichever the terminals use. A
// "-" means the keys run nothing there; they are held anyway, since MultiExec can't tell shells apart.
//
//   keys             bash emacs               bash vi                  zsh emacs                zsh vi
//   Enter, Ctrl+J    accept-line              accept-line              accept-line              accept-line
//   Ctrl+O           operate-and-get-next:    - (inserts ^O)           accept-line-and-down-    -
//                    runs it, then puts the                            history: the same
//                    next history line up
//   Esc Enter,       -                        command mode, then       - (a line break in       command mode, then
//   Esc Ctrl+J                                accept-line              the buffer)              accept-line
//   Esc Ctrl+O       held like Ctrl+O, in case a shell reads the Esc on its own first
//   Esc #, and #     insert-comment: runs     insert-comment           -                        pound-insert: runs
//   in vi command    the line commented out;                                                    it commented out,
//   mode             with a count, takes                                                        or without its #
//                    its # away and runs it                                                     if it starts with #
//   Esc a, Esc A     -                        - (append)               accept-and-hold          - (append)
//   Esc Ctrl+E       shell-expand-line: runs  -                        -                        -
//                    the line's $(...)
//   Esc z            -                        -                        execute-last-named-cmd   -
//   Esc O M          the keypad's Enter in application keypad mode, which setups bind to accept-line
//
// Refused, never sent: what runs is decided after the keys, so rating the line can't cover it.
//   Ctrl+X Ctrl+E    bash's edit-and-execute-command (oh-my-zsh binds zsh's edit-command-line there)
//   v after Esc      bash vi's edit-and-execute-command (oh-my-zsh's vi-mode: vv)
//   Ctrl+X e or E    bash's call-last-kbd-macro (a macro may hold Enter); zsh's _expand_word may run $(...)
//   Esc x, and :     execute-named-command (bash 5.3) and execute-named-cmd (zsh, and : in vicmd): any
//   in vi command    command by name, edit-and-execute included
//   mode
//
// The next line is unreliable after keys that leave text on the shell's line: any run key but Enter;
// Enter right after Ctrl+V or Ctrl+Q (quoted-insert puts it in the line); Ctrl+J after Ctrl+R or Ctrl+S
// (it ends the search and leaves the line found); Esc p, Esc n, and / or ? in vi command mode (bash reads
// a search up to Enter and leaves the line found); Ctrl+Q, Esc q and Esc Q (zsh's push-line brings the
// line back after the next one); an escape sequence that is not a key.
//
// Esc: a lone Esc waits for the key after it and goes with it, so the two can be held or refused
// together. xterm.js sends an escape sequence (an arrow key, Home, a bracketed paste's markers) in one
// piece; one that is not a key (a control key, `#` or `v` in it) is read as the shells read it: Esc,
// then each key on its own. After a lone Esc, vi's command mode may be on until a key that goes back to
// typing (i, I, a, A, s, S, c and its motion, C, R): there `#` runs the line and `v` and `:` are
// refused. In emacs mode that guess is wrong and those keys type themselves; they are held or refused
// all the same.
//
// Not covered: bindings a user added (inputrc, bindkey); and a shell in the C locale may read bytes with
// the eighth bit set as Alt and a key (readline's convert-meta), so typed non-ASCII text could act as
// one there. MultiExec passes such text on as text.

/// SS-10: a key (or keys) after which a shell may run the line. Held like Enter: the line is rated
/// first, and exactly these keys go once it may run (see the table above).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKey {
    /// Enter: CR, or LF (Ctrl+J). The only one after which the shell's next line is empty.
    Enter(u8),
    /// Ctrl+O.
    CtrlO,
    /// A lone Esc (or Alt), then CR, LF, Ctrl+O, #, a, A, Ctrl+E or z.
    Esc(u8),
    /// `#` in vi command mode.
    Comment,
    /// The keypad's Enter in application keypad mode: Esc O M.
    KeypadEnter,
}

impl RunKey {
    /// The keys that may run the line after a lone Esc.
    const AFTER_ESC: [u8; 8] = [b'\r', b'\n', CTRL_O, b'#', b'a', b'A', CTRL_E, b'z'];

    /// What is sent once the line may run.
    pub fn keys(self) -> Vec<u8> {
        match self {
            RunKey::Enter(byte) => vec![byte],
            RunKey::CtrlO => vec![CTRL_O],
            RunKey::Esc(byte) => vec![ESC, byte],
            RunKey::Comment => vec![b'#'],
            RunKey::KeypadEnter => vec![ESC, b'O', b'M'],
        }
    }

    /// The run key `keys` start with, and how many bytes it takes.
    pub fn parse(keys: &[u8]) -> Option<(RunKey, usize)> {
        let key = match keys {
            [byte @ (b'\r' | b'\n'), ..] => RunKey::Enter(*byte),
            [CTRL_O, ..] => RunKey::CtrlO,
            [b'#', ..] => RunKey::Comment,
            [ESC, b'O', b'M', ..] => RunKey::KeypadEnter,
            [ESC, byte, ..] if Self::AFTER_ESC.contains(byte) => RunKey::Esc(*byte),
            _ => return None,
        };
        Some((key, key.keys().len()))
    }

    /// Enter: the only run key after which nothing is left on the shell's line, and the only one a
    /// paste's next line may follow.
    pub fn is_enter(self) -> bool {
        matches!(self, RunKey::Enter(_))
    }

    /// Takes a `#` away (or adds one), so what runs is not the line as typed.
    fn toggles_comment(self) -> bool {
        matches!(self, RunKey::Comment | RunKey::Esc(b'#'))
    }

    /// How the approval dialog and the audit log name it.
    pub fn label(self) -> &'static str {
        match self {
            RunKey::Enter(b'\n') => "Ctrl+J",
            RunKey::Enter(_) => "Enter",
            RunKey::CtrlO => "Ctrl+O",
            RunKey::Esc(b'\r') => "Esc then Enter",
            RunKey::Esc(b'\n') => "Esc then Ctrl+J",
            RunKey::Esc(CTRL_O) => "Esc then Ctrl+O",
            RunKey::Esc(b'#') => "Esc then #",
            RunKey::Esc(b'a') => "Esc then a",
            RunKey::Esc(b'A') => "Esc then A",
            RunKey::Esc(CTRL_E) => "Esc then Ctrl+E",
            RunKey::Esc(_) => "Esc then z",
            RunKey::Comment => "# in vi command mode",
            RunKey::KeypadEnter => "the keypad's Enter",
        }
    }

    /// What the key does in the shells, for the approval dialog; `None` for Enter.
    pub fn note(self) -> Option<String> {
        let label = self.label();
        let note = match self {
            RunKey::Enter(_) => return None,
            RunKey::CtrlO => format!(
                "{label} runs the line in bash and zsh, then puts the next line of their history on the prompt, so \
                 the next line is rated as one Remotely can't follow."
            ),
            RunKey::Esc(b'\r' | b'\n') => format!(
                "{label} runs the line in vi mode. In emacs mode zsh adds a line break instead and bash does nothing; \
                 Remotely rates the line as if it runs."
            ),
            RunKey::Esc(b'a' | b'A') => format!(
                "{label} runs the line and keeps it (zsh's accept-and-hold). In vi mode it appends to the line \
                 instead; Remotely rates the line as if it runs."
            ),
            RunKey::Esc(CTRL_E) => format!(
                "{label} expands the line in bash, which runs any $(...) or `...` in it. Remotely rates the whole line."
            ),
            RunKey::Esc(b'z') => {
                format!("{label} repeats zsh's last command run by name, which may run the line.")
            }
            RunKey::Comment | RunKey::Esc(b'#') => format!(
                "{label} comments the line out and runs it (bash's insert-comment, zsh's pound-insert). On a line \
                 that starts with #, it may take the # away and run the rest, so Remotely rates the line without it."
            ),
            RunKey::Esc(_) => format!("{label} may run the line; Remotely rates it as if it does."),
            RunKey::KeypadEnter => format!("{label} runs the line where it is bound to accept-line."),
        };
        Some(note)
    }
}

/// SS-10: at Enter, the terminal typed into shows a password or code prompt (`screen`, its cursor's line)
/// that does not end with what was typed: the keys went into the prompt, unseen, so `typed` is a secret.
fn typed_into_secret_prompt(screen: &str, typed: &str) -> bool {
    let typed = typed.trim_end();
    !typed.trim().is_empty() && is_secret_prompt(screen) && !screen.trim_end().ends_with(typed)
}

/// The line as the shells run it with `run`: a comment toggle takes away the `#` each line starts with
/// (on a line that doesn't start with one it adds one, and nothing runs; the line is rated as typed).
fn as_run(text: &str, run: RunKey) -> String {
    if !run.toggles_comment() || !text.starts_with('#') {
        return text.to_owned();
    }
    text.split('\n')
        .map(|line| line.strip_prefix('#').unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

const EDIT_AND_RUN: &str =
    "Ctrl+X Ctrl+E was not sent: it opens the line in an editor, and the shells run whatever is \
     saved there, which MultiExec can't rate. Finish the line here, or edit it in one terminal at a time.";
const MACRO: &str = "Ctrl+X E was not sent: in bash it replays a keyboard macro, which can run lines MultiExec \
     can't rate (and zsh may run the line's $(...) to expand it).";
const VI_EDIT: &str = "v was not sent: after Esc it opens the line in an editor in vi mode, and the shells run \
     whatever is saved there, which MultiExec can't rate. Type i to go on typing, or Ctrl+C to drop the line.";
const NAMED: &str = "Esc then x was not sent: in bash and zsh it runs an editing command by name, which can open the \
     line in an editor or run it in ways MultiExec can't rate. (In vi mode, delete with the Delete key instead.)";
const VI_NAMED: &str = ": after Esc was not sent: in zsh's vi mode it runs an editing command by name, which can \
     open the line in an editor or run it in ways MultiExec can't rate. Type i to go on typing.";

/// Where the buffer is in an escape sequence the keyboard sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Escape {
    #[default]
    None,
    /// A lone Esc so far.
    Started,
    Csi,
    Ss3,
}

/// What the keys say about vi mode (see the table above): after a lone Esc, its command mode may be on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Vi {
    #[default]
    Insert,
    Command,
    /// After r, f, F, t, T, m or `: the next key is their argument, not a command.
    Argument,
    /// After c: a motion, then typing.
    Change,
    /// After c and f, F, t or T: their argument, then typing.
    ChangeArgument,
}

/// What a byte did to the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Part of the line, or a key that edits it: what it put in `out` goes to the terminals now. A
    /// lone Esc, Ctrl+X or an escape sequence not complete yet waits for its next key.
    Key,
    /// The shells may run the line with this key: it is held while the line is rated.
    Run(RunKey),
    /// Ctrl+C (in `out`): the shells drop the line.
    Interrupt,
    /// Keys that would run what MultiExec can't rate: they go nowhere, and the text says why.
    Refused(&'static str),
}

/// The line being typed, as far as the keys show it (see the module comment).
#[derive(Debug, Default)]
pub(crate) struct LineBuffer {
    text: String,
    unreliable: bool,
    escape: Escape,
    /// The keys of an escape sequence not resolved yet, held until it is.
    pending: Vec<u8>,
    /// Inside a bracketed paste (`CSI 200 ~` to `CSI 201 ~`): Enter is part of the text.
    paste: bool,
    /// Bytes of a character not complete yet.
    partial: Vec<u8>,
    /// Ctrl+X came: held until the key after it.
    ctrl_x: bool,
    vi: Vi,
    /// The last key was Ctrl+V or Ctrl+Q (quoted insert): an Enter now may go into the line.
    quoted: bool,
    /// Ctrl+R or Ctrl+S: an incremental search, which Ctrl+J ends without running the line.
    search: bool,
    /// After this line's run key the shell may still hold text, or bring a line back.
    leaves_text: bool,
}

impl LineBuffer {
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    pub(crate) fn unreliable(&self) -> bool {
        self.unreliable
    }

    pub(crate) fn mark_unreliable(&mut self) {
        self.unreliable = true;
    }

    /// The shells may hold text after this line's run key (see the table above).
    pub(crate) fn leaves_text(&self) -> bool {
        self.leaves_text
    }

    /// Nothing typed since the line started. Held keys (a lone Esc, Ctrl+X) never reached the shells.
    pub(crate) fn is_empty(&self) -> bool {
        self.text.is_empty() && !self.unreliable && !self.paste
    }

    pub(crate) fn clear(&mut self) {
        *self = LineBuffer::default();
    }

    /// One byte typed. What goes to the terminals now is added to `out`; a run key is not (it is held).
    pub(crate) fn feed(&mut self, byte: u8, out: &mut Vec<u8>) -> Step {
        let quoted = std::mem::take(&mut self.quoted);
        if std::mem::take(&mut self.ctrl_x) {
            match byte {
                CTRL_E => return Step::Refused(EDIT_AND_RUN),
                // `E` is `e` in bash (do-lowercase-version).
                b'e' | b'E' => return Step::Refused(MACRO),
                // Keys that act on their own whatever came before: Ctrl+X goes, then they count as usual.
                b'\r' | b'\n' | CTRL_O | CTRL_C | ESC => {
                    out.push(CTRL_X);
                    self.unreliable = true;
                }
                _ => {
                    out.extend([CTRL_X, byte]);
                    self.unreliable = true;
                    // zsh: Ctrl+X Ctrl+V is vi-cmd-mode.
                    if byte == CTRL_V {
                        self.vi = Vi::Command;
                    }
                    return Step::Key;
                }
            }
        }
        match self.escape {
            Escape::None => self.plain(byte, quoted, out),
            Escape::Started => self.after_esc(byte, out),
            Escape::Csi => self.in_csi(byte, out),
            Escape::Ss3 => self.in_ss3(byte, out),
        }
    }

    /// A byte outside an escape sequence.
    fn plain(&mut self, byte: u8, quoted: bool, out: &mut Vec<u8>) -> Step {
        if byte >= 0x80 {
            out.push(byte);
            self.partial.push(byte);
            match std::str::from_utf8(&self.partial) {
                Ok(text) => {
                    self.text.push_str(text);
                    self.partial.clear();
                }
                Err(err) if err.error_len().is_some() || self.partial.len() >= 4 => self.partial.clear(),
                Err(_) => {}
            }
            return Step::Key;
        }
        self.partial.clear();
        if byte == ESC {
            // Held: the key after it decides (an escape sequence, Alt and a key, or a vi command).
            self.escape = Escape::Started;
            self.pending.push(ESC);
            return Step::Key;
        }
        if self.paste {
            // The shell inserts a bracketed paste as it is, line breaks too, until Enter after it.
            out.push(byte);
            match byte {
                b'\r' | b'\n' => self.text.push('\n'),
                b'\t' => self.text.push(' '),
                b' '..=b'~' => self.text.push(char::from(byte)),
                // How a shell takes other control characters in a paste is up to it.
                _ => self.unreliable = true,
            }
            return Step::Key;
        }
        match byte {
            b'\r' | b'\n' => {
                if quoted || (self.search && byte == b'\n') {
                    self.leaves_text = true;
                }
                return Step::Run(RunKey::Enter(byte));
            }
            CTRL_O => {
                if quoted {
                    self.leaves_text = true;
                }
                return Step::Run(RunKey::CtrlO);
            }
            CTRL_C => {
                // The shell drops the line, whatever it held.
                out.push(byte);
                self.clear();
                return Step::Interrupt;
            }
            CTRL_X => {
                // A prefix: held until the key after it.
                self.ctrl_x = true;
                return Step::Key;
            }
            _ => {}
        }
        if let Some(step) = self.vi_command(byte) {
            return step;
        }
        out.push(byte);
        match byte {
            // Backspace (DEL or ^H).
            0x7f | 0x08 => {
                self.text.pop();
            }
            // Ctrl+U: the line goes (from the cursor back, which is the end unless it moved).
            0x15 => self.text.clear(),
            // Ctrl+W: the word before the cursor goes.
            0x17 => {
                let kept = self.text.trim_end().len();
                self.text.truncate(kept);
                let start = self.text.rfind(char::is_whitespace).map_or(0, |i| i + 1);
                self.text.truncate(start);
            }
            // Ctrl+L clears the screen, Ctrl+D at the end of the line deletes nothing: harmless.
            0x0c | 0x04 => {}
            b' '..=b'~' => self.text.push(char::from(byte)),
            _ => {
                // Tab (completion), Ctrl+R (history search), Ctrl+A/E (cursor), Ctrl+P/N (history),
                // Ctrl+Y (yank), Ctrl+K, Ctrl+T, Ctrl+V, Ctrl+_ ...
                self.unreliable = true;
                self.control(byte);
            }
        }
        Step::Key
    }

    /// What a control key says about the keys after it (see the table above).
    fn control(&mut self, byte: u8) {
        match byte {
            CTRL_V => self.quoted = true,
            // zsh: Ctrl+Q is push-line; elsewhere quoted-insert, like Ctrl+V.
            CTRL_Q => {
                self.quoted = true;
                self.leaves_text = true;
            }
            CTRL_R | CTRL_S => self.search = true,
            _ => {}
        }
    }

    /// A key typed while vi's command mode may be on: `#` runs the line, `v` and `:` are refused, and
    /// the keys that go back to typing end it. `None`: the key is handled as usual.
    fn vi_command(&mut self, byte: u8) -> Option<Step> {
        match self.vi {
            Vi::Insert => {}
            Vi::Argument => self.vi = Vi::Command,
            Vi::ChangeArgument => self.vi = Vi::Insert,
            Vi::Change => {
                self.vi = match byte {
                    b'0'..=b'9' => Vi::Change,
                    b'f' | b'F' | b't' | b'T' => Vi::ChangeArgument,
                    _ => Vi::Insert,
                }
            }
            Vi::Command => match byte {
                b'#' => {
                    self.unreliable = true;
                    return Some(Step::Run(RunKey::Comment));
                }
                b'v' => return Some(Step::Refused(VI_EDIT)),
                b':' => return Some(Step::Refused(VI_NAMED)),
                _ => self.vi_key(byte),
            },
        }
        None
    }

    /// vi's command mode after `byte` (bash binds no `o` or `O` there, so they don't go back to typing).
    fn vi_key(&mut self, byte: u8) {
        match byte {
            b'i' | b'I' | b'a' | b'A' | b's' | b'S' | b'C' | b'R' => self.vi = Vi::Insert,
            b'c' => self.vi = Vi::Change,
            b'r' | b'f' | b'F' | b't' | b'T' | b'm' | b'`' => self.vi = Vi::Argument,
            // A search read up to Enter, which leaves the line found.
            b'/' | b'?' => self.leaves_text = true,
            _ => {}
        }
    }

    /// The key after a lone Esc.
    fn after_esc(&mut self, byte: u8, out: &mut Vec<u8>) -> Step {
        match byte {
            b'[' => {
                self.pending.push(byte);
                self.escape = Escape::Csi;
                Step::Key
            }
            b'O' => {
                self.pending.push(byte);
                self.escape = Escape::Ss3;
                Step::Key
            }
            _ => {
                self.escape = Escape::None;
                self.pending.clear();
                self.alt(byte, out)
            }
        }
    }

    /// Esc and then `byte`, as two keys: Alt and a key, or Esc and a vi command.
    fn alt(&mut self, byte: u8, out: &mut Vec<u8>) -> Step {
        if self.paste {
            // In a bracketed paste the shell takes them as text.
            out.extend([ESC, byte]);
            self.unreliable = true;
            return Step::Key;
        }
        if RunKey::AFTER_ESC.contains(&byte) {
            if matches!(byte, b'#' | b'z') {
                self.unreliable = true;
            }
            return Step::Run(RunKey::Esc(byte));
        }
        match byte {
            b'v' => return Step::Refused(VI_EDIT),
            b'x' => return Step::Refused(NAMED),
            CTRL_C => {
                out.extend([ESC, CTRL_C]);
                self.clear();
                return Step::Interrupt;
            }
            _ => {}
        }
        out.push(ESC);
        self.unreliable = true;
        self.vi = Vi::Command;
        match byte {
            // The first Esc goes; the second waits for its own next key.
            ESC => {
                self.escape = Escape::Started;
                self.pending.push(ESC);
            }
            CTRL_X => self.ctrl_x = true,
            _ => {
                out.push(byte);
                match byte {
                    // zsh: push-line; bash: a history search read up to Enter.
                    b'q' | b'Q' | b'p' | b'n' => self.leaves_text = true,
                    0..=0x1f | 0x7f => self.control(byte),
                    _ => self.vi_key(byte),
                }
            }
        }
        Step::Key
    }

    /// A byte of a CSI sequence (Esc [). A key's sequence goes on whole once it ends.
    fn in_csi(&mut self, byte: u8, out: &mut Vec<u8>) -> Step {
        match byte {
            0x30..=0x3f if self.pending.len() < 32 => {
                self.pending.push(byte);
                Step::Key
            }
            // No key sends `v` here; read as keys, it would be vi's edit-and-execute.
            0x40..=0x7e if byte != b'v' => {
                self.escape = Escape::None;
                let params = String::from_utf8_lossy(&self.pending[2..]).into_owned();
                out.append(&mut self.pending);
                out.push(byte);
                match (params.as_str(), byte) {
                    ("200", b'~') => self.paste = true,
                    ("201", b'~') => self.paste = false,
                    // Focus in and out: the terminal reports it, the line is untouched.
                    ("", b'I' | b'O') => {}
                    // Arrows, Home, End, Delete, Page Up...: the cursor moved or history changed.
                    _ => self.unreliable = true,
                }
                Step::Key
            }
            _ => self.broken(byte, out),
        }
    }

    /// The byte after Esc O: arrows, Home, End, F1 to F4 and the keypad in application mode.
    fn in_ss3(&mut self, byte: u8, out: &mut Vec<u8>) -> Step {
        match byte {
            b'M' if !self.paste => {
                self.escape = Escape::None;
                self.pending.clear();
                Step::Run(RunKey::KeypadEnter)
            }
            b'A'..=b'Z' | b'a'..=b'z' => {
                self.escape = Escape::None;
                out.append(&mut self.pending);
                out.push(byte);
                self.unreliable = true;
                Step::Key
            }
            _ => self.broken(byte, out),
        }
    }

    /// The escape sequence so far, and `byte`, are no key: the shells read them one by one (Esc and
    /// the next key, then each other key), and so does MultiExec.
    fn broken(&mut self, byte: u8, out: &mut Vec<u8>) -> Step {
        self.escape = Escape::None;
        let mut keys = std::mem::take(&mut self.pending);
        keys.push(byte);
        if self.paste {
            out.extend(keys);
            self.unreliable = true;
            return Step::Key;
        }
        // What a shell makes of them is not known.
        self.leaves_text = true;
        let mut step = self.alt(keys[1], out);
        for byte in keys.into_iter().skip(2) {
            if step != Step::Key {
                break;
            }
            step = self.feed(byte, out);
        }
        step
    }
}

/// SS-10: the later lines of a paste of several lines (without bracketed paste), after its first
/// line's Enter.
#[derive(Debug, Default)]
pub(crate) struct Paste {
    pub(crate) lines: Vec<String>,
    pub(crate) unreliable: bool,
    /// The bytes they take: up to and with the last Enter.
    pub(crate) len: usize,
}

/// The lines in `keys` that go with a first line's Enter: each ends with Enter. They stop before a
/// line that ends another way (another run key, keys after which the shell may hold text, a refused
/// key, or no Enter yet): those keys are typed, and rated, once the first line has gone.
pub(crate) fn paste_lines(keys: &[u8]) -> Paste {
    let mut paste = Paste::default();
    let mut scan = LineBuffer::default();
    let mut out = Vec::new();
    for (i, byte) in keys.iter().enumerate() {
        match scan.feed(*byte, &mut out) {
            Step::Key => {}
            // Ctrl+C after Enter: the shells drop that line, not the one already run.
            Step::Interrupt => scan.clear(),
            Step::Run(run) if run.is_enter() && !scan.leaves_text() => {
                paste.lines.push(scan.text().to_owned());
                paste.unreliable |= scan.unreliable();
                scan.clear();
                paste.len = i + 1;
            }
            Step::Run(_) | Step::Refused(_) => break,
        }
    }
    paste
}

/// SS-10, for the command bus and the job runner: the `keys` of a [`Command::TerminalLine`] are one
/// [`RunKey`], and after an Enter only a paste's later lines, each with its Enter, that `line` (what
/// was rated) ends with. So nothing reaches the terminals that was not rated.
pub(crate) fn check_keys(line: &str, keys: &[u8], unreliable: bool) -> std::result::Result<(), String> {
    let Some((run, len)) = RunKey::parse(keys) else {
        return Err("A MultiExec line is sent with the key that runs it (Enter, Ctrl+O...).".into());
    };
    let rest = &keys[len..];
    if rest.is_empty() {
        return Ok(());
    }
    if !run.is_enter() {
        return Err(format!(
            "A MultiExec line sent with {} goes with no other keys.",
            run.label()
        ));
    }
    let paste = paste_lines(rest);
    if paste.len != rest.len() {
        return Err("A MultiExec line's keys end with the Enter of its last line.".into());
    }
    if paste.unreliable && !unreliable {
        return Err("A MultiExec line's keys hold keys Remotely can't follow, and the line doesn't say so.".into());
    }
    let tail = paste.lines.join("\n");
    let tail = tail.trim_end();
    if !tail.trim().is_empty() && !line.trim_end().ends_with(&format!("\n{tail}")) {
        return Err("A MultiExec line's keys hold lines that were not rated.".into());
    }
    Ok(())
}

// ---- What the UI sees ------------------------------------------------------------------------------

/// How a line's keys are handled, from the screen of the terminal typed into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LineMode {
    /// A shell (or a program reading lines): Enter is held and the line rated.
    Command,
    /// A password, passphrase or one-time code prompt: keys pass straight through, unrated and unlogged.
    Password,
    /// A full-screen program: keys pass straight through.
    FullScreen,
}

/// A target that did not get a line's keys, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeftOut {
    pub terminal_id: Uuid,
    pub reason: String,
}

/// What happened to keys sent to [`MultiExec::input`].
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum InputOutcome {
    /// The keys went to `reached`.
    Typed {
        mode: LineMode,
        reached: Vec<Uuid>,
        left_out: Vec<LeftOut>,
    },
    /// The terminal typed into is not a MultiExec target (or can't be one now): the keys went to it
    /// alone, as typing normally does.
    Alone { reason: String },
    /// Enter (or another [`RunKey`]) is held while the line is rated. Low: `job_id` sends it. Higher:
    /// answer `request` with [`MultiExec::approve`] or [`MultiExec::cancel`].
    Held {
        line_id: Uuid,
        tier: Tier,
        reached: Vec<Uuid>,
        left_out: Vec<LeftOut>,
        job_id: Option<Uuid>,
        request: Option<Box<ApprovalRequest>>,
        /// The key that runs the line once it may ([`RunKey::label`]): "Enter", "Ctrl+O"...
        run_key: String,
    },
    /// A line waits for its Enter; these keys follow it once it is sent.
    Queued { line_id: Uuid, dropped: bool },
    /// Keys that would run what MultiExec can't rate (Ctrl+X Ctrl+E, `v` after Esc...) were not sent,
    /// and neither was anything typed after them in the same input; `reason` says why. The keys before
    /// them went to `reached`.
    Refused {
        reason: String,
        reached: Vec<Uuid>,
        left_out: Vec<LeftOut>,
    },
}

/// Sent as lines finish, and for lines held while earlier keys were replayed.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum MultiExecEvent {
    /// A held line ended: its run key went out (`sent`), or the line was cancelled and Ctrl+C went out.
    LineDone {
        line_id: Uuid,
        sent: bool,
        terminals: usize,
        status: Option<JobStatus>,
        /// The key that ran it ([`RunKey::label`]): "Enter", "Ctrl+O"...
        run_key: String,
    },
    /// Keys that waited for a line were sent, and held another line (which may need approval), or
    /// some of them were refused.
    Outcome { outcome: InputOutcome },
    /// QL-12: the recorded lines changed: `line_id` was recorded or one of its terminals started or
    /// finished; `None` when several went at once (a cap, MultiExec turned off, terminals closed).
    Recorded { line_id: Option<Uuid> },
    /// QL-12, QL-07: every terminal of a recorded line is done. Once per line, never per terminal.
    /// `terminals`: the ones Enter reached; `unfinished`: those whose recording did not end well (time
    /// limit, connection lost, never sent).
    LineFinished {
        line_id: Uuid,
        line: String,
        /// The terminals Enter reached, so the UI knows their tabs.
        terminal_ids: Vec<Uuid>,
        terminals: usize,
        after_secs: u64,
        how: FinishedHow,
        unfinished: usize,
    },
}

/// One target as MultiExec sees it now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetState {
    pub terminal_id: Uuid,
    pub name: String,
    /// Gets what is typed now.
    pub receives: bool,
    /// Why not, when it does not.
    pub reason: Option<String>,
    /// How it gets keys when they pass straight through: at a password prompt, or to a full-screen
    /// program.
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiExecStatus {
    pub on: bool,
    pub targets: Vec<TargetState>,
    /// The line waiting for its Enter, if any.
    pub held: Option<Uuid>,
}

// ---- The service -----------------------------------------------------------------------------------

/// The line being typed: where its keys go and how they are handled.
#[derive(Debug, Clone)]
struct Current {
    mode: LineMode,
    to: Vec<Uuid>,
    left_out: Vec<LeftOut>,
}

/// A line whose Enter waits.
struct Held {
    id: Uuid,
    /// The terminal typed into: the keys that wait are its own.
    from: Uuid,
    to: Vec<Uuid>,
    /// What came after the line's keys in the same input, sent once it is.
    after: Vec<u8>,
    request: Option<Uuid>,
    job: Option<Uuid>,
    /// Once its keys went, the shells may still hold text on their line ([`LineBuffer::leaves_text`],
    /// or a [`RunKey`] other than Enter): the next line there is unreliable.
    leaves_text: bool,
    /// [`RunKey::label`], for the UI's note once it is sent.
    run_key: &'static str,
}

#[derive(Default)]
struct State {
    on: bool,
    targets: Vec<Uuid>,
    buffer: LineBuffer,
    current: Option<Current>,
    held: Option<Held>,
    queued: Vec<u8>,
}

struct Shared {
    /// FD-02: the workspace shown, whose terminals MultiExec types into.
    workspace: crate::workspaces::Current,
    terminals: Terminals,
    bus: Arc<CommandBus>,
    jobs: Arc<JobRunner>,
    state: Mutex<State>,
    events: broadcast::Sender<MultiExecEvent>,
    /// QL-12.
    recorder: Recorder,
}

/// SS-10 (see the module comment). One per app: the Terminal page is the only place to type.
#[derive(Clone)]
pub struct MultiExec {
    shared: Arc<Shared>,
}

/// What a target's screen and session say about a line starting now.
#[derive(Clone)]
struct Seen {
    id: Uuid,
    name: String,
    connected: bool,
    protected: bool,
    password: bool,
    alternate: bool,
    dirty: bool,
}

impl MultiExec {
    pub fn new(
        workspace: crate::workspaces::Current,
        terminals: Terminals,
        bus: Arc<CommandBus>,
        jobs: Arc<JobRunner>,
    ) -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            shared: Arc::new(Shared {
                workspace,
                terminals,
                bus,
                jobs,
                state: Mutex::new(State::default()),
                recorder: Recorder::new(events.clone()),
                events,
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MultiExecEvent> {
        self.shared.events.subscribe()
    }

    // ---- QL-12: recordings ----------------------------------------------------------------------------

    /// The caps and the per-line time limit (tests shorten them).
    pub fn set_record_limits(&self, limits: RecordLimits) {
        self.shared.recorder.set_limits(limits);
    }

    fn alive(&self) -> impl Fn(Uuid) -> bool + '_ {
        |id| self.shared.terminals.pane_info(id).is_some()
    }

    /// The lines recorded in this MultiExec session, newest first.
    pub fn recordings(&self) -> Recordings {
        self.shared.recorder.list(&self.alive())
    }

    /// One recorded line, grouped by output like a Compare run (BX-03).
    pub fn recorded(&self, line_id: Uuid, opts: GroupOptions) -> Result<RecordedResults> {
        self.shared.recorder.results(line_id, opts, &self.alive())
    }

    /// One terminal's recorded output of a line (so far, while it runs).
    pub fn recorded_output(&self, line_id: Uuid, terminal_id: Uuid) -> Result<HostOutput> {
        self.shared.recorder.output(line_id, terminal_id)
    }

    /// BX-03's diff between two terminals' outputs of a line.
    pub fn recorded_diff(&self, line_id: Uuid, left: Uuid, right: Uuid, opts: GroupOptions) -> Result<OutputDiff> {
        self.shared.recorder.diff(line_id, left, right, opts)
    }

    /// A recorded line, or all of them (`None`), for `BulkRuns::export_recorded`.
    pub fn recorded_runs(&self, line_id: Option<Uuid>) -> Result<Vec<RecordedRun>> {
        self.shared.recorder.runs(line_id)
    }

    /// Turns MultiExec on for these terminals, or changes them. A line being typed keeps going to the
    /// targets it started with that are still picked; ones picked meanwhile join at the next line.
    pub async fn set_targets(&self, targets: Vec<Uuid>) -> Result<MultiExecStatus> {
        self.shared.bus.read_only().check(Change::MultiExec)?;
        let mut seen = HashSet::new();
        let targets: Vec<Uuid> = targets.into_iter().filter(|id| seen.insert(*id)).collect();
        let mut state = self.shared.state.lock().await;
        state.on = true;
        if let Some(current) = &mut state.current {
            let dropped: Vec<Uuid> = current.to.iter().filter(|id| !targets.contains(id)).copied().collect();
            current.to.retain(|id| targets.contains(id));
            // Part of a line is on their screens now, which MultiExec no longer follows there.
            if current.mode == LineMode::Command {
                for id in dropped {
                    self.shared.terminals.set_dirty(id, true);
                }
            }
        }
        state.targets = targets;
        self.status_of(&state).await
    }

    /// Turns MultiExec off. A line waiting for approval is cancelled (Ctrl+C to its terminals); one
    /// already approved goes ahead. QL-12: the session's recordings go.
    pub async fn stop(&self) -> Result<MultiExecStatus> {
        self.shared.recorder.clear();
        let mut state = self.shared.state.lock().await;
        if let Some(held) = state.held.take() {
            match held.job {
                // In its countdown, cancelling it still stops it; the line then gets Ctrl+C.
                Some(job) => {
                    if self.shared.jobs.cancel(job) {
                        self.interrupt(&held.to).await;
                    } else if held.leaves_text {
                        // Its keys went, and the shells may still hold text.
                        for id in &held.to {
                            self.shared.terminals.set_dirty(*id, true);
                        }
                    }
                }
                None => {
                    if let Some(request) = held.request {
                        self.shared.bus.cancel_approval(request).await?;
                    }
                    self.interrupt(&held.to).await;
                }
            }
            self.done(&held, false, None);
        }
        if let Some(current) = state.current.take() {
            if current.mode == LineMode::Command && !state.buffer.is_empty() {
                for id in current.to {
                    self.shared.terminals.set_dirty(id, true);
                }
            }
        }
        *state = State::default();
        self.status_of(&state).await
    }

    pub async fn status(&self) -> Result<MultiExecStatus> {
        let state = self.shared.state.lock().await;
        self.status_of(&state).await
    }

    async fn status_of(&self, state: &State) -> Result<MultiExecStatus> {
        let mut targets = Vec::with_capacity(state.targets.len());
        for id in &state.targets {
            let seen = self.seen(*id).await;
            let reason = match &seen {
                None => Some("closed".to_owned()),
                Some(s) if s.protected => Some("protected: Type in all tabs leaves it out".to_owned()),
                Some(s) if !s.connected => Some("not connected".to_owned()),
                Some(_) => None,
            };
            let note = match &seen {
                Some(s) if reason.is_none() && s.alternate => {
                    Some("a full-screen program is open: keys pass straight through".to_owned())
                }
                Some(s) if reason.is_none() && s.password => {
                    Some("at a password prompt: keys pass straight through, never logged".to_owned())
                }
                _ => None,
            };
            targets.push(TargetState {
                terminal_id: *id,
                name: seen.map(|s| s.name).unwrap_or_else(|| "a closed terminal".into()),
                receives: reason.is_none(),
                reason,
                note,
            });
        }
        Ok(MultiExecStatus {
            on: state.on,
            targets,
            held: state.held.as_ref().map(|h| h.id),
        })
    }

    /// Keys typed into terminal `from` (raw bytes, as xterm.js sends them).
    pub async fn input(&self, from: Uuid, data: Vec<u8>) -> Result<InputOutcome> {
        let mut state = self.shared.state.lock().await;
        if let Some(held) = &state.held {
            if state.targets.contains(&from) || held.from == from {
                let line_id = held.id;
                let room = MAX_QUEUED_BYTES.saturating_sub(state.queued.len());
                let dropped = data.len() > room;
                state.queued.extend_from_slice(&data[..data.len().min(room)]);
                return Ok(InputOutcome::Queued { line_id, dropped });
            }
        }
        let outcome = self.process(&mut state, from, data).await?;
        Ok(outcome)
    }

    /// Answers the approval of a held line; once the job sends Enter, keys that waited follow.
    pub async fn approve(&self, line_id: Uuid, answers: ApprovalAnswers) -> Result<Uuid> {
        let mut state = self.shared.state.lock().await;
        let held = state
            .held
            .as_mut()
            .filter(|h| h.id == line_id)
            .ok_or_else(|| CoreError::InvalidInput("That MultiExec line is no longer waiting.".into()))?;
        let (Some(request), None) = (held.request, held.job) else {
            return Err(CoreError::InvalidInput(
                "That MultiExec line does not wait for an approval.".into(),
            ));
        };
        let job = self.shared.bus.approve(request, answers).await?;
        held.job = Some(job);
        self.shared.recorder.approved(line_id, job);
        self.wait_for(line_id, job);
        Ok(job)
    }

    /// Cancels a held line: its approval, or its job's countdown. Every terminal it went to gets
    /// Ctrl+C, which clears the line; keys typed after it are dropped.
    pub async fn cancel(&self, line_id: Uuid) -> Result<()> {
        let mut state = self.shared.state.lock().await;
        let Some(held) = state.held.as_ref().filter(|h| h.id == line_id) else {
            return Ok(());
        };
        if let Some(job) = held.job {
            // The job's end lets the line go (with Ctrl+C if it was cancelled in time).
            self.shared.jobs.cancel(job);
            return Ok(());
        }
        let request = held.request;
        if let Some(request) = request {
            self.shared.bus.cancel_approval(request).await?;
        }
        if let Some(held) = state.held.take() {
            state.queued.clear();
            self.interrupt(&held.to).await;
            self.shared.recorder.discard(held.id);
            self.done(&held, false, None);
        }
        Ok(())
    }

    fn done(&self, held: &Held, sent: bool, status: Option<JobStatus>) {
        let _ = self.shared.events.send(MultiExecEvent::LineDone {
            line_id: held.id,
            sent,
            terminals: held.to.len(),
            status,
            run_key: held.run_key.to_owned(),
        });
    }

    /// Ctrl+C to each terminal: the line it holds goes.
    async fn interrupt(&self, to: &[Uuid]) {
        for id in to {
            let _ = self.shared.terminals.send_keys(*id, &[CTRL_C]).await;
            self.shared.terminals.set_dirty(*id, false);
        }
    }

    /// Lets the line go once its job has ended (in the background).
    fn wait_for(&self, line_id: Uuid, job: Uuid) {
        let this = self.clone();
        tokio::spawn(async move {
            let status = this.shared.jobs.wait(job).await.unwrap_or(JobStatus::Failed);
            if let Err(err) = this.release(line_id, status).await {
                tracing::warn!(error = %err, "MultiExec could not send the keys that waited for a line");
            }
        });
    }

    /// The held line's job ended: Enter went out, or (cancelled) it did not and Ctrl+C clears the line.
    async fn release(&self, line_id: Uuid, status: JobStatus) -> Result<()> {
        let mut state = self.shared.state.lock().await;
        if state.held.as_ref().map(|h| h.id) != Some(line_id) {
            return Ok(());
        }
        let Some(held) = state.held.take() else {
            return Ok(());
        };
        let queued = std::mem::take(&mut state.queued);
        let terminals = &self.shared.terminals;
        self.shared
            .recorder
            .job_ended(line_id, status == JobStatus::Cancelled, |id| {
                terminals.pane_info(id).is_some_and(|i| i.screen.connected)
            });
        if status == JobStatus::Cancelled {
            self.interrupt(&held.to).await;
            self.done(&held, false, Some(status));
            return Ok(());
        }
        for id in &held.to {
            self.shared.terminals.set_dirty(*id, held.leaves_text);
        }
        self.done(&held, true, Some(status));
        let mut rest = held.after;
        rest.extend_from_slice(&queued);
        if !rest.is_empty() && state.on {
            let outcome = self.process(&mut state, held.from, rest).await?;
            if matches!(outcome, InputOutcome::Held { .. } | InputOutcome::Refused { .. }) {
                let _ = self.shared.events.send(MultiExecEvent::Outcome { outcome });
            }
        }
        Ok(())
    }

    /// What a terminal's screen and session say now; `None` once it has closed.
    async fn seen(&self, id: Uuid) -> Option<Seen> {
        let info = self.shared.terminals.pane_info(id)?;
        let target = self
            .shared
            .terminals
            .target(&self.shared.workspace.get(), id)
            .await
            .ok();
        Some(Seen {
            id,
            name: target.as_ref().map_or_else(|| info.name.clone(), |t| t.name.clone()),
            connected: info.screen.connected,
            protected: target.is_some_and(|t| t.protected),
            password: info.screen.at_secret_prompt(),
            alternate: info.screen.alternate,
            dirty: info.dirty,
        })
    }

    /// A line starts in `from`: how its keys are handled, and which targets get them.
    async fn start_line(&self, state: &mut State, from: &Seen) -> Current {
        let mode = if from.alternate {
            LineMode::FullScreen
        } else if from.password {
            LineMode::Password
        } else {
            LineMode::Command
        };
        let mut to = Vec::new();
        let mut left_out = Vec::new();
        let mut dirty = false;
        for id in state.targets.clone() {
            let seen = if id == from.id {
                Some(from.clone())
            } else {
                self.seen(id).await
            };
            let Some(seen) = seen else {
                continue;
            };
            let reason = if seen.protected {
                Some("protected")
            } else if !seen.connected {
                Some("not connected")
            } else {
                match mode {
                    LineMode::FullScreen if !seen.alternate => Some("no full-screen program is open"),
                    LineMode::Password if seen.alternate || !seen.password => Some("not at a password prompt"),
                    LineMode::Command if seen.alternate => Some("a full-screen program is open"),
                    LineMode::Command if seen.password => Some("at a password prompt"),
                    _ => None,
                }
            };
            match reason {
                Some(reason) => left_out.push(LeftOut {
                    terminal_id: id,
                    reason: reason.into(),
                }),
                None => {
                    dirty |= seen.dirty;
                    to.push(id);
                }
            }
        }
        state.buffer.clear();
        if mode == LineMode::Command && dirty {
            // Text was typed on some line outside MultiExec: what the shells hold is not known.
            state.buffer.mark_unreliable();
        }
        Current { mode, to, left_out }
    }

    async fn send(&self, to: &[Uuid], bytes: &[u8], left_out: &mut Vec<LeftOut>) -> Vec<Uuid> {
        let mut reached = Vec::with_capacity(to.len());
        if bytes.is_empty() {
            return to.to_vec();
        }
        for id in to {
            match self.shared.terminals.send_keys(*id, bytes).await {
                Ok(()) => reached.push(*id),
                Err(_) => {
                    if !left_out.iter().any(|l| l.terminal_id == *id) {
                        left_out.push(LeftOut {
                            terminal_id: *id,
                            reason: "not connected".into(),
                        });
                    }
                }
            }
        }
        reached
    }

    /// Handles keys from `from` until they end or a line is held.
    async fn process(&self, state: &mut State, from: Uuid, data: Vec<u8>) -> Result<InputOutcome> {
        let from_seen = self.seen(from).await;
        let alone = match &from_seen {
            _ if !state.on => Some("MultiExec is off"),
            _ if !state.targets.contains(&from) => Some("this terminal is not picked for MultiExec"),
            None => Some("this terminal has closed"),
            Some(s) if s.protected => Some("this terminal's session is protected, so MultiExec leaves it out"),
            Some(s) if !s.connected => Some("this terminal is not connected"),
            Some(_) => None,
        };
        let Some(from_seen) = from_seen.filter(|_| alone.is_none()) else {
            self.shared.terminals.write(from, data).await;
            return Ok(InputOutcome::Alone {
                reason: alone.unwrap_or_default().to_owned(),
            });
        };

        let mut at = 0;
        let mut last = InputOutcome::Typed {
            mode: LineMode::Command,
            reached: Vec::new(),
            left_out: Vec::new(),
        };
        while at < data.len() {
            if state.current.is_none() {
                // A new line: the screen as it is now decides.
                let seen = match at {
                    0 => from_seen.clone(),
                    _ => self.seen(from).await.unwrap_or_else(|| from_seen.clone()),
                };
                let current = self.start_line(state, &seen).await;
                state.current = Some(current);
            }
            let Some(current) = state.current.clone() else {
                break;
            };
            match current.mode {
                LineMode::FullScreen => {
                    // A full-screen program reads keys, not lines: all of them, straight through.
                    let mut left_out = current.left_out.clone();
                    let reached = self.send(&current.to, &data[at..], &mut left_out).await;
                    state.current = None;
                    return Ok(InputOutcome::Typed {
                        mode: LineMode::FullScreen,
                        reached,
                        left_out,
                    });
                }
                LineMode::Password => {
                    // Straight through up to and with Enter (or Ctrl+C), never kept.
                    let end = data[at..]
                        .iter()
                        .position(|b| matches!(*b, b'\r' | b'\n' | CTRL_C))
                        .map(|i| at + i + 1);
                    let stop = end.unwrap_or(data.len());
                    let mut left_out = current.left_out.clone();
                    let reached = self.send(&current.to, &data[at..stop], &mut left_out).await;
                    if end.is_some() {
                        state.current = None;
                    }
                    at = stop;
                    last = InputOutcome::Typed {
                        mode: LineMode::Password,
                        reached,
                        left_out,
                    };
                }
                LineMode::Command => {
                    // What goes to the terminals now: the keys typed, not a held prefix or run key.
                    let mut out = Vec::new();
                    let mut end = Step::Key;
                    while at < data.len() {
                        let byte = data[at];
                        at += 1;
                        end = state.buffer.feed(byte, &mut out);
                        if end != Step::Key {
                            break;
                        }
                    }
                    let mut left_out = current.left_out.clone();
                    let reached = self.send(&current.to, &out, &mut left_out).await;
                    match end {
                        Step::Key => {}
                        Step::Interrupt => {
                            // The shells drop the line; the next keys start a new one.
                            state.current = None;
                            state.buffer.clear();
                            for id in &current.to {
                                self.shared.terminals.set_dirty(*id, false);
                            }
                        }
                        Step::Refused(reason) => {
                            // Neither those keys nor what came after them: the user is told why.
                            return Ok(InputOutcome::Refused {
                                reason: reason.to_owned(),
                                reached,
                                left_out,
                            });
                        }
                        Step::Run(run) => {
                            return self
                                .enter(state, from, &current, run, &data[at..], reached, left_out)
                                .await;
                        }
                    }
                    last = InputOutcome::Typed {
                        mode: LineMode::Command,
                        reached,
                        left_out,
                    };
                }
            }
        }
        Ok(last)
    }

    /// The line runs with `run` (Enter, or another [`RunKey`]): the line (with the later lines of the
    /// same paste in `rest`) is rated, and the run key is held unless it is Enter on an empty line.
    #[allow(clippy::too_many_arguments)]
    async fn enter(
        &self,
        state: &mut State,
        from: Uuid,
        current: &Current,
        run: RunKey,
        rest: &[u8],
        reached: Vec<Uuid>,
        left_out: Vec<LeftOut>,
    ) -> Result<InputOutcome> {
        let mut lines = vec![as_run(state.buffer.text(), run)];
        let mut unreliable = state.buffer.unreliable();
        let leaves_text = !run.is_enter() || state.buffer.leaves_text();
        // A paste of several lines is one script: its later lines go with the first one's Enter (only
        // after an Enter that leaves the shell's line empty, and as text the keys can carry).
        let mut take = 0;
        if !leaves_text {
            let paste = paste_lines(rest);
            if std::str::from_utf8(&rest[..paste.len]).is_ok() {
                take = paste.len;
                lines.extend(paste.lines);
                unreliable |= paste.unreliable;
            }
        }
        let mut keys = run.keys();
        keys.extend_from_slice(&rest[..take]);
        let after = rest[take..].to_vec();
        let script = lines.join("\n").trim_end().to_owned();
        // Another key than Enter on an empty line may still do something: it is rated.
        unreliable |= script.trim().is_empty() && !run.is_enter();
        state.buffer.clear();
        state.current = None;

        let to = current.to.clone();
        if to.is_empty() {
            return Ok(InputOutcome::Typed {
                mode: LineMode::Command,
                reached,
                left_out,
            });
        }
        let screen = self.shared.terminals.pane_info(from).map(|i| i.screen.line);
        let typed = script.lines().next().unwrap_or_default();
        if screen.is_some_and(|screen| typed_into_secret_prompt(&screen, typed)) {
            // A password typed ahead of its prompt: never rated, journaled or audited, and not sent.
            self.interrupt(&to).await;
            return Ok(InputOutcome::Refused {
                reason: "A password prompt came up while you typed, so what you typed went into it and was not \
                         sent. Type it again at the prompt."
                    .into(),
                reached,
                left_out,
            });
        }
        if script.trim().is_empty() && !unreliable && keys.iter().all(|b| matches!(*b, b'\r' | b'\n')) {
            // Enter on an empty line runs nothing: no rating, no audit.
            let mut left_out = left_out;
            let reached = self.send(&to, &keys, &mut left_out).await;
            if after.is_empty() {
                return Ok(InputOutcome::Typed {
                    mode: LineMode::Command,
                    reached,
                    left_out,
                });
            }
            return Box::pin(self.process(state, from, after)).await;
        }

        let line_id = Uuid::new_v4();
        // QL-12: each terminal gets its recording before anything can send the Enter (a Low line's
        // job may run before `submit` returns), through its input, so it comes first.
        let names: Vec<(Uuid, String)> = to
            .iter()
            .map(|id| {
                let name = self.shared.terminals.pane_info(*id).map(|i| i.name);
                (*id, name.unwrap_or_else(|| "a closed terminal".into()))
            })
            .collect();
        for slot in self.shared.recorder.begin(line_id, &script, &names) {
            self.shared.terminals.record(slot).await;
        }
        let command = Command::TerminalLine {
            targets: to
                .iter()
                .map(|id| TargetRef::Terminal {
                    terminal_id: *id,
                    session_id: None,
                })
                .collect(),
            line: script,
            unreliable,
            // Valid UTF-8: the run key is ASCII, and a paste's lines are taken only when they are.
            keys: String::from_utf8_lossy(&keys).into_owned(),
        };
        let outcome = match self.shared.bus.submit(&self.shared.workspace.get(), command).await {
            Ok(outcome) => outcome,
            Err(err) => {
                // Nothing will press Enter: clear the line the terminals hold, so it can't run later.
                self.shared.recorder.discard(line_id);
                self.interrupt(&to).await;
                return Err(err);
            }
        };
        let (tier, job_id, request) = match outcome {
            SubmitOutcome::Queued { job_id, tier, .. } => (tier, Some(job_id), None),
            SubmitOutcome::NeedsApproval { request } => (request.tier, None, Some(Box::new(request))),
        };
        self.shared.recorder.taken(line_id, tier, job_id);
        state.held = Some(Held {
            id: line_id,
            from,
            to,
            after,
            request: request.as_ref().map(|r| r.id),
            job: job_id,
            leaves_text,
            run_key: run.label(),
        });
        if let Some(job) = job_id {
            self.wait_for(line_id, job);
        }
        Ok(InputOutcome::Held {
            line_id,
            tier,
            reached,
            left_out,
            job_id,
            request,
            run_key: run.label().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_typed_into_a_prompt_that_came_up_late_is_a_secret() {
        for (screen, typed) in [
            ("[sudo] password for alice: ", "hunter2"),
            ("Password: ", "correct horse"),
            ("Verification code: ", "123456"),
            ("Enter passphrase for key '/home/alice/.ssh/id_ed25519': ", "x y z"),
        ] {
            assert!(typed_into_secret_prompt(screen, typed), "{screen:?} {typed:?}");
        }
        for (screen, typed) in [
            // Echoed: the shell has the line, whatever it says.
            ("alice@web01:~$ echo Password:", "echo Password:"),
            ("alice@web01:~$ uptime", "uptime"),
            ("alice@web01:~$ ", "uptime"),
            // Nothing typed: Enter alone at the prompt.
            ("[sudo] password for alice: ", ""),
            ("[sudo] password for alice: ", "  "),
            ("Do you want to continue? [Y/n] ", "y"),
        ] {
            assert!(!typed_into_secret_prompt(screen, typed), "{screen:?} {typed:?}");
        }
    }

    /// Feeds `keys`, returning the line, whether it is unreliable, and the steps that were not keys.
    fn typed(keys: &[u8]) -> (String, bool, Vec<Step>) {
        let mut buffer = LineBuffer::default();
        let mut out = Vec::new();
        let steps = keys
            .iter()
            .map(|b| buffer.feed(*b, &mut out))
            .filter(|s| *s != Step::Key)
            .collect();
        (buffer.text().to_owned(), buffer.unreliable(), steps)
    }

    /// Feeds `keys` as `process` does, up to the first step that is not a key: what went to the
    /// terminals, that step (`Step::Key` when the keys ran out), and the buffer.
    fn sent(keys: &[u8]) -> (Vec<u8>, Step, LineBuffer) {
        let mut buffer = LineBuffer::default();
        let mut out = Vec::new();
        let mut end = Step::Key;
        for key in keys {
            end = buffer.feed(*key, &mut out);
            if end != Step::Key {
                break;
            }
        }
        (out, end, buffer)
    }

    #[test]
    fn printable_keys_backspace_and_line_editing_are_followed() {
        assert_eq!(typed(b"uptime"), ("uptime".into(), false, vec![]));
        assert_eq!(typed(b"uptimx\x7fe").0, "uptime");
        assert_eq!(typed(b"ls\x08\x08df -h").0, "df -h");
        assert_eq!(typed(b"rm -rf /tmp/x\x15uptime").0, "uptime", "Ctrl+U clears the line");
        assert_eq!(
            typed(b"systemctl restart nginx  \x17status").0,
            "systemctl restart status"
        );
        assert_eq!(typed("echo café".as_bytes()).0, "echo café");
        assert_eq!(typed(b"\x0cuptime").0, "uptime", "Ctrl+L only clears the screen");
        let (text, unreliable, steps) = typed(b"uptime\r");
        assert_eq!((text.as_str(), unreliable), ("uptime", false));
        assert_eq!(steps, [Step::Run(RunKey::Enter(b'\r'))]);
    }

    #[test]
    fn typed_keys_go_to_the_terminals_one_by_one() {
        let mut buffer = LineBuffer::default();
        for (i, key) in b"rm -i x\x7f\x15ls\t".iter().enumerate() {
            let mut out = Vec::new();
            assert_eq!(buffer.feed(*key, &mut out), Step::Key, "key {i}");
            assert_eq!(out, [*key], "key {i} goes at once");
        }
        let (out, end, _) = sent("echo café".as_bytes());
        assert_eq!((out.as_slice(), end), ("echo café".as_bytes(), Step::Key));
    }

    #[test]
    fn ctrl_o_is_held_and_rated_like_enter() {
        let (out, end, buffer) = sent(b"systemctl restart nginx\x0f");
        assert_eq!(out, b"systemctl restart nginx", "Ctrl+O itself is held");
        assert_eq!(end, Step::Run(RunKey::CtrlO));
        assert_eq!(buffer.text(), "systemctl restart nginx");
        assert!(!buffer.unreliable(), "it runs the line as typed");
        assert_eq!(RunKey::CtrlO.keys(), [CTRL_O]);
        assert!(!RunKey::CtrlO.is_enter(), "the next history line comes up after it");
    }

    #[test]
    fn a_lone_esc_waits_for_the_key_after_it_and_esc_enter_is_held() {
        let mut buffer = LineBuffer::default();
        let mut out = Vec::new();
        for key in b"ls -l\x1b" {
            assert_eq!(buffer.feed(*key, &mut out), Step::Key);
        }
        assert_eq!(out, b"ls -l", "Esc waits, even across inputs");
        assert_eq!(buffer.feed(b'\r', &mut out), Step::Run(RunKey::Esc(b'\r')));
        assert_eq!(out, b"ls -l", "Esc and Enter are held together");
        assert_eq!(RunKey::Esc(b'\r').keys(), b"\x1b\r");
        assert_eq!(buffer.text(), "ls -l");

        for key in [b'\n', CTRL_O, b'a', b'A', CTRL_E, b'z', b'#'] {
            let (out, end, _) = sent(&[b'l', b's', ESC, key]);
            assert_eq!(
                (out.as_slice(), end),
                (&b"ls"[..], Step::Run(RunKey::Esc(key))),
                "Esc {key}"
            );
        }
        // Alt+Enter from xterm.js is the same pair.
        assert_eq!(sent(b"uptime\x1b\r").1, Step::Run(RunKey::Esc(b'\r')));
        // The keypad's Enter in application mode.
        let (out, end, _) = sent(b"uptime\x1bOM");
        assert_eq!((out.as_slice(), end), (&b"uptime"[..], Step::Run(RunKey::KeypadEnter)));
    }

    #[test]
    fn a_comment_toggle_is_held_and_rated_without_its_hash() {
        let (_, end, buffer) = sent(b"#rm -rf /srv\x1b#");
        assert_eq!(end, Step::Run(RunKey::Esc(b'#')));
        assert!(buffer.unreliable());
        assert_eq!(as_run(buffer.text(), RunKey::Esc(b'#')), "rm -rf /srv");
        assert_eq!(as_run("#a\n#b\nc", RunKey::Comment), "a\nb\nc");
        assert_eq!(
            as_run("uptime", RunKey::Comment),
            "uptime",
            "commented out: rated as typed"
        );
        assert_eq!(as_run("#keep", RunKey::Enter(b'\r')), "#keep");
    }

    #[test]
    fn vi_command_mode_runs_with_hash_and_refuses_v_until_typing_resumes() {
        // Esc, b (a word back), then # in vi command mode.
        let (out, end, _) = sent(b"ls\x1bb#");
        assert_eq!((out.as_slice(), end), (&b"ls\x1bb"[..], Step::Run(RunKey::Comment)));
        assert_eq!(RunKey::Comment.keys(), b"#");
        // v opens the editor: refused, and nothing of it is sent.
        let (out, end, _) = sent(b"ls\x1b0v");
        assert_eq!((out.as_slice(), end), (&b"ls\x1b0"[..], Step::Refused(VI_EDIT)));
        assert_eq!(sent(b"ls\x1bv").1, Step::Refused(VI_EDIT));
        assert_eq!(sent(b"ls\x1bb:").1, Step::Refused(VI_NAMED));
        // i, A, c and a motion... go back to typing: v and # are text again.
        for keys in [
            &b"ls\x1bbi-v #"[..],
            b"ls\x1bhA -v #",
            b"ls\x1bcw-v #",
            b"ls\x1bc2w-v #",
            b"ls\x1bcfx-v",
        ] {
            let (out, end, _) = sent(keys);
            assert_eq!((out.as_slice(), end), (keys, Step::Key), "{keys:?}");
        }
        // The argument of r, f, t... is a character, not a command.
        assert_eq!(sent(b"ls\x1bfvx").1, Step::Key);
        assert_eq!(sent(b"ls\x1brv#").1, Step::Run(RunKey::Comment));
        // A new line starts in insert mode.
        let mut buffer = LineBuffer::default();
        let mut out = Vec::new();
        for key in b"ls\x1bb" {
            buffer.feed(*key, &mut out);
        }
        buffer.clear();
        assert_eq!(buffer.feed(b'v', &mut out), Step::Key);
    }

    #[test]
    fn edit_and_run_keys_are_refused() {
        let (out, end, _) = sent(b"vi /etc/hosts\x18\x05");
        assert_eq!(
            (out.as_slice(), end),
            (&b"vi /etc/hosts"[..], Step::Refused(EDIT_AND_RUN))
        );
        // Ctrl+X waits for its next key, across inputs too.
        let mut buffer = LineBuffer::default();
        let mut out = Vec::new();
        assert_eq!(buffer.feed(CTRL_X, &mut out), Step::Key);
        assert!(out.is_empty(), "Ctrl+X is held");
        assert_eq!(buffer.feed(CTRL_E, &mut out), Step::Refused(EDIT_AND_RUN));
        assert!(out.is_empty());
        // The keyboard macro, and running a command by name.
        assert_eq!(sent(b"\x18e").1, Step::Refused(MACRO));
        assert_eq!(sent(b"\x18E").1, Step::Refused(MACRO));
        assert_eq!(sent(b"ls\x1bx").1, Step::Refused(NAMED));
    }

    #[test]
    fn ctrl_x_and_any_other_key_go_on_together() {
        for second in [0x15, CTRL_X, b'(', b'*', b'g'] {
            let (out, end, buffer) = sent(&[b'l', b's', CTRL_X, second]);
            assert_eq!((out.as_slice(), end), (&[b'l', b's', CTRL_X, second][..], Step::Key));
            assert!(buffer.unreliable());
        }
        // Keys that act on their own: Ctrl+X goes, and they count as usual.
        let (out, end, _) = sent(b"ls\x18\r");
        assert_eq!((out.as_slice(), end), (&b"ls\x18"[..], Step::Run(RunKey::Enter(b'\r'))));
        let (out, end, _) = sent(b"ls\x18\x03");
        assert_eq!((out.as_slice(), end), (&b"ls\x18\x03"[..], Step::Interrupt));
        // zsh: Ctrl+X Ctrl+V is vi command mode.
        assert_eq!(sent(b"ls\x18\x16#").1, Step::Run(RunKey::Comment));
    }

    #[test]
    fn escape_sequences_of_keys_go_on_whole() {
        for keys in [
            &b"\x1b[A"[..],
            b"\x1bOA",
            b"\x1b[1;5C",
            b"\x1b[H",
            b"\x1b[3~",
            b"\x1bOP",
            b"\x1b[15~",
            b"\x1b[I",
            b"\x1b[200~ls\x1b[201~",
        ] {
            let (out, end, _) = sent(keys);
            assert_eq!((out.as_slice(), end), (keys, Step::Key), "{keys:?}");
        }
        // An arrow key's sequence is held until it ends, then goes whole.
        let mut buffer = LineBuffer::default();
        let mut out = Vec::new();
        buffer.feed(ESC, &mut out);
        buffer.feed(b'[', &mut out);
        assert!(out.is_empty());
        buffer.feed(b'A', &mut out);
        assert_eq!(out, b"\x1b[A");
    }

    #[test]
    fn an_escape_sequence_that_is_no_key_is_read_key_by_key() {
        // The shells read Esc [ and then Enter: it may run the line.
        let (out, end, buffer) = sent(b"ls\x1b[\r");
        assert_eq!(
            (out.as_slice(), end),
            (&b"ls\x1b["[..], Step::Run(RunKey::Enter(b'\r')))
        );
        assert!(buffer.leaves_text());
        assert_eq!(sent(b"ls\x1bO\r").1, Step::Run(RunKey::Enter(b'\r')));
        assert_eq!(sent(b"ls\x1b[1;2\x0f").1, Step::Run(RunKey::CtrlO));
        // # and v in it are vi commands.
        assert_eq!(sent(b"ls\x1b[#").1, Step::Run(RunKey::Comment));
        assert_eq!(sent(b"ls\x1b[v").1, Step::Refused(VI_EDIT));
        assert_eq!(sent(b"ls\x1bO#").1, Step::Run(RunKey::Comment));
        // Inside a bracketed paste, all of it is text.
        let (out, end, buffer) = sent(b"\x1b[200~a\x1b[#\x1bv\r\x0f\x1b[201~");
        assert_eq!(
            (out.as_slice(), end),
            (&b"\x1b[200~a\x1b[#\x1bv\r\x0f\x1b[201~"[..], Step::Key)
        );
        assert!(!buffer.leaves_text());
    }

    #[test]
    fn keys_after_which_the_shell_may_hold_text_mark_the_line() {
        for keys in [
            &b"echo \x16\r"[..],  // quoted insert: Enter goes into the line
            b"echo \x11\r",       // Ctrl+Q: the same, or zsh's push-line
            b"rm -rf /x\x11ls\r", // zsh's push-line: the line comes back after the next one
            b"\x12ssh\n",         // Ctrl+J ends a search and leaves the line found
            b"\x1bpssh\r",        // bash's non-incremental search
            b"\x1bqls\r",         // zsh's push-line
            b"ls\x1b/ssh\r",      // vi's search
        ] {
            let (_, end, buffer) = sent(keys);
            assert!(matches!(end, Step::Run(_)), "{keys:?}");
            assert!(buffer.leaves_text(), "{keys:?}");
        }
        for keys in [&b"ls\r"[..], b"\x12ssh\r", b"ls\x1b[A\r", b"echo \x16\x09x\r"] {
            assert!(!sent(keys).2.leaves_text(), "{keys:?}");
        }
    }

    #[test]
    fn a_paste_goes_on_with_the_lines_that_end_with_enter() {
        let paste = paste_lines(b"df -h\rls -l\rpartial");
        assert_eq!(paste.lines, ["df -h", "ls -l"]);
        assert_eq!(paste.len, b"df -h\rls -l\r".len());
        assert!(!paste.unreliable);
        // Ctrl+C drops a line in between.
        let keys = b"rm -rf /\x03ls\r";
        let paste = paste_lines(keys);
        assert_eq!(
            (paste.lines.as_slice(), paste.len),
            (&["ls".to_owned()][..], keys.len())
        );
        // A line run another way, or refused, stops it: those keys are rated on their own.
        for keys in [&b"ls\x0fdf\r"[..], b"ls\x1b#df\r", b"ls\x16\rdf\r", b"ls\x18\x05df\r"] {
            assert_eq!(paste_lines(keys).len, 0, "{keys:?}");
        }
        assert!(paste_lines(b"syst\tstatus\r").unreliable);
    }

    #[test]
    fn the_bus_sends_only_the_held_keys_of_the_rated_line() {
        for keys in [
            &b"\r"[..],
            b"\n",
            b"\x0f",
            b"\x1b\r",
            b"\x1b#",
            b"\x1ba",
            b"#",
            b"\x1bOM",
        ] {
            assert_eq!(check_keys("uptime", keys, false), Ok(()), "{keys:?}");
        }
        // Nothing, other keys, or a run key with more after it.
        for keys in [
            &b""[..],
            b"x",
            b"\x1bx",
            b"\x1b[A",
            b"\x0fls\r",
            b"\x1b#\r",
            b"\x18\x05",
        ] {
            assert!(check_keys("uptime", keys, false).is_err(), "{keys:?}");
        }
        // After Enter: a paste's later lines, each with its Enter, that the rated line ends with.
        assert_eq!(check_keys("uptime\nls -l", b"\rls -l\r", false), Ok(()));
        assert_eq!(check_keys("uptime\n\nls -l", b"\r\rls -l\r\r", false), Ok(()));
        assert_eq!(
            check_keys("uptime", b"\r\r\r", false),
            Ok(()),
            "empty lines run nothing"
        );
        assert!(check_keys("uptime", b"\rrm -rf /srv\r", false).is_err(), "not rated");
        assert!(check_keys("uptime\nls", b"\rls", false).is_err(), "no Enter after it");
        assert!(check_keys("uptime\nls", b"\rls\r\x18\x05", false).is_err());
        assert!(check_keys("uptime\nls", b"\rls\x0f", false).is_err());
        // Keys Remotely can't follow in them: the line must say so.
        assert!(check_keys("uptime\nls", b"\r\x1b[Als\r", false).is_err());
        assert_eq!(check_keys("uptime\nls", b"\r\x1b[Als\r", true), Ok(()));
    }

    #[test]
    fn ctrl_c_drops_the_line() {
        let (text, unreliable, steps) = typed(b"rm -rf /\x1b[A\x03");
        assert_eq!(
            (text.as_str(), unreliable),
            ("", false),
            "the shell dropped it, unreliable or not"
        );
        assert_eq!(steps, [Step::Interrupt]);
    }

    #[test]
    fn keys_that_cannot_be_followed_make_the_line_unreliable() {
        for keys in [
            &b"syst\tstatus"[..], // Tab completion
            b"\x1b[A",            // Up: history
            b"ls\x1b[D\x1b[Drm ", // Left arrows, then typing mid-line
            b"\x12restart",       // Ctrl+R
            b"ls\x01rm ",         // Ctrl+A, then typing at the start
            b"\x10",              // Ctrl+P: history
            b"\x1bOA",            // Up in application mode
            b"echo \x1b.",        // Alt+.: the last argument
            b"ls \x19",           // Ctrl+Y: yank
            b"\x1b[3~",           // Delete
        ] {
            assert!(typed(keys).1, "{keys:?}");
        }
        assert!(!typed(b"\x1b[I\x1b[Ouptime").1, "focus reports change nothing");
    }

    #[test]
    fn a_bracketed_paste_is_text_even_with_line_breaks() {
        let (text, unreliable, steps) = typed(b"\x1b[200~cd /srv\rmake\tall\x1b[201~\r");
        assert_eq!(text, "cd /srv\nmake all");
        assert!(!unreliable);
        assert_eq!(
            steps,
            [Step::Run(RunKey::Enter(b'\r'))],
            "only the Enter after the paste"
        );
        // Ctrl+C inside a paste is not the key: the shell may keep the text before it.
        let (text, unreliable, steps) = typed(b"\x1b[200~rm -rf /srv\x03ls\x1b[201~");
        assert_eq!(text, "rm -rf /srvls");
        assert!(unreliable);
        assert!(steps.is_empty());
    }

    #[test]
    fn split_characters_are_joined() {
        let mut buffer = LineBuffer::default();
        let mut out = Vec::new();
        for b in "é".as_bytes() {
            buffer.feed(*b, &mut out);
        }
        assert_eq!(buffer.text(), "é");
        let mut bad = LineBuffer::default();
        bad.feed(0xff, &mut out);
        bad.feed(b'x', &mut out);
        assert_eq!(bad.text(), "x");
    }
}
