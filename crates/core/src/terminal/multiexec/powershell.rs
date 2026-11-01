//! BX-13: Type in all tabs on PowerShell tabs. A PowerShell tab has no shell reading keys: Remotely's own console
//! ([`crate::adapters::winrm::console`]) edits the line, and Enter sends it to PowerShell as one statement, or holds it
//! (`>> `) while the statement is left open. So MultiExec follows a PowerShell line as that console does, key for key
//! ([`PsLine`], which mirrors the console's `Editor::keys` at its prompt):
//!
//! * Printable text (whole UTF-8 characters, up to the console's line limit), Backspace and Ctrl+U edit the line;
//!   Tab and other control keys do nothing; Ctrl+C drops the line and any statement left open.
//! * Enter is CR or LF (an LF right after a CR is the same Enter), wherever it comes: in a bracketed paste too, since
//!   the console sends a line at every Enter. It is the only key that runs anything, and it is held.
//! * After Esc the next key goes with it (`Esc Enter` runs nothing); `Esc [` and `Esc O` start a sequence up to its
//!   final byte. Up and Down replace the line with one of the tab's own history, which MultiExec can't know: the line
//!   is unreliable. Other sequences do nothing.
//!
//! At Enter, MultiExec works out what the console sends with [`crate::adapters::winrm::console::statements`] (the
//! function the console itself decides with): a line that only adds to a statement left open runs nothing and goes at
//! once, unrated; a line that closes one sends the whole statement, and that is what is rated (the open lines, then
//! this one). Pasted lines that follow at once go with the first Enter, in one piece, so the console runs them one
//! statement per prompt as it does any paste; they are rated with it.

use crate::adapters::winrm::console::MAX_LINE;

use super::{RunKey, Step};

const CTRL_C: u8 = 0x03;
const CTRL_U: u8 = 0x15;
const ESC: u8 = 0x1b;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Escape {
    #[default]
    None,
    /// After Esc: the next key goes with it.
    Start,
    /// After `Esc [` or `Esc O`: up to the final byte.
    Sequence,
}

/// A PowerShell tab's line as its console follows it (see the module comment).
#[derive(Debug, Default)]
pub(crate) struct PsLine {
    text: String,
    unreliable: bool,
    escape: Escape,
    sequence: Vec<u8>,
    partial: Vec<u8>,
    after_cr: bool,
}

impl PsLine {
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    pub(crate) fn unreliable(&self) -> bool {
        self.unreliable
    }

    pub(crate) fn mark_unreliable(&mut self) {
        self.unreliable = true;
    }

    /// A new line. Whether the last key was CR stays: an LF next is still that Enter.
    pub(crate) fn clear(&mut self) {
        let after_cr = self.after_cr;
        *self = PsLine::default();
        self.after_cr = after_cr;
    }

    /// One byte typed. Every byte but Enter goes to the tabs now (in `out`); Enter is held.
    pub(crate) fn feed(&mut self, byte: u8, out: &mut Vec<u8>) -> Step {
        let after_cr = std::mem::replace(&mut self.after_cr, false);
        match self.escape {
            Escape::Start => {
                self.escape = if byte == b'[' || byte == b'O' {
                    Escape::Sequence
                } else {
                    Escape::None
                };
                out.push(byte);
                return Step::Key;
            }
            Escape::Sequence => {
                self.sequence.push(byte);
                out.push(byte);
                if (0x40..=0x7e).contains(&byte) || self.sequence.len() > 16 {
                    self.escape = Escape::None;
                    let sequence = std::mem::take(&mut self.sequence);
                    // Up and Down: a line of the tab's own history.
                    if matches!(sequence.last(), Some(b'A' | b'B')) {
                        self.unreliable = true;
                    }
                }
                return Step::Key;
            }
            Escape::None => {}
        }
        match byte {
            ESC => {
                self.escape = Escape::Start;
                out.push(byte);
                Step::Key
            }
            b'\r' => {
                self.after_cr = true;
                Step::Run(RunKey::Enter(b'\r'))
            }
            b'\n' if after_cr => {
                // The same Enter as the CR before it: the console ignores it.
                out.push(byte);
                Step::Key
            }
            b'\n' => Step::Run(RunKey::Enter(b'\n')),
            CTRL_C => {
                out.push(byte);
                Step::Interrupt
            }
            0x7f | 0x08 => {
                self.text.pop();
                out.push(byte);
                Step::Key
            }
            CTRL_U => {
                self.text.clear();
                out.push(byte);
                Step::Key
            }
            b if b < 0x20 => {
                out.push(byte);
                Step::Key
            }
            _ => {
                out.push(byte);
                self.partial.push(byte);
                let need = utf8_len(self.partial[0]);
                if self.partial.len() >= need {
                    let bytes = std::mem::take(&mut self.partial);
                    if let Ok(text) = std::str::from_utf8(&bytes) {
                        if self.text.len() + text.len() <= MAX_LINE {
                            self.text.push_str(text);
                        }
                    }
                }
                Step::Key
            }
        }
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

/// BX-13: the pasted lines that go with an Enter: each plain text (no control or escape bytes) ending with Enter (CR,
/// LF, or CR LF), as many as come at once. `len` is the bytes they take. Plain text only, so the bus's own check of a
/// line's keys reads them the same way.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PsPaste {
    pub(crate) lines: Vec<String>,
    pub(crate) len: usize,
}

pub(crate) fn paste_lines(keys: &[u8]) -> PsPaste {
    let mut paste = PsPaste::default();
    let mut start = 0;
    let mut at = 0;
    while at < keys.len() {
        match keys[at] {
            b'\r' | b'\n' => {
                let Ok(line) = std::str::from_utf8(&keys[start..at]) else {
                    break;
                };
                if line.len() > MAX_LINE {
                    break;
                }
                paste.lines.push(line.to_owned());
                at += if keys[at] == b'\r' && keys.get(at + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                paste.len = at;
                start = at;
            }
            b if b < 0x20 || b == 0x7f => break,
            _ => at += 1,
        }
    }
    paste
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(keys: &[u8]) -> (String, bool, Vec<Step>, Vec<u8>) {
        let mut line = PsLine::default();
        let mut out = Vec::new();
        let steps = keys.iter().map(|b| line.feed(*b, &mut out)).collect();
        (line.text().to_owned(), line.unreliable(), steps, out)
    }

    #[test]
    fn text_backspace_and_ctrl_u_edit_the_line_as_the_console_does() {
        let (text, unreliable, _, out) = typed(b"Get-Proc\x7fcess");
        assert_eq!(text, "Get-Process");
        assert!(!unreliable);
        assert_eq!(out, b"Get-Proc\x7fcess", "every typed key goes to the tabs");
        assert_eq!(typed(b"abc\x15Get-Date").0, "Get-Date");
        // Tab, Ctrl+W and Ctrl+O do nothing in the console (and don't make the line unreliable).
        let (text, unreliable, _, _) = typed(b"Get\t-Da\x17\x0fte");
        assert_eq!(text, "Get-Date");
        assert!(!unreliable);
        // Split UTF-8 characters are joined.
        assert_eq!(typed("Write-Output é".as_bytes()).0, "Write-Output é");
    }

    #[test]
    fn enter_is_cr_or_lf_and_held_and_cr_lf_is_one_enter() {
        let (_, _, steps, out) = typed(b"Get-Date\r");
        assert_eq!(steps.last(), Some(&Step::Run(RunKey::Enter(b'\r'))));
        assert!(!out.contains(&b'\r'), "Enter is held");
        let mut line = PsLine::default();
        let mut out = Vec::new();
        assert_eq!(line.feed(b'\r', &mut out), Step::Run(RunKey::Enter(b'\r')));
        line.clear();
        assert_eq!(line.feed(b'\n', &mut out), Step::Key, "the LF of CR LF runs nothing more");
        assert_eq!(line.feed(b'\n', &mut out), Step::Run(RunKey::Enter(b'\n')));
        // In a bracketed paste too: the console sends a line at every Enter.
        let (_, _, steps, _) = typed(b"\x1b[200~Get-Date\rhostname\x1b[201~");
        assert!(steps.contains(&Step::Run(RunKey::Enter(b'\r'))));
    }

    #[test]
    fn esc_takes_the_next_key_and_history_keys_make_the_line_unreliable() {
        // Esc then Enter: the console takes the CR with the Esc, so nothing runs.
        let (_, _, steps, _) = typed(b"Get-Date\x1b\r");
        assert!(!steps.iter().any(|s| matches!(s, Step::Run(_))));
        let (text, unreliable, _, _) = typed(b"\x1b[A");
        assert!(unreliable && text.is_empty());
        let (_, unreliable, _, _) = typed(b"\x1bOB");
        assert!(unreliable);
        // Left and Right, Home and Delete do nothing to the console's line.
        let (text, unreliable, _, _) = typed(b"Get-Date\x1b[D\x1b[C\x1b[3~");
        assert_eq!(text, "Get-Date");
        assert!(!unreliable);
    }

    #[test]
    fn ctrl_c_interrupts() {
        let (_, _, steps, out) = typed(b"Stop-Comp\x03");
        assert_eq!(steps.last(), Some(&Step::Interrupt));
        assert!(out.ends_with(&[CTRL_C]));
    }

    #[test]
    fn pasted_lines_are_plain_text_lines_each_with_its_enter() {
        assert_eq!(
            paste_lines(b"hostname\r\nwhoami\rGet-Da"),
            PsPaste {
                lines: vec!["hostname".into(), "whoami".into()],
                len: 17
            }
        );
        // A control key ends the paste there.
        assert_eq!(paste_lines(b"a\r\x1b[Ab\r").lines, ["a"]);
        assert_eq!(paste_lines(b"\r\n").lines, [""]);
        assert!(paste_lines(b"no enter").lines.is_empty());
    }
}
