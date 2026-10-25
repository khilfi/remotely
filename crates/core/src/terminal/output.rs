//! SS-11: terminals' whole scrollback, copied, printed or saved to text files, one terminal or several
//! at once (one file each, or one file with a header per terminal).
//!
//! The text comes from xterm.js in the UI. The core scrubs each terminal's login secrets from it
//! (see [`super::Terminals::scrub_output`]), writes the files where the user chose in a dialog the shell
//! opens, and audits that output was saved: which sessions and which files, never the output itself.
//!
//! QL-05: a selection copied from a terminal (copy-on-select, Ctrl+C, Ctrl+Shift+C) is scrubbed the same
//! way ([`super::Terminals::scrub_for_copy`]) before the shell puts it on the clipboard.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::log::{clock, offset_label};
use super::{scrub, Terminals};
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;

/// One terminal's text, as the UI read it from the terminal's buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalText {
    /// The core's terminal id, so its secrets can be scrubbed. `None` for a pane that never opened.
    pub terminal_id: Option<Uuid>,
    /// What the tab shows, e.g. `web01 · 192.0.2.10`.
    pub title: String,
    pub text: String,
}

/// How several terminals are saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SaveLayout {
    /// One file; with several terminals, each starts with a header.
    OneFile,
    /// One file per terminal, in a folder.
    FilePerTerminal,
}

/// What a save wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedOutput {
    pub files: Vec<String>,
    pub terminals: usize,
}

/// More text than this in one save is refused: scrollback is capped well below it.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// Longest file name stem a terminal's title gives.
const MAX_STEM: usize = 80;

/// Windows line ends, so Notepad and every other editor show the lines.
pub fn crlf(text: &str) -> String {
    let unix = text.replace("\r\n", "\n");
    let trimmed = unix.trim_end_matches('\n');
    let mut out = trimmed.replace('\n', "\r\n");
    out.push_str("\r\n");
    out
}

/// One file holding several terminals' output, each under a header.
pub fn combined(items: &[TerminalText], saved_at: OffsetDateTime) -> String {
    let mut out = format!(
        "Output of {} terminals, saved by Remotely on {} {}\r\n",
        items.len(),
        clock(saved_at),
        offset_label(saved_at)
    );
    for item in items {
        out.push_str(&format!("\r\n===== {} =====\r\n", one_line(&item.title)));
        out.push_str(&crlf(&item.text));
    }
    out
}

/// A title on one line.
fn one_line(title: &str) -> String {
    let joined: String = title.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    match joined.trim() {
        "" => "terminal".into(),
        t => t.to_owned(),
    }
}

/// A file name for a terminal's output: its title, safe for Windows, and when.
/// `web01 · 192.0.2.10` saved on 19 Oct 2026 at 14:03 gives `web01 - 192.0.2.10 2026-10-19 1403.txt`.
pub fn file_name(title: &str, at: OffsetDateTime, extension: &str) -> String {
    let mut stem = String::new();
    for c in one_line(title).replace(" · ", " - ").chars() {
        let safe = if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
            '-'
        } else {
            c
        };
        stem.push(safe);
    }
    let stem: String = stem.chars().take(MAX_STEM).collect();
    let stem = stem.trim_matches(|c: char| c == '.' || c == ' ' || c == '-');
    let stem = if stem.is_empty() { "terminal" } else { stem };
    format!(
        "{stem} {:04}-{:02}-{:02} {:02}{:02}.{extension}",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute()
    )
}

/// `name.txt` in `folder`, or `name (2).txt` and so on when that is taken (by a file there or one
/// already chosen in this save).
pub fn unique_path(folder: &Path, name: &str, taken: &[PathBuf]) -> PathBuf {
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, ext)) => (stem.to_owned(), format!(".{ext}")),
        None => (name.to_owned(), String::new()),
    };
    let mut candidate = folder.join(name);
    let mut n = 2;
    while candidate.exists() || taken.contains(&candidate) {
        candidate = folder.join(format!("{stem} ({n}){extension}"));
        n += 1;
    }
    candidate
}

/// Checks a save before anything is written.
pub fn check(items: &[TerminalText]) -> Result<()> {
    if items.is_empty() {
        return Err(CoreError::InvalidInput("Choose at least one terminal to save.".into()));
    }
    let total: usize = items.iter().map(|i| i.text.len()).sum();
    if total > MAX_OUTPUT_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "That is more than {} MB of text; save fewer terminals at once.",
            MAX_OUTPUT_BYTES / (1024 * 1024)
        )));
    }
    Ok(())
}

/// What "Copy output" puts on the clipboard: one terminal's text as it is, several each under a header.
pub fn clipboard_text(items: &[TerminalText]) -> String {
    match items {
        [one] => one.text.clone(),
        several => several
            .iter()
            .map(|item| format!("===== {} =====\n{}", one_line(&item.title), item.text))
            .collect::<Vec<_>>()
            .join("\n\n"),
    }
}

fn too_much_to_copy(bytes: usize) -> Result<()> {
    if bytes > MAX_OUTPUT_BYTES {
        return Err(CoreError::InvalidInput(format!(
            "That is more than {} MB of text to copy at once.",
            MAX_OUTPUT_BYTES / (1024 * 1024)
        )));
    }
    Ok(())
}

impl Terminals {
    /// SS-11 "Copy output": the terminals' text with their login secrets scrubbed, as one text for the
    /// clipboard (see [`clipboard_text`]).
    pub fn copy_output_text(&self, items: Vec<TerminalText>) -> Result<String> {
        if items.is_empty() {
            return Err(CoreError::InvalidInput("Choose at least one terminal to copy.".into()));
        }
        too_much_to_copy(items.iter().map(|i| i.text.len()).sum())?;
        Ok(clipboard_text(&self.scrub_output(items)))
    }

    /// QL-05: text selected in a terminal, for the clipboard, scrubbed like "Copy output": every secret the
    /// terminal knows (its login password or passphrase, passwords typed for it or its jump hosts, vault
    /// secrets typed into it) becomes `[redacted]`.
    ///
    /// Without a terminal id (a pane that never opened: only the app's own lines are on it) what looks like a
    /// password or token is redacted. A terminal that has closed has let go of its secrets, so the text can't
    /// be checked against them: it is refused rather than copied unchecked.
    pub fn scrub_for_copy(&self, terminal_id: Option<Uuid>, text: &str) -> Result<String> {
        too_much_to_copy(text.len())?;
        let Some(id) = terminal_id else {
            return Ok(redact_secrets(text).0);
        };
        let control = self
            .control(id)
            .ok_or_else(|| CoreError::UnknownTarget("that terminal has closed".into()))?;
        Ok(scrub(text, &control.known_secrets()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const AT: OffsetDateTime = datetime!(2026-10-19 14:03:22 +02:00);

    fn text(title: &str, text: &str) -> TerminalText {
        TerminalText {
            terminal_id: None,
            title: title.into(),
            text: text.into(),
        }
    }

    #[test]
    fn line_ends_become_crlf_with_one_at_the_end() {
        assert_eq!(crlf("a\nb\r\nc\n\n\n"), "a\r\nb\r\nc\r\n");
        assert_eq!(crlf(""), "\r\n");
    }

    #[test]
    fn a_combined_file_has_a_header_per_terminal() {
        let out = combined(
            &[
                text("web01 · 192.0.2.10", "$ uptime\nup 3 days\n"),
                text("db01", "$ df\n"),
            ],
            AT,
        );
        assert!(out.starts_with("Output of 2 terminals, saved by Remotely on 2026-10-19 14:03:22 +02:00\r\n"));
        assert!(
            out.contains("\r\n\r\n===== web01 · 192.0.2.10 =====\r\n$ uptime\r\nup 3 days\r\n"),
            "{out}"
        );
        assert!(out.contains("\r\n===== db01 =====\r\n$ df\r\n"), "{out}");
        assert!(out.ends_with("$ df\r\n"));
    }

    #[test]
    fn file_names_are_safe_for_windows() {
        assert_eq!(
            file_name("web01 · 192.0.2.10", AT, "txt"),
            "web01 - 192.0.2.10 2026-10-19 1403.txt"
        );
        assert_eq!(
            file_name("alice@[2001:db8::1]:22", AT, "log"),
            "alice@[2001-db8--1]-22 2026-10-19 1403.log"
        );
        assert_eq!(file_name("  ...  ", AT, "txt"), "terminal 2026-10-19 1403.txt");
        assert!(file_name(&"x".repeat(300), AT, "txt").len() < 120);
    }

    #[test]
    fn taken_names_get_a_number() {
        let folder = std::env::temp_dir().join(format!("remotely-names-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("web01.txt"), "x").unwrap();
        let first = unique_path(&folder, "web01.txt", &[]);
        assert_eq!(first, folder.join("web01 (2).txt"));
        let second = unique_path(&folder, "web01.txt", std::slice::from_ref(&first));
        assert_eq!(second, folder.join("web01 (3).txt"));
        assert_eq!(unique_path(&folder, "db01.txt", &[]), folder.join("db01.txt"));
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn empty_and_huge_saves_are_refused() {
        assert!(check(&[]).is_err());
        assert!(check(&[text("web01", "ok")]).is_ok());
    }

    #[test]
    fn copied_output_has_a_header_per_terminal_only_when_there_are_several() {
        assert_eq!(
            clipboard_text(&[text("web01", "$ uptime\nup 3 days")]),
            "$ uptime\nup 3 days"
        );
        assert_eq!(
            clipboard_text(&[text("web01 · 192.0.2.10", "$ uptime"), text("db01\n", "$ df")]),
            "===== web01 · 192.0.2.10 =====\n$ uptime\n\n===== db01 =====\n$ df"
        );
    }

    #[test]
    fn copies_have_a_size_limit() {
        assert!(too_much_to_copy(MAX_OUTPUT_BYTES).is_ok());
        let err = too_much_to_copy(MAX_OUTPUT_BYTES + 1).unwrap_err();
        assert_eq!(err.code(), "invalid_input");
    }
}
