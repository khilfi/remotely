//! FD-05, FD-08: one table model for every format a report is written in: an Excel sheet ([`super::xlsx`]), a CSV
//! file (A10's rules, through [`crate::export::push_row`]) and an HTML table ([`super::html`]).
//!
//! Every text cell is made here ([`Cell::text`]), so every format gets the same clean text: anything that looks like a
//! secret replaced (`export::redact_secrets`; a session name, a tag or a note may hold one by mistake), control and
//! invisible format characters (U+202E and the like, which can make a name read backwards) taken out, line breaks
//! made spaces, and the length capped at what an Excel cell holds.

use crate::export::{push_row, redact_secrets};
use crate::untrusted::is_format_char;

/// Characters a cell keeps at most. Excel's cells hold 32,767.
pub const MAX_CELL_CHARS: usize = 32_000;

/// One cell. Text is always text: no format writes it as a formula, whatever it starts with.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Text(String),
    Int(i64),
    Number(f64),
    Empty,
}

impl Cell {
    /// Cleaned text ([`clean`]); empty text is an empty cell.
    pub fn text(value: impl AsRef<str>) -> Self {
        let text = clean(value.as_ref());
        if text.is_empty() {
            Cell::Empty
        } else {
            Cell::Text(text)
        }
    }

    pub fn opt_text(value: Option<impl AsRef<str>>) -> Self {
        value.map_or(Cell::Empty, Cell::text)
    }

    pub fn int(value: impl TryInto<i64>) -> Self {
        value.try_into().map_or(Cell::Empty, Cell::Int)
    }

    pub fn opt_int(value: Option<impl TryInto<i64>>) -> Self {
        value.map_or(Cell::Empty, Cell::int)
    }

    /// A number rounded to two decimals; not a number is an empty cell.
    pub fn number(value: f64) -> Self {
        if value.is_finite() {
            Cell::Number((value * 100.0).round() / 100.0)
        } else {
            Cell::Empty
        }
    }

    pub fn opt_number(value: Option<f64>) -> Self {
        value.map_or(Cell::Empty, Cell::number)
    }

    pub fn yes_no(value: bool) -> Self {
        Cell::Text(if value { "Yes" } else { "No" }.to_owned())
    }

    /// The cell as text, for CSV and HTML.
    pub fn display(&self) -> String {
        match self {
            Cell::Text(text) => text.clone(),
            Cell::Int(n) => n.to_string(),
            Cell::Number(n) => {
                if n.fract() == 0.0 && n.abs() < 1e15 {
                    format!("{n:.0}")
                } else {
                    format!("{n:.2}")
                }
            }
            Cell::Empty => String::new(),
        }
    }
}

/// Text fit for a report: secrets redacted, control and format characters out (line breaks and tabs become spaces),
/// runs of spaces made one, trimmed, and cut at [`MAX_CELL_CHARS`] characters (by character, never by byte).
pub fn clean(value: &str) -> String {
    let (redacted, _) = redact_secrets(value);
    let mut out = String::with_capacity(redacted.len().min(MAX_CELL_CHARS));
    let mut space = false;
    let mut count = 0;
    for c in redacted.chars() {
        let c = if c == '\n' || c == '\r' || c == '\t' { ' ' } else { c };
        if c.is_control() || is_format_char(c) {
            continue;
        }
        if c == ' ' {
            if space || out.is_empty() {
                continue;
            }
            space = true;
        } else {
            space = false;
        }
        if count >= MAX_CELL_CHARS {
            out.push('…');
            break;
        }
        out.push(c);
        count += 1;
    }
    out.trim_end().to_owned()
}

/// Text that keeps its lines (a job's output in the handover pack): secrets redacted, control and format characters
/// out but line breaks and tabs kept, cut at `max_chars`.
pub fn clean_lines(value: &str, max_chars: usize) -> (String, bool) {
    let (redacted, _) = redact_secrets(value);
    let mut out = String::new();
    let mut cut = false;
    for (count, c) in redacted.chars().filter(|c| *c != '\r').enumerate() {
        if count >= max_chars {
            cut = true;
            break;
        }
        if (c.is_control() && c != '\n' && c != '\t') || is_format_char(c) {
            continue;
        }
        out.push(c);
    }
    (out, cut)
}

/// A column: its heading and, for Excel, its width in characters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Column {
    pub title: &'static str,
    pub width: f64,
}

pub const fn col(title: &'static str, width: f64) -> Column {
    Column { title, width }
}

/// One sheet of a report.
#[derive(Debug, Clone, PartialEq)]
pub struct Sheet {
    /// The sheet's tab in Excel and its CSV's name (`vms` is `vms.csv`).
    pub name: &'static str,
    /// What Excel's tab shows.
    pub title: &'static str,
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Cell>>,
}

impl Sheet {
    pub fn new(name: &'static str, title: &'static str, columns: &[Column]) -> Self {
        Self {
            name,
            title,
            columns: columns.to_vec(),
            rows: Vec::new(),
        }
    }

    /// Adds a row, padded or cut to the columns.
    pub fn push(&mut self, mut row: Vec<Cell>) {
        row.resize(self.columns.len(), Cell::Empty);
        self.rows.push(row);
    }

    /// The sheet as CSV (A10): a byte-order mark so Excel reads UTF-8, the header, one row each, every cell through
    /// [`crate::export::csv_cell`]'s formula guard and quoting.
    pub fn csv(&self) -> String {
        let mut out = String::from("\u{FEFF}");
        push_row(&mut out, self.columns.iter().map(|c| c.title.to_owned()));
        for row in &self.rows {
            push_row(&mut out, row.iter().map(Cell::display));
        }
        out
    }

    /// `vms.csv`.
    pub fn csv_name(&self) -> String {
        format!("{}.csv", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_cleaned_of_secrets_controls_and_format_characters() {
        assert_eq!(
            Cell::text("web01\u{202E}10bew"),
            Cell::Text("web0110bew".into()),
            "a right-to-left override"
        );
        assert_eq!(
            Cell::text("two\nlines\tand\u{7}bell"),
            Cell::Text("two lines andbell".into())
        );
        assert_eq!(Cell::text("  spaced   out  "), Cell::Text("spaced out".into()));
        assert_eq!(
            Cell::text("db password=Hunter2Hunter2"),
            Cell::Text("db password=[redacted]".into())
        );
        assert_eq!(Cell::text(" \n "), Cell::Empty);
        let long = "\u{e9}".repeat(MAX_CELL_CHARS + 10);
        let Cell::Text(cut) = Cell::text(&long) else {
            panic!("text")
        };
        assert_eq!(
            cut.chars().count(),
            MAX_CELL_CHARS + 1,
            "cut by character, with an ellipsis"
        );
    }

    #[test]
    fn lines_keep_their_breaks_and_lose_their_secrets() {
        let (text, cut) = clean_lines("one\r\ntwo\ttoken=abc123\u{1b}[0m", 100);
        assert_eq!(text, "one\ntwo\ttoken=[redacted]");
        assert!(!cut);
        let (text, cut) = clean_lines("\u{e9}\u{e9}\u{e9}", 2);
        assert_eq!((text.as_str(), cut), ("\u{e9}\u{e9}", true));
    }

    #[test]
    fn csv_guards_formulas_and_quotes_separators() {
        let mut sheet = Sheet::new("vms", "VMs", &[col("Name", 10.0), col("vCPU", 5.0), col("RAM", 5.0)]);
        sheet.push(vec![
            Cell::text("=HYPERLINK(\"http://example.com\")"),
            Cell::int(4),
            Cell::number(2.5),
        ]);
        sheet.push(vec![Cell::text("+1; -2")]);
        let csv = sheet.csv();
        let lines: Vec<&str> = csv.trim_start_matches('\u{FEFF}').split("\r\n").collect();
        assert_eq!(lines[0], "Name,vCPU,RAM");
        assert_eq!(lines[1], "\"'=HYPERLINK(\"\"http://example.com\"\")\",4,2.50");
        assert_eq!(lines[2], "\"'+1; -2\",,");
        assert_eq!(sheet.csv_name(), "vms.csv");
    }

    #[test]
    fn numbers_show_plainly() {
        assert_eq!(Cell::number(8.0).display(), "8");
        assert_eq!(Cell::number(7.456).display(), "7.46");
        assert_eq!(Cell::number(f64::NAN), Cell::Empty);
        assert_eq!(Cell::int(u64::MAX), Cell::Empty);
        assert_eq!(Cell::opt_int(Some(3u32)), Cell::Int(3));
    }
}
