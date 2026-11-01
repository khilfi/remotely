//! FD-05, FD-08: one table model for every format a report is written in: an Excel sheet ([`super::xlsx`]), a CSV
//! file (A10's rules, through [`crate::export::push_row`]) and an HTML table ([`super::html`]).
//!
//! Every text cell is made here ([`Cell::text`]), so every format gets the same clean text: anything that looks like a
//! secret replaced (`export::redact_secrets`; a session name, a tag or a note may hold one by mistake), control and
//! invisible format characters (U+202E and the like, which can make a name read backwards) taken out, line breaks
//! made spaces, and the length capped at what an Excel cell holds.

use crate::export::{push_row, redact_secrets};
use crate::untrusted::is_format_char;

/// UTF-16 units a cell keeps at most. Excel's cells hold 32,767 of them (an emoji takes two).
pub const MAX_CELL_UNITS: usize = 32_000;

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

/// A character that ends a line somewhere a report is read: line feed, carriage return, vertical tab, form feed, and
/// U+0085, U+2028 and U+2029, which YAML, Python's `splitlines` and JavaScript take for line breaks too.
pub fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// U+FFFE and U+FFFF, which XML 1.0 doesn't take: a workbook or an SVG holding one doesn't open.
pub fn is_not_xml(c: char) -> bool {
    matches!(c, '\u{FFFE}' | '\u{FFFF}')
}

/// Text fit for a report: control, format and non-XML characters out, line breaks and tabs made spaces, runs of spaces
/// made one, trimmed; then secrets redacted (after, so a zero-width space between `password=` and its value can't hide
/// it); then cut at [`MAX_CELL_UNITS`] UTF-16 units (by character, never by byte), as Excel counts.
pub fn clean(value: &str) -> String {
    let mut text = String::with_capacity(value.len());
    let mut space = false;
    for c in value.chars() {
        let c = if is_line_break(c) || c == '\t' { ' ' } else { c };
        if c.is_control() || is_format_char(c) || is_not_xml(c) {
            continue;
        }
        if c == ' ' {
            if space || text.is_empty() {
                continue;
            }
            space = true;
        } else {
            space = false;
        }
        text.push(c);
    }
    let (redacted, _) = redact_secrets(text.trim_end());
    cut_units(redacted.trim_end(), MAX_CELL_UNITS)
}

/// `text` cut at `max` UTF-16 units, an ellipsis after it when cut.
fn cut_units(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max * 2));
    let mut units = 0;
    for c in text.chars() {
        if units + c.len_utf16() > max {
            out.push('…');
            break;
        }
        units += c.len_utf16();
        out.push(c);
    }
    out
}

/// Text that keeps its lines (a job's output in the handover pack): control, format and non-XML characters out but
/// line breaks (each kind made `\n`) and tabs kept; then secrets redacted; then cut at `max_chars`.
pub fn clean_lines(value: &str, max_chars: usize) -> (String, bool) {
    let mut text = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' && chars.peek() == Some(&'\n') {
            continue;
        }
        if is_line_break(c) {
            text.push('\n');
        } else if c == '\t' || !(c.is_control() || is_format_char(c) || is_not_xml(c)) {
            text.push(c);
        }
    }
    let (redacted, _) = redact_secrets(&text);
    let mut out = String::new();
    for (count, c) in redacted.chars().enumerate() {
        if count >= max_chars {
            return (out, true);
        }
        out.push(c);
    }
    (out, false)
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
        let long = "\u{e9}".repeat(MAX_CELL_UNITS + 10);
        let Cell::Text(cut) = Cell::text(&long) else {
            panic!("text")
        };
        assert_eq!(
            cut.chars().count(),
            MAX_CELL_UNITS + 1,
            "cut by character, with an ellipsis"
        );
        // Excel counts UTF-16 units: 20,000 emoji are 40,000 of them.
        let Cell::Text(cut) = Cell::text("\u{1F600}".repeat(20_000)) else {
            panic!("text")
        };
        assert!(cut.encode_utf16().count() <= 32_767, "{}", cut.encode_utf16().count());
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn a_hidden_character_never_hides_a_secret() {
        for text in [
            "password\u{200B}=Hunter2Hunter2",
            "password=\u{200B}Hunter2Hunter2",
            "pass\u{2060}word=Hunter2Hunter2",
            "token:\u{0}\u{7}Hunter2Hunter2",
            "password\u{FEFF}: Hunter2Hunter2",
        ] {
            let cleaned = clean(text);
            assert!(!cleaned.contains("Hunter2"), "{text:?} gave {cleaned:?}");
            let (lines, _) = clean_lines(text, 1000);
            assert!(!lines.contains("Hunter2"), "{text:?} gave {lines:?}");
        }
    }

    #[test]
    fn every_kind_of_line_break_and_non_xml_character_goes() {
        assert_eq!(
            clean("a\u{2028}b\u{2029}c\u{85}d\u{0B}e\u{0C}f"),
            "a b c d e f",
            "YAML and Python break lines at these"
        );
        assert_eq!(clean("x\u{FFFE}y\u{FFFF}z"), "xyz");
        let (text, _) = clean_lines("one\u{2028}two\rthree\r\nfour\u{FFFF}", 100);
        assert_eq!(text, "one\ntwo\nthree\nfour");
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
