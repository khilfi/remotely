//! VM-28: YAML for Ubuntu autoinstall and cloud-init user data.
//!
//! * [`parse`] builds a small tree with line numbers from `saphyr-parser`'s events, with caps for a hostile file
//!   (nodes, depth, alias expansion). Scalars keep their text and whether they were quoted: Subiquity and cloud-init
//!   read YAML with PyYAML, which is YAML 1.1, so [`Node::as_bool`] takes `yes`, `no`, `on` and `off` as it does.
//! * [`emit`] writes a value in block style, two spaces a level, quoting a string whenever a plain one could read as
//!   something else.
//! * [`set`] changes one key of a block mapping in place: its line (and the lines under it) are replaced, every other
//!   line stays as it was, comments included. The result is parsed again and compared with the old tree minus that key;
//!   when anything else would change (a flow mapping, an anchor, a layout the editor can't follow), it refuses.

use std::collections::HashMap;

use saphyr_parser::{Event, Parser, ScalarStyle, Span, SpannedEventReceiver};

/// Nodes one file may hold, aliases expanded.
const MAX_NODES: usize = 50_000;
/// Collections inside each other.
const MAX_DEPTH: usize = 64;

/// How a scalar was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// Unquoted, as read: its type is YAML 1.1's (a bool, a number, null or a string).
    Plain,
    Quoted,
    /// A `|` or `>` block.
    Block,
    /// A string made to be written: plain when that reads back as the same string, else quoted.
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Str(String, Style),
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>),
}

/// A value and the line (from 1) it starts on; 0 for a value made to be emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub line: u32,
    pub value: Value,
}

/// Why a file isn't YAML Remotely can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError {
    pub line: u32,
    pub message: String,
}

impl Node {
    pub fn new(value: Value) -> Self {
        Self { line: 0, value }
    }

    /// A string, written plain when it can be.
    pub fn str(text: impl Into<String>) -> Self {
        Self::new(Value::Str(text.into(), Style::Auto))
    }

    /// A string emitted in double quotes whatever it holds.
    pub fn quoted(text: impl Into<String>) -> Self {
        Self::new(Value::Str(text.into(), Style::Quoted))
    }

    pub fn bool(value: bool) -> Self {
        Self::new(Value::Str((if value { "true" } else { "false" }).into(), Style::Plain))
    }

    pub fn int(value: i64) -> Self {
        Self::new(Value::Str(value.to_string(), Style::Plain))
    }

    pub fn seq(items: Vec<Node>) -> Self {
        Self::new(Value::Seq(items))
    }

    pub fn map(entries: Vec<(&str, Node)>) -> Self {
        Self::new(Value::Map(
            entries.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        ))
    }

    /// The value of `key` in a mapping (the last, as PyYAML keeps it).
    pub fn get(&self, key: &str) -> Option<&Node> {
        match &self.value {
            Value::Map(entries) => entries.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Follows keys down nested mappings.
    pub fn at(&self, path: &[&str]) -> Option<&Node> {
        path.iter().try_fold(self, |node, key| node.get(key))
    }

    pub fn entries(&self) -> &[(String, Node)] {
        match &self.value {
            Value::Map(entries) => entries,
            _ => &[],
        }
    }

    pub fn items(&self) -> &[Node] {
        match &self.value {
            Value::Seq(items) => items,
            _ => &[],
        }
    }

    pub fn is_map(&self) -> bool {
        matches!(self.value, Value::Map(_))
    }

    pub fn is_seq(&self) -> bool {
        matches!(self.value, Value::Seq(_))
    }

    /// PyYAML's null: nothing, `~` or `null` in any of its spellings, unquoted.
    pub fn is_null(&self) -> bool {
        match &self.value {
            Value::Null => true,
            Value::Str(text, Style::Plain) => matches!(text.as_str(), "" | "~" | "null" | "Null" | "NULL"),
            _ => false,
        }
    }

    /// A string as PyYAML would give it: quoted text, or plain text that isn't a bool, a number or null.
    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            Value::Str(text, Style::Quoted | Style::Block | Style::Auto) => Some(text),
            Value::Str(text, Style::Plain) => {
                (!self.is_null() && bool_11(text).is_none() && !looks_numeric(text)).then_some(text.as_str())
            }
            _ => None,
        }
    }

    /// Any scalar's text, whatever type PyYAML would make of it.
    pub fn text(&self) -> Option<&str> {
        match &self.value {
            Value::Str(text, _) => Some(text),
            _ => None,
        }
    }

    /// YAML 1.1's booleans, as PyYAML reads them: true, yes, on and their opposites, unquoted.
    pub fn as_bool(&self) -> Option<bool> {
        match &self.value {
            Value::Str(text, Style::Plain) => bool_11(text),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match &self.value {
            Value::Str(text, Style::Plain) => text.replace('_', "").parse().ok(),
            _ => None,
        }
    }

    /// What the value means, positions and quoting aside where they don't change it.
    pub fn same(&self, other: &Node) -> bool {
        match (&self.value, &other.value) {
            (Value::Seq(a), Value::Seq(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.same(y)),
            (Value::Map(a), Value::Map(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|((ka, va), (kb, vb))| ka == kb && va.same(vb))
            }
            _ => self.resolved() == other.resolved(),
        }
    }

    /// A scalar's type and text as PyYAML reads it.
    fn resolved(&self) -> Option<(&'static str, String)> {
        if self.is_null() {
            return Some(("null", String::new()));
        }
        if let Some(b) = self.as_bool() {
            return Some(("bool", b.to_string()));
        }
        match &self.value {
            Value::Str(text, Style::Plain) if looks_numeric(text) => Some(("number", text.clone())),
            Value::Str(text, _) => Some(("str", text.clone())),
            _ => None,
        }
    }
}

/// YAML 1.1's boolean spellings.
fn bool_11(text: &str) -> Option<bool> {
    match text {
        "y" | "Y" | "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => Some(true),
        "n" | "N" | "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => Some(false),
        _ => None,
    }
}

/// An integer or float as YAML 1.1 would read it (roughly: digits, a sign, a dot, an exponent, 0x, 0o, `_`).
fn looks_numeric(text: &str) -> bool {
    let t = text.strip_prefix(['-', '+']).unwrap_or(text).replace('_', "");
    if t.is_empty() {
        return false;
    }
    if let Some(hex) = t.strip_prefix("0x") {
        return !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    if let Some(oct) = t.strip_prefix("0o") {
        return !oct.is_empty() && oct.chars().all(|c| c.is_digit(8));
    }
    if matches!(t.as_str(), ".inf" | ".Inf" | ".INF" | ".nan" | ".NaN" | ".NAN") {
        return true;
    }
    // Sexagesimal (1:30) is YAML 1.1 too; the installers' keys never hold one, but a plain time would read as one.
    if t.contains(':')
        && t.split(':')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    {
        return true;
    }
    let mut digits = false;
    let mut dot = false;
    let mut exp = false;
    let mut chars = t.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '0'..='9' => digits = true,
            '.' if !dot && !exp => dot = true,
            'e' | 'E' if digits && !exp => {
                exp = true;
                if matches!(chars.peek(), Some('-' | '+')) {
                    chars.next();
                }
            }
            _ => return false,
        }
    }
    digits
}

// ---- Parsing ------------------------------------------------------------------------------------------------------

enum Frame {
    Seq {
        line: u32,
        anchor: usize,
        items: Vec<Node>,
    },
    Map {
        line: u32,
        anchor: usize,
        entries: Vec<(String, Node)>,
        key: Option<String>,
    },
}

#[derive(Default)]
struct Builder {
    stack: Vec<Frame>,
    docs: Vec<Node>,
    anchors: HashMap<usize, Node>,
    nodes: usize,
    error: Option<YamlError>,
    duplicates: Vec<(u32, String)>,
}

fn count(node: &Node) -> usize {
    1 + match &node.value {
        Value::Seq(items) => items.iter().map(count).sum(),
        Value::Map(entries) => entries.iter().map(|(_, v)| 1 + count(v)).sum(),
        _ => 0,
    }
}

impl Builder {
    fn fail(&mut self, line: u32, message: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(YamlError {
                line,
                message: message.into(),
            });
        }
    }

    fn add(&mut self, node: Node, anchor: usize) {
        self.nodes += count(&node);
        if self.nodes > MAX_NODES {
            self.fail(
                node.line,
                "The file is too large to check: it holds more than 50,000 values.",
            );
            return;
        }
        if anchor > 0 {
            self.anchors.insert(anchor, node.clone());
        }
        match self.stack.last_mut() {
            None => self.docs.push(node),
            Some(Frame::Seq { items, .. }) => items.push(node),
            Some(Frame::Map { entries, key, .. }) => match key.take() {
                None => {
                    let line = node.line;
                    match node.value {
                        Value::Str(text, _) => *key = Some(text),
                        Value::Null => *key = Some(String::new()),
                        _ => self.fail(
                            line,
                            "A key here is a list or a mapping, which the installers don't read.",
                        ),
                    }
                }
                Some(k) => {
                    if entries.iter().any(|(e, _)| *e == k) {
                        self.duplicates.push((node.line, k.clone()));
                    }
                    entries.push((k, node));
                }
            },
        }
    }
}

impl<'input> SpannedEventReceiver<'input> for Builder {
    fn on_event(&mut self, ev: Event<'input>, span: Span) {
        if self.error.is_some() {
            return;
        }
        let line = u32::try_from(span.start.line()).unwrap_or(u32::MAX);
        match ev {
            Event::Scalar(text, style, anchor, _tag) => {
                let style = match style {
                    ScalarStyle::Plain => Style::Plain,
                    ScalarStyle::SingleQuoted | ScalarStyle::DoubleQuoted => Style::Quoted,
                    _ => Style::Block,
                };
                let value = if style == Style::Plain && text.is_empty() {
                    Value::Null
                } else {
                    Value::Str(text.into_owned(), style)
                };
                self.add(Node { line, value }, anchor);
            }
            Event::SequenceStart(anchor, _) => {
                if self.stack.len() >= MAX_DEPTH {
                    self.fail(line, "The file nests lists and mappings more than 64 deep.");
                    return;
                }
                self.stack.push(Frame::Seq {
                    line,
                    anchor,
                    items: Vec::new(),
                });
            }
            Event::MappingStart(anchor, _) => {
                if self.stack.len() >= MAX_DEPTH {
                    self.fail(line, "The file nests lists and mappings more than 64 deep.");
                    return;
                }
                self.stack.push(Frame::Map {
                    line,
                    anchor,
                    entries: Vec::new(),
                    key: None,
                });
            }
            Event::SequenceEnd | Event::MappingEnd => match self.stack.pop() {
                Some(Frame::Seq { line, anchor, items }) => self.add(
                    Node {
                        line,
                        value: Value::Seq(items),
                    },
                    anchor,
                ),
                Some(Frame::Map {
                    line, anchor, entries, ..
                }) => self.add(
                    Node {
                        line,
                        value: Value::Map(entries),
                    },
                    anchor,
                ),
                None => self.fail(line, "A list or mapping ends that never started."),
            },
            Event::Alias(id) => match self.anchors.get(&id).cloned() {
                Some(node) => self.add(Node { line, ..node }, 0),
                None => self.fail(line, "An alias names an anchor that isn't defined before it."),
            },
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentStart(_) | Event::DocumentEnd => {}
        }
    }
}

/// What [`parse`] found: each document's root, and keys written twice (PyYAML keeps the last).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub docs: Vec<Node>,
    pub duplicates: Vec<(u32, String)>,
}

/// Every document of `text`, or the first reason it isn't YAML (with its line).
pub fn parse(text: &str) -> Result<Parsed, YamlError> {
    let mut builder = Builder::default();
    let mut parser = Parser::new_from_str(text);
    if let Err(err) = parser.load(&mut builder, true) {
        let line = u32::try_from(err.marker().line()).unwrap_or(u32::MAX);
        return Err(YamlError {
            line,
            message: format!("This isn't valid YAML: {}.", err.info()),
        });
    }
    if let Some(err) = builder.error {
        return Err(err);
    }
    Ok(Parsed {
        docs: builder.docs,
        duplicates: builder.duplicates,
    })
}

// ---- Emitting -----------------------------------------------------------------------------------------------------

/// Whether a plain scalar reads back as this same string.
fn plain_ok(text: &str) -> bool {
    if text.is_empty() || text != text.trim() || bool_11(text).is_some() || looks_numeric(text) {
        return false;
    }
    if matches!(text, "~" | "null" | "Null" | "NULL" | "<<" | "=") {
        return false;
    }
    let first = text.chars().next().unwrap_or(' ');
    if "-?:,[]{}#&*!|>'\"%@`".contains(first) && !(first == '-' && text.len() > 1 && !text.starts_with("- ")) {
        return false;
    }
    if text.ends_with(':') || text.contains(": ") || text.contains(" #") || text.contains(['\t', '\n', '\r']) {
        return false;
    }
    text.chars()
        .all(|c| c.is_ascii_alphanumeric() || " _./@+-=:,()~^%$*&!?".contains(c) || (c as u32) >= 0xa0)
        && !text.contains(['{', '}', '[', ']'])
}

/// A double-quoted scalar: JSON's escapes, which YAML reads the same.
pub fn quote(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned())
}

fn scalar(text: &str, style: Style) -> String {
    match style {
        // As it was read: it reads back the same.
        Style::Plain if text.is_empty() => "null".to_owned(),
        Style::Plain => text.to_owned(),
        Style::Auto if plain_ok(text) => text.to_owned(),
        _ => quote(text),
    }
}

fn is_inline(node: &Node) -> bool {
    match &node.value {
        Value::Null | Value::Str(..) => true,
        Value::Seq(items) => items.is_empty(),
        Value::Map(entries) => entries.is_empty(),
    }
}

fn inline(node: &Node) -> String {
    match &node.value {
        Value::Null => "null".to_owned(),
        Value::Str(text, style) => scalar(text, *style),
        Value::Seq(_) => "[]".to_owned(),
        Value::Map(_) => "{}".to_owned(),
    }
}

/// A literal block scalar (`|`) when that keeps the text exactly, for multi-line commands.
fn literal(text: &str, indent: usize) -> Option<Vec<String>> {
    if !text.contains('\n') || text.starts_with([' ', '\n']) || text.contains(['\r', '\t']) {
        return None;
    }
    let body = text.strip_suffix('\n');
    let (head, lines) = match body {
        Some(rest) if !rest.ends_with('\n') => ("|", rest),
        None => ("|-", text),
        Some(_) => return None,
    };
    let pad = " ".repeat(indent);
    let mut out = vec![head.to_owned()];
    for line in lines.split('\n') {
        out.push(if line.is_empty() {
            String::new()
        } else {
            format!("{pad}{line}")
        });
    }
    Some(out)
}

/// `key: value` lines for a mapping entry at `indent`.
fn emit_entry(key: &str, value: &Node, indent: usize, out: &mut Vec<String>) {
    let pad = " ".repeat(indent);
    let key = scalar(key, Style::Auto);
    if let Value::Str(text, Style::Block | Style::Quoted | Style::Auto) = &value.value {
        if let Some(block) = literal(text, indent + 2) {
            let mut lines = block.into_iter();
            out.push(format!("{pad}{key}: {}", lines.next().unwrap_or_default()));
            out.extend(lines);
            return;
        }
    }
    if is_inline(value) {
        out.push(format!("{pad}{key}: {}", inline(value)));
        return;
    }
    out.push(format!("{pad}{key}:"));
    emit_block(value, indent + 2, out);
}

/// A collection's lines at `indent`.
fn emit_block(node: &Node, indent: usize, out: &mut Vec<String>) {
    let pad = " ".repeat(indent);
    match &node.value {
        Value::Map(entries) => {
            for (key, value) in entries {
                emit_entry(key, value, indent, out);
            }
        }
        Value::Seq(items) => {
            for item in items {
                if is_inline(item) {
                    match &item.value {
                        Value::Str(text, _) if literal(text, indent + 2).is_some() => {
                            let block = literal(text, indent + 2).unwrap_or_default();
                            let mut lines = block.into_iter();
                            out.push(format!("{pad}- {}", lines.next().unwrap_or_default()));
                            out.extend(lines);
                        }
                        _ => out.push(format!("{pad}- {}", inline(item))),
                    }
                    continue;
                }
                let mut inner = Vec::new();
                emit_block(item, indent + 2, &mut inner);
                let first = inner.first().map(|l| l.trim_start().to_owned()).unwrap_or_default();
                if item.is_map() {
                    out.push(format!("{pad}- {first}"));
                    out.extend(inner.into_iter().skip(1));
                } else {
                    out.push(format!("{pad}-"));
                    out.extend(inner);
                }
            }
        }
        _ => out.push(format!("{pad}{}", inline(node))),
    }
}

/// `node` as block-style YAML lines at `indent`, for a document's root or a key's value.
pub fn emit(node: &Node, indent: usize) -> Vec<String> {
    let mut out = Vec::new();
    emit_block(node, indent, &mut out);
    out
}

// ---- Editing in place ---------------------------------------------------------------------------------------------

/// Why [`set`] can't change a key: the message for the user, and which check refused (for tests and logs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditError(pub String, pub &'static str);

fn layout_at(site: &'static str) -> EditError {
    EditError(
        "The form can't change this part of the file without changing others (it's written in a style the form \
         doesn't follow): edit the file instead."
            .into(),
        site,
    )
}

struct Line<'a> {
    text: &'a str,
    indent: usize,
    /// Blank or a comment.
    blank: bool,
}

fn lines_of(text: &str) -> Vec<Line<'_>> {
    text.split('\n')
        .map(|raw| {
            let text = raw.strip_suffix('\r').unwrap_or(raw);
            let trimmed = text.trim_start_matches(' ');
            Line {
                text,
                indent: text.len() - trimmed.len(),
                blank: trimmed.is_empty() || trimmed.starts_with('#'),
            }
        })
        .collect()
}

/// The key a line starts with at its indent, and where its value starts (bytes into the line).
fn key_of(line: &str, indent: usize) -> Option<(String, usize)> {
    let rest = line.get(indent..)?;
    if rest.starts_with(['-', '#', '?']) || rest.starts_with("---") {
        return None;
    }
    let (key, after) = if let Some(q) = rest.strip_prefix('"') {
        let end = q.find('"')?;
        (q[..end].to_owned(), 1 + end + 1)
    } else if let Some(q) = rest.strip_prefix('\'') {
        let end = q.find('\'')?;
        (q[..end].to_owned(), 1 + end + 1)
    } else {
        let colon = rest.find(':')?;
        (rest[..colon].trim_end().to_owned(), colon)
    };
    let tail = rest.get(after..)?;
    let tail = tail.trim_start_matches(' ');
    let colon_at = rest.len() - tail.len();
    let after_colon = tail.strip_prefix(':')?;
    if !(after_colon.is_empty() || after_colon.starts_with([' ', '\t'])) {
        return None;
    }
    if key.is_empty() || key.contains(['{', '[', ',']) {
        return None;
    }
    Some((key, indent + colon_at + 1))
}

/// The lines (half-open) a key's value takes below its own line: deeper lines, and a sequence at the key's indent.
fn block_end(lines: &[Line<'_>], key_line: usize, indent: usize, end: usize) -> usize {
    let mut last = key_line;
    let mut i = key_line + 1;
    while i < end {
        let line = &lines[i];
        if line.blank {
            i += 1;
            continue;
        }
        let same_level_item = line.indent == indent && line.text[indent..].starts_with('-');
        if line.indent > indent || same_level_item {
            last = i;
            i += 1;
            continue;
        }
        break;
    }
    last + 1
}

/// The document's own lines: after a `---` or `%` directives, up to the next document.
fn document_range(lines: &[Line<'_>]) -> (usize, usize) {
    let mut start = 0;
    for (i, line) in lines.iter().enumerate() {
        if line.text.starts_with('%') {
            start = i + 1;
            continue;
        }
        if line.text.starts_with("---") {
            start = i + 1;
        }
        if !line.blank && !line.text.starts_with('%') {
            break;
        }
    }
    let end = lines
        .iter()
        .enumerate()
        .skip(start)
        .find(|(_, l)| l.text.starts_with("---") || l.text.starts_with("..."))
        .map_or(lines.len(), |(i, _)| i);
    (start, end)
}

/// A mapping's children: the indent they sit at (None when it has none) within lines `start..end`.
fn child_indent(lines: &[Line<'_>], start: usize, end: usize, deeper_than: Option<usize>) -> Option<usize> {
    lines[start..end]
        .iter()
        .find(|l| !l.blank)
        .map(|l| l.indent)
        .filter(|i| deeper_than.is_none_or(|d| *i > d))
}

/// Where `key` is among a mapping's children at `indent` in `start..end`: its line.
fn find_key(lines: &[Line<'_>], start: usize, end: usize, indent: usize, key: &str) -> Option<usize> {
    (start..end).rev().find(|&i| {
        let line = &lines[i];
        !line.blank && line.indent == indent && key_of(line.text, indent).is_some_and(|(k, _)| k == key)
    })
}

/// Sets `path` (keys from the document's root) to `value`, or removes it with `None`, keeping every other line.
pub fn set(text: &str, path: &[&str], value: Option<&Node>) -> Result<String, EditError> {
    if path.is_empty() {
        return Err(layout_at("empty path"));
    }
    let before = parse(text).map_err(|_| layout_at("unreadable before"))?;
    let ending = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let lines = lines_of(text);
    let (doc_start, doc_end) = document_range(&lines);
    let mut out: Vec<String> = lines.iter().map(|l| l.text.to_owned()).collect();

    // Walk down: each level's range of lines and the indent its children have.
    let mut start = doc_start;
    let mut end = doc_end;
    let mut parent_indent: Option<usize> = None;
    let mut step = 2usize;
    for (depth, key) in path.iter().enumerate() {
        let last = depth + 1 == path.len();
        let indent = child_indent(&lines, start, end, parent_indent);
        let found = indent.and_then(|i| find_key(&lines, start, end, i, key));
        match found {
            Some(at) => {
                let indent = indent.unwrap_or(0);
                let (_, value_at) = key_of(lines[at].text, indent).ok_or_else(|| layout_at("key line"))?;
                let inline = lines[at].text[value_at..].trim();
                let inline = inline.split(" #").next().unwrap_or("").trim();
                let block = block_end(&lines, at, indent, end);
                if last {
                    let mut replacement = Vec::new();
                    if let Some(value) = value {
                        emit_entry(key, value, indent, &mut replacement);
                    }
                    out.splice(at..block, replacement);
                    break;
                }
                // Going deeper: the value must be a block mapping, or empty.
                if !(inline.is_empty() || inline == "{}" || inline == "null" || inline == "~") {
                    return Err(layout_at("not a block mapping"));
                }
                if inline == "{}" || inline == "null" || inline == "~" {
                    if block > at + 1 {
                        return Err(layout_at("inline value with lines below"));
                    }
                    // `key: {}` becomes `key:` with the rest made below it.
                    let line = format!("{}{key}:", " ".repeat(indent));
                    out[at] = line;
                    let rest: Vec<&str> = path[depth + 1..].to_vec();
                    let made = nested(&rest, value, indent + step);
                    out.splice(at + 1..at + 1, made);
                    break;
                }
                if let Some(child) = child_indent(&lines, at + 1, block, Some(indent)) {
                    step = child - indent;
                }
                parent_indent = Some(indent);
                start = at + 1;
                end = block;
            }
            None => {
                let Some(value) = value else {
                    // Nothing to remove.
                    return Ok(text.to_owned());
                };
                let indent = indent.unwrap_or_else(|| parent_indent.map_or(0, |p| p + step));
                let rest: Vec<&str> = path[depth..].to_vec();
                let made = nested(&rest, Some(value), indent);
                // After the last line of this mapping that holds something.
                let insert_at = (start..end).rev().find(|&i| !lines[i].blank).map_or(start, |i| i + 1);
                let insert_at = insert_at.max(start);
                out.splice(insert_at..insert_at, made);
                break;
            }
        }
    }
    let mut joined = out.join(ending);
    if text.is_empty() && !joined.ends_with('\n') {
        joined.push_str(ending);
    }
    verify(&before, &joined, path, value)?;
    Ok(joined)
}

/// `a:` / `  b:` / `    c: value` for the keys still to make.
fn nested(path: &[&str], value: Option<&Node>, indent: usize) -> Vec<String> {
    let mut out = Vec::new();
    let Some(value) = value else {
        return out;
    };
    let mut indent = indent;
    for (i, key) in path.iter().enumerate() {
        if i + 1 == path.len() {
            emit_entry(key, value, indent, &mut out);
        } else {
            out.push(format!("{}{}:", " ".repeat(indent), scalar(key, Style::Auto)));
            indent += 2;
        }
    }
    out
}

/// The edit changed `path` to `value` and nothing else.
fn verify(before: &Parsed, after_text: &str, path: &[&str], value: Option<&Node>) -> Result<(), EditError> {
    let after = parse(after_text).map_err(|_| layout_at("unreadable after"))?;
    // An empty file gains its first document; otherwise the documents stay as many.
    if before.docs.len() != after.docs.len() && !(before.docs.is_empty() && after.docs.len() == 1) {
        return Err(layout_at("documents changed"));
    }
    let empty = Node::new(Value::Null);
    let old_root = before.docs.first().unwrap_or(&empty);
    let new_root = after.docs.first().ok_or_else(|| layout_at("no document"))?;
    match (value, new_root.at(path)) {
        (Some(v), Some(found)) if found.same(v) => {}
        (None, None) => {}
        _ => return Err(layout_at("value not as set")),
    }
    if !without(old_root, path).same(&without(new_root, path)) {
        return Err(layout_at("other keys changed"));
    }
    for (a, b) in before.docs.iter().zip(&after.docs).skip(1) {
        if !a.same(b) {
            return Err(layout_at("other documents changed"));
        }
    }
    Ok(())
}

/// `node` with `path` taken out, and mappings it leaves empty (made for the path) too.
fn without(node: &Node, path: &[&str]) -> Node {
    let Some((first, rest)) = path.split_first() else {
        return node.clone();
    };
    match &node.value {
        Value::Map(entries) => {
            let mut kept = Vec::new();
            for (k, v) in entries {
                if k != first {
                    kept.push((k.clone(), v.clone()));
                } else if !rest.is_empty() {
                    let inner = without(v, rest);
                    let emptied = inner.is_null() || (inner.is_map() && inner.entries().is_empty());
                    if !emptied {
                        kept.push((k.clone(), inner));
                    }
                }
            }
            Node {
                line: node.line,
                value: Value::Map(kept),
            }
        }
        _ if node.is_null() => Node::new(Value::Map(Vec::new())),
        _ => node.clone(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn root(text: &str) -> Node {
        parse(text).unwrap().docs.into_iter().next().unwrap()
    }

    #[test]
    fn values_read_as_pyyaml_reads_them() {
        let doc = root("a: yes\nb: 'yes'\nc: 0755\nd: ~\ne:\nf: \"x\"\ng: 1.5\nh: web-1\n");
        assert_eq!(doc.get("a").unwrap().as_bool(), Some(true));
        assert_eq!(doc.get("b").unwrap().as_str(), Some("yes"));
        assert_eq!(doc.get("b").unwrap().as_bool(), None);
        assert_eq!(doc.get("c").unwrap().as_str(), None, "a number");
        assert!(doc.get("d").unwrap().is_null());
        assert!(doc.get("e").unwrap().is_null());
        assert_eq!(doc.get("f").unwrap().as_str(), Some("x"));
        assert_eq!(doc.get("g").unwrap().as_str(), None);
        assert_eq!(doc.get("h").unwrap().as_str(), Some("web-1"));
        assert_eq!(doc.get("h").unwrap().line, 8);
    }

    #[test]
    fn errors_name_their_line() {
        let err = parse("a: 1\nb: [1, 2\nc: 3\n").unwrap_err();
        assert!(err.line >= 2, "{err:?}");
        assert!(err.message.starts_with("This isn't valid YAML"), "{err:?}");
        let err = parse("a: *nothing\n").unwrap_err();
        assert!(err.message.contains("anchor"), "{err:?}");
    }

    #[test]
    fn hostile_files_stop_at_the_caps() {
        // A billion laughs: each level doubles the one before.
        let mut text = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..12 {
            let p = i - 1;
            text.push_str(&format!(
                "a{i}: &a{i} [*a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}]\n"
            ));
        }
        assert!(parse(&text).unwrap_err().message.contains("too large"));
        let deep = format!("{}{}", "[".repeat(100), "]".repeat(100));
        assert!(parse(&deep).unwrap_err().message.contains("64 deep"));
    }

    #[test]
    fn duplicate_keys_are_noted() {
        let parsed = parse("a: 1\nb: 2\na: 3\n").unwrap();
        assert_eq!(parsed.duplicates, [(3, "a".to_owned())]);
        assert_eq!(parsed.docs[0].get("a").unwrap().text(), Some("3"));
    }

    #[test]
    fn emitted_values_read_back_the_same() {
        let value = Node::map(vec![
            ("plain", Node::str("web-1")),
            ("yes", Node::str("yes")),
            ("number", Node::str("0755")),
            ("colon", Node::str("a: b")),
            ("placeholder", Node::str("{{hostname}}")),
            ("flag", Node::bool(true)),
            ("empty", Node::seq(vec![])),
            ("list", Node::seq(vec![Node::str("a"), Node::str("b c")])),
            (
                "users",
                Node::seq(vec![Node::map(vec![
                    ("name", Node::str("alice")),
                    ("keys", Node::seq(vec![Node::str("ssh-ed25519 AAAA alice@example.com")])),
                ])]),
            ),
            ("script", Node::str("echo one\necho two\n")),
        ]);
        let text = emit(&value, 0).join("\n");
        let back = root(&text);
        assert!(back.same(&value), "{text}");
        assert!(text.contains("placeholder: \"{{hostname}}\""), "{text}");
        assert!(
            text.contains("\"yes\": \"yes\""),
            "a key PyYAML would read as true is quoted too: {text}"
        );
        assert!(text.contains("script: |\n  echo one\n  echo two"), "{text}");
        assert!(
            text.contains("- name: alice\n    keys:\n      - ssh-ed25519 AAAA alice@example.com"),
            "{text}"
        );
    }

    const FILE: &str = "#cloud-config\n# A comment that stays.\nautoinstall:\n  version: 1\n  identity:\n    hostname: old # here\n    username: alice\n  # Packages below.\n  packages:\n  - curl\n  - git\n  late-commands: [\"true\"]\n";

    #[test]
    fn a_key_changes_and_every_other_line_stays() {
        let out = set(
            FILE,
            &["autoinstall", "identity", "hostname"],
            Some(&Node::str("{{hostname}}")),
        )
        .unwrap();
        assert_eq!(
            out,
            FILE.replace("    hostname: old # here", "    hostname: \"{{hostname}}\"")
        );
        // A list at the key's own indent is replaced whole.
        let out = set(
            FILE,
            &["autoinstall", "packages"],
            Some(&Node::seq(vec![Node::str("nginx")])),
        )
        .unwrap();
        assert!(
            out.contains("  # Packages below.\n  packages:\n    - nginx\n  late-commands"),
            "{out}"
        );
        // A new key goes at the end of its mapping, and missing mappings are made.
        let out = set(FILE, &["autoinstall", "ssh", "allow-pw"], Some(&Node::bool(false))).unwrap();
        assert!(
            out.ends_with("  late-commands: [\"true\"]\n  ssh:\n    allow-pw: false\n"),
            "{out}"
        );
        let out = set(
            FILE,
            &["autoinstall", "identity", "realname"],
            Some(&Node::str("Alice")),
        )
        .unwrap();
        assert!(
            out.contains("    username: alice\n    realname: Alice\n  # Packages"),
            "{out}"
        );
        // Removed.
        let out = set(FILE, &["autoinstall", "packages"], None).unwrap();
        assert!(!out.contains("curl") && out.contains("# Packages below."), "{out}");
        assert_eq!(set(FILE, &["autoinstall", "absent"], None).unwrap(), FILE);
        // Windows line endings stay.
        let crlf = FILE.replace('\n', "\r\n");
        let out = set(&crlf, &["autoinstall", "version"], Some(&Node::int(1))).unwrap();
        assert!(!out.replace("\r\n", "").contains('\n'), "{out:?}");
    }

    #[test]
    fn layouts_the_editor_cant_follow_are_refused() {
        let flow = "autoinstall: {version: 1, identity: {hostname: a}}\n";
        assert!(set(flow, &["autoinstall", "identity", "hostname"], Some(&Node::str("b"))).is_err());
        let anchored = "base: &b\n  x: 1\nother:\n  <<: *b\n";
        // Changing the anchor would change the alias too.
        assert!(set(anchored, &["base", "x"], Some(&Node::int(2))).is_err());
        // An empty file gets its first key.
        assert_eq!(set("", &["a"], Some(&Node::int(1))).unwrap(), "a: 1\n");
        // `key: {}` opens up.
        let out = set("a: {}\nb: 2\n", &["a", "c"], Some(&Node::int(1))).unwrap();
        assert_eq!(out, "a:\n  c: 1\nb: 2\n");
    }
}
