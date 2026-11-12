//! VM-28: Windows unattend files (`autounattend.xml`) read as untrusted, like `convert::describe`'s descriptions, but
//! strictly: an answer file Windows Setup can't read should say why before a deploy, with its line.
//!
//! [`parse`] checks well-formedness (one root, matching tags, unique attributes, quoted attribute values, `&` only as
//! one of XML's five entities or a character reference, no control characters) within caps: 64 elements deep and
//! 20,000 in all; the caller caps the file's size. A DOCTYPE is refused, so no entity is ever defined or expanded.
//! Each element keeps where it starts and ends in the text, so [`set_text`] can change one element's text and leave
//! every other byte as it was.

/// Elements inside each other.
const MAX_DEPTH: usize = 64;
/// Elements in all.
const MAX_ELEMENTS: usize = 20_000;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Element {
    /// As written, prefix included.
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Element>,
    /// The element's own text (not its children's), unescaped.
    pub text: String,
    pub line: u32,
    /// Byte offsets: the `<` of its start tag, just after that tag's `>`, the `<` of its end tag, just after it.
    pub start: usize,
    pub open_end: usize,
    pub close_start: usize,
    pub end: usize,
    pub self_closing: bool,
}

impl Element {
    /// The name without its prefix.
    pub fn local(&self) -> &str {
        self.name.rsplit(':').next().unwrap_or(&self.name)
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k.rsplit(':').next() == Some(name) || k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn child(&self, local: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.local() == local)
    }

    pub fn children_named<'a>(&'a self, local: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.local() == local)
    }

    /// Follows children by local name.
    pub fn at(&self, path: &[&str]) -> Option<&Element> {
        path.iter().try_fold(self, |e, name| e.child(name))
    }

    /// Every element under this one (itself included) with this local name, in document order.
    pub fn find_all<'a>(&'a self, local: &str, out: &mut Vec<&'a Element>) {
        if self.local() == local {
            out.push(self);
        }
        for child in &self.children {
            child.find_all(local, out);
        }
    }

    pub fn trimmed(&self) -> &str {
        self.text.trim()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlError {
    pub line: u32,
    pub message: String,
}

struct Reader<'a> {
    text: &'a str,
    line_starts: Vec<usize>,
}

impl Reader<'_> {
    fn line(&self, at: usize) -> u32 {
        let i = self.line_starts.partition_point(|s| *s <= at);
        u32::try_from(i).unwrap_or(u32::MAX)
    }

    fn err(&self, at: usize, message: impl Into<String>) -> XmlError {
        XmlError {
            line: self.line(at),
            message: message.into(),
        }
    }
}

fn name_start(c: char) -> bool {
    c.is_alphabetic() || c == '_' || c == ':'
}

fn name_char(c: char) -> bool {
    name_start(c) || c.is_alphanumeric() || matches!(c, '-' | '.' | '\u{b7}')
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(name_start) && chars.all(name_char)
}

fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}')
}

/// `&...;` in text or an attribute, unescaped; an error for anything that isn't one of XML's own.
fn unescape(reader: &Reader<'_>, at: usize, raw: &str) -> Result<String, XmlError> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    let mut offset = at;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let Some(semi) = after.find(';').filter(|s| *s <= 10) else {
            return Err(reader.err(
                offset + amp,
                "A & must start an entity such as &amp;: write &amp; for the character itself.",
            ));
        };
        let entity = &after[..semi];
        let ch = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32)
                .filter(|c| xml_char(*c)),
        };
        let Some(ch) = ch else {
            return Err(reader.err(
                offset + amp,
                format!("&{entity}; isn't an entity XML knows: only &amp; &lt; &gt; &quot; &apos; and character references."),
            ));
        };
        out.push(ch);
        let used = amp + 1 + semi + 1;
        offset += used;
        rest = &rest[used..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Parses an unattend file (or any XML document) into its root element, or the first reason it isn't well formed.
pub fn parse(text: &str) -> Result<Element, XmlError> {
    let mut line_starts = vec![0usize];
    line_starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
    let reader = Reader { text, line_starts };
    if let Some((at, _)) = text.char_indices().find(|(_, c)| !xml_char(*c)) {
        return Err(reader.err(at, "The file holds a control character XML doesn't allow."));
    }
    let mut pos = usize::from(text.starts_with('\u{feff}')) * '\u{feff}'.len_utf8();
    // The declaration, only at the very start.
    if text[pos..].starts_with("<?xml") {
        let Some(end) = text[pos..].find("?>") else {
            return Err(reader.err(pos, "The XML declaration isn't closed with ?>."));
        };
        pos += end + 2;
    }
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut count = 0usize;
    while pos < text.len() {
        let rest = &reader.text[pos..];
        let Some(lt) = rest.find('<') else {
            // Text after the last tag.
            if !rest.trim().is_empty() {
                return Err(reader.err(pos, "There is text after the root element ends."));
            }
            break;
        };
        // Text before the tag.
        if lt > 0 {
            let raw = &rest[..lt];
            match stack.last_mut() {
                Some(top) => {
                    if raw.contains('>') && raw.contains("]]>") {
                        return Err(reader.err(pos, "]]> can only end a CDATA section."));
                    }
                    let text = unescape(&reader, pos, raw)?;
                    top.text.push_str(&text);
                }
                None if !raw.trim().is_empty() => {
                    return Err(reader.err(pos, "There is text outside the root element."));
                }
                None => {}
            }
        }
        pos += lt;
        let tag = &reader.text[pos..];
        if let Some(after) = tag.strip_prefix("<!--") {
            let Some(end) = after.find("-->") else {
                return Err(reader.err(pos, "A comment isn't closed with -->."));
            };
            if after[..end].contains("--") {
                return Err(reader.err(pos, "A comment can't hold -- before its end."));
            }
            pos += 4 + end + 3;
            continue;
        }
        if let Some(after) = tag.strip_prefix("<![CDATA[") {
            let Some(end) = after.find("]]>") else {
                return Err(reader.err(pos, "A CDATA section isn't closed with ]]>."));
            };
            let Some(top) = stack.last_mut() else {
                return Err(reader.err(pos, "A CDATA section can only be inside an element."));
            };
            top.text.push_str(&after[..end]);
            pos += 9 + end + 3;
            continue;
        }
        if tag.starts_with("<!") {
            return Err(reader.err(
                pos,
                "A DOCTYPE or other declaration isn't allowed: answer files don't need one, and Remotely never defines entities.",
            ));
        }
        if let Some(after) = tag.strip_prefix("<?") {
            let Some(end) = after.find("?>") else {
                return Err(reader.err(pos, "A processing instruction isn't closed with ?>."));
            };
            if after.to_ascii_lowercase().starts_with("xml") && after[3..].starts_with([' ', '?', '\t', '\r', '\n']) {
                return Err(reader.err(pos, "The XML declaration can only be at the very start of the file."));
            }
            pos += 2 + end + 2;
            continue;
        }
        if let Some(after) = tag.strip_prefix("</") {
            let Some(end) = after.find('>') else {
                return Err(reader.err(pos, "An end tag isn't closed with >."));
            };
            let name = after[..end].trim_end();
            let Some(mut open) = stack.pop() else {
                return Err(reader.err(pos, format!("</{name}> ends an element that never started.")));
            };
            if open.name != name {
                return Err(reader.err(
                    pos,
                    format!("</{name}> doesn't match <{}> (line {}).", open.name, open.line),
                ));
            }
            open.close_start = pos;
            pos += 2 + end + 1;
            open.end = pos;
            match stack.last_mut() {
                Some(parent) => parent.children.push(open),
                None => root = Some(open),
            }
            continue;
        }
        // A start tag.
        if root.is_some() {
            return Err(reader.err(pos, "A second root element: an XML file has one."));
        }
        let start = pos;
        let mut i = 1;
        let name_end = tag[i..]
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .map_or(tag.len(), |e| e + i);
        let name = &tag[i..name_end];
        if !valid_name(name) {
            return Err(reader.err(pos, "A tag's name isn't a valid XML name."));
        }
        count += 1;
        if count > MAX_ELEMENTS {
            return Err(reader.err(pos, "The file holds more than 20,000 elements."));
        }
        if stack.len() >= MAX_DEPTH {
            return Err(reader.err(pos, "The file nests elements more than 64 deep."));
        }
        i = name_end;
        let mut attrs: Vec<(String, String)> = Vec::new();
        let self_closing;
        loop {
            let rest = &tag[i..];
            let trimmed = rest.trim_start();
            let skipped = rest.len() - trimmed.len();
            i += skipped;
            if let Some(after) = trimmed.strip_prefix("/>") {
                let _ = after;
                self_closing = true;
                i += 2;
                break;
            }
            if trimmed.starts_with('>') {
                self_closing = false;
                i += 1;
                break;
            }
            if trimmed.is_empty() {
                return Err(reader.err(start, format!("<{name}> isn't closed with >.")));
            }
            if skipped == 0 {
                return Err(reader.err(pos + i, format!("<{name}>'s attributes need spaces between them.")));
            }
            let Some(eq) = trimmed.find('=') else {
                return Err(reader.err(pos + i, format!("An attribute of <{name}> has no value.")));
            };
            let attr_name = trimmed[..eq].trim_end();
            if !valid_name(attr_name) {
                return Err(reader.err(
                    pos + i,
                    format!("An attribute of <{name}> has a name XML doesn't allow."),
                ));
            }
            let after_eq = trimmed[eq + 1..].trim_start();
            let value_at = i + (trimmed.len() - after_eq.len());
            let Some(quote) = after_eq.chars().next().filter(|c| *c == '"' || *c == '\'') else {
                return Err(reader.err(pos + i, format!("{attr_name}'s value needs quotes.")));
            };
            let Some(close) = after_eq[1..].find(quote) else {
                return Err(reader.err(pos + i, format!("{attr_name}'s value isn't closed.")));
            };
            let raw = &after_eq[1..1 + close];
            if raw.contains('<') {
                return Err(reader.err(pos + i, format!("{attr_name}'s value can't hold <.")));
            }
            if attrs.iter().any(|(k, _)| k == attr_name) {
                return Err(reader.err(pos + i, format!("<{name}> has {attr_name} twice.")));
            }
            let value = unescape(&reader, pos + value_at + 1, raw)?;
            attrs.push((attr_name.to_owned(), value));
            i = value_at + 1 + close + 1;
        }
        let element = Element {
            name: name.to_owned(),
            attrs,
            line: reader.line(start),
            start,
            open_end: pos + i,
            close_start: pos + i,
            end: pos + i,
            self_closing,
            ..Element::default()
        };
        pos += i;
        if self_closing {
            match stack.last_mut() {
                Some(parent) => parent.children.push(element),
                None => root = Some(element),
            }
        } else {
            stack.push(element);
        }
    }
    if let Some(open) = stack.last() {
        return Err(reader.err(open.start, format!("<{}> is never closed.", open.name)));
    }
    root.ok_or_else(|| reader.err(0, "The file has no root element."))
}

/// `&`, `<`, `>`, and both quotes as entities.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// `text` with `element`'s content replaced by `value` (escaped). An element with children is refused (`None`).
pub fn set_text(text: &str, element: &Element, value: &str) -> Option<String> {
    if !element.children.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(text.len() + value.len());
    if element.self_closing {
        out.push_str(text.get(..element.start)?);
        out.push_str(&format!("<{}>{}</{}>", element.name, escape(value), element.name));
        out.push_str(text.get(element.end..)?);
    } else {
        out.push_str(text.get(..element.open_end)?);
        out.push_str(&escape(value));
        out.push_str(text.get(element.close_start..)?);
    }
    Some(out)
}

/// The spaces before the line `at` is on.
pub fn indent_at(text: &str, at: usize) -> String {
    let line_start = text[..at.min(text.len())].rfind('\n').map_or(0, |i| i + 1);
    text[line_start..]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const DOC: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<unattend xmlns=\"urn:schemas-microsoft-com:unattend\">\n  <!-- a comment -->\n  <settings pass=\"specialize\">\n    <component name=\"Microsoft-Windows-Shell-Setup\">\n      <ComputerName>{{hostname}}</ComputerName>\n      <TimeZone/>\n      <Note>a &amp; b &#x41;</Note>\n    </component>\n  </settings>\n</unattend>\n";

    #[test]
    fn a_well_formed_file_reads_with_its_lines() {
        let root = parse(DOC).unwrap();
        assert_eq!(root.local(), "unattend");
        let component = root.at(&["settings", "component"]).unwrap();
        assert_eq!(component.attr("name"), Some("Microsoft-Windows-Shell-Setup"));
        assert_eq!(component.child("ComputerName").unwrap().trimmed(), "{{hostname}}");
        assert_eq!(component.child("ComputerName").unwrap().line, 6);
        assert_eq!(component.child("Note").unwrap().trimmed(), "a & b A");
        assert!(component.child("TimeZone").unwrap().self_closing);
    }

    #[test]
    fn set_text_changes_one_element_only() {
        let root = parse(DOC).unwrap();
        let component = root.at(&["settings", "component"]).unwrap();
        let out = set_text(DOC, component.child("ComputerName").unwrap(), "web<1>").unwrap();
        assert_eq!(out, DOC.replace("{{hostname}}", "web&lt;1&gt;"));
        let out = set_text(DOC, component.child("TimeZone").unwrap(), "UTC").unwrap();
        assert_eq!(out, DOC.replace("<TimeZone/>", "<TimeZone>UTC</TimeZone>"));
        assert!(set_text(DOC, component, "x").is_none(), "it has children");
        assert_eq!(indent_at(DOC, component.start), "    ");
    }

    #[test]
    fn what_isnt_well_formed_says_why_and_where() {
        for (text, why, line) in [
            ("<a><b></a>", "doesn't match", 1),
            ("<a>\n<b>\n</b>", "never closed", 1),
            ("<a x=1/>", "needs quotes", 1),
            ("<a x='1' x='2'/>", "twice", 1),
            ("<a>\n& b</a>", "A & must start", 2),
            ("<a>&nbsp;</a>", "isn't an entity", 1),
            ("<!DOCTYPE a [<!ENTITY x \"y\">]><a/>", "DOCTYPE", 1),
            ("<a/><b/>", "second root", 1),
            ("text<a/>", "outside the root", 1),
            ("<a/>text", "after the root", 1),
            ("<a>\u{1}</a>", "control character", 1),
            ("<a><!-- x -- y --></a>", "comment", 1),
            ("", "no root", 1),
            ("<1a/>", "valid XML name", 1),
        ] {
            let err = parse(text).unwrap_err();
            assert!(err.message.contains(why), "{text}: {err:?}");
            assert_eq!(err.line, line, "{text}: {err:?}");
        }
    }

    #[test]
    fn caps_stop_hostile_files() {
        let deep = format!("{}{}", "<a>".repeat(70), "</a>".repeat(70));
        assert!(parse(&deep).unwrap_err().message.contains("64 deep"));
        let wide = format!("<r>{}</r>", "<a/>".repeat(20_001));
        assert!(parse(&wide).unwrap_err().message.contains("20,000"));
    }
}
