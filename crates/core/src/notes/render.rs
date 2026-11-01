//! FD-06: a note's markdown as HTML, made here so nothing in a note can run or reach out.
//!
//! CommonMark with tables, task lists and strikethrough ([`pulldown_cmark`]). What the parser hands over is rewritten
//! before any HTML is written:
//!
//! * Raw HTML (blocks and inline) becomes text: a block shows in a `<pre>`, inline HTML as escaped characters.
//! * Images become their text (`[image: alt]`): a picture from a web address would be fetched just by showing the note.
//! * Links: only `http` and `https` addresses with a host, and the app's own links, `session:`, `vm:`, `vault:`,
//!   `command:` and `runbook:` followed by a name (`[db](vault:DB admin)`, `<session:web01>`; `<...>` around a
//!   destination with spaces, or `%20`). The HTML carries no address: each link is `data-note-link="N"`, and
//!   [`RenderedNote::links`] says what N is, so the window opens a web address only after a confirm that shows it, and an
//!   app link through its own navigation. A vault link names a vault item by its label and never carries its secret.
//!   Anything else (`javascript:`, `file:`, `data:`...) shows as text, refused.
//! * Code blocks are `data-note-code="N"`, their text in [`RenderedNote::code_blocks`], so the window can offer "Send to
//!   terminal" through the multi-line paste confirm (QL-05). Nothing runs by itself.
//!
//! [`LinkMode::Static`] is for a file read outside the app (F6's handover pack): each block's text goes through
//! `export::redact_secrets` as it reads, not as its markdown is written (rule 7: a note that holds a password must not
//! carry it into an unencrypted file; `redact_runs` says why), app links become their name, and a web link its text
//! with the address after it in brackets, as text: the pack holds no address in any attribute (no `href`, no `title`),
//! so nothing in it leads anywhere, and the address still prints.

use std::collections::{HashMap, HashSet};

use pulldown_cmark::{CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd};
use serde::Serialize;
use uuid::Uuid;

use crate::export;

/// How links come out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMode {
    /// In the app: `data-note-link` and [`RenderedNote::links`].
    App,
    /// In a file read elsewhere (F6's handover pack): web links as their text and address, app links as their name;
    /// no attribute holds an address.
    Static,
}

/// What a link in a note points at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum NoteLink {
    /// An `http` or `https` address, opened after a confirm that shows it.
    Web { url: String },
    /// A saved session by name; `id` when one has that name here.
    Session { name: String, id: Option<Uuid> },
    /// A VM by its display name; `key` when one has that name here.
    Vm { name: String, key: Option<String> },
    /// A vault item by its label (never its value); `found` when the vault has one.
    Vault { name: String, found: bool },
    /// A saved or built-in command by name.
    Command { name: String, found: bool },
    /// A troubleshooting runbook of the command library, by name.
    Runbook { name: String, found: bool },
    /// Not an address a note may open; shown as text.
    Refused { target: String },
}

/// A note made ready to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedNote {
    pub html: String,
    /// What each `data-note-link="N"` is, by N.
    pub links: Vec<NoteLink>,
    /// Each `data-note-code="N"` block's text, by N.
    pub code_blocks: Vec<String>,
    /// The text has something that looks like a secret (`export::redact_secrets` would change it): the note says so
    /// and suggests the vault.
    pub looks_secret: bool,
}

/// The names app links are found by, in one workspace. Matched without letter case.
#[derive(Debug, Clone, Default)]
pub struct LinkNames {
    pub sessions: HashMap<String, Uuid>,
    pub vms: HashMap<String, String>,
    pub vault: HashSet<String>,
    pub commands: HashSet<String>,
    pub runbooks: HashSet<String>,
}

impl LinkNames {
    pub fn add_session(&mut self, name: &str, id: Uuid) {
        self.sessions.entry(name.to_lowercase()).or_insert(id);
    }

    pub fn add_vm(&mut self, name: &str, key: &str) {
        self.vms.entry(name.to_lowercase()).or_insert_with(|| key.to_owned());
    }

    pub fn add_vault(&mut self, label: &str) {
        self.vault.insert(label.to_lowercase());
    }

    pub fn add_command(&mut self, name: &str) {
        self.commands.insert(name.to_lowercase());
    }

    pub fn add_runbook(&mut self, name: &str) {
        self.runbooks.insert(name.to_lowercase());
    }
}

/// What a note is parsed with.
fn options() -> Options {
    Options::ENABLE_TABLES | Options::ENABLE_TASKLISTS | Options::ENABLE_STRIKETHROUGH
}

/// Whether `text` holds something that looks like a secret, in its markdown or in the text a reader reads (where
/// `**Pass**word: x` or `password&#58; x` reads as `Password: x`).
pub fn looks_secret(text: &str) -> bool {
    export::redact_secrets(text).1 || redact_runs(Parser::new_ext(text, options()), false).1
}

/// An event inside one block's text (a paragraph, heading, table cell, list item's text, code block or HTML block).
fn in_text(event: &Event<'_>) -> bool {
    matches!(
        event,
        Event::Text(_)
            | Event::Code(_)
            | Event::InlineHtml(_)
            | Event::Html(_)
            | Event::SoftBreak
            | Event::HardBreak
            | Event::Start(Tag::Emphasis | Tag::Strong | Tag::Strikethrough | Tag::Link { .. } | Tag::Image { .. })
            | Event::End(TagEnd::Emphasis | TagEnd::Strong | TagEnd::Strikethrough | TagEnd::Link | TagEnd::Image)
    )
}

/// A run's text as a reader reads it.
fn run_text(run: &[Event<'_>]) -> String {
    let mut text = String::new();
    for event in run {
        match event {
            Event::Text(t) | Event::Code(t) | Event::InlineHtml(t) | Event::Html(t) => text.push_str(t),
            Event::SoftBreak | Event::HardBreak => text.push('\n'),
            _ => {}
        }
    }
    text
}

/// What a block's text is redacted behind when the block before it ended with a secret's key (`Password:` above a
/// list of one), so its first word is read as the value.
const CARRIED_KEY: &str = "password: ";

/// F6, rule 7: `export::redact_secrets` on each block's text as it reads, not as it is written. Markdown can split a
/// secret's key from its value (`**Pass**word: x`), hide the separator (`password&#58; x`), or put the value in the
/// next block (`Password:` then `- x`); and redacting the markdown itself can take its syntax for the value (the `-`
/// of that list) and leave the secret. With `replace`, a block's text that holds one becomes its redacted text alone
/// (its emphasis and links go with it). Returns the events and whether any block held one.
fn redact_runs<'a>(events: impl Iterator<Item = Event<'a>>, replace: bool) -> (Vec<Event<'a>>, bool) {
    struct Runs<'a> {
        out: Vec<Event<'a>>,
        run: Vec<Event<'a>>,
        replace: bool,
        /// The block before ended with a key and no value.
        carry: bool,
        found: bool,
    }
    impl<'a> Runs<'a> {
        fn flush(&mut self) {
            if self.run.is_empty() {
                return;
            }
            let text = run_text(&self.run);
            let (redacted, changed) = if self.carry {
                let (r, changed) = export::redact_secrets(&format!("{CARRIED_KEY}{text}"));
                (r.strip_prefix(CARRIED_KEY).map(str::to_owned).unwrap_or(r), changed)
            } else {
                export::redact_secrets(&text)
            };
            self.carry = export::ends_with_secret_key(&text);
            self.found |= changed;
            if changed && self.replace {
                self.run.clear();
                self.out.push(Event::Text(CowStr::from(redacted)));
            } else {
                self.out.append(&mut self.run);
            }
        }
    }
    let mut runs = Runs {
        out: Vec::new(),
        run: Vec::new(),
        replace,
        carry: false,
        found: false,
    };
    for event in events {
        if in_text(&event) {
            runs.run.push(event);
        } else {
            runs.flush();
            runs.out.push(event);
        }
    }
    runs.flush();
    (runs.out, runs.found)
}

/// `text`, `"` and `'` escaped for HTML text and attribute values.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `%20` and the like decoded; anything that doesn't decode stays as it was.
fn percent_decoded(text: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

/// What a link's destination is.
pub fn classify(dest: &str, names: &LinkNames) -> NoteLink {
    let dest = dest.trim();
    if let Some((scheme, rest)) = dest.split_once(':') {
        let name = percent_decoded(rest).trim().to_owned();
        let key = name.to_lowercase();
        let scheme = scheme.to_ascii_lowercase();
        match scheme.as_str() {
            "http" | "https" => {
                if let Ok(url) = url::Url::parse(dest) {
                    if matches!(url.scheme(), "http" | "https") && url.host_str().is_some_and(|h| !h.is_empty()) {
                        return NoteLink::Web { url: url.to_string() };
                    }
                }
            }
            "session" if !name.is_empty() => {
                return NoteLink::Session {
                    id: names.sessions.get(&key).copied(),
                    name,
                }
            }
            "vm" if !name.is_empty() => {
                return NoteLink::Vm {
                    key: names.vms.get(&key).cloned(),
                    name,
                }
            }
            "vault" if !name.is_empty() => {
                return NoteLink::Vault {
                    found: names.vault.contains(&key),
                    name,
                }
            }
            "command" if !name.is_empty() => {
                return NoteLink::Command {
                    found: names.commands.contains(&key),
                    name,
                }
            }
            "runbook" if !name.is_empty() => {
                return NoteLink::Runbook {
                    found: names.runbooks.contains(&key),
                    name,
                }
            }
            _ => {}
        }
    }
    NoteLink::Refused {
        target: dest.chars().take(200).collect(),
    }
}

/// How a link's text is closed.
enum Open {
    Anchor,
    Span,
    /// [`LinkMode::Static`]: a web link's address follows its text, unless the text is the address.
    Web {
        url: String,
        text: String,
    },
}

/// The note as HTML, with its links and code blocks. `names` resolves app links in the workspace.
pub fn render(text: &str, names: &LinkNames, mode: LinkMode) -> RenderedNote {
    let secret = looks_secret(text);
    let source = match mode {
        LinkMode::App => Parser::new_ext(text, options()).collect::<Vec<_>>(),
        // Each block's text as it reads; the addresses and a code block's language, which no block's text holds, are
        // redacted where they are written below.
        LinkMode::Static => redact_runs(Parser::new_ext(text, options()), true).0,
    };
    let mut links: Vec<NoteLink> = Vec::new();
    let mut code_blocks: Vec<String> = Vec::new();
    let mut open_links: Vec<Open> = Vec::new();
    let mut code: Option<String> = None;
    let mut events: Vec<Event<'_>> = Vec::new();
    for event in source {
        if let (Event::Text(t) | Event::Code(t), Some(Open::Web { text, .. })) = (&event, open_links.last_mut()) {
            text.push_str(t);
        }
        if let Some(block) = code.as_mut() {
            match event {
                Event::End(TagEnd::CodeBlock) => {
                    let body = code.take().unwrap_or_default();
                    events.push(Event::Html(CowStr::from(format!("{}</code></pre>\n", escape(&body)))));
                    code_blocks.push(body);
                }
                Event::Text(t) | Event::Code(t) | Event::Html(t) | Event::InlineHtml(t) => block.push_str(&t),
                _ => {}
            }
            continue;
        }
        match event {
            Event::Start(Tag::CodeBlock(kind)) => {
                let lang = match &kind {
                    CodeBlockKind::Fenced(info) => info.split_whitespace().next().unwrap_or("").to_owned(),
                    CodeBlockKind::Indented => String::new(),
                };
                let lang = match mode {
                    LinkMode::App => lang,
                    LinkMode::Static => export::redact_secrets(&lang).0,
                };
                let class = if lang.is_empty() {
                    String::new()
                } else {
                    format!(" data-lang=\"{}\"", escape(&lang))
                };
                let attr = match mode {
                    LinkMode::App => format!(" data-note-code=\"{}\"", code_blocks.len()),
                    LinkMode::Static => String::new(),
                };
                events.push(Event::Html(CowStr::from(format!("<pre{attr}{class}><code>"))));
                code = Some(String::new());
            }
            Event::Start(Tag::HtmlBlock) => events.push(Event::Html(CowStr::from("<pre class=\"note-raw\">"))),
            Event::End(TagEnd::HtmlBlock) => events.push(Event::Html(CowStr::from("</pre>\n"))),
            Event::Html(t) | Event::InlineHtml(t) => events.push(Event::Text(t)),
            Event::Start(Tag::Image { .. }) => {
                events.push(Event::Html(CowStr::from("<span class=\"note-image\">[image: ")));
            }
            Event::End(TagEnd::Image) => {
                events.push(Event::Html(CowStr::from("]</span>")));
            }
            Event::Start(Tag::Link { dest_url, title, .. }) => {
                let link = classify(&dest_url, names);
                // A file read elsewhere carries no attribute text a reader didn't see (an address in a title).
                let title = if title.is_empty() || mode == LinkMode::Static {
                    String::new()
                } else {
                    format!(" title=\"{}\"", escape(&title))
                };
                let (html, open) = match (mode, &link) {
                    (_, NoteLink::Refused { .. }) => (format!("<span class=\"note-link-refused\"{title}>"), Open::Span),
                    (LinkMode::Static, NoteLink::Web { url }) => (
                        "<span class=\"note-link\">".to_owned(),
                        Open::Web {
                            url: url.clone(),
                            text: String::new(),
                        },
                    ),
                    (LinkMode::Static, _) => (format!("<span class=\"note-link\"{title}>"), Open::Span),
                    (LinkMode::App, _) => (
                        format!(
                            "<a role=\"link\" tabindex=\"0\" class=\"note-link\" data-note-link=\"{}\"{title}>",
                            links.len()
                        ),
                        Open::Anchor,
                    ),
                };
                if mode == LinkMode::App {
                    links.push(link);
                }
                open_links.push(open);
                events.push(Event::Html(CowStr::from(html)));
            }
            Event::End(TagEnd::Link) => {
                let close = match open_links.pop() {
                    Some(Open::Anchor) => "</a>".to_owned(),
                    Some(Open::Web { url, text }) => {
                        let shown = text.trim();
                        if shown == url || shown == url.trim_end_matches('/') {
                            "</span>".to_owned()
                        } else {
                            // `https://alice:x@...` or `?token=x` in the address.
                            let url = export::redact_secrets(&url).0;
                            format!("</span> <span class=\"note-url\">({})</span>", escape(&url))
                        }
                    }
                    _ => "</span>".to_owned(),
                };
                events.push(Event::Html(CowStr::from(close)));
            }
            // Footnotes, math and the like aren't turned on; anything else is plain markdown.
            other => events.push(other),
        }
    }
    // A code block left open by the end of the text.
    if let Some(body) = code.take() {
        events.push(Event::Html(CowStr::from(format!("{}</code></pre>\n", escape(&body)))));
        code_blocks.push(body);
    }
    let mut html = String::with_capacity(text.len() * 2);
    pulldown_cmark::html::push_html(&mut html, events.into_iter());
    RenderedNote {
        html,
        links,
        code_blocks,
        looks_secret: secret,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> LinkNames {
        let mut n = LinkNames::default();
        n.add_session("web01", Uuid::nil());
        n.add_vm("it-db", "C:\\VMs\\it-db\\it-db.vmx");
        n.add_vault("DB admin");
        n.add_command("Disk usage");
        n.add_runbook("Disk full");
        n
    }

    fn app(text: &str) -> RenderedNote {
        render(text, &names(), LinkMode::App)
    }

    #[test]
    fn markdown_with_tables_and_task_lists_renders() {
        let out = app("# Title\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n- [x] done\n- [ ] to do\n\n~~old~~");
        assert!(out.html.contains("<h1>Title</h1>"));
        assert!(out.html.contains("<table>"));
        assert!(out.html.contains("type=\"checkbox\""));
        assert!(out.html.contains("<del>old</del>"));
        assert!(!out.looks_secret);
    }

    #[test]
    fn raw_html_shows_as_text() {
        let out = app("<script>alert(1)</script>\n\nsee <img src=x onerror=alert(1)> here");
        assert!(!out.html.contains("<script"), "{}", out.html);
        assert!(!out.html.contains("<img"), "{}", out.html);
        assert!(out.html.contains("&lt;script&gt;"));
        assert!(out.html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    }

    #[test]
    fn images_are_never_fetched() {
        let out = app("![diagram](https://example.com/x.png)");
        assert!(!out.html.contains("<img"), "{}", out.html);
        assert!(!out.html.contains("example.com"), "{}", out.html);
        assert!(out.html.contains("[image: diagram]"));
    }

    #[test]
    fn only_web_and_app_links_are_links() {
        let out = app(
            "[a](https://example.com/runbook?x=1) [b](javascript:alert(1)) [c](file:///C:/x) [d](data:text/html,x) \
             [e](http://)",
        );
        assert_eq!(
            out.links[0],
            NoteLink::Web {
                url: "https://example.com/runbook?x=1".into()
            }
        );
        assert!(matches!(out.links[1], NoteLink::Refused { .. }));
        assert!(matches!(out.links[2], NoteLink::Refused { .. }));
        assert!(matches!(out.links[3], NoteLink::Refused { .. }));
        assert!(matches!(out.links[4], NoteLink::Refused { .. }));
        assert!(!out.html.contains("href"), "the HTML carries no address: {}", out.html);
        assert!(!out.html.contains("javascript"), "{}", out.html);
        assert_eq!(out.html.matches("data-note-link=").count(), 1);
    }

    #[test]
    fn app_links_find_their_items_by_name() {
        let out = app(
            "[s](session:WEB01) <vm:it-db> [p](<vault:DB admin>) [c](command:Disk%20usage) [r](runbook:Disk%20full) \
             [x](session:gone)",
        );
        assert_eq!(
            out.links,
            vec![
                NoteLink::Session {
                    name: "WEB01".into(),
                    id: Some(Uuid::nil())
                },
                NoteLink::Vm {
                    name: "it-db".into(),
                    key: Some("C:\\VMs\\it-db\\it-db.vmx".into())
                },
                NoteLink::Vault {
                    name: "DB admin".into(),
                    found: true
                },
                NoteLink::Command {
                    name: "Disk usage".into(),
                    found: true
                },
                NoteLink::Runbook {
                    name: "Disk full".into(),
                    found: true
                },
                NoteLink::Session {
                    name: "gone".into(),
                    id: None
                },
            ]
        );
    }

    #[test]
    fn link_titles_are_escaped() {
        let out = app("[a](https://example.com \"x\\\" onmouseover=\\\"alert(1)\")");
        assert!(!out.html.contains("\" onmouseover"), "{}", out.html);
    }

    #[test]
    fn code_blocks_are_kept_for_send_to_terminal() {
        let out = app("```bash\nsystemctl status nginx\njournalctl -u nginx -n 50\n```\n\n    df -h\n");
        assert_eq!(
            out.code_blocks,
            vec![
                "systemctl status nginx\njournalctl -u nginx -n 50\n".to_owned(),
                "df -h\n".to_owned()
            ]
        );
        assert!(out.html.contains("data-note-code=\"0\""));
        assert!(out.html.contains("data-note-code=\"1\""));
        assert!(out.html.contains("data-lang=\"bash\""));
    }

    #[test]
    fn code_in_a_block_is_escaped() {
        let out = app("```\n<script>alert(1)</script>\n```");
        assert!(out.html.contains("&lt;script&gt;"));
        assert!(!out.html.contains("<script>"));
    }

    #[test]
    fn a_note_that_looks_like_a_secret_says_so() {
        assert!(app("db password: hunter2hunter2").looks_secret || app("password=hunter2hunter2").looks_secret);
        assert!(!app("Restart nginx after a deploy.").looks_secret);
    }

    #[test]
    fn a_file_read_elsewhere_never_carries_a_secret() {
        let text = "DB: `password=Hunter2Hunter2!`

```
mysql --user=alice --password=Hunter2Hunter2!
export API_KEY=Hunter2Hunter2!
```";
        let out = render(text, &names(), LinkMode::Static);
        assert!(!out.html.contains("Hunter2"), "{}", out.html);
        assert!(out.looks_secret);
        assert!(
            render(text, &names(), LinkMode::App).html.contains("Hunter2"),
            "the app shows the user's own text"
        );
    }

    #[test]
    fn markdown_never_hides_a_secret_from_redaction() {
        for text in [
            "**Password:** Hunter2Hunter2",
            "**Password**: Hunter2Hunter2",
            "`password`: Hunter2Hunter2",
            "Pass**word**: Hunter2Hunter2",
            "password&#58; Hunter2Hunter2",
            "- [ ] the *token* = Hunter2Hunter2",
            "| what | value |\n|---|---|\n| db | **password:** Hunter2Hunter2 |",
            "# Password: Hunter2Hunter2",
            "> api_key:\n> Hunter2Hunter2",
            "[admin](https://alice:Hunter2Hunter2@example.com/)",
            "Password:\n- Hunter2Hunter2",
            "Token:\n\n```\nHunter2Hunter2\n```",
            "```password=Hunter2Hunter2\nx\n```",
        ] {
            assert!(looks_secret(text), "the editor warns: {text}");
            let out = render(text, &names(), LinkMode::Static);
            assert!(!out.html.contains("Hunter2"), "{text}: {}", out.html);
            assert!(out.looks_secret, "{text}");
        }
        // A note with no secret keeps its markdown.
        let plain = render(
            "**Restart** nginx, then `systemctl status nginx`.",
            &names(),
            LinkMode::Static,
        );
        assert!(plain.html.contains("<strong>Restart</strong>"), "{}", plain.html);
        assert!(
            plain.html.contains("<code>systemctl status nginx</code>"),
            "{}",
            plain.html
        );
    }

    #[test]
    fn static_links_are_plain_for_a_file_read_elsewhere() {
        let out = render(
            "[site](https://example.org/) [db](<vault:DB admin>) [x](javascript:alert(1))",
            &names(),
            LinkMode::Static,
        );
        // F6: the address is text after the link's, never an attribute.
        assert!(
            out.html.contains(
                "<span class=\"note-link\">site</span> <span class=\"note-url\">(https://example.org/)</span>"
            ),
            "{}",
            out.html
        );
        assert!(!out.html.contains("href"));
        assert!(out.html.contains("<span class=\"note-link\">db</span>"));
        let bare = render(
            "<https://example.org/x> [t](https://example.org/y \"https://example.org/z\")",
            &names(),
            LinkMode::Static,
        );
        assert!(bare.html.contains("<span class=\"note-link\">https://example.org/x</span> <span class=\"note-link\">t</span> <span class=\"note-url\">(https://example.org/y)</span>"), "{}", bare.html);
        assert!(!bare.html.contains("title="), "{}", bare.html);
        assert!(!out.html.contains("data-note-link"));
        assert!(!out.html.contains("javascript"));
        assert!(!out.html.contains("data-note-code"));
    }
}
