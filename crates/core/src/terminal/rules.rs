//! QL-17 highlight and alert rules for terminal output.
//!
//! A rule is a regular expression with a colour and a style (the text in that colour, or a fill behind it), a scope
//! (every terminal, the terminals of sessions with one environment label, or one saved session's) and case
//! sensitivity. The UI colours what a pane's rules match (`src/lib/terminal-highlights.ts`); a rule with its alert on
//! also notifies when a line of output matches ([`super::alerts`]), once per burst of matches.
//!
//! * Five built-in rules ([`BUILTINS`]) are part of the app, with fixed patterns: the user turns each on or off, and
//!   its alert on or off (`terminal_builtin_rules` keeps only those changes). Duplicate in the UI makes an editable
//!   copy. Their highlights are on and their alerts off until the user says otherwise: notifications nobody asked for
//!   are noise.
//! * The user's own rules, at most [`MAX_RULES`], are kept in their order. Adding, changing, reordering and deleting
//!   them, and changing a built-in one, is audited (`terminal_rule_changed`) with the rule's name and scope, never its
//!   pattern (like a favourite command's text), and refused by presentation mode's read-only lock. Nothing here
//!   touches a host, so it skips the command bus, like the session library.
//! * A pattern must mean the same in Rust's `regex` crate (alerts, here) and in JavaScript with the `u` flag
//!   (highlights, in the UI), so [`check_pattern`] takes a common subset of both, and compiles `\d`, `\w`, `\s`, `\b`
//!   and `.` with their JavaScript meaning (ASCII digits and word characters, JavaScript's white space, a line's
//!   characters). Repeats of something that repeats or alternates again (`(a+)+`, `(a|ab)*`) are refused: Rust's
//!   engine runs in linear time, but JavaScript's backtracks and can take exponential time on them. Case sensitivity
//!   is the rule's own setting, never an inline flag.
//! * Open panes follow every change at once: the rules with their alert on go out on a watch channel
//!   ([`TerminalRules::subscribe`]), already compiled.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use regex::{Regex, RegexBuilder};
use regex_syntax::ast::{
    self, AssertionKind, Ast, ClassPerl, ClassPerlKind, ClassSet, ClassSetItem, GroupKind, HexLiteralKind, LiteralKind,
    RepetitionKind, RepetitionRange, SpecialLiteralKind,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use uuid::Uuid;

use crate::domain::{Context, Environment, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::presentation::Change;
use crate::sessions::SessionColor;
use crate::store::{BuiltinRuleRow, NewAuditEntry, Store, TerminalRuleFields, TerminalRuleRow};
use crate::untrusted::is_format_char;

/// The user's own rules one workspace keeps.
pub const MAX_RULES: usize = 50;
/// The longest pattern, in characters.
pub const MAX_PATTERN_CHARS: usize = 200;
/// The longest rule name, in characters.
pub const MAX_NAME_CHARS: usize = 60;
/// The largest count in `{n}`, `{n,}` or `{n,m}`.
pub const MAX_REPEAT_COUNT: u32 = 1000;
/// The most memory one pattern's compiled program may take.
const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// A repeat of something that repeats or alternates again may go round at most this many times (`(\d{1,3}\.){3}`).
const NESTED_REPEAT_LIMIT: u32 = 10;
/// How deep groups may nest.
const NEST_LIMIT: u32 = 32;
/// A built-in rule's id: this, then its key.
const BUILTIN_PREFIX: &str = "builtin:";

/// How a rule colours what it matches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleStyle {
    /// The matched text in the colour.
    #[default]
    Text,
    /// The colour behind the matched text.
    Fill,
}

impl RuleStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleStyle::Text => "text",
            RuleStyle::Fill => "fill",
        }
    }

    fn parse(text: &str) -> Self {
        if text == "fill" {
            RuleStyle::Fill
        } else {
            RuleStyle::Text
        }
    }
}

/// Which terminals a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum RuleScope {
    /// Every terminal, saved sessions and quick connections alike.
    Global,
    /// The terminals of sessions with this environment label (lab, staging or prod).
    Environment { environment: Environment },
    /// One saved session's terminals.
    Session { session_id: Uuid },
}

impl RuleScope {
    /// Whether the rule applies to a terminal of this session (`None`: a quick connection that was not saved) with
    /// this label.
    pub fn applies(&self, session_id: Option<Uuid>, environment: Environment) -> bool {
        match *self {
            RuleScope::Global => true,
            RuleScope::Environment { environment: label } => label != Environment::None && label == environment,
            RuleScope::Session { session_id: id } => session_id == Some(id),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            RuleScope::Global => "global",
            RuleScope::Environment { .. } => "environment",
            RuleScope::Session { .. } => "session",
        }
    }
}

/// A rule that comes with the app. Its pattern is fixed; the user turns it, or its alert, on and off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInRule {
    pub key: &'static str,
    pub name: &'static str,
    pub pattern: &'static str,
    pub case_sensitive: bool,
    pub color: SessionColor,
    pub style: RuleStyle,
}

/// The built-in rules, in the order the list shows them. Words alone (`\b`), so `errors`, `error_count` or `stderr`
/// don't light up; fatal errors and panics get a fill, the rest coloured text.
pub const BUILTINS: [BuiltInRule; 5] = [
    BuiltInRule {
        key: "error",
        name: "Error",
        pattern: r"\berror\b",
        case_sensitive: false,
        color: SessionColor::Red,
        style: RuleStyle::Text,
    },
    BuiltInRule {
        key: "fatal",
        name: "Fatal",
        pattern: r"\bfatal\b",
        case_sensitive: false,
        color: SessionColor::Red,
        style: RuleStyle::Fill,
    },
    BuiltInRule {
        key: "panic",
        name: "Panic",
        pattern: r"\bpanic(?:ked)?\b",
        case_sensitive: false,
        color: SessionColor::Red,
        style: RuleStyle::Fill,
    },
    BuiltInRule {
        key: "traceback",
        name: "Python traceback",
        pattern: r"^Traceback \(most recent call last\):",
        case_sensitive: true,
        color: SessionColor::Red,
        style: RuleStyle::Fill,
    },
    BuiltInRule {
        key: "warning",
        name: "Warning",
        pattern: r"\bwarn(?:ing)?\b",
        case_sensitive: false,
        color: SessionColor::Amber,
        style: RuleStyle::Text,
    },
];

/// A rule as the Settings card and the Terminal page see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalRule {
    /// `builtin:<key>` for a built-in rule, else the rule's id.
    pub id: String,
    pub builtin: bool,
    pub name: String,
    pub pattern: String,
    pub case_sensitive: bool,
    /// `None`: no highlight, the rule only alerts.
    pub color: Option<SessionColor>,
    pub style: RuleStyle,
    pub alert: bool,
    pub scope: RuleScope,
    pub enabled: bool,
    /// Why the saved pattern can't be used any more (a rule saved by another version of Remotely): it neither
    /// highlights nor alerts until it is changed.
    pub problem: Option<String>,
    /// `None` for a built-in rule.
    pub updated_at: Option<String>,
}

/// What the rule dialog sends.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalRuleInput {
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub color: Option<SessionColor>,
    #[serde(default)]
    pub style: RuleStyle,
    #[serde(default)]
    pub alert: bool,
    pub scope: RuleScope,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

fn enabled_by_default() -> bool {
    true
}

/// The rule dialog's live check of a pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatternCheck {
    pub valid: bool,
    /// What is wrong with it, in words.
    pub message: Option<String>,
}

/// A pattern as Rust runs it: [`CompiledPattern::source`] has JavaScript's meaning of `\d`, `\w`, `\s`, `\b` and
/// `.`, and `(?i)` in front when case doesn't matter.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub source: String,
    pub regex: Regex,
}

/// A rule with its alert on, compiled, for the panes it applies to.
#[derive(Debug)]
pub struct AlertRule {
    /// As [`TerminalRule::id`].
    pub id: String,
    pub name: String,
    pub scope: RuleScope,
    pub pattern: CompiledPattern,
}

/// The rules that alert now, as open panes follow them ([`TerminalRules::subscribe`]).
#[derive(Debug, Default)]
pub struct RuleBook {
    /// Goes up with each change.
    pub version: u64,
    pub alerts: Vec<Arc<AlertRule>>,
}

impl RuleBook {
    /// The alerting rules for a terminal of this session (`None`: not saved) with this label, in list order.
    pub fn for_pane(&self, session_id: Option<Uuid>, environment: Environment) -> Vec<Arc<AlertRule>> {
        self.alerts
            .iter()
            .filter(|rule| rule.scope.applies(session_id, environment))
            .cloned()
            .collect()
    }
}

// ---- patterns ---------------------------------------------------------------------------------------------------

/// JavaScript's `\s` (white space and line terminators), for Rust.
const JS_SPACE: &str =
    r"\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}";

fn perl_class(class: &ClassPerl) -> String {
    let items = match class.kind {
        ClassPerlKind::Digit => "0-9",
        ClassPerlKind::Word => "0-9A-Za-z_",
        ClassPerlKind::Space => JS_SPACE,
    };
    let caret = if class.negated { "^" } else { "" };
    format!("[{caret}{items}]")
}

/// JavaScript's `.`: any character but a line terminator.
const JS_DOT: &str = r"[^\n\r\x{2028}\x{2029}]";

const FLAGS: &str = "Inline flags such as (?i) aren't supported: use the rule's Match case setting instead.";
const NAMED: &str = "Named groups aren't supported: use (…) or (?:…).";
const UNICODE_CLASS: &str = "Unicode classes such as \\p{L} aren't supported.";
const POSIX_CLASS: &str = "POSIX classes such as [[:alpha:]] aren't supported: write [A-Za-z].";
const NESTED_CLASS: &str = "Classes inside classes, and && or -- in a class, aren't supported.";
const DASH: &str = "Put - first or last in a class, or write \\-.";
const ASSERTION: &str = "\\A, \\z, \\< and \\b{…} aren't supported: use ^, $ and \\b.";
const REPEAT_NOTHING: &str = "Repeat something that matches text, not ^, $ or \\b.";
const BRACES: &str = "Write a count as {n}, {n,} or {n,m}, without spaces.";
const NESTED_REPEAT: &str = "Repeats of something that repeats or alternates again, such as (a+)+ or (a|b)*, can make \
     highlighting very slow. Write it another way, such as [ab]* for (a|b)*.";
const MATCHES_EMPTY: &str = "This pattern can match empty text (such as a* or x?), which highlights nothing. Make it \
     need at least one character.";

/// Checks a pattern and compiles it for Rust (see the module comment). The error says what is wrong, in words.
pub fn check_pattern(pattern: &str, case_sensitive: bool) -> std::result::Result<CompiledPattern, String> {
    if pattern.trim().is_empty() {
        return Err("Type a pattern.".into());
    }
    if pattern.chars().count() > MAX_PATTERN_CHARS {
        return Err(format!("A pattern can be at most {MAX_PATTERN_CHARS} characters."));
    }
    if pattern.chars().any(char::is_control) {
        return Err("A pattern can't hold tabs, line breaks or other control characters: write \\t for a tab.".into());
    }
    if pattern.chars().any(is_format_char) {
        return Err("A pattern can't hold invisible formatting characters.".into());
    }
    let ast = ast::parse::ParserBuilder::new()
        .nest_limit(NEST_LIMIT)
        .build()
        .parse(pattern)
        .map_err(|err| {
            let at = pattern
                .get(..err.span().start.offset)
                .map_or(0, |before| before.chars().count());
            format!("Not a valid pattern: {} (at character {}).", err.kind(), at + 1)
        })?;
    let mut walk = Walk {
        pattern,
        rewrites: Vec::new(),
    };
    walk.ast(&ast)?;
    let source = walk.rewritten(case_sensitive);
    let hir = regex_syntax::ParserBuilder::new()
        .nest_limit(NEST_LIMIT + 4)
        .build()
        .parse(&source)
        .map_err(|err| {
            let why = match &err {
                regex_syntax::Error::Parse(err) => err.kind().to_string(),
                regex_syntax::Error::Translate(err) => err.kind().to_string(),
                other => other.to_string(),
            };
            format!("Not a pattern Remotely can use: {why}.")
        })?;
    if hir.properties().minimum_len() == Some(0) {
        return Err(MATCHES_EMPTY.into());
    }
    let regex = RegexBuilder::new(&source)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|err| match err {
            regex::Error::CompiledTooBig(_) => {
                "This pattern is too big: make it shorter, or use smaller counts.".to_owned()
            }
            other => format!("Not a pattern Remotely can use: {other}."),
        })?;
    Ok(CompiledPattern { source, regex })
}

/// Walks a pattern's syntax tree: refuses what Rust and JavaScript don't both read the same way, and notes what
/// Rust must read as JavaScript does.
struct Walk<'a> {
    pattern: &'a str,
    /// Byte ranges of the pattern and what replaces them for Rust.
    rewrites: Vec<(usize, usize, String)>,
}

impl Walk<'_> {
    fn text(&self, span: &ast::Span) -> &str {
        self.pattern.get(span.start.offset..span.end.offset).unwrap_or("")
    }

    fn rewrite(&mut self, span: &ast::Span, with: String) {
        self.rewrites.push((span.start.offset, span.end.offset, with));
    }

    fn ast(&mut self, ast: &Ast) -> std::result::Result<(), String> {
        match ast {
            Ast::Empty(_) => Ok(()),
            Ast::Flags(_) => Err(FLAGS.into()),
            Ast::Literal(literal) => check_literal(literal, false),
            Ast::Dot(span) => {
                self.rewrite(span, JS_DOT.to_owned());
                Ok(())
            }
            Ast::Assertion(assertion) => match assertion.kind {
                AssertionKind::StartLine | AssertionKind::EndLine => Ok(()),
                // ASCII word characters, as JavaScript's \b and \B.
                AssertionKind::WordBoundary => {
                    self.rewrite(&assertion.span, r"(?-u:\b)".to_owned());
                    Ok(())
                }
                AssertionKind::NotWordBoundary => {
                    self.rewrite(&assertion.span, r"(?-u:\B)".to_owned());
                    Ok(())
                }
                _ => Err(ASSERTION.into()),
            },
            Ast::ClassUnicode(_) => Err(UNICODE_CLASS.into()),
            Ast::ClassPerl(class) => {
                self.rewrite(&class.span, perl_class(class));
                Ok(())
            }
            Ast::ClassBracketed(class) => {
                let items: Vec<&ClassSetItem> = match &class.kind {
                    ClassSet::BinaryOp(_) => return Err(NESTED_CLASS.into()),
                    ClassSet::Item(ClassSetItem::Union(union)) => union.items.iter().collect(),
                    ClassSet::Item(item) => vec![item],
                };
                self.class_items(&items)
            }
            Ast::Repetition(repetition) => {
                let max = match &repetition.op.kind {
                    RepetitionKind::ZeroOrOne => Some(1),
                    RepetitionKind::ZeroOrMore | RepetitionKind::OneOrMore => None,
                    RepetitionKind::Range(range) => {
                        if !plain_count(self.text(&repetition.op.span)) {
                            return Err(BRACES.into());
                        }
                        let (min, max) = match *range {
                            RepetitionRange::Exactly(n) => (n, Some(n)),
                            RepetitionRange::AtLeast(n) => (n, None),
                            RepetitionRange::Bounded(from, to) => (from, Some(to)),
                        };
                        if min > MAX_REPEAT_COUNT || max.is_some_and(|m| m > MAX_REPEAT_COUNT) {
                            return Err(format!("A count can be at most {MAX_REPEAT_COUNT}."));
                        }
                        max
                    }
                };
                if matches!(*repetition.ast, Ast::Empty(_) | Ast::Flags(_) | Ast::Assertion(_)) {
                    return Err(REPEAT_NOTHING.into());
                }
                if max.is_none_or(|m| m > NESTED_REPEAT_LIMIT) && repeats_or_alternates(&repetition.ast) {
                    return Err(NESTED_REPEAT.into());
                }
                self.ast(&repetition.ast)
            }
            Ast::Group(group) => {
                match &group.kind {
                    GroupKind::CaptureIndex(_) => {}
                    GroupKind::CaptureName { .. } => return Err(NAMED.into()),
                    GroupKind::NonCapturing(flags) if !flags.items.is_empty() => return Err(FLAGS.into()),
                    GroupKind::NonCapturing(_) => {}
                }
                self.ast(&group.ast)
            }
            Ast::Alternation(alternation) => alternation.asts.iter().try_for_each(|ast| self.ast(ast)),
            Ast::Concat(concat) => concat.asts.iter().try_for_each(|ast| self.ast(ast)),
        }
    }

    /// A bracketed class's items: literals, ranges and \d, \w, \s only.
    fn class_items(&mut self, items: &[&ClassSetItem]) -> std::result::Result<(), String> {
        let last = items.len().saturating_sub(1);
        for (i, item) in items.iter().enumerate() {
            match item {
                ClassSetItem::Empty(_) => {}
                ClassSetItem::Literal(literal) => {
                    check_literal(literal, true)?;
                    if literal.kind == LiteralKind::Verbatim && literal.c == '-' && i != 0 && i != last {
                        return Err(DASH.into());
                    }
                }
                ClassSetItem::Range(range) => {
                    check_literal(&range.start, true)?;
                    check_literal(&range.end, true)?;
                }
                ClassSetItem::Ascii(_) => return Err(POSIX_CLASS.into()),
                ClassSetItem::Unicode(_) => return Err(UNICODE_CLASS.into()),
                // A class in the class, which Rust takes as a union.
                ClassSetItem::Perl(class) => self.rewrite(&class.span, perl_class(class)),
                ClassSetItem::Bracketed(_) | ClassSetItem::Union(_) => return Err(NESTED_CLASS.into()),
            }
        }
        Ok(())
    }

    /// The pattern as Rust runs it.
    fn rewritten(mut self, case_sensitive: bool) -> String {
        self.rewrites.sort_by_key(|r| r.0);
        let mut out = String::with_capacity(self.pattern.len() + 64);
        if !case_sensitive {
            out.push_str("(?i)");
        }
        let mut at = 0;
        for (start, end, with) in &self.rewrites {
            if *start < at {
                continue;
            }
            out.push_str(self.pattern.get(at..*start).unwrap_or(""));
            out.push_str(with);
            at = *end;
        }
        out.push_str(self.pattern.get(at..).unwrap_or(""));
        out
    }
}

/// One character, written so both engines read it the same way.
fn check_literal(literal: &ast::Literal, in_class: bool) -> std::result::Result<(), String> {
    let c = literal.c;
    match &literal.kind {
        LiteralKind::Verbatim => match c {
            // JavaScript (with the u flag) refuses a lone brace or bracket.
            '{' | '}' if !in_class => Err(format!("Write {c} as \\{c}.")),
            ']' => Err("Write ] as \\].".into()),
            _ => Ok(()),
        },
        LiteralKind::Meta => {
            let both = matches!(
                c,
                '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
            ) || (in_class && c == '-');
            if both {
                Ok(())
            } else {
                Err(format!("Write {c} without the backslash."))
            }
        }
        LiteralKind::Superfluous if c == '/' => Ok(()),
        LiteralKind::Superfluous if c.is_whitespace() => Err("Write a space without the backslash.".into()),
        LiteralKind::Superfluous => Err(format!("Write {c} without the backslash.")),
        LiteralKind::Octal => Err("Octal escapes aren't supported: write \\x41 or \\u0041.".into()),
        LiteralKind::HexFixed(HexLiteralKind::X | HexLiteralKind::UnicodeShort)
        | LiteralKind::HexBrace(HexLiteralKind::UnicodeShort) => Ok(()),
        LiteralKind::HexFixed(HexLiteralKind::UnicodeLong) | LiteralKind::HexBrace(_) => {
            Err("Write a character's code as \\x41, \\u0041 or \\u{1F600}.".into())
        }
        LiteralKind::Special(special) => match special {
            SpecialLiteralKind::Tab
            | SpecialLiteralKind::LineFeed
            | SpecialLiteralKind::CarriageReturn
            | SpecialLiteralKind::FormFeed
            | SpecialLiteralKind::VerticalTab => Ok(()),
            SpecialLiteralKind::Bell => Err("\\a isn't supported: write \\x07.".into()),
            SpecialLiteralKind::Space => Err("Write a space without the backslash.".into()),
        },
    }
}

/// `{3}`, `{3,}` or `{1,3}`, maybe lazy (`?` after it): what JavaScript reads as a count.
fn plain_count(op: &str) -> bool {
    let op = op.strip_suffix('?').unwrap_or(op);
    let Some(inner) = op.strip_prefix('{').and_then(|rest| rest.strip_suffix('}')) else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    match inner.split_once(',') {
        None => digits(inner),
        Some((from, to)) => digits(from) && (to.is_empty() || digits(to)),
    }
}

/// The pattern holds an alternation, or a repeat that can go round more than once.
fn repeats_or_alternates(ast: &Ast) -> bool {
    match ast {
        Ast::Alternation(_) => true,
        Ast::Repetition(repetition) => {
            let more_than_once = match &repetition.op.kind {
                RepetitionKind::ZeroOrOne => false,
                RepetitionKind::ZeroOrMore | RepetitionKind::OneOrMore => true,
                RepetitionKind::Range(RepetitionRange::Exactly(n)) => *n > 1,
                RepetitionKind::Range(RepetitionRange::AtLeast(_)) => true,
                RepetitionKind::Range(RepetitionRange::Bounded(_, to)) => *to > 1,
            };
            more_than_once || repeats_or_alternates(&repetition.ast)
        }
        Ast::Group(group) => repeats_or_alternates(&group.ast),
        Ast::Concat(concat) => concat.asts.iter().any(repeats_or_alternates),
        _ => false,
    }
}

// ---- the rules --------------------------------------------------------------------------------------------------

/// Checked fields of a rule.
struct Clean {
    name: String,
    pattern: String,
    case_sensitive: bool,
    color: Option<SessionColor>,
    style: RuleStyle,
    alert: bool,
    scope: RuleScope,
    enabled: bool,
}

impl Clean {
    fn fields(&self) -> TerminalRuleFields<'_> {
        let (environment, session_id) = match self.scope {
            RuleScope::Global => (None, None),
            RuleScope::Environment { environment } => (Some(environment.as_str()), None),
            RuleScope::Session { session_id } => (None, Some(session_id)),
        };
        TerminalRuleFields {
            name: &self.name,
            pattern: &self.pattern,
            case_sensitive: self.case_sensitive,
            color: self.color.map(SessionColor::as_str),
            style: self.style.as_str(),
            alert: self.alert,
            scope: self.scope.as_str(),
            environment,
            session_id,
            enabled: self.enabled,
        }
    }
}

fn builtin_id(key: &str) -> String {
    format!("{BUILTIN_PREFIX}{key}")
}

/// A built-in rule as the user set it: on, alert off unless they changed it.
fn builtin_rule(rule: &BuiltInRule, overrides: &[BuiltinRuleRow]) -> TerminalRule {
    let changed = overrides.iter().find(|o| o.rule_key == rule.key);
    TerminalRule {
        id: builtin_id(rule.key),
        builtin: true,
        name: rule.name.to_owned(),
        pattern: rule.pattern.to_owned(),
        case_sensitive: rule.case_sensitive,
        color: Some(rule.color),
        style: rule.style,
        alert: changed.is_some_and(|o| o.alert),
        scope: RuleScope::Global,
        enabled: changed.is_none_or(|o| o.enabled),
        problem: None,
        updated_at: None,
    }
}

/// A stored rule. A label or scope this version doesn't know becomes a problem, not an error.
fn user_rule(row: TerminalRuleRow, problem: Option<String>) -> TerminalRule {
    let mut problem = problem;
    let scope = match row.scope.as_str() {
        "environment" => {
            let environment = Environment::parse(row.environment.as_deref().unwrap_or(""));
            if environment == Environment::None {
                problem.get_or_insert_with(|| "Its environment label is not one Remotely knows.".to_owned());
            }
            RuleScope::Environment { environment }
        }
        "session" => match row.session_id {
            Some(session_id) => RuleScope::Session { session_id },
            None => RuleScope::Global,
        },
        _ => RuleScope::Global,
    };
    TerminalRule {
        id: row.id.to_string(),
        builtin: false,
        name: row.name,
        pattern: row.pattern,
        case_sensitive: row.case_sensitive,
        color: row.color.as_deref().and_then(SessionColor::parse),
        style: RuleStyle::parse(&row.style),
        alert: row.alert,
        scope,
        enabled: row.enabled,
        problem,
        updated_at: Some(row.updated_at),
    }
}

/// One line of text: trimmed, at most `max` characters, no control characters.
fn clean_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CoreError::InvalidInput("Give the rule a name.".into()));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(CoreError::InvalidInput(format!(
            "A rule's name can be at most {MAX_NAME_CHARS} characters."
        )));
    }
    if name.chars().any(|c| c.is_control() || is_format_char(c)) {
        return Err(CoreError::InvalidInput(
            "A rule's name can't hold line breaks, tabs or invisible characters.".into(),
        ));
    }
    Ok(name.to_owned())
}

/// `red text`, `amber fill`, or `no highlight`.
fn look(color: Option<SessionColor>, style: RuleStyle) -> String {
    match color {
        Some(color) => format!("{} {}", color.as_str(), style.as_str()),
        None => "no highlight".to_owned(),
    }
}

fn on_off(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
    }
}

/// The highlight and alert rules (see the module comment). Cloning gives another handle to the same rules.
#[derive(Clone)]
pub struct TerminalRules {
    inner: Arc<Inner>,
}

struct Inner {
    store: Store,
    /// The alerting rules, for open panes.
    book: watch::Sender<Arc<RuleBook>>,
    /// Rules whose saved pattern no longer passes the checks, with why.
    problems: Mutex<HashMap<Uuid, String>>,
    version: AtomicU64,
}

impl TerminalRules {
    /// Reads the workspace's rules and compiles the ones that alert.
    pub async fn load(store: Store, ctx: &Context) -> Result<Self> {
        let rules = Self {
            inner: Arc::new(Inner {
                store,
                book: watch::channel(Arc::new(RuleBook::default())).0,
                problems: Mutex::default(),
                version: AtomicU64::new(0),
            }),
        };
        rules.publish(ctx).await?;
        Ok(rules)
    }

    /// The alerting rules, now and after every change (each pane's alert watch follows this).
    pub fn subscribe(&self) -> watch::Receiver<Arc<RuleBook>> {
        self.inner.book.subscribe()
    }

    /// FD-02: another workspace is shown: panes opened from now on follow its alert rules.
    pub async fn switch_to(&self, ctx: &Context) -> Result<()> {
        self.publish(ctx).await
    }

    /// Built-in rules first, then the user's, in their order.
    pub async fn list(&self, ctx: &Context) -> Result<Vec<TerminalRule>> {
        let store = &self.inner.store;
        let overrides = store.terminal_builtin_rules(ctx).await?;
        let mut rules: Vec<TerminalRule> = BUILTINS.iter().map(|b| builtin_rule(b, &overrides)).collect();
        let problems = locks::lock(&self.inner.problems).clone();
        for row in store.list_terminal_rules(ctx).await? {
            let problem = problems.get(&row.id).cloned();
            rules.push(user_rule(row, problem));
        }
        Ok(rules)
    }

    /// The rule dialog's check while a pattern is typed. Changes nothing.
    pub fn validate(&self, pattern: &str, case_sensitive: bool) -> PatternCheck {
        match check_pattern(pattern, case_sensitive) {
            Ok(_) => PatternCheck {
                valid: true,
                message: None,
            },
            Err(message) => PatternCheck {
                valid: false,
                message: Some(message),
            },
        }
    }

    async fn row(&self, ctx: &Context, id: Uuid) -> Result<TerminalRuleRow> {
        self.inner
            .store
            .terminal_rule(ctx, id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal rule {id}")))
    }

    async fn get(&self, ctx: &Context, id: Uuid) -> Result<TerminalRule> {
        let id_text = id.to_string();
        self.list(ctx)
            .await?
            .into_iter()
            .find(|rule| rule.id == id_text)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal rule {id}")))
    }

    /// The saved session a rule is scoped to, as an audit target; checks it exists.
    async fn session_target(&self, ctx: &Context, scope: RuleScope) -> Result<Option<Target>> {
        let RuleScope::Session { session_id } = scope else {
            return Ok(None);
        };
        let (name, environment, protected) = self
            .inner
            .store
            .find_session_target(ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::InvalidInput("That session no longer exists. Pick another.".into()))?;
        Ok(Some(Target {
            target: TargetRef::Session { session_id },
            name,
            environment,
            protected,
        }))
    }

    /// `for every terminal`, `for Prod sessions`, `for the session 'web01'`.
    fn scope_text(scope: RuleScope, target: Option<&Target>) -> String {
        match scope {
            RuleScope::Global => "for every terminal".to_owned(),
            RuleScope::Environment { environment } => format!("for {} sessions", label(environment)),
            RuleScope::Session { .. } => match target {
                Some(target) => format!("for the session '{}'", target.name),
                None => "for one session".to_owned(),
            },
        }
    }

    async fn clean(
        &self,
        ctx: &Context,
        input: &TerminalRuleInput,
        except: Option<Uuid>,
    ) -> Result<(Clean, Option<Target>)> {
        let name = clean_name(&input.name)?;
        if let Some(builtin) = BUILTINS.iter().find(|b| b.name.eq_ignore_ascii_case(&name)) {
            return Err(CoreError::InvalidInput(format!(
                "'{}' is a built-in rule's name. Choose another.",
                builtin.name
            )));
        }
        let taken = self
            .inner
            .store
            .list_terminal_rules(ctx)
            .await?
            .iter()
            .any(|row| Some(row.id) != except && row.name.to_lowercase() == name.to_lowercase());
        if taken {
            return Err(CoreError::InvalidInput(format!(
                "There is a rule named '{name}' already."
            )));
        }
        check_pattern(&input.pattern, input.case_sensitive).map_err(CoreError::InvalidInput)?;
        if input.color.is_none() && !input.alert {
            return Err(CoreError::InvalidInput(
                "Pick a colour, or turn the alert on: otherwise the rule does nothing.".into(),
            ));
        }
        if matches!(
            input.scope,
            RuleScope::Environment {
                environment: Environment::None
            }
        ) {
            return Err(CoreError::InvalidInput("Pick a label: lab, staging or prod.".into()));
        }
        let target = self.session_target(ctx, input.scope).await?;
        Ok((
            Clean {
                name,
                pattern: input.pattern.clone(),
                case_sensitive: input.case_sensitive,
                color: input.color,
                style: input.style,
                alert: input.alert,
                scope: input.scope,
                enabled: input.enabled,
            },
            target,
        ))
    }

    /// Saves a new rule after the others. Audited (name and scope, never the pattern).
    pub async fn create(&self, ctx: &Context, input: TerminalRuleInput) -> Result<TerminalRule> {
        self.inner.store.read_only().check(Change::TerminalRules)?;
        let (clean, target) = self.clean(ctx, &input, None).await?;
        if self.inner.store.list_terminal_rules(ctx).await?.len() >= MAX_RULES {
            return Err(CoreError::InvalidInput(format!(
                "There are {MAX_RULES} rules already. Delete some first."
            )));
        }
        let id = Uuid::new_v4();
        self.inner.store.insert_terminal_rule(ctx, id, &clean.fields()).await?;
        let mut detail = format!(
            "{}; {}; alerts {}",
            Self::scope_text(clean.scope, target.as_ref()),
            look(clean.color, clean.style),
            on_off(clean.alert)
        );
        if !clean.enabled {
            detail.push_str("; turned off");
        }
        self.audit(
            ctx,
            &format!("Added the terminal rule '{}'", clean.name),
            &detail,
            target.as_slice(),
        )
        .await?;
        self.publish(ctx).await?;
        self.get(ctx, id).await
    }

    /// Changes a rule; it keeps its place. Audited with what changed (never the pattern itself).
    pub async fn update(&self, ctx: &Context, id: Uuid, input: TerminalRuleInput) -> Result<TerminalRule> {
        self.inner.store.read_only().check(Change::TerminalRules)?;
        let before = self.row(ctx, id).await?;
        let (clean, target) = self.clean(ctx, &input, Some(id)).await?;
        let was = user_rule(before.clone(), None);
        let mut changes = Vec::new();
        if was.name != clean.name {
            changes.push(format!("renamed to '{}'", clean.name));
        }
        if was.pattern != clean.pattern {
            changes.push("pattern changed".to_owned());
        }
        if was.case_sensitive != clean.case_sensitive {
            changes.push(
                if clean.case_sensitive {
                    "now matches case"
                } else {
                    "now ignores case"
                }
                .to_owned(),
            );
        }
        if (was.color, was.style) != (clean.color, clean.style) {
            changes.push(format!("now {}", look(clean.color, clean.style)));
        }
        if was.scope != clean.scope {
            changes.push(format!("now {}", Self::scope_text(clean.scope, target.as_ref())));
        }
        if was.alert != clean.alert {
            changes.push(format!("alerts {}", on_off(clean.alert)));
        }
        if was.enabled != clean.enabled {
            changes.push(format!("turned {}", on_off(clean.enabled)));
        }
        if changes.is_empty() {
            return self.get(ctx, id).await;
        }
        self.inner.store.update_terminal_rule(ctx, id, &clean.fields()).await?;
        let mut targets: Vec<Target> = target.into_iter().collect();
        if let RuleScope::Session { .. } = was.scope {
            if let Ok(Some(old)) = self.session_target(ctx, was.scope).await {
                if !targets.iter().any(|t| t.target == old.target) {
                    targets.push(old);
                }
            }
        }
        self.audit(
            ctx,
            &format!("Changed the terminal rule '{}'", was.name),
            &changes.join(", "),
            &targets,
        )
        .await?;
        self.publish(ctx).await?;
        self.get(ctx, id).await
    }

    /// Audited.
    pub async fn delete(&self, ctx: &Context, id: Uuid) -> Result<()> {
        self.inner.store.read_only().check(Change::TerminalRules)?;
        let row = self.row(ctx, id).await?;
        let rule = user_rule(row, None);
        // A session that is gone took its rules with it; one still here is named.
        let target = self.session_target(ctx, rule.scope).await.ok().flatten();
        self.inner.store.delete_terminal_rule(ctx, id).await?;
        self.audit(
            ctx,
            &format!("Deleted the terminal rule '{}'", rule.name),
            &Self::scope_text(rule.scope, target.as_ref()),
            target.as_slice(),
        )
        .await?;
        self.publish(ctx).await
    }

    /// Puts the user's rules in this order; `ids` must be exactly those rules. Audited.
    pub async fn reorder(&self, ctx: &Context, ids: &[Uuid]) -> Result<Vec<TerminalRule>> {
        self.inner.store.read_only().check(Change::TerminalRules)?;
        let current: Vec<Uuid> = self
            .inner
            .store
            .list_terminal_rules(ctx)
            .await?
            .iter()
            .map(|row| row.id)
            .collect();
        if current == ids {
            return self.list(ctx).await;
        }
        let have: HashSet<Uuid> = current.iter().copied().collect();
        let want: HashSet<Uuid> = ids.iter().copied().collect();
        if have != want || want.len() != ids.len() {
            return Err(CoreError::InvalidInput(
                "The rules changed meanwhile. Try again.".into(),
            ));
        }
        self.inner.store.order_terminal_rules(ctx, ids).await?;
        self.audit(
            ctx,
            "Reordered the terminal rules",
            &format!("{} rules", ids.len()),
            &[],
        )
        .await?;
        self.publish(ctx).await?;
        self.list(ctx).await
    }

    /// Turns a built-in rule, or its alert, on or off. Audited.
    pub async fn set_builtin(&self, ctx: &Context, key: &str, enabled: bool, alert: bool) -> Result<TerminalRule> {
        self.inner.store.read_only().check(Change::TerminalRules)?;
        let builtin = BUILTINS
            .iter()
            .find(|b| b.key == key)
            .ok_or_else(|| CoreError::UnknownTarget(format!("built-in terminal rule '{key}'")))?;
        let overrides = self.inner.store.terminal_builtin_rules(ctx).await?;
        let was = builtin_rule(builtin, &overrides);
        let mut changes = Vec::new();
        if was.enabled != enabled {
            changes.push(format!("turned {}", on_off(enabled)));
        }
        if was.alert != alert {
            changes.push(format!("alerts {}", on_off(alert)));
        }
        if changes.is_empty() {
            return Ok(was);
        }
        self.inner
            .store
            .set_terminal_builtin_rule(ctx, builtin.key, enabled, alert)
            .await?;
        self.audit(
            ctx,
            &format!("Changed the built-in terminal rule '{}'", builtin.name),
            &changes.join(", "),
            &[],
        )
        .await?;
        self.publish(ctx).await?;
        let overrides = self.inner.store.terminal_builtin_rules(ctx).await?;
        Ok(builtin_rule(builtin, &overrides))
    }

    /// Compiles the rules again and sends the alerting ones to open panes; notes the patterns that no longer pass.
    async fn publish(&self, ctx: &Context) -> Result<()> {
        let store = &self.inner.store;
        let overrides = store.terminal_builtin_rules(ctx).await?;
        let rows = store.list_terminal_rules(ctx).await?;
        let mut alerts = Vec::new();
        for builtin in &BUILTINS {
            let rule = builtin_rule(builtin, &overrides);
            if !(rule.enabled && rule.alert) {
                continue;
            }
            match check_pattern(builtin.pattern, builtin.case_sensitive) {
                Ok(pattern) => alerts.push(Arc::new(AlertRule {
                    id: rule.id,
                    name: rule.name,
                    scope: rule.scope,
                    pattern,
                })),
                Err(problem) => {
                    tracing::error!(rule = builtin.key, %problem, "a built-in terminal rule doesn't compile")
                }
            }
        }
        let mut problems = HashMap::new();
        for row in rows {
            let id = row.id;
            match check_pattern(&row.pattern, row.case_sensitive) {
                Err(problem) => {
                    problems.insert(id, problem);
                }
                Ok(pattern) => {
                    let rule = user_rule(row, None);
                    if rule.enabled && rule.alert && rule.problem.is_none() {
                        alerts.push(Arc::new(AlertRule {
                            id: rule.id,
                            name: rule.name,
                            scope: rule.scope,
                            pattern,
                        }));
                    }
                }
            }
        }
        *locks::lock(&self.inner.problems) = problems;
        let version = self.inner.version.fetch_add(1, Ordering::SeqCst) + 1;
        self.inner.book.send_replace(Arc::new(RuleBook { version, alerts }));
        Ok(())
    }

    async fn audit(&self, ctx: &Context, action: &str, detail: &str, targets: &[Target]) -> Result<()> {
        self.inner
            .store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "terminal_rule_changed",
                    action,
                    tier: None,
                    job_id: None,
                    targets,
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await
            .map(drop)
    }
}

/// `Prod`, `Lab`, `Staging`.
fn label(environment: Environment) -> &'static str {
    match environment {
        Environment::None => "unlabelled",
        Environment::Lab => "Lab",
        Environment::Staging => "Staging",
        Environment::Prod => "Prod",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rust(pattern: &str) -> String {
        check_pattern(pattern, true).unwrap().source
    }

    fn refused(pattern: &str) -> String {
        check_pattern(pattern, false).expect_err(pattern)
    }

    #[test]
    fn the_built_in_rules_compile_and_match_what_they_name() {
        for builtin in &BUILTINS {
            check_pattern(builtin.pattern, builtin.case_sensitive).unwrap();
        }
        let matches = |key: &str, line: &str| {
            let b = BUILTINS.iter().find(|b| b.key == key).unwrap();
            check_pattern(b.pattern, b.case_sensitive).unwrap().regex.is_match(line)
        };
        assert!(matches("error", "ERROR: disk full"));
        assert!(matches("error", "2026-10-25 [error] worker 3 died"));
        assert!(!matches("error", "0 errors, 0 warnings"));
        assert!(!matches("error", "error_count=0"));
        assert!(!matches("error", "2>/dev/stderr"));
        assert!(matches("fatal", "fatal: not a git repository"));
        assert!(matches("panic", "thread 'main' panicked at src/main.rs:2:5"));
        assert!(matches("panic", "Kernel panic - not syncing"));
        assert!(matches("traceback", "Traceback (most recent call last):"));
        assert!(!matches("traceback", "  traceback (most recent call last):"));
        assert!(matches("warning", "WARN  [main] slow query"));
        assert!(matches("warning", "warning: unused variable"));
        assert!(!matches("warning", "forewarned"));
    }

    #[test]
    fn perl_classes_word_boundaries_and_dot_mean_what_they_mean_in_javascript() {
        assert_eq!(rust(r"\d+"), "[0-9]+");
        assert_eq!(rust(r"\W"), "[^0-9A-Za-z_]");
        assert_eq!(rust(r"[\w.-]+"), "[[0-9A-Za-z_].-]+");
        assert_eq!(rust(r"\berror\b"), r"(?-u:\b)error(?-u:\b)");
        assert_eq!(rust("a.c"), r"a[^\n\r\x{2028}\x{2029}]c");
        assert_eq!(check_pattern("x", false).unwrap().source, "(?i)x");
        // Unicode digits and letters are not \d or \w in JavaScript.
        assert!(!check_pattern(r"\d", true).unwrap().regex.is_match("٣"));
        assert!(!check_pattern(r"^\w+$", true).unwrap().regex.is_match("café"));
        // é is no word character, so there is a boundary before "rror" in JavaScript too.
        assert!(check_pattern(r"\brror", true).unwrap().regex.is_match("érror"));
        // JavaScript's \s takes a no-break space and a byte order mark.
        assert!(check_pattern(r"a\sb", true).unwrap().regex.is_match("a\u{FEFF}b"));
        assert!(check_pattern(r"a\Sb", true).unwrap().regex.is_match("axb"));
        // Case: the rule's own setting.
        assert!(check_pattern("error", false).unwrap().regex.is_match("ERROR"));
        assert!(!check_pattern("error", true).unwrap().regex.is_match("ERROR"));
    }

    #[test]
    fn what_both_engines_read_alike_is_taken() {
        for pattern in [
            r"^\[(?:ERROR|WARN)\]",
            r"OutOfMemoryError",
            r"\b(?:Killed process|Out of memory)\b",
            r"(\d{1,3}\.){3}\d{1,3}",
            r"status=[45]\d\d",
            r"[^a-z]x",
            r"[-a]",
            r"[a-]",
            r"[\-a\]]",
            r"\x41\u0042\u{1F600}",
            r"a\/b",
            r"\$\{HOME\}",
            r"a{2}b{1,}c{2,3}?",
            r"(?:ab)+",
            r"a+?b*?",
            r"x(a|b)",
            r"\t\r\n",
        ] {
            check_pattern(pattern, false).unwrap_or_else(|e| panic!("{pattern}: {e}"));
        }
    }

    #[test]
    fn what_only_rust_or_only_javascript_reads_is_refused() {
        assert!(refused("(?i)error").contains("Match case"), "inline flags");
        assert!(refused("(?i:error)").contains("Match case"));
        assert!(refused("(?P<word>x)").contains("Named"));
        assert!(refused("(?<word>x)").contains("Named"));
        assert!(refused(r"\Aerror").contains("\\A"));
        assert!(refused(r"error\z").contains("\\A"));
        assert!(refused(r"\b{start}x").contains("\\A"));
        assert!(refused(r"\pL+").contains("Unicode"));
        assert!(refused(r"\p{Greek}").contains("Unicode"));
        assert!(refused(r"[[:alpha:]]").contains("POSIX"));
        assert!(refused(r"[a[bc]]").contains("inside classes"));
        assert!(refused(r"[a-z&&[^aeiou]]").contains("inside classes"));
        let dash = refused(r"[\w-x]");
        assert!(dash.contains("first or last") || dash.contains("range"), "{dash}");
        // regex-syntax reads {,3} as {0,3}, or not at all, depending on its version; JavaScript as text or an error.
        let count = refused(r"x{,3}");
        assert!(count.contains("count") || count.contains("Not a valid"), "{count}");
        assert!(refused(r"a}").contains("\\}"));
        assert!(refused(r"a]").contains("\\]"));
        assert!(refused(r"\#").contains("without the backslash"));
        assert!(refused(r"\-").contains("without the backslash"));
        assert!(refused(r"\x{41}").contains("\\x41"));
        assert!(refused(r"\U00000041").contains("\\x41"));
        assert!(refused(r"\a").contains("\\x07"));
        assert!(refused(r"\b+").contains("Repeat something"));
        assert!(refused("(?=x)").contains("Not a valid pattern"), "look-around");
        assert!(refused(r"(a)\1").contains("Not a valid pattern"), "backreferences");
        assert!(refused("(unclosed").contains("at character"));
    }

    #[test]
    fn nested_repeats_are_refused() {
        for pattern in [
            r"(a+)+",
            r"(\d+\.)+",
            r"(a|ab)*",
            r"(?:error|warn)+",
            r"(\w+\s?)*$",
            r"(a{1,2})+",
            r"(a+){1,20}",
            r"(x(a|b))*",
        ] {
            assert!(refused(pattern).contains("very slow"), "{pattern}");
        }
        // A small, bounded outer repeat, or an inner one that goes round once at most, is fine.
        for pattern in [r"(\d{1,3}\.){3}", r"(?:ab?)+", r"(a+){2}", r"[ab]+"] {
            check_pattern(pattern, false).unwrap_or_else(|e| panic!("{pattern}: {e}"));
        }
    }

    #[test]
    fn empty_matches_size_and_characters_are_capped() {
        assert!(refused("").contains("Type a pattern"));
        assert!(refused("   ").contains("Type a pattern"));
        assert!(refused("a*").contains("empty text"));
        assert!(refused("x?").contains("empty text"));
        assert!(refused("^$").contains("empty text"));
        assert!(refused("a|").contains("empty text"));
        assert!(refused(&"x".repeat(MAX_PATTERN_CHARS + 1)).contains("at most"));
        check_pattern(&"x".repeat(MAX_PATTERN_CHARS), false).unwrap();
        assert!(refused("a{1001}").contains("at most 1000"));
        assert!(refused("a\tb").contains("control"));
        assert!(refused("a\u{202E}b").contains("invisible"));
        // Big enough to pass the parser, too big to compile within the limit.
        assert!(refused(r"\w{1000}\w{1000}\w{1000}\w{1000}").contains("too big"));
    }

    #[test]
    fn scopes_pick_the_panes_they_name() {
        let web = Uuid::new_v4();
        assert!(RuleScope::Global.applies(None, Environment::None));
        let prod = RuleScope::Environment {
            environment: Environment::Prod,
        };
        assert!(prod.applies(Some(web), Environment::Prod));
        assert!(
            prod.applies(None, Environment::Prod),
            "a quick connection with its own label"
        );
        assert!(!prod.applies(Some(web), Environment::Lab));
        assert!(!RuleScope::Environment {
            environment: Environment::None
        }
        .applies(None, Environment::None));
        let one = RuleScope::Session { session_id: web };
        assert!(one.applies(Some(web), Environment::Lab));
        assert!(!one.applies(Some(Uuid::new_v4()), Environment::Lab));
        assert!(!one.applies(None, Environment::Lab));
        // The book keeps list order and leaves out what doesn't apply.
        let rule = |id: &str, scope| {
            Arc::new(AlertRule {
                id: id.into(),
                name: id.into(),
                scope,
                pattern: check_pattern("x", false).unwrap(),
            })
        };
        let book = RuleBook {
            version: 1,
            alerts: vec![rule("all", RuleScope::Global), rule("prod", prod), rule("web", one)],
        };
        let ids = |rules: Vec<Arc<AlertRule>>| rules.iter().map(|r| r.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(book.for_pane(Some(web), Environment::Prod)), ["all", "prod", "web"]);
        assert_eq!(ids(book.for_pane(None, Environment::Lab)), ["all"]);
    }

    #[test]
    fn built_in_rules_follow_the_users_changes() {
        let error = &BUILTINS[0];
        let fresh = builtin_rule(error, &[]);
        assert!(fresh.enabled && !fresh.alert, "highlights on, alerts off until asked");
        assert_eq!(fresh.id, "builtin:error");
        let changed = builtin_rule(
            error,
            &[BuiltinRuleRow {
                rule_key: "error".into(),
                enabled: false,
                alert: true,
            }],
        );
        assert!(!changed.enabled && changed.alert);
        let other = builtin_rule(
            &BUILTINS[1],
            &[BuiltinRuleRow {
                rule_key: "error".into(),
                enabled: false,
                alert: true,
            }],
        );
        assert!(other.enabled && !other.alert, "only its own row counts");
    }

    #[test]
    fn names_are_checked() {
        assert!(clean_name("  ").is_err());
        assert!(clean_name("a\nb").is_err());
        assert!(clean_name(&"x".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert_eq!(clean_name("  OOM killer ").unwrap(), "OOM killer");
    }
}
