//! BX-13: PowerShell's command and pipeline syntax, read well enough to find every command a script runs, and to tell
//! when part of it can't be read as only reading. What it finds:
//!
//! * Commands in pipelines (`|`), statement lists (`;`, line breaks), chains (`&&`, `||`), script blocks (`{ }`, wherever
//!   they are: an argument, a hashtable value, a variable's value), parentheses, subexpressions (`$( )`, `@( )`, also
//!   inside double-quoted strings and here-strings), and the bodies of `if`, `foreach`, `switch`, `try`, `function`...
//! * Each command's name as PowerShell resolves it: an alias is its command (`rm` and `del` are `Remove-Item`, `%` is
//!   `ForEach-Object`, `iex` is `Invoke-Expression`), a program is itself without its folder and `.exe`.
//! * The call operator (`& name`, `& { }`) and dot-sourcing (`. name`): a literal name or block is read like any command;
//!   anything else (`& $x`, `. .\script.ps1`) can't be.
//! * Nested interpreters: `powershell`/`pwsh` with `-Command` (or the text after it), `-EncodedCommand` (decoded),
//!   `cmd /c "…"` (split where cmd splits), `Invoke-Expression 'text'` and `Start-Process` of one of them, followed
//!   three levels deep. Their commands count for the dangerous-command rules; the interpreters themselves never read
//!   only.
//!
//! It fails closed: what it can't read is reported in [`PsScript::unreadable`] (a method call, `& $x`, a file
//! redirection, an assignment to anything but a plain variable, splatting, `--%`, a bracket or string left open, the
//! language's rarer parts), and a script with any of them is never read-only. Commands it found are still found, so the
//! dangerous-command rules see them.

use base64::Engine;

/// How deep brackets, blocks and subexpressions nest before the parser gives up (and the script can't be read).
const MAX_DEPTH: usize = 64;
/// How deep `powershell -Command "powershell -Command …"` and `cmd /c "…"` are followed.
const MAX_NESTED: usize = 3;
/// A nested script longer than this is not read (it is never read-only anyway: its interpreter isn't).
const MAX_NESTED_BYTES: usize = 64 * 1024;

/// What an argument is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArgKind {
    /// `-Name`, or `-Name:value` with the value attached.
    Parameter,
    /// A bare word, a string or a number.
    Value,
    /// A script block `{ … }`: its commands are among the script's.
    Block,
    /// A variable, `( )`, `$( )`, `@( )`, `@{ }`, an array: known only when it runs.
    Expression,
}

/// One argument of a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Arg {
    /// A literal's value (quotes and escapes removed, dashes made `-`), or the source text of anything else.
    pub text: String,
    /// Its value is known as written: a bare word or a string with nothing to expand in it.
    pub literal: bool,
    pub kind: ArgKind,
}

impl Arg {
    /// A parameter's name in lower case, without its dash and attached value (`-Recurse:$false` is `recurse`).
    pub fn parameter(&self) -> Option<String> {
        if self.kind != ArgKind::Parameter {
            return None;
        }
        let name = self.text.trim_start_matches('-');
        let name = name.split(':').next().unwrap_or(name);
        Some(name.to_lowercase())
    }

    /// `-Name:value`: the value came with the parameter.
    pub fn attached(&self) -> bool {
        self.kind == ArgKind::Parameter && self.text.trim_start_matches('-').contains(':')
    }
}

/// One command a script runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PsCommand {
    /// Where its statement starts in the script (a byte offset); a nested script's commands give their interpreter's.
    pub at: usize,
    /// As the rules read it: an alias's command (`rm` is `Remove-Item`), a program without its folder or extension.
    pub name: String,
    /// What the read-only list matches ([`command_key`]): `None` for a command named by a path or found only when
    /// it runs (`& $x`).
    pub key: Option<String>,
    pub args: Vec<Arg>,
    /// Third review (P5): whether this is the first command in its pipeline. A command after the first takes pipeline
    /// input, so a dynamic value given to one of its parameters may delay-bind a script block (run once per object).
    pub first_in_pipeline: bool,
}

impl PsCommand {
    /// The command on one line for the dangerous-command rules: its name and arguments, an argument holding a space
    /// in single quotes (so `Write-Output "Stop-Computer now"` doesn't read as `Stop-Computer now`).
    pub fn line(&self) -> String {
        let mut line = self.name.clone();
        for arg in &self.args {
            line.push(' ');
            if arg.literal && (arg.text.is_empty() || arg.text.contains(char::is_whitespace)) {
                line.push('\'');
                line.push_str(&arg.text);
                line.push('\'');
            } else {
                line.push_str(&arg.text);
            }
        }
        line
    }
}

/// A script as read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PsScript {
    pub commands: Vec<PsCommand>,
    /// Why parts of it can't be read as only reading, in words; empty when every part was read.
    pub unreadable: Vec<String>,
}

/// Reads a PowerShell script.
pub(crate) fn parse(script: &str) -> PsScript {
    let mut parser = Parser::new(script, None, 0);
    // Control characters other than tab and the line breaks, and Unicode's other line breaks, aren't read the way
    // PowerShell may read them (a statement's end?): such a script is never read-only.
    if script
        .chars()
        .any(|c| (c.is_control() && !matches!(c, '\t' | '\n' | '\r')) || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        parser.unreadable("a control character or an unusual line break");
    }
    parser.statements(End::Eof);
    parser.out
}

/// Characters PowerShell reads as a dash: `-`, the en dash, the em dash and the horizontal bar.
pub(crate) fn is_dash(c: char) -> bool {
    matches!(c, '-' | '\u{2013}' | '\u{2014}' | '\u{2015}')
}

fn is_squote(c: char) -> bool {
    matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}')
}

fn is_dquote(c: char) -> bool {
    matches!(c, '"' | '\u{201c}' | '\u{201d}' | '\u{201e}')
}

fn is_newline(c: char) -> bool {
    matches!(c, '\n' | '\r')
}

fn is_space(c: char) -> bool {
    !is_newline(c) && c.is_whitespace()
}

/// A character of a variable's name (`$env:PATH` has a scope before its colon).
fn is_var_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '?'
}

/// A member's or a keyword's character.
fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Dashes made `-`, so the rules see `–Recurse` (an en dash) as `-Recurse`, as PowerShell does.
pub(crate) fn plain_dashes(text: &str) -> String {
    text.chars().map(|c| if is_dash(c) { '-' } else { c }).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Eof,
    /// `}`.
    Brace,
    /// `)`.
    Paren,
}

/// How a command was invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Invocation {
    Plain,
    /// `& …`.
    Call,
    /// `. …` (dot-sourcing).
    Dot,
}

/// What an expression was, for assignments.
#[derive(Debug, Clone, Copy, Default)]
struct Expr {
    /// A variable of this script's own (`$name`): the only thing a read-only script may assign to.
    plain_variable: bool,
}

struct Parser {
    chars: Vec<char>,
    /// The byte offset of each character, and the text's length after the last.
    offsets: Vec<usize>,
    i: usize,
    depth: usize,
    /// How many interpreters deep this script is.
    nested: usize,
    /// A nested script's commands report their interpreter's offset.
    at: Option<usize>,
    out: PsScript,
}

impl Parser {
    fn new(text: &str, at: Option<usize>, nested: usize) -> Self {
        let mut chars = Vec::with_capacity(text.len());
        let mut offsets = Vec::with_capacity(text.len() + 1);
        for (offset, c) in text.char_indices() {
            chars.push(c);
            offsets.push(offset);
        }
        offsets.push(text.len());
        Self {
            chars,
            offsets,
            i: 0,
            depth: 0,
            nested,
            at,
            out: PsScript::default(),
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.i).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.i + ahead).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }

    fn offset(&self) -> usize {
        self.offsets[self.i.min(self.chars.len())]
    }

    fn source(&self, from: usize) -> String {
        self.chars[from.min(self.i)..self.i].iter().collect()
    }

    fn unreadable(&mut self, why: impl Into<String>) {
        let why = why.into();
        if !self.out.unreadable.contains(&why) && self.out.unreadable.len() < 20 {
            self.out.unreadable.push(why);
        }
    }

    /// A1, P1: whether a `#`/`<#` here clearly begins a comment. PowerShell starts a comment when the `#` is preceded by
    /// whitespace, the start of the input, or a statement/expression delimiter; glued to a token it can instead be part
    /// of it (`$x#`, `${x}#`), or still a comment (`'a'#`, `$x[0]#`). We can't tell the two apart from the character
    /// alone, so only the unambiguous delimiters count as a boundary; a `#` anywhere else makes the script unreadable
    /// (fail closed: never guess). `}` and `]` are left out because `${x}#` glues the `#` on, `'`/`"` because a string
    /// then `#` is a comment but the parser has already read the string.
    fn comment_boundary(&self) -> bool {
        match self.i.checked_sub(1).and_then(|p| self.chars.get(p).copied()) {
            None => true,
            Some(c) => c.is_whitespace() || matches!(c, ';' | '(' | ')' | '{' | '|' | '&'),
        }
    }

    /// Spaces, comments and backtick line continuations; line breaks too when `newlines`.
    fn skip_space(&mut self, newlines: bool) {
        while let Some(c) = self.peek() {
            if is_space(c) || (newlines && is_newline(c)) {
                self.bump();
            } else if c == '`' && self.peek_at(1).is_some_and(is_newline) {
                self.bump();
                if self.bump() == Some('\r') && self.peek() == Some('\n') {
                    self.bump();
                }
            } else if c == '#' {
                // P1, fail closed: a `#` glued to a token may or may not be a comment in PowerShell, so the script
                // can't be read as only reading. Consume it to the line's end either way (so a following quote can't
                // open a string that hides the next statements), but mark it unreadable when it isn't clearly a comment.
                if !self.comment_boundary() {
                    self.unreadable("a '#' that may or may not start a comment");
                }
                while self.peek().is_some_and(|c| !is_newline(c)) {
                    self.bump();
                }
            } else if c == '<' && self.peek_at(1) == Some('#') {
                if !self.comment_boundary() {
                    self.unreadable("a '<#' that may or may not start a comment");
                }
                self.i += 2;
                loop {
                    match self.bump() {
                        None => {
                            self.unreadable("a block comment left open");
                            break;
                        }
                        Some('#') if self.peek() == Some('>') => {
                            self.bump();
                            break;
                        }
                        Some(_) => {}
                    }
                }
            } else {
                break;
            }
        }
    }

    /// The letters ahead in lower case, if a keyword-like word ends there.
    fn word_ahead(&self) -> Option<String> {
        let mut word = String::new();
        let mut at = self.i;
        while let Some(c) = self.chars.get(at).copied().filter(|c| c.is_ascii_alphabetic()) {
            word.push(c.to_ascii_lowercase());
            at += 1;
        }
        let ends = self
            .chars
            .get(at)
            .is_none_or(|c| c.is_whitespace() || matches!(c, '(' | '{' | ';' | ')' | '}' | '$' | '[' | '\'' | '"'));
        (!word.is_empty() && ends).then_some(word)
    }

    fn take_word(&mut self, word: &str) {
        self.i += word.chars().count();
    }

    // ---- Statements --------------------------------------------------------------------------------------------------

    fn statements(&mut self, end: End) {
        loop {
            self.skip_space(true);
            while self.peek() == Some(';') {
                self.bump();
                self.skip_space(true);
            }
            match self.peek() {
                None => {
                    if end != End::Eof {
                        self.unreadable("a bracket left open");
                    }
                    return;
                }
                Some('}') if end == End::Brace => return,
                Some(')') if end == End::Paren => return,
                Some('}' | ')') => {
                    self.unreadable("a closing bracket with no opening one");
                    self.bump();
                    continue;
                }
                _ => {}
            }
            let before = self.i;
            self.statement();
            if self.i == before {
                let c = self.peek().unwrap_or(' ');
                self.unreadable(format!("'{c}' where a command was expected"));
                self.bump();
            }
        }
    }

    /// Consumes the closing bracket a nested part ends with, or says it is missing.
    fn close(&mut self, c: char) {
        if self.peek() == Some(c) {
            self.bump();
        } else {
            self.unreadable("a bracket left open");
        }
    }

    fn enter(&mut self) -> bool {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.unreadable("brackets nested too deep to read");
            // Nothing past here is read: skip to the end, so no part of it can count as read.
            self.i = self.chars.len();
            return false;
        }
        true
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn statement(&mut self) {
        if let Some(word) = self.word_ahead() {
            if self.keyword_statement(&word) {
                return;
            }
        }
        // A loop's label: `:outer foreach (…)`.
        if self.peek() == Some(':') && self.peek_at(1).is_some_and(is_ident_char) {
            self.bump();
            while self.peek().is_some_and(is_ident_char) {
                self.bump();
            }
            self.skip_space(false);
            if let Some(word) = self.word_ahead() {
                if self.keyword_statement(&word) {
                    return;
                }
            }
        }
        self.pipeline_chain();
    }

    /// A statement that starts with a keyword; false when `word` is no keyword here.
    fn keyword_statement(&mut self, word: &str) -> bool {
        match word {
            "if" | "while" | "do" | "try" => {
                self.take_word(word);
                self.clauses();
            }
            "for" => {
                self.take_word(word);
                self.clauses();
            }
            "foreach" if self.next_after_word_is(word, '(') || self.next_after_word_is(word, '-') => {
                self.take_word(word);
                self.skip_space(false);
                // `foreach -parallel (…)` (workflows).
                if self.peek().is_some_and(is_dash) {
                    self.unreadable("a workflow's foreach -parallel");
                    self.bump();
                    while self.peek().is_some_and(is_ident_char) {
                        self.bump();
                    }
                    self.skip_space(false);
                }
                if self.peek() == Some('(') && self.enter() {
                    self.bump();
                    self.skip_space(true);
                    // P4: the loop variable is assigned each turn. A drive-qualified or execution-steering one
                    // (`$alias:hostname`, `$function:x`, `$env:PSModulePath`, `$PSDefaultParameterValues`) defines an
                    // alias, function or variable that a later line could use, so it is never read-only.
                    if !self.postfix().plain_variable {
                        self.unreadable("a foreach variable that assigns an alias, function or environment variable");
                    }
                    self.skip_space(true);
                    if self.word_ahead().as_deref() == Some("in") {
                        self.take_word("in");
                    } else {
                        self.unreadable("a foreach without 'in'");
                    }
                    self.statements(End::Paren);
                    self.close(')');
                    self.leave();
                }
                self.clauses();
            }
            "switch" => {
                self.take_word(word);
                self.switch();
            }
            "trap" => {
                self.take_word(word);
                self.clauses();
            }
            "function" | "filter" | "workflow" => {
                self.take_word(word);
                // Review: a function defined now may be called later by a read-only command's name (a PowerShell console
                // keeps it), so a definition is never read-only; its body's commands count.
                self.unreadable("a function definition");
                self.skip_space(false);
                while self
                    .peek()
                    .is_some_and(|c| !c.is_whitespace() && !matches!(c, '{' | '(' | ';'))
                {
                    self.bump();
                }
                self.clauses();
            }
            "return" | "throw" | "exit" => {
                self.take_word(word);
                self.skip_space(false);
                if !self.at_statement_end() {
                    self.pipeline_chain();
                }
            }
            "break" | "continue" => {
                self.take_word(word);
                self.skip_space(false);
                // An optional label.
                while self.peek().is_some_and(is_ident_char) {
                    self.bump();
                }
            }
            "begin" | "process" | "end" | "dynamicparam" if self.next_after_word_is(word, '{') => {
                self.take_word(word);
                self.clauses();
            }
            "param" if self.next_after_word_is(word, '(') => {
                self.take_word(word);
                self.unreadable("a param block");
                self.clauses();
            }
            "class" | "enum" | "using" | "data" | "configuration" | "inlinescript" | "parallel" | "sequence" => {
                self.take_word(word);
                self.unreadable(format!("PowerShell's '{word}'"));
                self.skim_statement();
            }
            _ => return false,
        }
        true
    }

    fn next_after_word_is(&self, word: &str, c: char) -> bool {
        let mut at = self.i + word.chars().count();
        while self.chars.get(at).copied().is_some_and(|c| c.is_whitespace()) {
            at += 1;
        }
        self.chars
            .get(at)
            .copied()
            .is_some_and(|n| if c == '-' { is_dash(n) } else { n == c })
    }

    fn at_statement_end(&self) -> bool {
        self.peek()
            .is_none_or(|c| is_newline(c) || matches!(c, ';' | '}' | ')' | '|'))
    }

    /// A keyword's conditions and blocks: `(…)`, `[type]` (catch, trap), `{…}`, and the words between them (`else`,
    /// `elseif`, `catch`, `finally`, `while`, `until`).
    fn clauses(&mut self) {
        loop {
            self.skip_space(false);
            match self.peek() {
                Some('(') => self.paren_group(),
                Some('[') => {
                    self.type_literal();
                }
                Some(',') => {
                    self.bump();
                }
                Some('{') => {
                    self.block();
                    let save = self.i;
                    self.skip_space(true);
                    match self.word_ahead() {
                        Some(w)
                            if matches!(w.as_str(), "else" | "elseif" | "catch" | "finally" | "while" | "until") =>
                        {
                            self.take_word(&w);
                        }
                        _ => {
                            self.i = save;
                            return;
                        }
                    }
                }
                Some(c) if c.is_ascii_alphabetic() => match self.word_ahead() {
                    Some(w) if matches!(w.as_str(), "else" | "elseif" | "catch" | "finally" | "while" | "until") => {
                        self.take_word(&w);
                    }
                    _ => return,
                },
                Some(c) if is_newline(c) => {
                    // A block may start on the next line.
                    let save = self.i;
                    self.skip_space(true);
                    if !matches!(self.peek(), Some('{' | '(')) {
                        self.i = save;
                        return;
                    }
                }
                _ => return,
            }
        }
    }

    fn switch(&mut self) {
        loop {
            self.skip_space(false);
            match self.peek() {
                Some(c) if is_dash(c) => {
                    self.bump();
                    let mut option = String::new();
                    while let Some(c) = self.peek().filter(|c| c.is_ascii_alphabetic()) {
                        option.push(c.to_ascii_lowercase());
                        self.bump();
                    }
                    // `-file <path>`: the next word is the file it reads.
                    if !option.is_empty() && "file".starts_with(&option) {
                        self.skip_space(false);
                        self.arg_value();
                    }
                }
                Some('(') => {
                    self.paren_group();
                    break;
                }
                _ => break,
            }
        }
        self.skip_space(true);
        if self.peek() != Some('{') || !self.enter() {
            self.unreadable("a switch without its body");
            return;
        }
        self.bump();
        loop {
            self.skip_space(true);
            while self.peek() == Some(';') {
                self.bump();
                self.skip_space(true);
            }
            match self.peek() {
                None => {
                    self.unreadable("a bracket left open");
                    break;
                }
                Some('}') => {
                    self.bump();
                    break;
                }
                Some('{') => self.block(),
                _ => {
                    let before = self.i;
                    self.arg_value();
                    if self.i == before {
                        self.unreadable("a switch case that can't be read");
                        self.bump();
                    }
                }
            }
            self.skip_space(true);
            if self.peek() == Some('{') {
                self.block();
            }
        }
        self.leave();
    }

    /// Skips to the statement's end, reading the blocks, brackets and strings on the way for their commands.
    fn skim_statement(&mut self) {
        while let Some(c) = self.peek() {
            match c {
                '\n' | '\r' | ';' => return,
                '}' | ')' if self.depth > 0 => return,
                '{' => self.block(),
                '(' => self.paren_group(),
                c if is_squote(c) || is_dquote(c) => {
                    self.string();
                }
                _ => {
                    self.bump();
                }
            }
        }
    }

    fn pipeline_chain(&mut self) {
        loop {
            self.pipeline();
            self.skip_space(false);
            let chain = matches!(
                (self.peek(), self.peek_at(1)),
                (Some('&'), Some('&')) | (Some('|'), Some('|'))
            );
            if !chain {
                return;
            }
            self.i += 2;
            self.skip_space(true);
        }
    }

    fn pipeline(&mut self) {
        let mut first = true;
        loop {
            self.skip_space(false);
            self.element(first);
            first = false;
            self.skip_space(false);
            if self.peek() == Some('|') && self.peek_at(1) != Some('|') {
                self.bump();
                self.skip_space(true);
                continue;
            }
            return;
        }
    }

    fn element(&mut self, first: bool) {
        let Some(c) = self.peek() else {
            if !first {
                self.unreadable("a pipe with nothing after it");
            }
            return;
        };
        if is_newline(c) || matches!(c, ';' | ')' | '}' | '|') {
            if !first {
                self.unreadable("a pipe with nothing after it");
            }
            return;
        }
        match c {
            '&' if self.peek_at(1) != Some('&') => self.command(Invocation::Call, first),
            '.' if self
                .peek_at(1)
                .is_some_and(|n| n.is_whitespace() || matches!(n, '{' | '$' | '(') || is_squote(n) || is_dquote(n)) =>
            {
                self.command(Invocation::Dot, first)
            }
            c if self.starts_expression(c) => {
                // A9: a token beginning with a digit (or `.digit`) is an expression only when it is a real number
                // literal (`1`, `0x1F`, `1kb`, `1.5e3`); otherwise PowerShell runs it as a program (`7z.exe`, `1z`),
                // which runs anything, so it is a command here.
                if (c.is_ascii_digit() || c == '.') && !self.number_literal_ahead() {
                    self.command(Invocation::Plain, first);
                } else {
                    if !first {
                        self.unreadable("an expression after a pipe");
                    }
                    self.expression_statement();
                }
            }
            _ => self.command(Invocation::Plain, first),
        }
    }

    fn starts_expression(&self, c: char) -> bool {
        matches!(c, '$' | '@' | '(' | '[' | '!' | '+' | ',' | '{')
            || c.is_ascii_digit()
            || is_squote(c)
            || is_dquote(c)
            || is_dash(c)
            || (c == '.' && self.peek_at(1).is_some_and(|n| n.is_ascii_digit()))
    }

    /// A9: whether the token at the cursor is a real PowerShell number literal (and not a command name that starts with
    /// a digit). Reads without moving: a numeric core (`0x1F`, digits with one decimal point and an exponent), an
    /// optional type suffix and multiplier (`1kb`, `1lgb`, `1d`), then a boundary. Trailing letters that aren't a known
    /// suffix (`7z`, `1z`, `0x1G`, `1kbx`), or a second `.`-joined word (`1.2.3`, `1.a`), make it a command.
    fn number_literal_ahead(&self) -> bool {
        let get = |at: usize| self.chars.get(at).copied();
        let mut at = self.i;
        if get(at) == Some('0') && matches!(get(at + 1), Some('x' | 'X' | 'b' | 'B')) {
            let hex = matches!(get(at + 1), Some('x' | 'X'));
            at += 2;
            let digits_start = at;
            while get(at).is_some_and(|c| {
                if hex {
                    c.is_ascii_hexdigit()
                } else {
                    matches!(c, '0' | '1')
                }
            }) {
                at += 1;
            }
            if at == digits_start {
                return false;
            }
        } else {
            let mut saw_digit = false;
            while get(at).is_some_and(|c| c.is_ascii_digit()) {
                at += 1;
                saw_digit = true;
            }
            if get(at) == Some('.') && get(at + 1).is_some_and(|c| c.is_ascii_digit()) {
                at += 1;
                while get(at).is_some_and(|c| c.is_ascii_digit()) {
                    at += 1;
                    saw_digit = true;
                }
            }
            if !saw_digit {
                return false;
            }
            if matches!(get(at), Some('e' | 'E')) {
                let mut e = at + 1;
                if matches!(get(e), Some('+' | '-')) {
                    e += 1;
                }
                if get(e).is_some_and(|c| c.is_ascii_digit()) {
                    while get(e).is_some_and(|c| c.is_ascii_digit()) {
                        e += 1;
                    }
                    at = e;
                }
            }
        }
        // A type suffix and/or a byte multiplier, as letters right after the digits. P7: Windows PowerShell 5.1 takes
        // only `l`, `d` and the size multipliers; a token like `1s`, `1u` or `1y` is a command (a program on PATH), so
        // the newer suffixes are left out.
        let mut tail = String::new();
        while let Some(c) = get(at).filter(|c| c.is_ascii_alphabetic()) {
            tail.push(c.to_ascii_lowercase());
            at += 1;
        }
        if !tail.is_empty() {
            let base = ["kb", "mb", "gb", "tb", "pb"]
                .iter()
                .find_map(|m| tail.strip_suffix(m))
                .unwrap_or(&tail);
            if !matches!(base, "" | "l" | "d") {
                return false;
            }
        }
        // After a valid number, more identifier characters, or a `.` joined to a word, make it a command.
        match get(at) {
            Some(c) if is_ident_char(c) => false,
            Some('.') => !get(at + 1).is_some_and(is_ident_char),
            _ => true,
        }
    }

    /// An expression on its own, or an assignment (`$x = <statement>`), then any redirection.
    fn expression_statement(&mut self) {
        // A5: an assignment's right side is another statement (`$a = $b = …`), so this recurses; count the depth.
        if !self.enter() {
            return;
        }
        self.expression_statement_inner();
        self.leave();
    }

    fn expression_statement_inner(&mut self) {
        let lhs = self.expression();
        self.skip_space(false);
        let assignment = match (self.peek(), self.peek_at(1), self.peek_at(2)) {
            (Some('='), _, _) => Some(1),
            (Some('+' | '*' | '/' | '%'), Some('='), _) => Some(2),
            (Some(c), Some('='), _) if is_dash(c) => Some(2),
            (Some('?'), Some('?'), Some('=')) => Some(3),
            _ => None,
        };
        if let Some(len) = assignment {
            if !lhs.plain_variable {
                self.unreadable("an assignment to a property, an index or a variable outside the script");
            }
            self.i += len;
            self.skip_space(true);
            if let Some(word) = self.word_ahead() {
                if self.keyword_statement(&word) {
                    return;
                }
            }
            self.pipeline_chain();
            return;
        }
        self.redirections();
    }

    fn redirections(&mut self) {
        loop {
            self.skip_space(false);
            if !self.at_redirection() {
                return;
            }
            self.redirection();
        }
    }

    fn at_redirection(&self) -> bool {
        match (self.peek(), self.peek_at(1)) {
            (Some('>'), _) => true,
            (Some('<'), _) => true,
            (Some(c), Some('>')) => matches!(c, '1'..='6' | '*'),
            _ => false,
        }
    }

    /// `>`, `>>`, `2>`, `*>&1`, `2>$null`: one that writes a file can't be read-only.
    fn redirection(&mut self) {
        let start = self.i;
        if self.peek() == Some('<') {
            self.bump();
            self.unreadable("input redirection (<)");
            return;
        }
        if self.peek() != Some('>') {
            self.bump();
        }
        self.bump();
        if self.peek() == Some('>') {
            self.bump();
        }
        if self.peek() == Some('&') {
            self.bump();
            if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.bump();
                return;
            }
            self.unreadable("a redirection that can't be read");
            return;
        }
        self.skip_space(false);
        let target = self.arg_value();
        // P2: `>$null` is the only safe target, and only when it ends there. `>$null'C:\x'`, `>$null\Windows\x` and the
        // like are one expandable token naming a file that would be overwritten, so anything glued after `$null` (the
        // token didn't end) makes it a file-writing redirection.
        let clean_null = target.text.eq_ignore_ascii_case("$null")
            && self
                .peek()
                .is_none_or(|c| c.is_whitespace() || matches!(c, ';' | '|' | '&' | ')' | '}'));
        if !clean_null {
            let shown = self.source(start);
            self.unreadable(format!("a redirection that writes a file ({})", shown.trim()));
        }
    }

    // ---- Expressions -------------------------------------------------------------------------------------------------

    fn expression(&mut self) -> Expr {
        let mut expr = self.unary();
        loop {
            let save = self.i;
            self.skip_space(false);
            match self.consume_type_operator() {
                Some("as") => {
                    // A3, P3: `-as` converts, running the target type's constructor, so it is read-only only when the
                    // target is exactly one value-type literal with nothing after it (`$x -as [int]`). A non-value type,
                    // a type named at run time (`-as [string]$t`, `-as 'IO.StreamWriter'`) or a second cast is not.
                    self.skip_space(true);
                    if !self.read_as_target() {
                        self.unreadable("a conversion that may run a constructor (-as)");
                    }
                    expr.plain_variable = false;
                }
                Some(_) => {
                    // `-is` / `-isnot`: a type test runs no constructor, so its type literal is read without the
                    // value-type check.
                    self.skip_space(true);
                    if self.peek() == Some('[') {
                        self.type_literal();
                    } else {
                        self.unary();
                    }
                    expr.plain_variable = false;
                }
                None => {
                    if self.binary_operator() {
                        self.skip_space(true);
                        self.unary();
                        expr.plain_variable = false;
                    } else {
                        self.i = save;
                        return expr;
                    }
                }
            }
        }
    }

    /// Consumes `-as`, `-is` or `-isnot` if one is next, returning which, so the caller checks its type. Leaves the
    /// cursor unmoved otherwise.
    fn consume_type_operator(&mut self) -> Option<&'static str> {
        let (Some(c), Some(n)) = (self.peek(), self.peek_at(1)) else {
            return None;
        };
        if !is_dash(c) || !n.is_ascii_alphabetic() {
            return None;
        }
        let mut word = String::new();
        let mut at = self.i + 1;
        while let Some(ch) = self.chars.get(at).copied().filter(|c| c.is_ascii_alphabetic()) {
            word.push(ch.to_ascii_lowercase());
            at += 1;
        }
        let op = match word.as_str() {
            "as" => "as",
            "is" => "is",
            "isnot" => "isnot",
            _ => return None,
        };
        self.i = at;
        Some(op)
    }

    /// P3: reads a `-as` target. True only when it is exactly one value-type literal (`[int]`) and the expression ends
    /// there; false for a non-value type, a glued continuation (`[string]$t`, `[string][x]`) or a string type name.
    fn read_as_target(&mut self) -> bool {
        if self.peek() != Some('[') {
            if self
                .peek()
                .is_some_and(|c| self.starts_operand(c) || c == '!' || is_dash(c))
            {
                self.unary();
            }
            return false;
        }
        let type_text = self.type_literal();
        if !is_value_type(&type_text) {
            return false;
        }
        // Nothing may be glued to the type, and after any space the expression must end (not another cast or operand).
        if self.peek().is_some_and(|c| !self.ends_word(c)) {
            return false;
        }
        let save = self.i;
        self.skip_space(false);
        let ends = self
            .peek()
            .is_none_or(|c| is_newline(c) || matches!(c, ';' | '|' | '&' | ')' | '}' | ','));
        self.i = save;
        ends
    }

    /// Consumes a binary operator, if one is next.
    fn binary_operator(&mut self) -> bool {
        match (self.peek(), self.peek_at(1)) {
            (Some(c), Some(n)) if is_dash(c) && n.is_ascii_alphabetic() => {
                let mut at = self.i + 1;
                let mut word = String::new();
                while let Some(c) = self.chars.get(at).copied().filter(|c| c.is_ascii_alphabetic()) {
                    word.push(c.to_ascii_lowercase());
                    at += 1;
                }
                if is_operator(&word) {
                    self.i = at;
                    true
                } else {
                    false
                }
            }
            (Some('.'), Some('.')) => {
                self.i += 2;
                true
            }
            (Some('?'), Some('?')) if self.peek_at(2) != Some('=') => {
                self.i += 2;
                true
            }
            (Some('+' | '*' | '/' | '%' | ','), n) if n != Some('=') => {
                self.bump();
                true
            }
            (Some(c), n) if is_dash(c) && n != Some('=') && !n.is_some_and(is_dash) => {
                self.bump();
                true
            }
            _ => false,
        }
    }

    fn unary(&mut self) -> Expr {
        // A5: prefix operators (`-not -not …`, `!!…`, repeated casts) and the recursion through them can run deep, so
        // count it against the same limit as brackets.
        if !self.enter() {
            return Expr::default();
        }
        let expr = self.unary_inner();
        self.leave();
        expr
    }

    fn unary_inner(&mut self) -> Expr {
        self.skip_space(false);
        match (self.peek(), self.peek_at(1)) {
            (Some('!' | ','), _) => {
                self.bump();
                self.unary();
                Expr::default()
            }
            (Some('+'), Some('+')) => {
                self.i += 2;
                let target = self.unary();
                if !target.plain_variable {
                    self.unreadable("an assignment to a property, an index or a variable outside the script");
                }
                Expr::default()
            }
            (Some(c), Some(n)) if is_dash(c) && is_dash(n) => {
                self.i += 2;
                let target = self.unary();
                if !target.plain_variable {
                    self.unreadable("an assignment to a property, an index or a variable outside the script");
                }
                Expr::default()
            }
            (Some(c), Some(n)) if is_dash(c) && n.is_ascii_alphabetic() => {
                // `-not`, `-bnot`, `-split`, `-join` before their operand.
                let mut word = String::new();
                let mut at = self.i + 1;
                while let Some(c) = self.chars.get(at).copied().filter(|c| c.is_ascii_alphabetic()) {
                    word.push(c.to_ascii_lowercase());
                    at += 1;
                }
                if is_operator(&word) {
                    self.i = at;
                    self.unary();
                } else {
                    self.unreadable(format!("'-{word}' where a value was expected"));
                    self.i = at;
                }
                Expr::default()
            }
            (Some(c), _) if is_dash(c) || c == '+' => {
                self.bump();
                self.unary();
                Expr::default()
            }
            (Some('['), _) => {
                let type_text = self.type_literal();
                // `[type]::Member`: the postfix part reads it (and [`Self::member`] checks the call).
                if self.peek() == Some(':') && self.peek_at(1) == Some(':') {
                    self.postfix_after(Expr::default());
                    return Expr::default();
                }
                // A3, P3: a type literal used as a value or a cast runs the type's constructor (`[IO.StreamWriter]'path'`
                // truncates a file; `[IO.StreamWriter] -join 'path'` casts the join result), so only a plain value type
                // (`[int]`, `[string]`, `[datetime]`…) is read-only here. `-is`/`-isnot` type tests are read elsewhere.
                if !is_value_type(&type_text) {
                    self.unreadable("a type literal that may run a constructor");
                }
                // A cast operand: `[int]$x`, `[int] (…)`, `[int]-5`.
                let save = self.i;
                self.skip_space(false);
                if self
                    .peek()
                    .is_some_and(|c| self.starts_operand(c) || c == '!' || (is_dash(c) && save == self.i))
                {
                    self.unary();
                } else {
                    self.i = save;
                }
                Expr::default()
            }
            _ => self.postfix(),
        }
    }

    fn starts_operand(&self, c: char) -> bool {
        matches!(c, '$' | '@' | '(' | '[' | '{') || c.is_ascii_digit() || is_squote(c) || is_dquote(c)
    }

    fn postfix(&mut self) -> Expr {
        let expr = self.primary();
        self.postfix_after(expr)
    }

    /// Member access, method calls, indexes and `++`/`--` after a value.
    fn postfix_after(&mut self, mut expr: Expr) -> Expr {
        loop {
            match (self.peek(), self.peek_at(1)) {
                (Some('.'), Some(n)) if is_ident_char(n) || n == '$' || n == '(' || is_squote(n) || is_dquote(n) => {
                    self.bump();
                    self.member(false);
                    expr.plain_variable = false;
                }
                (Some('?'), Some('.')) => {
                    self.i += 2;
                    self.member(false);
                    expr.plain_variable = false;
                }
                (Some(':'), Some(':')) => {
                    self.i += 2;
                    self.member(true);
                    expr.plain_variable = false;
                }
                (Some('['), _) => {
                    if !self.enter() {
                        return expr;
                    }
                    self.bump();
                    self.statements_until(']');
                    self.leave();
                    expr.plain_variable = false;
                }
                (Some('+'), Some('+')) => {
                    if !expr.plain_variable {
                        self.unreadable("an assignment to a property, an index or a variable outside the script");
                    }
                    self.i += 2;
                    expr.plain_variable = false;
                }
                (Some(c), Some(n)) if is_dash(c) && is_dash(n) && !self.peek_at(2).is_some_and(is_ident_char) => {
                    if !expr.plain_variable {
                        self.unreadable("an assignment to a property, an index or a variable outside the script");
                    }
                    self.i += 2;
                    expr.plain_variable = false;
                }
                _ => return expr,
            }
        }
    }

    /// Expressions separated by commas until `close` (an index `[…]`, a method's arguments `(…)`).
    fn statements_until(&mut self, close: char) {
        loop {
            self.skip_space(true);
            match self.peek() {
                None => {
                    self.unreadable("a bracket left open");
                    return;
                }
                Some(c) if c == close => {
                    self.bump();
                    return;
                }
                Some(',') => {
                    self.bump();
                }
                Some(_) => {
                    let before = self.i;
                    if let Some(word) = self.word_ahead() {
                        // A method's argument may be a statement: `.Where({ … }, 'First')` holds a block, never a command.
                        if self.keyword_statement(&word) {
                            continue;
                        }
                    }
                    if self.peek().is_some_and(|c| self.starts_expression(c)) {
                        self.expression();
                    } else {
                        self.pipeline_chain();
                    }
                    if self.i == before {
                        self.unreadable("an argument that can't be read");
                        self.bump();
                    }
                }
            }
        }
    }

    /// A member after `.` or `::`, and its call when `(` follows: a method call can do anything, so only a few that
    /// only compute a value are read.
    fn member(&mut self, is_static: bool) {
        let mut name = String::new();
        let mut dynamic = false;
        match self.peek() {
            Some('$') => {
                dynamic = true;
                self.variable();
            }
            Some('(') => {
                dynamic = true;
                self.paren_group();
            }
            Some(c) if is_squote(c) || is_dquote(c) => {
                let (text, literal) = self.string();
                dynamic = !literal;
                name = text;
            }
            _ => {
                while let Some(c) = self.peek().filter(|c| is_ident_char(*c)) {
                    name.push(c);
                    self.bump();
                }
            }
        }
        // A2, P3: a member followed by `(` or `{` is a call that invokes the method — `$x.Delete{}` and `$x.Delete()`,
        // and (fail closed) also when a space, a comment or a backtick-newline comes between (`$x.Delete ()`,
        // `$x.Delete <#c#>()`), which PowerShell either calls or refuses, never a plain read.
        let save = self.i;
        self.skip_space(false);
        let call = match self.peek() {
            Some('(') => '(',
            Some('{') => '{',
            _ => {
                self.i = save;
                return;
            }
        };
        let shown = if dynamic {
            "a member named at run time".to_owned()
        } else {
            name.clone()
        };
        let first_is_block = if call == '{' {
            true
        } else {
            let args_start = self.i + 1;
            self.chars
                .get(args_start..)
                .is_some_and(|rest| rest.iter().find(|c| !c.is_whitespace()).copied() == Some('{'))
        };
        let pure = !dynamic && pure_method(&name, is_static, first_is_block);
        if !pure {
            let sep = if is_static { "::" } else { "." };
            self.unreadable(format!("a method call ({sep}{shown}())"));
        }
        if call == '{' {
            // `block` guards its own depth.
            self.block();
        } else if self.enter() {
            self.bump();
            self.statements_until(')');
            self.leave();
        }
    }

    fn primary(&mut self) -> Expr {
        let Some(c) = self.peek() else {
            self.unreadable("a value missing at the end");
            return Expr::default();
        };
        match c {
            '$' if self.peek_at(1) == Some('(') => {
                self.subexpression();
                Expr::default()
            }
            '$' => self.variable(),
            '@' => {
                match self.peek_at(1) {
                    Some('(') => {
                        self.bump();
                        self.subexpression_paren();
                    }
                    Some('{') => self.hashtable(),
                    Some(n) if is_squote(n) || is_dquote(n) => {
                        self.here_string();
                    }
                    _ => {
                        self.unreadable("splatting (@name)");
                        self.bump();
                        while self.peek().is_some_and(is_var_char) {
                            self.bump();
                        }
                    }
                }
                Expr::default()
            }
            '(' => {
                self.paren_group();
                Expr::default()
            }
            '{' => {
                self.block();
                Expr::default()
            }
            '[' => {
                self.type_literal();
                Expr::default()
            }
            c if is_squote(c) || is_dquote(c) => {
                self.string();
                Expr::default()
            }
            c if c.is_ascii_digit() || c == '.' => {
                self.bump();
                while self.peek().is_some_and(|c| is_ident_char(c) || c == '.') {
                    // `1..3` is a range: stop before `..`.
                    if self.peek() == Some('.') && self.peek_at(1) == Some('.') {
                        break;
                    }
                    self.bump();
                }
                Expr::default()
            }
            _ => {
                let start = self.i;
                while self
                    .peek()
                    .is_some_and(|c| !c.is_whitespace() && !matches!(c, ';' | '|' | ')' | '}' | ']' | ',' | '('))
                {
                    self.bump();
                }
                if self.i == start {
                    self.bump();
                }
                let word = self.source(start);
                self.unreadable(format!("'{word}' where a value was expected"));
                Expr::default()
            }
        }
    }

    /// `$name`, `$env:NAME`, `${any name}`, `$_`, `$$`, `$?`, `$^`.
    fn variable(&mut self) -> Expr {
        self.bump();
        match self.peek() {
            Some('{') => {
                self.bump();
                loop {
                    match self.bump() {
                        None => {
                            self.unreadable("a variable name left open");
                            break;
                        }
                        Some('`') => {
                            self.bump();
                        }
                        Some('}') => break,
                        Some(_) => {}
                    }
                }
                Expr::default()
            }
            Some('$' | '^') => {
                self.bump();
                Expr::default()
            }
            Some(c) if is_var_char(c) => {
                let start = self.i;
                let mut qualified = false;
                while self.peek().is_some_and(is_var_char) {
                    self.bump();
                }
                let name: String = self.chars[start..self.i].iter().collect();
                // `$env:PATH`, `$global:x`, `$c:file`: a scope or a drive, never `::`.
                if self.peek() == Some(':') && self.peek_at(1).is_some_and(|c| c != ':' && !c.is_whitespace()) {
                    qualified = true;
                    self.bump();
                    while self
                        .peek()
                        .is_some_and(|c| is_var_char(c) || matches!(c, '\\' | '/' | '.' | '-'))
                    {
                        self.bump();
                    }
                }
                Expr {
                    // A4: assigning an execution-steering automatic variable changes what later commands do
                    // (`$PSDefaultParameterValues=@{'*:MemberName'='Kill'}` turns a bare ForEach-Object into a method
                    // call), so it is never a read-only "plain variable". `$env:…` is qualified, so already excluded.
                    plain_variable: !qualified && !is_execution_variable(&name),
                }
            }
            _ => Expr::default(),
        }
    }

    /// `$( … )`.
    fn subexpression(&mut self) {
        self.bump();
        self.subexpression_paren();
    }

    /// `( … )` after a `$` or `@` that was consumed.
    fn subexpression_paren(&mut self) {
        if !self.enter() {
            return;
        }
        self.bump();
        self.statements(End::Paren);
        self.close(')');
        self.leave();
    }

    fn paren_group(&mut self) {
        if !self.enter() {
            return;
        }
        self.bump();
        self.statements(End::Paren);
        self.close(')');
        self.leave();
    }

    fn block(&mut self) {
        if !self.enter() {
            return;
        }
        self.bump();
        self.statements(End::Brace);
        self.close('}');
        self.leave();
    }

    /// `@{ key = <statement>; … }`.
    fn hashtable(&mut self) {
        if !self.enter() {
            return;
        }
        self.i += 2;
        loop {
            self.skip_space(true);
            while self.peek() == Some(';') {
                self.bump();
                self.skip_space(true);
            }
            match self.peek() {
                None => {
                    self.unreadable("a bracket left open");
                    break;
                }
                Some('}') => {
                    self.bump();
                    break;
                }
                Some(c) if is_squote(c) || is_dquote(c) => {
                    self.string();
                }
                Some('$') | Some('(') => {
                    self.postfix();
                }
                Some(_) => {
                    let start = self.i;
                    while self
                        .peek()
                        .is_some_and(|c| !c.is_whitespace() && !matches!(c, '=' | ';' | '}'))
                    {
                        self.bump();
                    }
                    if self.i == start {
                        self.bump();
                    }
                }
            }
            self.skip_space(false);
            if self.peek() != Some('=') {
                self.unreadable("a hashtable entry that can't be read");
                continue;
            }
            self.bump();
            self.skip_space(true);
            self.statement();
        }
        self.leave();
    }

    /// `[type]`, `[System.Collections.Generic.List[string]]`; an attribute (`[ValidateScript({ … })]`) has its
    /// arguments read for commands, and can't be read-only. Returns the type's text (between the outer brackets).
    fn type_literal(&mut self) -> String {
        if !self.enter() {
            return String::new();
        }
        self.bump();
        let start = self.i;
        let mut text_end = self.i;
        let mut depth = 1;
        while let Some(c) = self.peek() {
            match c {
                '[' => {
                    depth += 1;
                    self.bump();
                    text_end = self.i;
                }
                ']' => {
                    depth -= 1;
                    self.bump();
                    if depth == 0 {
                        break;
                    }
                    text_end = self.i;
                }
                '(' => {
                    self.unreadable("an attribute");
                    if self.enter() {
                        self.bump();
                        self.statements_until(')');
                        self.leave();
                    }
                    text_end = self.i;
                }
                c if is_newline(c) => {
                    self.unreadable("a type name left open");
                    break;
                }
                _ => {
                    self.bump();
                    text_end = self.i;
                }
            }
        }
        if depth > 0 && self.peek().is_none() {
            self.unreadable("a type name left open");
        }
        self.leave();
        self.chars[start.min(self.chars.len())..text_end.min(self.chars.len())]
            .iter()
            .collect()
    }

    // ---- Strings -----------------------------------------------------------------------------------------------------

    /// A string at the cursor: its value and whether it is literal (nothing in it expands).
    fn string(&mut self) -> (String, bool) {
        match self.peek() {
            Some(c) if is_squote(c) => (self.single_quoted(), true),
            Some(c) if is_dquote(c) => self.double_quoted(),
            _ => (String::new(), true),
        }
    }

    fn single_quoted(&mut self) -> String {
        self.bump();
        let mut value = String::new();
        loop {
            match self.bump() {
                None => {
                    self.unreadable("a string left open");
                    break;
                }
                Some(c) if is_squote(c) => {
                    if self.peek().is_some_and(is_squote) {
                        value.push(c);
                        self.bump();
                    } else {
                        break;
                    }
                }
                Some(c) => value.push(c),
            }
        }
        value
    }

    fn double_quoted(&mut self) -> (String, bool) {
        self.bump();
        let mut value = String::new();
        let mut literal = true;
        loop {
            match self.peek() {
                None => {
                    self.unreadable("a string left open");
                    break;
                }
                Some('`') => {
                    self.bump();
                    if let Some(c) = self.bump() {
                        value.push(c);
                    }
                }
                Some(c) if is_dquote(c) => {
                    self.bump();
                    if self.peek().is_some_and(is_dquote) {
                        value.push(c);
                        self.bump();
                    } else {
                        break;
                    }
                }
                Some('$') => {
                    if self.expansion(&mut value) {
                        literal = false;
                    }
                }
                Some(c) => {
                    value.push(c);
                    self.bump();
                }
            }
        }
        (value, literal)
    }

    /// A `$` in an expandable string or a bare word: `$(…)` is read for its commands, `$name` is a variable. Returns
    /// whether it expands.
    fn expansion(&mut self, value: &mut String) -> bool {
        let start = self.i;
        match self.peek_at(1) {
            Some('(') => {
                self.subexpression();
            }
            Some(c) if is_var_char(c) || matches!(c, '{' | '$' | '^') => {
                self.variable();
            }
            _ => {
                self.bump();
                value.push('$');
                return false;
            }
        }
        value.push_str(&self.source(start));
        true
    }

    /// `@'…'@` (literal) or `@"…"@` (expandable): from the line after the opening to a line that starts with the
    /// closing.
    fn here_string(&mut self) -> (String, bool) {
        self.bump();
        let quote = self.bump().unwrap_or('\'');
        let expandable = is_dquote(quote);
        while self.peek().is_some_and(is_space) {
            self.bump();
        }
        if !self.peek().is_some_and(is_newline) {
            self.unreadable("a here-string that doesn't start on its own line");
            return (String::new(), false);
        }
        let mut value = String::new();
        let mut literal = true;
        let mut line_start = false;
        loop {
            let Some(c) = self.peek() else {
                self.unreadable("a here-string left open");
                break;
            };
            if line_start
                && ((expandable && is_dquote(c)) || (!expandable && is_squote(c)))
                && self.peek_at(1) == Some('@')
            {
                self.i += 2;
                break;
            }
            line_start = is_newline(c);
            if expandable && c == '$' {
                if self.expansion(&mut value) {
                    literal = false;
                }
                continue;
            }
            if expandable && c == '`' {
                self.bump();
                if let Some(next) = self.bump() {
                    value.push(next);
                    line_start = is_newline(next);
                }
                continue;
            }
            value.push(c);
            self.bump();
        }
        (value, literal)
    }

    // ---- Commands ----------------------------------------------------------------------------------------------------

    fn command(&mut self, invocation: Invocation, first: bool) {
        let at = self.at.unwrap_or_else(|| self.offset());
        if invocation != Invocation::Plain {
            self.bump();
            self.skip_space(false);
        }
        // The command's name: a bare word (or, after & or ., a string), a literal script block, or something only
        // known when it runs.
        let mut name: Option<String> = None;
        match self.peek() {
            Some('{') if invocation != Invocation::Plain => self.block(),
            Some(c) if is_squote(c) || is_dquote(c) => {
                let (text, literal) = self.string();
                if literal {
                    name = Some(text);
                } else {
                    self.unreadable("a command named by an expanding string");
                }
            }
            Some('$' | '(' | '@') => {
                self.postfix();
                self.unreadable("a command named by a variable or an expression (& $x)");
            }
            _ => {
                let (text, literal) = self.bare_word();
                if literal {
                    name = Some(text);
                } else {
                    self.unreadable("a command named by a variable or an expression (& $x)");
                }
            }
        }
        let args = self.arguments();
        let Some(raw) = name.filter(|n| !n.is_empty()) else {
            return;
        };
        let (display, mut key) = command_key(&raw);
        if invocation == Invocation::Dot {
            // Dot-sourcing a script runs it in this scope: nothing in it is read here.
            self.unreadable(format!("a dot-sourced script (. {raw})"));
            key = None;
        }
        let command = PsCommand {
            at,
            name: display,
            key,
            args,
            first_in_pipeline: first,
        };
        self.add(command);
    }

    fn arguments(&mut self) -> Vec<Arg> {
        let mut args = Vec::new();
        loop {
            self.skip_space(false);
            let Some(c) = self.peek() else {
                return args;
            };
            match c {
                c if is_newline(c) => return args,
                ';' | ')' | '}' | '|' => return args,
                '&' => {
                    // `cmd &` runs it as a job (PowerShell 7); `&&` chains.
                    if self.peek_at(1) != Some('&') {
                        self.bump();
                    }
                    return args;
                }
                _ if self.at_redirection() => self.redirection(),
                c if is_dash(c) && self.peek_at(1).is_some_and(is_dash) && self.peek_at(2) == Some('%') => {
                    // `--%`: the rest of the line goes to a program as it is, %VARIABLES% expanded.
                    self.unreadable("the stop-parsing token (--%)");
                    while self.peek().is_some_and(|c| !is_newline(c) && c != '|') {
                        self.bump();
                    }
                    return args;
                }
                c if is_dash(c)
                    && self
                        .peek_at(1)
                        .is_some_and(|n| n.is_alphabetic() || n == '_' || n == '?') =>
                {
                    args.push(self.parameter());
                }
                _ => {
                    let arg = self.arg_value();
                    args.push(arg);
                }
            }
        }
    }

    /// `-Name` or `-Name:value`.
    fn parameter(&mut self) -> Arg {
        self.bump();
        let mut text = String::from("-");
        while let Some(c) = self.peek().filter(|c| is_var_char(*c) || is_dash(*c)) {
            text.push(if is_dash(c) { '-' } else { c });
            self.bump();
        }
        let mut literal = true;
        if self.peek() == Some(':') {
            self.bump();
            let value = self.arg_value();
            text.push(':');
            text.push_str(&value.text);
        } else if self.peek().is_some_and(|c| !self.ends_word(c)) {
            // `-type=mx` goes to a program as one word, as PowerShell passes it.
            let (rest, rest_literal) = self.bare_word();
            text.push_str(&plain_dashes(&rest));
            literal = rest_literal;
        }
        Arg {
            text,
            literal,
            kind: ArgKind::Parameter,
        }
    }

    /// One argument's value, with the elements of an array (`a,b`).
    fn arg_value(&mut self) -> Arg {
        let start = self.i;
        let arg = self.arg_element();
        // A8: build the array's source once at the end, not per element, so `a,a,a,…` is read in linear time.
        if self.peek() != Some(',') {
            return arg;
        }
        while self.peek() == Some(',') {
            self.bump();
            self.skip_space(true);
            self.arg_element();
        }
        Arg {
            text: self.source(start),
            literal: false,
            kind: ArgKind::Expression,
        }
    }

    fn arg_element(&mut self) -> Arg {
        let start = self.i;
        let expression = |parser: &mut Self, kind: ArgKind| Arg {
            text: parser.source(start),
            literal: false,
            kind,
        };
        match self.peek() {
            Some(c) if is_squote(c) || is_dquote(c) => {
                // A6: PowerShell ends an argument that starts with a quote at the closing quote; what follows at once
                // (`'computer'/h`) is a new argument, not joined. Joining hid an option (`/h`, `-Recurse`) from the
                // write checks, so we keep them apart.
                let (text, literal) = self.string();
                Arg {
                    text: if literal { text } else { self.source(start) },
                    literal,
                    kind: ArgKind::Value,
                }
            }
            Some('@') if self.peek_at(1).is_some_and(|n| is_squote(n) || is_dquote(n)) => {
                let (text, literal) = self.here_string();
                Arg {
                    text: if literal { text } else { self.source(start) },
                    literal,
                    kind: ArgKind::Value,
                }
            }
            Some('{') => {
                self.block();
                expression(self, ArgKind::Block)
            }
            Some('$' | '(' | '@') => {
                self.postfix();
                expression(self, ArgKind::Expression)
            }
            _ => {
                let (text, literal) = self.bare_word();
                if literal {
                    Arg {
                        text: plain_dashes(&text),
                        literal,
                        kind: ArgKind::Value,
                    }
                } else {
                    expression(self, ArgKind::Value)
                }
            }
        }
    }

    fn ends_word(&self, c: char) -> bool {
        c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')' | '{' | '}' | ',' | '>' | '<')
    }

    /// A bare word in command mode: up to a space or `;|&(){},<>`, with quoted parts and backtick escapes in it.
    /// Literal unless a `$` expands in it.
    fn bare_word(&mut self) -> (String, bool) {
        let mut text = String::new();
        let mut literal = true;
        while let Some(c) = self.peek() {
            if self.ends_word(c) {
                break;
            }
            match c {
                // P1: a `#` glued inside a word, with a quote right after, could be a comment (`[int]#'…`) rather than a
                // word continuing into a string. Stop the word here and let `skip_space` read the `#`, which marks the
                // script unreadable, so the quote never opens a string that hides the next statements.
                '#' if self.peek_at(1).is_some_and(|n| is_squote(n) || is_dquote(n)) => break,
                '`' => {
                    self.bump();
                    match self.peek() {
                        Some(n) if is_newline(n) => break,
                        Some(n) => {
                            text.push(n);
                            self.bump();
                        }
                        None => {}
                    }
                }
                c if is_squote(c) => text.push_str(&self.single_quoted()),
                c if is_dquote(c) => {
                    let (value, lit) = self.double_quoted();
                    text.push_str(&value);
                    literal &= lit;
                }
                '$' => {
                    if self.expansion(&mut text) {
                        literal = false;
                    }
                }
                c => {
                    text.push(c);
                    self.bump();
                }
            }
        }
        (text, literal)
    }

    /// Records a command, and reads what a nested interpreter it starts would run.
    fn add(&mut self, command: PsCommand) {
        let nested = self.nested_scripts(&command);
        self.out.commands.push(command);
        for (text, language) in nested {
            if text.len() > MAX_NESTED_BYTES {
                continue;
            }
            let at = self.out.commands.last().map(|c| c.at);
            let inner = match language {
                Language::PowerShell => {
                    let mut parser = Parser::new(&text, at, self.nested + 1);
                    parser.statements(End::Eof);
                    parser.out
                }
                Language::Cmd => cmd_script(&text, at.unwrap_or(0), self.nested + 1),
            };
            self.out.commands.extend(inner.commands);
        }
    }

    /// The scripts a command hands to another interpreter, as far as its arguments show them.
    fn nested_scripts(&mut self, command: &PsCommand) -> Vec<(String, Language)> {
        if self.nested >= MAX_NESTED {
            return Vec::new();
        }
        let base = command.name.to_lowercase();
        match base.as_str() {
            "powershell" | "pwsh" | "powershell_ise" => powershell_scripts(&command.args),
            "cmd" => cmd_scripts(&command.args),
            "invoke-expression" => command
                .args
                .iter()
                .filter(|a| a.kind == ArgKind::Value)
                .map(|a| (a.text.clone(), Language::PowerShell))
                .collect(),
            "start-process" => {
                let program = command
                    .args
                    .iter()
                    .filter(|a| a.kind == ArgKind::Value)
                    .find_map(|a| interpreter_of(&a.text));
                match program {
                    Some(language) => command
                        .args
                        .iter()
                        .filter(|a| a.kind == ArgKind::Value && a.text.contains(char::is_whitespace))
                        .map(|a| (a.text.clone(), language))
                        .collect(),
                    None => Vec::new(),
                }
            }
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    PowerShell,
    Cmd,
}

/// `powershell`, `pwsh` or `cmd` named by a program path or name.
fn interpreter_of(text: &str) -> Option<Language> {
    let base = text.rsplit(['\\', '/']).next().unwrap_or(text).to_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    match base {
        "powershell" | "pwsh" => Some(Language::PowerShell),
        "cmd" => Some(Language::Cmd),
        _ => None,
    }
}

/// Parameters of `powershell.exe` and `pwsh` that take the next word as their value.
const PS_VALUE_PARAMETERS: &[&str] = &[
    "executionpolicy",
    "ep",
    "ex",
    "windowstyle",
    "configurationname",
    "outputformat",
    "inputformat",
    "psconsolefile",
    "version",
    "workingdirectory",
    "wd",
    "settingsfile",
    "custompipename",
    "encodedarguments",
    "ea",
];

/// What `powershell -Command …`, `-EncodedCommand …` or `powershell <text>` runs.
fn powershell_scripts(args: &[Arg]) -> Vec<(String, Language)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(name) = arg.parameter() {
            if name.is_empty() {
                i += 1;
                continue;
            }
            let encoded = name == "e" || name == "ec" || (name.len() >= 2 && "encodedcommand".starts_with(&name));
            if encoded && !name.starts_with("ex") {
                if let Some(value) = args.get(i + 1) {
                    if let Some(text) = decode_encoded(&value.text) {
                        out.push((text, Language::PowerShell));
                    }
                }
                i += 2;
                continue;
            }
            if "command".starts_with(&name) {
                let text: Vec<&str> = args[i + 1..].iter().map(|a| a.text.as_str()).collect();
                out.push((text.join(" "), Language::PowerShell));
                return out;
            }
            if PS_VALUE_PARAMETERS.iter().any(|p| p.starts_with(&name)) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        // Windows PowerShell runs the first word that isn't a parameter, and the rest after it, as a command.
        let text: Vec<&str> = args[i..].iter().map(|a| a.text.as_str()).collect();
        out.push((text.join(" "), Language::PowerShell));
        return out;
    }
    out
}

/// `-EncodedCommand`'s base64 of UTF-16LE text.
fn decode_encoded(text: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(text.trim()).ok()?;
    if bytes.len() % 2 != 0 || bytes.len() > MAX_NESTED_BYTES * 2 {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .collect();
    String::from_utf16(&units).ok()
}

/// What `cmd /c …` (or `/k`, `/r`, also written together with the command: `/cdel x`) runs. No other switch of cmd
/// starts with those letters.
fn cmd_scripts(args: &[Arg]) -> Vec<(String, Language)> {
    for (i, arg) in args.iter().enumerate() {
        let lower = arg.text.to_lowercase();
        if ["/c", "/k", "/r"].iter().any(|switch| lower.starts_with(switch)) {
            let mut text: Vec<&str> = Vec::new();
            let attached = arg.text.get(2..).unwrap_or_default();
            if !attached.is_empty() {
                text.push(attached);
            }
            text.extend(args[i + 1..].iter().map(|a| a.text.as_str()));
            return vec![(text.join(" "), Language::Cmd)];
        }
    }
    Vec::new()
}

/// A cmd.exe command line, split where cmd splits it (`&`, `&&`, `||`, `|` outside quotes; `^` escapes), each
/// part's words as cmd reads them, and what a `powershell` or `cmd` among them runs.
fn cmd_script(text: &str, at: usize, nested: usize) -> PsScript {
    let mut out = PsScript::default();
    let mut parts: Vec<Vec<String>> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    let push_word = |words: &mut Vec<String>, word: &mut String| {
        if !word.is_empty() {
            words.push(std::mem::take(word));
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '"' => quoted = !quoted,
            '^' if !quoted => {
                if let Some(n) = chars.next() {
                    word.push(n);
                }
            }
            '&' | '|' if !quoted => {
                if chars.peek() == Some(&c) {
                    chars.next();
                }
                push_word(&mut words, &mut word);
                parts.push(std::mem::take(&mut words));
            }
            c if c.is_whitespace() && !quoted => push_word(&mut words, &mut word),
            c => word.push(c),
        }
    }
    push_word(&mut words, &mut word);
    parts.push(words);
    for part in parts.into_iter().filter(|p| !p.is_empty()) {
        // `@echo off`: the @ only hides the echo.
        let first = part[0].trim_start_matches('@');
        // P6: cmd.exe starts switches at the first `/` (`rd/s/q` is `rd` with `/s /q`), so the program name ends there;
        // a path uses `\`. Taking the text after the last `/` would read `rd/s/q` as the program `q`.
        let (prog_path, switches) = match first.find('/') {
            Some(i) => (&first[..i], &first[i..]),
            None => (first, ""),
        };
        let base = prog_path.rsplit('\\').next().unwrap_or(prog_path);
        let stem = strip_program_extension(base).unwrap_or(base);
        let mut args: Vec<Arg> = Vec::new();
        if !switches.is_empty() {
            args.push(Arg {
                text: plain_dashes(switches),
                literal: true,
                kind: ArgKind::Value,
            });
        }
        args.extend(part[1..].iter().map(|w| Arg {
            text: plain_dashes(w),
            literal: true,
            kind: if w.starts_with('-') && w.len() > 1 {
                ArgKind::Parameter
            } else {
                ArgKind::Value
            },
        }));
        let command = PsCommand {
            at,
            name: plain_dashes(stem),
            key: None,
            args,
            first_in_pipeline: true,
        };
        let mut parser = Parser::new("", Some(at), nested);
        parser.add(command);
        out.commands.extend(parser.out.commands);
    }
    out
}

/// PowerShell's operators written as a dash and a word (`-eq`, `-and`, `-replace`; `c` and `i` forms included).
fn is_operator(word: &str) -> bool {
    const OPERATORS: &[&str] = &[
        "eq",
        "ne",
        "gt",
        "ge",
        "lt",
        "le",
        "like",
        "notlike",
        "match",
        "notmatch",
        "replace",
        "contains",
        "notcontains",
        "in",
        "notin",
        "split",
        "join",
        "is",
        "isnot",
        "as",
        "and",
        "or",
        "xor",
        "not",
        "band",
        "bor",
        "bxor",
        "bnot",
        "shl",
        "shr",
        "f",
    ];
    /// The ones with a case-sensitive (`-ceq`) and an insensitive (`-ieq`) form.
    const CASED: &[&str] = &[
        "eq",
        "ne",
        "gt",
        "ge",
        "lt",
        "le",
        "like",
        "notlike",
        "match",
        "notmatch",
        "replace",
        "contains",
        "notcontains",
        "in",
        "notin",
        "split",
    ];
    if OPERATORS.contains(&word) {
        return true;
    }
    word.strip_prefix('c')
        .or_else(|| word.strip_prefix('i'))
        .is_some_and(|rest| CASED.contains(&rest))
}

/// A4: automatic variables whose assignment changes how later commands run, so assigning to one is never read-only.
/// `$null = <command>` and the like stay read-only, so only these execution-steering names count, not every automatic
/// variable.
fn is_execution_variable(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "psdefaultparametervalues" | "executioncontext" | "psmoduleautoloadingpreference"
    )
}

/// A3: types a cast or `-as` may use and still only compute a value. Any other type runs its constructor, which can
/// do anything (`[IO.StreamWriter]'path'` truncates the file, `[xml]` and COM types have side effects), so a cast to it
/// is never read-only. Array and generic-list suffixes are stripped; a `System.`/`Net.` prefix is allowed off.
fn is_value_type(text: &str) -> bool {
    let mut t = text.trim().to_lowercase();
    while let Some(stripped) = t.strip_suffix("[]").or_else(|| t.strip_suffix("[,]")) {
        t = stripped.trim_end().to_owned();
    }
    let t = t.strip_prefix("system.").unwrap_or(&t);
    let t = t.strip_prefix("net.").unwrap_or(t);
    const VALUE_TYPES: &[&str] = &[
        "int",
        "int16",
        "int32",
        "int64",
        "uint",
        "uint16",
        "uint32",
        "uint64",
        "long",
        "ulong",
        "short",
        "ushort",
        "byte",
        "sbyte",
        "double",
        "single",
        "float",
        "decimal",
        "bool",
        "boolean",
        "string",
        "char",
        "datetime",
        "datetimeoffset",
        "timespan",
        "version",
        "guid",
        "ipaddress",
        "bigint",
        "biginteger",
        "void",
        "switch",
        // Third review: common, side-effect-free constructors and casts used in everyday read-only one-liners
        // (building a report row, a lookup table, a pattern). `scriptblock` and `xml` stay out — a script block runs
        // code, and an XML cast can resolve external entities.
        "pscustomobject",
        "psobject",
        "ordered",
        "hashtable",
        "array",
        "regex",
    ];
    VALUE_TYPES.contains(&t)
}

/// Methods that only compute a value from what they are given, on the types PowerShell scripts use them on (strings,
/// numbers, dates, `[math]`). Anything else (`.Kill()`, `.Delete()`, `.Invoke()`, `::Create()`, `.Add()` on a COM
/// object) may change something.
fn pure_method(name: &str, is_static: bool, first_is_block: bool) -> bool {
    const INSTANCE: &[&str] = &[
        "tostring",
        "toupper",
        "tolower",
        "toupperinvariant",
        "tolowerinvariant",
        "trim",
        "trimstart",
        "trimend",
        "split",
        "substring",
        "indexof",
        "lastindexof",
        "startswith",
        "endswith",
        "contains",
        "padleft",
        "padright",
        "gettype",
        "equals",
        "compareto",
        "gethashcode",
        "toshortdatestring",
        "tolongdatestring",
        "toshorttimestring",
        "tolongtimestring",
        "touniversaltime",
        "tolocaltime",
        "adddays",
        "addhours",
        "addminutes",
        "addseconds",
        "addmilliseconds",
        "addmonths",
        "addyears",
        "normalize",
    ];
    const STATIC: &[&str] = &[
        "round",
        "floor",
        "ceiling",
        "abs",
        "max",
        "min",
        "pow",
        "sqrt",
        "truncate",
        "join",
        "format",
        "isnullorempty",
        "isnullorwhitespace",
        "concat",
        "parse",
        "parseexact",
        "fromseconds",
        "fromminutes",
        "fromhours",
        "fromdays",
        "frommilliseconds",
    ];
    let lower = name.to_lowercase();
    // `.Where({ … })` filters; `.ForEach({ … })` runs a block that is read like any other, but `.ForEach('Kill')`
    // calls a method by its name.
    if !is_static && matches!(lower.as_str(), "where" | "foreach") {
        return first_is_block;
    }
    if is_static {
        STATIC.contains(&lower.as_str())
    } else {
        INSTANCE.contains(&lower.as_str())
    }
}

/// PowerShell's built-in aliases and the functions that stand for a command (Windows PowerShell 5.1), in lower case,
/// with the command each runs.
pub(crate) const ALIASES: &[(&str, &str)] = &[
    ("%", "ForEach-Object"),
    ("?", "Where-Object"),
    ("ac", "Add-Content"),
    ("asnp", "Add-PSSnapin"),
    ("cat", "Get-Content"),
    ("cd", "Set-Location"),
    ("cd..", "Set-Location"),
    ("cd\\", "Set-Location"),
    ("cfs", "ConvertFrom-String"),
    ("chdir", "Set-Location"),
    ("clc", "Clear-Content"),
    ("clear", "Clear-Host"),
    ("clhy", "Clear-History"),
    ("cli", "Clear-Item"),
    ("clp", "Clear-ItemProperty"),
    ("cls", "Clear-Host"),
    ("clv", "Clear-Variable"),
    ("cnsn", "Connect-PSSession"),
    ("compare", "Compare-Object"),
    ("copy", "Copy-Item"),
    ("cp", "Copy-Item"),
    ("cpi", "Copy-Item"),
    ("cpp", "Copy-ItemProperty"),
    ("curl", "Invoke-WebRequest"),
    ("cvpa", "Convert-Path"),
    ("dbp", "Disable-PSBreakpoint"),
    ("del", "Remove-Item"),
    ("diff", "Compare-Object"),
    ("dir", "Get-ChildItem"),
    ("dnsn", "Disconnect-PSSession"),
    ("ebp", "Enable-PSBreakpoint"),
    ("echo", "Write-Output"),
    ("epal", "Export-Alias"),
    ("epcsv", "Export-Csv"),
    ("epsn", "Export-PSSession"),
    ("erase", "Remove-Item"),
    ("etsn", "Enter-PSSession"),
    ("exsn", "Exit-PSSession"),
    ("fc", "Format-Custom"),
    ("fhx", "Format-Hex"),
    ("fl", "Format-List"),
    ("foreach", "ForEach-Object"),
    ("ft", "Format-Table"),
    ("fw", "Format-Wide"),
    ("gal", "Get-Alias"),
    ("gbp", "Get-PSBreakpoint"),
    ("gc", "Get-Content"),
    ("gcb", "Get-Clipboard"),
    ("gci", "Get-ChildItem"),
    ("gcm", "Get-Command"),
    ("gcs", "Get-PSCallStack"),
    ("gdr", "Get-PSDrive"),
    ("ghy", "Get-History"),
    ("gi", "Get-Item"),
    ("gin", "Get-ComputerInfo"),
    ("gjb", "Get-Job"),
    ("gl", "Get-Location"),
    ("gm", "Get-Member"),
    ("gmo", "Get-Module"),
    ("gp", "Get-ItemProperty"),
    ("gps", "Get-Process"),
    ("gpv", "Get-ItemPropertyValue"),
    ("group", "Group-Object"),
    ("gsn", "Get-PSSession"),
    ("gsnp", "Get-PSSnapin"),
    ("gsv", "Get-Service"),
    ("gtz", "Get-TimeZone"),
    ("gu", "Get-Unique"),
    ("gv", "Get-Variable"),
    ("gwmi", "Get-WmiObject"),
    ("h", "Get-History"),
    ("help", "Get-Help"),
    ("history", "Get-History"),
    ("icm", "Invoke-Command"),
    ("iex", "Invoke-Expression"),
    ("ihy", "Invoke-History"),
    ("ii", "Invoke-Item"),
    ("ipal", "Import-Alias"),
    ("ipcsv", "Import-Csv"),
    ("ipmo", "Import-Module"),
    ("ipsn", "Import-PSSession"),
    ("irm", "Invoke-RestMethod"),
    ("ise", "powershell_ise"),
    ("iwmi", "Invoke-WmiMethod"),
    ("iwr", "Invoke-WebRequest"),
    ("kill", "Stop-Process"),
    ("lp", "Out-Printer"),
    ("ls", "Get-ChildItem"),
    ("man", "Get-Help"),
    ("md", "New-Item"),
    ("measure", "Measure-Object"),
    ("mi", "Move-Item"),
    ("mkdir", "New-Item"),
    ("mount", "New-PSDrive"),
    ("move", "Move-Item"),
    ("mp", "Move-ItemProperty"),
    ("mv", "Move-Item"),
    ("nal", "New-Alias"),
    ("ndr", "New-PSDrive"),
    ("ni", "New-Item"),
    ("nmo", "New-Module"),
    ("npssc", "New-PSSessionConfigurationFile"),
    ("nsn", "New-PSSession"),
    ("nv", "New-Variable"),
    ("ogv", "Out-GridView"),
    ("oh", "Out-Host"),
    ("oss", "Out-String"),
    ("pause", "Read-Host"),
    ("popd", "Pop-Location"),
    ("ps", "Get-Process"),
    ("pushd", "Push-Location"),
    ("pwd", "Get-Location"),
    ("r", "Invoke-History"),
    ("rbp", "Remove-PSBreakpoint"),
    ("rcjb", "Receive-Job"),
    ("rcsn", "Receive-PSSession"),
    ("rd", "Remove-Item"),
    ("rdr", "Remove-PSDrive"),
    ("ren", "Rename-Item"),
    ("ri", "Remove-Item"),
    ("rjb", "Remove-Job"),
    ("rm", "Remove-Item"),
    ("rmdir", "Remove-Item"),
    ("rmo", "Remove-Module"),
    ("rni", "Rename-Item"),
    ("rnp", "Rename-ItemProperty"),
    ("rp", "Remove-ItemProperty"),
    ("rsn", "Remove-PSSession"),
    ("rsnp", "Remove-PSSnapin"),
    ("rujb", "Resume-Job"),
    ("rv", "Remove-Variable"),
    ("rvpa", "Resolve-Path"),
    ("rwmi", "Remove-WmiObject"),
    ("sajb", "Start-Job"),
    ("sal", "Set-Alias"),
    ("saps", "Start-Process"),
    ("sasv", "Start-Service"),
    ("sbp", "Set-PSBreakpoint"),
    ("sc", "Set-Content"),
    ("scb", "Set-Clipboard"),
    ("select", "Select-Object"),
    ("set", "Set-Variable"),
    ("shcm", "Show-Command"),
    ("si", "Set-Item"),
    ("sl", "Set-Location"),
    ("sleep", "Start-Sleep"),
    ("sls", "Select-String"),
    ("sort", "Sort-Object"),
    ("sp", "Set-ItemProperty"),
    ("spjb", "Stop-Job"),
    ("spps", "Stop-Process"),
    ("spsv", "Stop-Service"),
    ("start", "Start-Process"),
    ("stz", "Set-TimeZone"),
    ("sujb", "Suspend-Job"),
    ("sv", "Set-Variable"),
    ("swmi", "Set-WmiInstance"),
    ("tee", "Tee-Object"),
    ("trcm", "Trace-Command"),
    ("type", "Get-Content"),
    ("wget", "Invoke-WebRequest"),
    ("where", "Where-Object"),
    ("wjb", "Wait-Job"),
    ("write", "Write-Output"),
];

/// The command an alias or built-in function stands for.
pub(crate) fn alias_of(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();
    if let Some((_, command)) = ALIASES.iter().find(|(alias, _)| *alias == lower) {
        return Some(command);
    }
    // `C:`, `D:`: Windows PowerShell's functions that change the drive.
    let mut chars = lower.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some(c), Some(':'), None) if c.is_ascii_alphabetic() => Some("Set-Location"),
        _ => None,
    }
}

/// A command's name as the rules read it, and its key for the read-only list: an alias is its command (`rm` is
/// `Remove-Item`, key `remove-item`); a program is its name without `.exe` or `.com` (`IPCONFIG.EXE` is `IPCONFIG`, key
/// `ipconfig.exe`, as is `ipconfig`); a name with a dash is a cmdlet or function (`Get-Service`, key `get-service`); a
/// path (`C:\Tools\x.exe`, `.\script.ps1`, `Module\Cmdlet`) is its last part, with no key: PowerShell runs what is
/// there, which no list can vouch for.
pub(crate) fn command_key(raw: &str) -> (String, Option<String>) {
    let name = plain_dashes(raw.trim());
    if name.contains(['\\', '/']) && !matches!(name.to_lowercase().as_str(), "cd\\") {
        let base = name.rsplit(['\\', '/']).next().unwrap_or(&name).to_owned();
        let shown = strip_program_extension(&base).unwrap_or(&base).to_owned();
        return (shown, None);
    }
    if let Some(stem) = strip_program_extension(&name) {
        return (stem.to_owned(), Some(format!("{}.exe", stem.to_lowercase())));
    }
    if let Some(command) = alias_of(&name) {
        let key = if command == "powershell_ise" {
            "powershell_ise.exe".to_owned()
        } else {
            command.to_lowercase()
        };
        return (command.to_owned(), Some(key));
    }
    let lower = name.to_lowercase();
    if name.contains('-') || name.contains('.') {
        return (name, Some(lower));
    }
    (name, Some(format!("{lower}.exe")))
}

fn strip_program_extension(name: &str) -> Option<&str> {
    let lower = name.to_lowercase();
    if lower.len() > 4 && (lower.ends_with(".exe") || lower.ends_with(".com")) {
        name.get(..name.len() - 4)
    } else {
        None
    }
}
