//! OpenSSH client config (SS-02): `~/.ssh/config` and the files it includes.
//!
//! Every concrete alias (a `Host` pattern without `*`, `?` or `!`) becomes one candidate named after
//! it. Its settings come from every block that applies to it, in file order, and the first value of
//! each setting wins, as in ssh itself: options before the first `Host`, `Host *.example.com` and
//! `Host *` all count, and a block with a matching negated pattern (`!web01`) does not apply. `Match`
//! blocks depend on what is only known when connecting, so their options are left out, with a warning.
//!
//! Read: `HostName`, `User`, `Port`, `IdentityFile` (the first one is the key), `ProxyJump` (the first
//! hop is the jump host), `RemoteCommand` (the startup command) and `Include`. `ProxyCommand` is not
//! imported. Without an `IdentityFile` a session logs in with the SSH agent, as ssh would.

use std::path::{Path, PathBuf};

use super::{count, finish, parse_port, Candidate, CandidateAuth, Parsed, Skipped, DEFAULT_PORT};

/// Includes inside includes, as deep as ssh itself goes.
const MAX_INCLUDE_DEPTH: usize = 16;

/// The hosts in an ssh config. `home` is the user's home folder (for `~`, `%d` and relative
/// includes, which are under `home/.ssh`), `local_user` the Windows user name (`%u`, and `%r` without
/// a `User`). `read_include` returns the text of an included file, or `None` when it does not exist;
/// an include with `*` or `?` in its file name lists the folder on disk and reads each match with it.
pub fn parse(text: &str, home: &Path, local_user: &str, read_include: &dyn Fn(&Path) -> Option<String>) -> Parsed {
    let mut config = Config {
        home,
        read_include,
        blocks: Vec::new(),
        aliases: Vec::new(),
        parsed: Parsed::default(),
    };
    config.read(text, &Scope::default(), 0);
    let mut parsed = std::mem::take(&mut config.parsed);
    for alias in &config.aliases {
        parsed.push(config.candidate(alias, local_user));
    }
    if parsed.is_empty() {
        parsed.warn("The file has no Host entries without wildcards, so there is nothing to import");
    }
    parsed
}

/// Where a block applies.
#[derive(Debug, Clone, Default)]
struct Scope {
    /// Host lines that must all match: the block's own and, for a file included inside a block, that
    /// block's too.
    hosts: Vec<Vec<String>>,
    /// In a `Match` block (or an empty `Host` line): applies to nothing here.
    never: bool,
}

impl Scope {
    fn applies(&self, alias: &str) -> bool {
        !self.never && self.hosts.iter().all(|patterns| host_line_matches(patterns, alias))
    }
}

struct Block {
    scope: Scope,
    /// Lower-case keyword and value, in file order. Only the keywords the import reads.
    options: Vec<(String, String)>,
}

struct Config<'a> {
    home: &'a Path,
    read_include: &'a dyn Fn(&Path) -> Option<String>,
    blocks: Vec<Block>,
    /// Concrete aliases, in the order they first appear.
    aliases: Vec<String>,
    parsed: Parsed,
}

impl Config<'_> {
    /// Reads one file. `outer` is where the file was included (nothing for the main file): lines
    /// before its first `Host` belong there, and its `Host` blocks only apply inside it.
    fn read(&mut self, text: &str, outer: &Scope, depth: usize) {
        self.blocks.push(Block {
            scope: outer.clone(),
            options: Vec::new(),
        });
        for line in text.lines() {
            let Some((keyword, rest)) = split_keyword(line) else {
                continue;
            };
            match keyword.as_str() {
                "host" => {
                    let patterns = split_args(rest);
                    let mut scope = outer.clone();
                    scope.never |= patterns.is_empty();
                    if !scope.never {
                        for pattern in patterns.iter().filter(|p| is_concrete(p)) {
                            if !self.aliases.iter().any(|a| a.eq_ignore_ascii_case(pattern)) {
                                self.aliases.push(pattern.clone());
                            }
                        }
                    }
                    scope.hosts.push(patterns);
                    self.start_block(scope);
                }
                "match" => {
                    let mut scope = outer.clone();
                    // `Match all` applies everywhere, like `Host *`; it often just ends a Host block.
                    let all = matches!(split_args(rest).as_slice(), [only] if only.eq_ignore_ascii_case("all"));
                    if !all {
                        scope.never = true;
                        self.parsed.warn("Match blocks were not imported");
                    }
                    self.start_block(scope);
                }
                "include" => {
                    let scope = self.blocks.last().map(|b| b.scope.clone()).unwrap_or_default();
                    for arg in split_args(rest) {
                        self.include(&arg, &scope, depth);
                    }
                    // Back in the block that had the Include.
                    self.start_block(scope);
                }
                "hostname" | "user" | "port" | "identityfile" | "proxyjump" => {
                    if let Some(value) = split_args(rest).into_iter().next() {
                        self.add_option(keyword, value);
                    }
                }
                // ssh takes the rest of the line as it is.
                "proxycommand" | "remotecommand" => {
                    let value = rest.trim();
                    if !value.is_empty() {
                        self.add_option(keyword, value.to_owned());
                    }
                }
                _ => {}
            }
        }
    }

    fn start_block(&mut self, scope: Scope) {
        self.blocks.push(Block {
            scope,
            options: Vec::new(),
        });
    }

    fn add_option(&mut self, keyword: String, value: String) {
        if let Some(block) = self.blocks.last_mut() {
            block.options.push((keyword, value));
        }
    }

    fn include(&mut self, arg: &str, scope: &Scope, depth: usize) {
        if depth >= MAX_INCLUDE_DEPTH {
            self.parsed.warn(format!(
                "Includes nested more than {MAX_INCLUDE_DEPTH} deep were not read"
            ));
            return;
        }
        let path = self.include_path(arg);
        let wildcard = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| n.contains(['*', '?']));
        let paths = match wildcard {
            // ssh skips a pattern that matches nothing.
            Some(pattern) => matching_files(path.parent(), &pattern),
            None => vec![path],
        };
        for path in paths {
            match (self.read_include)(&path) {
                Some(text) => self.read(&text, scope, depth + 1),
                None => self
                    .parsed
                    .warn(format!("Include {}: the file was not found", path.display())),
            }
        }
    }

    /// `~/x` under the home folder, a relative path under `home/.ssh`.
    fn include_path(&self, arg: &str) -> PathBuf {
        if arg == "~" {
            return self.home.to_path_buf();
        }
        if let Some(rest) = arg.strip_prefix("~/").or_else(|| arg.strip_prefix("~\\")) {
            return join(self.home, rest);
        }
        if is_absolute(arg) {
            return PathBuf::from(arg);
        }
        join(&self.home.join(".ssh"), arg)
    }

    /// The settings that apply to `alias`, first value wins.
    fn settings(&self, alias: &str) -> Settings {
        let mut s = Settings::default();
        for block in self.blocks.iter().filter(|b| b.scope.applies(alias)) {
            for (keyword, value) in &block.options {
                match keyword.as_str() {
                    "hostname" => first(&mut s.host_name, value),
                    "user" => first(&mut s.user, value),
                    "port" => first(&mut s.port, value),
                    "remotecommand" => first(&mut s.remote_command, value),
                    "identityfile" => s.identity_files.push(value.clone()),
                    // Whichever of the two comes first stops the other, as in ssh.
                    "proxyjump" | "proxycommand" if s.proxy.is_none() => {
                        s.proxy = Some(if value.eq_ignore_ascii_case("none") {
                            Proxy::Off
                        } else if keyword == "proxyjump" {
                            Proxy::Jump(value.clone())
                        } else {
                            Proxy::Command
                        });
                    }
                    _ => {}
                }
            }
        }
        s
    }

    fn candidate(&self, alias: &str, local_user: &str) -> Result<Candidate, Skipped> {
        let s = self.settings(alias);
        let host = s
            .host_name
            .as_deref()
            .map_or_else(|| alias.to_owned(), |h| expand_tokens(h, &[('h', alias)]));
        let port = match &s.port {
            Some(port) => parse_port(port).map_err(|reason| Skipped::new(alias, reason))?,
            None => DEFAULT_PORT,
        };

        let mut c = Candidate::new(alias, host.clone());
        c.port = port;
        c.username = s.user.clone();

        let remote_user = s.user.as_deref().unwrap_or(local_user);
        let mut keys: Vec<String> = Vec::new();
        for file in s.identity_files.iter().filter(|f| !f.eq_ignore_ascii_case("none")) {
            let path = self.expand_key_path(file, local_user, &host, remote_user);
            if !keys.contains(&path) {
                keys.push(path);
            }
        }
        c.auth = match keys.split_first() {
            Some((key, rest)) => {
                if !rest.is_empty() {
                    c.notes.push(format!(
                        "{} not imported; a session uses one key",
                        count(rest.len(), "more IdentityFile was", "more IdentityFiles were")
                    ));
                }
                CandidateAuth::KeyFile { path: key.clone() }
            }
            None => CandidateAuth::Agent,
        };

        match &s.proxy {
            Some(Proxy::Jump(jump)) => {
                let hops: Vec<&str> = jump.split(',').map(str::trim).filter(|h| !h.is_empty()).collect();
                if let Some(first) = hops.first() {
                    c.jump = Some((*first).to_owned());
                    if hops.len() > 1 {
                        c.notes.push(format!(
                            "ProxyJump goes through {} jump hosts; only the first ({first}) was imported",
                            hops.len()
                        ));
                    }
                }
            }
            Some(Proxy::Command) => c.notes.push("ProxyCommand was not imported".into()),
            Some(Proxy::Off) | None => {}
        }
        if let Some(command) = &s.remote_command {
            c.startup_command = Some(command.clone());
            c.notes
                .push("RemoteCommand was imported as the startup command, which runs in the shell after login".into());
        }
        finish(c)
    }

    /// `~`, `%d` (home), `%u` (local user), `%h` (host), `%r` (remote user) and `%%`. A relative path
    /// is taken as under the home folder, where ssh usually runs.
    fn expand_key_path(&self, path: &str, local_user: &str, host: &str, remote_user: &str) -> String {
        let home = self.home.to_string_lossy();
        let home = home.trim_end_matches(['\\', '/']);
        let path = if path == "~" {
            home.to_owned()
        } else if let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
            format!("{home}/{rest}")
        } else {
            path.to_owned()
        };
        let path = expand_tokens(
            &path,
            &[('d', home), ('u', local_user), ('h', host), ('r', remote_user)],
        );
        let path = if is_absolute(&path) {
            path
        } else {
            format!("{home}/{path}")
        };
        // One kind of separator on Windows, for a path that reads well in the preview.
        if home.contains('\\') {
            path.replace('/', "\\")
        } else {
            path
        }
    }
}

#[derive(Default)]
struct Settings {
    host_name: Option<String>,
    user: Option<String>,
    port: Option<String>,
    identity_files: Vec<String>,
    proxy: Option<Proxy>,
    remote_command: Option<String>,
}

enum Proxy {
    Jump(String),
    Command,
    /// `ProxyJump none` or `ProxyCommand none`.
    Off,
}

fn first(slot: &mut Option<String>, value: &str) {
    if slot.is_none() {
        *slot = Some(value.to_owned());
    }
}

/// The keyword (lower case) and the rest of the line, for `Keyword value` and `Keyword=value`.
/// `None` for blank lines and comments.
fn split_keyword(line: &str) -> Option<(String, &str)> {
    let line = line.trim().trim_start_matches('\u{feff}');
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(line.len());
    let (keyword, rest) = line.split_at(end);
    if keyword.is_empty() {
        return None;
    }
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    Some((keyword.to_ascii_lowercase(), rest))
}

/// Arguments as ssh splits them: on whitespace, with `"..."` and `'...'` quoting, `\\`, `\"`, `\'`
/// and (outside quotes) `\ ` escapes, and a `#` starting an argument ending the line. Other
/// backslashes stay, so Windows paths need no escaping.
fn split_args(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        match chars.peek() {
            None | Some('#') => break,
            Some(_) => {}
        }
        let mut arg = String::new();
        let mut quote: Option<char> = None;
        while let Some(&c) = chars.peek() {
            if quote.is_none() && c.is_whitespace() {
                break;
            }
            chars.next();
            match c {
                '\\' => match chars.peek() {
                    Some(&next) if matches!(next, '\\' | '"' | '\'') || (quote.is_none() && next == ' ') => {
                        arg.push(next);
                        chars.next();
                    }
                    _ => arg.push('\\'),
                },
                '"' | '\'' if quote.is_none() => quote = Some(c),
                c if Some(c) == quote => quote = None,
                c => arg.push(c),
            }
        }
        args.push(arg);
    }
    args
}

/// A Host pattern naming one host: no wildcard, no negation.
fn is_concrete(pattern: &str) -> bool {
    !pattern.is_empty() && !pattern.contains(['*', '?', '!'])
}

/// A Host line matches when one of its patterns does and none of its negated (`!`) patterns does.
fn host_line_matches(patterns: &[String], alias: &str) -> bool {
    let mut matched = false;
    for pattern in patterns {
        match pattern.strip_prefix('!') {
            Some(negated) if glob(negated, alias) => return false,
            Some(_) => {}
            None => matched |= glob(pattern, alias),
        }
    }
    matched
}

/// `*` (any run of characters) and `?` (one character), ignoring letter case.
fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0, 0);
    // The last `*` seen and the text position it was tried at, to backtrack to.
    let mut star: Option<(usize, usize)> = None;
    while let Some(&tc) = t.get(ti) {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some(&pc) if pc == '?' || pc == tc => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    pi = sp + 1;
                    ti = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    p.get(pi..).is_none_or(|rest| rest.iter().all(|&c| c == '*'))
}

/// `%h`-style tokens from `tokens`, and `%%`. Unknown tokens stay as written.
fn expand_tokens(text: &str, tokens: &[(char, &str)]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some(token) => match tokens.iter().find(|(t, _)| *t == token) {
                Some((_, value)) => out.push_str(value),
                None => {
                    out.push('%');
                    out.push(token);
                }
            },
            None => out.push('%'),
        }
    }
    out
}

/// `/x`, `\x`, `C:\x` or `C:/x`, on any platform.
fn is_absolute(path: &str) -> bool {
    match path.as_bytes() {
        [b'/' | b'\\', ..] => true,
        [letter, b':', ..] => letter.is_ascii_alphabetic(),
        _ => false,
    }
}

/// `base` with the `/` or `\` separated parts of `rest` added.
fn join(base: &Path, rest: &str) -> PathBuf {
    rest.split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

/// The files in `dir` whose names match `pattern`, sorted, as ssh reads them.
fn matching_files(dir: Option<&Path>, pattern: &str) -> Vec<PathBuf> {
    let Some(entries) = dir.and_then(|d| std::fs::read_dir(d).ok()) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .is_some_and(|name| glob(pattern, &name.to_string_lossy()))
        })
        .collect();
    files.sort();
    files
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn home() -> &'static Path {
        Path::new(r"C:\Users\alice")
    }

    fn no_includes(_: &Path) -> Option<String> {
        None
    }

    fn parse_alone(text: &str) -> Parsed {
        parse(text, home(), "alice", &no_includes)
    }

    fn find<'a>(parsed: &'a Parsed, name: &str) -> &'a Candidate {
        parsed
            .candidates
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no candidate {name} in {parsed:?}"))
    }

    fn key(path: &str) -> CandidateAuth {
        CandidateAuth::KeyFile { path: path.into() }
    }

    #[test]
    fn first_value_wins_across_matching_blocks() {
        let parsed = parse_alone(
            "Host web01 web02
    HostName %h.example.com
    User alice

Host db01
    HostName=192.0.2.30
    User bob
    Port 2222

Host web* !web02
    Port 2200
    IdentityFile ~/.ssh/web_key

Host *
    User nobody
    Port 22
    IdentityFile %d/.ssh/id_ed25519
",
        );
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        let names: Vec<_> = parsed.candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["web01", "web02", "db01"]);

        let web01 = find(&parsed, "web01");
        assert_eq!(web01.host, "web01.example.com");
        assert_eq!(web01.username.as_deref(), Some("alice"));
        assert_eq!(web01.port, 2200);
        assert_eq!(web01.auth, key(r"C:\Users\alice\.ssh\web_key"));
        assert_eq!(
            web01.notes,
            ["1 more IdentityFile was not imported; a session uses one key"]
        );

        // `!web02` keeps the web* block away from web02.
        let web02 = find(&parsed, "web02");
        assert_eq!(web02.host, "web02.example.com");
        assert_eq!(web02.port, 22);
        assert_eq!(web02.auth, key(r"C:\Users\alice\.ssh\id_ed25519"));
        assert!(web02.notes.is_empty());

        let db01 = find(&parsed, "db01");
        assert_eq!((db01.host.as_str(), db01.port), ("192.0.2.30", 2222));
        assert_eq!(db01.username.as_deref(), Some("bob"));
        assert_eq!(db01.environment, crate::domain::Environment::None);
    }

    #[test]
    fn options_before_the_first_host_apply_to_every_host_and_win() {
        let parsed = parse_alone(
            "User alice
Port 2200

Host lab
    HostName lab.example.com
    User bob
",
        );
        let lab = find(&parsed, "lab");
        assert_eq!(lab.username.as_deref(), Some("alice"));
        assert_eq!(lab.port, 2200);
        assert_eq!(lab.auth, CandidateAuth::Agent, "no IdentityFile: the agent");
    }

    #[test]
    fn an_alias_without_host_name_connects_to_itself() {
        let parsed = parse_alone("Host 192.0.2.10 web01.example.com\n");
        assert_eq!(parsed.candidates.len(), 2);
        assert_eq!(parsed.candidates[0].host, "192.0.2.10");
        assert_eq!(parsed.candidates[0].username, None);
        assert_eq!(parsed.candidates[1].name, "web01.example.com");
    }

    #[test]
    fn proxies_remote_commands_and_match_blocks() {
        let parsed = parse_alone(
            "Host db01
    HostName db01.example.com
    ProxyJump bob@bastion.example.org:2200,jump2.example.org
    ProxyCommand ssh -W %h:%p other.example.org

Host app01
    HostName app01.example.com
    ProxyCommand ssh -W %h:%p gw.example.org
    RemoteCommand tmux new -A -s main

Match host app01 exec \"true\"
    User bob
    Port 2222

Host direct01
    ProxyJump none
    ProxyCommand ssh -W %h:%p gw.example.org

Match all
Host *
    ProxyJump bastion.example.org
",
        );
        assert_eq!(parsed.warnings, ["Match blocks were not imported"]);

        let db01 = find(&parsed, "db01");
        assert_eq!(db01.jump.as_deref(), Some("bob@bastion.example.org:2200"));
        assert_eq!(db01.notes.len(), 1);
        assert!(db01.notes[0].contains("2 jump hosts"), "{:?}", db01.notes);

        let app01 = find(&parsed, "app01");
        assert_eq!(app01.jump, None);
        assert_eq!(app01.port, 22, "the Match block is left out");
        assert_eq!(app01.username, None);
        assert_eq!(app01.startup_command.as_deref(), Some("tmux new -A -s main"));
        assert_eq!(app01.notes[0], "ProxyCommand was not imported");
        assert!(app01.notes[1].starts_with("RemoteCommand"));

        let direct01 = find(&parsed, "direct01");
        assert_eq!(direct01.jump, None, "ProxyJump none comes first");
        assert!(direct01.notes.is_empty());
    }

    #[test]
    fn identity_file_tokens_and_none() {
        let parsed = parse(
            "Host db01
    HostName db01.example.com
    User bob
    IdentityFile none
    IdentityFile ~/.ssh/%r@%h_%u%%
    IdentityFile ~/.ssh/%r@%h_%u%%
Host web01
    IdentityFile keys/id_ed25519
",
            home(),
            "alice",
            &no_includes,
        );
        let db01 = find(&parsed, "db01");
        assert_eq!(db01.auth, key(r"C:\Users\alice\.ssh\bob@db01.example.com_alice%"));
        assert!(db01.notes.is_empty(), "duplicates count once: {:?}", db01.notes);
        assert_eq!(find(&parsed, "web01").auth, key(r"C:\Users\alice\keys\id_ed25519"));

        let unix = parse(
            "Host lab01\n IdentityFile ~/.ssh/id_%u\n",
            Path::new("/home/alice/"),
            "alice",
            &no_includes,
        );
        assert_eq!(unix.candidates[0].auth, key("/home/alice/.ssh/id_alice"));
    }

    #[test]
    fn quoting_comments_and_letter_case() {
        let parsed = parse_alone(
            "# a comment line
HOST web03   # trailing comment
  hostname = web03.example.com
  IDENTITYFILE \"C:\\Users\\alice\\My Keys\\id_ed25519\"
  user=\"alice\"
Host \"web 04\"
",
        );
        let web03 = find(&parsed, "web03");
        assert_eq!(web03.host, "web03.example.com");
        assert_eq!(web03.username.as_deref(), Some("alice"));
        assert_eq!(web03.auth, key(r"C:\Users\alice\My Keys\id_ed25519"));
        // "web 04" is an alias, but its host name has a space in it.
        assert_eq!(parsed.skipped.len(), 1);
        assert_eq!(parsed.skipped[0].name, "web 04");
        assert_eq!(parsed.skipped[0].reason, "the host name has spaces in it");
    }

    #[test]
    fn a_bad_port_is_skipped_and_an_empty_file_warns() {
        let parsed = parse_alone("Host web01\n Port ssh\n");
        assert_eq!(parsed.skipped, [Skipped::new("web01", "port ssh is not valid")]);
        let empty = parse_alone("Host *\n User alice\n");
        assert!(empty.is_empty());
        assert_eq!(empty.warnings.len(), 1);
    }

    #[test]
    fn includes_are_read_through_the_callback() {
        let ssh = home().join(".ssh");
        let files: HashMap<PathBuf, &str> = HashMap::from([
            (
                ssh.join("work.conf"),
                // Before any Host line, so it is not conditional on work01.
                "Include nested/more.conf\nHost work01\n  HostName work01.example.org\n  User bob\n",
            ),
            (
                ssh.join("nested").join("more.conf"),
                "Host work02\n HostName work02.example.org\n",
            ),
            (home().join("extra.conf"), "Host extra01\n HostName 192.0.2.40\n"),
            (ssh.join("web-options.conf"), "User alice\n"),
        ]);
        let read = |path: &Path| files.get(path).map(|t| (*t).to_owned());
        let parsed = parse(
            "Include work.conf missing.conf ~/extra.conf
Host home01
    HostName 192.0.2.10
Host web01
    HostName web01.example.com
    Include web-options.conf
    Port 2201
Host web02
    HostName web02.example.com
",
            home(),
            "alice",
            &read,
        );
        let names: Vec<_> = parsed.candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["work02", "work01", "extra01", "home01", "web01", "web02"]);
        assert_eq!(find(&parsed, "work01").username.as_deref(), Some("bob"));
        assert_eq!(find(&parsed, "work02").host, "work02.example.org");
        assert_eq!(find(&parsed, "extra01").host, "192.0.2.40");
        assert_eq!(parsed.warnings.len(), 1);
        assert!(parsed.warnings[0].contains("missing.conf"), "{:?}", parsed.warnings);

        // An Include inside a Host block applies to that host only, and the block goes on after it.
        let web01 = find(&parsed, "web01");
        assert_eq!((web01.username.as_deref(), web01.port), (Some("alice"), 2201));
        let web02 = find(&parsed, "web02");
        assert_eq!((web02.username.as_deref(), web02.port), (None, 22));
    }

    #[test]
    fn includes_stop_at_the_depth_limit() {
        let read = |_: &Path| Some("Include loop.conf\nHost loop01\n HostName loop01.example.com\n".to_owned());
        let parsed = parse("Include loop.conf\n", home(), "alice", &read);
        assert_eq!(parsed.candidates.len(), 1);
        assert_eq!(parsed.candidates[0].name, "loop01");
        assert_eq!(parsed.warnings.len(), 1);
        assert!(parsed.warnings[0].contains("16"), "{:?}", parsed.warnings);
    }

    #[test]
    fn wildcard_includes_list_the_folder() {
        let dir = std::env::temp_dir().join(format!("remotely-ssh-config-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("config.d")).unwrap();
        std::fs::write(
            dir.join("config.d").join("b.conf"),
            "Host b01\n HostName b01.example.com\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("config.d").join("a.conf"),
            "Host a01\n HostName a01.example.com\n",
        )
        .unwrap();
        std::fs::write(dir.join("config.d").join("notes.txt"), "Host n01\n").unwrap();
        let read = |path: &Path| std::fs::read_to_string(path).ok();
        let main = format!("Include \"{}\"\n", dir.join("config.d").join("*.conf").display());
        let parsed = parse(&main, home(), "alice", &read);
        let none = parse(
            &format!("Include \"{}\"\n", dir.join("empty.d").join("*").display()),
            home(),
            "alice",
            &read,
        );
        std::fs::remove_dir_all(&dir).unwrap();

        let names: Vec<_> = parsed.candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a01", "b01"]);
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
        assert_eq!(
            none.warnings.len(),
            1,
            "only the nothing-to-import warning: {:?}",
            none.warnings
        );
    }

    #[test]
    fn patterns() {
        assert!(glob("*.example.com", "web01.EXAMPLE.com"));
        assert!(glob("web??", "web01"));
        assert!(!glob("web??", "web1"));
        assert!(glob("*", ""));
        assert!(glob("a*b*c", "aXbYbZc"));
        assert!(!glob("a*b*c", "aXbYbZ"));
        let line = |p: &[&str]| p.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(host_line_matches(&line(&["web*", "!web02"]), "web01"));
        assert!(!host_line_matches(&line(&["web*", "!web02"]), "web02"));
        assert!(
            !host_line_matches(&line(&["!web02"]), "web01"),
            "negation alone matches nothing"
        );
        assert_eq!(
            split_args(r#"a "b c" 'd "e"' f\ g h\\i C:\x # rest"#),
            ["a", "b c", r#"d "e""#, "f g", r"h\i", r"C:\x"]
        );
        assert_eq!(expand_tokens("%h.%x.%%.%", &[('h', "web01")]), "web01.%x.%.%");
    }
}
