//! An SSH server on 127.0.0.1 for the terminal tests (SS-03, SS-05): russh's server with keys made at
//! run time, so no test connects to a real host and no key is ever committed.
//!
//! Every connection runs through a small relay the test controls: [`TestSshServer::drop_connections`]
//! cuts the TCP connections the way a network failure would (no SSH goodbye), and
//! [`TestSshServer::freeze_connections`] silently swallows their traffic, so only keep-alives can tell
//! the connection is dead. The shell is a toy that echoes what is typed and understands a few
//! commands (`exit [code]`, `whoami`, `split-utf8`, `echo <text>`, and for trying the app by hand,
//! `drop-connection` and `change-host-key`). The server logs what clients ask for
//! (`pty xterm-256color 80x24`, `resize 120x40`, `shell`, `line whoami`, `exec uptime`) for tests to
//! check; it never logs what arrives on stdin.
//!
//! Exec channels (BX-02) run a toy POSIX shell ([`ToyShell`]): `;`, `&&`, `||` and new lines, quotes,
//! `>&2`, and `echo`, `hostname`, `whoami`, `uptime`, `cat` (files set with
//! [`TestSshServer::with_file`], or stdin), `seq`, `sleep`, `exit`, `true`, `false`, `exec </dev/null`,
//! `sh -c` and `sudo` (BX-07: `-S` reads the password from stdin, `-p` sets the prompt, asked up to
//! three times like the real one; see [`SudoMode`]).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{HashAlg, PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Response, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::locks;
use crate::vault::SecretString;

/// A new Ed25519 key from the system's random source.
pub fn generate_key() -> PrivateKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap_or_else(|err| panic!("no random source: {err}"));
    PrivateKey::from(Ed25519Keypair::from_seed(&seed))
}

/// The key in OpenSSH's text form, encrypted with `passphrase` if one is given. Only ever held in
/// memory: tests hand it to the vault or the adapter.
pub fn private_key_text(key: &PrivateKey, passphrase: Option<&str>) -> SecretString {
    let key = match passphrase {
        Some(p) => key
            .encrypt(&mut getrandom::SysRng, p)
            .unwrap_or_else(|err| panic!("can't encrypt the test key: {err}")),
        None => key.clone(),
    };
    let text = key
        .to_openssh(LineEnding::LF)
        .unwrap_or_else(|err| panic!("can't encode the test key: {err}"));
    SecretString::new(text.as_str())
}

/// `SHA256:...`, as the adapter reports host keys.
pub fn fingerprint(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

/// How `sudo` behaves on the test server (BX-07).
#[derive(Debug, Clone, Default)]
pub enum SudoMode {
    /// No sudo installed.
    #[default]
    Missing,
    /// Asks for this password.
    Password(String),
    /// NOPASSWD in sudoers: never asks, never reads stdin.
    NoPassword,
    /// A broken sudo that prints the password it read on stdout, to check the client scrubs it.
    EchoesPassword(String),
}

#[derive(Default)]
struct State {
    host_key: Mutex<Option<PrivateKey>>,
    hostname: Mutex<Option<String>>,
    files: Mutex<HashMap<String, String>>,
    sudo: Mutex<SudoMode>,
    /// Every exec waits this long before it answers.
    exec_delay: Mutex<Option<Duration>>,
    /// When each exec sent its exit status.
    exits: Mutex<Vec<std::time::Instant>>,
    passwords: Mutex<HashMap<String, String>>,
    keys: Mutex<HashMap<String, Vec<PublicKey>>>,
    /// A second factor asked by keyboard-interactive after a password or key.
    otp: Mutex<Option<String>>,
    /// Passwords only through keyboard-interactive, like a PAM-only server.
    interactive_only: AtomicBool,
    banner: Mutex<Option<String>>,
    inactivity_timeout: Mutex<Option<Duration>>,
    links: Mutex<Vec<Link>>,
    connections: AtomicUsize,
    log: Mutex<Vec<String>>,
}

struct Link {
    freeze: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl State {
    fn note(&self, line: impl Into<String>) {
        locks::lock(&self.log).push(line.into());
    }

    fn drop_links(&self) {
        for link in locks::lock(&self.links).drain(..) {
            for task in link.tasks {
                task.abort();
            }
        }
    }
}

pub struct TestSshServer {
    port: u16,
    state: Arc<State>,
    accept: JoinHandle<()>,
}

impl TestSshServer {
    pub async fn start() -> Self {
        Self::start_on(0).await
    }

    /// On a given port of 127.0.0.1 (0: any free one).
    pub async fn start_on(port: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap_or_else(|err| panic!("can't listen on 127.0.0.1:{port}: {err}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|err| panic!("no local address: {err}"))
            .port();
        let state = Arc::new(State::default());
        *locks::lock(&state.host_key) = Some(generate_key());
        let accept = tokio::spawn(accept_loop(listener, Arc::clone(&state)));
        Self { port, state, accept }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn with_password(self, user: &str, password: &str) -> Self {
        locks::lock(&self.state.passwords).insert(user.into(), password.into());
        self
    }

    pub fn with_key(self, user: &str, key: &PublicKey) -> Self {
        locks::lock(&self.state.keys)
            .entry(user.into())
            .or_default()
            .push(key.clone());
        self
    }

    /// After the first factor, ask for this code by keyboard-interactive.
    pub fn with_otp(self, code: &str) -> Self {
        *locks::lock(&self.state.otp) = Some(code.into());
        self
    }

    /// Offer passwords through keyboard-interactive only.
    pub fn interactive_only(self) -> Self {
        self.state.interactive_only.store(true, Ordering::SeqCst);
        self
    }

    pub fn with_banner(self, banner: &str) -> Self {
        *locks::lock(&self.state.banner) = Some(banner.into());
        self
    }

    /// The server hangs up on connections idle for this long (applies to new connections).
    pub fn with_inactivity_timeout(self, timeout: Duration) -> Self {
        *locks::lock(&self.state.inactivity_timeout) = Some(timeout);
        self
    }

    /// What `hostname` prints (default `test-host`).
    pub fn with_hostname(self, name: &str) -> Self {
        *locks::lock(&self.state.hostname) = Some(name.into());
        self
    }

    /// A file `cat` can read.
    pub fn with_file(self, path: &str, contents: &str) -> Self {
        locks::lock(&self.state.files).insert(path.into(), contents.into());
        self
    }

    pub fn with_sudo(self, mode: SudoMode) -> Self {
        *locks::lock(&self.state.sudo) = mode;
        self
    }

    /// Every command waits this long before it answers, like a slow host.
    pub fn with_exec_delay(self, delay: Duration) -> Self {
        *locks::lock(&self.state.exec_delay) = Some(delay);
        self
    }

    pub fn host_key_fingerprint(&self) -> String {
        locks::lock(&self.state.host_key)
            .as_ref()
            .map(fingerprint)
            .unwrap_or_default()
    }

    /// A new host key for new connections, as after a reinstall (or an attacker in the middle).
    pub fn rotate_host_key(&self) {
        *locks::lock(&self.state.host_key) = Some(generate_key());
    }

    /// Cuts every open connection without an SSH goodbye, like a network failure.
    pub fn drop_connections(&self) {
        self.state.drop_links();
    }

    /// Swallows all traffic on the open connections from now on; the sockets stay open.
    pub fn freeze_connections(&self) {
        for link in locks::lock(&self.state.links).iter() {
            let _ = link.freeze.send(true);
        }
    }

    /// When the last command run here sent its exit status.
    pub fn last_exit(&self) -> Option<std::time::Instant> {
        locks::lock(&self.state.exits).last().copied()
    }

    /// TCP connections accepted so far.
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    pub fn log(&self) -> Vec<String> {
        locks::lock(&self.state.log).clone()
    }
}

impl Drop for TestSshServer {
    fn drop(&mut self) {
        self.accept.abort();
        self.drop_connections();
    }
}

async fn accept_loop(listener: TcpListener, state: Arc<State>) {
    while let Ok((socket, _)) = listener.accept().await {
        state.connections.fetch_add(1, Ordering::SeqCst);
        let Some(host_key) = locks::lock(&state.host_key).clone() else {
            continue;
        };
        let interactive_only = state.interactive_only.load(Ordering::SeqCst);
        let methods: &[MethodKind] = if interactive_only {
            &[MethodKind::PublicKey, MethodKind::KeyboardInteractive]
        } else {
            &[
                MethodKind::Password,
                MethodKind::PublicKey,
                MethodKind::KeyboardInteractive,
            ]
        };
        let config = Arc::new(server::Config {
            methods: MethodSet::from(methods),
            auth_rejection_time: Duration::from_millis(1),
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            inactivity_timeout: *locks::lock(&state.inactivity_timeout),
            ..Default::default()
        });
        let (relay_end, server_end) = tokio::io::duplex(64 * 1024);
        let handler = ServerHandler {
            state: Arc::clone(&state),
            user: String::new(),
            first_factor: false,
            lines: HashMap::new(),
            execs: HashMap::new(),
        };
        let session = tokio::spawn(async move {
            if let Ok(running) = server::run_stream(config, server_end, handler).await {
                let _ = running.await;
            }
        });
        let (freeze, frozen) = watch::channel(false);
        let (socket_read, socket_write) = socket.into_split();
        let (relay_read, relay_write) = tokio::io::split(relay_end);
        let up = tokio::spawn(relay(socket_read, relay_write, frozen.clone()));
        let down = tokio::spawn(relay(relay_read, socket_write, frozen));
        locks::lock(&state.links).push(Link {
            freeze,
            tasks: vec![up, down, session],
        });
    }
}

/// Copies bytes one way until either side closes; once frozen, drops them and stalls.
async fn relay(mut from: impl AsyncRead + Unpin, mut to: impl AsyncWrite + Unpin, frozen: watch::Receiver<bool>) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if *frozen.borrow() {
            std::future::pending::<()>().await;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}

struct ServerHandler {
    state: Arc<State>,
    user: String,
    /// The password or key was accepted; a one-time code may still be due.
    first_factor: bool,
    lines: HashMap<ChannelId, Vec<u8>>,
    /// Exec channels: the command, and stdin until the client ends it.
    execs: HashMap<ChannelId, (String, Vec<u8>)>,
}

impl ServerHandler {
    fn otp(&self) -> Option<String> {
        locks::lock(&self.state.otp).clone()
    }

    /// Accept, or ask for the one-time code next.
    fn first_factor_ok(&mut self) -> Auth {
        self.first_factor = true;
        if self.otp().is_some() {
            Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..])),
                partial_success: true,
            }
        } else {
            Auth::Accept
        }
    }

    fn run_line(&mut self, channel: ChannelId, line: &str, session: &mut Session) -> Result<(), russh::Error> {
        self.state.note(format!("line {line}"));
        let mut words = line.split_whitespace();
        match words.next() {
            Some("exit") => {
                let code = words.next().and_then(|c| c.parse().ok()).unwrap_or(0);
                session.data(channel, b"logout\r\n".to_vec())?;
                session.exit_status_request(channel, code)?;
                session.eof(channel)?;
                session.close(channel)?;
                return Ok(());
            }
            Some("whoami") => session.data(channel, format!("{}\r\n", self.user).into_bytes())?,
            // "é" sent as two packets, split inside the character.
            Some("split-utf8") => {
                session.data(channel, vec![0xC3])?;
                session.data(channel, vec![0xA9, b'\r', b'\n'])?;
            }
            Some("echo") => {
                let rest: Vec<&str> = words.collect();
                session.data(channel, format!("{}\r\n", rest.join(" ")).into_bytes())?;
            }
            // For trying the app by hand: a network failure, a moment later so this reply goes out.
            Some("drop-connection") => {
                session.data(channel, b"dropping every connection in a moment\r\n".to_vec())?;
                let state = Arc::clone(&self.state);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    state.drop_links();
                });
            }
            // For trying the app by hand: the next connection presents a new host key.
            Some("change-host-key") => {
                *locks::lock(&self.state.host_key) = Some(generate_key());
                session.data(channel, b"new host key for the next connection\r\n".to_vec())?;
            }
            Some(other) => session.data(channel, format!("{other}: command not found\r\n").into_bytes())?,
            None => {}
        }
        session.data(channel, b"$ ".to_vec())?;
        Ok(())
    }
}

impl server::Handler for ServerHandler {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(locks::lock(&self.state.banner).clone())
    }

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.user = user.to_owned();
        Ok(Auth::reject())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.user = user.to_owned();
        if self.state.interactive_only.load(Ordering::SeqCst) {
            return Ok(Auth::reject());
        }
        let ok = locks::lock(&self.state.passwords)
            .get(user)
            .is_some_and(|p| p == password);
        self.state
            .note(format!("password {user} {}", if ok { "ok" } else { "refused" }));
        Ok(if ok { self.first_factor_ok() } else { Auth::reject() })
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.user = user.to_owned();
        let ok = locks::lock(&self.state.keys)
            .get(user)
            .is_some_and(|keys| keys.iter().any(|k| k.key_data() == key.key_data()));
        self.state
            .note(format!("publickey {user} {}", if ok { "ok" } else { "refused" }));
        Ok(if ok { self.first_factor_ok() } else { Auth::reject() })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        self.user = user.to_owned();
        let asking_code = self.first_factor && self.otp().is_some();
        let Some(mut response) = response else {
            let prompt = if asking_code {
                "Verification code: "
            } else {
                "Password: "
            };
            return Ok(Auth::Partial {
                name: "".into(),
                instructions: "".into(),
                prompts: vec![(prompt.into(), false)].into(),
            });
        };
        let answer = response
            .next()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        if asking_code {
            let ok = self.otp().is_some_and(|code| code == answer);
            self.state
                .note(format!("otp {user} {}", if ok { "ok" } else { "refused" }));
            return Ok(if ok { Auth::Accept } else { Auth::reject() });
        }
        let ok = locks::lock(&self.state.passwords)
            .get(user)
            .is_some_and(|p| *p == answer);
        self.state
            .note(format!("interactive {user} {}", if ok { "ok" } else { "refused" }));
        Ok(if ok { self.first_factor_ok() } else { Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.lines.insert(channel.id(), Vec::new());
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.note(format!("pty {term} {cols}x{rows}"));
        session.channel_success(channel)
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.state.note("shell");
        session.channel_success(channel)?;
        session.data(channel, format!("Welcome, {}\r\n$ ", self.user).into_bytes())
    }

    async fn window_change_request(
        &mut self,
        _: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.note(format!("resize {cols}x{rows}"));
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        self.state.note(format!("exec {command}"));
        self.execs.insert(channel, (command, Vec::new()));
        session.channel_success(channel)
    }

    /// The command runs once stdin has ended, like `sh -c` reading a script that is all there.
    async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        if let Some((command, stdin)) = self.execs.remove(&channel) {
            let state = Arc::clone(&self.state);
            let user = self.user.clone();
            let handle = session.handle();
            tokio::spawn(async move {
                let delay = *locks::lock(&state.exec_delay);
                let mut shell = ToyShell::new(&state, &user, stdin);
                let status = shell.run(&command);
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                if !shell.sleep.is_zero() {
                    tokio::time::sleep(shell.sleep).await;
                }
                // In pieces, so the client sees output arrive over several reads.
                for chunk in shell.stdout.chunks(4096) {
                    let _ = handle.data(channel, chunk.to_vec()).await;
                }
                for chunk in shell.stderr.chunks(4096) {
                    let _ = handle.extended_data(channel, 1, chunk.to_vec()).await;
                }
                locks::lock(&state.exits).push(std::time::Instant::now());
                let _ = handle.exit_status_request(channel, status).await;
                let _ = handle.eof(channel).await;
                let _ = handle.close(channel).await;
            });
        }
        Ok(())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        if let Some((_, stdin)) = self.execs.get_mut(&channel) {
            stdin.extend_from_slice(data);
            return Ok(());
        }
        for &byte in data {
            if byte == b'\r' || byte == b'\n' {
                session.data(channel, b"\r\n".to_vec())?;
                let line = self.lines.get_mut(&channel).map(std::mem::take).unwrap_or_default();
                self.run_line(channel, &String::from_utf8_lossy(&line), session)?;
            } else {
                session.data(channel, vec![byte])?;
                self.lines.entry(channel).or_default().push(byte);
            }
        }
        Ok(())
    }
}

/// A word or an operator of a toy shell command line.
#[derive(Debug, PartialEq)]
enum Token {
    Word(String),
    /// `;` or a new line.
    Then,
    And,
    Or,
}

/// Splits a script into words and operators: single and double quotes, backslash escapes, `;`,
/// new lines, `&&` and `||`.
fn tokenize(script: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = script.chars().peekable();
    let end_word = |tokens: &mut Vec<Token>, word: &mut String, in_word: &mut bool| {
        if *in_word {
            tokens.push(Token::Word(std::mem::take(word)));
            *in_word = false;
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    word.push(q);
                }
            }
            '"' => {
                in_word = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' => {
                            if let Some(next) = chars.next() {
                                word.push(next);
                            }
                        }
                        _ => word.push(q),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            }
            ';' | '\n' => {
                end_word(&mut tokens, &mut word, &mut in_word);
                tokens.push(Token::Then);
            }
            '&' if chars.peek() == Some(&'&') => {
                chars.next();
                end_word(&mut tokens, &mut word, &mut in_word);
                tokens.push(Token::And);
            }
            '|' if chars.peek() == Some(&'|') => {
                chars.next();
                end_word(&mut tokens, &mut word, &mut in_word);
                tokens.push(Token::Or);
            }
            c if c.is_whitespace() => end_word(&mut tokens, &mut word, &mut in_word),
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    end_word(&mut tokens, &mut word, &mut in_word);
    tokens
}

/// Runs a script the way a small POSIX shell would, collecting stdout and stderr. `sleep` adds up
/// instead of blocking; the caller waits that long before it answers.
struct ToyShell<'a> {
    state: &'a State,
    user: String,
    stdin: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    sleep: Duration,
    exited: bool,
}

impl<'a> ToyShell<'a> {
    fn new(state: &'a State, user: &str, stdin: Vec<u8>) -> Self {
        Self {
            state,
            user: user.to_owned(),
            stdin,
            stdout: Vec::new(),
            stderr: Vec::new(),
            sleep: Duration::ZERO,
            exited: false,
        }
    }

    fn err(&mut self, text: &str) {
        self.stderr.extend_from_slice(text.as_bytes());
    }

    /// One line of stdin, without its line break. `None` at the end of stdin.
    fn read_line(&mut self) -> Option<String> {
        if self.stdin.is_empty() {
            return None;
        }
        let end = self.stdin.iter().position(|&b| b == b'\n');
        let line: Vec<u8> = match end {
            Some(at) => {
                let line = self.stdin[..at].to_vec();
                self.stdin.drain(..=at);
                line
            }
            None => std::mem::take(&mut self.stdin),
        };
        Some(String::from_utf8_lossy(&line).into_owned())
    }

    /// Runs a whole script; returns the status of the last command run.
    fn run(&mut self, script: &str) -> u32 {
        let mut status = 0;
        let mut words = Vec::new();
        let mut skip = false;
        let tokens = tokenize(script);
        let count = tokens.len();
        for (i, token) in tokens.into_iter().enumerate() {
            let op = match token {
                Token::Word(w) => {
                    words.push(w);
                    if i + 1 < count {
                        continue;
                    }
                    None
                }
                other => Some(other),
            };
            if !words.is_empty() && !skip {
                status = self.command(&std::mem::take(&mut words));
                if self.exited {
                    return status;
                }
            }
            words.clear();
            skip = match op {
                Some(Token::And) => status != 0,
                Some(Token::Or) => status == 0,
                _ => false,
            };
        }
        status
    }

    fn command(&mut self, words: &[String]) -> u32 {
        let mut words = words.to_vec();
        let to_stderr = words.last().is_some_and(|w| w == ">&2");
        if to_stderr {
            words.pop();
        }
        let before = self.stdout.len();
        let status = self.builtin(&words);
        if to_stderr {
            let printed = self.stdout.split_off(before);
            self.stderr.extend_from_slice(&printed);
        }
        status
    }

    fn builtin(&mut self, words: &[String]) -> u32 {
        let args = &words[1..];
        match words[0].as_str() {
            "echo" => {
                self.stdout
                    .extend_from_slice(format!("{}\n", args.join(" ")).as_bytes());
                0
            }
            "hostname" => {
                let name = locks::lock(&self.state.hostname)
                    .clone()
                    .unwrap_or_else(|| "test-host".into());
                self.stdout.extend_from_slice(format!("{name}\n").as_bytes());
                0
            }
            "whoami" => {
                self.stdout.extend_from_slice(format!("{}\n", self.user).as_bytes());
                0
            }
            "uptime" => {
                self.stdout
                    .extend_from_slice(b" 10:00:00 up 3 days,  2:01,  1 user,  load average: 0.00, 0.01, 0.05\n");
                0
            }
            "cat" if args.is_empty() => {
                let stdin = std::mem::take(&mut self.stdin);
                self.stdout.extend_from_slice(&stdin);
                0
            }
            "cat" => {
                let mut status = 0;
                for path in args {
                    let found = locks::lock(&self.state.files).get(path).cloned();
                    match found {
                        Some(text) => self.stdout.extend_from_slice(text.as_bytes()),
                        None => {
                            self.err(&format!("cat: {path}: No such file or directory\n"));
                            status = 1;
                        }
                    }
                }
                status
            }
            "seq" => {
                let n: u64 = args.first().and_then(|n| n.parse().ok()).unwrap_or(0);
                for i in 1..=n {
                    self.stdout.extend_from_slice(format!("{i}\n").as_bytes());
                }
                0
            }
            "sleep" => {
                let secs: f64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(0.0);
                self.sleep += Duration::from_secs_f64(secs.max(0.0));
                0
            }
            "exit" => {
                self.exited = true;
                args.first().and_then(|c| c.parse().ok()).unwrap_or(0)
            }
            "true" => 0,
            "false" => 1,
            "exec" if args.iter().any(|a| a == "</dev/null") => {
                self.stdin.clear();
                0
            }
            "sh" if args.first().is_some_and(|a| a == "-c") => {
                let script = args.get(1).cloned().unwrap_or_default();
                let status = self.run(&script);
                self.exited = false;
                status
            }
            "sudo" => self.sudo(args),
            other => {
                self.err(&format!("sh: 1: {other}: not found\n"));
                127
            }
        }
    }

    /// Like sudo: `-S` reads the password from stdin, `-p` sets the prompt (printed on stderr, with no
    /// line break after it), three tries, then the command as root. Logs whether it took the
    /// password, never the password.
    fn sudo(&mut self, args: &[String]) -> u32 {
        let mut i = 0;
        let mut from_stdin = false;
        let mut prompt = format!("[sudo] password for {}: ", self.user);
        while let Some(flag) = args.get(i).filter(|a| a.starts_with('-')) {
            match flag.as_str() {
                "-S" => from_stdin = true,
                "-p" => {
                    i += 1;
                    prompt = args.get(i).cloned().unwrap_or_default();
                }
                _ => {}
            }
            i += 1;
        }
        let command = &args[i..];
        if command.is_empty() {
            self.err("usage: sudo -h | -K | -k | -V\n");
            return 1;
        }
        let mode = locks::lock(&self.state.sudo).clone();
        let (password, echoes) = match mode {
            SudoMode::Missing => {
                self.err("sh: 1: sudo: not found\n");
                return 127;
            }
            SudoMode::NoPassword => (None, false),
            SudoMode::Password(p) => (Some(p), false),
            SudoMode::EchoesPassword(p) => (Some(p), true),
        };
        if let Some(password) = password {
            if !from_stdin {
                self.err("sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper\n");
                return 1;
            }
            let mut wrong = 0;
            loop {
                self.err(&prompt);
                let Some(typed) = self.read_line() else {
                    self.err("sudo: no password was provided\n");
                    if wrong > 0 {
                        self.err(&format!("sudo: {wrong} incorrect password attempt\n"));
                    }
                    self.state.note("sudo refused");
                    return 1;
                };
                if echoes {
                    self.stdout.extend_from_slice(format!("{typed}\n").as_bytes());
                }
                if typed == password {
                    self.state.note("sudo ok");
                    break;
                }
                wrong += 1;
                if wrong == 3 {
                    self.err("sudo: 3 incorrect password attempts\n");
                    self.state.note("sudo refused");
                    return 1;
                }
                self.err("Sorry, try again.\n");
            }
        }
        let user = std::mem::replace(&mut self.user, "root".into());
        let status = self.command(command);
        self.user = user;
        status
    }
}

/// An SSH agent on a named pipe holding `keys`, for the agent login test. Stops when the task is
/// aborted.
#[cfg(windows)]
pub async fn start_test_agent(pipe: &str, keys: &[PrivateKey]) -> JoinHandle<()> {
    use russh::keys::agent::client::AgentClient;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    let first = ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe)
        .unwrap_or_else(|err| panic!("can't create the agent pipe: {err}"));
    let name = pipe.to_owned();
    let listener = futures::stream::unfold(Some(first), move |server: Option<NamedPipeServer>| {
        let name = name.clone();
        async move {
            let server = server?;
            if server.connect().await.is_err() {
                return None;
            }
            let next = ServerOptions::new().create(&name).ok();
            Some((Ok::<_, std::io::Error>(server), next))
        }
    });
    let task = tokio::spawn(async move {
        let _ = russh::keys::agent::server::serve(Box::pin(listener), ()).await;
    });
    let mut client = AgentClient::connect_named_pipe(pipe)
        .await
        .unwrap_or_else(|err| panic!("can't reach the test agent: {err}"));
    for key in keys {
        client
            .add_identity(key, &[])
            .await
            .unwrap_or_else(|err| panic!("can't add a key to the test agent: {err}"));
    }
    task
}
