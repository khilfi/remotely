//! An SSH server on 127.0.0.1 for the terminal tests (SS-03, SS-05): russh's server with keys made at
//! run time, so no test connects to a real host and no key is ever committed.
//!
//! Every connection runs through a small relay the test controls: [`TestSshServer::drop_connections`]
//! cuts the TCP connections the way a network failure would (no SSH goodbye), and
//! [`TestSshServer::freeze_connections`] silently swallows their traffic, so only keep-alives can tell
//! the connection is dead. The shell is a toy that echoes what is typed and understands a few
//! commands (`exit [code]`, `whoami`, `split-utf8`, `echo <text>`, `sudo <command>` (asks for the
//! password without echoing it, as set by [`TestSshServer::with_sudo`]), `sleep <seconds>` (the prompt
//! comes back after that long), `work <seconds>` (prints a line every 100 ms that long, then stops
//! without a prompt), and for trying the app by hand, `drop-connection` and `change-host-key`). The server logs what clients ask for
//! (`pty xterm-256color 80x24`, `resize 120x40`, `shell`, `line whoami`, `exec uptime`) for tests to
//! check; it never logs what arrives on stdin.
//!
//! Exec channels (BX-02) run a toy POSIX shell ([`ToyShell`]): `;`, `&&`, `||` and new lines, quotes,
//! `#` comments, `$(...)`, `~`, the redirections `>`, `>>`, `>&2`, `2>&1` and `>/dev/null`, and `echo`,
//! `printf`, `hostname`, `whoami`, `uptime`, `cat` (files set with [`TestSshServer::with_file`], or
//! stdin), `head`, `tail`, `grep` (fixed strings), `[`/`test`, `seq`, `sleep`, `exit`, `true`, `false`,
//! `exec </dev/null`, `sh -c`, `command -v`, `cd`, and `sudo` (BX-07: `-S` reads the password from
//! stdin, `-p` sets the prompt, asked up to three times like the real one; see [`SudoMode`]). For
//! SS-09's key push it keeps a tiny file system: `umask`, `mkdir [-p]`, `touch` and `chmod` (octal),
//! with each file's and folder's mode ([`TestSshServer::file`], [`TestSshServer::mode`]).
//!
//! SS-08: an SFTP subsystem on a real temp folder ([`TestSshServer::sftp_root`], see [`sftp`]), and,
//! with [`TestSshServer::with_login_shell`], a login shell the shell probe calls bash or zsh: its
//! interactive shell then answers Remotely's prompt hook (prints the hook's marker, then OSC 7 and the
//! user report before each prompt) and knows `cd` and `pwd`. QL-09: `su [-] [user]` starts a shell as
//! that user (no password asked, root by default) with a `user@host:~$` prompt and no hook, as a real
//! switch would; `exit` goes back. [`TestSshServer::with_unreadable`] makes a folder SFTP can't open.
//!
//! SS-07: it forwards like OpenSSH with `AllowTcpForwarding yes`. A direct-tcpip channel (a jump
//! host's hop, a local or SOCKS forward) connects from here to where it asks; names set with
//! [`TestSshServer::with_route`] lead to another port on 127.0.0.1, so a second server is reachable
//! "only through this one" by a name this PC can't resolve (`db01.test`). tcpip-forward (a remote
//! forward) listens on 127.0.0.1 and sends each connection back over the client's connection.
//! [`TestSshServer::without_forwarding`] refuses both. The log says what was asked
//! (`direct-tcpip db01.test:22`, `tcpip-forward localhost:9000`), never what went through.

mod sftp;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
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
    /// Folders made by `mkdir` or `with_dir` (system folders, homes and folders holding a file exist anyway).
    dirs: Mutex<HashSet<String>>,
    /// Modes of files and folders the toy shell created or `chmod` set (`with_mode` too).
    modes: Mutex<HashMap<String, u32>>,
    /// Programs that print a fixed text (`with_program`).
    programs: Mutex<HashMap<String, String>>,
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
    /// SS-08: the folder SFTP serves, made when the server starts.
    sftp_root: Mutex<Option<PathBuf>>,
    /// SS-08: host folders SFTP refuses to write into.
    sftp_protected: Mutex<Vec<String>>,
    /// QL-09: host folders SFTP refuses to open, with everything in them.
    sftp_unreadable: Mutex<Vec<String>>,
    /// SS-08: each SFTP read and write waits this long.
    sftp_delay: Mutex<Option<Duration>>,
    /// SS-08: no SFTP subsystem, like a host without sftp-server.
    sftp_off: AtomicBool,
    /// SS-08: what the shell probe says the login shell is.
    login_shell: Mutex<Option<String>>,
    /// SS-07: names that lead to a port on 127.0.0.1 (lower case), as an internal DNS would.
    routes: Mutex<HashMap<String, u16>>,
    /// SS-07: refuse direct-tcpip and tcpip-forward, like `AllowTcpForwarding no`.
    no_forwarding: AtomicBool,
    /// SS-07: remote forwards listening, by (address, port), with the connection that asked.
    listeners: Mutex<HashMap<(String, u32), (usize, tokio::task::AbortHandle)>>,
}

struct Link {
    /// Which connection (counted from 1).
    id: usize,
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
        // Their remote forwards' listeners went with them.
        locks::lock(&self.listeners).clear();
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
        let root = std::env::temp_dir().join(format!("remotely-sftp-{}", uuid::Uuid::new_v4().simple()));
        for dir in sftp::SFTP_DIRS {
            let _ = std::fs::create_dir_all(sftp::local(&root, dir));
        }
        *locks::lock(&state.sftp_root) = Some(root);
        *locks::lock(&state.sftp_protected) = vec!["/etc".into(), "/root".into(), "/usr".into()];
        let accept = tokio::spawn(accept_loop(listener, Arc::clone(&state)));
        Self { port, state, accept }
    }

    /// SS-08: the folder on this PC that SFTP serves as `/`.
    pub fn sftp_root(&self) -> PathBuf {
        locks::lock(&self.state.sftp_root).clone().unwrap_or_default()
    }

    /// SS-08: where a host path is on this PC.
    pub fn sftp_path(&self, path: &str) -> PathBuf {
        sftp::local(&self.sftp_root(), path)
    }

    /// SS-08: a file SFTP serves (its folders are made too).
    pub fn with_sftp_file(self, path: &str, content: &[u8]) -> Self {
        let local = self.sftp_path(path);
        if let Some(folder) = local.parent() {
            let _ = std::fs::create_dir_all(folder);
        }
        std::fs::write(&local, content).unwrap_or_else(|err| panic!("can't write {}: {err}", local.display()));
        self
    }

    /// SS-08: an empty folder SFTP serves.
    pub fn with_sftp_dir(self, path: &str) -> Self {
        let _ = std::fs::create_dir_all(self.sftp_path(path));
        self
    }

    /// SS-08: a file as SFTP left it.
    pub fn sftp_file(&self, path: &str) -> Option<Vec<u8>> {
        std::fs::read(self.sftp_path(path)).ok()
    }

    /// SS-08: SFTP refuses to write into this folder (and below), like one the user may not write to.
    pub fn with_protected(self, folder: &str) -> Self {
        locks::lock(&self.state.sftp_protected).push(folder.into());
        self
    }

    /// QL-09: SFTP refuses to open this folder and anything in it, like a folder of another user's that
    /// the login user may not read (`drwx------ bob`). The toy shell can still `cd` into it, the way a
    /// shell switched to that user could.
    pub fn with_unreadable(self, folder: &str) -> Self {
        let _ = std::fs::create_dir_all(self.sftp_path(folder));
        locks::lock(&self.state.sftp_unreadable).push(folder.into());
        self
    }

    /// SS-08: each SFTP read and write waits this long, so a transfer takes a while.
    pub fn with_sftp_delay(self, delay: Duration) -> Self {
        *locks::lock(&self.state.sftp_delay) = Some(delay);
        self
    }

    /// SS-08: a host without an SFTP server.
    pub fn without_sftp(self) -> Self {
        self.state.sftp_off.store(true, Ordering::SeqCst);
        self
    }

    /// SS-08: the shell probe calls the login shell this (`bash`, `zsh`); its interactive shell answers
    /// Remotely's prompt hook and reports its folder with OSC 7 from then on.
    pub fn with_login_shell(self, shell: &str) -> Self {
        *locks::lock(&self.state.login_shell) = Some(shell.into());
        self
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// SS-07: a direct-tcpip channel to `name` (any port) connects to 127.0.0.1:`port`, like a name
    /// only this host's network resolves. A jump host's next hop is usually such a name.
    pub fn with_route(self, name: &str, port: u16) -> Self {
        self.set_route(name, port);
        self
    }

    /// [`TestSshServer::with_route`] while the server runs.
    pub fn set_route(&self, name: &str, port: u16) {
        locks::lock(&self.state.routes).insert(name.to_lowercase(), port);
    }

    /// SS-07: refuses port forwarding and jump host channels, like `AllowTcpForwarding no`.
    pub fn without_forwarding(self) -> Self {
        self.state.no_forwarding.store(true, Ordering::SeqCst);
        self
    }

    /// SS-07: the ports remote forwards listen on now.
    pub fn forwarded_ports(&self) -> Vec<u32> {
        let mut ports: Vec<u32> = locks::lock(&self.state.listeners).keys().map(|(_, p)| *p).collect();
        ports.sort_unstable();
        ports
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

    /// A file `cat` and `head` can read.
    pub fn with_file(self, path: &str, contents: &str) -> Self {
        self.set_file(path, contents);
        self
    }

    /// Adds or replaces a file while the server runs (MO-02: counters that move between rounds).
    pub fn set_file(&self, path: &str, contents: &str) {
        locks::lock(&self.state.files).insert(path.into(), contents.into());
    }

    /// An empty folder.
    pub fn with_dir(self, path: &str) -> Self {
        locks::lock(&self.state.dirs).insert(path.into());
        self
    }

    /// The mode of a file or folder, e.g. 0o664 for a file others may write (SS-09 tests).
    pub fn with_mode(self, path: &str, mode: u32) -> Self {
        locks::lock(&self.state.modes).insert(path.into(), mode);
        self
    }

    /// A file's text as the toy shell left it (`~` is `/home/<user>`).
    pub fn file(&self, path: &str) -> Option<String> {
        locks::lock(&self.state.files).get(path).cloned()
    }

    /// A file's or folder's mode, once created by the toy shell or set by `chmod` or `with_mode`.
    pub fn mode(&self, path: &str) -> Option<u32> {
        locks::lock(&self.state.modes).get(path).copied()
    }

    /// A program that prints `stdout` whatever its arguments, e.g. `df`.
    pub fn with_program(self, name: &str, stdout: &str) -> Self {
        locks::lock(&self.state.programs).insert(name.into(), stdout.into());
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
        for (_, (_, listener)) in locks::lock(&self.state.listeners).drain() {
            listener.abort();
        }
        if let Some(root) = locks::lock(&self.state.sftp_root).take() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

async fn accept_loop(listener: TcpListener, state: Arc<State>) {
    while let Ok((socket, _)) = listener.accept().await {
        let link = state.connections.fetch_add(1, Ordering::SeqCst) + 1;
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
            link,
            user: String::new(),
            first_factor: false,
            asking: HashMap::new(),
            full_screen: HashMap::new(),
            lines: HashMap::new(),
            execs: HashMap::new(),
            unclaimed: HashMap::new(),
            sftp: HashSet::new(),
            forwarded: HashSet::new(),
            folders: HashMap::new(),
            hooked: HashSet::new(),
            switched: HashMap::new(),
        };
        let session = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, server_end, handler).await {
                    let _ = running.await;
                }
                // SS-07: like sshd, its remote forwards stop listening with the connection.
                locks::lock(&state.listeners).retain(|_, (by, listener)| {
                    if *by == link {
                        listener.abort();
                    }
                    *by != link
                });
            })
        };
        let (freeze, frozen) = watch::channel(false);
        let (socket_read, socket_write) = socket.into_split();
        let (relay_read, relay_write) = tokio::io::split(relay_end);
        let up = tokio::spawn(relay(socket_read, relay_write, frozen.clone()));
        let down = tokio::spawn(relay(relay_read, socket_write, frozen));
        locks::lock(&state.links).push(Link {
            id: link,
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

/// A user's home folder on the toy host.
fn home_of(user: &str) -> String {
    if user == "root" {
        "/root".to_owned()
    } else {
        format!("/home/{user}")
    }
}

struct ServerHandler {
    state: Arc<State>,
    /// SS-07: this connection's [`Link`], so what it forwards is cut with it.
    link: usize,
    user: String,
    /// The password or key was accepted; a one-time code may still be due.
    first_factor: bool,
    lines: HashMap<ChannelId, Vec<u8>>,
    /// Exec channels: the command, and stdin until the client ends it.
    execs: HashMap<ChannelId, (String, Vec<u8>)>,
    /// Shell channels where `sudo` waits for its password: what was typed so far (not echoed), and
    /// the tries left.
    asking: HashMap<ChannelId, (Vec<u8>, u8)>,
    /// SS-10: shell channels where the full-screen `top` runs, and the keys it got so far.
    full_screen: HashMap<ChannelId, Vec<u8>>,
    /// SS-08: channels opened but not asked for anything yet; the one asking for SFTP takes its own.
    /// Dropped at the first other request, so their data is never queued unread.
    unclaimed: HashMap<ChannelId, Channel<Msg>>,
    /// SS-08: channels running SFTP: their data is not shell input.
    sftp: HashSet<ChannelId>,
    /// SS-07: direct-tcpip channels: their data is relayed, not shell input.
    forwarded: HashSet<ChannelId>,
    /// SS-08: each interactive shell's folder (`cd`).
    folders: HashMap<ChannelId, String>,
    /// SS-08: shells that ran Remotely's prompt hook, and so print OSC 7 before each prompt.
    hooked: HashSet<ChannelId>,
    /// QL-09: shells started with `su` in each interactive shell, innermost last: the user and its
    /// folder. They have no hook.
    switched: HashMap<ChannelId, Vec<(String, String)>>,
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

    fn home(&self) -> String {
        home_of(&self.user)
    }

    /// SS-08: the interactive shell's folder (QL-09: the switched shell's, after `su`).
    fn folder(&self, channel: ChannelId) -> String {
        if let Some((_, folder)) = self.switched.get(&channel).and_then(|s| s.last()) {
            return folder.clone();
        }
        self.folders.get(&channel).cloned().unwrap_or_else(|| self.home())
    }

    /// QL-09: who the interactive shell runs as.
    fn shell_user(&self, channel: ChannelId) -> String {
        match self.switched.get(&channel).and_then(|s| s.last()) {
            Some((user, _)) => user.clone(),
            None => self.user.clone(),
        }
    }

    fn host_name(&self) -> String {
        locks::lock(&self.state.hostname)
            .clone()
            .unwrap_or_else(|| "test-host".into())
    }

    /// The prompt: `$ `, after OSC 7 with the folder and the user report once the prompt hook ran
    /// (SS-08, QL-09). A shell started with `su` shows `bob@host:~$ ` (`#` for root) and no hook.
    fn prompt(&self, channel: ChannelId) -> Vec<u8> {
        if let Some((user, folder)) = self.switched.get(&channel).and_then(|s| s.last()) {
            let home = home_of(user);
            let shown = match folder.strip_prefix(&home) {
                Some(rest) if rest.is_empty() || rest.starts_with('/') => format!("~{rest}"),
                _ => folder.clone(),
            };
            let sign = if user == "root" { '#' } else { '$' };
            return format!("{user}@{}:{shown}{sign} ", self.host_name()).into_bytes();
        }
        if !self.hooked.contains(&channel) {
            return b"$ ".to_vec();
        }
        let path = self.folder(channel).replace('%', "%25");
        let user = self.user.replace('%', "%25");
        format!(
            "\x1b]7;file://{}{path}\x1b\\\x1b]7777;remotely-user={user}\x07$ ",
            self.host_name()
        )
        .into_bytes()
    }

    fn run_line(&mut self, channel: ChannelId, line: &str, session: &mut Session) -> Result<(), russh::Error> {
        let hook = line.trim_start().starts_with("__remotely_cwd()");
        // The hook is logged by name only: a test checks it never shows, not what it says.
        self.state.note(if hook {
            "line [prompt hook]".to_owned()
        } else {
            format!("line {line}")
        });
        let mut words = line.split_whitespace();
        match words.next() {
            // SS-08: Remotely's prompt hook, in a shell the probe called bash or zsh: it prints its
            // marker, and OSC 7 comes before each prompt from now on.
            Some(_) if hook && locks::lock(&self.state.login_shell).is_some() => {
                let token = line.split_whitespace().last().unwrap_or_default();
                session.data(channel, format!("\x1b]7777;remotely-{token}\x07").into_bytes())?;
                self.hooked.insert(channel);
            }
            Some("cd") => {
                let home = home_of(&self.shell_user(channel));
                let to = crate::terminal::files::resolve(&self.folder(channel), &home, words.next().unwrap_or("~"));
                let root = locks::lock(&self.state.sftp_root).clone().unwrap_or_default();
                if sftp::local(&root, &to).is_dir() {
                    match self.switched.get_mut(&channel).and_then(|s| s.last_mut()) {
                        Some((_, folder)) => *folder = to,
                        None => {
                            self.folders.insert(channel, to);
                        }
                    }
                } else {
                    session.data(channel, format!("cd: no such file or directory: {to}\r\n").into_bytes())?;
                }
            }
            Some("pwd") => session.data(channel, format!("{}\r\n", self.folder(channel)).into_bytes())?,
            // QL-09: a shell as another user, without the hook; `-` starts it in that user's home.
            Some("su") => {
                let mut login = false;
                let mut user = "root".to_owned();
                for word in words {
                    match word {
                        "-" | "-l" | "--login" => login = true,
                        other => user = other.to_owned(),
                    }
                }
                let folder = if login { home_of(&user) } else { self.folder(channel) };
                self.switched.entry(channel).or_default().push((user, folder));
            }
            Some("exit") if self.switched.get(&channel).is_some_and(|s| !s.is_empty()) => {
                if let Some(shells) = self.switched.get_mut(&channel) {
                    shells.pop();
                }
                session.data(channel, b"logout\r\n".to_vec())?;
            }
            Some("exit") => {
                let code = words.next().and_then(|c| c.parse().ok()).unwrap_or(0);
                session.data(channel, b"logout\r\n".to_vec())?;
                session.exit_status_request(channel, code)?;
                session.eof(channel)?;
                session.close(channel)?;
                return Ok(());
            }
            Some("whoami") => session.data(channel, format!("{}\r\n", self.shell_user(channel)).into_bytes())?,
            // "é" sent as two packets, split inside the character.
            Some("split-utf8") => {
                session.data(channel, vec![0xC3])?;
                session.data(channel, vec![0xA9, b'\r', b'\n'])?;
            }
            Some("echo") => {
                let rest: Vec<&str> = words.collect();
                session.data(channel, format!("{}\r\n", rest.join(" ")).into_bytes())?;
            }
            // QL-06: like sudo at a terminal, the password is not echoed.
            Some("sudo") => {
                let mode = locks::lock(&self.state.sudo).clone();
                match mode {
                    SudoMode::Missing => session.data(channel, b"sudo: command not found\r\n".to_vec())?,
                    SudoMode::NoPassword => session.data(channel, b"ok\r\n".to_vec())?,
                    SudoMode::Password(_) | SudoMode::EchoesPassword(_) => {
                        self.asking.insert(channel, (Vec::new(), 3));
                        return session.data(channel, format!("[sudo] password for {}: ", self.user).into_bytes());
                    }
                }
            }
            // QL-07: a long command; the prompt comes back when it is done.
            Some("sleep") => {
                let secs: f64 = words.next().and_then(|w| w.parse().ok()).unwrap_or(1.0);
                let handle = session.handle();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs_f64(secs.max(0.0))).await;
                    let _ = handle.data(channel, b"$ ".to_vec()).await;
                });
                return Ok(());
            }
            // QL-07: output for a while, then silence and no prompt.
            Some("work") => {
                let secs: f64 = words.next().and_then(|w| w.parse().ok()).unwrap_or(1.0);
                let handle = session.handle();
                tokio::spawn(async move {
                    let until = std::time::Instant::now() + Duration::from_secs_f64(secs.max(0.0));
                    let mut step = 1;
                    while std::time::Instant::now() < until {
                        let _ = handle.data(channel, format!("step {step}\r\n").into_bytes()).await;
                        step += 1;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    let _ = handle.data(channel, b"done, waiting\r\n".to_vec()).await;
                });
                return Ok(());
            }
            // SS-10: a full-screen program on the alternate screen; `q` quits it (see `data`).
            Some("top") => {
                self.full_screen.insert(channel, Vec::new());
                return session.data(
                    channel,
                    b"\x1b[?1049h\x1b[H\x1b[2Jtop - 10:00:00 up 3 days, 1 user\r\nTasks: 99 total\r\n".to_vec(),
                );
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
        session.data(channel, self.prompt(channel))?;
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
        // Keys set with `with_key`, and (SS-09) keys a push wrote to the user's authorized_keys.
        let home = if user == "root" {
            "/root".to_owned()
        } else {
            format!("/home/{user}")
        };
        let authorized = locks::lock(&self.state.files)
            .get(&format!("{home}/.ssh/authorized_keys"))
            .is_some_and(|text| {
                text.lines()
                    .filter_map(|line| PublicKey::from_openssh(line.trim()).ok())
                    .any(|k| k.key_data() == key.key_data())
            });
        let ok = authorized
            || locks::lock(&self.state.keys)
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
        self.unclaimed.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    /// SS-08: SFTP on its own channel, served from the temp folder.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.note(format!("subsystem {name}"));
        let stream = self.unclaimed.remove(&channel);
        let root = locks::lock(&self.state.sftp_root).clone();
        match (name, stream, root) {
            ("sftp", Some(stream), Some(root)) if !self.state.sftp_off.load(Ordering::SeqCst) => {
                self.sftp.insert(channel);
                session.channel_success(channel)?;
                let server = sftp::SftpServer::new(Arc::clone(&self.state), root, &self.user);
                russh_sftp::server::run(stream.into_stream(), server).await;
                Ok(())
            }
            _ => session.channel_failure(channel),
        }
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
        self.unclaimed.remove(&channel);
        self.state.note(format!("pty {term} {cols}x{rows}"));
        session.channel_success(channel)
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.unclaimed.remove(&channel);
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
        self.unclaimed.remove(&channel);
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
                // SS-08: the shell probe beside each new terminal names the login shell, if one is set.
                let login = locks::lock(&state.login_shell).clone();
                let status = match login {
                    Some(name) if command == crate::adapters::remote::SHELL_PROBE => {
                        shell.print(&format!("{name}\n"));
                        0
                    }
                    _ => shell.run(&command),
                };
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

    /// SS-07: a jump host's next hop, or a local or SOCKS forward: connects from here, through a
    /// route if the name has one.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state
            .note(format!("direct-tcpip {host_to_connect}:{port_to_connect}"));
        if self.state.no_forwarding.load(Ordering::SeqCst) {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        }
        let routed = locks::lock(&self.state.routes)
            .get(&host_to_connect.to_lowercase())
            .copied();
        let target = match (routed, u16::try_from(port_to_connect)) {
            (Some(port), _) => ("127.0.0.1".to_owned(), port),
            (None, Ok(port)) => (host_to_connect.to_owned(), port),
            (None, Err(_)) => {
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };
        let connected = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(target)).await;
        let Ok(Ok(mut socket)) = connected else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        self.forwarded.insert(channel.id());
        reply.accept().await;
        let task = tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut socket).await;
        });
        // Cut with the connection it rides on, like a network failure would.
        if let Some(link) = locks::lock(&self.state.links).iter_mut().find(|l| l.id == self.link) {
            link.tasks.push(task);
        }
        Ok(())
    }

    /// SS-07: a remote forward: listens on 127.0.0.1 and sends each connection back over this
    /// connection.
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.state.note(format!("tcpip-forward {address}:{port}"));
        if self.state.no_forwarding.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let Ok(asked) = u16::try_from(*port) else {
            return Ok(false);
        };
        // Tests never listen beyond this PC, whatever address is asked for.
        let Ok(listener) = TcpListener::bind(("127.0.0.1", asked)).await else {
            return Ok(false);
        };
        let bound = listener.local_addr().map(|a| u32::from(a.port())).unwrap_or(*port);
        *port = bound;
        let handle = session.handle();
        let connected_address = address.to_owned();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, from)) = listener.accept().await {
                let handle = handle.clone();
                let connected_address = connected_address.clone();
                tokio::spawn(async move {
                    let opened = handle
                        .channel_open_forwarded_tcpip(
                            connected_address,
                            bound,
                            from.ip().to_string(),
                            u32::from(from.port()),
                        )
                        .await;
                    if let Ok(channel) = opened {
                        let mut stream = channel.into_stream();
                        let _ = tokio::io::copy_bidirectional(&mut stream, &mut socket).await;
                    }
                });
            }
        });
        locks::lock(&self.state.listeners).insert((address.to_owned(), bound), (self.link, task.abort_handle()));
        if let Some(link) = locks::lock(&self.state.links).iter_mut().find(|l| l.id == self.link) {
            link.tasks.push(task);
        }
        Ok(true)
    }

    async fn cancel_tcpip_forward(&mut self, address: &str, port: u32, _: &mut Session) -> Result<bool, Self::Error> {
        self.state.note(format!("cancel-tcpip-forward {address}:{port}"));
        match locks::lock(&self.state.listeners).remove(&(address.to_owned(), port)) {
            Some((_, listener)) => {
                listener.abort();
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn channel_close(&mut self, channel: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        self.unclaimed.remove(&channel);
        self.sftp.remove(&channel);
        self.forwarded.remove(&channel);
        self.folders.remove(&channel);
        self.hooked.remove(&channel);
        self.switched.remove(&channel);
        Ok(())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        // SS-08: SFTP reads its own channel; SS-07: so does a forwarded connection's relay.
        if self.sftp.contains(&channel) || self.forwarded.contains(&channel) {
            return Ok(());
        }
        if let Some((_, stdin)) = self.execs.get_mut(&channel) {
            stdin.extend_from_slice(data);
            return Ok(());
        }
        for &byte in data {
            if self.asking.contains_key(&channel) {
                self.sudo_byte(channel, byte, session)?;
            } else if let Some(keys) = self.full_screen.get_mut(&channel) {
                // `top` reads keys, not lines; `q` quits and leaves the alternate screen.
                if byte == b'q' {
                    let keys = String::from_utf8_lossy(&std::mem::take(keys)).into_owned();
                    self.full_screen.remove(&channel);
                    self.state.note(format!("top keys {keys:?}"));
                    session.data(channel, b"\x1b[?1049l$ ".to_vec())?;
                } else {
                    keys.push(byte);
                }
            } else if byte == b'\r' || byte == b'\n' {
                session.data(channel, b"\r\n".to_vec())?;
                let line = self.lines.get_mut(&channel).map(std::mem::take).unwrap_or_default();
                self.run_line(channel, &String::from_utf8_lossy(&line), session)?;
            } else if byte == 0x03 {
                // Ctrl+C drops the line, like a shell.
                let dropped = self.lines.get_mut(&channel).map(std::mem::take).unwrap_or_default();
                self.state
                    .note(format!("interrupt {}", String::from_utf8_lossy(&dropped)));
                session.data(channel, b"^C\r\n$ ".to_vec())?;
            } else if byte == 0x7f || byte == 0x08 {
                if self.lines.entry(channel).or_default().pop().is_some() {
                    session.data(channel, b"\x08 \x08".to_vec())?;
                }
            } else {
                session.data(channel, vec![byte])?;
                self.lines.entry(channel).or_default().push(byte);
            }
        }
        Ok(())
    }
}

impl ServerHandler {
    /// A byte typed at the interactive `sudo` password prompt: kept, not echoed, until Enter. The log
    /// says whether it was right, never what it was.
    fn sudo_byte(&mut self, channel: ChannelId, byte: u8, session: &mut Session) -> Result<(), russh::Error> {
        let Some((typed, tries)) = self.asking.get_mut(&channel) else {
            return Ok(());
        };
        if byte == 0x03 {
            // Ctrl+C at the prompt: sudo gives up.
            typed.clear();
            self.asking.remove(&channel);
            return session.data(channel, b"^C\r\n$ ".to_vec());
        }
        if byte != b'\r' && byte != b'\n' {
            typed.push(byte);
            return Ok(());
        }
        let answer = String::from_utf8_lossy(&std::mem::take(typed)).into_owned();
        *tries -= 1;
        let tries_left = *tries;
        let mode = locks::lock(&self.state.sudo).clone();
        let (right, echo) = match &mode {
            SudoMode::Password(p) => (*p == answer, false),
            SudoMode::EchoesPassword(p) => (*p == answer, true),
            _ => (false, false),
        };
        session.data(channel, b"\r\n".to_vec())?;
        self.state
            .note(format!("sudo {} {}", self.user, if right { "ok" } else { "refused" }));
        if right {
            self.asking.remove(&channel);
            let reply = if echo {
                format!("ok {answer}\r\n$ ")
            } else {
                "ok\r\n$ ".to_owned()
            };
            return session.data(channel, reply.into_bytes());
        }
        if tries_left == 0 {
            self.asking.remove(&channel);
            return session.data(channel, b"sudo: 3 incorrect password attempts\r\n$ ".to_vec());
        }
        session.data(
            channel,
            format!("Sorry, try again.\r\n[sudo] password for {}: ", self.user).into_bytes(),
        )
    }
}

/// A piece of a toy shell word.
#[derive(Debug, Clone, PartialEq)]
enum Part {
    Text(String),
    /// `~` at the start of a word: the user's home folder.
    Home,
    /// `$(...)`: replaced by what the inner script prints, without its trailing line breaks.
    Output(String),
}

/// A word or an operator of a toy shell command line.
#[derive(Debug, PartialEq)]
enum Token {
    Word(Vec<Part>),
    /// `;` or a new line.
    Then,
    And,
    Or,
}

/// Collects the parts of the word being read.
#[derive(Default)]
struct WordBuilder {
    parts: Vec<Part>,
    text: String,
    started: bool,
}

impl WordBuilder {
    fn push(&mut self, c: char) {
        self.started = true;
        self.text.push(c);
    }

    fn part(&mut self, part: Part) {
        self.started = true;
        if !self.text.is_empty() {
            self.parts.push(Part::Text(std::mem::take(&mut self.text)));
        }
        self.parts.push(part);
    }

    fn finish(&mut self, tokens: &mut Vec<Token>) {
        if self.started {
            if !self.text.is_empty() {
                self.parts.push(Part::Text(std::mem::take(&mut self.text)));
            }
            tokens.push(Token::Word(std::mem::take(&mut self.parts)));
            self.started = false;
        }
    }
}

/// The script inside `$(...)`, after the `$(` was read: up to the matching `)`.
fn read_substitution(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut inner = String::new();
    let mut depth = 1;
    let mut quote: Option<char> = None;
    for c in chars.by_ref() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '(') => depth += 1,
            (None, ')') => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        inner.push(c);
    }
    inner
}

/// Splits a script into words and operators: single and double quotes, backslash escapes, `$(...)`,
/// `~` at the start of a word, `#` comments, `;`, new lines, `&&` and `||`.
fn tokenize(script: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut word = WordBuilder::default();
    let mut chars = script.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                word.started = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    word.push(q);
                }
            }
            '"' => {
                word.started = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' => {
                            if let Some(next) = chars.next() {
                                word.push(next);
                            }
                        }
                        '$' if chars.peek() == Some(&'(') => {
                            chars.next();
                            let inner = read_substitution(&mut chars);
                            word.part(Part::Output(inner));
                        }
                        _ => word.push(q),
                    }
                }
            }
            '\\' => {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            }
            '$' if chars.peek() == Some(&'(') => {
                chars.next();
                let inner = read_substitution(&mut chars);
                word.part(Part::Output(inner));
            }
            '#' if !word.started => {
                while chars.peek().is_some_and(|&n| n != '\n') {
                    chars.next();
                }
            }
            '~' if !word.started && chars.peek().is_none_or(|&n| n == '/' || n.is_whitespace()) => {
                word.part(Part::Home);
            }
            ';' | '\n' => {
                word.finish(&mut tokens);
                tokens.push(Token::Then);
            }
            '&' if chars.peek() == Some(&'&') => {
                chars.next();
                word.finish(&mut tokens);
                tokens.push(Token::And);
            }
            '|' if chars.peek() == Some(&'|') => {
                chars.next();
                word.finish(&mut tokens);
                tokens.push(Token::Or);
            }
            c if c.is_whitespace() => word.finish(&mut tokens),
            c => word.push(c),
        }
    }
    word.finish(&mut tokens);
    tokens
}

/// Folders every toy host has.
const SYSTEM_DIRS: [&str; 6] = ["/", "/home", "/root", "/tmp", "/etc", "/proc"];

/// What `command -v` finds besides the fake programs.
const BUILTINS: [&str; 25] = [
    "echo", "hostname", "whoami", "uptime", "cat", "head", "seq", "sleep", "exit", "true", "false", "exec", "sh",
    "sudo", "umask", "cd", "mkdir", "chmod", "touch", "grep", "tail", "[", "test", "printf", "command",
];

/// Where a command's output goes (`>`, `>>`, `2>&1`, `>/dev/null`, ...).
#[derive(Debug, Clone)]
enum Sink {
    Stdout,
    Stderr,
    Null,
    File { path: String, append: bool },
}

/// `/a/b` for `/a/b/c`; `/` for `/a`.
fn parent_of(path: &str) -> String {
    match path.rsplit_once('/') {
        Some(("", _)) | None => "/".to_owned(),
        Some((parent, _)) => parent.to_owned(),
    }
}

/// Runs a script the way a small POSIX shell would, collecting stdout and stderr. `sleep` adds up
/// instead of blocking; the caller waits that long before it answers. Files live in the server's
/// state (paths as given, `~` is `/home/<user>` or `/root`), with their modes once set or created.
struct ToyShell<'a> {
    state: &'a State,
    user: String,
    stdin: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    sleep: Duration,
    exited: bool,
    umask: u32,
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
            umask: 0o022,
        }
    }

    fn err(&mut self, text: &str) {
        self.stderr.extend_from_slice(text.as_bytes());
    }

    fn print(&mut self, text: &str) {
        self.stdout.extend_from_slice(text.as_bytes());
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

    fn home(&self) -> String {
        home_of(&self.user)
    }

    /// An absolute path: relative ones start in the home folder, where SSH commands start.
    fn path(&self, p: &str) -> String {
        let full = if p.starts_with('/') {
            p.to_owned()
        } else {
            format!("{}/{p}", self.home())
        };
        let trimmed = full.trim_end_matches('/');
        if trimmed.is_empty() {
            "/".to_owned()
        } else {
            trimmed.to_owned()
        }
    }

    fn is_dir(&self, path: &str) -> bool {
        let below = format!("{path}/");
        SYSTEM_DIRS.contains(&path)
            || path == self.home()
            || locks::lock(&self.state.dirs).contains(path)
            || locks::lock(&self.state.files).keys().any(|f| f.starts_with(&below))
    }

    /// A file's text, looked up by its absolute path, then as given (files set by tests).
    fn read_file(&self, p: &str) -> Option<String> {
        let files = locks::lock(&self.state.files);
        files.get(&self.path(p)).or_else(|| files.get(p)).cloned()
    }

    /// Writes or appends to a file, creating it (mode 0666 less the umask) in an existing folder.
    fn write_file(&mut self, p: &str, text: &str, append: bool) -> Result<(), &'static str> {
        let path = self.path(p);
        if self.is_dir(&path) {
            return Err("Is a directory");
        }
        let mut files = locks::lock(&self.state.files);
        if !files.contains_key(&path) {
            drop(files);
            if !self.is_dir(&parent_of(&path)) {
                return Err("Directory nonexistent");
            }
            locks::lock(&self.state.modes).insert(path.clone(), 0o666 & !self.umask);
            files = locks::lock(&self.state.files);
        }
        let file = files.entry(path).or_default();
        if !append {
            file.clear();
        }
        file.push_str(text);
        Ok(())
    }

    fn make_dir(&self, path: &str) {
        locks::lock(&self.state.dirs).insert(path.to_owned());
        locks::lock(&self.state.modes).insert(path.to_owned(), 0o777 & !self.umask);
    }

    fn expand(&mut self, parts: &[Part]) -> String {
        let mut word = String::new();
        for part in parts {
            match part {
                Part::Text(text) => word.push_str(text),
                Part::Home => word.push_str(&self.home()),
                Part::Output(script) => {
                    let saved = std::mem::take(&mut self.stdout);
                    let exited = self.exited;
                    self.run(script);
                    self.exited = exited;
                    let printed = std::mem::replace(&mut self.stdout, saved);
                    word.push_str(String::from_utf8_lossy(&printed).trim_end_matches('\n'));
                }
            }
        }
        word
    }

    /// Runs a whole script; returns the status of the last command run.
    fn run(&mut self, script: &str) -> u32 {
        let mut status = 0;
        let mut words: Vec<Vec<Part>> = Vec::new();
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
                let expanded: Vec<String> = std::mem::take(&mut words).iter().map(|w| self.expand(w)).collect();
                status = self.command(&expanded);
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

    /// One command with its redirections: `>`, `>>`, `2>`, `>&2`, `2>&1`, `>/dev/null`.
    fn command(&mut self, words: &[String]) -> u32 {
        let mut args = Vec::new();
        let mut out = Sink::Stdout;
        let mut errs = Sink::Stderr;
        let mut i = 0;
        while i < words.len() {
            let w = words[i].as_str();
            let (fd, target) = match w {
                ">&2" | "1>&2" => {
                    out = errs.clone();
                    i += 1;
                    continue;
                }
                "2>&1" => {
                    errs = out.clone();
                    i += 1;
                    continue;
                }
                ">" | ">>" | "2>" | "2>>" => {
                    i += 1;
                    match words.get(i) {
                        Some(target) => (w, target.as_str()),
                        None => {
                            self.err("sh: 1: Syntax error: newline unexpected\n");
                            return 2;
                        }
                    }
                }
                _ if w.starts_with("2>>") => ("2>>", &w[3..]),
                _ if w.starts_with("2>") => ("2>", &w[2..]),
                _ if w.starts_with(">>") => (">>", &w[2..]),
                _ if w.starts_with('>') => (">", &w[1..]),
                _ => {
                    args.push(w.to_owned());
                    i += 1;
                    continue;
                }
            };
            let sink = if target == "/dev/null" {
                Sink::Null
            } else {
                Sink::File {
                    path: target.to_owned(),
                    append: fd.ends_with(">>"),
                }
            };
            if fd.starts_with('2') {
                errs = sink;
            } else {
                out = sink;
            }
            i += 1;
        }
        if args.is_empty() {
            return 0;
        }
        let (out_before, err_before) = (self.stdout.len(), self.stderr.len());
        let mut status = self.builtin(&args);
        let printed = [
            (self.stdout.split_off(out_before), out),
            (self.stderr.split_off(err_before), errs),
        ];
        for (bytes, sink) in printed {
            match sink {
                Sink::Stdout => self.stdout.extend_from_slice(&bytes),
                Sink::Stderr => self.stderr.extend_from_slice(&bytes),
                Sink::Null => {}
                Sink::File { path, append } => {
                    if let Err(why) = self.write_file(&path, &String::from_utf8_lossy(&bytes), append) {
                        self.err(&format!("sh: 1: cannot create {path}: {why}\n"));
                        status = 2;
                    }
                }
            }
        }
        status
    }

    fn builtin(&mut self, words: &[String]) -> u32 {
        let args = &words[1..];
        match words[0].as_str() {
            "echo" => {
                self.print(&format!("{}\n", args.join(" ")));
                0
            }
            "hostname" => {
                let name = locks::lock(&self.state.hostname)
                    .clone()
                    .unwrap_or_else(|| "test-host".into());
                self.print(&format!("{name}\n"));
                0
            }
            "whoami" => {
                let user = self.user.clone();
                self.print(&format!("{user}\n"));
                0
            }
            "uptime" => {
                self.print(" 10:00:00 up 3 days,  2:01,  1 user,  load average: 0.00, 0.01, 0.05\n");
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
                    match self.read_file(path) {
                        Some(text) => self.print(&text),
                        None => {
                            self.err(&format!("cat: {path}: No such file or directory\n"));
                            status = 1;
                        }
                    }
                }
                status
            }
            "head" => {
                // `head -n N file`, the only form the guest metrics script uses.
                let (lines, path) = match args {
                    [flag, n, path] if flag == "-n" => (n.parse().unwrap_or(10), path),
                    [path] => (10, path),
                    _ => {
                        self.err("head: usage: head [-n N] file\n");
                        return 1;
                    }
                };
                match self.read_file(path) {
                    Some(text) => {
                        for line in text.split_inclusive('\n').take(lines) {
                            self.print(line);
                        }
                        0
                    }
                    None => {
                        self.err(&format!(
                            "head: cannot open '{path}' for reading: No such file or directory\n"
                        ));
                        1
                    }
                }
            }
            "tail" => {
                // `tail -c N file` and `tail -n N file`.
                let (bytes, n, path) = match args {
                    [flag, n, path] if flag == "-c" || flag == "-n" => (flag == "-c", n.parse().unwrap_or(10), path),
                    [path] => (false, 10, path),
                    _ => {
                        self.err("tail: usage: tail [-c N | -n N] file\n");
                        return 1;
                    }
                };
                let Some(text) = self.read_file(path) else {
                    self.err(&format!(
                        "tail: cannot open '{path}' for reading: No such file or directory\n"
                    ));
                    return 1;
                };
                if bytes {
                    let start = text.len().saturating_sub(n);
                    self.stdout.extend_from_slice(&text.as_bytes()[start..]);
                } else {
                    let lines: Vec<&str> = text.split_inclusive('\n').collect();
                    for line in &lines[lines.len().saturating_sub(n)..] {
                        self.print(line);
                    }
                }
                0
            }
            "seq" => {
                let n: u64 = args.first().and_then(|n| n.parse().ok()).unwrap_or(0);
                for i in 1..=n {
                    self.print(&format!("{i}\n"));
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
            "true" | "cd" => 0,
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
            "umask" => {
                match args.first() {
                    Some(mask) => match u32::from_str_radix(mask, 8) {
                        Ok(mask) => self.umask = mask & 0o777,
                        Err(_) => {
                            self.err(&format!("sh: 1: umask: Illegal mode: {mask}\n"));
                            return 2;
                        }
                    },
                    None => {
                        let mask = self.umask;
                        self.print(&format!("{mask:04o}\n"));
                    }
                }
                0
            }
            "mkdir" => {
                let parents = args.iter().any(|a| a == "-p");
                let mut status = 0;
                for dir in args.iter().filter(|a| !a.starts_with('-')) {
                    let path = self.path(dir);
                    if self.is_dir(&path) || self.read_file(&path).is_some() {
                        if !parents || !self.is_dir(&path) {
                            self.err(&format!("mkdir: cannot create directory '{dir}': File exists\n"));
                            status = 1;
                        }
                        continue;
                    }
                    let mut missing = vec![path.clone()];
                    let mut up = parent_of(&path);
                    while !self.is_dir(&up) {
                        missing.push(up.clone());
                        up = parent_of(&up);
                    }
                    if missing.len() > 1 && !parents {
                        self.err(&format!(
                            "mkdir: cannot create directory '{dir}': No such file or directory\n"
                        ));
                        status = 1;
                        continue;
                    }
                    for folder in missing.iter().rev() {
                        self.make_dir(folder);
                    }
                }
                status
            }
            "chmod" => {
                let Some((mode, paths)) = args.split_first() else {
                    self.err("chmod: missing operand\n");
                    return 1;
                };
                let Ok(mode) = u32::from_str_radix(mode, 8) else {
                    self.err(&format!("chmod: invalid mode: '{mode}'\n"));
                    return 1;
                };
                let mut status = 0;
                for p in paths {
                    let path = self.path(p);
                    if self.is_dir(&path) || self.read_file(&path).is_some() {
                        locks::lock(&self.state.modes).insert(path, mode);
                    } else {
                        self.err(&format!("chmod: cannot access '{p}': No such file or directory\n"));
                        status = 1;
                    }
                }
                status
            }
            "touch" => {
                let mut status = 0;
                for p in args {
                    let path = self.path(p);
                    if self.is_dir(&path) || self.read_file(&path).is_some() {
                        continue;
                    }
                    if let Err(why) = self.write_file(p, "", true) {
                        self.err(&format!("touch: cannot touch '{p}': {why}\n"));
                        status = 1;
                    }
                }
                status
            }
            "grep" => {
                // Fixed strings only: `grep [-q] [-F] [-x] [-e PATTERN | PATTERN] [FILE]`.
                let mut quiet = false;
                let mut whole_line = false;
                let mut pattern = None;
                let mut files = Vec::new();
                let mut rest = args.iter();
                while let Some(arg) = rest.next() {
                    if arg == "-e" {
                        pattern = rest.next().cloned();
                    } else if arg.starts_with('-') && arg.len() > 1 && pattern.is_none() {
                        quiet |= arg.contains('q');
                        whole_line |= arg.contains('x');
                    } else if pattern.is_none() {
                        pattern = Some(arg.clone());
                    } else {
                        files.push(arg.clone());
                    }
                }
                let Some(pattern) = pattern else {
                    self.err("grep: no pattern\n");
                    return 2;
                };
                let text = match files.first() {
                    None => String::from_utf8_lossy(&std::mem::take(&mut self.stdin)).into_owned(),
                    Some(file) => match self.read_file(file) {
                        Some(text) => text,
                        None => {
                            self.err(&format!("grep: {file}: No such file or directory\n"));
                            return 2;
                        }
                    },
                };
                let hits: Vec<&str> = text
                    .lines()
                    .filter(|l| {
                        if whole_line {
                            *l == pattern
                        } else {
                            l.contains(&pattern)
                        }
                    })
                    .collect();
                if !quiet {
                    for hit in &hits {
                        self.print(&format!("{hit}\n"));
                    }
                }
                u32::from(hits.is_empty())
            }
            name @ ("[" | "test") => {
                let mut a: Vec<&str> = args.iter().map(String::as_str).collect();
                if name == "[" {
                    if a.last() != Some(&"]") {
                        self.err("sh: 1: [: missing ]\n");
                        return 2;
                    }
                    a.pop();
                }
                let negate = a.first() == Some(&"!");
                if negate {
                    a.remove(0);
                }
                let result = match a.as_slice() {
                    [] => false,
                    [s] => !s.is_empty(),
                    ["-z", s] => s.is_empty(),
                    ["-n", s] => !s.is_empty(),
                    ["-s", f] => self.read_file(f).is_some_and(|t| !t.is_empty()),
                    ["-f", f] => self.read_file(f).is_some(),
                    ["-d", d] => self.is_dir(&self.path(d)),
                    ["-e", p] => self.read_file(p).is_some() || self.is_dir(&self.path(p)),
                    [x, "=", y] => x == y,
                    [x, "!=", y] => x != y,
                    _ => {
                        self.err("sh: 1: [: unexpected operator\n");
                        return 2;
                    }
                };
                u32::from(result == negate)
            }
            "printf" => {
                let Some((format, rest)) = args.split_first() else {
                    return 0;
                };
                // Like POSIX printf, the format is used again while arguments are left.
                let mut rest = rest.iter();
                loop {
                    let mut used = false;
                    let mut out = String::new();
                    let mut chars = format.chars();
                    while let Some(c) = chars.next() {
                        match c {
                            '\\' => match chars.next() {
                                Some('n') => out.push('\n'),
                                Some('t') => out.push('\t'),
                                Some(other) => out.push(other),
                                None => out.push('\\'),
                            },
                            '%' => match chars.next() {
                                Some('s') => {
                                    used = true;
                                    out.push_str(rest.next().map_or("", String::as_str));
                                }
                                Some(other) => out.push(other),
                                None => out.push('%'),
                            },
                            c => out.push(c),
                        }
                    }
                    self.print(&out);
                    if !used || rest.len() == 0 {
                        break;
                    }
                }
                0
            }
            "command" => match args {
                [flag, name] if flag == "-v" => {
                    let known = BUILTINS.contains(&name.as_str())
                        || locks::lock(&self.state.programs).contains_key(name.as_str());
                    if known {
                        self.print(&format!("{name}\n"));
                    }
                    u32::from(!known)
                }
                _ => {
                    self.err("sh: 1: command: only -v NAME is supported here\n");
                    2
                }
            },
            other if locks::lock(&self.state.programs).contains_key(other) => {
                let text = locks::lock(&self.state.programs)
                    .get(other)
                    .cloned()
                    .unwrap_or_default();
                self.print(&text);
                0
            }
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
