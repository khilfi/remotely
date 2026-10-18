//! An SSH server on 127.0.0.1 for the terminal tests (SS-03, SS-05): russh's server with keys made at
//! run time, so no test connects to a real host and no key is ever committed.
//!
//! Every connection runs through a small relay the test controls: [`TestSshServer::drop_connections`]
//! cuts the TCP connections the way a network failure would (no SSH goodbye), and
//! [`TestSshServer::freeze_connections`] silently swallows their traffic, so only keep-alives can tell
//! the connection is dead. The shell is a toy that echoes what is typed and understands a few
//! commands (`exit [code]`, `whoami`, `split-utf8`, `echo <text>`, and for trying the app by hand,
//! `drop-connection` and `change-host-key`). The server logs what clients ask for
//! (`pty xterm-256color 80x24`, `resize 120x40`, `shell`, `line whoami`) for tests to check.

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

#[derive(Default)]
struct State {
    host_key: Mutex<Option<PrivateKey>>,
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

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
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
