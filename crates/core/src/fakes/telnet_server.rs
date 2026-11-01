//! SS-12: a Telnet server on 127.0.0.1 for tests and `dev_ssh_server`: a small router-style console with a login.
//!
//! It asks for the window size and terminal type and echoes (WILL ECHO, WILL SGA, DO NAWS, DO TTYPE), unless made
//! a server that won't echo, then asks `login:` and `Password:` (never echoed) and answers a few commands at its
//! `router>` prompt (`show version`, `show clock`, `echo <text>`, `exit`). It keeps what each connection negotiated
//! and the raw bytes it got, for tests of line endings, window sizes and what crossed in clear text.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::adapters::telnet::{Decoder, Event, DO, ECHO, IAC, NAWS, SB, SE, SGA, TTYPE, WILL, WONT};
use crate::locks;

/// What one connection did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TelnetConnection {
    /// The window sizes it was told, in order.
    pub sizes: Vec<(u16, u16)>,
    pub terminal_type: Option<String>,
    /// Every byte it got, Telnet commands included.
    pub raw: Vec<u8>,
    /// The user and password it was logged in with.
    pub login: Option<(String, String)>,
    /// Breaks (IAC BRK) it got.
    pub breaks: u32,
}

#[derive(Default)]
struct State {
    connections: Vec<TelnetConnection>,
}

/// The server. Dropping it stops it.
pub struct TelnetTestServer {
    port: u16,
    state: Arc<Mutex<State>>,
    stop: CancellationToken,
    /// Cancelled to cut every open connection (a dropped network).
    drop_now: Arc<Mutex<CancellationToken>>,
}

struct Config {
    user: String,
    password: String,
    echo: bool,
}

impl TelnetTestServer {
    /// A server that echoes, for `user` with `password`.
    pub async fn start(user: &str, password: &str) -> std::io::Result<Self> {
        Self::start_on(0, user, password, true).await
    }

    /// A server that says it won't echo (the client echoes what is typed).
    pub async fn without_echo(user: &str, password: &str) -> std::io::Result<Self> {
        Self::start_on(0, user, password, false).await
    }

    /// On 127.0.0.1 and `port` (0: any free one).
    pub async fn start_on(port: u16, user: &str, password: &str, echo: bool) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        let port = listener.local_addr()?.port();
        let state = Arc::new(Mutex::new(State::default()));
        let stop = CancellationToken::new();
        let drop_now = Arc::new(Mutex::new(CancellationToken::new()));
        let config = Arc::new(Config {
            user: user.to_owned(),
            password: password.to_owned(),
            echo,
        });
        {
            let state = Arc::clone(&state);
            let stop = stop.clone();
            let drop_now = Arc::clone(&drop_now);
            tokio::spawn(async move {
                loop {
                    let accepted = tokio::select! {
                        () = stop.cancelled() => break,
                        accepted = listener.accept() => accepted,
                    };
                    let Ok((mut stream, _)) = accepted else { continue };
                    let index = {
                        let mut s = locks::lock(&state);
                        s.connections.push(TelnetConnection::default());
                        s.connections.len() - 1
                    };
                    let cut = locks::lock(&drop_now).clone();
                    let state = Arc::clone(&state);
                    let config = Arc::clone(&config);
                    let stop = stop.clone();
                    tokio::spawn(async move {
                        let cut_off = tokio::select! {
                            () = stop.cancelled() => false,
                            () = cut.cancelled() => true,
                            () = serve(&mut stream, state, index, config) => false,
                        };
                        // A dropped network: the connection resets instead of closing (which is how a logout looks).
                        if cut_off {
                            let _ = stream.set_zero_linger();
                        }
                    });
                }
            });
        }
        Ok(Self {
            port,
            state,
            stop,
            drop_now,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// What each connection did so far, in order.
    pub fn connections(&self) -> Vec<TelnetConnection> {
        locks::lock(&self.state).connections.clone()
    }

    /// Cuts every open connection without a word, as a dropped network would.
    pub fn drop_connections(&self) {
        let mut cut = locks::lock(&self.drop_now);
        cut.cancel();
        *cut = CancellationToken::new();
    }

    /// Waits until `n` connections came, for at most `wait`.
    pub async fn wait_for_connections(&self, n: usize, wait: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + wait;
        while tokio::time::Instant::now() < deadline {
            if self.connections().len() >= n {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }
}

impl Drop for TelnetTestServer {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

enum Phase {
    User,
    Password(String),
    Prompt,
}

async fn serve(stream: &mut TcpStream, state: Arc<Mutex<State>>, index: usize, config: Arc<Config>) {
    let mut opening = Vec::new();
    opening.extend([IAC, if config.echo { WILL } else { WONT }, ECHO]);
    opening.extend([IAC, WILL, SGA, IAC, DO, NAWS, IAC, DO, TTYPE]);
    // Ask for the terminal type (RFC 1091: SB TTYPE SEND).
    opening.extend([IAC, SB, TTYPE, 1, IAC, SE]);
    opening.extend(b"\r\nRemotely test router (Telnet)\r\n\r\nlogin: ");
    if stream.write_all(&opening).await.is_err() {
        return;
    }
    let mut decoder = Decoder::default();
    let mut phase = Phase::User;
    let mut line: Vec<u8> = Vec::new();
    let mut after_cr = false;
    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let raw = &buf[..n];
        let breaks = raw
            .windows(2)
            .filter(|w| *w == [IAC, crate::adapters::telnet::BRK])
            .count();
        {
            let mut s = locks::lock(&state);
            let c = &mut s.connections[index];
            c.raw.extend_from_slice(raw);
            c.breaks += u32::try_from(breaks).unwrap_or(0);
        }
        let mut data = Vec::new();
        let mut events = Vec::new();
        decoder.feed(raw, &mut data, &mut events);
        for event in events {
            let mut s = locks::lock(&state);
            let c = &mut s.connections[index];
            match event {
                Event::Subnegotiation(NAWS, body) if body.len() >= 4 => {
                    c.sizes.push((
                        u16::from_be_bytes([body[0], body[1]]),
                        u16::from_be_bytes([body[2], body[3]]),
                    ));
                }
                Event::Subnegotiation(TTYPE, body) if body.first() == Some(&0) => {
                    c.terminal_type = Some(String::from_utf8_lossy(&body[1..]).into_owned());
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        for &b in &data {
            let hidden = matches!(phase, Phase::Password(_));
            let lf_after_cr = b == b'\n' && after_cr;
            after_cr = b == b'\r';
            if lf_after_cr {
                continue;
            }
            match b {
                // A line ends at CR (CR LF, CR NUL) or a bare LF.
                b'\r' | b'\n' => {
                    let text = String::from_utf8_lossy(&line).into_owned();
                    line.clear();
                    out.extend(b"\r\n");
                    match std::mem::replace(&mut phase, Phase::Prompt) {
                        Phase::User => {
                            phase = Phase::Password(text);
                            out.extend(b"Password: ");
                        }
                        Phase::Password(user) => {
                            if user == config.user && text == config.password {
                                locks::lock(&state).connections[index].login = Some((user, text));
                                out.extend(b"router> ");
                            } else {
                                phase = Phase::User;
                                out.extend(b"% Login invalid\r\n\r\nlogin: ");
                            }
                        }
                        Phase::Prompt => {
                            match text.trim() {
                                "" => {}
                                "exit" | "logout" => {
                                    let _ = stream.write_all(&out).await;
                                    let _ = stream.write_all(b"Bye\r\n").await;
                                    return;
                                }
                                "show version" => out.extend(b"Remotely test router, version 1.0\r\n"),
                                "show clock" => out.extend(b"12:00:00 UTC\r\n"),
                                t if t.starts_with("echo ") => {
                                    out.extend(&t.as_bytes()["echo ".len()..]);
                                    out.extend(b"\r\n");
                                }
                                _ => out.extend(b"% Unknown command\r\n"),
                            }
                            out.extend(b"router> ");
                        }
                    }
                }
                0 => {}
                0x7f | 0x08 => {
                    if line.pop().is_some() && config.echo && !hidden {
                        out.extend(b"\x08 \x08");
                    }
                }
                b => {
                    line.push(b);
                    if config.echo && !hidden {
                        out.push(b);
                    }
                }
            }
        }
        if !out.is_empty() && stream.write_all(&out).await.is_err() {
            return;
        }
    }
}
