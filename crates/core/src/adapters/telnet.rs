//! SS-12 Telnet client (RFC 854) for a terminal pane: a TCP connection, the option negotiation, and the bytes in
//! between, as the same input and output channels an SSH shell has ([`super::remote::ShellInput`],
//! [`super::remote::ShellOutput`]), so the pane does everything for it that it does for SSH (logs and saved output
//! scrubbed of secrets, reconnects, alerts).
//!
//! * Options: it offers its window size (NAWS, RFC 1073) and terminal type (TTYPE, RFC 1091), lets the server echo
//!   (ECHO, RFC 857) and suppress go-ahead (SGA, RFC 858) both ways, and refuses every other option. Each option's
//!   state is kept for both sides, so an answer never starts another round (RFC 1143's rule, simply).
//! * Enter sends the session's line ending; a bare CR goes as CR NUL, as the NVT wants. A 0xFF byte is doubled.
//! * Until the server says it echoes, nothing is shown of what is typed; a server that says it won't (or says
//!   nothing within [`ECHO_WAIT`]) gets local echo, like PuTTY's "auto".
//! * Everything, passwords included, crosses the network in clear text: the pane says so, and a vault password typed
//!   into it asks for the vault password again on each connection (QL-06, `crate::terminal`).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::remote::{PtySize, ShellEnd, ShellInput, ShellOutput};
use crate::error::{CoreError, Result};
use crate::sessions::kinds::LineEnding;

pub const IAC: u8 = 255;
pub const DONT: u8 = 254;
pub const DO: u8 = 253;
pub const WONT: u8 = 252;
pub const WILL: u8 = 251;
pub const SB: u8 = 250;
pub const BRK: u8 = 243;
pub const SE: u8 = 240;

pub const ECHO: u8 = 1;
pub const SGA: u8 = 3;
pub const TTYPE: u8 = 24;
pub const NAWS: u8 = 31;

const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;

/// How long a server has to say it echoes before what is typed is echoed here.
pub const ECHO_WAIT: Duration = Duration::from_secs(1);
/// The most a subnegotiation may hold (a server can't grow it without end).
const MAX_SUBNEGOTIATION: usize = 1024;

/// What a Telnet pane connects to.
pub struct TelnetRequest<'a> {
    pub host: &'a str,
    pub port: u16,
    pub size: PtySize,
    pub line_ending: LineEnding,
    pub connect_timeout: Duration,
    /// The terminal type it announces (TTYPE), e.g. `XTERM-256COLOR`.
    pub term: &'a str,
}

/// A connected Telnet session's two ends.
pub struct TelnetShell {
    pub input: mpsc::Sender<ShellInput>,
    pub output: mpsc::Receiver<ShellOutput>,
    pub peer_ip: Option<IpAddr>,
}

/// Connects and starts the session. [`CoreError::Io`] or [`CoreError::Timeout`] when the host can't be reached, so
/// the pane tries again by itself after a dropped connection.
pub async fn connect(request: TelnetRequest<'_>) -> Result<TelnetShell> {
    let host = request.host.trim_start_matches('[').trim_end_matches(']');
    let address = crate::known_hosts::address(request.host, request.port);
    let stream = match tokio::time::timeout(request.connect_timeout, TcpStream::connect((host, request.port))).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            return Err(CoreError::Io(std::io::Error::new(
                err.kind(),
                format!("can't connect to {address}: {err}"),
            )))
        }
        Err(_) => {
            return Err(CoreError::Timeout {
                command: format!("connecting to {address}"),
                seconds: request.connect_timeout.as_secs(),
            })
        }
    };
    let _ = stream.set_nodelay(true);
    let peer_ip = stream.peer_addr().ok().map(|a| a.ip());
    let (input_tx, input_rx) = mpsc::channel(256);
    let (output_tx, output_rx) = mpsc::channel(256);
    let session = Session {
        options: Options::new(request.term),
        decoder: Decoder::default(),
        size: request.size,
        line_ending: request.line_ending,
        started: Instant::now(),
    };
    tokio::spawn(session.run(stream, input_rx, output_tx));
    Ok(TelnetShell {
        input: input_tx,
        output: output_rx,
        peer_ip,
    })
}

/// Where one option stands on one side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    No,
    /// Asked for; waiting for the answer.
    WantYes,
    Yes,
}

/// Both sides' options.
pub(crate) struct Options {
    /// What this end does (WILL/WONT).
    us: [State; 256],
    /// What the server does (DO/DONT).
    him: [State; 256],
    term: String,
    /// The server answered about its echo (either way).
    echo_known: bool,
}

impl Options {
    fn new(term: &str) -> Self {
        Self {
            us: [State::No; 256],
            him: [State::No; 256],
            term: term.to_ascii_uppercase(),
            echo_known: false,
        }
    }

    /// What this end offers when it connects.
    fn opening(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        for opt in [NAWS, TTYPE, SGA] {
            self.us[usize::from(opt)] = State::WantYes;
            out.extend([IAC, WILL, opt]);
        }
        for opt in [SGA, ECHO] {
            self.him[usize::from(opt)] = State::WantYes;
            out.extend([IAC, DO, opt]);
        }
        out
    }

    fn ours(opt: u8) -> bool {
        matches!(opt, NAWS | TTYPE | SGA)
    }

    fn theirs(opt: u8) -> bool {
        matches!(opt, ECHO | SGA)
    }

    /// The answer to the server's `cmd` about `opt`, and whether the window size should follow.
    fn answer(&mut self, cmd: u8, opt: u8, size: PtySize) -> Vec<u8> {
        let mut out = Vec::new();
        let i = usize::from(opt);
        match cmd {
            WILL => {
                if Self::theirs(opt) {
                    if self.him[i] == State::No {
                        out.extend([IAC, DO, opt]);
                    }
                    self.him[i] = State::Yes;
                } else if self.him[i] == State::No {
                    out.extend([IAC, DONT, opt]);
                }
                if opt == ECHO {
                    self.echo_known = true;
                }
            }
            WONT => {
                if self.him[i] == State::Yes {
                    out.extend([IAC, DONT, opt]);
                }
                self.him[i] = State::No;
                if opt == ECHO {
                    self.echo_known = true;
                }
            }
            DO => {
                if Self::ours(opt) {
                    let was = self.us[i];
                    if was == State::No {
                        out.extend([IAC, WILL, opt]);
                    }
                    self.us[i] = State::Yes;
                    if opt == NAWS && was != State::Yes {
                        out.extend(naws(size));
                    }
                } else if self.us[i] == State::No {
                    out.extend([IAC, WONT, opt]);
                }
            }
            DONT => {
                if self.us[i] == State::Yes {
                    out.extend([IAC, WONT, opt]);
                }
                self.us[i] = State::No;
            }
            _ => {}
        }
        out
    }

    /// The answer to a subnegotiation: the terminal type, when asked for it.
    fn subnegotiation(&self, opt: u8, data: &[u8]) -> Vec<u8> {
        if opt == TTYPE && data.first() == Some(&TTYPE_SEND) && self.us[usize::from(TTYPE)] == State::Yes {
            let mut out = vec![IAC, SB, TTYPE, TTYPE_IS];
            out.extend(escaped(self.term.as_bytes()));
            out.extend([IAC, SE]);
            return out;
        }
        Vec::new()
    }

    pub(crate) fn server_echoes(&self) -> bool {
        self.him[usize::from(ECHO)] == State::Yes
    }
}

/// `IAC SB NAWS <width> <height> IAC SE`, each 16 bits big-endian, a 255 byte doubled.
pub fn naws(size: PtySize) -> Vec<u8> {
    let mut out = vec![IAC, SB, NAWS];
    let mut data = Vec::with_capacity(4);
    data.extend(size.cols.to_be_bytes());
    data.extend(size.rows.to_be_bytes());
    out.extend(escaped(&data));
    out.extend([IAC, SE]);
    out
}

/// Data with every 0xFF doubled.
pub fn escaped(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        }
    }
    out
}

/// What the keyboard sends, as the server reads it: Enter (CR) as the session's line ending (a bare CR as CR NUL),
/// 0xFF doubled.
pub fn encode_input(data: &[u8], line_ending: LineEnding) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    for &b in data {
        match b {
            b'\r' => match line_ending {
                LineEnding::Cr => out.extend([b'\r', 0]),
                LineEnding::Lf => out.push(b'\n'),
                LineEnding::CrLf => out.extend(*b"\r\n"),
            },
            IAC => out.extend([IAC, IAC]),
            b => out.push(b),
        }
    }
    out
}

/// What local echo shows for typed bytes: Enter as a new line, Backspace as rubbing out a character; the escape
/// sequences of arrow and function keys and other control keys show nothing.
pub fn local_echo(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut escape = 0u8;
    for &b in data {
        match (escape, b) {
            (0, 0x1b) => escape = 1,
            (1, b'[' | b'O') => escape = 2,
            (1, _) => escape = 0,
            (2, 0x40..=0x7e) => escape = 0,
            (2, _) => {}
            (_, b'\r') => out.extend(*b"\r\n"),
            (_, 0x7f | 0x08) => out.extend(*b"\x08 \x08"),
            (_, b) if b < 0x20 => {}
            (_, b) => out.push(b),
        }
    }
    out
}

/// One thing the decoder found besides data.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// WILL, WONT, DO or DONT about an option.
    Negotiate(u8, u8),
    Subnegotiation(u8, Vec<u8>),
}

#[derive(Default, Debug, PartialEq, Eq)]
enum Step {
    #[default]
    Data,
    Iac,
    Command(u8),
    Sb,
    SbData,
    SbIac,
}

/// Splits what the server sends into data and Telnet commands; a command split across two reads is joined.
#[derive(Default)]
pub struct Decoder {
    step: Step,
    sb_option: u8,
    sb: Vec<u8>,
    /// The last data byte was CR: a NUL after it is the NVT's padding, not data.
    after_cr: bool,
}

impl Decoder {
    pub fn feed(&mut self, bytes: &[u8], data: &mut Vec<u8>, events: &mut Vec<Event>) {
        for &b in bytes {
            match self.step {
                Step::Data => {
                    if b == IAC {
                        self.step = Step::Iac;
                        continue;
                    }
                    if self.after_cr && b == 0 {
                        self.after_cr = false;
                        continue;
                    }
                    self.after_cr = b == b'\r';
                    data.push(b);
                }
                Step::Iac => {
                    self.step = Step::Data;
                    match b {
                        IAC => {
                            self.after_cr = false;
                            data.push(IAC);
                        }
                        WILL | WONT | DO | DONT => self.step = Step::Command(b),
                        SB => self.step = Step::Sb,
                        // NOP, GA, AYT, a stray SE...: nothing to show.
                        _ => {}
                    }
                }
                Step::Command(cmd) => {
                    events.push(Event::Negotiate(cmd, b));
                    self.step = Step::Data;
                }
                Step::Sb => {
                    self.sb_option = b;
                    self.sb.clear();
                    self.step = Step::SbData;
                }
                Step::SbData => {
                    if b == IAC {
                        self.step = Step::SbIac;
                    } else if self.sb.len() < MAX_SUBNEGOTIATION {
                        self.sb.push(b);
                    }
                }
                Step::SbIac => match b {
                    SE => {
                        events.push(Event::Subnegotiation(self.sb_option, std::mem::take(&mut self.sb)));
                        self.step = Step::Data;
                    }
                    IAC => {
                        if self.sb.len() < MAX_SUBNEGOTIATION {
                            self.sb.push(IAC);
                        }
                        self.step = Step::SbData;
                    }
                    _ => self.step = Step::SbData,
                },
            }
        }
    }
}

struct Session {
    options: Options,
    decoder: Decoder,
    size: PtySize,
    line_ending: LineEnding,
    started: Instant,
}

impl Session {
    /// Local echo: the server said it won't echo, or said nothing about it in time.
    fn echo_here(&self) -> bool {
        !self.options.server_echoes() && (self.options.echo_known || self.started.elapsed() >= ECHO_WAIT)
    }

    async fn run(
        mut self,
        stream: TcpStream,
        mut input: mpsc::Receiver<ShellInput>,
        output: mpsc::Sender<ShellOutput>,
    ) {
        let (mut reader, mut writer) = stream.into_split();
        let opening = self.options.opening();
        if writer.write_all(&opening).await.is_err() {
            let _ = output
                .send(ShellOutput::Closed(ShellEnd::Lost {
                    reason: "the connection was lost".into(),
                }))
                .await;
            return;
        }
        let mut buf = vec![0u8; 16 * 1024];
        let end = loop {
            tokio::select! {
                msg = input.recv() => match msg {
                    Some(ShellInput::Data(bytes)) => {
                        if self.echo_here() {
                            let shown = local_echo(&bytes);
                            if !shown.is_empty() && output.send(ShellOutput::Data(shown)).await.is_err() {
                                break None;
                            }
                        }
                        if writer.write_all(&encode_input(&bytes, self.line_ending)).await.is_err() {
                            break Some(ShellEnd::Lost { reason: "the connection was lost".into() });
                        }
                    }
                    Some(ShellInput::Resize { cols, rows }) => {
                        self.size = PtySize { cols, rows };
                        if self.options.us[usize::from(NAWS)] == State::Yes
                            && writer.write_all(&naws(self.size)).await.is_err()
                        {
                            break Some(ShellEnd::Lost { reason: "the connection was lost".into() });
                        }
                    }
                    Some(ShellInput::Break) => {
                        let _ = writer.write_all(&[IAC, BRK]).await;
                    }
                    Some(ShellInput::Close) | None => {
                        let _ = writer.shutdown().await;
                        break Some(ShellEnd::Exited { status: None });
                    }
                },
                read = reader.read(&mut buf) => match read {
                    // The server closed the connection: the session ended (a logout).
                    Ok(0) => break Some(ShellEnd::Exited { status: None }),
                    Ok(n) => {
                        let mut data = Vec::with_capacity(n);
                        let mut events = Vec::new();
                        self.decoder.feed(&buf[..n], &mut data, &mut events);
                        let mut reply = Vec::new();
                        for event in events {
                            match event {
                                Event::Negotiate(cmd, opt) => reply.extend(self.options.answer(cmd, opt, self.size)),
                                Event::Subnegotiation(opt, body) => reply.extend(self.options.subnegotiation(opt, &body)),
                            }
                        }
                        if !reply.is_empty() && writer.write_all(&reply).await.is_err() {
                            break Some(ShellEnd::Lost { reason: "the connection was lost".into() });
                        }
                        if !data.is_empty() && output.send(ShellOutput::Data(data)).await.is_err() {
                            break None;
                        }
                    }
                    Err(err) => break Some(ShellEnd::Lost { reason: format!("the connection was lost ({err})") }),
                },
            }
        };
        if let Some(end) = end {
            let _ = output.send(ShellOutput::Closed(end)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: PtySize = PtySize { cols: 120, rows: 40 };

    #[test]
    fn commands_are_split_from_data_even_across_reads() {
        let mut d = Decoder::default();
        let (mut data, mut events) = (Vec::new(), Vec::new());
        d.feed(b"login:\xff\xfb", &mut data, &mut events);
        d.feed(b"\x01 x\xff\xff\xff\xfa\x18\x01\xff", &mut data, &mut events);
        d.feed(b"\xf0end", &mut data, &mut events);
        assert_eq!(data, b"login: x\xffend");
        assert_eq!(
            events,
            [
                Event::Negotiate(WILL, ECHO),
                Event::Subnegotiation(TTYPE, vec![TTYPE_SEND])
            ]
        );
    }

    #[test]
    fn a_nul_after_cr_is_padding() {
        let mut d = Decoder::default();
        let (mut data, mut events) = (Vec::new(), Vec::new());
        d.feed(b"a\r\0b\r\nc\0", &mut data, &mut events);
        assert_eq!(data, b"a\rb\r\nc\0");
    }

    #[test]
    fn enter_becomes_the_line_ending_and_iac_is_doubled() {
        assert_eq!(encode_input(b"ls\r", LineEnding::CrLf), b"ls\r\n");
        assert_eq!(encode_input(b"ls\r", LineEnding::Cr), b"ls\r\0");
        assert_eq!(encode_input(b"ls\r", LineEnding::Lf), b"ls\n");
        assert_eq!(encode_input(b"\xff", LineEnding::Cr), b"\xff\xff");
    }

    #[test]
    fn the_window_size_goes_with_255_doubled() {
        assert_eq!(
            naws(PtySize { cols: 80, rows: 24 }),
            [IAC, SB, NAWS, 0, 80, 0, 24, IAC, SE]
        );
        assert_eq!(
            naws(PtySize { cols: 255, rows: 24 }),
            [IAC, SB, NAWS, 0, 255, 255, 0, 24, IAC, SE]
        );
    }

    #[test]
    fn negotiation_answers_once_and_never_loops() {
        let mut o = Options::new("xterm-256color");
        let opening = o.opening();
        assert_eq!(
            opening,
            [IAC, WILL, NAWS, IAC, WILL, TTYPE, IAC, WILL, SGA, IAC, DO, SGA, IAC, DO, ECHO]
        );
        // The server agrees to what was offered: no answer, but the window size follows its DO NAWS.
        assert_eq!(o.answer(DO, NAWS, SIZE), naws(SIZE));
        assert!(o.answer(WILL, ECHO, SIZE).is_empty());
        assert!(o.server_echoes());
        // Asked again: still no answer.
        assert!(o.answer(WILL, ECHO, SIZE).is_empty());
        // Options it doesn't do are refused, once.
        assert_eq!(o.answer(DO, 39, SIZE), [IAC, WONT, 39]);
        assert_eq!(o.answer(WILL, 34, SIZE), [IAC, DONT, 34]);
        // A server that stops echoing: confirmed, and local echo takes over.
        assert_eq!(o.answer(WONT, ECHO, SIZE), [IAC, DONT, ECHO]);
        assert!(!o.server_echoes());
        // The terminal type, when asked.
        o.answer(DO, TTYPE, SIZE);
        let ttype = o.subnegotiation(TTYPE, &[TTYPE_SEND]);
        assert_eq!(&ttype[..4], [IAC, SB, TTYPE, TTYPE_IS]);
        assert_eq!(&ttype[4..ttype.len() - 2], b"XTERM-256COLOR");
        // DONT turns an option off with WONT, once.
        assert_eq!(o.answer(DONT, NAWS, SIZE), [IAC, WONT, NAWS]);
        assert!(o.answer(DONT, NAWS, SIZE).is_empty());
    }

    #[test]
    fn local_echo_shows_what_is_typed() {
        assert_eq!(local_echo(b"ab\x7f\r"), b"ab\x08 \x08\r\n");
        assert_eq!(local_echo(b"\x1b[Ax\x1bOPy\x1b[15~z"), b"xyz");
    }
}
