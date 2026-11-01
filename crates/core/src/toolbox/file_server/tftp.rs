//! FD-09: TFTP (RFC 1350) with option negotiation (RFC 2347), `blksize` (RFC 2348) and `tsize` (RFC 2349).
//!
//! Requests arrive on the listening port; each transfer gets a socket of its own on the same address (its transfer
//! ID), connected to the client, so the system drops packets from anyone else. Hostile clients are bounded:
//!
//! * at most [`super::FileServerTuning::max_tftp`] transfers at once, fewer per client;
//! * each block is sent again at most [`super::FileServerTuning::tftp_retries`] times, only when its ACK times out
//!   (never on a duplicate ACK, the "Sorcerer's Apprentice" bug), then the transfer ends;
//! * at most 65,535 blocks a transfer, so block numbers never wrap round: a larger file needs a larger `blksize`
//!   (or HTTP);
//! * a request is read up to 2 KB; requests with an unknown opcode or a malformed body get an error, not a
//!   transfer; packets other than requests on the listening port are dropped.
//!
//! `netascii` is accepted and sent as it is (as most servers do); `mail` is refused.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::log::{self, Outcome, Protocol};
use super::paths::{self, Refused};
use super::served::Found;
use super::uploads::{size_text, UploadRefused};
use super::{Pending, Shared, Slots};

pub const RRQ: u16 = 1;
pub const WRQ: u16 = 2;
pub const DATA: u16 = 3;
pub const ACK: u16 = 4;
pub const ERROR: u16 = 5;
pub const OACK: u16 = 6;

/// RFC 1350's block size, without `blksize`.
pub const DEFAULT_BLOCK: usize = 512;
/// RFC 2348's range.
pub const MIN_BLOCKSIZE: u64 = 8;
pub const MAX_BLOCKSIZE: u64 = 65464;
/// Block numbers are 16 bits; a transfer stops before they would wrap round.
pub const MAX_BLOCKS: u16 = u16::MAX;
/// The largest request read.
const MAX_REQUEST: usize = 2048;
/// Room for any UDP datagram: Windows refuses to read one into a smaller buffer.
const DATAGRAM: usize = 65536;
/// The most options a request may carry.
const MAX_OPTIONS: usize = 16;

/// RFC 1350's error codes.
pub mod code {
    pub const NOT_DEFINED: u16 = 0;
    pub const NOT_FOUND: u16 = 1;
    pub const ACCESS: u16 = 2;
    pub const DISK_FULL: u16 = 3;
    pub const ILLEGAL: u16 = 4;
    pub const EXISTS: u16 = 6;
}

/// A read or write request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub write: bool,
    pub name: Vec<u8>,
    /// `blksize`, when asked for (already within RFC 2348's range).
    pub blksize: Option<u64>,
    /// `tsize`, when sent (0 on a read: the client asks for the size).
    pub tsize: Option<u64>,
}

/// Why a request isn't served, as the error packet says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub code: u16,
    pub message: String,
}

impl Failure {
    fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Reads a request packet. Never panics: every length is checked.
pub fn parse_request(packet: &[u8]) -> Result<Request, Failure> {
    let illegal = |why: &str| Failure::new(code::ILLEGAL, why);
    let [hi, lo, rest @ ..] = packet else {
        return Err(illegal("Illegal TFTP operation"));
    };
    let opcode = u16::from_be_bytes([*hi, *lo]);
    let write = match opcode {
        RRQ => false,
        WRQ => true,
        _ => return Err(illegal("Illegal TFTP operation")),
    };
    // Every field ends with a NUL.
    let Some((&0, body)) = rest.split_last() else {
        return Err(illegal("Malformed request"));
    };
    let mut fields = body.split(|b| *b == 0);
    let name = fields.next().unwrap_or_default();
    let mode = fields.next().ok_or_else(|| illegal("Malformed request"))?;
    if name.is_empty() {
        return Err(Failure::new(code::NOT_FOUND, "No file named"));
    }
    let mode = std::str::from_utf8(mode).map_err(|_| illegal("Unknown transfer mode"))?;
    if mode.eq_ignore_ascii_case("mail") {
        return Err(illegal("Mail mode is not supported"));
    }
    if !mode.eq_ignore_ascii_case("octet") && !mode.eq_ignore_ascii_case("netascii") {
        return Err(illegal("Unknown transfer mode"));
    }
    let mut request = Request {
        write,
        name: name.to_vec(),
        blksize: None,
        tsize: None,
    };
    let mut options = 0usize;
    while let Some(option) = fields.next() {
        let value = fields.next().ok_or_else(|| illegal("Malformed option"))?;
        options += 1;
        if options > MAX_OPTIONS {
            return Err(illegal("Too many options"));
        }
        let Ok(option) = std::str::from_utf8(option) else {
            continue;
        };
        let number = || {
            std::str::from_utf8(value)
                .ok()
                .filter(|v| !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|v| v.parse::<u64>().ok())
        };
        // RFC 2347: option names without case; the first of a repeated one counts; unknown ones are left out of the
        // answer, so the client goes on without them.
        if option.eq_ignore_ascii_case("blksize") && request.blksize.is_none() {
            let size = number().ok_or_else(|| Failure::new(8, "Bad blksize"))?;
            if size < MIN_BLOCKSIZE {
                return Err(Failure::new(8, "blksize below 8"));
            }
            request.blksize = Some(size.min(MAX_BLOCKSIZE));
        } else if option.eq_ignore_ascii_case("tsize") && request.tsize.is_none() {
            request.tsize = Some(number().ok_or_else(|| Failure::new(8, "Bad tsize"))?);
        }
    }
    Ok(request)
}

/// An ERROR packet. The message is ASCII, at most 120 bytes.
pub fn error_packet(failure: &Failure) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + failure.message.len() + 1);
    packet.extend_from_slice(&ERROR.to_be_bytes());
    packet.extend_from_slice(&failure.code.to_be_bytes());
    packet.extend(
        failure
            .message
            .chars()
            .map(|c| {
                if c.is_ascii() && !c.is_ascii_control() {
                    c as u8
                } else {
                    b'?'
                }
            })
            .take(120),
    );
    packet.push(0);
    packet
}

fn data_packet(block: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + data.len());
    packet.extend_from_slice(&DATA.to_be_bytes());
    packet.extend_from_slice(&block.to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

fn ack_packet(block: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4);
    packet.extend_from_slice(&ACK.to_be_bytes());
    packet.extend_from_slice(&block.to_be_bytes());
    packet
}

fn oack_packet(options: &[(&str, u64)]) -> Vec<u8> {
    let mut packet = OACK.to_be_bytes().to_vec();
    for (name, value) in options {
        packet.extend_from_slice(name.as_bytes());
        packet.push(0);
        packet.extend_from_slice(value.to_string().as_bytes());
        packet.push(0);
    }
    packet
}

/// A packet from the client during a transfer.
enum Incoming<'a> {
    Data(u16, &'a [u8]),
    Ack(u16),
    Error(u16, String),
    Other,
}

fn parse_incoming(packet: &[u8]) -> Incoming<'_> {
    let [o1, o2, b1, b2, rest @ ..] = packet else {
        return Incoming::Other;
    };
    let block = u16::from_be_bytes([*b1, *b2]);
    match u16::from_be_bytes([*o1, *o2]) {
        DATA => Incoming::Data(block, rest),
        ACK => Incoming::Ack(block),
        ERROR => {
            let message = rest.split(|b| *b == 0).next().unwrap_or_default();
            Incoming::Error(block, log::clean_path(&String::from_utf8_lossy(message)))
        }
        _ => Incoming::Other,
    }
}

/// How a transfer ended badly.
enum Broken {
    /// The client didn't answer in time, after every retransmit.
    TimedOut,
    /// It sent an ERROR.
    Client(u16, String),
    /// The network said it is gone (Windows reports an ICMP "port unreachable" as a reset).
    Gone,
    /// This side failed (a file read or write).
    Local(String),
}

impl Broken {
    fn describe(&self) -> String {
        match self {
            Broken::TimedOut => "the client stopped answering".into(),
            Broken::Client(code, message) if message.is_empty() => format!("the client ended it (error {code})"),
            Broken::Client(code, message) => format!("the client ended it (error {code}: {message})"),
            Broken::Gone => "the client went away".into(),
            Broken::Local(why) => why.clone(),
        }
    }
}

/// Serves requests on `socket` until `stop`; every transfer stops with it, and their sockets close.
pub(super) async fn serve(socket: UdpSocket, shared: Arc<Shared>, stop: CancellationToken) {
    let socket = Arc::new(socket);
    let slots = Arc::new(Slots::new(shared.tuning.max_tftp, shared.tuning.max_tftp_per_client));
    let mut transfers = JoinSet::new();
    let mut buf = vec![0u8; DATAGRAM];
    loop {
        // Ended transfers leave the set as they go.
        while transfers.try_join_next().is_some() {}
        let received = tokio::select! {
            () = stop.cancelled() => break,
            received = socket.recv_from(&mut buf) => received,
        };
        let (len, peer) = match received {
            Ok(got) => got,
            // Windows reports an earlier send's ICMP "port unreachable" on the next receive.
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(err) => {
                tracing::warn!(error = %err, "the TFTP socket failed to receive");
                tokio::select! {
                    () = stop.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_millis(200)) => continue,
                }
            }
        };
        let packet = &buf[..len];
        // Only requests start anything here; a stray DATA or ACK is dropped (answering it would let anyone bounce
        // packets off this PC).
        let opcode = packet.get(..2).map(|o| u16::from_be_bytes([o[0], o[1]]));
        if !matches!(opcode, Some(RRQ | WRQ)) {
            continue;
        }
        let name = request_name(packet);
        let write = opcode == Some(WRQ);
        let mut pending = Pending::new(
            &shared,
            log::entry(Protocol::Tftp, peer, if write { "write" } else { "read" }, &name),
        );
        if len > MAX_REQUEST {
            let failure = Failure::new(code::ILLEGAL, "Request too long");
            let _ = socket.send_to(&error_packet(&failure), peer).await;
            pending.done(Outcome::Refused, "the request is too long");
            continue;
        }
        let request = match parse_request(packet) {
            Ok(request) => request,
            Err(failure) => {
                let _ = socket.send_to(&error_packet(&failure), peer).await;
                pending.done(Outcome::Refused, &failure.message);
                continue;
            }
        };
        let Some(slot) = slots.take(peer.ip()) else {
            let failure = Failure::new(code::NOT_DEFINED, "Server busy: try again");
            let _ = socket.send_to(&error_packet(&failure), peer).await;
            pending.done(Outcome::Refused, "too many transfers at once");
            continue;
        };
        let shared = Arc::clone(&shared);
        transfers.spawn(async move {
            let _slot = slot;
            let socket = match transfer_socket(shared.ip, peer).await {
                Ok(socket) => socket,
                Err(err) => {
                    pending.done(Outcome::Failed, &format!("could not open a transfer socket: {err}"));
                    return;
                }
            };
            if request.write {
                write_transfer(&shared, &socket, request, peer, pending).await;
            } else {
                read_transfer(&shared, &socket, request, pending).await;
            }
        });
    }
    // Stopping: every transfer ends now (a half upload is deleted by its guard) and its socket closes.
    transfers.abort_all();
    while transfers.join_next().await.is_some() {}
}

/// The request's file name as sent, for the log (lossy for bytes that aren't UTF-8).
fn request_name(packet: &[u8]) -> String {
    let name = packet.get(2..).unwrap_or_default();
    let name = name.split(|b| *b == 0).next().unwrap_or_default();
    String::from_utf8_lossy(name).into_owned()
}

async fn transfer_socket(ip: IpAddr, peer: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
    socket.connect(peer).await?;
    Ok(socket)
}

async fn send_failure(socket: &UdpSocket, failure: &Failure) {
    let _ = socket.send(&error_packet(failure)).await;
}

/// The block size agreed: the client's `blksize`, or 512.
fn block_size(request: &Request) -> usize {
    request
        .blksize
        .and_then(|b| usize::try_from(b).ok())
        .unwrap_or(DEFAULT_BLOCK)
}

/// Sends `packet` and waits for what `accept` takes, sending it again each time the wait times out, up to the
/// retries. `accept` returns `Some` for the answer it waits for, `None` to go on waiting (a duplicate). `buf` holds a
/// block and its header (a larger datagram is cut short, and then refused as larger than agreed).
async fn exchange<T>(
    buf: &mut [u8],
    shared: &Shared,
    socket: &UdpSocket,
    packet: &[u8],
    mut accept: impl FnMut(Incoming<'_>) -> Result<Option<T>, Broken>,
) -> Result<T, Broken> {
    for _attempt in 0..=shared.tuning.tftp_retries {
        socket.send(packet).await.map_err(gone_or)?;
        let deadline = tokio::time::Instant::now() + shared.tuning.tftp_timeout;
        loop {
            let received = tokio::time::timeout_at(deadline, socket.recv(buf)).await;
            let len = match received {
                Err(_) => break,
                Ok(Ok(len)) => len,
                Ok(Err(err)) => return Err(gone_or(err)),
            };
            if let Some(answer) = accept(parse_incoming(&buf[..len]))? {
                return Ok(answer);
            }
        }
    }
    Err(Broken::TimedOut)
}

fn gone_or(err: std::io::Error) -> Broken {
    if matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
    ) {
        Broken::Gone
    } else {
        Broken::Local(format!("the network failed: {err}"))
    }
}

/// A read request: the file, block by block.
async fn read_transfer(shared: &Arc<Shared>, socket: &UdpSocket, request: Request, mut pending: Pending) {
    let path = match paths::tftp_path(&request.name) {
        Ok(path) => path,
        Err(refused) => {
            send_failure(socket, &refusal_failure(refused)).await;
            pending.done(Outcome::Refused, refused.describe());
            return;
        }
    };
    let served = shared.served.clone();
    let found = tokio::task::spawn_blocking(move || served.find(&path)).await;
    let (file, size, real) = match found {
        Ok(Ok(Found::File { file, size, real, .. })) => (file, size, real),
        Ok(Ok(Found::Folder { .. })) => {
            send_failure(socket, &Failure::new(code::NOT_FOUND, "That is a folder")).await;
            pending.done(Outcome::Refused, "a folder (TFTP sends files only)");
            return;
        }
        Ok(Err(refused)) => {
            send_failure(socket, &refusal_failure(refused)).await;
            pending.done(Outcome::Refused, refused.describe());
            return;
        }
        Err(err) => {
            send_failure(socket, &Failure::new(code::NOT_DEFINED, "Server error")).await;
            pending.done(Outcome::Failed, &err.to_string());
            return;
        }
    };
    if shared.uploads.as_ref().is_some_and(|u| u.is_writing(&real)) {
        send_failure(socket, &Failure::new(code::ACCESS, "Still being uploaded")).await;
        pending.done(Outcome::Refused, "the file is still being uploaded");
        return;
    }
    let block = block_size(&request);
    let blocks = size / block as u64 + 1;
    if blocks > u64::from(MAX_BLOCKS) {
        let message = format!("File too large for TFTP at {block}-byte blocks: ask for a larger blksize, or use HTTP");
        send_failure(socket, &Failure::new(code::NOT_DEFINED, message)).await;
        pending.done(
            Outcome::Refused,
            &format!(
                "{} needs more than 65,535 blocks of {block} bytes (a larger blksize, or HTTP, can send it)",
                size_text(size)
            ),
        );
        return;
    }
    let mut file = tokio::fs::File::from_std(file);
    let mut buf = vec![0u8; DATAGRAM];
    let mut options: Vec<(&str, u64)> = Vec::new();
    if request.blksize.is_some() {
        options.push(("blksize", block as u64));
    }
    if request.tsize.is_some() {
        options.push(("tsize", size));
    }
    if !options.is_empty() {
        let acked = exchange(
            &mut buf,
            shared,
            socket,
            &oack_packet(&options),
            |incoming| match incoming {
                Incoming::Ack(0) => Ok(Some(())),
                Incoming::Error(code, message) => Err(Broken::Client(code, message)),
                _ => Ok(None),
            },
        )
        .await;
        if let Err(broken) = acked {
            pending.done(Outcome::Failed, &broken.describe());
            return;
        }
    }
    let mut chunk = vec![0u8; block];
    let mut number: u16 = 0;
    let mut sent: u64 = 0;
    loop {
        if number == MAX_BLOCKS {
            send_failure(socket, &Failure::new(code::NOT_DEFINED, "File grew past 65535 blocks")).await;
            pending.bytes(sent);
            pending.done(Outcome::Failed, "the file grew past 65,535 blocks while it was sent");
            return;
        }
        number += 1;
        let filled = match fill(&mut file, &mut chunk).await {
            Ok(filled) => filled,
            Err(err) => {
                send_failure(socket, &Failure::new(code::NOT_DEFINED, "Read error")).await;
                pending.bytes(sent);
                pending.done(Outcome::Failed, &format!("could not read the file: {err}"));
                return;
            }
        };
        let packet = data_packet(number, &chunk[..filled]);
        let acked = exchange(&mut buf, shared, socket, &packet, |incoming| match incoming {
            Incoming::Ack(n) if n == number => Ok(Some(())),
            Incoming::Error(code, message) => Err(Broken::Client(code, message)),
            // A duplicate ACK of an earlier block: waiting on, never sending again for it.
            _ => Ok(None),
        })
        .await;
        if let Err(broken) = acked {
            pending.bytes(sent);
            pending.done(Outcome::Failed, &broken.describe());
            return;
        }
        sent += filled as u64;
        pending.bytes(sent);
        if filled < block {
            break;
        }
    }
    pending.done(Outcome::Sent, "");
}

/// Reads until `chunk` is full or the file ends.
async fn fill(file: &mut tokio::fs::File, chunk: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < chunk.len() {
        let n = file.read(&mut chunk[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

fn refusal_failure(refused: Refused) -> Failure {
    match refused {
        Refused::NotFound | Refused::Empty => Failure::new(code::NOT_FOUND, "File not found"),
        other => Failure::new(code::ACCESS, format!("Access violation: {}", other.describe())),
    }
}

fn upload_failure(refused: &UploadRefused) -> Failure {
    match refused {
        UploadRefused::Exists => Failure::new(code::EXISTS, "File already exists"),
        UploadRefused::FileTooLarge(_) | UploadRefused::TotalTooLarge(_) | UploadRefused::TooManyFiles => {
            Failure::new(code::DISK_FULL, "Over the upload limit")
        }
        UploadRefused::Outside => Failure::new(code::ACCESS, "Access violation"),
        UploadRefused::Io(_) => Failure::new(code::NOT_DEFINED, "Write error"),
    }
}

/// A write request: blocks into a new file in the upload folder.
async fn write_transfer(
    shared: &Arc<Shared>,
    socket: &UdpSocket,
    request: Request,
    peer: SocketAddr,
    mut pending: Pending,
) {
    let Some(uploads) = shared.uploads.clone() else {
        send_failure(
            socket,
            &Failure::new(code::ACCESS, "This server doesn't accept uploads"),
        )
        .await;
        pending.done(Outcome::Refused, "uploads are off");
        return;
    };
    let name = match paths::tftp_upload_name(&request.name) {
        Ok(name) => name,
        Err(refused) => {
            send_failure(socket, &refusal_failure(refused)).await;
            pending.done(Outcome::Refused, refused.describe());
            return;
        }
    };
    let block = block_size(&request);
    // A declared size that needs more blocks than there are numbers for is refused before anything is written.
    if let Some(size) = request.tsize {
        if size / block as u64 + 1 > u64::from(MAX_BLOCKS) {
            send_failure(
                socket,
                &Failure::new(code::DISK_FULL, "Too many blocks: use a larger blksize"),
            )
            .await;
            pending.done(Outcome::Refused, "it needs more than 65,535 blocks at this block size");
            return;
        }
    }
    let mut upload = match uploads.claim(&name, request.tsize).await {
        Ok(upload) => upload,
        Err(refused) => {
            send_failure(socket, &upload_failure(&refused)).await;
            pending.done(Outcome::Refused, &refused.describe());
            return;
        }
    };
    let mut options: Vec<(&str, u64)> = Vec::new();
    if request.blksize.is_some() {
        options.push(("blksize", block as u64));
    }
    if let Some(size) = request.tsize {
        options.push(("tsize", size));
    }
    let mut answer = if options.is_empty() {
        ack_packet(0)
    } else {
        oack_packet(&options)
    };
    let mut buf = vec![0u8; DATAGRAM];
    let mut expected: u16 = 1;
    loop {
        let previous = expected.wrapping_sub(1);
        let received = exchange(&mut buf, shared, socket, &answer, |incoming| match incoming {
            Incoming::Data(n, data) if n == expected => Ok(Some(data.to_vec())),
            // Our ACK was lost and the client sent the last block again: the ACK goes out again on the next
            // timeout, as RFC 1350 asks; nothing is written twice.
            Incoming::Data(n, _) if n == previous => Ok(None),
            Incoming::Error(code, message) => Err(Broken::Client(code, message)),
            _ => Ok(None),
        })
        .await;
        let data = match received {
            Ok(data) => data,
            Err(broken) => {
                pending.bytes(upload.written());
                pending.done(
                    Outcome::Failed,
                    &format!("{}; the part received was deleted", broken.describe()),
                );
                return;
            }
        };
        if data.len() > block {
            drop(upload);
            send_failure(socket, &Failure::new(code::ILLEGAL, "Block larger than agreed")).await;
            pending.done(
                Outcome::Failed,
                "a block larger than agreed; the part received was deleted",
            );
            return;
        }
        if let Err(refused) = upload.write(&data).await {
            pending.bytes(upload.written());
            // The part is deleted before the client hears why.
            drop(upload);
            send_failure(socket, &upload_failure(&refused)).await;
            pending.done(
                Outcome::Refused,
                &format!("{}; the part received was deleted", refused.describe()),
            );
            return;
        }
        pending.bytes(upload.written());
        answer = ack_packet(expected);
        if data.len() < block {
            break;
        }
        if expected == MAX_BLOCKS {
            drop(upload);
            send_failure(
                socket,
                &Failure::new(code::DISK_FULL, "Too many blocks: use a larger blksize"),
            )
            .await;
            pending.done(
                Outcome::Refused,
                "more than 65,535 blocks at this block size; the part received was deleted",
            );
            return;
        }
        expected += 1;
    }
    // The last block arrived: the file is kept (written out and marked) before its ACK goes, so a client that hears
    // the ACK finds it whole; the ACK goes again if the client sends that block once more (its ACK was lost), for one
    // timeout.
    let last = expected;
    let bytes = upload.written();
    match upload.finish(&peer.ip().to_string()).await {
        Ok(done) => {
            let _ = socket.send(&answer).await;
            pending.bytes(bytes);
            pending.done(Outcome::Received, done.note.as_deref().unwrap_or(""));
        }
        Err(refused) => {
            send_failure(socket, &upload_failure(&refused)).await;
            pending.done(Outcome::Failed, &refused.describe());
            return;
        }
    }
    let deadline = tokio::time::Instant::now() + shared.tuning.tftp_timeout;
    while let Ok(Ok(len)) = tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
        if matches!(parse_incoming(&buf[..len]), Incoming::Data(n, _) if n == last) {
            let _ = socket.send(&answer).await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn request(op: u16, fields: &[&[u8]]) -> Vec<u8> {
        let mut packet = op.to_be_bytes().to_vec();
        for f in fields {
            packet.extend_from_slice(f);
            packet.push(0);
        }
        packet
    }

    #[test]
    fn requests_and_their_options_are_read() {
        let r = parse_request(&request(
            RRQ,
            &[b"fw.bin", b"octet", b"BLKSIZE", b"1468", b"tsize", b"0"],
        ))
        .unwrap();
        assert_eq!(r.name, b"fw.bin");
        assert!(!r.write);
        assert_eq!(r.blksize, Some(1468));
        assert_eq!(r.tsize, Some(0));
        let w = parse_request(&request(WRQ, &[b"sw1-confg", b"NetASCII"])).unwrap();
        assert!(w.write);
        assert_eq!(w.blksize, None);
        // An unknown option is left out; a huge blksize is brought down to the RFC's largest.
        let r = parse_request(&request(
            RRQ,
            &[b"f", b"octet", b"windowsize", b"16", b"blksize", b"99999"],
        ))
        .unwrap();
        assert_eq!(r.blksize, Some(MAX_BLOCKSIZE));
    }

    #[test]
    fn hostile_requests_are_refused_without_panicking() {
        for packet in [
            vec![],
            vec![0],
            vec![0, 1],
            vec![0, 1, b'f'],
            request(RRQ, &[b"f"]),
            request(RRQ, &[b"", b"octet"]),
            request(RRQ, &[b"f", b"mail"]),
            request(RRQ, &[b"f", b"binary"]),
            request(RRQ, &[b"f", b"octet", b"blksize"]),
            request(RRQ, &[b"f", b"octet", b"blksize", b"4"]),
            request(RRQ, &[b"f", b"octet", b"blksize", b"-1"]),
            request(RRQ, &[b"f", b"octet", b"blksize", b"99999999999999999999999"]),
            request(RRQ, &[b"f", b"octet", b"tsize", b"x"]),
            request(ACK, &[b"f", b"octet"]),
            request(9, &[b"f", b"octet"]),
            request(RRQ, &[b"f", &[0xff, 0xfe]]),
        ] {
            assert!(parse_request(&packet).is_err(), "{packet:?}");
        }
        let many: Vec<&[u8]> = std::iter::once(&b"f"[..])
            .chain(std::iter::once(&b"octet"[..]))
            .chain(std::iter::repeat_n(&b"x"[..], 2 * (MAX_OPTIONS + 1)))
            .collect();
        assert!(parse_request(&request(RRQ, &many)).is_err());
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let _ = parse_request(&junk);
            let _ = parse_incoming(&junk);
        }
    }

    #[test]
    fn error_packets_are_ascii_and_short() {
        let packet = error_packet(&Failure::new(1, "Not found \u{202E} ".repeat(20)));
        assert_eq!(&packet[..4], &[0, 5, 0, 1]);
        assert!(packet.len() <= 4 + 120 + 1);
        assert_eq!(packet.last(), Some(&0));
        assert!(packet[4..packet.len() - 1].iter().all(|b| b.is_ascii() && *b != 0));
    }
}
