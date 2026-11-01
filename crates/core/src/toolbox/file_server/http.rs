//! FD-09: HTTP/1.1, GET and HEAD for files and folder listings, and PUT for uploads when they are on. One request a
//! connection (`Connection: close`), which keeps every bound simple:
//!
//! * at most [`super::FileServerTuning::max_http`] connections at once, fewer per client; one past the cap is closed
//!   at once;
//! * the request's head (request line and headers) must arrive whole within
//!   [`super::FileServerTuning::http_head`] (no slowloris), at most [`MAX_HEAD`] bytes, [`MAX_HEADERS`] headers and a
//!   target of [`MAX_TARGET`] bytes;
//! * each read of an upload's body and each write of a response must make progress within
//!   [`super::FileServerTuning::http_idle`];
//! * a PUT needs a `Content-Length` (chunked bodies are refused), which the caps are checked against before any byte
//!   is read; `Expect: 100-continue` is answered once the upload is accepted;
//! * `Host` must name the address and port it listens on ([`check_host`]), so a web page can't reach it through DNS
//!   rebinding (421 Misdirected Request).
//!
//! Requests are parsed by `httparse` (the parser hyper uses, already in the tree with reqwest). Files go out with
//! `Content-Type`, `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`; a listing escapes every
//! name and has a `Content-Security-Policy` that allows no script.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::log::{self, Outcome, Protocol};
use super::paths::{self, Refused, RequestPath};
use super::served::{Found, Listing};
use super::uploads::{size_text, Upload, UploadRefused};
use super::{Pending, Shared, Slots};

/// The most bytes a request's head may take.
pub const MAX_HEAD: usize = 16 * 1024;
/// The most headers a request may have.
pub const MAX_HEADERS: usize = 32;
/// The longest request target, in bytes.
pub const MAX_TARGET: usize = 4096;
/// What a response or an upload moves at a time.
const CHUNK: usize = 64 * 1024;
/// After a response, what is read and dropped (so the client sees the response, not a reset) before closing.
const LINGER_BYTES: usize = 256 * 1024;
const LINGER: Duration = Duration::from_secs(1);

/// A request's head, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    pub target: String,
    /// Header names in lower case, values as sent.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Where the body starts in what was read.
    pub len: usize,
    /// HTTP/1.0 (else 1.1).
    pub http10: bool,
}

/// Why a request's `Host` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRefused {
    /// HTTP/1.1 without one (RFC 9112 requires it).
    Missing,
    /// More than one.
    Repeated,
    /// Not the address and port the server listens on: a web page reaching it by a name of its own (DNS rebinding).
    Elsewhere,
}

impl HostRefused {
    fn status(self) -> u16 {
        match self {
            HostRefused::Missing | HostRefused::Repeated => 400,
            HostRefused::Elsewhere => 421,
        }
    }

    fn describe(self) -> &'static str {
        match self {
            HostRefused::Missing => "no Host header (HTTP/1.1 needs one)",
            HostRefused::Repeated => "more than one Host header",
            HostRefused::Elsewhere => {
                "the Host header doesn't name this server's address and port (a web page could be reaching it by a \
                 name of its own: DNS rebinding)"
            }
        }
    }
}

/// DNS rebinding: a web page the user opens can make its own name resolve to this server's address, and then read
/// (and write) what is served as if it were its own site. Its requests carry its name in `Host`, so a request is
/// served only when `Host` is the address the server listens on, as an IP literal (IPv6 in brackets), with the port
/// (which may be left out only for port 80); compared as addresses, so letter case and IPv6 spellings don't matter.
/// An HTTP/1.0 request without `Host` is served: browsers always send one, and firmware loaders such as U-Boot's
/// `wget` send none.
pub fn check_host(head: &Head, at: SocketAddr) -> Result<(), HostRefused> {
    match head.all("host").as_slice() {
        [] if head.http10 => Ok(()),
        [] => Err(HostRefused::Missing),
        [one] if host_names(one, at) => Ok(()),
        [_] => Err(HostRefused::Elsewhere),
        _ => Err(HostRefused::Repeated),
    }
}

/// Whether a `Host` value is `at`'s address and port.
fn host_names(value: &[u8], at: SocketAddr) -> bool {
    let Ok(text) = std::str::from_utf8(value) else {
        return false;
    };
    let text = text.trim();
    let (address, port): (Option<IpAddr>, Option<&str>) = if let Some(rest) = text.strip_prefix('[') {
        let Some((inside, after)) = rest.split_once(']') else {
            return false;
        };
        let port = match after {
            "" => None,
            other => match other.strip_prefix(':') {
                Some(port) => Some(port),
                None => return false,
            },
        };
        (inside.parse::<Ipv6Addr>().ok().map(IpAddr::V6), port)
    } else {
        match text.split_once(':') {
            Some((host, port)) => (host.parse::<Ipv4Addr>().ok().map(IpAddr::V4), Some(port)),
            None => (text.parse::<Ipv4Addr>().ok().map(IpAddr::V4), None),
        }
    };
    let port_fits = match port {
        None => at.port() == 80,
        Some(port) => {
            port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().ok() == Some(at.port())
        }
    };
    address == Some(at.ip()) && port_fits
}

impl Head {
    fn all(&self, name: &str) -> Vec<&[u8]> {
        self.headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
            .collect()
    }

    fn has(&self, name: &str) -> bool {
        self.headers.iter().any(|(n, _)| n == name)
    }
}

/// Why no head could be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadError {
    /// The client closed without sending anything (a port check, a scanner): not logged.
    Closed,
    /// It closed halfway.
    Incomplete,
    TooLarge,
    TooManyHeaders,
    Bad,
}

/// Parses `buf` if it holds a whole head. `Ok(None)`: more is needed.
pub fn parse_head(buf: &[u8]) -> Result<Option<Head>, HeadError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(buf) {
        Ok(httparse::Status::Complete(len)) => {
            if len > MAX_HEAD {
                return Err(HeadError::TooLarge);
            }
            let (Some(method), Some(target)) = (request.method, request.path) else {
                return Err(HeadError::Bad);
            };
            Ok(Some(Head {
                method: method.to_owned(),
                target: target.to_owned(),
                headers: request
                    .headers
                    .iter()
                    .map(|h| (h.name.to_ascii_lowercase(), h.value.to_vec()))
                    .collect(),
                len,
                http10: request.version == Some(0),
            }))
        }
        Ok(httparse::Status::Partial) if buf.len() > MAX_HEAD => Err(HeadError::TooLarge),
        Ok(httparse::Status::Partial) => Ok(None),
        Err(httparse::Error::TooManyHeaders) => Err(HeadError::TooManyHeaders),
        Err(_) => Err(HeadError::Bad),
    }
}

async fn read_head(stream: &mut TcpStream) -> Result<(Vec<u8>, Head), HeadError> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|_| HeadError::Incomplete)?;
        if n == 0 {
            return Err(if buf.is_empty() {
                HeadError::Closed
            } else {
                HeadError::Incomplete
            });
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(head) = parse_head(&buf)? {
            return Ok((buf, head));
        }
    }
}

/// Serves connections on `listener` until `stop`; every connection ends with it.
pub(super) async fn serve(listener: TcpListener, shared: Arc<Shared>, stop: CancellationToken) {
    let slots = Arc::new(Slots::new(shared.tuning.max_http, shared.tuning.max_http_per_client));
    let mut connections = JoinSet::new();
    loop {
        while connections.try_join_next().is_some() {}
        let accepted = tokio::select! {
            () = stop.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(error = %err, "the HTTP socket failed to accept a connection");
                tokio::select! {
                    () = stop.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_millis(100)) => continue,
                }
            }
        };
        // Past the cap the connection closes at once, unlogged: a flood must not fill the log or the memory.
        let Some(slot) = slots.take(peer.ip()) else {
            drop(stream);
            continue;
        };
        let _ = stream.set_nodelay(true);
        let shared = Arc::clone(&shared);
        connections.spawn(async move {
            let _slot = slot;
            connection(&shared, stream, peer).await;
        });
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn connection(shared: &Arc<Shared>, mut stream: TcpStream, peer: SocketAddr) {
    let tuning = shared.tuning;
    let head = tokio::time::timeout(tuning.http_head, read_head(&mut stream)).await;
    let (buf, head) = match head {
        Ok(Ok(read)) => read,
        Ok(Err(HeadError::Closed)) => return,
        failed => {
            let mut pending = Pending::new(shared, log::entry(Protocol::Http, peer, "?", ""));
            let (status, detail) = match failed {
                Err(_) => (
                    408,
                    format!(
                        "the request didn't arrive within {} seconds",
                        tuning.http_head.as_secs().max(1)
                    ),
                ),
                Ok(Err(HeadError::TooLarge)) => (431, format!("the request's head is over {} KB", MAX_HEAD / 1024)),
                Ok(Err(HeadError::TooManyHeaders)) => (431, format!("more than {MAX_HEADERS} headers")),
                Ok(Err(HeadError::Incomplete)) => {
                    pending.done(Outcome::Failed, "the client closed before the request was whole");
                    return;
                }
                _ => (400, "not an HTTP request".to_owned()),
            };
            let _ = respond_text(&mut stream, &tuning, status, &[], &format!("{detail}\n")).await;
            pending.done(Outcome::Refused, &detail);
            close(stream).await;
            return;
        }
    };
    let method = if head.method.len() <= 16 && head.method.bytes().all(|b| b.is_ascii_uppercase()) {
        head.method.clone()
    } else {
        "?".to_owned()
    };
    let raw_path = head.target.split(['?', '#']).next().unwrap_or_default();
    let shown = paths::percent_decode(raw_path).unwrap_or_else(|_| raw_path.to_owned());
    let mut pending = Pending::new(shared, log::entry(Protocol::Http, peer, &method, &shown));
    if head.target.len() > MAX_TARGET {
        let _ = respond_text(&mut stream, &tuning, 414, &[], "The address is too long.\n").await;
        pending.done(Outcome::Refused, "the address is too long");
        close(stream).await;
        return;
    }
    if let Some(at) = shared.http_at {
        if let Err(refused) = check_host(&head, at) {
            let status = refused.status();
            let _ = respond_text(&mut stream, &tuning, status, &[], &format!("{}.\n", refused.describe())).await;
            pending.done(Outcome::Refused, refused.describe());
            close(stream).await;
            return;
        }
    }
    match method.as_str() {
        "GET" | "HEAD" => get(shared, &mut stream, &head, method == "HEAD", &mut pending).await,
        "PUT" if shared.uploads.is_some() => {
            let body = buf.get(head.len..).unwrap_or_default().to_vec();
            put(shared, &mut stream, &head, body, peer, &mut pending).await;
        }
        _ => {
            let allow = if shared.uploads.is_some() {
                "GET, HEAD, PUT"
            } else {
                "GET, HEAD"
            };
            let _ = respond_text(
                &mut stream,
                &tuning,
                405,
                &[("Allow", allow.to_owned())],
                &format!("This server takes {allow}.\n"),
            )
            .await;
            pending.done(Outcome::Refused, &format!("only {allow}"));
        }
    }
    close(stream).await;
}

/// Ends the connection: no more writes, then what the client still sends is read and dropped for a moment, so it
/// reads the response instead of a reset.
async fn close(mut stream: TcpStream) {
    let _ = stream.shutdown().await;
    let mut sink = [0u8; 8192];
    let mut dropped = 0usize;
    let _ = tokio::time::timeout(LINGER, async {
        while dropped < LINGER_BYTES {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => dropped += n,
            }
        }
    })
    .await;
}

fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        301 => "Moved Permanently",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        _ => "Internal Server Error",
    }
}

/// The status line and headers, with what every response carries.
pub fn response_head(status: u16, headers: &[(&str, String)]) -> Vec<u8> {
    let mut text = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in headers {
        // Values are built here, never from a request, but a line break must never reach the wire.
        let value: String = value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    text.push_str("X-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n");
    text.into_bytes()
}

async fn write_timed(stream: &mut TcpStream, idle: Duration, bytes: &[u8]) -> std::io::Result<()> {
    match tokio::time::timeout(idle, stream.write_all(bytes)).await {
        Ok(written) => written,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the client stopped reading",
        )),
    }
}

async fn respond_text(
    stream: &mut TcpStream,
    tuning: &super::FileServerTuning,
    status: u16,
    extra: &[(&str, String)],
    body: &str,
) -> std::io::Result<()> {
    let mut headers: Vec<(&str, String)> = vec![
        ("Content-Type", "text/plain; charset=utf-8".to_owned()),
        ("Content-Length", body.len().to_string()),
    ];
    headers.extend(extra.iter().cloned());
    let mut bytes = response_head(status, &headers);
    bytes.extend_from_slice(body.as_bytes());
    write_timed(stream, tuning.http_idle, &bytes).await
}

fn refusal_status(refused: Refused) -> u16 {
    match refused {
        Refused::NotFound | Refused::Empty => 404,
        Refused::Encoding => 400,
        _ => 403,
    }
}

async fn refuse(stream: &mut TcpStream, shared: &Shared, pending: &mut Pending, refused: Refused) {
    let status = refusal_status(refused);
    let body = if status == 404 {
        "Not found.\n".to_owned()
    } else {
        format!("Refused: {}.\n", refused.describe())
    };
    let _ = respond_text(stream, &shared.tuning, status, &[], &body).await;
    pending.done(Outcome::Refused, refused.describe());
}

/// GET and HEAD.
async fn get(shared: &Arc<Shared>, stream: &mut TcpStream, head: &Head, head_only: bool, pending: &mut Pending) {
    let path = match paths::http_path(&head.target) {
        Ok(path) => path,
        Err(refused) => return refuse(stream, shared, pending, refused).await,
    };
    let served = shared.served.clone();
    let wanted = path.clone();
    let found = match tokio::task::spawn_blocking(move || served.find(&wanted)).await {
        Ok(Ok(found)) => found,
        Ok(Err(refused)) => return refuse(stream, shared, pending, refused).await,
        Err(err) => {
            let _ = respond_text(stream, &shared.tuning, 500, &[], "Server error.\n").await;
            pending.done(Outcome::Failed, &err.to_string());
            return;
        }
    };
    match found {
        Found::File { file, size, name, real } => {
            if shared.uploads.as_ref().is_some_and(|u| u.is_writing(&real)) {
                let _ = respond_text(stream, &shared.tuning, 409, &[], "Still being uploaded.\n").await;
                pending.done(Outcome::Refused, "the file is still being uploaded");
                return;
            }
            pending.transfer();
            send_file(
                shared,
                stream,
                tokio::fs::File::from_std(file),
                size,
                &name,
                head_only,
                pending,
            )
            .await;
        }
        Found::Folder { path: folder } => {
            if !path.folder {
                // `/images` to `/images/`, so the listing's links resolve under it.
                let location = RequestPath {
                    parts: path.parts.clone(),
                    folder: true,
                }
                .encoded();
                let _ = respond_text(stream, &shared.tuning, 301, &[("Location", location)], "Moved.\n").await;
                pending.done(Outcome::Sent, "a folder: sent on to its address with a /");
                return;
            }
            let served = shared.served.clone();
            let listing = match tokio::task::spawn_blocking(move || served.list(&folder)).await {
                Ok(Ok(listing)) => listing,
                _ => {
                    let _ = respond_text(stream, &shared.tuning, 404, &[], "Not found.\n").await;
                    pending.done(Outcome::Refused, "the folder can't be read");
                    return;
                }
            };
            pending.transfer();
            let html = listing_html(&path, &listing);
            let headers = [
                ("Content-Type", "text/html; charset=utf-8".to_owned()),
                ("Content-Length", html.len().to_string()),
                (
                    "Content-Security-Policy",
                    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'".to_owned(),
                ),
                ("X-Frame-Options", "DENY".to_owned()),
            ];
            let mut bytes = response_head(200, &headers);
            if !head_only {
                bytes.extend_from_slice(html.as_bytes());
            }
            match write_timed(stream, shared.tuning.http_idle, &bytes).await {
                Ok(()) => {
                    pending.bytes(if head_only { 0 } else { html.len() as u64 });
                    let entries = log::plural(listing.entries.len() as u64, "entry", "entries");
                    pending.done(Outcome::Sent, &format!("a folder listing of {entries}"));
                }
                Err(err) => pending.done(Outcome::Failed, &err.to_string()),
            }
        }
    }
}

async fn send_file(
    shared: &Shared,
    stream: &mut TcpStream,
    mut file: tokio::fs::File,
    size: u64,
    name: &str,
    head_only: bool,
    pending: &mut Pending,
) {
    let headers = [
        ("Content-Type", content_type(name).to_owned()),
        ("Content-Length", size.to_string()),
        ("Content-Disposition", content_disposition(name)),
    ];
    let idle = shared.tuning.http_idle;
    if let Err(err) = write_timed(stream, idle, &response_head(200, &headers)).await {
        pending.done(Outcome::Failed, &err.to_string());
        return;
    }
    if head_only {
        pending.done(Outcome::Sent, "the headers only (HEAD)");
        return;
    }
    let mut chunk = vec![0u8; CHUNK];
    let mut sent: u64 = 0;
    // Exactly the length announced, even if the file changes meanwhile.
    while sent < size {
        let want = usize::try_from((size - sent).min(CHUNK as u64)).unwrap_or(CHUNK);
        let n = match file.read(&mut chunk[..want]).await {
            Ok(0) => {
                pending.done(Outcome::Failed, "the file got shorter while it was sent");
                return;
            }
            Ok(n) => n,
            Err(err) => {
                pending.done(Outcome::Failed, &format!("could not read the file: {err}"));
                return;
            }
        };
        if let Err(err) = write_timed(stream, idle, &chunk[..n]).await {
            pending.done(Outcome::Failed, &err.to_string());
            return;
        }
        sent += n as u64;
        pending.bytes(sent);
    }
    pending.done(Outcome::Sent, "");
}

/// PUT: a new file in the upload folder.
async fn put(
    shared: &Arc<Shared>,
    stream: &mut TcpStream,
    head: &Head,
    mut body: Vec<u8>,
    peer: SocketAddr,
    pending: &mut Pending,
) {
    let tuning = shared.tuning;
    let Some(uploads) = shared.uploads.clone() else {
        return;
    };
    if head.has("transfer-encoding") {
        let _ = respond_text(stream, &tuning, 501, &[], "Send the file with a Content-Length.\n").await;
        pending.done(Outcome::Refused, "a chunked body (only a Content-Length is taken)");
        return;
    }
    let lengths = head.all("content-length");
    let length = match lengths.as_slice() {
        [] => {
            let _ = respond_text(stream, &tuning, 411, &[], "Send the file with a Content-Length.\n").await;
            pending.done(Outcome::Refused, "no Content-Length");
            return;
        }
        [one] => std::str::from_utf8(one)
            .ok()
            .map(str::trim)
            .filter(|v| !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|v| v.parse::<u64>().ok()),
        _ => None,
    };
    let Some(length) = length else {
        let _ = respond_text(stream, &tuning, 400, &[], "A bad Content-Length.\n").await;
        pending.done(Outcome::Refused, "a bad or repeated Content-Length");
        return;
    };
    let expect = head.all("expect");
    let continues = match expect.as_slice() {
        [] => false,
        [one] if one.eq_ignore_ascii_case(b"100-continue") => true,
        _ => {
            let _ = respond_text(stream, &tuning, 417, &[], "Only Expect: 100-continue is understood.\n").await;
            pending.done(Outcome::Refused, "an Expect header other than 100-continue");
            return;
        }
    };
    let name = match paths::http_upload_name(&head.target) {
        Ok(name) => name,
        Err(refused) => return refuse(stream, shared, pending, refused).await,
    };
    let mut upload = match uploads.claim(&name, Some(length), peer.ip()).await {
        Ok(upload) => upload,
        Err(refused) => {
            let status = upload_status(&refused);
            let _ = respond_text(
                stream,
                &tuning,
                status,
                &[],
                &format!("Refused: {}.\n", refused.describe()),
            )
            .await;
            pending.done(Outcome::Refused, &refused.describe());
            return;
        }
    };
    pending.transfer();
    if continues {
        if let Err(err) = write_timed(stream, tuning.http_idle, b"HTTP/1.1 100 Continue\r\n\r\n").await {
            pending.done(Outcome::Failed, &err.to_string());
            return;
        }
    }
    // What came with the head first, then the rest; nothing past the length is taken.
    body.truncate(usize::try_from(length).unwrap_or(usize::MAX).min(body.len()));
    let mut received = body.len() as u64;
    if let Err(refused) = upload.write(&body).await {
        return cut_off(stream, shared, pending, (&refused, upload), received).await;
    }
    let mut chunk = vec![0u8; CHUNK];
    while received < length {
        let want = usize::try_from((length - received).min(CHUNK as u64)).unwrap_or(CHUNK);
        let read = tokio::time::timeout(tuning.http_idle, stream.read(&mut chunk[..want])).await;
        let n = match read {
            Ok(Ok(0)) | Ok(Err(_)) => {
                pending.bytes(received);
                pending.done(
                    Outcome::Failed,
                    &format!(
                        "the upload stopped after {} of {}; the part received was deleted",
                        size_text(received),
                        size_text(length)
                    ),
                );
                return;
            }
            Err(_) => {
                pending.bytes(received);
                pending.done(
                    Outcome::Failed,
                    &format!(
                        "nothing arrived for {} seconds; the part received was deleted",
                        tuning.http_idle.as_secs().max(1)
                    ),
                );
                return;
            }
            Ok(Ok(n)) => n,
        };
        if let Err(refused) = upload.write(&chunk[..n]).await {
            return cut_off(stream, shared, pending, (&refused, upload), received).await;
        }
        received += n as u64;
        pending.bytes(received);
    }
    match upload.finish(&peer.ip().to_string()).await {
        Ok(done) => {
            let body = format!("Received {} ({}).\n", done.name, size_text(done.bytes));
            let _ = respond_text(stream, &tuning, 201, &[], &body).await;
            pending.bytes(done.bytes);
            pending.done(Outcome::Received, done.note.as_deref().unwrap_or(""));
        }
        Err(refused) => {
            let _ = respond_text(stream, &tuning, 500, &[], "The file could not be written.\n").await;
            pending.done(Outcome::Failed, &refused.describe());
        }
    }
}

/// The status an upload's refusal answers with.
fn upload_status(refused: &UploadRefused) -> u16 {
    match refused {
        UploadRefused::Exists => 409,
        UploadRefused::FileTooLarge(_) | UploadRefused::TotalTooLarge(_) | UploadRefused::TooManyFiles => 413,
        UploadRefused::ClientBusy(_) => 429,
        UploadRefused::TooSlow { .. } => 408,
        UploadRefused::Outside => 403,
        UploadRefused::Io(_) => 500,
    }
}

/// An upload refused part way: its part is deleted (the upload dropped) before the client hears why.
async fn cut_off(
    stream: &mut TcpStream,
    shared: &Shared,
    pending: &mut Pending,
    (refused, upload): (&UploadRefused, Upload),
    received: u64,
) {
    drop(upload);
    let status = upload_status(refused);
    let _ = respond_text(
        stream,
        &shared.tuning,
        status,
        &[],
        &format!("Refused: {}.\n", refused.describe()),
    )
    .await;
    pending.bytes(received);
    pending.done(
        Outcome::Refused,
        &format!("{}; the part received was deleted", refused.describe()),
    );
}

/// The type a file is sent as. Anything that could run in a browser goes as plain bytes; every file is an attachment
/// anyway.
pub fn content_type(name: &str) -> &'static str {
    let extension = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "txt" | "cfg" | "conf" | "log" | "ini" | "csv" | "md" => "text/plain; charset=utf-8",
        "json" => "application/json",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        "iso" => "application/x-iso9660-image",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// `attachment; filename="..."; filename*=UTF-8''...`: an ASCII name for old clients, the real one encoded.
pub fn content_disposition(name: &str) -> String {
    let ascii: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "attachment; filename=\"{ascii}\"; filename*=UTF-8''{}",
        paths::percent_encode(name)
    )
}

/// Escapes text for HTML: `&`, `<`, `>`, `"` and `'`.
pub fn escape_html(text: &str) -> String {
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

/// A folder's listing: every name escaped, every link percent-encoded and relative.
pub fn listing_html(path: &RequestPath, listing: &Listing) -> String {
    let title = escape_html(&format!("/{}", path.display()));
    let mut html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
         content=\"width=device-width\"><title>{title}</title><style>body{{font:14px system-ui,sans-serif;\
         margin:2em}}td{{padding:2px 16px 2px 0}}td.s{{text-align:right;color:#666}}</style></head><body>\
         <h1>{title}</h1><table>"
    );
    if !path.parts.is_empty() {
        html.push_str("<tr><td><a href=\"../\">../</a></td><td></td></tr>");
    }
    for entry in &listing.entries {
        let (href, text, size) = if entry.folder {
            (
                format!("{}/", paths::percent_encode(&entry.name)),
                format!("{}/", escape_html(&entry.name)),
                String::new(),
            )
        } else {
            (
                paths::percent_encode(&entry.name),
                escape_html(&entry.name),
                size_text(entry.size),
            )
        };
        html.push_str(&format!(
            "<tr><td><a href=\"{href}\">{text}</a></td><td class=\"s\">{size}</td></tr>"
        ));
    }
    html.push_str("</table>");
    if listing.more > 0 {
        html.push_str(&format!(
            "<p>{} more not listed.</p>",
            log::plural(listing.more as u64, "entry", "entries")
        ));
    }
    html.push_str("</body></html>");
    html
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::served::ListEntry;
    use super::*;

    #[test]
    fn heads_are_parsed_and_bounded() {
        let head = parse_head(b"GET /fw.bin HTTP/1.1\r\nHost: 192.0.2.10\r\nX-A: b\r\n\r\nrest")
            .unwrap()
            .unwrap();
        assert_eq!(head.method, "GET");
        assert_eq!(head.target, "/fw.bin");
        assert_eq!(head.headers[0], ("host".to_owned(), b"192.0.2.10".to_vec()));
        assert_eq!(head.len, 50);
        assert_eq!(parse_head(b"GET /fw.bin HTTP/1.1\r\nHost: x").unwrap(), None);
        let mut many = String::from("GET / HTTP/1.1\r\n");
        for i in 0..=MAX_HEADERS {
            many.push_str(&format!("X-{i}: y\r\n"));
        }
        many.push_str("\r\n");
        assert_eq!(parse_head(many.as_bytes()), Err(HeadError::TooManyHeaders));
        let long = format!("GET /{} HTTP/1.1\r\n", "a".repeat(MAX_HEAD));
        assert_eq!(parse_head(long.as_bytes()), Err(HeadError::TooLarge));
        for bad in [
            &b"\x16\x03\x01\x02\x00\r\n\r\n"[..],
            b"GET\r\n\r\n",
            b"G\0T / HTTP/1.1\r\n\r\n",
        ] {
            assert!(parse_head(bad).is_err(), "{bad:?}");
        }
        for len in 0..200 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 131 % 256) as u8).collect();
            let _ = parse_head(&junk);
        }
    }

    fn host_of(request: &str, at: &str) -> Result<(), HostRefused> {
        let head = parse_head(request.as_bytes()).unwrap().unwrap();
        check_host(&head, at.parse().unwrap())
    }

    #[test]
    fn only_the_servers_own_address_and_port_are_a_host() {
        let at = "192.0.2.10:8080";
        assert_eq!(host_of("GET / HTTP/1.1\r\nHost: 192.0.2.10:8080\r\n\r\n", at), Ok(()));
        assert_eq!(host_of("GET / HTTP/1.1\r\nhost:  192.0.2.10:8080 \r\n\r\n", at), Ok(()));
        for host in [
            "attacker.example:8080",
            "ATTACKER.example",
            "192.0.2.10",
            "192.0.2.10:80",
            "192.0.2.10:08080x",
            "192.0.2.11:8080",
            "192.000.002.010:8080",
            "3221225994:8080",
            "localhost:8080",
            "[::ffff:192.0.2.10]:8080",
            "alice@192.0.2.10:8080",
            "192.0.2.10:8080.attacker.example",
            "",
        ] {
            let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            assert_eq!(host_of(&request, at), Err(HostRefused::Elsewhere), "{host}");
        }
        assert_eq!(host_of("GET / HTTP/1.1\r\n\r\n", at), Err(HostRefused::Missing));
        assert_eq!(
            host_of(
                "GET / HTTP/1.1\r\nHost: 192.0.2.10:8080\r\nHost: attacker.example\r\n\r\n",
                at
            ),
            Err(HostRefused::Repeated)
        );
        // HTTP/1.0 without one (U-Boot's wget); with one, it is checked like any.
        assert_eq!(host_of("GET /fw.bin HTTP/1.0\r\n\r\n", at), Ok(()));
        assert_eq!(
            host_of("GET /fw.bin HTTP/1.0\r\nHost: attacker.example\r\n\r\n", at),
            Err(HostRefused::Elsewhere)
        );
        // Port 80 may be left out; IPv6 in brackets, in any spelling.
        assert_eq!(
            host_of("GET / HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n", "192.0.2.10:80"),
            Ok(())
        );
        let v6 = "[2001:db8::10]:8080";
        assert_eq!(
            host_of("GET / HTTP/1.1\r\nHost: [2001:DB8:0::10]:8080\r\n\r\n", v6),
            Ok(())
        );
        assert_eq!(
            host_of("GET / HTTP/1.1\r\nHost: 2001:db8::10:8080\r\n\r\n", v6),
            Err(HostRefused::Elsewhere)
        );
        assert_eq!(
            host_of("GET / HTTP/1.1\r\nHost: [2001:db8::10]\r\n\r\n", v6),
            Err(HostRefused::Elsewhere)
        );
    }

    #[test]
    fn listings_escape_every_name() {
        let path = paths::http_path("/a%20b/").unwrap();
        let listing = Listing {
            entries: vec![
                ListEntry {
                    name: "<script>alert(1)</script>.bin".into(),
                    folder: false,
                    size: 2048,
                },
                ListEntry {
                    name: "x\" onclick=\"y".into(),
                    folder: true,
                    size: 0,
                },
            ],
            more: 2,
        };
        let html = listing_html(&path, &listing);
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;.bin"));
        assert!(html.contains("href=\"%3Cscript%3Ealert%281%29%3C%2Fscript%3E.bin\""));
        assert!(html.contains("x&quot; onclick=&quot;y/"));
        assert!(!html.contains("onclick=\"y"));
        assert!(html.contains("<title>/a b/</title>"));
        assert!(html.contains("2 entries more not listed"));
    }

    #[test]
    fn files_go_as_attachments_that_never_run() {
        assert_eq!(content_type("fw.BIN"), "application/octet-stream");
        assert_eq!(content_type("page.html"), "application/octet-stream");
        assert_eq!(content_type("image.svg"), "application/octet-stream");
        assert_eq!(content_type("switch.cfg"), "text/plain; charset=utf-8");
        assert_eq!(
            content_disposition("café \"v2\".bin"),
            "attachment; filename=\"caf_ _v2_.bin\"; filename*=UTF-8''caf%C3%A9%20%22v2%22.bin"
        );
        let head = String::from_utf8(response_head(200, &[("X-Test", "a\r\nSet-Cookie: x".into())])).unwrap();
        assert!(head.contains("X-Test: aSet-Cookie: x\r\n"));
        assert!(head.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(head.ends_with("Connection: close\r\n\r\n"));
    }
}
