//! F4: a WinRM endpoint on 127.0.0.1 for tests and `dev_ssh_server`: WS-Management shells (create, command, send,
//! receive, signal, delete) over its own small HTTP/1.1 server, signed in with
//!
//! * Basic over HTTPS (a certificate made at run time with rcgen, never committed), or
//! * NTLM ([`ntlm`], checked against MS-NLMP's published values) over HTTP, every message after the sign-in sealed
//!   both ways, or over HTTPS.
//!
//! Its "PowerShell" is a toy that knows the lines Remotely sends: the console's prompt marker, `Read-Host`,
//! `Start-Sleep` (Ctrl+C ends it), `Set-Location`, `exit`, a few commands, and the guest metrics, host facts and service
//! reads by the comment line each starts with (answered from [`crate::metrics::windows::sample`] and
//! [`crate::host_details::windows::sample`]). Nothing here reaches a real Windows host.

pub mod ntlm;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::adapters::winrm::encryption;
use crate::convert::describe::{parse_xml_limited, Element, XmlLimits};
use crate::locks;

/// How the fake signs clients in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeWinrm {
    /// HTTPS with Basic.
    HttpsBasic,
    /// HTTP with NTLM, sealed.
    HttpNtlm,
    /// HTTPS with NTLM (not sealed: TLS protects it).
    HttpsNtlm,
}

impl FakeWinrm {
    fn https(self) -> bool {
        !matches!(self, FakeWinrm::HttpNtlm)
    }
}

/// What the fake saw, for tests.
#[derive(Debug, Clone, Default)]
pub struct WinrmStats {
    pub sign_ins: usize,
    pub refused_sign_ins: usize,
    pub shells_created: usize,
    pub shells_deleted: usize,
    /// Each command's program and arguments.
    pub commands: Vec<String>,
    /// Each stdin line, as received.
    pub stdin: Vec<String>,
    /// Requests over HTTP that came in clear text after the sign-in (refused).
    pub plain_refused: usize,
    /// Signals by their last path part (`ctrl_c`, `terminate`).
    pub signals: Vec<String>,
    /// Guest metrics reads answered.
    pub metrics_reads: u64,
}

/// A shell's commands, by id.
type Commands = HashMap<String, Arc<Mutex<Proc>>>;

struct Shared {
    mode: FakeWinrm,
    user: String,
    password: Mutex<String>,
    shells: Mutex<HashMap<String, Commands>>,
    services: Mutex<HashMap<String, String>>,
    stats: Mutex<WinrmStats>,
    round: AtomicU64,
    refusing: AtomicBool,
    drop_all: broadcast::Sender<()>,
}

/// A WinRM endpoint on 127.0.0.1. Stops when dropped.
pub struct WinrmTestServer {
    port: u16,
    certificate: Option<Vec<u8>>,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl Drop for WinrmTestServer {
    fn drop(&mut self) {
        self.task.abort();
        let _ = self.shared.drop_all.send(());
    }
}

impl WinrmTestServer {
    /// Listens on 127.0.0.1 and a free port.
    pub async fn start(mode: FakeWinrm, user: &str, password: &str) -> std::io::Result<Self> {
        Self::start_on(0, mode, user, password).await
    }

    /// Listens on 127.0.0.1 and `port` (0: a free one).
    pub async fn start_on(port: u16, mode: FakeWinrm, user: &str, password: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        let port = listener.local_addr()?.port();
        let (drop_all, _) = broadcast::channel(4);
        let shared = Arc::new(Shared {
            mode,
            user: user.to_owned(),
            password: Mutex::new(password.to_owned()),
            shells: Mutex::default(),
            services: Mutex::new(
                [
                    ("Spooler", "Running"),
                    ("W3SVC", "Running"),
                    ("MSSQL$SQLEXPRESS", "Stopped"),
                ]
                .into_iter()
                .map(|(n, s)| (n.to_ascii_lowercase(), s.to_owned()))
                .collect(),
            ),
            stats: Mutex::default(),
            round: AtomicU64::new(0),
            refusing: AtomicBool::new(false),
            drop_all,
        });
        let (acceptor, certificate) = if mode.https() {
            let (acceptor, der) = tls_acceptor().map_err(std::io::Error::other)?;
            (Some(acceptor), Some(der))
        } else {
            (None, None)
        };
        let task = tokio::spawn(accept_loop(listener, Arc::clone(&shared), acceptor));
        Ok(Self {
            port,
            certificate,
            shared,
            task,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn address(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// The HTTPS certificate's DER (none over HTTP).
    pub fn certificate(&self) -> Option<&[u8]> {
        self.certificate.as_deref()
    }

    /// The certificate's fingerprint as Remotely writes it (`SHA256:...`).
    pub fn fingerprint(&self) -> Option<String> {
        self.certificate
            .as_deref()
            .map(crate::adapters::winrm::http::fingerprint)
    }

    pub fn stats(&self) -> WinrmStats {
        locks::lock(&self.shared.stats).clone()
    }

    /// Shells open now.
    pub fn open_shells(&self) -> usize {
        locks::lock(&self.shared.shells).len()
    }

    /// The account's password from now on (a rotated password).
    pub fn set_password(&self, password: &str) {
        *locks::lock(&self.shared.password) = password.to_owned();
    }

    /// A service and its status (`Running`, `Stopped`...), or none.
    pub fn set_service(&self, name: &str, status: Option<&str>) {
        let mut services = locks::lock(&self.shared.services);
        match status {
            Some(status) => {
                services.insert(name.to_ascii_lowercase(), status.to_owned());
            }
            None => {
                services.remove(&name.to_ascii_lowercase());
            }
        }
    }

    /// Drops every connection now (the client reconnects); with `refusing`, new ones too until called with false.
    pub fn drop_connections(&self, refusing: bool) {
        self.shared.refusing.store(refusing, Ordering::SeqCst);
        let _ = self.shared.drop_all.send(());
    }
}

fn tls_acceptor() -> Result<(tokio_rustls::TlsAcceptor, Vec<u8>), String> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new(vec!["win01.test".to_owned(), "127.0.0.1".to_owned()])
        .map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "win01.test");
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    let der = cert.der().to_vec();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .map_err(|e| e.to_string())?;
    Ok((tokio_rustls::TlsAcceptor::from(Arc::new(config)), der))
}

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>, tls: Option<tokio_rustls::TlsAcceptor>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        if shared.refusing.load(Ordering::SeqCst) {
            drop(stream);
            continue;
        }
        let shared = Arc::clone(&shared);
        let tls = tls.clone();
        let mut dropped = shared.drop_all.subscribe();
        tokio::spawn(async move {
            let serve = async {
                match tls {
                    Some(acceptor) => {
                        if let Ok(stream) = acceptor.accept(stream).await {
                            connection(&shared, stream).await;
                        }
                    }
                    None => connection(&shared, stream).await,
                }
            };
            tokio::select! {
                () = serve => {}
                _ = dropped.recv() => {}
            }
        });
    }
}

/// One request as read.
struct Request {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S, buffer: &mut Vec<u8>) -> Option<Request> {
    let head_end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        if buffer.len() > 64 * 1024 {
            return None;
        }
        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut headers = Vec::new();
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let length: usize = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if length > 4 * 1024 * 1024 {
        return None;
    }
    let start = head_end + 4;
    while buffer.len() < start + length {
        let mut chunk = [0u8; 16384];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
    let body = buffer[start..start + length].to_vec();
    buffer.drain(..start + length);
    Some(Request { headers, body })
}

/// One response.
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn challenge(values: &[&str]) -> Self {
        Self {
            status: 401,
            headers: values
                .iter()
                .map(|v| ("WWW-Authenticate".to_owned(), (*v).to_owned()))
                .collect(),
            body: Vec::new(),
        }
    }
}

async fn write_response<S: AsyncWrite + Unpin>(stream: &mut S, response: Response) -> std::io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        500 => "Internal Server Error",
        _ => "Other",
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\nServer: Microsoft-HTTPAPI/2.0\r\n",
        response.status
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", response.body.len()));
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    stream.flush().await
}

/// A connection's sign-in state.
enum Auth {
    None,
    Challenged {
        negotiate: Vec<u8>,
        challenge: Vec<u8>,
        server_challenge: [u8; 8],
        flags: u32,
    },
    Ntlm(Box<ntlm::Keys>),
    /// A Basic sign-in passed on this connection (each request still carries it).
    Basic,
}

async fn connection<S: AsyncRead + AsyncWrite + Unpin>(shared: &Arc<Shared>, mut stream: S) {
    let mut buffer = Vec::new();
    let mut auth = Auth::None;
    while let Some(request) = read_request(&mut stream, &mut buffer).await {
        let response = handle(shared, &mut auth, request).await;
        if write_response(&mut stream, response).await.is_err() {
            return;
        }
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

async fn handle(shared: &Arc<Shared>, auth: &mut Auth, request: Request) -> Response {
    let authorization = request.header("Authorization").map(str::to_owned);
    match shared.mode {
        FakeWinrm::HttpsBasic => {
            let expected = format!(
                "Basic {}",
                b64(format!("{}:{}", shared.user, locks::lock(&shared.password)).as_bytes())
            );
            if authorization.as_deref() != Some(expected.as_str()) {
                if authorization.is_some() {
                    locks::lock(&shared.stats).refused_sign_ins += 1;
                }
                return Response::challenge(&["Basic realm=\"WSMAN\"", "Negotiate"]);
            }
            if !matches!(auth, Auth::Basic) {
                // Counted once per connection.
                locks::lock(&shared.stats).sign_ins += 1;
                *auth = Auth::Basic;
            }
            let xml = String::from_utf8_lossy(&request.body).into_owned();
            let (status, body) = soap(shared, &xml).await;
            xml_response(status, body.into_bytes())
        }
        FakeWinrm::HttpNtlm | FakeWinrm::HttpsNtlm => {
            if let Some(token) = authorization
                .as_deref()
                .and_then(|a| a.strip_prefix("Negotiate "))
                .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t.trim()).ok())
            {
                return sign_in(shared, auth, &token);
            }
            let Auth::Ntlm(keys) = auth else {
                return Response::challenge(&["Negotiate", "Kerberos"]);
            };
            let xml = if shared.mode.https() {
                String::from_utf8_lossy(&request.body).into_owned()
            } else {
                let sealed = request
                    .header("Content-Type")
                    .is_some_and(|c| c.to_ascii_lowercase().starts_with("multipart/encrypted"));
                if !sealed {
                    locks::lock(&shared.stats).plain_refused += 1;
                    return Response::empty(400);
                }
                let Ok(parts) = encryption::unwrap(&request.body) else {
                    return Response::empty(400);
                };
                let k = keys.as_mut();
                let Some(plain) = ntlm::unseal(
                    &mut k.client_seal,
                    &k.client_sign,
                    &mut k.client_seq,
                    &parts.signature,
                    &parts.sealed,
                ) else {
                    return Response::empty(400);
                };
                String::from_utf8_lossy(&plain).into_owned()
            };
            let (status, body) = soap(shared, &xml).await;
            if shared.mode.https() {
                return xml_response(status, body.into_bytes());
            }
            let k = keys.as_mut();
            let (signature, sealed) =
                ntlm::seal(&mut k.server_seal, &k.server_sign, &mut k.server_seq, body.as_bytes());
            Response {
                status,
                headers: vec![(
                    "Content-Type".into(),
                    encryption::content_type(encryption::PROTOCOL_SPNEGO),
                )],
                body: encryption::wrap(encryption::PROTOCOL_SPNEGO, body.len(), &signature, &sealed),
            }
        }
    }
}

fn xml_response(status: u16, body: Vec<u8>) -> Response {
    Response {
        status,
        headers: vec![("Content-Type".into(), "application/soap+xml;charset=UTF-8".into())],
        body,
    }
}

fn sign_in(shared: &Arc<Shared>, auth: &mut Auth, token: &[u8]) -> Response {
    match ntlm::message_type(token) {
        Some(1) => {
            let Some(flags) = ntlm::negotiate_flags(token) else {
                return Response::empty(400);
            };
            let mut server_challenge = [0u8; 8];
            server_challenge.copy_from_slice(&Uuid::new_v4().as_bytes()[..8]);
            // A FILETIME for now, so the client adds a MIC, as against a real host.
            let filetime = (time::OffsetDateTime::now_utc().unix_timestamp() as u64 + 11_644_473_600) * 10_000_000;
            let info = ntlm::target_info("WIN01", "WIN01", Some(filetime));
            let (challenge, flags) = ntlm::challenge(flags, server_challenge, "WIN01", &info);
            let header = format!("Negotiate {}", b64(&challenge));
            *auth = Auth::Challenged {
                negotiate: token.to_vec(),
                challenge,
                server_challenge,
                flags,
            };
            Response::challenge(&[header.as_str()])
        }
        Some(3) => {
            let Auth::Challenged {
                negotiate,
                challenge,
                server_challenge,
                flags,
            } = std::mem::replace(auth, Auth::None)
            else {
                return Response::challenge(&["Negotiate"]);
            };
            let password = locks::lock(&shared.password).clone();
            match ntlm::authenticate(
                &negotiate,
                &challenge,
                server_challenge,
                flags,
                token,
                &shared.user,
                &password,
            ) {
                Ok(keys) => {
                    locks::lock(&shared.stats).sign_ins += 1;
                    *auth = Auth::Ntlm(Box::new(keys));
                    Response::empty(200)
                }
                Err(_) => {
                    locks::lock(&shared.stats).refused_sign_ins += 1;
                    Response::challenge(&["Negotiate"])
                }
            }
        }
        _ => Response::challenge(&["Negotiate"]),
    }
}

const LIMITS: XmlLimits = XmlLimits {
    depth: 32,
    elements: 1000,
    text: 4 * 1024 * 1024,
};

fn envelope(body: &str) -> String {
    format!(
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\" xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\" \
xmlns:x=\"http://schemas.xmlsoap.org/ws/2004/09/transfer\"><s:Header><a:Action>response</a:Action></s:Header><s:Body>{body}</s:Body></s:Envelope>"
    )
}

fn fault(code: &str, subcode: &str, message: &str) -> (u16, String) {
    (
        500,
        envelope(&format!(
            "<s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:{subcode}</s:Value></s:Subcode></s:Code>\
<s:Reason><s:Text xml:lang=\"en-US\">{message}</s:Text></s:Reason><s:Detail><f:WSManFault xmlns:f=\"http://schemas.microsoft.com/wbem/wsman/1/wsmanfault\" \
Code=\"{code}\" Machine=\"win01.test\"><f:Message>{message}</f:Message></f:WSManFault></s:Detail></s:Fault>"
        )),
    )
}

fn timeout_secs(header: &Element) -> u64 {
    header
        .child("OperationTimeout")
        .map(|t| t.text().trim_start_matches("PT").trim_end_matches('S').to_owned())
        .and_then(|t| t.parse::<f64>().ok())
        .map(|t| t.clamp(0.1, 60.0) as u64)
        .unwrap_or(20)
}

async fn soap(shared: &Arc<Shared>, xml: &str) -> (u16, String) {
    let Some(root) = parse_xml_limited(xml, LIMITS) else {
        return fault("2150858817", "InvalidRepresentation", "The request is not XML.");
    };
    let (Some(header), Some(body)) = (root.child("Header"), root.child("Body")) else {
        return fault("2150858817", "InvalidRepresentation", "No header or body.");
    };
    let action = header.child("Action").map(|a| a.text().to_owned()).unwrap_or_default();
    let shell_id = {
        let mut selectors = Vec::new();
        header.find_all("Selector", &mut selectors);
        selectors
            .into_iter()
            .find(|s| s.attr("Name") == Some("ShellId"))
            .map(|s| s.text().to_owned())
    };
    let verb = action.rsplit('/').next().unwrap_or_default().to_owned();
    match verb.as_str() {
        "Create" => {
            let id = Uuid::new_v4().to_string().to_uppercase();
            locks::lock(&shared.shells).insert(id.clone(), HashMap::new());
            locks::lock(&shared.stats).shells_created += 1;
            (
                200,
                envelope(&format!(
                    "<x:ResourceCreated><a:Address>http://127.0.0.1/wsman</a:Address><a:ReferenceParameters><w:SelectorSet>\
<w:Selector Name=\"ShellId\">{id}</w:Selector></w:SelectorSet></a:ReferenceParameters></x:ResourceCreated>\
<rsp:Shell><rsp:ShellId>{id}</rsp:ShellId></rsp:Shell>"
                )),
            )
        }
        "Delete" => {
            let gone = shell_id.and_then(|id| locks::lock(&shared.shells).remove(&id));
            if let Some(commands) = gone {
                for proc in commands.values() {
                    locks::lock(proc).end(1);
                }
                locks::lock(&shared.stats).shells_deleted += 1;
            }
            (200, envelope(""))
        }
        "Command" => {
            let Some(id) = shell_id else {
                return no_shell();
            };
            let line = body.child("CommandLine");
            let program = line
                .and_then(|l| l.child("Command"))
                .map(|c| c.text().to_owned())
                .unwrap_or_default();
            let arguments = line
                .and_then(|l| l.child("Arguments"))
                .map(|c| c.text().to_owned())
                .unwrap_or_default();
            let command_id = Uuid::new_v4().to_string().to_uppercase();
            {
                let mut shells = locks::lock(&shared.shells);
                let Some(shell) = shells.get_mut(&id) else {
                    return no_shell();
                };
                shell.insert(
                    command_id.clone(),
                    Arc::new(Mutex::new(Proc::new(&program, &arguments))),
                );
            }
            locks::lock(&shared.stats)
                .commands
                .push(format!("{program} {arguments}"));
            (
                200,
                envelope(&format!(
                    "<rsp:CommandResponse><rsp:CommandId>{command_id}</rsp:CommandId></rsp:CommandResponse>"
                )),
            )
        }
        "Send" => {
            let Some(stream) = body.child("Send").and_then(|s| s.child("Stream")) else {
                return fault("2150858817", "InvalidRepresentation", "No stream.");
            };
            let Some(proc) = find_proc(shared, shell_id.as_deref(), stream.attr("CommandId")) else {
                return no_shell();
            };
            let data = base64::engine::general_purpose::STANDARD
                .decode(stream.text().trim().as_bytes())
                .unwrap_or_default();
            let end = stream.attr("End").is_some_and(|e| e.eq_ignore_ascii_case("true"));
            let lines = locks::lock(&proc).stdin(shared, &data, end);
            locks::lock(&shared.stats).stdin.extend(lines);
            (200, envelope("<rsp:SendResponse/>"))
        }
        "Receive" => {
            let command = body
                .child("Receive")
                .and_then(|r| r.child("DesiredStream"))
                .and_then(|d| d.attr("CommandId"))
                .map(str::to_owned);
            let Some(proc) = find_proc(shared, shell_id.as_deref(), command.as_deref()) else {
                return no_shell();
            };
            let command = command.unwrap_or_default();
            let wait = Duration::from_secs(timeout_secs(header));
            let until = Instant::now() + wait;
            loop {
                let answer = locks::lock(&proc).take(shared, &command);
                if let Some(answer) = answer {
                    return (200, envelope(&answer));
                }
                if Instant::now() >= until {
                    return fault(
                        "2150858793",
                        "TimedOut",
                        "The WS-Management service cannot complete the operation within the time specified in OperationTimeout.",
                    );
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        "Signal" => {
            let signal = body.child("Signal");
            let code = signal
                .and_then(|s| s.child("Code"))
                .map(|c| c.text().rsplit('/').next().unwrap_or_default().to_owned())
                .unwrap_or_default();
            let Some(proc) = find_proc(shared, shell_id.as_deref(), signal.and_then(|s| s.attr("CommandId"))) else {
                return no_shell();
            };
            locks::lock(&proc).signal(shared, &code);
            locks::lock(&shared.stats).signals.push(code);
            (200, envelope("<rsp:SignalResponse/>"))
        }
        _ => fault("2150858817", "ActionNotSupported", "This action is not supported."),
    }
}

fn no_shell() -> (u16, String) {
    fault(
        "2150858843",
        "InvalidSelectors",
        "The request for the Windows Remote Shell failed because the shell was not found on the server.",
    )
}

fn find_proc(shared: &Shared, shell: Option<&str>, command: Option<&str>) -> Option<Arc<Mutex<Proc>>> {
    let shells = locks::lock(&shared.shells);
    shells.get(shell?)?.get(command?).cloned()
}

/// What a toy command reads next.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Skip {
    No,
    /// Lines of a read already answered, until the runner's end marker line (or stdin's end).
    Read,
    /// The service read: its `Get-Service` line names the service, its `if` line answers.
    Service(Option<String>),
}

/// What a wrapped statement still has to do once a `Read-Host` has its line or a sleep is over.
#[derive(Debug, Clone)]
enum Deferred {
    Line(String),
    /// The prompt marker with this nonce, naming the folder as it is when it prints.
    Marker(String),
}

/// A toy PowerShell reading statements from stdin.
struct Proc {
    /// Through `cmd /c ... 2>&1`: errors on stdout.
    merged: bool,
    out: Vec<u8>,
    err: Vec<u8>,
    done: Option<i64>,
    partial: Vec<u8>,
    location: String,
    skip: Skip,
    /// A `Read-Host` waits for the next stdin line.
    reading: bool,
    sleeping: Option<Instant>,
    queued: VecDeque<String>,
    /// The rest of a statement (its lines and its prompt marker) after a `Read-Host` or a sleep.
    deferred: VecDeque<Deferred>,
    stdin_closed: bool,
    failed_last: bool,
    reported_done: bool,
}

/// The single-quoted strings of Remotely's statement line (`'a' + "`n" + 'b'`), unquoted, and what follows them.
fn quoted_parts(text: &str) -> Option<(Vec<String>, &str)> {
    let mut parts = Vec::new();
    let mut rest = text;
    loop {
        let mut chars = rest.char_indices();
        let (_, first) = chars.next()?;
        if first != '\'' {
            return None;
        }
        let mut part = String::new();
        let mut end = None;
        let mut iter = rest.char_indices().skip(1).peekable();
        while let Some((at, c)) = iter.next() {
            if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
                if iter.peek().map(|(_, n)| *n) == Some(c) {
                    part.push(c);
                    iter.next();
                    continue;
                }
                end = Some(at + c.len_utf8());
                break;
            }
            part.push(c);
        }
        parts.push(part);
        rest = &rest[end?..];
        match rest.strip_prefix(" + \"`n\" + ") {
            Some(next) => rest = next,
            None => return Some((parts, rest)),
        }
    }
}

impl Proc {
    fn new(program: &str, arguments: &str) -> Self {
        let known = program.eq_ignore_ascii_case("powershell.exe") && arguments.contains("-Command -");
        let mut proc = Self {
            merged: arguments.contains("2>&1"),
            out: Vec::new(),
            err: Vec::new(),
            done: None,
            partial: Vec::new(),
            location: "C:\\Users\\alice".into(),
            skip: Skip::No,
            reading: false,
            sleeping: None,
            queued: VecDeque::new(),
            deferred: VecDeque::new(),
            stdin_closed: false,
            failed_last: false,
            reported_done: false,
        };
        if !known {
            proc.err
                .extend_from_slice(format!("'{program}' is not recognized as a program here.\r\n").as_bytes());
            proc.done = Some(1);
        }
        proc
    }

    fn end(&mut self, code: i64) {
        if self.done.is_none() {
            self.done = Some(code);
        }
    }

    fn print(&mut self, text: &str) {
        self.out.extend_from_slice(text.as_bytes());
    }

    fn error(&mut self, text: &str) {
        let line = format!("{text}\r\n");
        if self.merged {
            self.out.extend_from_slice(line.as_bytes());
        } else {
            self.err.extend_from_slice(line.as_bytes());
        }
        self.failed_last = true;
    }

    /// Takes stdin; returns the whole lines it held.
    fn stdin(&mut self, shared: &Shared, data: &[u8], end: bool) -> Vec<String> {
        self.partial.extend_from_slice(data);
        let mut lines = Vec::new();
        while let Some(at) = self.partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=at).collect();
            let text = String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']).to_owned();
            lines.push(text.clone());
            self.queued.push_back(text);
        }
        if end {
            self.stdin_closed = true;
        }
        self.run_queue(shared);
        lines
    }

    fn signal(&mut self, shared: &Shared, code: &str) {
        match code {
            // The running statement stops (the rest of it, its prompt marker too, is dropped).
            "ctrl_c" => {
                self.sleeping = None;
                self.reading = false;
                self.deferred.clear();
                self.run_queue(shared);
            }
            _ => self.end(1),
        }
    }

    fn busy(&self) -> bool {
        self.reading || self.sleeping.is_some()
    }

    fn run_queue(&mut self, shared: &Shared) {
        if self.sleeping.is_some_and(|until| Instant::now() < until) {
            return;
        }
        self.sleeping = None;
        self.run_deferred(shared);
        // A line while a `Read-Host` waits is its answer ([`Self::line`]).
        while self.done.is_none() && self.sleeping.is_none() {
            let Some(line) = self.queued.pop_front() else {
                break;
            };
            self.line(shared, &line);
        }
        if self.stdin_closed && self.queued.is_empty() && self.done.is_none() && !self.busy() {
            self.done = Some(i64::from(self.failed_last));
        }
    }

    fn run_deferred(&mut self, shared: &Shared) {
        while self.done.is_none() && !self.busy() {
            match self.deferred.pop_front() {
                Some(Deferred::Line(line)) => self.statement(shared, &line),
                Some(Deferred::Marker(nonce)) => {
                    let location = self.location.clone();
                    self.print(&format!(
                        "]7790;{nonce};{location}
"
                    ));
                }
                None => break,
            }
        }
    }

    /// A stdin line: a `Read-Host`'s answer, a read's line, Remotely's statement line, or a statement.
    fn line(&mut self, shared: &Shared, line: &str) {
        let t = line.trim();
        if self.reading {
            self.reading = false;
            self.print(&format!("{t}\r\n"));
            self.run_deferred(shared);
            return;
        }
        match &self.skip {
            Skip::Read => {
                if let Some(marker) = t
                    .strip_prefix("[Console]::Out.WriteLine('")
                    .and_then(|r| r.strip_suffix("')"))
                {
                    self.print(&format!("{marker}\r\n"));
                    self.skip = Skip::No;
                }
                return;
            }
            Skip::Service(name) => {
                if let Some(rest) = t.split("Get-Service -Name '").nth(1) {
                    let named = rest.split('\'').next().unwrap_or_default().to_owned();
                    self.skip = Skip::Service(Some(named));
                } else if t.starts_with("if (") {
                    let status = name
                        .as_deref()
                        .and_then(|n| locks::lock(&shared.services).get(&n.to_ascii_lowercase()).cloned());
                    match status {
                        Some(status) => self.print(&format!("@@service {status}\r\n")),
                        None => self.print("@@service missing\r\n"),
                    }
                    self.skip = Skip::No;
                }
                return;
            }
            Skip::No => {}
        }
        // The console's statement line: its lines, then the prompt marker after them.
        if let Some(inner) = t.strip_prefix("try { . ([scriptblock]::Create(") {
            let Some((lines, rest)) = quoted_parts(inner) else {
                self.error("At line:1 char:1 The statement could not be read.");
                return;
            };
            for line in lines {
                self.deferred.push_back(Deferred::Line(line));
            }
            if let Some(at) = rest.find("\"$([char]27)]7790;") {
                let nonce = rest[at + "\"$([char]27)]7790;".len()..]
                    .split(';')
                    .next()
                    .unwrap_or_default();
                self.deferred.push_back(Deferred::Marker(nonce.to_owned()));
            }
            self.run_deferred(shared);
            return;
        }
        self.statement(shared, t);
    }

    fn statement(&mut self, shared: &Shared, line: &str) {
        let t = line.trim();
        self.failed_last = false;
        if t.is_empty() || t.starts_with("$ProgressPreference") {
            return;
        }
        if t == "# remotely:guest-metrics" {
            let round = shared.round.fetch_add(1, Ordering::SeqCst);
            locks::lock(&shared.stats).metrics_reads += 1;
            self.print(&crate::metrics::windows::sample(round));
            self.skip = Skip::Read;
            return;
        }
        if t == "# remotely:host-facts" {
            self.print(&crate::host_details::windows::sample());
            self.print("\r\n");
            self.skip = Skip::Read;
            return;
        }
        if t == "# remotely:service" {
            self.skip = Skip::Service(None);
            return;
        }
        if t.starts_with('#') {
            return;
        }
        if let Some(rest) = t.strip_prefix("\"$([char]27)]7790;") {
            let nonce = rest.split(';').next().unwrap_or_default();
            let location = self.location.clone();
            self.print(&format!("\x1b]7790;{nonce};{location}\x07\r\n"));
            return;
        }
        if let Some(marker) = t
            .strip_prefix("[Console]::Out.WriteLine('")
            .and_then(|r| r.strip_suffix("')"))
        {
            self.print(&format!("{marker}\r\n"));
            return;
        }
        let (word, rest) = t.split_once(' ').map_or((t, ""), |(w, r)| (w, r.trim()));
        let unquoted = rest.trim_matches(['\'', '"']);
        match word.to_ascii_lowercase().as_str() {
            "exit" => self.end(rest.parse().unwrap_or(0)),
            "hostname" => self.print("WIN01\r\n"),
            "get-date" => self.print("\r\nSunday, November 1, 2026 10:00:00 AM\r\n\r\n"),
            "write-output" | "echo" => self.print(&format!("{unquoted}\r\n")),
            "set-location" | "cd" => self.location = unquoted.to_owned(),
            "get-location" | "pwd" => {
                let location = self.location.clone();
                self.print(&format!("\r\nPath\r\n----\r\n{location}\r\n\r\n"));
            }
            "read-host" => {
                // Windows PowerShell shows no prompt when its stdin is a pipe; the toy says it, for tests.
                self.print(&format!("{unquoted}: "));
                self.reading = true;
            }
            "start-sleep" => {
                let secs: u64 = unquoted.parse().unwrap_or(1);
                self.sleeping = Some(Instant::now() + Duration::from_secs(secs));
            }
            "write-error" => self.error(&format!("Write-Error: {unquoted}")),
            "if" | "foreach" | "}" => {}
            _ if t.starts_with('\'') || t.starts_with('"') => {
                let text = t.trim_matches(['\'', '"']).to_owned();
                self.print(&format!("{text}\r\n"));
            }
            _ => self.error(&format!(
                "{word} : The term '{word}' is not recognized as the name of a cmdlet, function, script file, or operable program."
            )),
        }
    }

    /// What a Receive gets now: `None` while there is nothing to give.
    fn take(&mut self, shared: &Shared, command: &str) -> Option<String> {
        self.run_queue(shared);
        if self.out.is_empty() && self.err.is_empty() && (self.done.is_none() || self.reported_done) {
            return None;
        }
        let out: Vec<u8> = self.out.drain(..self.out.len().min(16 * 1024)).collect();
        let err: Vec<u8> = self.err.drain(..self.err.len().min(16 * 1024)).collect();
        let mut text = String::from("<rsp:ReceiveResponse>");
        if !out.is_empty() {
            text.push_str(&format!(
                "<rsp:Stream Name=\"stdout\" CommandId=\"{command}\">{}</rsp:Stream>",
                b64(&out)
            ));
        }
        if !err.is_empty() {
            text.push_str(&format!(
                "<rsp:Stream Name=\"stderr\" CommandId=\"{command}\">{}</rsp:Stream>",
                b64(&err)
            ));
        }
        match self.done {
            Some(code) if self.out.is_empty() && self.err.is_empty() => {
                self.reported_done = true;
                text.push_str(&format!(
                    "<rsp:Stream Name=\"stdout\" CommandId=\"{command}\" End=\"true\"></rsp:Stream>\
<rsp:CommandState CommandId=\"{command}\" State=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done\">\
<rsp:ExitCode>{code}</rsp:ExitCode></rsp:CommandState>"
                ));
            }
            _ => text.push_str(&format!(
                "<rsp:CommandState CommandId=\"{command}\" State=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running\"/>"
            )),
        }
        text.push_str("</rsp:ReceiveResponse>");
        Some(text)
    }
}
