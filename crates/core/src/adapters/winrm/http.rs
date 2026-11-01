//! SS-12: WinRM's HTTP side: one HTTP/1.1 connection per [`Connection`], signed in once, and the [`Client`] that
//! keeps a few of them (a console's long Receive holds one while another sends what is typed).
//!
//! * **HTTPS**: TLS with any chain read first, then checked before a byte of the sign-in is sent: Windows must trust
//!   it for the host's name, or (by the session's rule) its SHA-256 fingerprint is trusted for that host and port,
//!   asked the first time like an SSH host key; a changed one blocks.
//! * **Sign-in**: Basic (HTTPS only: the header holds the password as it is), or NTLM and Negotiate through Windows'
//!   SSPI ([`super::sspi`]): an empty POST with the first token, the host's 401 with its challenge, then the answer.
//!   Over HTTP, every message after that is sealed with the context ([`super::encryption`]); nothing ever goes in
//!   clear over HTTP, and the client refuses an answer that isn't sealed.
//! * **Untrusted answers**: each answer is read whole up to [`MAX_ANSWER`] bytes within its time limit, headers up to
//!   hyper's buffer, tokens up to [`MAX_TOKEN`]; anything else is refused.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST, USER_AGENT, WWW_AUTHENTICATE};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::Digest;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use super::encryption;
use super::sspi::{self, Package};
use crate::adapters::net_tools::{BoxedStream, NetworkTools, TrustUse};
use crate::adapters::remote::HostKeyVerifier;
use crate::error::{CoreError, Result};
use crate::known_hosts::{address, HostKey};
use crate::locks;
use crate::sessions::kinds::WinrmCertificate;
use crate::vault::SecretString;

/// The most an answer may be, sealed or not: WinRM's envelope is at most 500 KB.
pub const MAX_ANSWER: usize = 1024 * 1024;
/// The most a sign-in token may be, base64 (a Kerberos ticket with a big PAC runs to tens of KB).
pub const MAX_TOKEN: usize = 64 * 1024;
/// Connections one client keeps at most.
pub const MAX_CONNECTIONS: usize = 4;
/// A connection left idle longer than this is not used again: Windows' HTTP.sys drops idle keep-alive connections after
/// two minutes (its default), and a message on one it dropped would be lost.
pub const MAX_IDLE: Duration = Duration::from_secs(50);
/// Rounds of the sign-in before Remotely gives up on a host that keeps asking.
const MAX_SIGN_IN_ROUNDS: usize = 4;

/// The `key_type` of a WinRM host's certificate in the known hosts table, beside SSH's key types.
pub const CERT_KEY_TYPE: &str = "tls-certificate";

/// How a client signs in.
pub enum SignIn {
    /// `Authorization: Basic ...` on every request (HTTPS only).
    Basic { header: Zeroizing<String> },
    /// Windows' SSPI.
    Sspi {
        package: Package,
        credentials: Arc<sspi::Credentials>,
    },
}

impl SignIn {
    pub fn basic(user: &str, password: &SecretString) -> Self {
        let raw = Zeroizing::new(format!("{user}:{}", password.expose()));
        let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(raw.as_bytes()));
        Self::Basic {
            header: Zeroizing::new(format!("Basic {}", encoded.as_str())),
        }
    }
}

/// Where a client connects, and how it trusts the host.
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub certificate: WinrmCertificate,
    pub tools: Arc<dyn NetworkTools>,
    /// Asks about (or checks) a certificate Windows doesn't trust, by its fingerprint.
    pub verifier: Arc<dyn HostKeyVerifier>,
    pub connect_timeout: Duration,
}

impl Endpoint {
    /// `https://win01.example.com:5986/wsman`.
    pub fn url(&self) -> String {
        format!(
            "{}://{}/wsman",
            if self.https { "https" } else { "http" },
            address(&self.host, self.port)
        )
    }

    fn address(&self) -> String {
        address(&self.host, self.port)
    }
}

/// `SHA256:` and the base64 digest of a certificate, as SSH fingerprints are written.
pub fn fingerprint(der: &[u8]) -> String {
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(der))
    )
}

/// RFC 5929's `tls-server-end-point` channel binding for a certificate: the label, then the certificate's hash with
/// its signature's hash function (SHA-256 for MD5, SHA-1 and SHA-256 signatures, and when it can't be read).
pub fn tls_server_end_point(der: &[u8]) -> Vec<u8> {
    let algorithm = crate::toolbox::x509::parse(der)
        .map(|info| info.signature_algorithm)
        .unwrap_or_default();
    let hash: Vec<u8> = if algorithm.contains("SHA-512") {
        sha2::Sha512::digest(der).to_vec()
    } else if algorithm.contains("SHA-384") {
        sha2::Sha384::digest(der).to_vec()
    } else {
        sha2::Sha256::digest(der).to_vec()
    };
    let mut out = b"tls-server-end-point:".to_vec();
    out.extend_from_slice(&hash);
    out
}

/// One signed-in HTTP/1.1 connection.
pub struct Connection {
    send: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    driver: tokio::task::JoinHandle<()>,
    /// Over HTTP with SSPI: the context that seals each message.
    seal: Option<sspi::Context>,
    basic: Option<Zeroizing<String>>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// What a request got back.
pub struct Answered {
    pub status: StatusCode,
    pub body: String,
}

/// A response's headers and whole body, within `limit`.
struct Raw {
    status: StatusCode,
    content_type: String,
    challenges: Vec<String>,
    body: Vec<u8>,
}

impl Connection {
    fn closed(&self) -> bool {
        self.send.is_closed() || self.driver.is_finished()
    }

    async fn exchange(
        &mut self,
        endpoint: &Endpoint,
        body: Vec<u8>,
        content_type: Option<&str>,
        authorization: Option<&str>,
        timeout: Duration,
    ) -> Result<Raw> {
        let host = endpoint.address();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/wsman")
            .header(HOST, host.as_str())
            .header(USER_AGENT, "Remotely")
            .header(CONTENT_LENGTH, body.len());
        if let Some(content_type) = content_type {
            request = request.header(CONTENT_TYPE, content_type);
        }
        if let Some(authorization) = authorization {
            request = request.header(AUTHORIZATION, authorization);
        }
        let request = request
            .body(Full::new(Bytes::from(body)))
            .map_err(|err| CoreError::Winrm(format!("a request could not be built: {err}")))?;
        let lost = |err: hyper::Error| {
            CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("the connection to {host} was lost: {err}"),
            ))
        };
        let exchange = async {
            self.send.ready().await.map_err(lost)?;
            let response = self.send.send_request(request).await.map_err(lost)?;
            let status = response.status();
            let header = |name: hyper::header::HeaderName| -> Vec<String> {
                response
                    .headers()
                    .get_all(name)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .map(str::to_owned)
                    .collect()
            };
            let content_type = header(CONTENT_TYPE).into_iter().next().unwrap_or_default();
            let challenges = header(WWW_AUTHENTICATE);
            let body = Limited::new(response.into_body(), MAX_ANSWER)
                .collect()
                .await
                .map_err(|_| {
                    CoreError::Winrm(format!(
                        "the answer from {host} was larger than {} KB or broke off",
                        MAX_ANSWER / 1024
                    ))
                })?
                .to_bytes()
                .to_vec();
            Ok::<Raw, CoreError>(Raw {
                status,
                content_type,
                challenges,
                body,
            })
        };
        tokio::time::timeout(timeout, exchange)
            .await
            .map_err(|_| CoreError::Timeout {
                command: format!("waiting for {host}"),
                seconds: timeout.as_secs(),
            })?
    }

    /// Opens a connection and signs in.
    pub async fn open(
        endpoint: &Endpoint,
        sign_in: &SignIn,
        accepted: &Mutex<Option<String>>,
    ) -> Result<(Self, Option<IpAddr>)> {
        if matches!(sign_in, SignIn::Basic { .. }) && !endpoint.https {
            return Err(CoreError::InvalidInput(
                "Basic sends the password as it is, so Remotely uses it over HTTPS only.".into(),
            ));
        }
        let (stream, peer, leaf) = open_stream(endpoint, accepted).await?;
        let (send, conn) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(256 * 1024)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|err| CoreError::Winrm(format!("HTTP could not start with {}: {err}", endpoint.address())))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut connection = Connection {
            send,
            driver,
            seal: None,
            basic: None,
        };
        match sign_in {
            SignIn::Basic { header } => {
                // Review F4 #2: checked now, with one empty POST, so a wrong password shows (and parks) at the sign-in
                // rather than on every read.
                let timeout = endpoint.connect_timeout.saturating_mul(2);
                let raw = connection
                    .exchange(endpoint, Vec::new(), None, Some(header.as_str()), timeout)
                    .await?;
                if raw.status == StatusCode::UNAUTHORIZED {
                    return Err(CoreError::AuthFailed(format!(
                        "{} refused the user name or password",
                        endpoint.address()
                    )));
                }
                connection.basic = Some(header.clone());
            }
            SignIn::Sspi { package, credentials } => {
                // Over HTTPS the sign-in is bound to this TLS channel (Extended Protection).
                let channel = leaf.as_deref().map(tls_server_end_point);
                let context = connection
                    .negotiate(endpoint, *package, Arc::clone(credentials), channel)
                    .await?;
                if !endpoint.https {
                    connection.seal = Some(context);
                }
            }
        }
        Ok((connection, peer))
    }

    /// The SSPI sign-in on this connection (empty POSTs), giving the context. The host's answer other than a 401 only
    /// counts once the context is complete; the Windows sign-in (Kerberos only) never sends an NTLM token and needs the
    /// host to prove itself (mutual authentication).
    async fn negotiate(
        &mut self,
        endpoint: &Endpoint,
        package: Package,
        credentials: Arc<sspi::Credentials>,
        channel: Option<Vec<u8>>,
    ) -> Result<sspi::Context> {
        let spn = sspi::spn(&endpoint.host);
        let timeout = endpoint.connect_timeout.saturating_mul(2);
        let kerberos = package == Package::KerberosOnly;
        let place = endpoint.address();
        let kerberos_failed = |why: String| {
            CoreError::AuthFailed(format!(
                "Kerberos couldn't sign in to {place} ({why}). For a host outside your domain, or reached by its address, sign in with NTLM and a password from the vault"
            ))
        };
        let check = |step: &sspi::Step| -> Result<()> {
            if kerberos && sspi::is_ntlm(&step.token) {
                return Err(kerberos_failed(
                    "Windows offered NTLM, which this sign-in never sends".into(),
                ));
            }
            Ok(())
        };
        // Kerberos may ask a domain controller: never on the runtime's own threads.
        let first = tokio::task::spawn_blocking(move || {
            let mut context = sspi::Context::new(credentials, &spn, channel.as_deref());
            let step = context.step(None);
            step.map(|s| (context, s))
        })
        .await
        .map_err(|_| CoreError::Winrm("Windows' sign-in stopped".into()))?;
        let (mut context, mut step) = match first {
            Ok(started) => started,
            Err(err) if kerberos => return Err(kerberos_failed(err.to_string())),
            Err(err) => return Err(err),
        };
        check(&step)?;
        for _ in 0..MAX_SIGN_IN_ROUNDS {
            let header = format!(
                "Negotiate {}",
                base64::engine::general_purpose::STANDARD.encode(&step.token)
            );
            let raw = self
                .exchange(endpoint, Vec::new(), None, Some(&header), timeout)
                .await?;
            let token = challenge_token(&raw.challenges)?;
            if raw.status == StatusCode::UNAUTHORIZED {
                let Some(token) = token.filter(|_| !step.complete) else {
                    return Err(refused(endpoint, package, &raw.challenges));
                };
                if kerberos && sspi::is_ntlm(&token) {
                    return Err(kerberos_failed("the host answered with NTLM".into()));
                }
                let (back, next) = tokio::task::spawn_blocking(move || {
                    let next = context.step(Some(&token));
                    (context, next)
                })
                .await
                .map_err(|_| CoreError::Winrm("Windows' sign-in stopped".into()))?;
                context = back;
                step = match next {
                    Ok(step) => step,
                    Err(err) if kerberos => return Err(kerberos_failed(err.to_string())),
                    Err(err) => return Err(err),
                };
                check(&step)?;
                continue;
            }
            // The host took the sign-in (WinRM answers the empty POST once it has checked it). Negotiate may send a last
            // token that proves the host (Kerberos' mutual authentication).
            if let (Some(token), false) = (token, step.complete) {
                let (back, last) = tokio::task::spawn_blocking(move || {
                    let last = context.step(Some(&token));
                    (context, last)
                })
                .await
                .map_err(|_| CoreError::Winrm("Windows' sign-in stopped".into()))?;
                context = back;
                step = last?;
            }
            if !step.complete {
                return Err(CoreError::AuthFailed(format!(
                    "{place} answered before the sign-in was complete, so Remotely didn't trust it"
                )));
            }
            if kerberos && !step.mutual {
                return Err(kerberos_failed("the host didn't prove who it is".into()));
            }
            return Ok(context);
        }
        Err(CoreError::AuthFailed(format!(
            "{place} kept asking for more of the sign-in, so Remotely stopped"
        )))
    }

    /// One WS-Management message: sealed over HTTP with SSPI, plain over HTTPS.
    pub async fn post(&mut self, endpoint: &Endpoint, xml: &str, timeout: Duration) -> Result<Answered> {
        let soap = "application/soap+xml;charset=UTF-8";
        let raw = match &mut self.seal {
            Some(context) => {
                let (signature, sealed) = context.seal(xml.as_bytes())?;
                let body = encryption::wrap(encryption::PROTOCOL_SPNEGO, xml.len(), &signature, &sealed);
                let content_type = encryption::content_type(encryption::PROTOCOL_SPNEGO);
                self.exchange(endpoint, body, Some(&content_type), None, timeout)
                    .await?
            }
            None => {
                let authorization = self.basic.clone();
                self.exchange(
                    endpoint,
                    xml.as_bytes().to_vec(),
                    Some(soap),
                    authorization.as_deref().map(String::as_str),
                    timeout,
                )
                .await?
            }
        };
        if raw.status == StatusCode::UNAUTHORIZED {
            return Err(CoreError::AuthFailed(format!(
                "{} refused the user name or password",
                endpoint.address()
            )));
        }
        let body = match &mut self.seal {
            Some(context) if !raw.body.is_empty() => {
                if !encryption::is_sealed(&raw.content_type) {
                    return Err(CoreError::Winrm(format!(
                        "{} answered in clear text over HTTP, which Remotely doesn't accept",
                        endpoint.address()
                    )));
                }
                let parts = encryption::unwrap(&raw.body)?;
                let plain = context.unseal(&parts.signature, &parts.sealed)?;
                if plain.len() != parts.plain_len {
                    return Err(CoreError::Winrm("a sealed answer's length is not what it says".into()));
                }
                plain
            }
            _ => raw.body,
        };
        let body = String::from_utf8(body)
            .map_err(|_| CoreError::Winrm(format!("{}'s answer is not UTF-8 text", endpoint.address())))?;
        Ok(Answered {
            status: raw.status,
            body,
        })
    }
}

/// The host's token in `WWW-Authenticate: Negotiate <base64>`, if it sent one.
fn challenge_token(challenges: &[String]) -> Result<Option<Vec<u8>>> {
    for challenge in challenges {
        for part in challenge.split(',') {
            let part = part.trim();
            let Some((scheme, token)) = part.split_once(' ') else {
                continue;
            };
            if !scheme.eq_ignore_ascii_case("Negotiate") {
                continue;
            }
            let token = token.trim();
            if token.len() > MAX_TOKEN {
                return Err(CoreError::Winrm("the host's sign-in token is too long".into()));
            }
            return base64::engine::general_purpose::STANDARD
                .decode(token)
                .map(Some)
                .map_err(|_| CoreError::Winrm("the host's sign-in token is not base64".into()));
        }
    }
    Ok(None)
}

/// A 401 the sign-in can't go on from: refused, or a scheme the host doesn't offer.
fn refused(endpoint: &Endpoint, package: Package, challenges: &[String]) -> CoreError {
    let offers: Vec<String> = challenges
        .iter()
        .flat_map(|c| c.split(','))
        .filter_map(|c| c.split_whitespace().next())
        .map(str::to_owned)
        .filter(|s| s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        .collect();
    let negotiates = offers.iter().any(|o| o.eq_ignore_ascii_case("Negotiate"));
    if !offers.is_empty() && !negotiates {
        return CoreError::AuthFailed(format!(
            "{} doesn't offer {} sign-in (it offers {})",
            endpoint.address(),
            match package {
                Package::Ntlm => "NTLM",
                Package::KerberosOnly => "Kerberos",
            },
            offers.join(", ")
        ));
    }
    CoreError::AuthFailed(format!("{} refused the sign-in", endpoint.address()))
}

/// TCP, then TLS with the certificate checked, for HTTPS.
/// The leaf certificate's DER comes back over HTTPS, for channel binding.
async fn open_stream(
    endpoint: &Endpoint,
    accepted: &Mutex<Option<String>>,
) -> Result<(BoxedStream, Option<IpAddr>, Option<Vec<u8>>)> {
    let host = endpoint.host.trim_start_matches('[').trim_end_matches(']');
    let place = endpoint.address();
    let tcp = match tokio::time::timeout(
        endpoint.connect_timeout,
        tokio::net::TcpStream::connect((host, endpoint.port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            return Err(CoreError::Io(std::io::Error::new(
                err.kind(),
                format!("can't connect to {place}: {err}"),
            )))
        }
        Err(_) => {
            return Err(CoreError::Timeout {
                command: format!("connecting to {place}"),
                seconds: endpoint.connect_timeout.as_secs(),
            })
        }
    };
    let peer = tcp.peer_addr().ok().map(|a| a.ip());
    let _ = tcp.set_nodelay(true);
    if !endpoint.https {
        return Ok((Box::new(tcp), peer, None));
    }
    let name = crate::toolbox::certs::server_name(host)?;
    let (tls, chain) = crate::toolbox::certs::tls_connect(Box::new(tcp), name, endpoint.connect_timeout).await?;
    check_certificate(endpoint, &chain, accepted).await?;
    let leaf = chain.first().cloned();
    Ok((Box::new(tls), peer, leaf))
}

/// The session's rule for the host's certificate, before anything is sent: Windows trusts it for the host's name,
/// or its fingerprint is trusted for this host and port. A second connection of the same client takes the
/// certificate the first one accepted.
async fn check_certificate(endpoint: &Endpoint, chain: &[Vec<u8>], accepted: &Mutex<Option<String>>) -> Result<()> {
    let place = endpoint.address();
    let leaf = chain
        .first()
        .ok_or_else(|| CoreError::Winrm(format!("{place} sent no certificate")))?;
    let print = fingerprint(leaf);
    if locks::lock(accepted).as_deref() == Some(print.as_str()) {
        return Ok(());
    }
    let report = crate::toolbox::certs::report_for(endpoint.tools.as_ref(), chain, TrustUse::TlsServer).await?;
    let name_ok = report
        .chain
        .first()
        .is_some_and(|info| info.matches_host(endpoint.host.trim_start_matches('[').trim_end_matches(']')));
    if report.trusted && name_ok {
        *locks::lock(accepted) = Some(print);
        return Ok(());
    }
    let mut why: Vec<String> = report.trust_problems.iter().map(|p| super::soap::clean(p)).collect();
    if !name_ok {
        why.push(format!("it doesn't name {}", endpoint.host));
    }
    if why.is_empty() {
        why.push("not trusted".into());
    }
    match endpoint.certificate {
        WinrmCertificate::Windows => Err(CoreError::CertificateNotTrusted {
            address: place,
            why: why.join("; "),
        }),
        WinrmCertificate::Fingerprint => {
            let key = HostKey {
                host: endpoint.host.clone(),
                port: endpoint.port,
                key_type: CERT_KEY_TYPE.into(),
                fingerprint: print.clone(),
            };
            match endpoint.verifier.verify(&key, None).await {
                Ok(()) => {
                    *locks::lock(accepted) = Some(print);
                    Ok(())
                }
                Err(CoreError::HostKeyChanged { .. }) => Err(CoreError::CertificateChanged { address: place }),
                Err(CoreError::HostKeyRejected { .. }) => Err(CoreError::CertificateRejected { address: place }),
                Err(CoreError::HostKeyUnknown { .. }) => Err(CoreError::CertificateUnknown { address: place }),
                Err(other) => Err(other),
            }
        }
    }
}

/// Signed-in connections to one host, a few at a time.
pub struct Client {
    pub endpoint: Endpoint,
    sign_in: SignIn,
    /// Signed-in connections not in use, with when each was last used.
    idle: Mutex<Vec<(Connection, std::time::Instant)>>,
    permits: Semaphore,
    accepted: Mutex<Option<String>>,
    peer: Mutex<Option<IpAddr>>,
    /// Shells made on the host and not deleted yet, so closing deletes what still runs.
    live: Mutex<std::collections::HashSet<String>>,
}

impl Client {
    /// A client that signs in with `sign_in`; [`Client::warm`] opens its first connection.
    pub fn new(endpoint: Endpoint, sign_in: SignIn) -> Self {
        Self {
            endpoint,
            sign_in,
            idle: Mutex::default(),
            permits: Semaphore::new(MAX_CONNECTIONS),
            accepted: Mutex::default(),
            peer: Mutex::default(),
            live: Mutex::default(),
        }
    }

    /// Opens and signs in one connection now, so a refused sign-in, an untrusted certificate or an unreachable host
    /// shows at once.
    pub async fn warm(&self) -> Result<()> {
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| CoreError::Winrm("the connection is closed".into()))?;
        let (connection, peer) = Connection::open(&self.endpoint, &self.sign_in, &self.accepted).await?;
        *locks::lock(&self.peer) = peer;
        locks::lock(&self.idle).push((connection, std::time::Instant::now()));
        Ok(())
    }

    /// The address this PC reached.
    pub fn peer_ip(&self) -> Option<IpAddr> {
        *locks::lock(&self.peer)
    }

    /// Review C4: what the journal records as this host's key: the leaf certificate's fingerprint for an HTTPS host
    /// (set whether Windows or a trusted fingerprint accepted it), or `http` for an HTTP host.
    pub fn host_key(&self) -> Option<String> {
        if self.endpoint.https {
            locks::lock(&self.accepted)
                .clone()
                .map(|print| format!("{CERT_KEY_TYPE} {print}"))
        } else {
            Some("http".to_owned())
        }
    }

    /// One message on a free connection (opened and signed in when none is): the answer's text.
    pub async fn post(&self, xml: &str, timeout: Duration) -> Result<Answered> {
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| CoreError::Winrm("the connection is closed".into()))?;
        let reused = {
            let mut idle = locks::lock(&self.idle);
            idle.retain(|(c, since)| !c.closed() && since.elapsed() < MAX_IDLE);
            idle.pop().map(|(c, _)| c)
        };
        let mut connection = match reused {
            Some(connection) => connection,
            None => {
                let (connection, peer) = Connection::open(&self.endpoint, &self.sign_in, &self.accepted).await?;
                if let Some(peer) = peer {
                    *locks::lock(&self.peer) = Some(peer);
                }
                connection
            }
        };
        let answered = connection.post(&self.endpoint, xml, timeout).await?;
        // A connection that failed is dropped with its error; a good one goes back for the next message.
        if !connection.closed() {
            locks::lock(&self.idle).push((connection, std::time::Instant::now()));
        }
        Ok(answered)
    }

    /// Closes every idle connection and refuses new messages.
    pub fn close(&self) {
        self.permits.close();
        locks::lock(&self.idle).clear();
    }

    /// A shell made on the host.
    pub(super) fn shell_opened(&self, id: &str) {
        locks::lock(&self.live).insert(id.to_owned());
    }

    /// The shells not deleted yet.
    pub fn live_shells(&self) -> Vec<String> {
        locks::lock(&self.live).iter().cloned().collect()
    }

    /// Deletes a shell on the host (and what runs in it), once, within 10 s. Also after [`Client::close`]: then on a
    /// connection of its own, outside the limit on connections, so a closing session leaves nothing running.
    pub async fn delete_shell(&self, id: &str) {
        if !locks::lock(&self.live).remove(id) {
            return;
        }
        let header = super::soap::Header {
            to: &self.endpoint.url(),
            action: super::soap::ACTION_DELETE,
            shell_id: Some(id),
            options: &[],
            timeout_secs: 10,
        };
        let xml = super::soap::envelope(&header, "");
        let deleted = if self.is_closed() {
            self.post_unlimited(&xml, Duration::from_secs(10)).await
        } else {
            self.post(&xml, Duration::from_secs(10)).await
        };
        if let Err(err) = deleted {
            tracing::debug!(error = %err, "winrm: a shell could not be deleted; the host drops it when it idles");
        }
    }

    /// One message on a connection of its own, whatever the limit: only for cleaning up after [`Client::close`].
    async fn post_unlimited(&self, xml: &str, timeout: Duration) -> Result<Answered> {
        let (mut connection, _) =
            tokio::time::timeout(timeout, Connection::open(&self.endpoint, &self.sign_in, &self.accepted))
                .await
                .map_err(|_| CoreError::Timeout {
                    command: "deleting a shell".into(),
                    seconds: timeout.as_secs(),
                })??;
        connection.post(&self.endpoint, xml, timeout).await
    }

    pub fn is_closed(&self) -> bool {
        self.permits.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_give_the_negotiate_token() {
        let challenges = vec!["Basic realm=\"WSMAN\"".to_owned(), "Negotiate TlRMTVNTUAAC".to_owned()];
        assert_eq!(
            challenge_token(&challenges).unwrap().unwrap(),
            b"NTLMSSP\0\x02".to_vec()
        );
        assert_eq!(challenge_token(&["Negotiate".to_owned()]).unwrap(), None);
        assert!(challenge_token(&["Negotiate !!!".to_owned()]).is_err());
        let long = format!("Negotiate {}", "A".repeat(MAX_TOKEN + 4));
        assert!(challenge_token(&[long]).is_err());
    }

    #[test]
    fn basic_holds_the_user_and_password() {
        let password = SecretString::new("pa:ss");
        let SignIn::Basic { header } = SignIn::basic("alice", &password) else {
            panic!("basic");
        };
        assert_eq!(header.as_str(), "Basic YWxpY2U6cGE6c3M=");
        assert!(fingerprint(b"x").starts_with("SHA256:"));
    }
}
