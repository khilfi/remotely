//! FD-09 certificate viewer. A TLS handshake to a host and port (with SNI) takes whatever chain the server sends, so
//! it can be read even when it wouldn't be trusted; then Windows checks it against its trust store (only what this PC
//! has: nothing is downloaded, and revocation isn't checked), and the name is checked against the leaf's alternative
//! names. Nothing is sent after the handshake. A `.crt`, `.cer` or `.pem` file can be opened instead (A3's path
//! rules, at most 1 MB).

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;

use super::x509::{self, CertificateInfo};
use super::{ProbeTarget, Reach, Route};
use crate::adapters::net_tools::{BoxedStream, NetworkTools, TrustUse, TrustVerdict};
use crate::error::{CoreError, Result};
use crate::locks;

/// The largest certificate file read.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

fn default_port() -> u16 {
    443
}
fn default_timeout() -> u64 {
    10_000
}

/// What the Certificate tab asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertRequest {
    pub target: ProbeTarget,
    #[serde(default = "default_port")]
    pub port: u16,
    /// The name sent as SNI and checked against the certificate; empty: the host, when it is a name.
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

/// What the viewer shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateReport {
    /// `web01 (web01.example.com:443)`, or the file's name.
    pub source: String,
    /// The address connected to from this PC; `None` behind a jump host or for a file.
    pub address: Option<String>,
    pub via: Option<String>,
    /// The name sent as SNI, and checked.
    pub server_name: Option<String>,
    /// "TLS 1.3".
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    /// As the server sent it (or the file holds it), the leaf first.
    pub chain: Vec<CertificateInfo>,
    /// The subjects of the chain Windows built, leaf first (with the root from this PC's store).
    pub built: Vec<String>,
    pub trusted: bool,
    pub trust_problems: Vec<String>,
    /// The leaf names the server name; `None` for a file, or with no name to check.
    pub name_matches: Option<bool>,
    /// Days until the leaf expires; negative once it has.
    pub days_left: Option<i64>,
    /// The handshake failed after the chain was read (its signature, a protocol the server offers...).
    pub handshake_error: Option<String>,
    /// Certificates sent after the leaf that couldn't be read, in words ("the 2nd certificate: ..."); the rest of the
    /// report still stands.
    pub unreadable: Vec<String>,
    /// FD-03: the host checked; `None` for a file.
    pub host: Option<String>,
    /// FD-03: the names the report shows that may be a customer's hosts (the server name, the leaf's common name and
    /// DNS alternative names), for the presentation masker to learn.
    pub hosts: Vec<String>,
}

/// Takes any chain and keeps it, so the viewer can show what Windows wouldn't trust. The handshake's signature is
/// still checked: the server holds the key of the certificate it shows.
#[derive(Debug)]
struct ReadAnyChain {
    provider: Arc<rustls::crypto::CryptoProvider>,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ServerCertVerifier for ReadAnyChain {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let mut chain = vec![end_entity.as_ref().to_vec()];
        chain.extend(intermediates.iter().take(16).map(|c| c.as_ref().to_vec()));
        *locks::lock(&self.seen) = chain;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// What the handshake gave.
struct Handshake {
    chain: Vec<Vec<u8>>,
    protocol: Option<String>,
    cipher: Option<String>,
    error: Option<String>,
}

/// A TLS handshake over `stream`, keeping the chain the server sends.
async fn handshake(stream: BoxedStream, name: ServerName<'static>, timeout: Duration) -> Result<Handshake> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let verifier = Arc::new(ReadAnyChain {
        provider: Arc::clone(&provider),
        seen: Arc::clone(&seen),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| CoreError::Network(format!("TLS isn't available: {err}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let done = tokio::time::timeout(timeout, connector.connect(name, stream)).await;
    let chain = locks::lock(&seen).clone();
    match done {
        Ok(Ok(mut tls)) => {
            let (protocol, cipher) = {
                let (_, connection) = tls.get_ref();
                (
                    connection.protocol_version().map(protocol_name),
                    connection.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite())),
                )
            };
            // Close politely; nothing else is sent.
            let _ = tokio::time::timeout(Duration::from_secs(1), tls.shutdown()).await;
            Ok(Handshake {
                chain,
                protocol,
                cipher,
                error: None,
            })
        }
        Ok(Err(err)) if !chain.is_empty() => Ok(Handshake {
            chain,
            protocol: None,
            cipher: None,
            error: Some(handshake_words(&err)),
        }),
        Ok(Err(err)) => Err(CoreError::Network(format!(
            "the TLS handshake failed: {}",
            handshake_words(&err)
        ))),
        Err(_) if !chain.is_empty() => Ok(Handshake {
            chain,
            protocol: None,
            cipher: None,
            error: Some(format!(
                "the handshake didn't finish within {} s",
                timeout.as_secs().max(1)
            )),
        }),
        Err(_) => Err(CoreError::Network(format!(
            "no TLS answer within {} s: is it a TLS port?",
            timeout.as_secs().max(1)
        ))),
    }
}

fn handshake_words(err: &std::io::Error) -> String {
    let text = err.to_string();
    if text.contains("PeerIncompatible") || text.contains("protocol version") {
        "the server offers no TLS version Remotely speaks (1.2 or 1.3)".into()
    } else if text.contains("InvalidContentType") || text.contains("corrupt message") {
        "the port doesn't speak TLS".into()
    } else {
        text
    }
}

fn protocol_name(version: rustls::ProtocolVersion) -> String {
    match version {
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".into(),
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".into(),
        other => format!("{other:?}"),
    }
}

/// The name a TLS client sends (SNI) for a host name or an IP address.
pub(crate) fn server_name(name: &str) -> Result<ServerName<'static>> {
    match crate::adapters::network::ip_literal(name) {
        Some(ip) => Ok(ServerName::IpAddress(ip.into())),
        None => ServerName::try_from(name.to_owned())
            .map_err(|_| CoreError::InvalidInput(format!("'{name}' can't be sent as a TLS server name."))),
    }
}

/// MO-08: a TLS connection over `stream` for an HTTPS check, speaking HTTP/1.1, with the chain the server sent. Any
/// chain is taken here (its handshake signature still checked); the caller checks it against Windows' trust store and
/// the name with [`report_for`], so a check that allows certificate errors still gets its answer.
pub(crate) async fn tls_connect(
    stream: BoxedStream,
    name: ServerName<'static>,
    timeout: Duration,
) -> Result<(tokio_rustls::client::TlsStream<BoxedStream>, Vec<Vec<u8>>)> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let verifier = Arc::new(ReadAnyChain {
        provider: Arc::clone(&provider),
        seen: Arc::clone(&seen),
    });
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| CoreError::Network(format!("TLS isn't available: {err}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    match tokio::time::timeout(timeout, connector.connect(name, stream)).await {
        Ok(Ok(tls)) => {
            let chain = locks::lock(&seen).clone();
            Ok((tls, chain))
        }
        Ok(Err(err)) => Err(CoreError::Network(format!(
            "the TLS handshake failed: {}",
            handshake_words(&err)
        ))),
        Err(_) => Err(CoreError::Network(format!(
            "no TLS answer within {} s: is it a TLS port?",
            timeout.as_secs().max(1)
        ))),
    }
}

/// The certificate a server presents, read and checked.
pub(crate) async fn from_server(
    tools: &dyn NetworkTools,
    route: &Route,
    reach: &Reach,
    request: &CertRequest,
) -> Result<CertificateReport> {
    if request.port == 0 {
        return Err(CoreError::InvalidInput("Choose a port from 1 to 65535.".into()));
    }
    let timeout = Duration::from_millis(request.timeout_ms.clamp(1000, 60_000));
    let typed = request
        .server_name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(super::check_host)
        .transpose()?;
    let checked_name = typed.clone().unwrap_or_else(|| route.host.clone());
    let sni = server_name(&checked_name)?;
    let stream = reach
        .open(request.port, timeout)
        .await
        .map_err(|failure| CoreError::Network(format!("port {}: {}", request.port, failure.describe())))?;
    let shaken = handshake(stream, sni, timeout).await?;
    let mut report = report_for(tools, &shaken.chain, TrustUse::TlsServer).await?;
    report.source = format!(
        "{} ({})",
        route.label,
        crate::known_hosts::address(&route.host, request.port)
    );
    report.address = reach.address().map(|a| a.to_string());
    report.via = reach.via();
    report.server_name = Some(checked_name.clone());
    report.protocol = shaken.protocol;
    report.cipher = shaken.cipher;
    report.handshake_error = shaken.error;
    report.name_matches = report.chain.first().map(|leaf| leaf.matches_host(&checked_name));
    report.host = Some(route.host.clone());
    if !report.hosts.contains(&checked_name) {
        report.hosts.insert(0, checked_name);
    }
    Ok(report)
}

/// A certificate file picked in a dialog.
pub(super) async fn from_file(tools: &dyn NetworkTools, path: &Path) -> Result<CertificateReport> {
    if let Some(refusal) = crate::untrusted::path_refusal(path) {
        return Err(CoreError::InvalidInput(format!(
            "Remotely doesn't open that file: it {}.",
            refusal.describe()
        )));
    }
    let bytes = crate::untrusted::read_capped(path, MAX_FILE_BYTES).await?;
    let chain = x509::certificates_in(&bytes)?;
    let mut report = report_for(tools, &chain, TrustUse::Any).await?;
    report.source = path
        .file_name()
        .map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned());
    Ok(report)
}

/// The chain read and checked, with nothing about where it came from yet.
pub(crate) async fn report_for(
    tools: &dyn NetworkTools,
    chain: &[Vec<u8>],
    usage: TrustUse,
) -> Result<CertificateReport> {
    if chain.is_empty() {
        return Err(CoreError::Network("the server sent no certificate".into()));
    }
    // The leaf must be readable; a bad certificate after it is noted, and the report goes on.
    let mut infos: Vec<CertificateInfo> = vec![x509::parse(&chain[0])?];
    let mut unreadable = Vec::new();
    for (i, der) in chain.iter().enumerate().skip(1) {
        match x509::parse(der) {
            Ok(info) => infos.push(info),
            Err(err) => unreadable.push(format!("the {} certificate sent: {err}", ordinal(i + 1))),
        }
    }
    let leaf = &infos[0];
    let mut hosts: Vec<String> = leaf
        .dns_names
        .iter()
        .map(|n| n.trim_start_matches("*.").to_owned())
        .collect();
    hosts.extend(leaf.subject_common_name.clone());
    let mut seen = std::collections::HashSet::new();
    hosts.retain(|h| !h.is_empty() && seen.insert(h.to_ascii_lowercase()));
    let verdict = tools
        .check_chain(chain, usage)
        .await
        .unwrap_or_else(|err| TrustVerdict {
            trusted: false,
            problems: vec![err.to_string()],
            built: Vec::new(),
        });
    let built = verdict
        .built
        .iter()
        .filter_map(|der| x509::parse(der).ok())
        .map(|info| info.subject)
        .collect();
    let now = OffsetDateTime::now_utc();
    Ok(CertificateReport {
        source: String::new(),
        address: None,
        via: None,
        server_name: None,
        protocol: None,
        cipher: None,
        days_left: infos.first().and_then(|leaf| leaf.days_left(now)),
        chain: infos,
        built,
        trusted: verdict.trusted,
        trust_problems: verdict.problems,
        name_matches: None,
        handshake_error: None,
        unreadable,
        host: None,
        hosts,
    })
}

/// "2nd", "3rd", "11th".
fn ordinal(n: usize) -> String {
    let suffix = match (n % 10, n % 100) {
        (1, r) if r != 11 => "st",
        (2, r) if r != 12 => "nd",
        (3, r) if r != 13 => "rd",
        _ => "th",
    };
    format!("{n}{suffix}")
}
