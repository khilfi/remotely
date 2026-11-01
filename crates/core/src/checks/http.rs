//! MO-08: an HTTP(S) check: one GET over the stream F1's probes open ([`Reach`]: a TCP connection from this PC, or a
//! jump host's direct-tcpip channel), so it goes the same way directly and through a jump host, and never through a
//! proxy (the system proxy has no business with addresses inside the customer's network). HTTP/1.1 with
//! `Connection: close`.
//!
//! Bounded against a hostile server: the status line and headers fit in [`MAX_HEADER_BYTES`] (hyper refuses more,
//! and at most 100 headers), the body is read only when the check looks for text in it, and then only its first
//! [`MAX_BODY_BYTES`]; at most [`MAX_REDIRECTS`] redirects, to `http` and `https` addresses only; the whole run within
//! the check's timeout. HTTPS checks the certificate against Windows' trust store and the name, as F1's certificate
//! viewer does, unless the check allows certificate errors.

use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, CONNECTION, HOST, LOCATION, USER_AGENT};
use hyper_util::rt::TokioIo;

use super::probe::Probed;
use crate::adapters::net_tools::{BoxedStream, NetworkTools, TrustUse};
use crate::toolbox::{certs, Reach, Toolbox};

/// The status line and headers, at most (hyper's own buffer).
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
/// The body read when looking for text, at most.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
pub const MAX_REDIRECTS: usize = 5;

/// What an HTTP check asks, from its spec and target.
pub(super) struct HttpAsk<'a> {
    pub host: String,
    pub https: bool,
    pub port: Option<u16>,
    pub path: String,
    pub status: (u16, u16),
    pub body_contains: Option<&'a str>,
    pub follow_redirects: bool,
    pub allow_invalid_cert: bool,
}

/// One answer.
struct Answer {
    status: u16,
    location: Option<String>,
    /// The body's first bytes, when the check reads it, and whether there was more.
    body: Option<(Vec<u8>, bool)>,
}

/// A failed step, in words.
type Step<T> = std::result::Result<T, String>;

fn left(deadline: Instant) -> Step<Duration> {
    let now = Instant::now();
    if now >= deadline {
        Err("no answer in time".into())
    } else {
        Ok(deadline - now)
    }
}

/// Runs the check.
pub(super) async fn check(
    toolbox: &Toolbox,
    tools: &dyn NetworkTools,
    reach: Reach,
    ask: HttpAsk<'_>,
    timeout: Duration,
) -> Probed {
    let started = Instant::now();
    let deadline = started + timeout;
    let mut reach = reach;
    let mut host = ask.host.clone();
    let mut https = ask.https;
    let mut port = ask.port;
    let mut path = ask.path.clone();
    let mut redirects = 0usize;
    loop {
        let answer = match one(tools, &reach, &host, https, port, &path, &ask, deadline).await {
            Ok(answer) => answer,
            Err(why) => return Probed::down(None, why),
        };
        let is_redirect = matches!(answer.status, 301 | 302 | 303 | 307 | 308);
        if ask.follow_redirects && is_redirect {
            if redirects >= MAX_REDIRECTS {
                return Probed::down(None, format!("more than {MAX_REDIRECTS} redirects"));
            }
            let Some(next) = answer
                .location
                .as_deref()
                .and_then(|l| next_place(https, &host, port, &path, l))
            else {
                return Probed::down(
                    None,
                    format!(
                        "HTTP {}: a redirect to an address Remotely doesn't follow",
                        answer.status
                    ),
                );
            };
            redirects += 1;
            if !next.host.eq_ignore_ascii_case(&host) {
                reach = match reach_for(toolbox, &reach, &next.host).await {
                    Ok(reach) => reach,
                    Err(why) => return Probed::down(None, why),
                };
            }
            (host, https, port, path) = (next.host, next.https, next.port, next.path);
            continue;
        }
        let took = crate::toolbox::millis(started.elapsed());
        let after = match redirects {
            0 => String::new(),
            1 => " after 1 redirect".into(),
            n => format!(" after {n} redirects"),
        };
        let (min, max) = ask.status;
        if !(min..=max).contains(&answer.status) {
            return Probed::down(
                Some(took),
                format!("HTTP {}{after} (expected {min}-{max})", answer.status),
            );
        }
        if let (Some(text), Some((body, more))) = (ask.body_contains, &answer.body) {
            if !String::from_utf8_lossy(body).contains(text) {
                let read = if *more { " (its first 256 KB read)" } else { "" };
                return Probed::down(
                    Some(took),
                    format!(
                        "HTTP {}{after}, but the body doesn't hold the text{read}",
                        answer.status
                    ),
                );
            }
        }
        return Probed::up(took, format!("HTTP {}{after} in {took} ms", answer.status));
    }
}

/// Where a redirect goes.
struct Place {
    host: String,
    https: bool,
    port: Option<u16>,
    path: String,
}

/// The place a `Location` names, relative to the request's own; `None` for anything but `http` and `https`.
fn next_place(https: bool, host: &str, port: Option<u16>, path: &str, location: &str) -> Option<Place> {
    let scheme = if https { "https" } else { "http" };
    let authority = match port {
        Some(p) => crate::known_hosts::address(host, p),
        None if host.contains(':') => format!("[{host}]"),
        None => host.to_owned(),
    };
    let base = url::Url::parse(&format!("{scheme}://{authority}{path}")).ok()?;
    let next = base.join(location.trim()).ok()?;
    let https = match next.scheme() {
        "https" => true,
        "http" => false,
        _ => return None,
    };
    let host = crate::toolbox::check_host(next.host_str()?).ok()?;
    let mut path = next.path().to_owned();
    if let Some(query) = next.query() {
        path.push('?');
        path.push_str(query);
    }
    if path.len() > super::spec::MAX_PATH || !path.chars().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    Some(Place {
        host,
        https,
        port: next.port(),
        path,
    })
}

/// How a redirect to another host is reached: through the same jump host, or from this PC.
async fn reach_for(toolbox: &Toolbox, reach: &Reach, host: &str) -> Step<Reach> {
    match reach {
        Reach::Jump { connection, jump, .. } => Ok(Reach::Jump {
            connection: connection.clone(),
            jump: jump.clone(),
            host: host.to_owned(),
        }),
        Reach::Direct { tools, .. } => match toolbox.address_of(host).await {
            Ok(address) => Ok(Reach::Direct {
                tools: tools.clone(),
                address,
            }),
            Err(err) => Err(format!("a redirect to {host}, which doesn't resolve: {err}")),
        },
    }
}

/// One request and its answer.
#[allow(clippy::too_many_arguments)]
async fn one(
    tools: &dyn NetworkTools,
    reach: &Reach,
    host: &str,
    https: bool,
    port: Option<u16>,
    path: &str,
    ask: &HttpAsk<'_>,
    deadline: Instant,
) -> Step<Answer> {
    let port = port.unwrap_or(if https { 443 } else { 80 });
    let stream = reach
        .open(port, left(deadline)?)
        .await
        .map_err(|failure| match (&failure, reach.via()) {
            (crate::adapters::net_tools::ConnectFailure::Refused, Some(jump)) => {
                format!("port {port}: closed, or the jump host '{jump}' can't reach it")
            }
            _ => format!("port {port}: {}", failure.describe()),
        })?;
    let stream: BoxedStream = if https {
        let name = certs::server_name(host).map_err(|err| err.to_string())?;
        let (tls, chain) = certs::tls_connect(stream, name, left(deadline)?)
            .await
            .map_err(|err| err.to_string())?;
        if !ask.allow_invalid_cert {
            certificate_problem(tools, &chain, host).await?;
        }
        Box::new(tls)
    } else {
        stream
    };
    let default_port = if https { 443 } else { 80 };
    let host_header = if port == default_port {
        if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        }
    } else {
        crate::known_hosts::address(host, port)
    };
    let read_body = ask.body_contains.is_some();
    match tokio::time::timeout(left(deadline)?, request(stream, &host_header, path, read_body)).await {
        Ok(answer) => answer,
        Err(_) => Err("no answer in time".into()),
    }
}

/// The certificate is trusted by Windows, names the host and hasn't expired; else why not.
async fn certificate_problem(tools: &dyn NetworkTools, chain: &[Vec<u8>], host: &str) -> Step<()> {
    let report = certs::report_for(tools, chain, TrustUse::TlsServer)
        .await
        .map_err(|err| format!("the certificate can't be read: {err}"))?;
    if report.days_left.is_some_and(|d| d < 0) {
        return Err("the certificate has expired".into());
    }
    if !report.trusted {
        let why = report
            .trust_problems
            .first()
            .cloned()
            .unwrap_or_else(|| "Windows doesn't trust it".into());
        return Err(format!("the certificate isn't trusted: {why}"));
    }
    if report.chain.first().is_some_and(|leaf| !leaf.matches_host(host)) {
        return Err(format!("the certificate doesn't name {host}"));
    }
    Ok(())
}

/// Stops hyper's connection task when the request is done or dropped.
struct Driver(tokio::task::JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn request(stream: BoxedStream, host_header: &str, path: &str, read_body: bool) -> Step<Answer> {
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder.max_buf_size(MAX_HEADER_BYTES);
    let (mut sender, connection) = builder
        .handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
        .await
        .map_err(|err| format!("HTTP failed: {err}"))?;
    let _driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let request = hyper::Request::get(path)
        .header(HOST, host_header)
        .header(
            USER_AGENT,
            concat!("Remotely/", env!("CARGO_PKG_VERSION"), " health check"),
        )
        .header(ACCEPT, "*/*")
        .header(CONNECTION, "close")
        .body(Empty::<Bytes>::new())
        .map_err(|err| format!("the request can't be made: {err}"))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|err| format!("HTTP failed: {}", words(&err)))?;
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = if read_body {
        let mut body = response.into_body();
        let mut read = Vec::new();
        let mut more = false;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|err| format!("the body broke off: {}", words(&err)))?;
            if let Ok(data) = frame.into_data() {
                let room = MAX_BODY_BYTES - read.len();
                if data.len() > room {
                    read.extend_from_slice(data.get(..room).unwrap_or_default());
                    more = true;
                    break;
                }
                read.extend_from_slice(&data);
            }
        }
        Some((read, more))
    } else {
        None
    };
    Ok(Answer { status, location, body })
}

/// hyper's error in a few words.
fn words(err: &hyper::Error) -> String {
    if err.is_parse() {
        "the answer isn't HTTP, or its headers are too large".into()
    } else if err.is_incomplete_message() {
        "the connection closed before the answer was complete".into()
    } else {
        err.to_string()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn redirects_follow_http_and_https_only() {
        let next = next_place(
            false,
            "web01.example.com",
            None,
            "/old",
            "https://web01.example.com/new?a=1",
        )
        .unwrap();
        assert!(next.https);
        assert_eq!(next.host, "web01.example.com");
        assert_eq!(next.path, "/new?a=1");
        assert_eq!(next.port, None);
        let relative = next_place(true, "192.0.2.10", Some(8443), "/a/b", "c").unwrap();
        assert_eq!(relative.path, "/a/c");
        assert_eq!(relative.port, Some(8443));
        assert_eq!(relative.host, "192.0.2.10");
        let v6 = next_place(false, "2001:db8::1", None, "/", "/up").unwrap();
        assert_eq!(v6.host, "2001:db8::1");
        assert!(next_place(false, "web01.example.com", None, "/", "file:///etc/passwd").is_none());
        assert!(next_place(false, "web01.example.com", None, "/", "javascript:alert(1)").is_none());
        assert!(next_place(false, "web01.example.com", None, "/", "ftp://web01.example.com/").is_none());
    }
}
