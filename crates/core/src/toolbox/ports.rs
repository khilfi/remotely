//! FD-09 port check: a TCP connection to each of up to [`MAX_PORTS`] ports, with a timeout, and optionally the first
//! bytes the service sends (a banner: SSH's version line, an SMTP greeting), with control and format characters
//! removed. It connects and closes; it sends nothing. Behind a jump host each connection starts there (SS-07).

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::{millis, ProbeProgress, ProbeTarget, Progress, Reach, Route};
use crate::adapters::net_tools::ConnectFailure;
use crate::error::{CoreError, Result};

/// Ports one run checks at most: a check, not a scanner.
pub const MAX_PORTS: usize = 100;
/// Bytes of a banner kept.
pub const BANNER_BYTES: usize = 256;
/// How long a service may take to send its banner.
pub const BANNER_WAIT: Duration = Duration::from_millis(1500);
/// Connections at once from this PC, and through a jump host.
const PARALLEL_DIRECT: usize = 8;
const PARALLEL_JUMP: usize = 4;

fn default_timeout() -> u64 {
    3000
}

/// What the Ports tab asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortRequest {
    pub target: ProbeTarget,
    /// `22, 80, 443, 8000-8010`. Empty for a session: its own port.
    #[serde(default)]
    pub ports: String,
    /// Milliseconds each connection may take.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Read what the service sends first.
    #[serde(default)]
    pub banner: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PortState {
    /// It took the connection.
    Open,
    /// Refused: nothing listens (behind a jump host: or the jump host couldn't reach it).
    Closed,
    /// No answer in time: a firewall drops it, or the host is off.
    NoAnswer,
    /// Something else went wrong.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    /// How long connecting took, when it opened.
    pub ms: Option<u64>,
    pub banner: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortSummary {
    pub label: String,
    pub host: String,
    /// The address connected to from this PC; `None` behind a jump host.
    pub address: Option<String>,
    /// The jump host the connections started from.
    pub via: Option<String>,
    /// In the order asked.
    pub results: Vec<PortResult>,
    pub open: usize,
    pub cancelled: bool,
}

/// The ports in `22, 80 443; 8000-8010`, in order and each once. Empty: the session's own port, if there is one.
pub fn parse_ports(text: &str, default: Option<u16>) -> Result<Vec<u16>> {
    let mut ports: Vec<u16> = Vec::new();
    let bad = |part: &str| CoreError::InvalidInput(format!("'{part}' isn't a port or a range (like 8000-8010)."));
    for part in text
        .split([',', ';', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let (from, to) = match part.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (part, part),
        };
        let from: u16 = from.parse().map_err(|_| bad(part))?;
        let to: u16 = to.parse().map_err(|_| bad(part))?;
        if from == 0 || to < from {
            return Err(bad(part));
        }
        if usize::from(to - from) >= MAX_PORTS {
            return Err(too_many());
        }
        for port in from..=to {
            if !ports.contains(&port) {
                ports.push(port);
                if ports.len() > MAX_PORTS {
                    return Err(too_many());
                }
            }
        }
    }
    if ports.is_empty() {
        return match default {
            Some(port) => Ok(vec![port]),
            None => Err(CoreError::InvalidInput("Type the ports to check, like 22, 443.".into())),
        };
    }
    Ok(ports)
}

fn too_many() -> CoreError {
    CoreError::InvalidInput(format!(
        "A check takes at most {MAX_PORTS} ports at a time: it checks ports, it doesn't scan for them."
    ))
}

/// What a banner shows: the text without control or format characters, runs of spaces made one.
pub fn clean_banner(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for c in text.chars() {
        let c = if matches!(c, '\r' | '\n' | '\t') { ' ' } else { c };
        if c.is_control() || crate::untrusted::is_format_char(c) || c == '\u{fffd}' {
            continue;
        }
        if c == ' ' && out.ends_with(' ') {
            continue;
        }
        out.push(c);
    }
    let out = out.trim().to_owned();
    (!out.is_empty()).then_some(out)
}

/// Checks every port, a few at a time, each result reported as it comes.
pub(super) async fn check(
    route: &Route,
    reach: &Reach,
    ports: &[u16],
    request: &PortRequest,
    cancel: &CancellationToken,
    progress: Progress<'_>,
) -> PortSummary {
    let timeout = Duration::from_millis(request.timeout_ms.clamp(100, 30_000));
    let parallel = match reach {
        Reach::Direct { .. } => PARALLEL_DIRECT,
        Reach::Jump { .. } => PARALLEL_JUMP,
    };
    let limit = Arc::new(Semaphore::new(parallel));
    let mut running = JoinSet::new();
    for &port in ports {
        let limit = Arc::clone(&limit);
        let reach = reach.clone();
        let cancel = cancel.clone();
        let banner = request.banner;
        running.spawn(async move {
            let _permit = limit.acquire_owned().await;
            if cancel.is_cancelled() {
                return None;
            }
            tokio::select! {
                result = one(&reach, port, timeout, banner) => Some(result),
                () = cancel.cancelled() => None,
            }
        });
    }
    let mut results = Vec::new();
    while let Some(done) = running.join_next().await {
        if let Ok(Some(result)) = done {
            progress(ProbeProgress::Port { result: result.clone() });
            results.push(result);
        }
    }
    results.sort_by_key(|r| ports.iter().position(|p| *p == r.port));
    PortSummary {
        label: route.label.clone(),
        host: route.host.clone(),
        address: reach.address().map(|a| a.to_string()),
        via: reach.via(),
        open: results.iter().filter(|r| r.state == PortState::Open).count(),
        cancelled: cancel.is_cancelled() || results.len() < ports.len(),
        results,
    }
}

async fn one(reach: &Reach, port: u16, timeout: Duration, banner: bool) -> PortResult {
    let started = Instant::now();
    match reach.open(port, timeout).await {
        Ok(mut stream) => {
            let ms = Some(millis(started.elapsed()));
            let banner = if banner {
                let mut buf = vec![0u8; BANNER_BYTES];
                match tokio::time::timeout(BANNER_WAIT.min(timeout), stream.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => clean_banner(&buf[..n]),
                    _ => None,
                }
            } else {
                None
            };
            PortResult {
                port,
                state: PortState::Open,
                ms,
                banner,
                detail: None,
            }
        }
        Err(failure) => {
            let (state, detail) = match (&failure, reach.via()) {
                (ConnectFailure::Refused, Some(jump)) => (
                    PortState::Closed,
                    Some(format!("closed, or the jump host '{jump}' can't reach it")),
                ),
                (ConnectFailure::Refused, None) => (PortState::Closed, None),
                (ConnectFailure::TimedOut, _) => (PortState::NoAnswer, None),
                (ConnectFailure::Other(why), _) => (PortState::Failed, Some(why.clone())),
            };
            PortResult {
                port,
                state,
                ms: None,
                banner: None,
                detail,
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ports_and_ranges_are_read_in_order_and_once() {
        assert_eq!(
            parse_ports("22, 80 443;8000-8002", None).unwrap(),
            [22, 80, 443, 8000, 8001, 8002]
        );
        assert_eq!(parse_ports("443,22,443", None).unwrap(), [443, 22]);
        assert_eq!(parse_ports(" ", Some(2222)).unwrap(), [2222]);
        assert!(parse_ports("", None).is_err());
        for bad in ["0", "65536", "ssh", "90-80", "1-2-3", "-5"] {
            assert!(parse_ports(bad, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_run_takes_at_most_a_hundred_ports() {
        assert_eq!(parse_ports("1-100", None).unwrap().len(), 100);
        assert!(parse_ports("1-101", None).is_err());
        assert!(parse_ports("1-65535", None).is_err());
        assert!(parse_ports("1-60, 61-100, 200", None).is_err());
    }

    #[test]
    fn banners_lose_control_and_format_characters() {
        assert_eq!(
            clean_banner(b"SSH-2.0-OpenSSH_9.6\r\n").as_deref(),
            Some("SSH-2.0-OpenSSH_9.6")
        );
        assert_eq!(
            clean_banner("220 mail\u{202e}gnp\u{7} ready\r\n\r\n".as_bytes()).as_deref(),
            Some("220 mailgnp ready")
        );
        assert_eq!(clean_banner(b"\x00\x01\x02"), None);
        assert_eq!(clean_banner(&[0xff, 0xfe, b'o', b'k']).as_deref(), Some("ok"));
    }
}
