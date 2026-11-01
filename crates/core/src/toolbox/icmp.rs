//! FD-09 ping and trace route, from this PC (Windows' ICMP API: no administrator rights). A session behind a jump
//! host can't be pinged from here, and the tools say so instead of pinging a name that only resolves over there.

use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::{ProbeProgress, ProbeTarget, Progress, Route};
use crate::adapters::net_tools::{Echo, EchoRequest, NetworkTools};
use crate::adapters::network::NetworkAdapter;
use crate::error::{CoreError, Result};

/// Echo requests one ping run sends at most.
pub const MAX_COUNT: u32 = 1000;
/// The shortest wait between two echo requests.
pub const MIN_INTERVAL_MS: u64 = 1000;
/// The largest request Windows sends.
pub const MAX_SIZE: u16 = 65500;
/// Trace route's hop limit.
pub const MAX_HOPS: u8 = 30;
/// Requests per hop.
pub const PROBES_PER_HOP: usize = 3;

fn default_count() -> u32 {
    4
}
fn default_interval() -> u64 {
    MIN_INTERVAL_MS
}
fn default_size() -> u16 {
    32
}
fn default_timeout() -> u64 {
    2000
}
fn default_hops() -> u8 {
    MAX_HOPS
}

/// What the Ping tab asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PingRequest {
    pub target: ProbeTarget,
    #[serde(default = "default_count")]
    pub count: u32,
    /// Milliseconds between requests, at least [`MIN_INTERVAL_MS`].
    #[serde(default = "default_interval")]
    pub interval_ms: u64,
    /// Bytes of data in each request.
    #[serde(default = "default_size")]
    pub size: u16,
    /// Milliseconds each reply may take.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn check_timeout(timeout_ms: u64) -> Result<()> {
    if !(100..=10_000).contains(&timeout_ms) {
        return Err(CoreError::InvalidInput(
            "A reply's timeout is 0.1 to 10 seconds.".into(),
        ));
    }
    Ok(())
}

impl PingRequest {
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_COUNT).contains(&self.count) {
            return Err(CoreError::InvalidInput(format!("Send 1 to {MAX_COUNT} requests.")));
        }
        if !(MIN_INTERVAL_MS..=60_000).contains(&self.interval_ms) {
            return Err(CoreError::InvalidInput("Requests go 1 to 60 seconds apart.".into()));
        }
        if self.size > MAX_SIZE {
            return Err(CoreError::InvalidInput(format!(
                "A request holds at most {MAX_SIZE} bytes."
            )));
        }
        check_timeout(self.timeout_ms)
    }
}

/// One request's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingReply {
    pub seq: u32,
    pub echo: Echo,
}

/// A ping run's result.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingSummary {
    pub label: String,
    pub host: String,
    pub address: IpAddr,
    pub replies: Vec<PingReply>,
    pub sent: u32,
    pub received: u32,
    /// Percent of requests without a reply.
    pub loss_percent: f64,
    pub min_ms: Option<u32>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<u32>,
    /// Stopped before it sent them all.
    pub cancelled: bool,
}

/// Ping and trace route go from this PC: a session behind a jump host can't be reached that way.
pub(super) fn refuse_jump(route: &Route, what: &str) -> Result<()> {
    match &route.via {
        Some(jump) => Err(CoreError::InvalidInput(format!(
            "'{}' is behind the jump host '{}', so this PC can't {what} it: ping and trace route go from this PC. \
             Check its ports instead, which go through the jump host.",
            route.label, jump.name
        ))),
        None => Ok(()),
    }
}

/// Waits `wait`, or less when cancelled. True when cancelled.
async fn pause(wait: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        () = tokio::time::sleep(wait) => false,
        () = cancel.cancelled() => true,
    }
}

/// Sends the run's requests one after another.
pub(super) async fn ping(
    tools: &dyn NetworkTools,
    route: &Route,
    address: IpAddr,
    request: &PingRequest,
    cancel: &CancellationToken,
    progress: Progress<'_>,
) -> PingSummary {
    let mut replies = Vec::new();
    let mut cancelled = false;
    for seq in 1..=request.count {
        if cancel.is_cancelled() {
            cancelled = true;
            break;
        }
        let echo = tokio::select! {
            echo = tools.echo(EchoRequest {
                to: address,
                ttl: 128,
                size: request.size,
                timeout: Duration::from_millis(request.timeout_ms),
            }) => echo.unwrap_or_else(|err| Echo::Unreachable { from: None, reason: err.to_string() }),
            () = cancel.cancelled() => {
                cancelled = true;
                break;
            }
        };
        let reply = PingReply { seq, echo };
        progress(ProbeProgress::Ping { reply: reply.clone() });
        replies.push(reply);
        if seq < request.count && pause(Duration::from_millis(request.interval_ms), cancel).await {
            cancelled = true;
            break;
        }
    }
    summarize(route, address, replies, cancelled)
}

fn summarize(route: &Route, address: IpAddr, replies: Vec<PingReply>, cancelled: bool) -> PingSummary {
    let times: Vec<u32> = replies
        .iter()
        .filter_map(|r| match r.echo {
            Echo::Reply { rtt_ms, .. } => Some(rtt_ms),
            _ => None,
        })
        .collect();
    let sent = u32::try_from(replies.len()).unwrap_or(u32::MAX);
    let received = u32::try_from(times.len()).unwrap_or(u32::MAX);
    let loss_percent = if sent == 0 {
        0.0
    } else {
        f64::from(sent - received) * 100.0 / f64::from(sent)
    };
    let avg_ms = (!times.is_empty()).then(|| times.iter().map(|&t| f64::from(t)).sum::<f64>() / times.len() as f64);
    PingSummary {
        label: route.label.clone(),
        host: route.host.clone(),
        address,
        sent,
        received,
        loss_percent,
        min_ms: times.iter().min().copied(),
        avg_ms,
        max_ms: times.iter().max().copied(),
        replies,
        cancelled,
    }
}

/// What the Trace route tab asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceRequest {
    pub target: ProbeTarget,
    #[serde(default = "default_hops")]
    pub max_hops: u8,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Look up each hop's name (reverse DNS); off by default, since it asks the DNS server about each one.
    #[serde(default)]
    pub resolve_names: bool,
}

impl TraceRequest {
    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_HOPS).contains(&self.max_hops) {
            return Err(CoreError::InvalidInput(format!("Trace 1 to {MAX_HOPS} hops.")));
        }
        check_timeout(self.timeout_ms)
    }
}

/// One hop: who answered, and each request's time (`None`: no answer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceHop {
    pub hop: u8,
    pub address: Option<IpAddr>,
    pub name: Option<String>,
    pub rtts_ms: Vec<Option<u32>>,
    /// The destination answered at this hop.
    pub reached: bool,
    /// A router said the destination can't be reached.
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceSummary {
    pub label: String,
    pub host: String,
    pub address: IpAddr,
    pub hops: Vec<TraceHop>,
    pub reached: bool,
    pub cancelled: bool,
}

/// Trace route: [`PROBES_PER_HOP`] requests per TTL from 1, until the destination answers, a router says it can't
/// be reached, or the hop limit.
pub(super) async fn trace(
    tools: &dyn NetworkTools,
    names: Option<&dyn NetworkAdapter>,
    route: &Route,
    address: IpAddr,
    request: &TraceRequest,
    cancel: &CancellationToken,
    progress: Progress<'_>,
) -> TraceSummary {
    let mut hops = Vec::new();
    let mut reached = false;
    let mut cancelled = false;
    'hops: for ttl in 1..=request.max_hops {
        let mut hop = TraceHop {
            hop: ttl,
            address: None,
            name: None,
            rtts_ms: Vec::new(),
            reached: false,
            note: None,
        };
        let mut stop = false;
        for _ in 0..PROBES_PER_HOP {
            let echo = tokio::select! {
                echo = tools.echo(EchoRequest {
                    to: address,
                    ttl,
                    size: 32,
                    timeout: Duration::from_millis(request.timeout_ms),
                }) => echo.unwrap_or_else(|err| Echo::Unreachable { from: None, reason: err.to_string() }),
                () = cancel.cancelled() => {
                    cancelled = true;
                    break 'hops;
                }
            };
            match echo {
                Echo::Reply { from, rtt_ms, .. } => {
                    hop.address.get_or_insert(from);
                    hop.rtts_ms.push(Some(rtt_ms));
                    hop.reached = true;
                }
                Echo::TtlExpired { from, rtt_ms } => {
                    hop.address.get_or_insert(from);
                    hop.rtts_ms.push(Some(rtt_ms));
                }
                Echo::Unreachable { from, reason } => {
                    if let Some(from) = from {
                        hop.address.get_or_insert(from);
                    }
                    hop.rtts_ms.push(None);
                    hop.note = Some(reason);
                    stop = true;
                }
                Echo::TimedOut => hop.rtts_ms.push(None),
            }
        }
        if let (Some(names), Some(at)) = (names, hop.address) {
            hop.name = tokio::select! {
                name = names.reverse(at) => name.map(|n| super::x509::clean(&n)),
                () = cancel.cancelled() => None,
            };
        }
        progress(ProbeProgress::Hop { hop: hop.clone() });
        let done = hop.reached;
        hops.push(hop);
        if done {
            reached = true;
            break;
        }
        if stop {
            break;
        }
    }
    TraceSummary {
        label: route.label.clone(),
        host: route.host.clone(),
        address,
        hops,
        reached,
        cancelled,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn route() -> Route {
        Route {
            host: "web01.example.com".into(),
            label: "web01".into(),
            via: None,
            port: None,
        }
    }

    #[test]
    fn requests_are_checked() {
        let ping = |count: u32, interval_ms: u64, size: u16, timeout_ms: u64| PingRequest {
            target: ProbeTarget::Address {
                host: "192.0.2.10".into(),
            },
            count,
            interval_ms,
            size,
            timeout_ms,
        };
        assert!(ping(4, 1000, 32, 2000).validate().is_ok());
        assert!(ping(0, 1000, 32, 2000).validate().is_err());
        assert!(ping(4, 999, 32, 2000).validate().is_err(), "at least a second apart");
        assert!(ping(4, 1000, 65501, 2000).validate().is_err());
        assert!(ping(4, 1000, 32, 50).validate().is_err());
        let trace = |max_hops: u8| TraceRequest {
            target: ProbeTarget::Address {
                host: "192.0.2.10".into(),
            },
            max_hops,
            timeout_ms: 1000,
            resolve_names: false,
        };
        assert!(trace(30).validate().is_ok());
        assert!(trace(31).validate().is_err());
        assert!(trace(0).validate().is_err());
    }

    #[test]
    fn the_summary_counts_loss_and_times() {
        let reply = |seq: u32, ms: Option<u32>| PingReply {
            seq,
            echo: match ms {
                Some(rtt_ms) => Echo::Reply {
                    from: "192.0.2.10".parse().unwrap(),
                    rtt_ms,
                    ttl: Some(64),
                },
                None => Echo::TimedOut,
            },
        };
        let summary = summarize(
            &route(),
            "192.0.2.10".parse().unwrap(),
            vec![reply(1, Some(2)), reply(2, None), reply(3, Some(6)), reply(4, Some(4))],
            false,
        );
        assert_eq!((summary.sent, summary.received), (4, 3));
        assert!((summary.loss_percent - 25.0).abs() < f64::EPSILON);
        assert_eq!((summary.min_ms, summary.max_ms), (Some(2), Some(6)));
        assert!((summary.avg_ms.unwrap() - 4.0).abs() < f64::EPSILON);
        let none = summarize(&route(), "192.0.2.10".parse().unwrap(), Vec::new(), true);
        assert_eq!(none.avg_ms, None);
        assert!(none.cancelled);
    }

    #[test]
    fn a_session_behind_a_jump_host_is_not_pinged() {
        let behind = Route {
            via: Some(super::super::JumpHost {
                session_id: uuid::Uuid::new_v4(),
                name: "bastion".into(),
            }),
            ..route()
        };
        let err = refuse_jump(&behind, "ping").unwrap_err().to_string();
        assert!(err.contains("behind the jump host 'bastion'"), "{err}");
        assert!(refuse_jump(&route(), "ping").is_ok());
    }
}
