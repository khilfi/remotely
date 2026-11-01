//! MO-08: one run of a check, with F1's probes ([`crate::toolbox`]): ping (one echo from this PC), a TCP connection,
//! an HTTP(S) request ([`super::http`]), a certificate read and checked ([`crate::toolbox::certs`]), a DNS lookup from
//! this PC, or a service read ([`super::service`]). A run only reads: nothing goes through the bus, nothing is
//! audited.
//!
//! A run is **up**, **down** (the probe failed: no answer, refused, a wrong status, an expired certificate...) or
//! **unknown** (Remotely couldn't check: the vault is locked, a login is parked or capped, the session went), so a
//! locked vault doesn't make every service check down.
//!
//! **Backoff.** A login to a host (a service check's own, or a jump host) that can't be reached isn't parked by the
//! login guard (the host may come back), yet each attempt counts against its hourly cap, shared with the dashboard and
//! the Containers page. So after a failed connection the checks wait before trying that host again ([`Backoffs`]:
//! 1 minute, doubling to 15), and the runs in between are skipped: nothing is kept, the check stays down (or
//! failing), and its row says when the next try is.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::http::{self, HttpAsk};
use super::service::{ServiceReader, ServiceRequest};
use super::spec::{CheckSpec, HealthCheck};
use super::RunResult;
use crate::adapters::net_tools::{DnsFailure, DnsQuery, Echo, EchoRequest, NetworkTools, RecordType};
use crate::domain::Context;
use crate::error::CoreError;
use crate::toolbox::{certs, icmp, millis, CertRequest, ProbeTarget, Reach, Route, Toolbox};

/// The longest detail a run keeps.
pub const MAX_DETAIL: usize = 300;

/// A check that runs at most this often keeps its connection to a jump host or a session's host open between runs;
/// one that runs less often logs in each time (at most 6 times an hour).
pub const HOLD_UP_TO_SECS: u64 = 600;

/// How much longer than the time between runs a held connection stays.
pub const HOLD_GRACE: Duration = Duration::from_secs(30);

/// The first wait after a host couldn't be reached, doubled after each failed try up to [`BACKOFF_MAX`]: a check
/// every 30 seconds then tries at most 8 logins in the first hour and 4 an hour after that.
pub const BACKOFF_MIN: Duration = Duration::from_secs(60);
pub const BACKOFF_MAX: Duration = Duration::from_secs(15 * 60);

/// Hosts whose connection failed, and when a check may log in to them again (Unix ms on the checks' clock).
#[derive(Debug, Default)]
pub struct Backoffs {
    hosts: Mutex<HashMap<Uuid, (u32, i64)>>,
}

impl Backoffs {
    /// When the session's host may be tried again, while that is still to come.
    pub fn waiting(&self, session: Uuid, now: i64) -> Option<i64> {
        crate::locks::lock(&self.hosts)
            .get(&session)
            .map(|(_, until)| *until)
            .filter(|until| *until > now)
    }

    /// A connection failed: the next try waits longer. Returns when it may be.
    pub fn failed(&self, session: Uuid, now: i64) -> i64 {
        let mut hosts = crate::locks::lock(&self.hosts);
        let failures = hosts.get(&session).map_or(0, |(n, _)| *n).saturating_add(1);
        let wait = crate::metrics::guest::backoff(failures, BACKOFF_MIN, BACKOFF_MAX);
        let until = now.saturating_add(i64::try_from(wait.as_millis()).unwrap_or(i64::MAX));
        hosts.insert(session, (failures, until));
        until
    }

    /// It connected: no more waiting.
    pub fn cleared(&self, session: Uuid) {
        crate::locks::lock(&self.hosts).remove(&session);
    }

    pub fn clear_all(&self) {
        crate::locks::lock(&self.hosts).clear();
    }
}

/// How long a check's kept connection is held after a run: until its next run, for a check that runs often.
pub fn hold_for(interval_secs: u64) -> Option<Duration> {
    (interval_secs <= HOLD_UP_TO_SECS).then(|| Duration::from_secs(interval_secs) + HOLD_GRACE)
}

/// What one run found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probed {
    pub result: RunResult,
    pub took_ms: Option<u64>,
    pub detail: String,
    pub cert_days: Option<i64>,
    /// The session whose kept connection the run used (a jump host's, or a service check's own).
    pub held: Option<Uuid>,
    /// Its host couldn't be reached: no login is tried before then (Unix ms).
    pub waiting_until: Option<i64>,
    /// Not run: its host is backed off. Nothing is kept and the status stays.
    pub skipped: bool,
}

impl Probed {
    pub(super) fn up(took_ms: u64, detail: impl Into<String>) -> Self {
        Self::new(RunResult::Up, Some(took_ms), detail)
    }

    pub(super) fn down(took_ms: Option<u64>, detail: impl Into<String>) -> Self {
        Self::new(RunResult::Down, took_ms, detail)
    }

    pub(super) fn unknown(detail: impl Into<String>) -> Self {
        Self::new(RunResult::Unknown, None, detail)
    }

    fn new(result: RunResult, took_ms: Option<u64>, detail: impl Into<String>) -> Self {
        Self {
            result,
            took_ms,
            detail: one_line(&detail.into()),
            cert_days: None,
            held: None,
            waiting_until: None,
            skipped: false,
        }
    }

    /// Not run, its host waiting until `until`.
    pub(super) fn skipped(until: i64) -> Self {
        Self {
            skipped: true,
            waiting_until: Some(until),
            ..Self::new(RunResult::Unknown, None, "")
        }
    }

    fn waiting(mut self, until: i64) -> Self {
        self.waiting_until = Some(until);
        self
    }

    fn with_days(mut self, days: Option<i64>) -> Self {
        self.cert_days = days;
        self
    }

    fn held(mut self, held: Option<Uuid>) -> Self {
        self.held = held;
        self
    }
}

/// A detail as one line: no control or format characters, spaces collapsed, secrets redacted, at most
/// [`MAX_DETAIL`] characters (cut by characters, never inside one).
pub fn one_line(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if crate::untrusted::is_format_char(c) || (c == ' ' && (out.is_empty() || out.ends_with(' '))) {
            continue;
        }
        out.push(c);
    }
    let (out, _) = crate::export::redact_secrets(out.trim_end());
    if out.chars().count() > MAX_DETAIL {
        let mut cut: String = out.chars().take(MAX_DETAIL - 1).collect();
        cut.push('…');
        cut
    } else {
        out
    }
}

/// Errors that say Remotely couldn't check, rather than that the target failed.
fn remotely_could_not(err: &CoreError) -> bool {
    matches!(
        err,
        CoreError::VaultLocked
            | CoreError::VaultNotSetUp
            | CoreError::ReauthRequired { .. }
            | CoreError::LoginParked { .. }
            | CoreError::LoginsCapped { .. }
            | CoreError::AuthFailed(_)
            | CoreError::AgentUnavailable(_)
            | CoreError::HostKeyChanged { .. }
            | CoreError::HostKeyRejected { .. }
            | CoreError::HostKeyUnknown { .. }
            | CoreError::UnknownTarget(_)
            | CoreError::NotInWorkspace(_)
            | CoreError::VmUnassigned(_)
            | CoreError::WrongSessionKind { .. }
            | CoreError::Cancelled
            | CoreError::Db(_)
    )
}

fn failed(err: &CoreError) -> Probed {
    match err {
        CoreError::UnknownTarget(_) => Probed::unknown("its session or VM is no longer here"),
        err if remotely_could_not(err) => Probed::unknown(format!("couldn't check: {err}")),
        err => Probed::down(None, err.to_string()),
    }
}

/// A connection to the host itself failed (no answer, refused, the handshake broke, its key isn't trusted yet): worth
/// backing off. Not a parked or capped login, a locked vault or a session gone (the login guard and the vault handle
/// those), nor a command that ran and failed.
fn connect_failure(err: &CoreError) -> bool {
    !remotely_could_not(err)
        && !matches!(
            err,
            CoreError::CommandTimedOut { .. } | CoreError::InvalidInput(_) | CoreError::CancelledRemote
        )
}

/// Runs checks with the toolbox's probes.
pub(super) struct Prober {
    pub toolbox: Toolbox,
    pub tools: Arc<dyn NetworkTools>,
    pub services: Arc<dyn ServiceReader>,
    pub backoffs: Arc<Backoffs>,
    /// When the run started (Unix ms, the checks' clock).
    pub now: i64,
}

impl Prober {
    /// One run of `check`, within its timeout (a jump host's login has its own).
    pub(super) async fn run(&self, ctx: &Context, check: &HealthCheck) -> Probed {
        let timeout = Duration::from_secs(check.timeout_secs);
        let hold = hold_for(check.interval_secs);
        if let CheckSpec::Service { unit } = &check.spec {
            let ProbeTarget::Session { session_id } = check.target else {
                return Probed::unknown("a service check needs a session");
            };
            return self.service(ctx, session_id, unit, timeout, hold).await;
        }
        let route = match self.toolbox.route(ctx, &check.target).await {
            Ok(route) => route,
            Err(err) => return failed(&err),
        };
        let held = route.via.as_ref().filter(|_| hold.is_some()).map(|j| j.session_id);
        let probed = match &check.spec {
            CheckSpec::Ping => self.ping(&route, timeout).await,
            CheckSpec::Dns {
                record_type,
                server,
                expect,
            } => {
                self.dns(&route, *record_type, server.as_deref(), expect.as_deref(), timeout)
                    .await
            }
            CheckSpec::Tcp { port } => match self.reach(ctx, &route, hold).await {
                Ok(reach) => {
                    let started = Instant::now();
                    match reach.open(*port, timeout).await {
                        Ok(_stream) => {
                            let took = millis(started.elapsed());
                            Probed::up(took, format!("port {port} open in {took} ms"))
                        }
                        Err(crate::adapters::net_tools::ConnectFailure::Refused) if reach.via().is_some() => {
                            Probed::down(
                                None,
                                format!(
                                    "port {port}: closed, or the jump host '{}' can't reach it",
                                    reach.via().unwrap_or_default()
                                ),
                            )
                        }
                        Err(failure) => Probed::down(None, format!("port {port}: {}", failure.describe())),
                    }
                }
                Err(probed) => *probed,
            },
            CheckSpec::Http {
                https,
                port,
                path,
                status_min,
                status_max,
                body_contains,
                follow_redirects,
                allow_invalid_cert,
            } => match self.reach(ctx, &route, hold).await {
                Ok(reach) => {
                    let ask = HttpAsk {
                        host: route.host.clone(),
                        https: *https,
                        port: *port,
                        path: path.clone(),
                        status: (*status_min, *status_max),
                        body_contains: body_contains.as_deref(),
                        follow_redirects: *follow_redirects,
                        allow_invalid_cert: *allow_invalid_cert,
                    };
                    http::check(&self.toolbox, self.tools.as_ref(), reach, ask, timeout).await
                }
                Err(probed) => *probed,
            },
            CheckSpec::Certificate {
                port,
                server_name,
                allow_untrusted,
            } => match self.reach(ctx, &route, hold).await {
                Ok(reach) => {
                    let request = CertRequest {
                        target: check.target.clone(),
                        port: *port,
                        server_name: server_name.clone(),
                        timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
                    };
                    self.certificate(&route, &reach, &request, *allow_untrusted).await
                }
                Err(probed) => *probed,
            },
            CheckSpec::Service { .. } => Probed::unknown("a service check needs a session"),
        };
        probed.held(held)
    }

    /// How a connecting probe reaches its host. Through a jump host that couldn't be reached lately, nothing is tried
    /// (the run is skipped) until its backoff ends; a failed connection to it starts or lengthens the backoff.
    async fn reach(&self, ctx: &Context, route: &Route, hold: Option<Duration>) -> Result<Reach, Box<Probed>> {
        let jump = route.via.as_ref();
        if let Some(until) = jump.and_then(|j| self.backoffs.waiting(j.session_id, self.now)) {
            return Err(Box::new(Probed::skipped(until)));
        }
        match self.toolbox.reach_held(ctx, route, hold).await {
            Ok(reach) => {
                if let Some(jump) = jump {
                    self.backoffs.cleared(jump.session_id);
                }
                Ok(reach)
            }
            Err(err) => match jump {
                Some(jump) if connect_failure(&err) => {
                    let until = self.backoffs.failed(jump.session_id, self.now);
                    Err(Box::new(
                        Probed::down(None, format!("the jump host '{}' can't be reached: {err}", jump.name))
                            .waiting(until),
                    ))
                }
                _ => Err(Box::new(failed(&err))),
            },
        }
    }

    async fn ping(&self, route: &Route, timeout: Duration) -> Probed {
        if let Err(err) = icmp::refuse_jump(route, "ping") {
            return Probed::unknown(err.to_string());
        }
        let address = match self.toolbox.address_of(&route.host).await {
            Ok(address) => address,
            Err(err) => return Probed::down(None, format!("{} doesn't resolve: {err}", route.host)),
        };
        let echo = self
            .tools
            .echo(EchoRequest {
                to: address,
                ttl: 128,
                size: 32,
                timeout,
            })
            .await;
        match echo {
            Ok(Echo::Reply { rtt_ms, .. }) => {
                Probed::up(u64::from(rtt_ms), format!("reply from {address} in {rtt_ms} ms"))
            }
            Ok(Echo::TimedOut) => Probed::down(None, format!("no reply within {} s", timeout.as_secs())),
            Ok(Echo::TtlExpired { from, .. }) => Probed::down(None, format!("a router ({from}) dropped it")),
            Ok(Echo::Unreachable { reason, .. }) => Probed::down(None, reason),
            Err(err) => Probed::down(None, err.to_string()),
        }
    }

    async fn dns(
        &self,
        route: &Route,
        record_type: RecordType,
        server: Option<&str>,
        expect: Option<&str>,
        timeout: Duration,
    ) -> Probed {
        let name = route.host.clone();
        if crate::adapters::network::ip_literal(&name).is_some() {
            return Probed::unknown("a DNS check looks up a name, and this target is an address");
        }
        let server = server.and_then(crate::adapters::network::ip_literal);
        let started = Instant::now();
        let answer = self
            .tools
            .dns(&DnsQuery {
                name: name.clone(),
                record_type,
                server,
                timeout,
            })
            .await;
        let took = millis(started.elapsed());
        let kind = record_type.as_str();
        let records = match answer {
            Ok(Ok(records)) => records,
            Ok(Err(DnsFailure::NoSuchName)) => return Probed::down(Some(took), "no such name"),
            Ok(Err(DnsFailure::NoRecords)) => return Probed::down(Some(took), format!("no {kind} record")),
            Ok(Err(DnsFailure::Failed { message })) => return Probed::down(Some(took), message),
            Err(err) => return Probed::down(None, err.to_string()),
        };
        let addresses: Vec<std::net::IpAddr> = records
            .iter()
            .filter(|r| r.record_type == kind)
            .filter_map(|r| crate::adapters::network::ip_literal(r.data.trim()))
            .collect();
        if addresses.is_empty() {
            return Probed::down(Some(took), format!("no {kind} record"));
        }
        let listed = addresses
            .iter()
            .take(3)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let more = if addresses.len() > 3 { ", ..." } else { "" };
        match expect.and_then(crate::adapters::network::ip_literal) {
            Some(want) if !addresses.contains(&want) => {
                Probed::down(Some(took), format!("resolves to {listed}{more}, not {want}"))
            }
            _ => Probed::up(took, format!("resolves to {listed}{more}")),
        }
    }

    async fn certificate(
        &self,
        route: &Route,
        reach: &crate::toolbox::Reach,
        request: &CertRequest,
        allow_untrusted: bool,
    ) -> Probed {
        let started = Instant::now();
        let report = match certs::from_server(self.tools.as_ref(), route, reach, request).await {
            Ok(report) => report,
            Err(err) => return failed(&err),
        };
        let took = millis(started.elapsed());
        let days = report.days_left;
        let name = report.server_name.clone().unwrap_or_else(|| route.host.clone());
        let problem = if let Some(error) = &report.handshake_error {
            Some(format!("the handshake failed: {error}"))
        } else if let Some(d) = days.filter(|d| *d < 0) {
            Some(format!("the certificate expired {} ago", day_text(-d)))
        } else if report
            .chain
            .first()
            .is_some_and(|leaf| !leaf.valid_at(time::OffsetDateTime::now_utc()))
        {
            Some("the certificate isn't valid yet".to_owned())
        } else if !allow_untrusted && !report.trusted {
            Some(format!(
                "the certificate isn't trusted: {}",
                report
                    .trust_problems
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Windows doesn't trust it".into())
            ))
        } else if !allow_untrusted && report.name_matches == Some(false) {
            Some(format!("the certificate doesn't name {name}"))
        } else {
            None
        };
        match problem {
            Some(why) => Probed::down(Some(took), why).with_days(days),
            None => {
                let valid = days.map_or_else(
                    || "valid".to_owned(),
                    |d| {
                        if d == 1 {
                            "valid for 1 more day".to_owned()
                        } else {
                            format!("valid for {d} more days")
                        }
                    },
                );
                Probed::up(took, valid).with_days(days)
            }
        }
    }

    async fn service(
        &self,
        ctx: &Context,
        session_id: Uuid,
        unit: &str,
        timeout: Duration,
        hold: Option<Duration>,
    ) -> Probed {
        if let Some(until) = self.backoffs.waiting(session_id, self.now) {
            return Probed::skipped(until);
        }
        let read = self
            .services
            .read(ServiceRequest {
                ctx,
                session_id,
                unit,
                timeout,
                hold,
            })
            .await;
        let held = hold.map(|_| session_id);
        if read.is_ok() {
            self.backoffs.cleared(session_id);
        }
        match read {
            Ok(state) if state.running => Probed::up(state.took_ms, format!("{unit} is {}", state.state)),
            Ok(state) => Probed::down(Some(state.took_ms), format!("{unit} is {}", state.state)),
            Err(CoreError::InvalidInput(why)) => Probed::unknown(why),
            Err(err) if connect_failure(&err) => {
                let until = self.backoffs.failed(session_id, self.now);
                Probed::down(None, format!("the host can't be reached: {err}")).waiting(until)
            }
            Err(err) => failed(&err),
        }
        .held(held)
    }
}

/// "1 day", "12 days".
fn day_text(days: i64) -> String {
    if days == 1 {
        "1 day".into()
    } else {
        format!("{days} days")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn details_are_one_short_clean_line() {
        assert_eq!(one_line("  port 22:\r\n refused\u{202e}  now "), "port 22: refused now");
        let long = one_line(&"é".repeat(1000));
        assert_eq!(long.chars().count(), MAX_DETAIL);
        assert!(long.ends_with('…'));
        assert!(!one_line("token=ghp_abcdefghijklmnopqrstuvwxyz0123456789")
            .contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
    }

    #[test]
    fn an_unreachable_host_waits_longer_after_each_failed_try_up_to_15_minutes() {
        let backoffs = Backoffs::default();
        let host = Uuid::new_v4();
        assert_eq!(backoffs.waiting(host, 0), None);
        let mut waits = Vec::new();
        let mut now = 0;
        for _ in 0..7 {
            let until = backoffs.failed(host, now);
            waits.push((until - now) / 1000);
            assert_eq!(backoffs.waiting(host, now), Some(until));
            assert_eq!(
                backoffs.waiting(host, until),
                None,
                "the try at the end of the wait goes ahead"
            );
            now = until;
        }
        assert_eq!(waits, [60, 120, 240, 480, 900, 900, 900]);
        backoffs.cleared(host);
        assert_eq!(backoffs.failed(host, 0), 60_000, "a host that answered starts over");
    }

    #[test]
    fn only_a_failed_connection_backs_off() {
        assert!(connect_failure(&CoreError::Ssh("connection reset".into())));
        assert!(connect_failure(&CoreError::Network("no route".into())));
        assert!(!connect_failure(&CoreError::VaultLocked));
        assert!(!connect_failure(&CoreError::LoginsCapped {
            message: "capped".into(),
            wait_secs: 60
        }));
        assert!(!connect_failure(&CoreError::CommandTimedOut { seconds: 5 }));
    }

    #[test]
    fn checks_that_run_often_hold_their_connection_until_the_next_run() {
        assert_eq!(hold_for(60), Some(Duration::from_secs(90)));
        assert_eq!(hold_for(600), Some(Duration::from_secs(630)));
        assert_eq!(hold_for(601), None, "at most 6 logins an hour without a hold");
    }

    #[test]
    fn what_remotely_couldnt_check_is_unknown_not_down() {
        assert_eq!(failed(&CoreError::VaultLocked).result, RunResult::Unknown);
        assert_eq!(
            failed(&CoreError::LoginParked {
                message: "parked".into()
            })
            .result,
            RunResult::Unknown
        );
        assert_eq!(failed(&CoreError::UnknownTarget("x".into())).result, RunResult::Unknown);
        assert_eq!(failed(&CoreError::Network("refused".into())).result, RunResult::Down);
        assert_eq!(
            failed(&CoreError::Ssh("connection reset".into())).result,
            RunResult::Down
        );
    }
}
