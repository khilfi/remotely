//! QL-17 alerts: a pane's rules with their alert on, matched against each line its output completes.
//!
//! * Lines are split as the SS-11 session log splits them ([`ScrubbedLines`]: escapes dropped, a carriage return
//!   redraws, backspace takes back), with the pane's secrets scrubbed from the raw bytes and from each line, and
//!   matched with Rust's `regex` (linear time) on their first [`MAX_MATCHED_CHARS`] characters.
//! * No alert comes from a full-screen program (the alternate screen: vim, less, top), from a line that asks for a
//!   password or a one-time code, or from the line the user pressed Enter on (the command they typed, not its output).
//! * One notification per burst, never one per line: a rule's first match in a pane opens a burst; matches within
//!   [`AlertTiming::burst`] are counted; then one [`TerminalAlert`] goes out with the count and a short sample of the
//!   first line; then for [`AlertTiming::cooldown`] that rule's matches in that pane are only counted, and reported
//!   with its next alert.
//! * The pane's scope (its saved session and label, or a quick connection's label) picks the rules
//!   ([`RuleBook::for_pane`]); a change of rules reaches it at its next output.
//!
//! Nothing here is logged, journaled or audited: an alert is a notice for the user, and its sample stays in memory.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use regex::{RegexSet, RegexSetBuilder};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::watch;
use uuid::Uuid;

use super::activity::is_secret_prompt;
use super::log::{Line, ScrubbedLines};
use super::rules::{AlertRule, RuleBook};
use crate::domain::Environment;
use crate::export::redact_secrets;
use crate::untrusted::is_format_char;
use crate::vault::SecretString;

/// A line is matched on this many characters, its start.
pub const MAX_MATCHED_CHARS: usize = 2000;
/// The longest sample line an alert carries, in characters.
pub const MAX_SAMPLE_CHARS: usize = 200;
/// The most memory a pane's set of alert patterns may compile to; past that, they are matched one by one.
const SET_SIZE_LIMIT: usize = 8 << 20;

/// How matches are gathered into alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertTiming {
    /// After a rule's first match, how long more matches join the same alert.
    pub burst: Duration,
    /// After an alert, how long the same rule in the same pane only counts its matches.
    pub cooldown: Duration,
}

impl Default for AlertTiming {
    fn default() -> Self {
        Self {
            burst: Duration::from_secs(2),
            cooldown: Duration::from_secs(60),
        }
    }
}

/// A burst of matches of one rule in one pane ([`super::TerminalEvent::Alert`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalAlert {
    /// As [`super::rules::TerminalRule::id`].
    pub rule_id: String,
    pub rule_name: String,
    pub terminal_id: Uuid,
    /// The saved session; `None` for a quick connection that was not saved.
    pub session_id: Option<Uuid>,
    /// Lines that matched in this burst.
    pub count: u32,
    /// Lines that matched during the cooldown since the last alert, reported now.
    pub suppressed: u32,
    /// RFC 3339, UTC: the burst's first and last match.
    pub first_at: String,
    pub last_at: String,
    /// The burst's first matching line, scrubbed and cut to [`MAX_SAMPLE_CHARS`] around the match.
    pub sample: String,
}

/// An alert ready to go out, timed by the pump's clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertBurst {
    pub rule_id: String,
    pub rule_name: String,
    pub count: u32,
    pub suppressed: u32,
    pub first: Instant,
    pub last: Instant,
    pub sample: String,
}

impl AlertBurst {
    /// With wall-clock times: `now` on the pump's clock is `wall`.
    pub fn into_alert(
        self,
        terminal_id: Uuid,
        session_id: Option<Uuid>,
        now: Instant,
        wall: OffsetDateTime,
    ) -> TerminalAlert {
        TerminalAlert {
            rule_id: self.rule_id,
            rule_name: self.rule_name,
            terminal_id,
            session_id,
            count: self.count,
            suppressed: self.suppressed,
            first_at: wall_time(self.first, now, wall),
            last_at: wall_time(self.last, now, wall),
            sample: self.sample,
        }
    }
}

fn wall_time(at: Instant, now: Instant, wall: OffsetDateTime) -> String {
    let ago = time::Duration::try_from(now.saturating_duration_since(at)).unwrap_or(time::Duration::ZERO);
    let when = wall.checked_sub(ago).unwrap_or(wall);
    when.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| when.unix_timestamp().to_string())
}

/// The sample an alert shows: the line with what looks like a password or token redacted, control and invisible
/// formatting characters dropped, cut around the rule's first match.
fn sample(rule: &AlertRule, line: &str) -> String {
    let (redacted, _) = redact_secrets(line);
    let clean: String = redacted
        .chars()
        .map(|c| if c == '\t' { ' ' } else { c })
        .filter(|c| !c.is_control() && !is_format_char(*c))
        .collect();
    let clean = clean.trim();
    let total = clean.chars().count();
    if total <= MAX_SAMPLE_CHARS {
        return clean.to_owned();
    }
    // Room for an ellipsis at each end.
    let window = MAX_SAMPLE_CHARS - 2;
    let at = rule
        .pattern
        .regex
        .find(clean)
        .and_then(|m| clean.get(..m.start()))
        .map_or(0, |before| before.chars().count());
    let start = at.saturating_sub(MAX_SAMPLE_CHARS / 5).min(total - window);
    let mut out = String::with_capacity(MAX_SAMPLE_CHARS * 2);
    if start > 0 {
        out.push('…');
    }
    out.extend(clean.chars().skip(start).take(window));
    if start + window < total {
        out.push('…');
    }
    out
}

/// A pane's alerting rules, matched together.
struct Matcher {
    rules: Vec<Arc<AlertRule>>,
    /// All of them in one pass; `None` when they compile too big together.
    set: Option<RegexSet>,
}

impl Matcher {
    fn new(rules: Vec<Arc<AlertRule>>) -> Self {
        let set = RegexSetBuilder::new(rules.iter().map(|r| r.pattern.source.as_str()))
            .size_limit(SET_SIZE_LIMIT)
            .build();
        let set = match set {
            Ok(set) => Some(set),
            Err(err) => {
                tracing::warn!(error = %err, rules = rules.len(), "alert rules matched one by one");
                None
            }
        };
        Self { rules, set }
    }

    /// The indexes of the rules that match.
    fn matching(&self, line: &str) -> Vec<usize> {
        match &self.set {
            Some(set) => set.matches(line).into_iter().collect(),
            None => self
                .rules
                .iter()
                .enumerate()
                .filter(|(_, rule)| rule.pattern.regex.is_match(line))
                .map(|(i, _)| i)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Matches join the alert that goes out at `due`.
    Burst { due: Instant },
    /// Matches are counted until `until`, for the next alert.
    Cooldown { until: Instant },
}

/// One rule in one pane.
#[derive(Debug)]
struct RuleState {
    name: String,
    phase: Phase,
    count: u32,
    first: Instant,
    last: Instant,
    sample: String,
    /// Matches during the last cooldown.
    suppressed: u32,
}

/// One pane's alerts (see the module comment). Kept across its reconnects, so a cooldown outlives a dropped
/// connection; each new shell starts a new line splitter.
pub struct AlertWatch {
    rules: Option<watch::Receiver<Arc<RuleBook>>>,
    timing: AlertTiming,
    session_id: Option<Uuid>,
    environment: Environment,
    /// The book has to be read again (a new shell, or a new pane).
    stale: bool,
    /// `None`: no rule alerts in this pane, so its output is not split at all.
    matcher: Option<Matcher>,
    lines: Option<ScrubbedLines>,
    /// What the pane knows of its secrets, for a new splitter.
    secrets: Vec<SecretString>,
    states: HashMap<String, RuleState>,
}

impl AlertWatch {
    /// `rules`: the alerting rules as they change; `None` alerts on nothing.
    pub fn new(rules: Option<watch::Receiver<Arc<RuleBook>>>, timing: AlertTiming) -> Self {
        Self {
            rules,
            timing,
            session_id: None,
            environment: Environment::None,
            stale: true,
            matcher: None,
            lines: None,
            secrets: Vec::new(),
            states: HashMap::new(),
        }
    }

    pub fn set_timing(&mut self, timing: AlertTiming) {
        self.timing = timing;
    }

    /// A new shell: the pane's session and label as they are now, and the secrets its login knows.
    pub fn new_shell(&mut self, session_id: Option<Uuid>, environment: Environment, secrets: Vec<SecretString>) {
        self.session_id = session_id;
        self.environment = environment;
        self.secrets = secrets;
        self.lines = None;
        self.stale = true;
    }

    /// A secret typed into the terminal (QL-06): scrubbed from the lines from here on.
    pub fn add_secret(&mut self, secret: &SecretString) {
        if !self.secrets.iter().any(|s| s.expose() == secret.expose()) {
            self.secrets.push(secret.clone());
        }
        if let Some(lines) = &mut self.lines {
            lines.add_secret(secret);
        }
    }

    /// The user (or MultiExec, or the startup command) pressed Enter: the line on screen is a command, not output.
    pub fn enter_pressed(&mut self) {
        if let Some(lines) = &mut self.lines {
            lines.mark_line();
        }
    }

    /// The rules for this pane, when they changed.
    fn refresh(&mut self) {
        let changed = match &mut self.rules {
            Some(rules) => rules.has_changed().unwrap_or(false),
            None => false,
        };
        if !(changed || self.stale) {
            return;
        }
        self.stale = false;
        let book = match &mut self.rules {
            Some(rules) => Arc::clone(&rules.borrow_and_update()),
            None => return,
        };
        let rules = book.for_pane(self.session_id, self.environment);
        self.matcher = (!rules.is_empty()).then(|| Matcher::new(rules));
    }

    /// Output the user sees. `alternate`: a full-screen program had the screen before these bytes (for a splitter
    /// that starts now).
    pub fn output(&mut self, bytes: &[u8], alternate: bool, now: Instant) {
        self.refresh();
        let Some(matcher) = &self.matcher else {
            self.lines = None;
            return;
        };
        let secrets = &self.secrets;
        let lines = self.lines.get_or_insert_with(|| {
            let refs: Vec<&SecretString> = secrets.iter().collect();
            let mut lines = ScrubbedLines::new(&refs);
            lines.set_alternate(alternate);
            lines
        });
        for line in lines.feed(bytes) {
            match_line(matcher, &mut self.states, self.timing, &line, now);
        }
    }

    /// When [`AlertWatch::tick`] should next be called: the end of the first open burst.
    pub fn deadline(&self) -> Option<Instant> {
        self.states
            .values()
            .filter_map(|state| match state.phase {
                Phase::Burst { due } => Some(due),
                Phase::Cooldown { .. } => None,
            })
            .min()
    }

    /// The alerts whose burst has ended by `now`; their cooldowns start.
    pub fn tick(&mut self, now: Instant) -> Vec<AlertBurst> {
        self.take(now, |due| due <= now)
    }

    /// Every open burst now, whatever its time (the connection ended).
    pub fn flush(&mut self, now: Instant) -> Vec<AlertBurst> {
        self.take(now, |_| true)
    }

    fn take(&mut self, now: Instant, ready: impl Fn(Instant) -> bool) -> Vec<AlertBurst> {
        let cooldown = self.timing.cooldown;
        let mut out = Vec::new();
        for (id, state) in &mut self.states {
            let Phase::Burst { due } = state.phase else {
                continue;
            };
            if !ready(due) {
                continue;
            }
            out.push(AlertBurst {
                rule_id: id.clone(),
                rule_name: state.name.clone(),
                count: state.count,
                suppressed: state.suppressed,
                first: state.first,
                last: state.last,
                sample: std::mem::take(&mut state.sample),
            });
            state.suppressed = 0;
            state.count = 0;
            state.phase = Phase::Cooldown { until: now + cooldown };
        }
        // Cooldowns that ended with nothing to report are forgotten.
        self.states.retain(|_, state| match state.phase {
            Phase::Burst { .. } => true,
            Phase::Cooldown { until } => until > now || state.suppressed > 0,
        });
        out.sort_by_key(|burst| burst.first);
        out
    }
}

fn match_line(
    matcher: &Matcher,
    states: &mut HashMap<String, RuleState>,
    timing: AlertTiming,
    line: &Line,
    now: Instant,
) {
    if line.full_screen || line.marked {
        return;
    }
    let text = match line.text.char_indices().nth(MAX_MATCHED_CHARS) {
        Some((cut, _)) => line.text.get(..cut).unwrap_or(""),
        None => line.text.as_str(),
    };
    if text.trim().is_empty() || is_secret_prompt(text) {
        return;
    }
    for i in matcher.matching(text) {
        let Some(rule) = matcher.rules.get(i) else {
            continue;
        };
        record(states, rule, text, timing, now);
    }
}

fn record(states: &mut HashMap<String, RuleState>, rule: &AlertRule, line: &str, timing: AlertTiming, now: Instant) {
    let burst = Phase::Burst {
        due: now + timing.burst,
    };
    match states.get_mut(&rule.id) {
        None => {
            states.insert(
                rule.id.clone(),
                RuleState {
                    name: rule.name.clone(),
                    phase: burst,
                    count: 1,
                    first: now,
                    last: now,
                    sample: sample(rule, line),
                    suppressed: 0,
                },
            );
        }
        Some(state) => match state.phase {
            Phase::Burst { .. } => {
                state.count = state.count.saturating_add(1);
                state.last = now;
            }
            Phase::Cooldown { until } if now < until => {
                state.suppressed = state.suppressed.saturating_add(1);
            }
            Phase::Cooldown { .. } => {
                // A new burst; what the cooldown counted goes out with it.
                state.name.clone_from(&rule.name);
                state.phase = burst;
                state.count = 1;
                state.first = now;
                state.last = now;
                state.sample = sample(rule, line);
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::rules::{check_pattern, RuleScope};

    const MS: Duration = Duration::from_millis(1);

    fn rule(id: &str, pattern: &str, scope: RuleScope) -> Arc<AlertRule> {
        Arc::new(AlertRule {
            id: id.into(),
            name: format!("rule {id}"),
            scope,
            pattern: check_pattern(pattern, false).unwrap(),
        })
    }

    /// A watch on these rules, for a saved Lab session.
    fn watch_on(rules: Vec<Arc<AlertRule>>) -> (AlertWatch, watch::Sender<Arc<RuleBook>>) {
        let (tx, rx) = watch::channel(Arc::new(RuleBook {
            version: 1,
            alerts: rules,
        }));
        let mut alerts = AlertWatch::new(Some(rx), AlertTiming::default());
        alerts.new_shell(Some(Uuid::new_v4()), Environment::Lab, Vec::new());
        (alerts, tx)
    }

    fn error_rule() -> Arc<AlertRule> {
        rule("e", r"\berror\b", RuleScope::Global)
    }

    #[test]
    fn a_match_split_across_reads_and_colour_codes_is_one_line() {
        let (mut alerts, _tx) = watch_on(vec![error_rule()]);
        let t0 = Instant::now();
        alerts.output(b"build: ER", false, t0);
        alerts.output(b"\x1b[31mROR\x1b[0m in step 3", false, t0);
        assert_eq!(alerts.deadline(), None, "the line is not complete yet");
        alerts.output(b"\r\n$ ", false, t0 + MS);
        assert_eq!(alerts.deadline(), Some(t0 + MS + Duration::from_secs(2)));
        assert!(
            alerts.tick(t0 + Duration::from_secs(1)).is_empty(),
            "the burst is still open"
        );
        let out = alerts.tick(t0 + MS + Duration::from_secs(2));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].count, 1);
        assert_eq!(out[0].sample, "build: ERROR in step 3");
        assert_eq!(out[0].rule_id, "e");
    }

    #[test]
    fn a_burst_is_one_alert_then_a_cooldown_counts_quietly() {
        let (mut alerts, _tx) = watch_on(vec![error_rule()]);
        let t0 = Instant::now();
        let second = Duration::from_secs(1);
        for i in 0..5u32 {
            alerts.output(format!("error {i}\r\n").as_bytes(), false, t0 + MS * (100 * i));
        }
        let out = alerts.tick(t0 + 2 * second);
        assert_eq!(out.len(), 1, "one alert for the burst, not five");
        assert_eq!((out[0].count, out[0].suppressed), (5, 0));
        assert_eq!((out[0].first, out[0].last), (t0, t0 + 400 * MS));
        assert_eq!(out[0].sample, "error 0");
        assert_eq!(alerts.deadline(), None, "cooling down");
        // During the cooldown: counted, no alert.
        for i in 0..3u32 {
            alerts.output(b"error again\r\n", false, t0 + 10 * second + MS * i);
        }
        assert!(alerts.tick(t0 + 30 * second).is_empty());
        assert_eq!(alerts.deadline(), None);
        // After it, the next match opens a burst that reports them.
        alerts.output(b"error late\r\n", false, t0 + 70 * second);
        let out = alerts.tick(t0 + 72 * second);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].count, out[0].suppressed), (1, 3));
        assert_eq!(out[0].sample, "error late");
        // A cooldown that ends with nothing counted is forgotten.
        assert!(alerts.tick(t0 + 200 * second).is_empty());
        assert!(alerts.states.is_empty());
    }

    #[test]
    fn each_rule_has_its_own_burst() {
        let (mut alerts, _tx) = watch_on(vec![error_rule(), rule("w", r"\bwarn(?:ing)?\b", RuleScope::Global)]);
        let t0 = Instant::now();
        alerts.output(b"warning: low disk\r\nerror: no disk\r\n", false, t0);
        let out = alerts.tick(t0 + Duration::from_secs(2));
        let mut ids: Vec<&str> = out.iter().map(|b| b.rule_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["e", "w"]);
    }

    #[test]
    fn full_screen_programs_password_prompts_and_typed_commands_never_alert() {
        let (mut alerts, _tx) = watch_on(vec![rule("p", "password|error", RuleScope::Global)]);
        let t0 = Instant::now();
        // top on the alternate screen, its lines and the one it leaves on.
        alerts.output(
            b"\x1b[?1049h\x1b[Herror rate 3%\r\nmore error\r\n\x1b[?1049l",
            false,
            t0,
        );
        // A password prompt, answered (not echoed) and ended by Enter.
        alerts.output(b"[sudo] password for alice: ", false, t0);
        alerts.output(b"\r\n", false, t0);
        // The command line the user pressed Enter on.
        alerts.output(b"alice@web01:~$ grep error app.log", false, t0);
        alerts.enter_pressed();
        alerts.output(b"\r\n", false, t0);
        assert_eq!(alerts.deadline(), None, "nothing matched yet");
        // Its output does alert.
        alerts.output(b"error: one\r\n", false, t0);
        assert!(alerts.deadline().is_some());
        // A splitter that starts while a full-screen program is open knows it.
        let (mut late, _tx) = watch_on(vec![error_rule()]);
        late.output(b"error in vim's status line\r\n", true, t0);
        assert_eq!(late.deadline(), None);
    }

    #[test]
    fn samples_are_scrubbed_redacted_and_cut_around_the_match() {
        let secret = SecretString::new("hunter2-xyz");
        let (tx, rx) = watch::channel(Arc::new(RuleBook {
            version: 1,
            alerts: vec![error_rule()],
        }));
        let mut alerts = AlertWatch::new(Some(rx), AlertTiming::default());
        alerts.new_shell(None, Environment::None, vec![secret.clone()]);
        let t0 = Instant::now();
        alerts.output(b"error: login hun\x1b[0mter2-xyz refused\r\n", false, t0);
        let out = alerts.flush(t0);
        assert_eq!(out[0].sample, "error: login [redacted] refused");
        // A secret typed later; and a token the pattern list knows.
        alerts.add_secret(&SecretString::new("typed-later-1"));
        alerts.output(
            b"error typed-later-1 password=abc123\r\n",
            false,
            t0 + Duration::from_secs(61),
        );
        let out = alerts.flush(t0 + Duration::from_secs(61));
        assert!(!out[0].sample.contains("typed-later-1"), "{}", out[0].sample);
        assert!(!out[0].sample.contains("abc123"), "{}", out[0].sample);
        // A long line is cut around its match, with an ellipsis on each side; bidi controls go.
        let long = format!("{}\u{202E} error {}\r\n", "a".repeat(500), "b".repeat(500));
        alerts.output(long.as_bytes(), false, t0 + Duration::from_secs(200));
        let out = alerts.flush(t0 + Duration::from_secs(200));
        let sample = &out[0].sample;
        assert!(sample.chars().count() <= MAX_SAMPLE_CHARS, "{}", sample.len());
        assert!(sample.starts_with('…') && sample.ends_with('…'), "{sample}");
        assert!(sample.contains("error"), "{sample}");
        assert!(!sample.contains('\u{202E}'));
        drop(tx);
    }

    #[test]
    fn only_the_start_of_a_very_long_line_is_matched() {
        let (mut alerts, _tx) = watch_on(vec![error_rule()]);
        let t0 = Instant::now();
        let late = format!("{} error\r\n", "x".repeat(MAX_MATCHED_CHARS));
        alerts.output(late.as_bytes(), false, t0);
        assert_eq!(alerts.deadline(), None);
        let early = format!("error {}\r\n", "x".repeat(MAX_MATCHED_CHARS));
        alerts.output(early.as_bytes(), false, t0);
        assert!(alerts.deadline().is_some());
    }

    #[test]
    fn the_panes_scope_picks_the_rules_and_changes_arrive_live() {
        let web = Uuid::new_v4();
        let (tx, rx) = watch::channel(Arc::new(RuleBook::default()));
        let mut alerts = AlertWatch::new(Some(rx), AlertTiming::default());
        alerts.new_shell(Some(web), Environment::Prod, Vec::new());
        let t0 = Instant::now();
        alerts.output(b"error before any rule\r\n", false, t0);
        assert_eq!(alerts.deadline(), None);
        tx.send_replace(Arc::new(RuleBook {
            version: 2,
            alerts: vec![
                rule(
                    "lab",
                    "error",
                    RuleScope::Environment {
                        environment: Environment::Lab,
                    },
                ),
                rule(
                    "other",
                    "error",
                    RuleScope::Session {
                        session_id: Uuid::new_v4(),
                    },
                ),
                rule(
                    "prod",
                    "error",
                    RuleScope::Environment {
                        environment: Environment::Prod,
                    },
                ),
                rule("web", "error", RuleScope::Session { session_id: web }),
            ],
        }));
        alerts.output(b"error now\r\n", false, t0);
        let mut ids: Vec<String> = alerts.flush(t0).into_iter().map(|b| b.rule_id).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["prod", "web"]);
        // Turned off again: nothing more.
        tx.send_replace(Arc::new(RuleBook::default()));
        alerts.output(b"error after\r\n", false, t0 + Duration::from_secs(100));
        assert_eq!(alerts.deadline(), None);
    }

    #[test]
    fn alerts_carry_wall_clock_times() {
        let t0 = Instant::now();
        let wall = time::macros::datetime!(2026-10-25 10:00:05 UTC);
        let alert = AlertBurst {
            rule_id: "e".into(),
            rule_name: "Error".into(),
            count: 2,
            suppressed: 0,
            first: t0,
            last: t0 + Duration::from_secs(2),
            sample: "error".into(),
        }
        .into_alert(Uuid::nil(), None, t0 + Duration::from_secs(5), wall);
        assert_eq!(alert.first_at, "2026-10-25T10:00:00Z");
        assert_eq!(alert.last_at, "2026-10-25T10:00:02Z");
        let json = serde_json::to_value(&alert).unwrap();
        assert_eq!(json["ruleName"], "Error");
        assert_eq!(json["sessionId"], serde_json::Value::Null);
    }
}
