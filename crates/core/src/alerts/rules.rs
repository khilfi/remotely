//! MO-07: what a rule is, the rules Remotely ships, and the checks every rule passes before it is saved.
//!
//! Built-in rules are created at start in each workspace and never deleted: the owner can turn each on or
//! off and change its threshold, duration, severity and notification, and reset it to its defaults. Their
//! metric and scope are fixed (a rule of one's own covers anything else). The defaults lean quiet: what
//! signals real trouble and rarely fires in a busy lab is on (a VM that stopped without a Remotely action, a
//! watched host's disk above 85% or a watched host unreachable for 5 minutes, this PC's memory above 90% for
//! 5 minutes); CPU and memory of VMs and hosts, which builds and caches push high on purpose, are off until
//! turned on.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};

/// What a rule watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AlertMetric {
    /// Busy share of the machine's own CPUs (the guest's view, else the VM's process; this PC's whole CPU).
    Cpu,
    /// Memory in use against what there is (the guest's view, else the VM's working set against its RAM).
    Memory,
    /// The fullest mounted disk (a watched guest).
    Disk,
    /// Swap in use against its size (a watched guest), or this PC's paging files.
    Swap,
    /// A watched host that can't be reached (a running VM's watched guest, or an SSH host).
    Unreachable,
    /// A VM whose process went away with no Remotely job on it: powered off, suspended or crashed outside the app.
    Stopped,
}

impl AlertMetric {
    pub const ALL: [AlertMetric; 6] = [
        AlertMetric::Cpu,
        AlertMetric::Memory,
        AlertMetric::Disk,
        AlertMetric::Swap,
        AlertMetric::Unreachable,
        AlertMetric::Stopped,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AlertMetric::Cpu => "cpu",
            AlertMetric::Memory => "memory",
            AlertMetric::Disk => "disk",
            AlertMetric::Swap => "swap",
            AlertMetric::Unreachable => "unreachable",
            AlertMetric::Stopped => "stopped",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str() == text)
    }

    /// CPU, memory, disk and swap are percentages with a threshold; the others are states.
    pub fn has_threshold(self) -> bool {
        matches!(
            self,
            AlertMetric::Cpu | AlertMetric::Memory | AlertMetric::Disk | AlertMetric::Swap
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            AlertMetric::Cpu => "CPU",
            AlertMetric::Memory => "Memory",
            AlertMetric::Disk => "Disk",
            AlertMetric::Swap => "Swap",
            AlertMetric::Unreachable => "Unreachable",
            AlertMetric::Stopped => "Stopped",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "warning" => Some(Severity::Warning),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

/// Which targets a rule covers. A VM's key is its .vmx path or VirtualBox UUID; an SSH host is a session the
/// dashboard watches (on its own row, or as the guest of a VM's row).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum AlertScope {
    AllVms,
    Vm {
        key: String,
    },
    /// VMs and watched hosts with the tag.
    Tag {
        tag: String,
    },
    Host {
        session_id: Uuid,
    },
    /// Every watched host.
    AllHosts,
    ThisPc,
}

impl AlertScope {
    pub fn kind_str(&self) -> &'static str {
        match self {
            AlertScope::AllVms => "allVms",
            AlertScope::Vm { .. } => "vm",
            AlertScope::Tag { .. } => "tag",
            AlertScope::Host { .. } => "host",
            AlertScope::AllHosts => "allHosts",
            AlertScope::ThisPc => "thisPc",
        }
    }

    pub fn key(&self) -> Option<String> {
        match self {
            AlertScope::Vm { key } => Some(key.clone()),
            AlertScope::Tag { tag } => Some(tag.clone()),
            AlertScope::Host { session_id } => Some(session_id.to_string()),
            AlertScope::AllVms | AlertScope::AllHosts | AlertScope::ThisPc => None,
        }
    }

    pub fn from_parts(kind: &str, key: Option<String>) -> Option<Self> {
        Some(match kind {
            "allVms" => AlertScope::AllVms,
            "vm" => AlertScope::Vm { key: key? },
            "tag" => AlertScope::Tag { tag: key? },
            "host" => AlertScope::Host {
                session_id: Uuid::parse_str(&key?).ok()?,
            },
            "allHosts" => AlertScope::AllHosts,
            "thisPc" => AlertScope::ThisPc,
            _ => return None,
        })
    }

    /// Whether `metric` means anything for this scope's targets.
    pub fn allows(&self, metric: AlertMetric) -> bool {
        match self {
            AlertScope::ThisPc => matches!(metric, AlertMetric::Cpu | AlertMetric::Memory | AlertMetric::Swap),
            AlertScope::Host { .. } | AlertScope::AllHosts => metric != AlertMetric::Stopped,
            AlertScope::AllVms | AlertScope::Vm { .. } | AlertScope::Tag { .. } => true,
        }
    }
}

/// A saved rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertRule {
    pub id: Uuid,
    /// A rule Remotely ships ([`BUILTINS`]); `None` for the owner's own.
    pub builtin: Option<String>,
    pub name: String,
    pub metric: AlertMetric,
    pub scope: AlertScope,
    /// Percent (above it fires), for CPU, memory, disk and swap; `None` for unreachable and stopped.
    pub threshold: Option<f64>,
    /// How long the condition must hold before the alert fires.
    pub for_secs: u64,
    pub severity: Severity,
    /// A Windows notification when it fires (at most one per rule and target in [`super::eval::COOLDOWN_MS`]).
    pub notify: bool,
    pub enabled: bool,
    pub updated_at: String,
}

/// A rule as the editor sends it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertRuleInput {
    pub name: String,
    pub metric: AlertMetric,
    pub scope: AlertScope,
    #[serde(default)]
    pub threshold: Option<f64>,
    pub for_secs: u64,
    pub severity: Severity,
    pub notify: bool,
    pub enabled: bool,
}

impl AlertRule {
    pub fn input(&self) -> AlertRuleInput {
        AlertRuleInput {
            name: self.name.clone(),
            metric: self.metric,
            scope: self.scope.clone(),
            threshold: self.threshold,
            for_secs: self.for_secs,
            severity: self.severity,
            notify: self.notify,
            enabled: self.enabled,
        }
    }
}

/// A rule Remotely ships, by its stable key.
#[derive(Debug, Clone, Copy)]
pub struct Builtin {
    pub key: &'static str,
    pub name: &'static str,
    pub metric: AlertMetric,
    pub scope: BuiltinScope,
    pub threshold: Option<f64>,
    pub for_secs: u64,
    pub severity: Severity,
    pub notify: bool,
    pub enabled: bool,
}

/// The scopes built-in rules use (none names one target).
#[derive(Debug, Clone, Copy)]
pub enum BuiltinScope {
    AllVms,
    AllHosts,
    ThisPc,
}

impl Builtin {
    pub fn input(&self) -> AlertRuleInput {
        AlertRuleInput {
            name: self.name.to_owned(),
            metric: self.metric,
            scope: match self.scope {
                BuiltinScope::AllVms => AlertScope::AllVms,
                BuiltinScope::AllHosts => AlertScope::AllHosts,
                BuiltinScope::ThisPc => AlertScope::ThisPc,
            },
            threshold: self.threshold,
            for_secs: self.for_secs,
            severity: self.severity,
            notify: self.notify,
            enabled: self.enabled,
        }
    }
}

/// The built-in rules (see the module's comment for why some are on and some off).
pub const BUILTINS: [Builtin; 7] = [
    Builtin {
        key: "vm-stopped",
        name: "A VM stopped without a Remotely action",
        metric: AlertMetric::Stopped,
        scope: BuiltinScope::AllVms,
        threshold: None,
        for_secs: 0,
        severity: Severity::Critical,
        notify: true,
        enabled: true,
    },
    Builtin {
        key: "host-disk",
        name: "A watched host's disk above 85% full",
        metric: AlertMetric::Disk,
        scope: BuiltinScope::AllHosts,
        threshold: Some(85.0),
        for_secs: 300,
        severity: Severity::Warning,
        notify: true,
        enabled: true,
    },
    Builtin {
        key: "host-unreachable",
        name: "A watched host unreachable for 5 minutes",
        metric: AlertMetric::Unreachable,
        scope: BuiltinScope::AllHosts,
        threshold: None,
        for_secs: 300,
        severity: Severity::Critical,
        notify: true,
        enabled: true,
    },
    Builtin {
        key: "this-pc-memory",
        name: "This PC's memory above 90% for 5 minutes",
        metric: AlertMetric::Memory,
        scope: BuiltinScope::ThisPc,
        threshold: Some(90.0),
        for_secs: 300,
        severity: Severity::Warning,
        notify: true,
        enabled: true,
    },
    Builtin {
        key: "vm-cpu",
        name: "A VM's CPU above 90% for 5 minutes",
        metric: AlertMetric::Cpu,
        scope: BuiltinScope::AllVms,
        threshold: Some(90.0),
        for_secs: 300,
        severity: Severity::Warning,
        notify: true,
        enabled: false,
    },
    Builtin {
        key: "vm-memory",
        name: "A VM's memory above 95% for 10 minutes",
        metric: AlertMetric::Memory,
        scope: BuiltinScope::AllVms,
        threshold: Some(95.0),
        for_secs: 600,
        severity: Severity::Warning,
        notify: true,
        enabled: false,
    },
    Builtin {
        key: "host-cpu",
        name: "A watched host's CPU above 90% for 5 minutes",
        metric: AlertMetric::Cpu,
        scope: BuiltinScope::AllHosts,
        threshold: Some(90.0),
        for_secs: 300,
        severity: Severity::Warning,
        notify: true,
        enabled: false,
    },
];

pub fn builtin(key: &str) -> Option<&'static Builtin> {
    BUILTINS.iter().find(|b| b.key == key)
}

pub const MAX_NAME: usize = 80;

/// A VM's key or a tag, at most.
pub const MAX_SCOPE_KEY: usize = 1024;

/// The longest duration a rule may wait: a day.
pub const MAX_FOR_SECS: u64 = 24 * 60 * 60;

/// The rule as it is saved: the name trimmed, a threshold only where it means something. Refused with a
/// reason the editor shows when it can't be saved.
pub fn checked(mut input: AlertRuleInput) -> Result<AlertRuleInput> {
    let invalid = |why: String| Err(CoreError::InvalidInput(why));
    input.name = input.name.trim().to_owned();
    if input.name.is_empty() {
        return invalid("A rule needs a name.".into());
    }
    if input.name.chars().count() > MAX_NAME {
        return invalid(format!("A rule's name can be at most {MAX_NAME} characters."));
    }
    if input.name.chars().any(char::is_control) {
        return invalid("A rule's name can't hold control characters.".into());
    }
    if !input.scope.allows(input.metric) {
        return invalid(format!(
            "{} can't be watched on {}.",
            input.metric.label(),
            scope_text(&input.scope)
        ));
    }
    match &mut input.scope {
        AlertScope::Vm { key } | AlertScope::Tag { tag: key } => {
            *key = key.trim().to_owned();
            if key.is_empty() || key.len() > MAX_SCOPE_KEY || key.chars().any(char::is_control) {
                return invalid("Choose the VM or tag the rule watches.".into());
            }
        }
        AlertScope::AllVms | AlertScope::Host { .. } | AlertScope::AllHosts | AlertScope::ThisPc => {}
    }
    if input.metric.has_threshold() {
        match input.threshold {
            Some(t) if t.is_finite() && t > 0.0 && t < 100.0 => {}
            _ => return invalid("The threshold must be more than 0% and less than 100%.".into()),
        }
    } else {
        input.threshold = None;
    }
    if input.for_secs > MAX_FOR_SECS {
        return invalid("A rule can wait at most a day before it fires.".into());
    }
    Ok(input)
}

/// "every VM", "the VM web-01"..., for messages. A VM's or host's own name is filled in by the caller when it
/// knows it.
pub fn scope_text(scope: &AlertScope) -> String {
    match scope {
        AlertScope::AllVms => "every VM".into(),
        AlertScope::Vm { .. } => "a VM".into(),
        AlertScope::Tag { tag } => format!("everything tagged {tag}"),
        AlertScope::Host { .. } => "a watched host".into(),
        AlertScope::AllHosts => "every watched host".into(),
        AlertScope::ThisPc => "this PC".into(),
    }
}

/// "5 minutes", "30 seconds", "1 hour".
pub fn duration_text(secs: u64) -> String {
    let unit = |n: u64, one: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {one}s")
        }
    };
    if secs >= 3600 && secs.is_multiple_of(3600) {
        unit(secs / 3600, "hour")
    } else if secs >= 60 && secs.is_multiple_of(60) {
        unit(secs / 60, "minute")
    } else {
        unit(secs, "second")
    }
}

fn pct(value: f64) -> String {
    if value >= 10.0 {
        format!("{value:.0}%")
    } else {
        format!("{value:.1}%")
    }
}

/// What a rule says when it fires: "CPU at 97%, above 90% for 5 minutes".
pub fn message(rule: &AlertRule, value: Option<f64>, mount: Option<&str>) -> String {
    let held = if rule.for_secs > 0 {
        format!(" for {}", duration_text(rule.for_secs))
    } else {
        String::new()
    };
    let threshold = rule.threshold.map(pct).unwrap_or_default();
    let now = value.map(pct).unwrap_or_else(|| "—".into());
    match rule.metric {
        AlertMetric::Cpu => format!("CPU at {now}, above {threshold}{held}"),
        AlertMetric::Memory => format!("Memory at {now}, above {threshold}{held}"),
        AlertMetric::Disk => match mount {
            Some(mount) => format!("Disk {now} full on {mount}, above {threshold}{held}"),
            None => format!("Disk {now} full, above {threshold}{held}"),
        },
        AlertMetric::Swap => format!("Swap at {now}, above {threshold}{held}"),
        AlertMetric::Unreachable => format!("Not reachable{held}"),
        AlertMetric::Stopped => {
            if rule.for_secs > 0 {
                format!(
                    "Stopped without a Remotely action, and still off after {}",
                    duration_text(rule.for_secs)
                )
            } else {
                "Stopped without a Remotely action (powered off, suspended or crashed outside the app)".into()
            }
        }
    }
}

/// A rule in a line, for the audit log: "CPU above 90% for 5 minutes on every VM, warning, notifies, on".
pub fn describe(rule: &AlertRuleInput) -> String {
    let what = match (rule.metric, rule.threshold) {
        (AlertMetric::Unreachable, _) => "unreachable".to_owned(),
        (AlertMetric::Stopped, _) => "stopped without a Remotely action".to_owned(),
        (metric, Some(t)) => format!("{} above {}", metric.label(), pct(t)),
        (metric, None) => metric.label().to_owned(),
    };
    let held = if rule.for_secs > 0 {
        format!(" for {}", duration_text(rule.for_secs))
    } else {
        String::new()
    };
    let scope = match &rule.scope {
        AlertScope::Vm { key } => format!("the VM {key}"),
        AlertScope::Host { session_id } => format!("the watched host {session_id}"),
        other => scope_text(other),
    };
    format!(
        "'{}': {what}{held} on {scope}, {}, {}, {}",
        rule.name,
        rule.severity.as_str(),
        if rule.notify { "notifies" } else { "no notification" },
        if rule.enabled { "on" } else { "off" },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(metric: AlertMetric, scope: AlertScope, threshold: Option<f64>) -> AlertRuleInput {
        AlertRuleInput {
            name: " CPU high ".into(),
            metric,
            scope,
            threshold,
            for_secs: 300,
            severity: Severity::Warning,
            notify: true,
            enabled: true,
        }
    }

    #[test]
    fn a_rule_is_trimmed_and_keeps_a_threshold_only_where_it_means_something() {
        let rule = checked(input(AlertMetric::Cpu, AlertScope::AllVms, Some(90.0))).unwrap();
        assert_eq!(rule.name, "CPU high");
        assert_eq!(rule.threshold, Some(90.0));
        let rule = checked(input(AlertMetric::Unreachable, AlertScope::AllHosts, Some(90.0))).unwrap();
        assert_eq!(rule.threshold, None, "a state has no threshold");
    }

    #[test]
    fn a_rule_that_cant_mean_anything_is_refused_with_a_reason() {
        let refused = |i: AlertRuleInput| checked(i).unwrap_err().to_string();
        assert!(refused(input(AlertMetric::Cpu, AlertScope::AllVms, None)).contains("threshold"));
        assert!(refused(input(AlertMetric::Cpu, AlertScope::AllVms, Some(100.0))).contains("threshold"));
        assert!(refused(input(AlertMetric::Cpu, AlertScope::AllVms, Some(0.0))).contains("threshold"));
        assert!(refused(input(AlertMetric::Cpu, AlertScope::AllVms, Some(f64::NAN))).contains("threshold"));
        assert!(refused(input(AlertMetric::Disk, AlertScope::ThisPc, Some(85.0))).contains("this PC"));
        assert!(refused(input(AlertMetric::Unreachable, AlertScope::ThisPc, None)).contains("this PC"));
        assert!(refused(input(AlertMetric::Stopped, AlertScope::AllHosts, None)).contains("watched host"));
        let tag = AlertScope::Tag { tag: "  ".into() };
        assert!(refused(input(AlertMetric::Cpu, tag, Some(80.0))).contains("tag"));
        let mut long = input(AlertMetric::Cpu, AlertScope::AllVms, Some(80.0));
        long.name = "x".repeat(MAX_NAME + 1);
        assert!(refused(long).contains("at most"));
        let mut slow = input(AlertMetric::Cpu, AlertScope::AllVms, Some(80.0));
        slow.for_secs = MAX_FOR_SECS + 1;
        assert!(refused(slow).contains("a day"));
        let mut blank = input(AlertMetric::Cpu, AlertScope::AllVms, Some(80.0));
        blank.name = "\t".into();
        assert!(refused(blank).contains("name"));
    }

    #[test]
    fn every_builtin_rule_passes_the_checks_and_quiet_ones_start_off() {
        let mut keys = std::collections::HashSet::new();
        for b in BUILTINS {
            assert!(keys.insert(b.key), "{} twice", b.key);
            let input = b.input();
            assert_eq!(checked(input.clone()).unwrap(), input, "{}", b.key);
        }
        let on: Vec<&str> = BUILTINS.iter().filter(|b| b.enabled).map(|b| b.key).collect();
        assert_eq!(on, ["vm-stopped", "host-disk", "host-unreachable", "this-pc-memory"]);
        assert!(builtin("vm-cpu").is_some_and(|b| !b.enabled));
    }

    #[test]
    fn a_rule_says_what_fired_in_words() {
        let mut rule = AlertRule {
            id: Uuid::nil(),
            builtin: None,
            name: "CPU".into(),
            metric: AlertMetric::Cpu,
            scope: AlertScope::AllVms,
            threshold: Some(90.0),
            for_secs: 300,
            severity: Severity::Warning,
            notify: true,
            enabled: true,
            updated_at: String::new(),
        };
        assert_eq!(message(&rule, Some(97.4), None), "CPU at 97%, above 90% for 5 minutes");
        rule.metric = AlertMetric::Disk;
        rule.threshold = Some(85.0);
        rule.for_secs = 0;
        assert_eq!(
            message(&rule, Some(91.0), Some("/var")),
            "Disk 91% full on /var, above 85%"
        );
        rule.metric = AlertMetric::Unreachable;
        rule.for_secs = 3600;
        assert_eq!(message(&rule, None, None), "Not reachable for 1 hour");
        assert_eq!(duration_text(90), "90 seconds");
        assert_eq!(duration_text(60), "1 minute");
        assert_eq!(
            describe(&input(AlertMetric::Cpu, AlertScope::AllVms, Some(90.0))),
            "' CPU high ': CPU above 90% for 5 minutes on every VM, warning, notifies, on"
        );
    }

    #[test]
    fn scopes_go_to_and_from_their_columns() {
        let id = Uuid::new_v4();
        for scope in [
            AlertScope::AllVms,
            AlertScope::Vm {
                key: r"C:\VMs\web\web.vmx".into(),
            },
            AlertScope::Tag { tag: "web".into() },
            AlertScope::Host { session_id: id },
            AlertScope::AllHosts,
            AlertScope::ThisPc,
        ] {
            assert_eq!(
                AlertScope::from_parts(scope.kind_str(), scope.key()),
                Some(scope.clone())
            );
        }
        assert_eq!(AlertScope::from_parts("host", Some("not a uuid".into())), None);
        assert_eq!(AlertScope::from_parts("everything", None), None);
        for metric in AlertMetric::ALL {
            assert_eq!(AlertMetric::parse(metric.as_str()), Some(metric));
        }
    }
}
