//! AP-08: a ticket or change number given with a High or Critical approval.
//!
//! The policy engine asks for one ([`crate::policy::ApprovalStep::ChangeId`]) on every High and Critical
//! approval, standing approvals for schedules included; it is optional unless the workspace's rule
//! ([`ChangeIdRules::required_for_prod`]) makes it required for an action on a Prod target. What is given is kept in
//! the approval record (so in the job and its audit entries), in the job's own column for Activity, and in the AP-05
//! audit CSV and the Compare and MultiExec exports. It is free text a person types, so it is cleaned like any: at
//! most [`MAX_CHANGE_ID_CHARS`] characters, one line without control or format characters, and run through
//! [`redact_secrets`] before it is kept.

use serde::{Deserialize, Serialize};

use crate::domain::{Context, Environment, Target};
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;
use crate::store::Store;
use crate::untrusted::is_format_char;

/// AP-08: the workspace's change ID rule (a per-workspace setting, FD-02).
pub const CHANGE_ID_KEY: &str = "approvals.changeIds";

/// AP-08: the longest change ID kept. Tickets are short ("CHG0012345", "OPS-1234"); a longer text is refused, not cut.
pub const MAX_CHANGE_ID_CHARS: usize = 64;

/// AP-08: what the workspace asks of change IDs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ChangeIdRules {
    /// A High or Critical action on a Prod target needs a change ID.
    pub required_for_prod: bool,
}

impl ChangeIdRules {
    /// The workspace's rule (off when never set).
    pub async fn load(store: &Store, ctx: &Context) -> Result<Self> {
        Ok(store
            .get_setting::<ChangeIdRules>(ctx, CHANGE_ID_KEY)
            .await?
            .unwrap_or_default())
    }

    /// Whether an approval on these targets must have a change ID.
    pub fn requires(&self, targets: &[Target]) -> bool {
        self.required_for_prod && targets.iter().any(|t| t.environment == Environment::Prod)
    }
}

/// AP-08: the change ID as it is kept, or `None` when none was given (blank counts as none). Refused when it is too
/// long or holds a line break, a control or a format character. What looks like a secret is replaced by
/// `[redacted]`.
pub fn clean_change_id(raw: Option<&str>) -> Result<Option<String>> {
    let Some(text) = raw.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    if text.chars().count() > MAX_CHANGE_ID_CHARS {
        return Err(CoreError::ApprovalRejected(format!(
            "a change ID is at most {MAX_CHANGE_ID_CHARS} characters"
        )));
    }
    if text.chars().any(|c| c.is_control() || is_format_char(c)) {
        return Err(CoreError::ApprovalRejected(
            "a change ID is one line of plain text".into(),
        ));
    }
    Ok(Some(redact_secrets(text).0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::TargetRef;

    fn target(environment: Environment) -> Target {
        Target {
            target: TargetRef::App,
            name: "x".into(),
            environment,
            protected: false,
        }
    }

    #[test]
    fn a_change_id_is_trimmed_and_blank_is_none() {
        assert_eq!(clean_change_id(None).unwrap(), None);
        assert_eq!(clean_change_id(Some("   ")).unwrap(), None);
        assert_eq!(
            clean_change_id(Some("  CHG0012345 ")).unwrap().as_deref(),
            Some("CHG0012345")
        );
    }

    #[test]
    fn a_change_id_is_capped_and_one_line() {
        let longest = "A".repeat(MAX_CHANGE_ID_CHARS);
        assert_eq!(clean_change_id(Some(&longest)).unwrap(), Some(longest.clone()));
        assert!(clean_change_id(Some(&format!("{longest}B"))).is_err());
        assert!(clean_change_id(Some("CHG1\nCHG2")).is_err());
        assert!(clean_change_id(Some("CHG\u{202e}1")).is_err(), "a format character");
    }

    #[test]
    fn a_secret_in_a_change_id_is_redacted() {
        let kept = clean_change_id(Some("password=hunter2")).unwrap().unwrap();
        assert!(!kept.contains("hunter2"), "{kept}");
    }

    #[test]
    fn the_rule_asks_only_for_prod_targets_and_only_when_on() {
        let off = ChangeIdRules::default();
        let on = ChangeIdRules {
            required_for_prod: true,
        };
        let prod = [target(Environment::Lab), target(Environment::Prod)];
        let lab = [target(Environment::Lab)];
        assert!(!off.requires(&prod));
        assert!(on.requires(&prod));
        assert!(!on.requires(&lab));
    }
}
