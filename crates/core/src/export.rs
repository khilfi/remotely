//! Audit log export to CSV (AP-05), and the redaction that keeps secrets out of it.
//!
//! The audit log never stores a vault secret: approvals keep only what the user answered, never the
//! vault password (AP-06). Free text can still hold one by mistake, e.g. a command typed with
//! `--password=...` or a reason with a token in it, so [`redact_secrets`] runs on free text before
//! it is stored and again on every exported text cell. A row that had to be redacted is marked, since
//! its hash then no longer matches the exported text.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::store::AuditEntry;

// Constant patterns, compiled by the tests below; `expect` cannot fire on user input here.
#[allow(clippy::expect_used)]
static SECRET_PATTERNS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        // --password hunter2, -token=abc, --api-key 'x y'; CT-01 Redis's --requirepass and --masterauth (a
        // container's command line)
        (
            r#"(?i)(--?(?:password|passwd|pass|pwd|passphrase|secret|token|api-?key|access-?key|requirepass|masterauth)(?:=|\s+))("[^"]*"|'[^']*'|[^\s;&|`"']+)"#,
            "${1}[redacted]",
        ),
        // password=hunter2, TOKEN: abc, api_key = "x"
        (
            r#"(?i)((?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s;&|`"']+)"#,
            "${1}[redacted]",
        ),
        // https://alice:hunter2@example.com
        (r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@", "${1}[redacted]@"),
        // Authorization: Bearer abc.def
        (r"(?i)\b(bearer\s+)[a-z0-9._~+/=-]+", "${1}[redacted]"),
    ]
    .into_iter()
    .map(|(pattern, with)| (Regex::new(pattern).expect("valid secret pattern"), with))
    .collect()
});

/// Replaces what looks like a password, token or key in free text with `[redacted]`. Returns the
/// text and whether anything was replaced.
pub fn redact_secrets(text: &str) -> (String, bool) {
    let mut out = text.to_owned();
    for (re, with) in SECRET_PATTERNS.iter() {
        if re.is_match(&out) {
            out = re.replace_all(&out, *with).into_owned();
        }
    }
    let changed = out != text;
    (out, changed)
}

/// Redacts every string inside a JSON document, keeping it valid JSON. Unchanged text is returned
/// as it was, byte for byte, so its hash still checks out.
fn redact_json(json: &str) -> (String, bool) {
    fn walk(value: &mut Value) -> bool {
        match value {
            Value::String(text) => {
                let (clean, changed) = redact_secrets(text);
                *text = clean;
                changed
            }
            Value::Array(items) => items.iter_mut().fold(false, |any, v| walk(v) | any),
            Value::Object(map) => map.values_mut().fold(false, |any, v| walk(v) | any),
            _ => false,
        }
    }
    match serde_json::from_str::<Value>(json) {
        Ok(mut value) => {
            if walk(&mut value) {
                (value.to_string(), true)
            } else {
                (json.to_owned(), false)
            }
        }
        // Not JSON after all: treat it as text.
        Err(_) => redact_secrets(json),
    }
}

/// The file name the save dialog offers, e.g. `remotely-audit-2026-10-18.csv` (today, UTC).
pub fn audit_file_name() -> String {
    let today = time::OffsetDateTime::now_utc().date();
    format!("remotely-audit-{today}.csv")
}

/// Header of the exported file. `id`, `time`, the raw `targets_json` and `approval_json` columns and
/// the others the hash covers, with `prev_hash` and `hash`, let anyone recompute the hash chain from
/// the file alone ([`AuditEntry::compute_hash`]; an empty cell stands for no value). Rows marked
/// `redacted` no longer match their hash, by design.
pub const AUDIT_CSV_COLUMNS: [&str; 23] = [
    "seq",
    "id",
    "time",
    "event",
    "action",
    "tier",
    "job_id",
    "targets",
    "target_count",
    "typed_target_count",
    "reason",
    "safety_snapshot",
    "vault_reauth",
    "approved_at",
    "result",
    "detail",
    "workspace_id",
    "user_id",
    "targets_json",
    "approval_json",
    "prev_hash",
    "hash",
    "redacted",
];

/// The audit entries as CSV (RFC 4180, CRLF line ends, UTF-8 with a byte-order mark so Excel reads
/// it as UTF-8). Returns the text and how many rows had something redacted.
pub fn audit_csv(entries: &[AuditEntry]) -> (String, usize) {
    let mut out = String::from("\u{FEFF}");
    push_row(&mut out, AUDIT_CSV_COLUMNS.iter().map(|c| (*c).to_owned()));
    let mut redacted_rows = 0;
    for e in entries {
        let mut redacted = false;
        let mut clean = |text: &str| {
            let (text, changed) = redact_secrets(text);
            redacted |= changed;
            text
        };
        let targets: Vec<Value> = serde_json::from_str(&e.targets_json).unwrap_or_default();
        let names: Vec<&str> = targets
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect();
        let approval: Option<Value> = e.approval_json.as_deref().and_then(|a| serde_json::from_str(a).ok());
        let field = |key: &str| -> String {
            match approval.as_ref().and_then(|a| a.get(key)) {
                None | Some(Value::Null) => String::new(),
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
            }
        };
        let mut row = vec![
            e.seq.to_string(),
            e.id.clone(),
            e.ts.clone(),
            e.event.clone(),
            clean(&e.action),
            e.tier.clone().unwrap_or_default(),
            e.job_id.clone().unwrap_or_default(),
            names.join("; "),
            targets.len().to_string(),
            field("typedTargetCount"),
            clean(&field("reason")),
            field("safetySnapshot"),
            field("vaultReauth"),
            field("approvedAt"),
            clean(e.result.as_deref().unwrap_or_default()),
            clean(e.detail.as_deref().unwrap_or_default()),
            e.workspace_id.clone(),
            e.user_id.clone(),
            e.targets_json.clone(),
            {
                let (json, changed) = redact_json(e.approval_json.as_deref().unwrap_or_default());
                redacted |= changed;
                json
            },
            e.prev_hash.clone(),
            e.hash.clone(),
        ];
        row.push(redacted.to_string());
        redacted_rows += usize::from(redacted);
        push_row(&mut out, row.into_iter());
    }
    (out, redacted_rows)
}

pub(crate) fn push_row(out: &mut String, cells: impl Iterator<Item = String>) {
    let mut first = true;
    for cell in cells {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&csv_cell(&cell));
    }
    out.push_str("\r\n");
}

/// Quotes a cell when it needs it, and stops a spreadsheet from running it as a formula: a cell
/// starting with `=`, `+`, `-`, `@` or a tab or carriage return gets a leading `'`. VM names come
/// from .vmx files, which anyone could have written.
fn csv_cell(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_passwords_tokens_and_url_credentials() {
        for (input, expected) in [
            (
                "mysql --password=hunter2 -e 'select 1'",
                "mysql --password=[redacted] -e 'select 1'",
            ),
            ("app --token abc123 run", "app --token [redacted] run"),
            ("export API_KEY=sk-123; run", "export API_KEY=[redacted]; run"),
            ("MY_API_KEY=sk-123", "MY_API_KEY=[redacted]"),
            (
                "Run `deploy --password=hunter2` on 2 hosts",
                "Run `deploy --password=[redacted]` on 2 hosts",
            ),
            ("password: \"two words\"", "password: [redacted]"),
            (
                "curl https://alice:hunter2@example.com/x",
                "curl https://alice:[redacted]@example.com/x",
            ),
            (
                "header 'Authorization: Bearer abc.def-ghi'",
                "header 'Authorization: Bearer [redacted]'",
            ),
            ("client_secret=xyz", "client_secret=[redacted]"),
            (
                "redis-server --requirepass hunter2 --port 6379",
                "redis-server --requirepass [redacted] --port 6379",
            ),
            (
                "redis-server --masterauth=hunter2",
                "redis-server --masterauth=[redacted]",
            ),
        ] {
            assert_eq!(redact_secrets(input), (expected.to_owned(), true), "{input}");
        }
    }

    #[test]
    fn leaves_ordinary_text_alone() {
        for text in [
            "Shut down 3 VMs",
            "CHG-1234 lab reset",
            "changed the password policy for alice",
            "ssh -p 2222 bob@example.com",
            "mkdir -p /tmp/x",
            "https://example.com/docs",
            "[redacted]",
            "redis-server --appendonly yes",
        ] {
            assert_eq!(redact_secrets(text), (text.to_owned(), false), "{text}");
        }
    }

    #[test]
    fn redacting_twice_changes_nothing_more() {
        let (once, _) = redact_secrets("--password=hunter2");
        assert_eq!(redact_secrets(&once), (once.clone(), false));
    }

    #[test]
    fn json_stays_valid_json_and_untouched_json_stays_byte_for_byte() {
        let (json, changed) = redact_json(r#"{"reason":"x password=hunter2","n":2,"list":["token: abc"]}"#);
        assert!(changed);
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["reason"], "x password=[redacted]");
        assert_eq!(value["list"][0], "token: [redacted]");
        assert_eq!(value["n"], 2);

        let plain = r#"{ "reason" : "CHG-1", "safetySnapshot":true }"#;
        assert_eq!(redact_json(plain), (plain.to_owned(), false));
        assert_eq!(redact_json(""), (String::new(), false));
    }

    #[test]
    fn cells_are_quoted_and_guarded_against_formulas() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("two\nlines"), "\"two\nlines\"");
        assert_eq!(
            csv_cell("=HYPERLINK(\"http://example.com\")"),
            "\"'=HYPERLINK(\"\"http://example.com\"\")\""
        );
        assert_eq!(csv_cell("+1"), "'+1");
        assert_eq!(csv_cell("-2"), "'-2");
        assert_eq!(csv_cell("@sum"), "'@sum");
    }

    fn entry(seq: i64, action: &str, approval_json: Option<&str>) -> AuditEntry {
        AuditEntry {
            seq,
            id: format!("id-{seq}"),
            workspace_id: "ws".into(),
            user_id: "user".into(),
            ts: "2026-10-18T01:59:23Z".into(),
            event: "approval_granted".into(),
            action: action.into(),
            tier: Some("high".into()),
            job_id: None,
            targets_json: r#"[{"target":{"kind":"vm","vmxPath":"C:\\VMs\\web01\\web01.vmx"},"name":"web01","environment":"lab","protected":false},{"target":{"kind":"vm","vmxPath":"C:\\VMs\\db01\\db01.vmx"},"name":"=db01","environment":"lab","protected":false}]"#.into(),
            approval_json: approval_json.map(str::to_owned),
            result: None,
            detail: None,
            prev_hash: "0".repeat(64),
            hash: "a".repeat(64),
        }
    }

    #[test]
    fn exports_one_row_per_entry_with_the_approval_answers() {
        let approval = r#"{"requestId":"r","tier":"high","typedTargetCount":2,"reason":"CHG-1234, lab","safetySnapshot":true,"vaultReauth":false,"approvedAt":"2026-10-18T01:59:00Z"}"#;
        let (csv, redacted) = audit_csv(&[entry(1, "Suspend 2 VMs", Some(approval))]);
        assert_eq!(redacted, 0);
        assert!(csv.starts_with('\u{FEFF}'));
        let lines: Vec<&str> = csv.trim_start_matches('\u{FEFF}').split("\r\n").collect();
        assert_eq!(lines[0], AUDIT_CSV_COLUMNS.join(","));
        assert!(lines[1].starts_with("1,id-1,2026-10-18T01:59:23Z,approval_granted,Suspend 2 VMs,high,,web01; =db01,2,2,\"CHG-1234, lab\",true,false,2026-10-18T01:59:00Z,"), "{}", lines[1]);
        assert!(lines[1].ends_with(",false"));
        assert_eq!(lines[2], "", "the file ends with a line break");
    }

    #[test]
    fn a_secret_in_free_text_is_redacted_and_the_row_marked() {
        let approval = r#"{"reason":"token=abc123","safetySnapshot":false,"vaultReauth":false}"#;
        let (csv, redacted) = audit_csv(&[
            entry(1, "Run `deploy --password=hunter2` on 2 hosts", Some(approval)),
            entry(2, "Start 2 VMs", None),
        ]);
        assert_eq!(redacted, 1);
        assert!(!csv.contains("hunter2") && !csv.contains("abc123"), "{csv}");
        let lines: Vec<&str> = csv.split("\r\n").collect();
        assert!(lines[1].ends_with(",true"));
        assert!(lines[2].ends_with(",false"));
    }
}
