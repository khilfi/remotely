//! BX-08 `{{variables}}` in saved commands: `{{name}}`, or `{{name:default}}`, asked when the command
//! is pasted. A name starts with a letter or `_` and holds letters, digits, `_` and `-`; anything else
//! between double braces is left as it is, so Go templates such as `docker ps --format '{{.Names}}'`
//! keep working.

use std::collections::HashMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use crate::error::{CoreError, Result};

/// Longest variable name.
pub const MAX_VARIABLE_NAME: usize = 40;
/// Longest value one variable takes.
pub const MAX_VARIABLE_VALUE: usize = 1024;

// A constant pattern, compiled by the tests: `expect` cannot fire on input here.
#[allow(clippy::expect_used)]
static VARIABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\{\{\s*([A-Za-z_][A-Za-z0-9_-]{0,39})\s*(?::([^{}\n]*))?\}\}").expect("valid variable regex")
});

/// A value the command asks for when it is pasted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Variable {
    pub name: String,
    /// From `{{name:default}}`; the first one given wins.
    pub default: Option<String>,
}

/// The command's variables, once each, in the order they first appear.
pub fn variables(command: &str) -> Vec<Variable> {
    let mut found: Vec<Variable> = Vec::new();
    for cap in VARIABLE.captures_iter(command) {
        let name = &cap[1];
        let default = cap.get(2).map(|d| d.as_str().trim().to_owned());
        match found.iter_mut().find(|v| v.name == name) {
            Some(known) => {
                if known.default.is_none() {
                    known.default = default;
                }
            }
            None => found.push(Variable {
                name: name.to_owned(),
                default,
            }),
        }
    }
    found
}

/// The command with each variable replaced by its value, or its default when the value is empty or
/// missing. A value can't hold a line break: it would press Enter in the middle of the command.
pub fn fill(command: &str, values: &HashMap<String, String>) -> Result<String> {
    let wanted = variables(command);
    let mut chosen: HashMap<&str, &str> = HashMap::new();
    for variable in &wanted {
        let value = values
            .get(&variable.name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
            .or(variable.default.as_deref())
            .ok_or_else(|| CoreError::InvalidInput(format!("Give a value for {{{{{}}}}}.", variable.name)))?;
        if value.contains(['\r', '\n']) {
            return Err(CoreError::InvalidInput(format!(
                "The value for {{{{{}}}}} can't hold a line break.",
                variable.name
            )));
        }
        if value.chars().count() > MAX_VARIABLE_VALUE {
            return Err(CoreError::InvalidInput(format!(
                "The value for {{{{{}}}}} is longer than {MAX_VARIABLE_VALUE} characters.",
                variable.name
            )));
        }
        chosen.insert(variable.name.as_str(), value);
    }
    Ok(VARIABLE
        .replace_all(command, |cap: &regex::Captures<'_>| {
            chosen.get(&cap[1]).copied().unwrap_or_default().to_owned()
        })
        .into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    #[test]
    fn variables_are_found_once_each_with_their_defaults() {
        let found =
            variables("journalctl -u {{service}} --since '{{since: 1 hour ago }}' -n {{ lines:200 }} {{service}}");
        assert_eq!(
            found,
            [
                Variable {
                    name: "service".into(),
                    default: None
                },
                Variable {
                    name: "since".into(),
                    default: Some("1 hour ago".into())
                },
                Variable {
                    name: "lines".into(),
                    default: Some("200".into())
                },
            ]
        );
        // A later default fills one the first use left out.
        assert_eq!(variables("{{a}} {{a:1}}")[0].default.as_deref(), Some("1"));
        assert_eq!(variables("{{extra:}}")[0].default.as_deref(), Some(""));
    }

    #[test]
    fn templates_that_are_not_variables_stay_as_they_are() {
        let command = "docker ps --format '{{.Names}}\\t{{ json .State }}' {{9lives}} {{}} {x} {{a b}}";
        assert!(variables(command).is_empty());
        assert_eq!(fill(command, &HashMap::new()).unwrap(), command);
        let long = format!("{{{{{}}}}}", "a".repeat(MAX_VARIABLE_NAME + 1));
        assert!(variables(&long).is_empty(), "too long a name");
    }

    #[test]
    fn filling_uses_values_then_defaults() {
        let command = "kubectl logs {{pod}} -n {{namespace:default}} --tail={{lines:200}} # {{pod}}";
        let out = fill(command, &values(&[("pod", "web-1"), ("lines", "")])).unwrap();
        assert_eq!(out, "kubectl logs web-1 -n default --tail=200 # web-1");
        let out = fill(
            command,
            &values(&[("pod", "web-1"), ("namespace", "shop"), ("other", "x")]),
        )
        .unwrap();
        assert_eq!(out, "kubectl logs web-1 -n shop --tail=200 # web-1");
        assert_eq!(fill("ls {{extra:}}", &HashMap::new()).unwrap(), "ls ");
    }

    #[test]
    fn a_missing_value_or_a_line_break_is_refused() {
        let err = fill("ping -c 4 {{host}}", &HashMap::new()).unwrap_err();
        assert_eq!(err.to_string(), "Give a value for {{host}}.");
        let err = fill("ping -c 4 {{host}}", &values(&[("host", "")])).unwrap_err();
        assert_eq!(err.code(), "invalid_input");
        let err = fill("ping -c 4 {{host}}", &values(&[("host", "web01.example.com\rreboot")])).unwrap_err();
        assert_eq!(err.to_string(), "The value for {{host}} can't hold a line break.");
        let long = "x".repeat(MAX_VARIABLE_VALUE + 1);
        assert!(fill("echo {{a}}", &values(&[("a", &long)])).is_err());
    }

    #[test]
    fn a_command_without_variables_is_unchanged() {
        assert_eq!(fill("df -h", &values(&[("x", "y")])).unwrap(), "df -h");
    }
}
