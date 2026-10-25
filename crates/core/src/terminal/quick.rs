//! QL-02 quick connect: a terminal to a host typed in the "New terminal" form, saved as a session or
//! not. An unsaved connection keeps nothing once its tab closes but a history entry (host, port, user
//! and how it logged in, with vault items by ID); a password typed in the form is used for that
//! terminal's logins only and is never saved, logged or sent back to the UI.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::Environment;
use crate::error::{CoreError, Result};
use crate::sessions::{SessionAuth, SessionColor, SessionInput, SessionRecord};
use crate::vault::SecretString;

/// What the "New terminal" form sends.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickConnect {
    /// A host name or IP address. `user@host:port` is taken apart.
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: Option<String>,
    pub auth: SessionAuth,
    /// A password typed in the form, for a password login without a vault item. Used for this
    /// terminal's logins (and its reconnects) only; never saved.
    #[serde(default)]
    pub password: Option<SecretString>,
    /// Also save the connection as a session.
    #[serde(default)]
    pub save: Option<SaveAs>,
}

/// "Save as session": where it goes and how it is labelled.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveAs {
    /// Empty: the host is used.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub folder_id: Option<Uuid>,
    /// SS-06: Prod raises the approval tier of actions on it.
    #[serde(default)]
    pub environment: Environment,
    #[serde(default)]
    pub color: Option<SessionColor>,
}

/// A quick connection that was not saved, as the history keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickConnectEntry {
    pub id: Uuid,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    /// Vault items by ID, as sessions keep them.
    pub auth: SessionAuth,
    pub used_at: String,
}

/// What a quick connect opened: the terminal, and the session when it was saved.
pub struct QuickOpened {
    pub handle: super::TerminalHandle,
    pub session: Option<SessionRecord>,
}

/// `user@host:port`, `host:port` and `[v6]:port` typed in the host field, taken apart. A port or user
/// typed in their own fields wins. IPv6 addresses without brackets are left whole.
pub fn split_target(typed: &str, port: Option<u16>, user: Option<&str>) -> Result<(String, u16, Option<String>)> {
    let typed = typed.trim();
    let (user_part, rest) = match typed.rsplit_once('@') {
        Some((u, rest)) => (Some(u.trim()), rest.trim()),
        None => (None, typed),
    };
    let (host, typed_port) = if let Some(inner) = rest.strip_prefix('[') {
        match inner.split_once(']') {
            Some((v6, tail)) => {
                let port = match tail.strip_prefix(':') {
                    Some(p) => Some(parse_port(p)?),
                    None if tail.is_empty() => None,
                    None => {
                        return Err(CoreError::InvalidInput(
                            "Write an IPv6 address as [address]:port.".into(),
                        ))
                    }
                };
                (format!("[{v6}]"), port)
            }
            None => return Err(CoreError::InvalidInput("An IPv6 address needs its closing ].".into())),
        }
    } else if rest.matches(':').count() == 1 {
        let (host, p) = rest.split_once(':').unwrap_or((rest, ""));
        (host.to_owned(), Some(parse_port(p)?))
    } else {
        (rest.to_owned(), None)
    };
    let user = user
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .or(user_part.filter(|u| !u.is_empty()))
        .map(str::to_owned);
    Ok((host, port.or(typed_port).unwrap_or(22), user))
}

fn parse_port(text: &str) -> Result<u16> {
    match text.trim().parse::<u16>() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(CoreError::InvalidInput("The port must be 1 to 65535.".into())),
    }
}

impl QuickConnect {
    /// The session the form describes, before the library's checks.
    pub(crate) fn input(&self) -> Result<SessionInput> {
        let (host, port, username) = split_target(&self.host, self.port, self.username.as_deref())?;
        if self.password.as_ref().is_some_and(|p| !p.is_empty()) {
            match self.auth {
                SessionAuth::Password { password_id: None } => {}
                SessionAuth::Password { password_id: Some(_) } => {
                    return Err(CoreError::InvalidInput(
                        "Choose a password from the vault or type one, not both.".into(),
                    ))
                }
                _ => {
                    return Err(CoreError::InvalidInput(
                        "A typed password is only for password logins.".into(),
                    ))
                }
            }
        }
        let save = self.save.clone().unwrap_or_default();
        Ok(SessionInput {
            name: save.name,
            folder_id: save.folder_id,
            host,
            port,
            username,
            auth: self.auth.clone(),
            jump_session_id: None,
            startup_command: None,
            startup_on_reconnect: false,
            prompt_hook: None,
            environment: save.environment,
            color: save.color,
            tags: vec![],
            vm_id: None,
        })
    }

    /// The typed password, if one was typed.
    pub(crate) fn typed_password(&self) -> Option<SecretString> {
        self.password.clone().filter(|p| !p.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_host_and_port_typed_together_are_taken_apart() {
        let split = |t: &str| split_target(t, None, None).unwrap();
        assert_eq!(split("web01.example.com"), ("web01.example.com".into(), 22, None));
        assert_eq!(
            split(" alice@web01.example.com:2222 "),
            ("web01.example.com".into(), 2222, Some("alice".into()))
        );
        assert_eq!(split("192.0.2.10:2200"), ("192.0.2.10".into(), 2200, None));
        assert_eq!(split("[2001:db8::1]:2222"), ("[2001:db8::1]".into(), 2222, None));
        assert_eq!(split("2001:db8::1"), ("2001:db8::1".into(), 22, None));
        assert_eq!(
            split("bob@[2001:db8::1]"),
            ("[2001:db8::1]".into(), 22, Some("bob".into()))
        );
        // The port and user fields win over what was typed in the host.
        assert_eq!(
            split_target("alice@web01.example.com:2222", Some(22), Some("bob")).unwrap(),
            ("web01.example.com".into(), 22, Some("bob".into()))
        );
        assert!(split_target("web01.example.com:0", None, None).is_err());
        assert!(split_target("web01.example.com:ssh", None, None).is_err());
        assert!(split_target("[2001:db8::1", None, None).is_err());
    }

    fn request(auth: SessionAuth, password: Option<&str>) -> QuickConnect {
        QuickConnect {
            host: "alice@192.0.2.10".into(),
            port: None,
            username: None,
            auth,
            password: password.map(SecretString::new),
            save: None,
        }
    }

    #[test]
    fn a_typed_password_goes_with_a_password_login_and_no_vault_item() {
        let ok = request(SessionAuth::Password { password_id: None }, Some("typed"));
        let input = ok.input().unwrap();
        assert_eq!(input.host, "192.0.2.10");
        assert_eq!(input.username.as_deref(), Some("alice"));
        assert!(ok.typed_password().is_some());
        let both = request(
            SessionAuth::Password {
                password_id: Some(crate::vault::SecretId(Uuid::new_v4())),
            },
            Some("typed"),
        );
        assert!(both.input().is_err());
        assert!(request(SessionAuth::Agent, Some("typed")).input().is_err());
        // An empty field is no password.
        assert!(request(SessionAuth::Agent, Some("")).input().is_ok());
        assert!(request(SessionAuth::Agent, Some("")).typed_password().is_none());
    }

    #[test]
    fn the_request_never_prints_the_typed_password() {
        let secret = format!("pw-{}", Uuid::new_v4().simple());
        let req = request(SessionAuth::Password { password_id: None }, Some(&secret));
        assert!(!format!("{req:?}").contains(&secret));
    }
}
