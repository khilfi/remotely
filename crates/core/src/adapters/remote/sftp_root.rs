//! SS-14: root browsing's SFTP channel: the host's sftp-server started under sudo on an exec channel of the
//! terminal's own connection, so every file operation on it runs as root.
//!
//! The command is fixed ([`root_command`]): `sudo -S` with a random prompt marker (BX-07's way), running `/bin/sh` only
//! to print a ready marker on stderr and then `exec` the server, so Remotely knows when sudo let it through before it
//! sends the first SFTP packet. Nothing goes on stdin until sudo asks: a host where sudo needs no password (NOPASSWD,
//! cached credentials) never gets the password, and the server never reads it as protocol. A second prompt means sudo
//! refused the password ([`CoreError::SudoPasswordRefused`]); the channel is closed at once, so sudo's own retries
//! never read SFTP bytes. The password goes once per prompt, from the vault, and never shows: sudo doesn't echo it,
//! and what this module reports of stderr is its first line without the marker.

use std::time::Duration;

use russh::client;
use russh::ChannelMsg;

use super::{sh_quote, Handler};
use crate::error::{CoreError, Result};
use crate::vault::SecretString;

/// What `/bin/sh` prints on stderr once sudo let it through, just before it becomes the SFTP server.
pub(crate) const READY: &str = "remotely-sftp-ready";

/// The prompt marker's prefix; a random part follows.
pub(crate) const PROMPT_PREFIX: &str = "remotely-sudo-";

/// How long sudo may take to let the server start.
const START_WAIT: Duration = Duration::from_secs(30);

/// The exec command for `server` with sudo prompting `marker` on stderr.
pub(crate) fn root_command(server: &str, marker: &str) -> String {
    let script = format!("printf '%s\\n' {READY} >&2; exec \"$1\"");
    format!(
        "sudo -S -p {} -- /bin/sh -c {} sh {}",
        sh_quote(marker),
        sh_quote(&script),
        sh_quote(server)
    )
}

/// The first line of what sudo said, without the prompt marker, for an error.
fn said(stderr: &[u8], marker: &str) -> String {
    let text = String::from_utf8_lossy(stderr).replace(marker, "");
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

/// What happened once the command ended (or the channel closed) before the ready marker.
fn ended(stderr: &[u8], marker: &str, prompts: usize, server: &str) -> CoreError {
    let text = String::from_utf8_lossy(stderr);
    if prompts >= 2 || text.contains("incorrect password attempt") || text.contains("Sorry, try again.") {
        return CoreError::SudoPasswordRefused;
    }
    let line = said(stderr, marker);
    if text.contains("not in the sudoers") || text.contains("is not allowed to") {
        return CoreError::Sftp(format!(
            "sudo on the host doesn't let the login user run {server}, so files can't be browsed as root ({line})"
        ));
    }
    if line.is_empty() {
        CoreError::Sftp(format!("sudo did not start the SFTP server {server} on the host"))
    } else {
        CoreError::Sftp(format!(
            "sudo did not start the SFTP server {server} on the host: {line}"
        ))
    }
}

/// Opens an exec channel, gets sudo past its password (if it asks), and hands back the channel's stream with the
/// server on it, and whether sudo took the password (false: it asked for none).
pub(super) async fn open_stream(
    handle: &client::Handle<Handler>,
    server: &str,
    password: Option<&SecretString>,
) -> Result<(russh::ChannelStream<client::Msg>, bool)> {
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|err| CoreError::Sftp(format!("the host did not open a channel for root browsing: {err}")))?;
    let marker = format!("{PROMPT_PREFIX}{}", uuid::Uuid::new_v4().simple());
    channel
        .exec(true, root_command(server, &marker).into_bytes())
        .await
        .map_err(|err| CoreError::Sftp(format!("asking the host for sudo failed: {err}")))?;
    let started = tokio::time::timeout(START_WAIT, async {
        let mut stderr: Vec<u8> = Vec::new();
        let mut answered = 0usize;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    stderr.extend_from_slice(&data);
                    let text = String::from_utf8_lossy(&stderr);
                    if text.contains(READY) {
                        return Ok(answered > 0);
                    }
                    let prompts = text.matches(&marker).count();
                    if prompts > answered {
                        if answered > 0 {
                            // Asked again: the password was refused.
                            return Err(CoreError::SudoPasswordRefused);
                        }
                        let Some(password) = password else {
                            return Err(CoreError::NoSudoPassword(
                                "sudo on the host asks for a password for root browsing. Choose a sudo password \
                                 from the vault, or save the session's login password"
                                    .into(),
                            ));
                        };
                        let mut line = zeroize::Zeroizing::new(password.expose().as_bytes().to_vec());
                        line.push(b'\n');
                        // A failed write shows up as the channel closing.
                        let _ = channel.data(&line[..]).await;
                        answered += 1;
                    }
                    // Keep what is left small: sudo's lecture is all it says before the prompt.
                    if stderr.len() > 64 * 1024 {
                        return Err(ended(&stderr, &marker, answered, server));
                    }
                }
                Some(ChannelMsg::Data { .. }) => {
                    // Nothing comes on stdout before the server starts; something that does isn't sudo.
                    return Err(CoreError::Sftp(format!(
                        "the host printed something before sudo started {server}, so root browsing stopped"
                    )));
                }
                Some(ChannelMsg::Failure) => {
                    return Err(CoreError::Sftp("the host refused to run sudo for root browsing".into()));
                }
                Some(ChannelMsg::ExitStatus { .. } | ChannelMsg::Eof | ChannelMsg::Close) | None => {
                    return Err(ended(&stderr, &marker, answered, server));
                }
                Some(_) => {}
            }
        }
    })
    .await;
    let result = match started {
        Ok(result) => result,
        Err(_) => Err(CoreError::Sftp(format!(
            "sudo did not start {server} within {} s, so root browsing stopped",
            START_WAIT.as_secs()
        ))),
    };
    let took = match result {
        Ok(took) => took,
        Err(err) => {
            let _ = channel.close().await;
            return Err(err);
        }
    };
    Ok((channel.into_stream(), took))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_is_fixed_and_quotes_the_server() {
        let command = root_command("/usr/lib/openssh/sftp-server", "remotely-sudo-abc");
        assert_eq!(
            command,
            "sudo -S -p 'remotely-sudo-abc' -- /bin/sh -c 'printf '\\''%s\\n'\\'' remotely-sftp-ready >&2; exec \"$1\"' \
             sh '/usr/lib/openssh/sftp-server'"
        );
    }

    #[test]
    fn a_second_prompt_or_sudos_words_mean_refused() {
        let marker = "remotely-sudo-abc";
        assert!(matches!(
            ended(
                b"remotely-sudo-abcSorry, try again.\nremotely-sudo-abc",
                marker,
                2,
                "/x"
            ),
            CoreError::SudoPasswordRefused
        ));
        assert!(matches!(
            ended(b"sudo: 1 incorrect password attempt\n", marker, 1, "/x"),
            CoreError::SudoPasswordRefused
        ));
        let not_allowed = ended(b"alice is not in the sudoers file.\n", marker, 0, "/x").to_string();
        assert!(not_allowed.contains("doesn't let the login user"), "{not_allowed}");
        let other = ended(b"remotely-sudo-abc\nsh: 1: /x: not found\n", marker, 1, "/x").to_string();
        assert!(other.ends_with("sh: 1: /x: not found"), "{other}");
        assert!(!other.contains(marker));
    }
}
