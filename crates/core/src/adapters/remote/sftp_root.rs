//! SS-14: root browsing's SFTP channel: the host's sftp-server started under sudo on an exec channel of the
//! terminal's own connection, so every file operation on it runs as root.
//!
//! The command is fixed ([`root_command`]): `sudo -S` with a random prompt marker (BX-07's way), running `/bin/sh` only
//! to print a ready line on stderr and then `exec` the server, so Remotely knows when sudo let it through before it
//! sends the first SFTP packet. The ready line is `remotely-sftp-ready-<nonce>`, printed from two words, so it never
//! appears in the command itself, nor in what sudo says about the command when it refuses it: only a whole line of
//! exactly that counts. Nothing goes on stdin until sudo asks: a host where sudo needs no password (NOPASSWD, cached
//! credentials) never gets the password, and the server never reads it as protocol. A second prompt means sudo refused
//! the password ([`CoreError::SudoPasswordRefused`]); the channel is closed at once, so sudo's own retries never read
//! SFTP bytes. The password goes once per prompt, from the vault, and never shows: sudo doesn't echo it, and what this
//! module reports of stderr is its first line without the marker and with the password scrubbed.

use std::time::Duration;

use russh::client;
use russh::ChannelMsg;

use super::{sh_quote, Handler};
use crate::error::{CoreError, Result};
use crate::vault::SecretString;

/// The ready line's first word; `-<nonce>` follows it.
pub(crate) const READY: &str = "remotely-sftp-ready";

/// The prompt marker's prefix; a random part follows.
pub(crate) const PROMPT_PREFIX: &str = "remotely-sudo-";

/// How long sudo may take to let the server start.
const START_WAIT: Duration = Duration::from_secs(30);

/// The exec command for `server` with sudo prompting `marker` on stderr, and `/bin/sh` printing the ready line
/// `remotely-sftp-ready-<nonce>` before it becomes the server.
pub(crate) fn root_command(server: &str, marker: &str, nonce: &str) -> String {
    let script = format!("printf '%s-%s\\n' {READY} {nonce} >&2; exec \"$1\"");
    format!(
        "sudo -S -p {} -- /bin/sh -c {} sh {}",
        sh_quote(marker),
        sh_quote(&script),
        sh_quote(server)
    )
}

/// The first line of what sudo said, without the prompt marker or the password, for an error.
fn said(stderr: &[u8], marker: &str, password: Option<&SecretString>) -> String {
    let mut text = String::from_utf8_lossy(stderr).replace(marker, "");
    if let Some(password) = password.filter(|p| !p.expose().is_empty()) {
        text = text.replace(password.expose(), "[password]");
    }
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

/// What happened once the command ended (or the channel closed) before the ready line.
fn ended(stderr: &[u8], marker: &str, prompts: usize, server: &str, password: Option<&SecretString>) -> CoreError {
    let text = String::from_utf8_lossy(stderr);
    if prompts >= 2 || text.contains("incorrect password attempt") || text.contains("Sorry, try again.") {
        return CoreError::SudoPasswordRefused;
    }
    let line = said(stderr, marker, password);
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

/// Whether stderr holds the ready line as a whole line of its own. sudo -S ends no line after its prompt (it reads the
/// password from stdin, with no terminal to echo a line break to), so the prompt marker counts as a line break.
fn ready(stderr: &[u8], marker: &str, line: &str) -> bool {
    String::from_utf8_lossy(stderr)
        .replace(marker, "\n")
        .split('\n')
        .any(|l| l.trim_end_matches('\r') == line)
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
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let ready_line = format!("{READY}-{nonce}");
    channel
        .exec(true, root_command(server, &marker, &nonce).into_bytes())
        .await
        .map_err(|err| CoreError::Sftp(format!("asking the host for sudo failed: {err}")))?;
    let started = tokio::time::timeout(START_WAIT, async {
        let mut stderr: Vec<u8> = Vec::new();
        let mut answered = 0usize;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    stderr.extend_from_slice(&data);
                    if ready(&stderr, &marker, &ready_line) {
                        return Ok(answered > 0);
                    }
                    let prompts = String::from_utf8_lossy(&stderr).matches(&marker).count();
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
                        return Err(ended(&stderr, &marker, answered, server, password));
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
                    return Err(ended(&stderr, &marker, answered, server, password));
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
        let command = root_command("/usr/lib/openssh/sftp-server", "remotely-sudo-abc", "n0nce");
        assert_eq!(
            command,
            "sudo -S -p 'remotely-sudo-abc' -- /bin/sh -c 'printf '\\''%s-%s\\n'\\'' remotely-sftp-ready n0nce >&2; \
             exec \"$1\"' sh '/usr/lib/openssh/sftp-server'"
        );
        assert!(
            !command.contains("remotely-sftp-ready-n0nce"),
            "the ready line is never in the command"
        );
    }

    #[test]
    fn only_the_ready_line_on_its_own_counts() {
        let (marker, line) = ("remotely-sudo-abc", "remotely-sftp-ready-n0nce");
        // Right after the prompt (sudo -S ends no line there), or after a lecture.
        assert!(ready(b"remotely-sudo-abcremotely-sftp-ready-n0nce\n", marker, line));
        assert!(ready(
            b"We trust you have received the usual lecture.\nremotely-sftp-ready-n0nce\n",
            marker,
            line
        ));
        // sudo quoting the command it refuses names both words, never the line.
        let refused = b"Sorry, user alice is not allowed to execute '/bin/sh -c printf %s-%s\\n remotely-sftp-ready \
n0nce >&2; exec \"$1\" sh /usr/lib/openssh/sftp-server' as root on web01.\n";
        assert!(!ready(refused, marker, line));
        assert!(
            !ready(b"xx remotely-sftp-ready-n0nce\n", marker, line),
            "a whole line only"
        );
        assert!(!ready(
            b"remotely-sudo-abcremotely-sftp-ready-n0nce-and-more\n",
            marker,
            line
        ));
    }

    #[test]
    fn a_second_prompt_or_sudos_words_mean_refused_and_the_password_never_shows() {
        let marker = "remotely-sudo-abc";
        assert!(matches!(
            ended(
                b"remotely-sudo-abcSorry, try again.\nremotely-sudo-abc",
                marker,
                2,
                "/x",
                None
            ),
            CoreError::SudoPasswordRefused
        ));
        assert!(matches!(
            ended(b"sudo: 1 incorrect password attempt\n", marker, 1, "/x", None),
            CoreError::SudoPasswordRefused
        ));
        let not_allowed = ended(b"alice is not in the sudoers file.\n", marker, 0, "/x", None).to_string();
        assert!(not_allowed.contains("doesn't let the login user"), "{not_allowed}");
        let other = ended(b"remotely-sudo-abc\nsh: 1: /x: not found\n", marker, 1, "/x", None).to_string();
        assert!(other.ends_with("sh: 1: /x: not found"), "{other}");
        assert!(!other.contains(marker));
        let password = SecretString::new("hunter2-secret");
        let echoed = ended(b"pam: bad hunter2-secret\n", marker, 1, "/x", Some(&password)).to_string();
        assert!(
            !echoed.contains("hunter2-secret") && echoed.contains("[password]"),
            "{echoed}"
        );
    }
}
