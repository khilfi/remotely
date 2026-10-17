//! Remote adapter: SSH to any reachable machine, via russh.
//!
//! Covers SS-03 (interactive terminal), BX-02 (bulk exec), BX-07 (sudo from the vault, never echoed
//! or logged), MO-02 (guest metrics from /proc) and SS-05 (block on a changed host key). Jump hosts
//! (SS-07) chain through russh's direct-tcpip channels.
//!
//! This is a stub: [`RusshAdapter`] holds the client config but does not connect yet.
//! [`loopback_shell`] stands in for a remote shell so the terminal wiring can be tested end to end.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::domain::Environment;
use crate::error::{CoreError, Result};
use crate::vault::{SecretId, SecretString};

/// A saved session, as the remote adapter needs it (SS-01).
#[derive(Debug, Clone)]
pub struct SessionSpec {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    pub jump: Option<Box<SessionSpec>>,
    pub environment: Environment,
}

#[derive(Debug, Clone)]
pub enum AuthMethod {
    Password(SecretId),
    PrivateKey {
        key: SecretId,
        passphrase: Option<SecretId>,
    },
    Agent,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecResult {
    pub exit_code: Option<u32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// Input to an interactive shell.
#[derive(Debug)]
pub enum ShellInput {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Close,
}

/// Both ends of an interactive shell: send keystrokes in, read terminal output.
pub struct ShellHandle {
    pub input: mpsc::Sender<ShellInput>,
    pub output: mpsc::Receiver<Vec<u8>>,
}

#[async_trait]
pub trait RemoteAdapter: Send + Sync {
    /// Runs a command or script and collects its output (BX-02). `sudo_password` comes from the vault.
    async fn exec(
        &self,
        session: &SessionSpec,
        script: &str,
        sudo_password: Option<&SecretString>,
    ) -> Result<ExecResult>;

    /// Opens an interactive PTY shell (SS-03).
    async fn open_shell(&self, session: &SessionSpec, cols: u16, rows: u16) -> Result<ShellHandle>;
}

pub struct RusshAdapter {
    #[allow(dead_code)] // used once connect() lands
    config: Arc<russh::client::Config>,
}

impl RusshAdapter {
    pub fn new() -> Self {
        let config = russh::client::Config {
            keepalive_interval: Some(Duration::from_secs(30)),
            inactivity_timeout: None,
            ..Default::default()
        };
        Self {
            config: Arc::new(config),
        }
    }
}

impl Default for RusshAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RemoteAdapter for RusshAdapter {
    async fn exec(&self, _: &SessionSpec, _: &str, _: Option<&SecretString>) -> Result<ExecResult> {
        Err(CoreError::NotImplemented("BX-02 remote exec over SSH"))
    }

    async fn open_shell(&self, _: &SessionSpec, _: u16, _: u16) -> Result<ShellHandle> {
        Err(CoreError::NotImplemented("SS-03 SSH terminal"))
    }
}

/// A fake shell that echoes what you type, so xterm.js <-> IPC <-> core can be tested before SSH.
pub fn loopback_shell() -> ShellHandle {
    let (input_tx, mut input_rx) = mpsc::channel::<ShellInput>(64);
    let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>(64);

    tokio::spawn(async move {
        const PROMPT: &[u8] = b"\x1b[32mloopback\x1b[0m$ ";
        let banner = b"\x1b[1mRemotely\x1b[0m terminal (loopback: SSH arrives with SS-03)\r\n\r\n";
        if output_tx.send([banner.as_slice(), PROMPT].concat()).await.is_err() {
            return;
        }
        let mut line = String::new();
        while let Some(msg) = input_rx.recv().await {
            let reply: Vec<u8> = match msg {
                ShellInput::Close => break,
                ShellInput::Resize { .. } => continue,
                ShellInput::Data(bytes) => {
                    let mut out = Vec::new();
                    for ch in String::from_utf8_lossy(&bytes).chars() {
                        match ch {
                            '\r' => {
                                out.extend_from_slice(b"\r\n");
                                if !line.trim().is_empty() {
                                    out.extend_from_slice(
                                        format!("not connected: `{}` was not sent anywhere\r\n", line.trim())
                                            .as_bytes(),
                                    );
                                }
                                out.extend_from_slice(PROMPT);
                                line.clear();
                            }
                            '\u{7f}' | '\u{8}' => {
                                if line.pop().is_some() {
                                    out.extend_from_slice(b"\x08 \x08");
                                }
                            }
                            c if c.is_control() => {}
                            c => {
                                line.push(c);
                                let mut buf = [0u8; 4];
                                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                            }
                        }
                    }
                    out
                }
            };
            if !reply.is_empty() && output_tx.send(reply).await.is_err() {
                break;
            }
        }
    });

    ShellHandle {
        input: input_tx,
        output: output_rx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_shell_echoes_input() {
        let mut shell = loopback_shell();
        let banner = shell.output.recv().await.unwrap();
        assert!(String::from_utf8_lossy(&banner).contains("loopback"));

        shell.input.send(ShellInput::Data(b"ls".to_vec())).await.unwrap();
        assert_eq!(shell.output.recv().await.unwrap(), b"ls");

        shell.input.send(ShellInput::Data(b"\r".to_vec())).await.unwrap();
        let reply = String::from_utf8_lossy(&shell.output.recv().await.unwrap()).into_owned();
        assert!(reply.contains("not connected: `ls`"));
    }
}
