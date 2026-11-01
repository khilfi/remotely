//! SS-12, MO-05, MO-13: a WinRS shell on a [`Client`]: create, command, send, receive, signal and delete, and the
//! two ways Remotely runs PowerShell in one:
//!
//! * [`run_script`]: one `powershell.exe -Command -` per run, the script on its stdin, stdin closed, output read
//!   until the command ends (its exit code), then the shell deleted. For host facts, service checks and (F8) bulk runs.
//! * [`Runner`]: one PowerShell kept open on its stdin, each read sent as lines and followed by a marker line, the
//!   output read up to the marker. For the dashboard's rounds every few seconds, so a watched host starts one
//!   PowerShell per connection, not one per round.
//!
//! A Receive waits on the host up to its operation timeout, then the host says "timed out" and Remotely asks again;
//! a host that answers "nothing yet" at once is asked at most every [`MIN_EMPTY_GAP`], and every run has a deadline,
//! so no loop runs on a host that keeps saying "not done".

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::http::Client;
use super::soap::{self, Answer, Header, Received};
use crate::adapters::exec_output::OutputCollector;
use crate::adapters::remote::ExecResult;
use crate::error::{CoreError, Result};
use crate::vault::SecretString;

/// How long a Receive waits on the host for output before it says "timed out" (WinRM's operation timeout).
pub const RECEIVE_WAIT: Duration = Duration::from_secs(20);
/// A Receive that came back empty sooner than this waits out the rest before the next one.
pub const MIN_EMPTY_GAP: Duration = Duration::from_millis(250);
/// Stdin goes in pieces of this many bytes (base64 grows them by a third, inside the envelope's limit).
const SEND_CHUNK: usize = 32 * 1024;
/// The program every PowerShell Remotely starts runs.
pub const POWERSHELL: &str = "powershell.exe";

/// Every WinRS option a shell or command gets: UTF-8 both ways (code page 65001), no user profile loaded.
const SHELL_OPTIONS: [(&str, &str); 2] = [("WINRS_NOPROFILE", "TRUE"), ("WINRS_CODEPAGE", "65001")];

/// One shell on the host.
pub struct RemoteShell {
    client: Arc<Client>,
    id: String,
    timeout: Duration,
    deleted: AtomicBool,
}

impl RemoteShell {
    async fn call(
        &self,
        action: &str,
        shell_id: Option<&str>,
        options: &[(&str, &str)],
        body: &str,
        wait: Duration,
    ) -> Result<Answer> {
        let header = Header {
            to: &self.client.endpoint.url(),
            action,
            shell_id,
            options,
            timeout_secs: wait.as_secs(),
        };
        let xml = soap::envelope(&header, body);
        let answered = self.client.post(&xml, wait + self.timeout).await?;
        soap::read_answer(&answered.body)
    }

    /// A new shell the host closes after `idle` without use.
    pub async fn create(client: Arc<Client>, idle: Duration, timeout: Duration) -> Result<Self> {
        let mut shell = Self {
            client,
            id: String::new(),
            timeout,
            deleted: AtomicBool::new(false),
        };
        match shell
            .call(
                soap::ACTION_CREATE,
                None,
                &SHELL_OPTIONS,
                &soap::create_body(idle.as_secs().max(60)),
                Duration::from_secs(20),
            )
            .await?
        {
            Answer::Body(body) => {
                shell.id = soap::shell_id(&body)?;
                shell.client.shell_opened(&shell.id);
            }
            Answer::Fault(fault) => return Err(fault.to_error("a new shell")),
        }
        Ok(shell)
    }

    /// Starts `program arguments` in the shell: its command id. `through_cmd`: run by `cmd.exe /c` (so `2>&1` and
    /// the like work), else started directly.
    pub async fn command(&self, program: &str, arguments: &str, through_cmd: bool) -> Result<String> {
        let skip = if through_cmd { "FALSE" } else { "TRUE" };
        let options = [("WINRS_CONSOLEMODE_STDIN", "FALSE"), ("WINRS_SKIP_CMD_SHELL", skip)];
        match self
            .call(
                soap::ACTION_COMMAND,
                Some(&self.id),
                &options,
                &soap::command_body(program, arguments),
                Duration::from_secs(20),
            )
            .await?
        {
            Answer::Body(body) => soap::command_id(&body),
            Answer::Fault(fault) => Err(fault.to_error("starting PowerShell")),
        }
    }

    /// Sends `data` to the command's stdin; `end` closes it after.
    pub async fn send(&self, command: &str, data: &[u8], end: bool) -> Result<()> {
        let mut chunks: Vec<&[u8]> = data.chunks(SEND_CHUNK).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        let last = chunks.len() - 1;
        for (i, chunk) in chunks.into_iter().enumerate() {
            let body = soap::send_body(command, chunk, end && i == last);
            if let Answer::Fault(fault) = self
                .call(soap::ACTION_SEND, Some(&self.id), &[], &body, Duration::from_secs(20))
                .await?
            {
                return Err(fault.to_error("what was typed"));
            }
        }
        Ok(())
    }

    /// What the command printed since the last Receive, waiting up to `wait` on the host. "Timed out" is an empty
    /// answer.
    pub async fn receive(&self, command: &str, wait: Duration) -> Result<Received> {
        let options = [("WSMAN_CMDSHELL_OPTION_KEEPALIVE", "TRUE")];
        match self
            .call(
                soap::ACTION_RECEIVE,
                Some(&self.id),
                &options,
                &soap::receive_body(command),
                wait,
            )
            .await?
        {
            Answer::Body(body) => soap::received(&body, command),
            Answer::Fault(fault) if fault.timed_out() => Ok(Received::default()),
            Answer::Fault(fault) => Err(fault.to_error("reading the output")),
        }
    }

    /// Sends `code` ([`soap::SIGNAL_CTRL_C`], [`soap::SIGNAL_TERMINATE`]) to the command.
    pub async fn signal(&self, command: &str, code: &str) -> Result<()> {
        match self
            .call(
                soap::ACTION_SIGNAL,
                Some(&self.id),
                &[],
                &soap::signal_body(command, code),
                Duration::from_secs(10),
            )
            .await?
        {
            Answer::Body(_) => Ok(()),
            Answer::Fault(fault) => Err(fault.to_error("the signal")),
        }
    }

    /// Deletes the shell on the host (and whatever still runs in it). Once.
    /// Deletes the shell on the host, once: also after the client closed (a vault lock, a workspace switch), so what still
    /// ran in it doesn't linger until the host's idle timeout.
    pub async fn delete(&self) {
        if self.deleted.swap(true, Ordering::SeqCst) {
            return;
        }
        self.client.delete_shell(&self.id).await;
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Deletes a shell when what holds it is dropped half way (a caller's time limit, a start that failed), on a task of its
/// own. `.0 = None` keeps it.
pub(super) struct DeleteOnDrop(pub(super) Option<Arc<RemoteShell>>);

impl Drop for DeleteOnDrop {
    fn drop(&mut self) {
        if let Some(shell) = self.0.take() {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move { shell.delete().await });
            }
        }
    }
}

/// Waits out the rest of [`MIN_EMPTY_GAP`] after an empty Receive that came back early.
async fn pace(started: Instant, empty: bool) {
    if empty {
        let spent = started.elapsed();
        if spent < MIN_EMPTY_GAP {
            tokio::time::sleep(MIN_EMPTY_GAP - spent).await;
        }
    }
}

/// Runs `script` in a new `powershell.exe -NoLogo -NoProfile -NonInteractive -Command -`, in a shell of its own that
/// is deleted after. The output is scrubbed of `secrets` and kept up to `max_output` bytes per stream (the rest is
/// read and dropped); the run ends by `deadline`.
pub async fn run_script(
    client: Arc<Client>,
    script: &str,
    secrets: &[SecretString],
    max_output: usize,
    deadline: Duration,
    timeout: Duration,
) -> Result<ExecResult> {
    let started = Instant::now();
    let shell = Arc::new(RemoteShell::create(client, Duration::from_secs(300), timeout).await?);
    let mut cleanup = DeleteOnDrop(Some(Arc::clone(&shell)));
    let command = shell
        .command(POWERSHELL, "-NoLogo -NoProfile -NonInteractive -Command -", false)
        .await?;
    let mut text = script.replace("\r\n", "\n").replace('\n', "\r\n");
    text.push_str("\r\n");
    shell.send(&command, text.as_bytes(), true).await?;
    let refs: Vec<&SecretString> = secrets.iter().collect();
    let mut collector = OutputCollector::new(&refs, max_output);
    let exit = loop {
        let left = deadline.saturating_sub(started.elapsed());
        if left.is_zero() {
            let _ = shell.signal(&command, soap::SIGNAL_TERMINATE).await;
            return Err(CoreError::CommandTimedOut {
                seconds: deadline.as_secs(),
            });
        }
        let asked = Instant::now();
        let got = shell.receive(&command, left.min(RECEIVE_WAIT)).await?;
        let empty = got.stdout.is_empty() && got.stderr.is_empty() && got.done.is_none();
        collector.stdout(&got.stdout);
        collector.stderr(&got.stderr);
        if let Some(code) = got.done {
            break code;
        }
        pace(asked, empty).await;
    };
    cleanup.0 = None;
    shell.delete().await;
    Ok(ExecResult {
        exit_code: exit.map(|c| c as u32),
        signal: None,
        output: collector.finish(),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        peer_ip: None,
    })
}

/// One PowerShell kept open for reads (MO-05): each [`Runner::read`] sends its lines and a marker line of its own, and
/// reads up to that marker. A read that fails, or is dropped half way (its caller's time limit), leaves the runner in an
/// unknown state: the caller drops it, and dropping it stops the PowerShell (its cleanup deletes the shell), so a later
/// read never takes an earlier read's output as its own.
pub struct Runner {
    shell: Arc<RemoteShell>,
    command: String,
    nonce: String,
    /// Reads made: each marker names its read, `@@remotely-end-<nonce>-<n>`.
    reads: u64,
    /// Output after the last marker (none, as reads are one at a time).
    pending: Vec<u8>,
    /// Deletes the shell when the runner is dropped without [`Runner::stop`].
    cleanup: DeleteOnDrop,
}

impl Runner {
    pub async fn start(client: Arc<Client>, idle: Duration, timeout: Duration) -> Result<Self> {
        let shell = Arc::new(RemoteShell::create(client, idle, timeout).await?);
        let cleanup = DeleteOnDrop(Some(Arc::clone(&shell)));
        let command = shell
            .command(POWERSHELL, "-NoLogo -NoProfile -NonInteractive -Command -", false)
            .await?;
        Ok(Self {
            shell,
            command,
            nonce: Uuid::new_v4().simple().to_string(),
            reads: 0,
            pending: Vec::new(),
            cleanup,
        })
    }

    fn marker_prefix(&self) -> String {
        format!("@@remotely-end-{}-", self.nonce)
    }

    /// Runs the lines of `script` (each a statement of its own) and returns what they printed on stdout, up to
    /// `max_output` bytes, within `deadline`. A failure leaves the runner unusable: the caller drops it.
    pub async fn read(&mut self, script: &str, max_output: usize, deadline: Duration) -> Result<String> {
        let started = Instant::now();
        self.reads += 1;
        let marker = format!("{}{}", self.marker_prefix(), self.reads);
        let mut text = String::new();
        for line in script.lines().map(str::trim).filter(|l| !l.is_empty()) {
            text.push_str(line);
            text.push_str("\r\n");
        }
        text.push_str(&format!("[Console]::Out.WriteLine('{marker}')\r\n"));
        self.shell.send(&self.command, text.as_bytes(), false).await?;
        let mut out = std::mem::take(&mut self.pending);
        loop {
            if let Some(at) = find_marker(&out, marker.as_bytes()) {
                let mut rest = out.split_off(at);
                // The marker's own line goes; anything after it waits for the next read.
                let after = rest.split_off(marker.len().min(rest.len()));
                self.pending = after.into_iter().skip_while(|b| matches!(b, b'\r' | b'\n')).collect();
                // Output of an earlier read (one that stopped half way) is not this read's.
                let prefix = self.marker_prefix();
                if let Some(old) = rfind(&out, prefix.as_bytes()) {
                    let line_end = out[old..]
                        .iter()
                        .position(|b| *b == b'\n')
                        .map_or(out.len(), |p| old + p + 1);
                    out.drain(..line_end);
                }
                out.truncate(max_output);
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
            let left = deadline.saturating_sub(started.elapsed());
            if left.is_zero() {
                return Err(CoreError::CommandTimedOut {
                    seconds: deadline.as_secs(),
                });
            }
            let asked = Instant::now();
            let got = self.shell.receive(&self.command, left.min(RECEIVE_WAIT)).await?;
            let empty = got.stdout.is_empty() && got.done.is_none();
            out.extend_from_slice(&got.stdout);
            // Remotely's reads print a few KB: a host that prints far more is not answering them.
            if out.len() > max_output + marker.len() + 64 {
                return Err(CoreError::Winrm(format!(
                    "the host printed more than {} KB for one read",
                    max_output / 1024
                )));
            }
            if got.done.is_some() {
                return Err(CoreError::Winrm("the host's PowerShell ended".into()));
            }
            pace(asked, empty).await;
        }
    }

    /// Ends the PowerShell and deletes its shell.
    pub async fn stop(mut self) {
        self.cleanup.0 = None;
        let _ = self.shell.signal(&self.command, soap::SIGNAL_TERMINATE).await;
        self.shell.delete().await;
    }
}

/// Where `marker` starts as a whole line's text: not followed by another digit (`-1` isn't `-12`).
fn find_marker(haystack: &[u8], marker: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(at) = find(&haystack[from..], marker).map(|p| p + from) {
        let next = haystack.get(at + marker.len());
        if !next.is_some_and(u8::is_ascii_digit) {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// The last place `needle` starts in `haystack`.
fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
