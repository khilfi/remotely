//! SS-12 consoles: what a session that is not SSH opens.
//!
//! * **Telnet** and **serial** sessions open terminal panes like SSH's: the pane's supervisor connects through
//!   [`crate::adapters::telnet`] or [`crate::adapters::serial`] instead of SSH, and gets the same input and output
//!   channels, so its logs and saved output are scrubbed of secrets, it reconnects and it alerts like an SSH pane.
//!   Neither has SFTP, tunnels, the folder hook or a startup command, and neither joins Type in all tabs or Compare
//!   hosts ([`PaneKind::joins_multiexec`]). A COM port has one pane at a time. A vault password typed into a Telnet
//!   pane asks for the vault password again on each connection, since Telnet sends it in clear text.
//! * **RDP** and **VNC** sessions open a window of another program ([`Terminals::open_window`]): `mstsc.exe` on a
//!   `.rdp` file ([`rdp_file`]) or the owner's VNC viewer, each asking for the password itself. Audited
//!   `rdp_opened` and `vnc_opened`, as opening a terminal is.
//! * Behind a jump host, an RDP or VNC session opens a **tunnel tab** instead ([`PaneKind::Tunnel`]): a terminal to
//!   the jump host (so its host key and login are asked as for any terminal) whose first connection opens an SS-07
//!   local forward to the session's host and port through the command bus (`Command::OpenTunnel`, at its own tier;
//!   rated as the more sensitive of the two sessions). Once it listens, the window opens on `127.0.0.1` and that
//!   port; when the window closes, the tab closes, and the tunnel with it. The forward keeps its port across the
//!   tab's reconnects, so mstsc's own reconnect finds it again.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::{oneshot, watch};
use uuid::Uuid;

use super::{audit, Control, NewPane, PaneKindInfo, Source, TerminalEvent, TerminalHandle, Terminals};
use crate::adapters::launcher::{locate_vnc_viewer, ConsoleLauncher, Launch, LaunchedWindow, Viewer};
use crate::adapters::remote::forward::{ForwardKind, ForwardSpec, RemoteForwards, RunningForward};
use crate::adapters::remote::{
    PtySize, RemoteEntry, RemoteFiles, RemoteListing, RemoteRead, RemoteWrite, ShellHandle, ShellInput, ShellOutput,
};
use crate::adapters::serial::{ComPort, SerialPorts};
use crate::adapters::winrm::{WinrmAdapter, WinrmTuning};
use crate::domain::{Context, Environment, Target, TargetRef};
use crate::error::{CoreError, Result};
use crate::forwards::PortForward;
use crate::known_hosts::address;
use crate::locks;
use crate::sessions::kinds::{RdpOptions, RdpScreen};
use crate::sessions::{SessionKind, SessionRecord};

/// SS-12: the setting that names the VNC viewer (this PC's: `settings::MACHINE_KEYS`).
pub const VNC_VIEWER_PATH_KEY: &str = "consoles.vncViewerPath";

/// What a terminal pane is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PaneKind {
    Ssh,
    Telnet,
    Serial,
    /// An SSH connection to a jump host that carries an RDP or VNC session's tunnel.
    Tunnel,
    /// F4: a WinRM session's PowerShell console.
    Powershell,
}

impl PaneKind {
    pub fn label(self) -> &'static str {
        match self {
            PaneKind::Ssh => "SSH",
            PaneKind::Telnet => "Telnet",
            PaneKind::Serial => "serial",
            PaneKind::Tunnel => "tunnel",
            PaneKind::Powershell => "PowerShell",
        }
    }

    /// Type in all tabs and Compare hosts are for shells: SSH panes, and (BX-13) PowerShell panes, whose lines the
    /// PowerShell rules rate. Never both kinds at once in Type in all tabs ([`super::multiexec`]).
    pub fn joins_multiexec(self) -> bool {
        matches!(self, PaneKind::Ssh | PaneKind::Powershell)
    }

    /// The pane's connection is SSH (SFTP, tunnels, exec channels).
    pub(crate) fn is_ssh(self) -> bool {
        matches!(self, PaneKind::Ssh | PaneKind::Tunnel)
    }
}

/// SS-12: where a tunnel tab's window is, for the tab's banner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum WindowState {
    /// The tunnel isn't open yet (connecting, or waiting for its approval).
    Waiting,
    /// The window is open, on this PC's `at`.
    Open { at: String },
    /// The window could not be started.
    Failed { message: String },
}

/// SS-12: a tunnel tab's RDP or VNC session and its forward.
pub(super) struct Carrier {
    /// The RDP or VNC session, as it was when the tab opened.
    pub(super) session: SessionRecord,
    /// Its forward (one id for the tab's life), with the port it got once it first listened.
    pub(super) forward: Mutex<PortForward>,
    /// Where the forward listens, once it does.
    pub(super) listening: watch::Sender<Option<String>>,
    pub(super) launched: AtomicBool,
}

impl Carrier {
    pub(super) fn forward(&self) -> PortForward {
        locks::lock(&self.forward).clone()
    }

    /// The forward listens at `at` (`127.0.0.1:50123`): it keeps that port from now on, and the window may open.
    pub(super) fn listening_at(&self, at: &str) {
        if let Some(port) = at.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()) {
            locks::lock(&self.forward).spec.bind_port = port;
        }
        let _ = self.listening.send(Some(at.to_owned()));
    }
}

/// What [`Terminals::open_window`] started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowOpened {
    /// `rdp` or `vnc`.
    pub protocol: String,
    /// Where the window connects.
    pub address: String,
}

/// The higher of two labels (Prod over Staging over Lab over none).
fn higher(a: Environment, b: Environment) -> Environment {
    let rank = |e: Environment| match e {
        Environment::None => 0,
        Environment::Lab => 1,
        Environment::Staging => 2,
        Environment::Prod => 3,
    };
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

/// The `.rdp` file for a session: where it connects, who as (mstsc asks for the password: the file holds none and
/// always asks), the screen and what is shared. `host` and `port` are the tunnel's when there is one.
pub fn rdp_file(host: &str, port: u16, username: Option<&str>, o: &RdpOptions) -> String {
    let flag = |on: bool| if on { 1 } else { 0 };
    let mut lines = vec![format!("full address:s:{}", address(host, port))];
    if let Some(user) = username.filter(|u| !u.is_empty()) {
        lines.push(format!("username:s:{user}"));
    }
    lines.push("prompt for credentials:i:1".into());
    match o.screen {
        RdpScreen::Full => {
            lines.push("screen mode id:i:2".into());
            lines.push("use multimon:i:0".into());
        }
        RdpScreen::AllMonitors => {
            lines.push("screen mode id:i:2".into());
            lines.push("use multimon:i:1".into());
        }
        RdpScreen::Window { width, height } => {
            lines.push("screen mode id:i:1".into());
            lines.push("use multimon:i:0".into());
            lines.push(format!("desktopwidth:i:{width}"));
            lines.push(format!("desktopheight:i:{height}"));
        }
    }
    lines.push(format!("redirectclipboard:i:{}", flag(o.clipboard)));
    lines.push(format!("redirectdrives:i:{}", flag(o.drives)));
    lines.push(format!("drivestoredirect:s:{}", if o.drives { "*" } else { "" }));
    lines.push(format!("redirectprinters:i:{}", flag(o.printers)));
    lines.push("redirectcomports:i:0".into());
    // 0: played on this PC; 2: not played at all.
    lines.push(format!("audiomode:i:{}", if o.audio { 0 } else { 2 }));
    lines.push("audiocapturemode:i:0".into());
    lines.push(format!("administrative session:i:{}", flag(o.admin)));
    // Warn when the host can't prove who it is, and use Network Level Authentication.
    lines.push("authentication level:i:2".into());
    lines.push("enablecredsspsupport:i:1".into());
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// SS-12: a console pane has no files over SFTP.
pub(super) struct NoFiles;

fn no_files() -> CoreError {
    CoreError::Sftp("this terminal has no file transfers: only SSH terminals do".into())
}

#[async_trait]
impl RemoteFiles for NoFiles {
    fn user(&self) -> String {
        String::new()
    }
    async fn home(&self) -> Result<String> {
        Err(no_files())
    }
    async fn list(&self, _folder: &str) -> Result<RemoteListing> {
        Err(no_files())
    }
    async fn stat(&self, _path: &str) -> Result<Option<RemoteEntry>> {
        Err(no_files())
    }
    async fn read(&self, _path: &str) -> Result<Box<dyn RemoteRead>> {
        Err(no_files())
    }
    async fn write(&self, _path: &str, _replace: bool) -> Result<Box<dyn RemoteWrite>> {
        Err(no_files())
    }
    async fn remove(&self, _path: &str) -> Result<()> {
        Err(no_files())
    }
}

/// SS-12: a console pane has no port forwards.
pub(super) struct NoForwards;

#[async_trait]
impl RemoteForwards for NoForwards {
    async fn start(&self, _spec: &ForwardSpec) -> Result<RunningForward> {
        Err(CoreError::Tunnel("only SSH terminals have tunnels".into()))
    }
}

/// A console's channels as a shell handle: no files, no forwards, no exec channels; the hostname and shell probes
/// answer nothing.
pub(super) fn console_handle(
    input: tokio::sync::mpsc::Sender<ShellInput>,
    output: tokio::sync::mpsc::Receiver<ShellOutput>,
    peer_ip: Option<IpAddr>,
) -> ShellHandle {
    let (hostname_tx, hostname) = oneshot::channel();
    let (shell_tx, shell) = oneshot::channel();
    let _ = hostname_tx.send(None);
    let _ = shell_tx.send(None);
    ShellHandle {
        input,
        output,
        peer_ip,
        hostname,
        shell,
        files: Arc::new(NoFiles),
        forwards: Arc::new(NoForwards),
        commands: None,
    }
}

impl Terminals {
    /// SS-12: what starts RDP and VNC windows (tests: [`crate::fakes::FakeLauncher`]).
    pub fn set_launcher(&self, launcher: Arc<dyn ConsoleLauncher>) {
        *locks::write(&self.inner.launcher) = launcher;
    }

    /// SS-12: this PC's COM ports (tests: [`crate::fakes::FakeSerialPorts`]).
    pub fn set_serial_ports(&self, ports: Arc<dyn SerialPorts>) {
        *locks::write(&self.inner.serial) = ports;
    }

    pub(super) fn serial(&self) -> Arc<dyn SerialPorts> {
        Arc::clone(&locks::read(&self.inner.serial))
    }

    /// F4: the WinRM client PowerShell panes connect with (Core sets the real one; tests use the fake server).
    pub fn set_winrm(&self, adapter: Arc<dyn WinrmAdapter>) {
        *locks::write(&self.inner.winrm) = adapter;
    }

    pub(super) fn winrm(&self) -> Arc<dyn WinrmAdapter> {
        Arc::clone(&locks::read(&self.inner.winrm))
    }

    /// F4: WinRM's time limits for panes (tests shorten them).
    pub fn set_winrm_tuning(&self, tuning: WinrmTuning) {
        *locks::lock(&self.inner.winrm_tuning) = tuning;
    }

    fn launcher(&self) -> Arc<dyn ConsoleLauncher> {
        Arc::clone(&locks::read(&self.inner.launcher))
    }

    /// SS-12: this PC's COM ports, for the session editor. A read: not audited.
    pub async fn serial_ports(&self) -> Result<Vec<ComPort>> {
        let ports = self.serial();
        tokio::task::spawn_blocking(move || ports.list())
            .await
            .map_err(|err| CoreError::SerialPort(format!("the COM ports could not be listed: {err}")))?
    }

    /// SS-12: the VNC viewer in use: the one saved in Settings, `REMOTELY_VNC_VIEWER`, or a default folder's.
    pub async fn vnc_viewer(&self, ctx: &Context) -> Result<Option<PathBuf>> {
        let saved = self.saved_vnc_viewer(ctx).await?;
        Ok(locate_vnc_viewer(saved.as_deref()))
    }

    /// SS-12: the VNC viewer saved in Settings, if any.
    pub async fn saved_vnc_viewer(&self, ctx: &Context) -> Result<Option<PathBuf>> {
        let saved = self
            .inner
            .store
            .get_setting::<Option<String>>(ctx, VNC_VIEWER_PATH_KEY)
            .await?;
        Ok(saved.flatten().map(PathBuf::from))
    }

    /// SS-12: sends a break on a serial pane's line (Telnet's IAC BRK on a Telnet pane). A break can halt a running
    /// console (a Cisco router drops to ROMMON, a SPARC to its OpenBoot prompt), so on a Prod or protected session it
    /// needs `confirmed` (the UI asks first). No tier; audited (`terminal_break_sent`). Refused while not connected.
    pub async fn send_break(&self, ctx: &Context, id: Uuid, confirmed: bool) -> Result<()> {
        let control = self
            .control(id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {id} has closed")))?;
        if !matches!(control.kind, PaneKind::Serial | PaneKind::Telnet) {
            return Err(CoreError::InvalidInput(
                "Send Break is for serial and Telnet terminals.".into(),
            ));
        }
        if !control.screen().connected {
            return Err(CoreError::InvalidInput(format!(
                "{} is not connected, so no break was sent.",
                super::quoted_name(&control)
            )));
        }
        let target = self.target(ctx, id).await?;
        let sensitive = target.environment == Environment::Prod || target.protected;
        if sensitive && !confirmed {
            return Err(CoreError::InvalidInput(format!(
                "{} is {}, and a break can halt a running console: confirm it first.",
                super::quoted_name(&control),
                if target.protected { "protected" } else { "Prod" }
            )));
        }
        let mut detail = match control.kind {
            PaneKind::Serial => format!(
                "a break on {} ({} ms)",
                control.serial_port.as_deref().unwrap_or("the line"),
                crate::adapters::serial::BREAK_LENGTH.as_millis()
            ),
            _ => "Telnet's break (IAC BRK)".to_owned(),
        };
        if sensitive {
            detail.push_str("; confirmed first");
        }
        audit(
            &self.inner.store,
            ctx,
            "terminal_break_sent",
            &format!("Sent a break to {}", super::quoted_name(&control)),
            control.targets(),
            &detail,
        )
        .await?;
        control
            .input
            .send(super::TerminalInput::Break)
            .await
            .map_err(|_| CoreError::UnknownTarget(format!("terminal {id} has closed")))
    }

    /// SS-12: opens an RDP or VNC session's window (`mstsc.exe`, or the VNC viewer), which asks for the password.
    /// Audited `rdp_opened` or `vnc_opened`. A session behind a jump host opens in a tunnel tab instead
    /// ([`Terminals::open`]).
    pub async fn open_window(&self, ctx: &Context, session_id: Uuid) -> Result<WindowOpened> {
        self.inner.vault.note_activity();
        let session = self
            .inner
            .store
            .get_session(ctx, session_id)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("session {session_id}")))?;
        if !session.kind.is_window() {
            return Err(CoreError::WrongSessionKind {
                session: session.name.clone(),
                kind: session.kind.label(),
                needs: "it opens in a terminal tab".into(),
            });
        }
        if session.jump_session_id.is_some() {
            return Err(CoreError::InvalidInput(format!(
                "'{}' goes through a jump host, so it opens in a tab that opens the tunnel first.",
                session.name
            )));
        }
        let window = self
            .launch_window(ctx, &session, &session.host, session.port, None)
            .await?;
        // The window runs on its own; nothing waits for it here.
        tokio::spawn(window.wait());
        if let Err(err) = self.inner.store.record_session_opened(ctx, session_id).await {
            tracing::warn!(error = %err, "could not note when a session was opened");
        }
        Ok(WindowOpened {
            protocol: session.kind.protocol().into(),
            address: address(&session.host, session.port),
        })
    }

    /// Starts the window for `session` at `host` and `port` (the tunnel's, `via` the jump host's name) and audits it.
    async fn launch_window(
        &self,
        ctx: &Context,
        session: &SessionRecord,
        host: &str,
        port: u16,
        via: Option<&str>,
    ) -> Result<Box<dyn LaunchedWindow>> {
        let through = via
            .map(|jump| format!("; through a tunnel to '{jump}', on {}", address(host, port)))
            .unwrap_or_default();
        let (launch, event, action, detail) = match &session.kind {
            SessionKind::Rdp(o) => {
                let file = rdp_file(host, port, session.username.as_deref(), o);
                let user = session
                    .username
                    .as_deref()
                    .map(|u| format!(", as {u}"))
                    .unwrap_or_default();
                let what = session.kind.describe().unwrap_or_default();
                (
                    Launch::Rdp {
                        name: session.name.clone(),
                        file,
                    },
                    "rdp_opened",
                    format!("Opened the remote desktop of '{}'", session.name),
                    format!(
                        "{}{user}; {what}; mstsc asks for the password{through}",
                        address(&session.host, session.port)
                    ),
                )
            }
            SessionKind::Vnc(o) => {
                let exe = self.vnc_viewer(ctx).await?.ok_or(CoreError::VncViewerNotFound)?;
                let args = Viewer::of(&exe).args(host, port, o.view_only);
                let view = if o.view_only { ", view only" } else { "" };
                let detail = format!(
                    "{}{view}, with {}; the viewer asks for the password; many VNC servers don't encrypt{through}",
                    address(&session.host, session.port),
                    exe.display()
                );
                (
                    Launch::Viewer { exe, args },
                    "vnc_opened",
                    format!("Opened the VNC viewer to '{}'", session.name),
                    detail,
                )
            }
            _ => {
                return Err(CoreError::WrongSessionKind {
                    session: session.name.clone(),
                    kind: session.kind.label(),
                    needs: "it opens in a terminal tab".into(),
                })
            }
        };
        // Rule 4: audited before it starts (as a terminal is before it connects), so no window opens unrecorded; one
        // that doesn't start gets a second entry saying why.
        let target = session.target();
        let targets = std::slice::from_ref(&target);
        audit(&self.inner.store, ctx, event, &action, targets, &detail).await?;
        match self.launcher().launch(launch).await {
            Ok(window) => Ok(window),
            Err(err) => {
                let failed = format!("{action}: it did not start");
                if let Err(audit_err) = super::audit_entry_result(
                    &self.inner.store,
                    ctx,
                    event,
                    &failed,
                    targets,
                    &err.to_string(),
                    "failed",
                )
                .await
                {
                    tracing::error!(error = %audit_err, "could not audit a window that did not start");
                }
                Err(err)
            }
        }
    }

    /// SS-12: a Telnet or serial session's pane. One pane per COM port.
    pub(super) async fn open_console(
        &self,
        ctx: &Context,
        session: SessionRecord,
        kind: PaneKind,
        size: PtySize,
    ) -> Result<TerminalHandle> {
        let serial_port = (kind == PaneKind::Serial).then(|| session.host.clone());
        if let Some(port) = &serial_port {
            let taken = locks::lock(&self.inner.open)
                .values()
                .any(|c| c.serial_port.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(port)));
            if taken {
                return Err(CoreError::SerialPort(format!(
                    "{port} is open in another tab already: a COM port has one tab at a time"
                )));
            }
        }
        let (_, environment, protected) = self.inner.store.find_session_target(ctx, session.id).await?.unwrap_or((
            session.name.clone(),
            session.environment,
            session.protected,
        ));
        let target = Target {
            target: TargetRef::Session { session_id: session.id },
            name: session.name.clone(),
            environment,
            protected,
        };
        let what = session.kind.describe().unwrap_or_default();
        let (action, detail) = match kind {
            PaneKind::Telnet => (
                format!("Opened a Telnet terminal to '{}'", session.name),
                format!("{}; {what}; clear text", session.address()),
            ),
            PaneKind::Powershell => (
                format!("Opened a PowerShell console to '{}'", session.name),
                format!("{}; {what}", session.address()),
            ),
            _ => (
                format!("Opened a serial terminal to '{}'", session.name),
                format!("{}; {what}", session.address()),
            ),
        };
        let pane = NewPane {
            source: Source::Saved(session.id),
            target: Some(target),
            name: session.name.clone(),
            remembered: None,
            jump_passwords: Default::default(),
            action,
            detail,
            container: None,
            kind: PaneKindInfo {
                kind,
                carrier: None,
                serial_port,
            },
        };
        let handle = self.start(ctx, pane, size).await?;
        if let Err(err) = self.inner.store.record_session_opened(ctx, session.id).await {
            tracing::warn!(error = %err, "could not note when a session was opened");
        }
        Ok(handle)
    }

    /// SS-12: an RDP or VNC session behind a jump host: a tunnel tab to the jump host, whose first connection opens
    /// the forward and then the window.
    pub(super) async fn open_tunnel_tab(
        &self,
        ctx: &Context,
        session: SessionRecord,
        size: PtySize,
    ) -> Result<TerminalHandle> {
        let jump = session.jump_session_id.ok_or_else(|| {
            CoreError::InvalidInput(format!(
                "'{}' has no jump host, so its window opens directly.",
                session.name
            ))
        })?;
        let spec = self
            .inner
            .store
            .session_spec(ctx, jump)
            .await?
            .ok_or_else(|| CoreError::UnknownTarget(format!("the jump host of '{}'", session.name)))?;
        let (_, jump_env, jump_protected) = self.inner.store.find_session_target(ctx, jump).await?.unwrap_or((
            spec.name.clone(),
            spec.environment,
            false,
        ));
        let (_, env, protected) = self.inner.store.find_session_target(ctx, session.id).await?.unwrap_or((
            session.name.clone(),
            session.environment,
            session.protected,
        ));
        // The tunnel is rated as the more sensitive of the two: it reaches the session's host.
        let target = Target {
            target: TargetRef::Session { session_id: jump },
            name: spec.name.clone(),
            environment: higher(env, jump_env),
            protected: protected || jump_protected,
        };
        let forward = PortForward {
            id: Uuid::new_v4(),
            session_id: jump,
            label: Some(match session.kind {
                SessionKind::Rdp(_) => format!("remote desktop of '{}'", session.name),
                _ => format!("VNC of '{}'", session.name),
            }),
            spec: ForwardSpec {
                kind: ForwardKind::Local,
                bind_address: "127.0.0.1".into(),
                bind_port: 0,
                dest_host: session.host.clone(),
                dest_port: session.port,
            },
            auto_start: false,
        };
        let window = match session.kind {
            SessionKind::Rdp(_) => "the remote desktop",
            _ => "the VNC viewer",
        };
        let via = spec.route().map(|route| format!(" via {route}")).unwrap_or_default();
        let action = format!(
            "Opened a tunnel tab to '{}' for {window} of '{}'",
            spec.name, session.name
        );
        let detail = format!(
            "{}{via}; a local forward to {} opens on its first connection, then {window}",
            spec.address(),
            address(&session.host, session.port)
        );
        let (listening, mut wait_listening) = watch::channel(None);
        let carrier = Arc::new(Carrier {
            session: session.clone(),
            forward: Mutex::new(forward),
            listening,
            launched: AtomicBool::new(false),
        });
        let pane = NewPane {
            source: Source::Saved(jump),
            target: Some(target),
            name: format!("{} (tunnel for {})", spec.name, session.name),
            remembered: None,
            jump_passwords: Default::default(),
            action,
            detail,
            container: None,
            kind: PaneKindInfo {
                kind: PaneKind::Tunnel,
                carrier: Some(Arc::clone(&carrier)),
                serial_port: None,
            },
        };
        let handle = self.start(ctx, pane, size).await?;
        if let Err(err) = self.inner.store.record_session_opened(ctx, session.id).await {
            tracing::warn!(error = %err, "could not note when a session was opened");
        }
        // Once the tunnel listens, the window opens on it; when the window closes, so does the tab.
        let terminals = self.clone();
        let ctx = *ctx;
        let id = handle.id;
        let jump_name = spec.name.clone();
        tokio::spawn(async move {
            let at = loop {
                if let Some(at) = wait_listening.borrow_and_update().clone() {
                    break at;
                }
                if wait_listening.changed().await.is_err() {
                    // The tab closed first.
                    return;
                }
            };
            if carrier.launched.swap(true, Ordering::SeqCst) {
                return;
            }
            let Some(control) = terminals.control(id) else {
                return;
            };
            let port = at
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .unwrap_or(0);
            let opened = terminals
                .launch_window(&ctx, &carrier.session, "127.0.0.1", port, Some(&jump_name))
                .await;
            match opened {
                Ok(window) => {
                    let _ = control
                        .events
                        .send(TerminalEvent::Window {
                            window: WindowState::Open { at },
                        })
                        .await;
                    drop(control);
                    window.wait().await;
                    terminals.close(id).await;
                }
                Err(err) => {
                    let _ = control
                        .events
                        .send(TerminalEvent::Window {
                            window: WindowState::Failed {
                                message: err.to_string(),
                            },
                        })
                        .await;
                }
            }
        });
        Ok(handle)
    }

    /// SS-12: a tunnel tab's target as it is now: the jump host, with the RDP or VNC session's label and protection
    /// if they are higher.
    pub(super) async fn raise_for_carrier(
        &self,
        ctx: &Context,
        control: &Control,
        mut target: Target,
    ) -> Result<Target> {
        if let Some(carrier) = &control.carrier {
            if let Some((_, env, protected)) = self.inner.store.find_session_target(ctx, carrier.session.id).await? {
                target.environment = higher(target.environment, env);
                target.protected |= protected;
            }
        }
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rdp_file_holds_no_password_and_shares_only_what_was_chosen() {
        let file = rdp_file("win01.example.com", 3389, Some(r"CORP\alice"), &RdpOptions::default());
        assert!(file.contains("full address:s:win01.example.com:3389\n"), "{file}");
        assert!(file.contains("username:s:CORP\\alice\n"));
        assert!(file.contains("prompt for credentials:i:1\n"));
        assert!(file.contains("redirectclipboard:i:1\n"));
        assert!(file.contains("redirectdrives:i:0\n") && file.contains("redirectprinters:i:0\n"));
        assert!(file.contains("audiomode:i:2\n") && file.contains("administrative session:i:0\n"));
        assert!(!file.to_lowercase().contains("password"), "{file}");

        let window = RdpOptions {
            screen: RdpScreen::Window {
                width: 1600,
                height: 900,
            },
            drives: true,
            audio: true,
            admin: true,
            clipboard: false,
            ..RdpOptions::default()
        };
        let file = rdp_file("2001:db8::5", 50123, None, &window);
        assert!(file.contains("full address:s:[2001:db8::5]:50123\n"), "{file}");
        assert!(!file.contains("username:"));
        assert!(file.contains("screen mode id:i:1\n") && file.contains("desktopwidth:i:1600\n"));
        assert!(file.contains("drivestoredirect:s:*\n") && file.contains("audiomode:i:0\n"));
        assert!(file.contains("administrative session:i:1\n") && file.contains("redirectclipboard:i:0\n"));
    }

    #[test]
    fn ssh_and_powershell_panes_join_type_in_all_tabs() {
        assert!(PaneKind::Ssh.joins_multiexec());
        // BX-13.
        assert!(PaneKind::Powershell.joins_multiexec());
        for kind in [PaneKind::Telnet, PaneKind::Serial, PaneKind::Tunnel] {
            assert!(!kind.joins_multiexec(), "{kind:?}");
        }
        assert_eq!(higher(Environment::Lab, Environment::Prod), Environment::Prod);
        assert_eq!(higher(Environment::Staging, Environment::None), Environment::Staging);
    }
}
