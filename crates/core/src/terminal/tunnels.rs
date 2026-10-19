//! SS-07 tunnels: a terminal's port forwards at run time.
//!
//! * The session's saved forwards ([`crate::forwards`]) are listed with each one's state: stopped,
//!   asking for approval, opening, listening (where, and how many connections it carried), waiting
//!   for the terminal to reconnect, or failed with why ([`TerminalEvent::Tunnels`]).
//! * Opening one is a command on the bus ([`Command::OpenTunnel`]): the policy engine rates it (one
//!   only this PC can use is Low, so Medium on a Prod host; a remote one, or one that listens on a
//!   network address, asks first), the UI collects the approval answers, and the job runner opens it
//!   on the terminal's own connection ([`Terminals::open_tunnel`]). Forwards that start with the
//!   terminal go the same way when it first connects, so a Prod session's ask too.
//! * An approved tunnel belongs to its terminal: after a dropped connection it opens again on the next
//!   one without asking again, and it closes with the terminal. Opening and closing are audited with
//!   the session, kind, addresses and ports, never traffic.

use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{audit_entry, human_duration, quoted_name, Control, TerminalEvent, Terminals};
use crate::adapters::remote::forward::ForwardStats;
use crate::command_bus::{ApprovalAnswers, ApprovalRequest, Command, CommandBus, SubmitOutcome};
use crate::domain::{Context, TargetRef};
use crate::error::{CoreError, Result};
use crate::forwards::PortForward;
use crate::locks;
use crate::policy::Tier;
use crate::store::Store;

/// Where a tunnel is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum TunnelState {
    Stopped,
    /// The approval waits for the user's answers ([`Terminals::tunnel_request`]).
    Asking,
    /// Approved (or Low tier); the job runner is opening it.
    Opening,
    Listening {
        /// Where, e.g. `127.0.0.1:8080`, or `localhost:9000 on the host`.
        at: String,
    },
    /// Approved, but the terminal's connection dropped: it opens again once the terminal reconnects.
    Waiting {
        reason: String,
    },
    Failed {
        message: String,
    },
}

/// One tunnel, as the Terminal page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelInfo {
    /// The forward as it runs (while it is open), or as saved.
    pub forward: PortForward,
    pub state: TunnelState,
    /// Connections it carried since it opened.
    pub connections: u64,
    /// Connections open now.
    pub open: u64,
    /// Why the last connection through it failed, e.g. that nothing listens at its destination.
    pub last_error: Option<String>,
    /// Still one of the session's saved forwards.
    pub saved: bool,
    /// The saved forward was edited since this one opened: stop and start it to use the edit.
    pub changed: bool,
}

/// How a start went: opening, or waiting for the approval answers.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum TunnelStart {
    Opening { job_id: Uuid },
    NeedsApproval { request: Box<ApprovalRequest> },
}

/// What the job runner opens: a [`Command::OpenTunnel`] on one terminal.
pub struct TunnelRun<'a> {
    pub ctx: Context,
    pub job_id: Uuid,
    pub tier: Tier,
    pub terminal_id: Uuid,
    pub forward: &'a PortForward,
}

/// The approval a tunnel was opened under: it opens again after a reconnect under the same one.
#[derive(Debug, Clone, Copy)]
struct Approved {
    job_id: Uuid,
    tier: Tier,
}

struct Running {
    stop: CancellationToken,
    stats: Arc<ForwardStats>,
    at: String,
    opened: Instant,
}

struct Entry {
    forward: PortForward,
    state: TunnelState,
    approved: Option<Approved>,
    running: Option<Running>,
    /// The approval waiting for answers.
    request: Option<ApprovalRequest>,
}

impl Entry {
    fn new(forward: PortForward) -> Self {
        Self {
            forward,
            state: TunnelState::Stopped,
            approved: None,
            running: None,
            request: None,
        }
    }

    fn info(&self, saved: Option<&PortForward>) -> TunnelInfo {
        let stats = self.running.as_ref().map(|r| &r.stats);
        let live = !matches!(self.state, TunnelState::Stopped | TunnelState::Failed { .. });
        TunnelInfo {
            forward: match (live, saved) {
                (false, Some(saved)) => saved.clone(),
                _ => self.forward.clone(),
            },
            state: self.state.clone(),
            connections: stats.map_or(0, |s| s.connections()),
            open: stats.map_or(0, |s| s.open()),
            last_error: stats.and_then(|s| s.last_error()),
            saved: saved.is_some(),
            changed: live && saved.is_some_and(|s| s.spec != self.forward.spec),
        }
    }
}

/// A terminal's tunnels.
#[derive(Default)]
pub(super) struct TunnelTable {
    entries: Vec<Entry>,
    /// The forwards that start with the terminal were asked for (at its first connection).
    auto_started: bool,
}

impl TunnelTable {
    fn entry(&mut self, forward: &PortForward) -> &mut Entry {
        let at = match self.entries.iter().position(|e| e.forward.id == forward.id) {
            Some(at) => at,
            None => {
                self.entries.push(Entry::new(forward.clone()));
                self.entries.len() - 1
            }
        };
        &mut self.entries[at]
    }

    fn find(&mut self, id: Uuid) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.forward.id == id)
    }
}

fn closed_terminal(id: Uuid) -> CoreError {
    CoreError::UnknownTarget(format!("terminal {id} has closed"))
}

impl Terminals {
    /// The bus tunnels go through. Set once, when the core is put together.
    pub(crate) fn set_bus(&self, bus: &Arc<CommandBus>) {
        let _ = self.inner.bus.set(Arc::downgrade(bus));
    }

    fn bus(&self) -> Result<Arc<CommandBus>> {
        self.inner
            .bus
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or_else(|| CoreError::InvalidInput("Tunnels are not available: the app is shutting down.".into()))
    }

    /// SS-07: the terminal's tunnels: the session's saved forwards with their state, and any open one
    /// that is no longer saved.
    pub async fn tunnels(&self, ctx: &Context, id: Uuid) -> Result<Vec<TunnelInfo>> {
        let control = self.control(id).ok_or_else(|| closed_terminal(id))?;
        list(&self.inner.store, ctx, &control).await
    }

    /// SS-07: opens one of the session's saved forwards on this terminal's connection, through the
    /// command bus. Low tier opens at once; otherwise the answer carries the approval to show, and
    /// [`Terminals::approve_tunnel`] or [`Terminals::decline_tunnel`] follows.
    pub async fn start_tunnel(&self, ctx: &Context, id: Uuid, forward_id: Uuid) -> Result<TunnelStart> {
        let control = self.control(id).ok_or_else(|| closed_terminal(id))?;
        let Some(session_id) = control.session_id() else {
            return Err(CoreError::InvalidInput(
                "Only saved sessions have port forwards. Save the connection as a session first.".into(),
            ));
        };
        let forward = self
            .inner
            .store
            .forward(ctx, forward_id)
            .await?
            .filter(|f| f.session_id == session_id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("port forward {forward_id}")))?;
        let _ops = control.tunnel_ops.lock().await;
        start(self, ctx, id, &control, session_id, forward).await
    }

    /// SS-07: the approval a tunnel waits for, to show it (e.g. one that starts with the terminal).
    pub fn tunnel_request(&self, id: Uuid, forward_id: Uuid) -> Option<ApprovalRequest> {
        let control = self.control(id)?;
        let mut table = locks::lock(&control.tunnels);
        table.find(forward_id).and_then(|e| e.request.clone())
    }

    /// SS-07: the user's answers to a tunnel's approval. A wrong answer keeps it waiting.
    pub async fn approve_tunnel(
        &self,
        ctx: &Context,
        id: Uuid,
        forward_id: Uuid,
        answers: ApprovalAnswers,
    ) -> Result<Uuid> {
        let control = self.control(id).ok_or_else(|| closed_terminal(id))?;
        let _ops = control.tunnel_ops.lock().await;
        let request = locks::lock(&control.tunnels)
            .find(forward_id)
            .and_then(|e| e.request.as_ref().map(|r| r.id))
            .ok_or_else(|| CoreError::InvalidInput("That tunnel is not waiting for approval.".into()))?;
        let job_id = self.bus()?.approve(request, answers).await?;
        if let Some(entry) = locks::lock(&control.tunnels).find(forward_id) {
            entry.request = None;
            entry.state = TunnelState::Opening;
        }
        emit(&self.inner.store, ctx, &control).await;
        Ok(job_id)
    }

    /// SS-07: the user closed a tunnel's approval without approving it (audited by the bus).
    pub async fn decline_tunnel(&self, ctx: &Context, id: Uuid, forward_id: Uuid) -> Result<()> {
        let control = self.control(id).ok_or_else(|| closed_terminal(id))?;
        let _ops = control.tunnel_ops.lock().await;
        let request = locks::lock(&control.tunnels).find(forward_id).and_then(|e| {
            e.state = TunnelState::Stopped;
            e.request.take()
        });
        if let Some(request) = request {
            self.bus()?.cancel_approval(request.id).await?;
        }
        emit(&self.inner.store, ctx, &control).await;
        Ok(())
    }

    /// SS-07: stops a tunnel (or its approval). It stays stopped after reconnects. Audited when it
    /// was open.
    pub async fn stop_tunnel(&self, ctx: &Context, id: Uuid, forward_id: Uuid) -> Result<()> {
        let control = self.control(id).ok_or_else(|| closed_terminal(id))?;
        let _ops = control.tunnel_ops.lock().await;
        let (stopped, request) = {
            let mut table = locks::lock(&control.tunnels);
            let Some(entry) = table.find(forward_id) else {
                return Ok(());
            };
            entry.state = TunnelState::Stopped;
            let approved = entry.approved.take();
            let stopped = entry
                .running
                .take()
                .map(|running| (entry.forward.clone(), approved, running));
            (stopped, entry.request.take())
        };
        if let Some(request) = request {
            self.bus()?.cancel_approval(request.id).await?;
        }
        if let Some((forward, approved, running)) = stopped {
            running.stop.cancel();
            audit_closed(
                &self.inner.store,
                ctx,
                &control,
                &forward,
                approved,
                &running,
                "stopped by the user",
            )
            .await;
        }
        emit(&self.inner.store, ctx, &control).await;
        Ok(())
    }

    /// SS-07: the job runner's part of [`Command::OpenTunnel`]: opens the forward on the terminal's
    /// connection. Returns where it listens. Audited once it does.
    pub(crate) async fn open_tunnel(&self, run: TunnelRun<'_>) -> Result<String> {
        let id = run.terminal_id;
        let control = self.control(id).ok_or_else(|| closed_terminal(id))?;
        let _ops = control.tunnel_ops.lock().await;
        // Stopped (or declined) while it waited to run: it stays stopped.
        let wanted = locks::lock(&control.tunnels)
            .find(run.forward.id)
            .is_some_and(|e| e.state == TunnelState::Opening);
        if !wanted {
            return Err(CoreError::Cancelled);
        }
        let approved = Approved {
            job_id: run.job_id,
            tier: run.tier,
        };
        let opened = open_on_connection(&self.inner.store, &run.ctx, &control, run.forward, approved, false).await;
        emit(&self.inner.store, &run.ctx, &control).await;
        opened
    }
}

/// Submits the start of one forward (with `control.tunnel_ops` held).
async fn start(
    terminals: &Terminals,
    ctx: &Context,
    id: Uuid,
    control: &Arc<Control>,
    session_id: Uuid,
    forward: PortForward,
) -> Result<TunnelStart> {
    if locks::lock(&control.forwards).is_none() {
        return Err(CoreError::InvalidInput(format!(
            "{} is not connected, and a tunnel opens on its connection. Connect it first.",
            quoted_name(control)
        )));
    }
    let busy = locks::lock(&control.tunnels)
        .find(forward.id)
        .map(|e| e.state.clone())
        .filter(|s| !matches!(s, TunnelState::Stopped | TunnelState::Failed { .. }));
    if let Some(state) = busy {
        let why = match state {
            TunnelState::Asking => "is waiting for approval",
            TunnelState::Opening => "is opening",
            TunnelState::Waiting { .. } => "opens again when the terminal reconnects",
            _ => "is open",
        };
        return Err(CoreError::InvalidInput(format!("That tunnel {why} already.")));
    }
    let bus = terminals.bus()?;
    let command = Command::OpenTunnel {
        targets: vec![TargetRef::Terminal {
            terminal_id: id,
            session_id: Some(session_id),
        }],
        forward: forward.clone(),
    };
    // Marked before submitting: a Low-tier job may run as soon as it is queued.
    {
        let mut table = locks::lock(&control.tunnels);
        let entry = table.entry(&forward);
        entry.forward = forward.clone();
        entry.state = TunnelState::Opening;
        entry.request = None;
    }
    let outcome = bus.submit(ctx, command).await;
    let result = {
        let mut table = locks::lock(&control.tunnels);
        let entry = table.entry(&forward);
        match outcome {
            Ok(SubmitOutcome::Queued { job_id, .. }) => Ok(TunnelStart::Opening { job_id }),
            Ok(SubmitOutcome::NeedsApproval { request }) => {
                entry.state = TunnelState::Asking;
                entry.request = Some(request.clone());
                Ok(TunnelStart::NeedsApproval {
                    request: Box::new(request),
                })
            }
            Err(err) => {
                entry.state = TunnelState::Failed {
                    message: err.to_string(),
                };
                Err(err)
            }
        }
    };
    emit(&terminals.inner.store, ctx, control).await;
    result
}

/// Opens one forward on the terminal's live connection (with `control.tunnel_ops` held) and records
/// how that went. `again`: after a reconnect, under the approval it had.
async fn open_on_connection(
    store: &Store,
    ctx: &Context,
    control: &Control,
    forward: &PortForward,
    approved: Approved,
    again: bool,
) -> Result<String> {
    let live = locks::lock(&control.forwards).clone();
    let opened = match live {
        Some(forwards) => forwards.start(&forward.spec).await,
        None => Err(CoreError::Tunnel(
            "the terminal is not connected, so the tunnel did not open".into(),
        )),
    };
    match opened {
        Ok(running) => {
            let at = running.listening.clone();
            {
                let mut table = locks::lock(&control.tunnels);
                let entry = table.entry(forward);
                entry.forward = forward.clone();
                entry.approved = Some(approved);
                entry.state = TunnelState::Listening { at: at.clone() };
                entry.running = Some(Running {
                    stop: running.stop,
                    stats: running.stats,
                    at: at.clone(),
                    opened: Instant::now(),
                });
            }
            audit_opened(store, ctx, control, forward, approved, &at, again).await;
            Ok(at)
        }
        Err(err) => {
            let mut table = locks::lock(&control.tunnels);
            let entry = table.entry(forward);
            entry.state = TunnelState::Failed {
                message: err.to_string(),
            };
            // A tunnel that failed to open after a reconnect is not opened again by itself.
            entry.approved = None;
            Err(err)
        }
    }
}

/// The terminal (re)connected: tunnels approved for it open again, and at its first connection the
/// session's forwards that start with the terminal are asked for, through the bus.
pub(super) async fn connected(terminals: Terminals, ctx: Context, id: Uuid, control: Arc<Control>) {
    let first = {
        let _ops = control.tunnel_ops.lock().await;
        // Already gone again: what waits keeps waiting for the next connection.
        if locks::lock(&control.forwards).is_none() {
            return;
        }
        let again: Vec<(PortForward, Approved)> = locks::lock(&control.tunnels)
            .entries
            .iter()
            .filter(|e| e.running.is_none() && matches!(e.state, TunnelState::Waiting { .. }))
            .filter_map(|e| e.approved.map(|a| (e.forward.clone(), a)))
            .collect();
        for (forward, approved) in again {
            if let Err(err) = open_on_connection(&terminals.inner.store, &ctx, &control, &forward, approved, true).await
            {
                tracing::warn!(error = %err, "a tunnel did not open again after a reconnect");
            }
        }
        let mut table = locks::lock(&control.tunnels);
        !std::mem::replace(&mut table.auto_started, true)
    };
    emit(&terminals.inner.store, &ctx, &control).await;
    let Some(session_id) = control.session_id().filter(|_| first) else {
        return;
    };
    let saved = match terminals.inner.store.list_forwards(&ctx, session_id).await {
        Ok(saved) => saved,
        Err(err) => {
            tracing::warn!(error = %err, "could not read the session's port forwards");
            return;
        }
    };
    for forward in saved.into_iter().filter(|f| f.auto_start) {
        let _ops = control.tunnel_ops.lock().await;
        // The connection dropped meanwhile: the rest waits for the user.
        if locks::lock(&control.forwards).is_none() {
            break;
        }
        if let Err(err) = start(&terminals, &ctx, id, &control, session_id, forward).await {
            tracing::warn!(error = %err, "a tunnel that starts with the terminal did not start");
        }
    }
}

/// The terminal's connection ended (dropped, or reconnecting): open tunnels close, audited, and
/// wait to open again on the next connection.
pub(super) async fn disconnected(store: &Store, ctx: &Context, control: &Control, reason: &str) {
    let _ops = control.tunnel_ops.lock().await;
    let closed: Vec<(PortForward, Option<Approved>, Running)> = {
        let mut table = locks::lock(&control.tunnels);
        table
            .entries
            .iter_mut()
            .filter_map(|e| {
                let running = e.running.take()?;
                e.state = TunnelState::Waiting {
                    reason: reason.to_owned(),
                };
                Some((e.forward.clone(), e.approved, running))
            })
            .collect()
    };
    if closed.is_empty() {
        return;
    }
    let why = format!("{reason}; it opens again when the terminal reconnects");
    for (forward, approved, running) in closed {
        running.stop.cancel();
        audit_closed(store, ctx, control, &forward, approved, &running, &why).await;
    }
    emit(store, ctx, control).await;
}

/// The terminal closed: every tunnel closes (audited) and open approvals are withdrawn.
pub(super) async fn closed(terminals: &Terminals, ctx: &Context, control: &Control) {
    let _ops = control.tunnel_ops.lock().await;
    let (closed, requests) = {
        let mut table = locks::lock(&control.tunnels);
        let mut closed = Vec::new();
        let mut requests = Vec::new();
        for e in &mut table.entries {
            e.state = TunnelState::Stopped;
            if let Some(running) = e.running.take() {
                closed.push((e.forward.clone(), e.approved.take(), running));
            }
            requests.extend(e.request.take());
        }
        (closed, requests)
    };
    for (forward, approved, running) in closed {
        running.stop.cancel();
        audit_closed(
            &terminals.inner.store,
            ctx,
            control,
            &forward,
            approved,
            &running,
            "the terminal closed",
        )
        .await;
    }
    if let Ok(bus) = terminals.bus() {
        for request in requests {
            if let Err(err) = bus.cancel_approval(request.id).await {
                tracing::warn!(error = %err, "could not withdraw a tunnel's approval");
            }
        }
    }
}

/// The list the UI shows.
async fn list(store: &Store, ctx: &Context, control: &Control) -> Result<Vec<TunnelInfo>> {
    let saved = match control.session_id() {
        Some(session_id) => store.list_forwards(ctx, session_id).await?,
        None => Vec::new(),
    };
    let table = locks::lock(&control.tunnels);
    let mut out: Vec<TunnelInfo> = saved
        .iter()
        .map(
            |forward| match table.entries.iter().find(|e| e.forward.id == forward.id) {
                Some(entry) => entry.info(Some(forward)),
                None => Entry::new(forward.clone()).info(Some(forward)),
            },
        )
        .collect();
    out.extend(
        table
            .entries
            .iter()
            .filter(|e| !saved.iter().any(|f| f.id == e.forward.id))
            .filter(|e| !matches!(e.state, TunnelState::Stopped | TunnelState::Failed { .. }))
            .map(|e| e.info(None)),
    );
    Ok(out)
}

/// Tells the UI what the terminal's tunnels look like now.
async fn emit(store: &Store, ctx: &Context, control: &Control) {
    match list(store, ctx, control).await {
        Ok(tunnels) => {
            let _ = control.events.send(TerminalEvent::Tunnels { tunnels }).await;
        }
        Err(err) => tracing::warn!(error = %err, "could not list a terminal's tunnels"),
    }
}

async fn audit_opened(
    store: &Store,
    ctx: &Context,
    control: &Control,
    forward: &PortForward,
    approved: Approved,
    at: &str,
    again: bool,
) {
    let action = format!("Opened a tunnel on {}: {}", quoted_name(control), forward.describe());
    let mut detail = format!("listening on {at}");
    if again {
        detail.push_str(", again after the terminal reconnected");
    }
    if let Err(err) = audit_entry(
        store,
        ctx,
        "tunnel_opened",
        &action,
        Some(approved.tier),
        Some(approved.job_id),
        control.targets(),
        &detail,
    )
    .await
    {
        tracing::error!(error = %err, "could not audit a tunnel opening");
    }
}

async fn audit_closed(
    store: &Store,
    ctx: &Context,
    control: &Control,
    forward: &PortForward,
    approved: Option<Approved>,
    running: &Running,
    why: &str,
) {
    let action = format!("Closed a tunnel on {}: {}", quoted_name(control), forward.describe());
    let connections = match running.stats.connections() {
        1 => "1 connection".to_owned(),
        n => format!("{n} connections"),
    };
    let detail = format!(
        "{why}; listened on {} for {}, {connections}",
        running.at,
        human_duration(running.opened.elapsed())
    );
    if let Err(err) = audit_entry(
        store,
        ctx,
        "tunnel_closed",
        &action,
        None,
        approved.map(|a| a.job_id),
        control.targets(),
        &detail,
    )
    .await
    {
        tracing::error!(error = %err, "could not audit a tunnel closing");
    }
}
