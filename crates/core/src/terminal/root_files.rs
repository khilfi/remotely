//! SS-14 (0.8.0 G2): browsing a terminal's host as root. The owner agreed on 12 Nov 2026 (`docs/plan-0.8.md`, "Files
//! as root"): an SFTP server started with sudo on an exec channel of the terminal's own connection, so listings,
//! downloads, uploads and file operations through it run as root.
//!
//! * **The server** is found with [`SFTP_SERVER_PROBE`] (a read, as the login user, run by `/bin/sh`): the
//!   distributions' fixed places only, never the PATH, since what it finds runs as root. It starts under `sudo -S`
//!   ([`crate::adapters::remote::sftp_root`]).
//! * **sudo's password** is BX-07's: the vault password chosen for it, else the session's own login password, else a
//!   password typed for this terminal's login; none when sudo asks for none. Rule 7: a vault password that would go
//!   somewhere it doesn't go yet asks for the vault password first ([`SecretBindings::may_go`],
//!   [`SecretBindings::confirm`]), and may go there from then on.
//! * **A refused password parks** sudo for the session and that password ([`LoginGuard`], [`ParkScope::Sudo`], keyed by
//!   [`login_guard::sudo_key`], so the Containers page's sudo and this one share one park): Remotely won't try it again
//!   (each try is a failed sudo in the host's logs, which pam_faillock may count) until the password or the choice
//!   changes, the vault unlocks, or the user asks to retry, which lifts that park alone. A quick connection parks on
//!   the terminal. A root channel that sudo refuses when it opens again parks too, and ends root browsing.
//! * **It ends** when the user stops it, the connection drops or reconnects, the vault locks, or the terminal closes:
//!   every transfer as root of the terminal is cancelled first and given a moment ([`ROOT_SETTLE`]) to delete what
//!   it made (a half-written file in `/etc` is worse than none), then the root SFTP channels close and sudo's
//!   password is forgotten ([`RemoteFiles::revoke`], which a paused upload's writer shares, so it never writes again),
//!   and `files_root_stopped` is audited with why. Starting is audited too. Every change made through it is one tier higher (the bus rates `as_root`).

use std::sync::{Arc, Weak};

use async_trait::async_trait;
use serde::Serialize;
use uuid::Uuid;

use super::{audit, quoted_name, Control, Inner, PaneKind, Source, Terminals};
use crate::adapters::remote::{
    parse_sftp_server, AuthMethod, RemoteEntry, RemoteFiles, RemoteListing, RemoteRead, RemoteWrite, RootOpened,
    SetAttrs, SFTP_SERVER_PROBE,
};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::login_guard::{self, LoginGuard, ParkReason, ParkScope, Parked};
use crate::vault::{SecretId, SecretString};

/// SS-14: a terminal's root browsing while it lasts.
pub(crate) struct RootFiles {
    pub(crate) files: Arc<dyn RemoteFiles>,
    /// What sudo took (for `cp -a` as root); `None`: sudo asked for none.
    pub(crate) password: Option<SecretString>,
    /// The SFTP server under sudo.
    pub(crate) server: String,
    /// Who started it: the entry when it ends is theirs.
    ctx: Context,
}

/// SS-14: how long root browsing's cancelled transfers get to delete what they made before its channels close.
pub const ROOT_SETTLE: std::time::Duration = std::time::Duration::from_secs(5);

/// SS-14: why root browsing ended, for its audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootEnd {
    Stopped,
    VaultLocked,
    ConnectionEnded,
    SudoRefused,
}

impl RootEnd {
    fn detail(self) -> &'static str {
        match self {
            RootEnd::Stopped => "stopped by the user",
            RootEnd::VaultLocked => "the vault locked",
            RootEnd::ConnectionEnded => "the terminal's connection ended or reconnected",
            RootEnd::SudoRefused => "sudo refused the password when the root channel opened again",
        }
    }
}

/// SS-14: where a refused sudo password parks: the saved session with [`login_guard::sudo_key`] (as the Containers
/// page parks it, so neither clears the other's), or the terminal itself for a quick connection.
#[derive(Debug, Clone)]
struct SudoPark {
    subject: Uuid,
    scope: ParkScope,
    key: String,
}

/// SS-14: how root browsing started.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootBrowsing {
    /// The host's sftp-server, e.g. `/usr/lib/openssh/sftp-server`.
    pub server: String,
    /// sudo took a password (false: it asked for none).
    pub with_password: bool,
}

/// SS-14: what [`Terminals::browse_as_root`] takes.
#[derive(Debug, Default)]
pub struct RootRequest {
    /// BX-07: the vault password sudo gets; `None`: the session's own login password.
    pub sudo_password_id: Option<SecretId>,
    /// AP-06: the vault password, when a vault password would go somewhere new.
    pub vault_password: Option<SecretString>,
    /// Try again although sudo refused the same password before.
    pub retry: bool,
}

/// The password sudo gets, and the vault item it came from.
struct Sudo {
    password: Option<SecretString>,
    secret: Option<SecretId>,
}

impl Terminals {
    /// SS-14: whether the terminal browses as root now, and how.
    pub fn root_browsing(&self, id: Uuid) -> Option<RootBrowsing> {
        let control = self.control(id)?;
        let root = locks::lock(&control.root);
        root.as_ref().map(|r| RootBrowsing {
            server: r.server.clone(),
            with_password: r.password.is_some(),
        })
    }

    /// SS-14: starts root browsing on an open SSH terminal. Errors say why not: no sftp-server, sudo refused (parked),
    /// no password for sudo, or the vault password needed first (`reauth_required`).
    pub async fn browse_as_root(&self, ctx: &Context, id: Uuid, request: RootRequest) -> Result<RootBrowsing> {
        let control = self
            .control(id)
            .ok_or_else(|| CoreError::UnknownTarget(format!("terminal {id} has closed")))?;
        if control.workspace != ctx.workspace_id {
            return Err(CoreError::NotInWorkspace(format!("Terminal {id}")));
        }
        if control.kind != PaneKind::Ssh {
            return Err(CoreError::InvalidInput(
                "Only SSH terminals browse files, as root or not.".into(),
            ));
        }
        let (_, files) = self.live(id)?;
        let commands = locks::lock(&control.commands).clone().ok_or_else(|| {
            CoreError::InvalidInput(format!(
                "{} is not connected, so it can't browse as root. Reconnect it first.",
                quoted_name(&control)
            ))
        })?;
        let probe = commands.run(SFTP_SERVER_PROBE, 4096).await?;
        let server = parse_sftp_server(&probe.output.stdout).ok_or_else(|| {
            CoreError::Sftp(format!(
                "no sftp-server was found on {}'s host (in /usr/lib/openssh, /usr/libexec/openssh, /usr/lib/ssh or \
                 /usr/libexec), so it can't be browsed as root",
                quoted_name(&control)
            ))
        })?;
        let sudo = self.sudo_for(ctx, &control, &request).await?;
        let (place, session) = self.place_of(ctx, &control, None).await?;
        let park = self.sudo_park(ctx, &control, sudo.secret).await?;
        let guard = self.inner.guard.get().cloned();
        if let Some(guard) = &guard {
            if request.retry {
                // This park alone: the session's logins and other sudo passwords stay as they are.
                guard.lift(park.subject, park.scope);
            } else if let Some(parked) = guard.parked(park.subject, park.scope, &park.key) {
                return Err(parked.error());
            }
        }
        // Rule 7: a vault password goes only where it goes already, unless the vault password says so.
        let mut asked = None;
        let mut goes = true;
        if let (Some(secret), Some(bindings)) = (sudo.secret, self.inner.bindings.get()) {
            goes = bindings.goes_to(ctx, secret, &place, None).await?;
            if !goes && !bindings.may_go(ctx, secret, &place, None).await? {
                let what = bindings.describe(ctx, secret).await?;
                let reason = format!(
                    "Browsing as root gives the {what} to sudo on {}:{}, where no saved session sends it yet",
                    place.host, place.port
                );
                let action = format!("Failed to browse {} as root", quoted_name(&control));
                asked = Some(
                    bindings
                        .confirm(ctx, request.vault_password.as_ref(), &action, &reason)
                        .await?,
                );
            }
        }
        let root = match files.open_as_root(&server, sudo.password.as_ref()).await {
            Ok(opened) => opened,
            Err(CoreError::SudoPasswordRefused) => {
                let parked = refused(&control);
                if let Some(guard) = &guard {
                    guard.park(park.subject, park.scope, &park.key, parked.clone());
                }
                audit(
                    &self.inner.store,
                    ctx,
                    "files_root_refused",
                    &format!("sudo refused root browsing on {}", quoted_name(&control)),
                    control.targets(),
                    &format!("{server} under sudo; the password was refused"),
                )
                .await?;
                return Err(parked.error());
            }
            Err(err) => return Err(err),
        };
        let with_password = root.took_password;
        let mut detail = format!(
            "{server} under sudo, {}",
            match sudo.secret {
                _ if !with_password => "which asked for no password",
                Some(_) => "with a password from the vault",
                None => "with the password typed for the login",
            }
        );
        if let Some(how) = asked {
            detail.push_str(&format!("; {how}"));
        }
        audit(
            &self.inner.store,
            ctx,
            "files_root_started",
            &format!("Started browsing {} as root", quoted_name(&control)),
            control.targets(),
            &detail,
        )
        .await?;
        if let (Some(secret), Some(bindings)) = (sudo.secret, self.inner.bindings.get()) {
            bindings.settle(&[secret]);
            // Given to this session's sudo for the first time: from now on it may be again.
            if let (false, true, Some((session_id, name))) = (goes, with_password, &session) {
                let how = asked.unwrap_or("given to sudo for root browsing for the first time");
                bindings.allow(ctx, *session_id, name, secret, how).await?;
            }
        }
        let files: Arc<dyn RemoteFiles> = Arc::new(ParkOnRefusal {
            files: root.files,
            terminals: Arc::downgrade(&self.inner),
            control: Arc::downgrade(&control),
            guard,
            park,
        });
        // One at a time: a root browsing started twice ends the first.
        let before = locks::lock(&control.root).replace(RootFiles {
            files,
            // A sudo that asked for none gets none for a copy either (`sudo -n`).
            password: sudo.password.filter(|_| with_password),
            server: server.clone(),
            ctx: *ctx,
        });
        if let Some(before) = before {
            before.files.revoke();
        }
        Ok(RootBrowsing { server, with_password })
    }

    /// SS-14: ends root browsing on a terminal, audited. False when it wasn't on.
    pub async fn stop_root(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let Some(control) = self.control(id) else {
            return Ok(false);
        };
        if control.workspace != ctx.workspace_id {
            return Err(CoreError::NotInWorkspace(format!("Terminal {id}")));
        }
        let Some((root, cancelled)) = self.take_root(&control) else {
            return Ok(false);
        };
        self.close_root(&root, &cancelled).await;
        audit(
            &self.inner.store,
            &root.ctx,
            "files_root_stopped",
            &format!("Stopped browsing {} as root", quoted_name(&control)),
            control.targets(),
            RootEnd::Stopped.detail(),
        )
        .await?;
        Ok(true)
    }

    /// SS-14: root browsing ends without the user (the vault locked, the connection ended): audited in the
    /// background with why.
    pub(super) fn end_root(&self, control: &Arc<Control>, why: RootEnd) {
        let Some((root, cancelled)) = self.take_root(control) else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            root.files.revoke();
            return;
        };
        let this = self.clone();
        let control = Arc::clone(control);
        runtime.spawn(async move {
            this.close_root(&root, &cancelled).await;
            let noted = audit(
                &this.inner.store,
                &root.ctx,
                "files_root_stopped",
                &format!("Stopped browsing {} as root", quoted_name(&control)),
                control.targets(),
                why.detail(),
            )
            .await;
            if let Err(err) = noted {
                tracing::error!(error = %err, "could not audit the end of root browsing");
            }
        });
    }

    /// Takes the terminal's root browsing, so nothing new goes through it, and cancels its transfers; the ids of
    /// those cancelled.
    fn take_root(&self, control: &Control) -> Option<(RootFiles, Vec<Uuid>)> {
        let root = locks::lock(&control.root).take()?;
        let cancelled = self.inner.transfers.cancel_root(control.id);
        Some((root, cancelled))
    }

    /// Once the cancelled transfers ended (each deletes what it made through the root channel; at most
    /// [`ROOT_SETTLE`]), the root channels close and sudo's password is forgotten: everything holding these files, a
    /// paused upload's writer too, stops working.
    async fn close_root(&self, root: &RootFiles, cancelled: &[Uuid]) {
        let settled = tokio::time::timeout(ROOT_SETTLE, async {
            while !self.inner.transfers.all_finished(cancelled) {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        if settled.is_err() {
            tracing::warn!("root browsing's transfers did not end in time; its channels close anyway");
        }
        root.files.revoke();
    }

    /// Where a refused sudo password for this terminal parks.
    async fn sudo_park(&self, ctx: &Context, control: &Control, secret: Option<SecretId>) -> Result<SudoPark> {
        let scope = ParkScope::Sudo { secret };
        match &control.source {
            Source::Saved(session_id) => {
                let spec = self
                    .inner
                    .store
                    .session_spec(ctx, *session_id)
                    .await?
                    .ok_or_else(|| CoreError::UnknownTarget("the session was deleted".into()))?;
                Ok(SudoPark {
                    subject: *session_id,
                    scope,
                    key: login_guard::sudo_key(&spec),
                })
            }
            Source::Unsaved(spec) => Ok(SudoPark {
                subject: control.id,
                scope,
                key: login_guard::sudo_key(spec),
            }),
        }
    }

    /// BX-07's choice of sudo password for this terminal.
    async fn sudo_for(&self, ctx: &Context, control: &Control, request: &RootRequest) -> Result<Sudo> {
        let mut chosen = request.sudo_password_id;
        if chosen.is_none() {
            if let Some(session_id) = control.session_id() {
                if let Some(spec) = self.inner.store.session_spec(ctx, session_id).await? {
                    if let AuthMethod::Password(Some(id)) = spec.auth {
                        chosen = Some(id);
                    }
                }
            }
        }
        if let Some(id) = chosen {
            return Ok(Sudo {
                password: Some(self.inner.vault.get(ctx, id).await?),
                secret: Some(id),
            });
        }
        // A password typed for this terminal's login goes to the same host's sudo.
        Ok(Sudo {
            password: locks::lock(&control.remembered).clone(),
            secret: None,
        })
    }
}

/// What a refused sudo password parks with.
fn refused(control: &Control) -> Parked {
    Parked {
        reason: ParkReason::SudoRefused,
        message: login_guard::parked_message(&format!(
            "sudo on {} refused the password for root browsing",
            quoted_name(control)
        )),
    }
}

/// SS-14: root browsing's files: when sudo refuses the password as a root channel opens again (the host's sudo
/// password changed), the password parks and root browsing ends, so nothing tries it again.
struct ParkOnRefusal {
    files: Arc<dyn RemoteFiles>,
    terminals: Weak<Inner>,
    control: Weak<Control>,
    guard: Option<LoginGuard>,
    park: SudoPark,
}

impl ParkOnRefusal {
    fn seen<T>(&self, result: Result<T>) -> Result<T> {
        if let Err(CoreError::SudoPasswordRefused) = &result {
            if let Some(control) = self.control.upgrade() {
                if let Some(guard) = &self.guard {
                    guard.park(self.park.subject, self.park.scope, &self.park.key, refused(&control));
                }
                if let Some(inner) = self.terminals.upgrade() {
                    Terminals { inner }.end_root(&control, RootEnd::SudoRefused);
                }
            }
            self.files.revoke();
        }
        result
    }
}

#[async_trait]
impl RemoteFiles for ParkOnRefusal {
    fn user(&self) -> String {
        self.files.user()
    }
    async fn home(&self) -> Result<String> {
        self.seen(self.files.home().await)
    }
    async fn list(&self, folder: &str) -> Result<RemoteListing> {
        self.seen(self.files.list(folder).await)
    }
    async fn stat(&self, path: &str) -> Result<Option<RemoteEntry>> {
        self.seen(self.files.stat(path).await)
    }
    async fn read(&self, path: &str) -> Result<Box<dyn RemoteRead>> {
        self.seen(self.files.read(path).await)
    }
    async fn write(&self, path: &str, replace: bool) -> Result<Box<dyn RemoteWrite>> {
        self.seen(self.files.write(path, replace).await)
    }
    async fn remove(&self, path: &str) -> Result<()> {
        self.seen(self.files.remove(path).await)
    }
    async fn lstat(&self, path: &str) -> Result<Option<RemoteEntry>> {
        self.seen(self.files.lstat(path).await)
    }
    async fn make_folder(&self, path: &str) -> Result<()> {
        self.seen(self.files.make_folder(path).await)
    }
    async fn remove_folder(&self, path: &str) -> Result<()> {
        self.seen(self.files.remove_folder(path).await)
    }
    async fn rename(&self, from: &str, to: &str, replace: bool) -> Result<()> {
        self.seen(self.files.rename(from, to, replace).await)
    }
    async fn set_attrs(&self, path: &str, attrs: SetAttrs) -> Result<()> {
        self.seen(self.files.set_attrs(path, attrs).await)
    }
    async fn read_from(&self, path: &str, offset: u64) -> Result<Box<dyn RemoteRead>> {
        self.seen(self.files.read_from(path, offset).await)
    }
    async fn open_as_root(&self, server: &str, password: Option<&SecretString>) -> Result<RootOpened> {
        self.files.open_as_root(server, password).await
    }
    fn as_root(&self) -> bool {
        self.files.as_root()
    }
    fn revoke(&self) {
        self.files.revoke();
    }
}
