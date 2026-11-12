//! SS-14 (0.8.0 G2): browsing a terminal's host as root. The owner agreed on 12 Nov 2026 (`docs/plan-0.8.md`, "Files
//! as root"): an SFTP server started with sudo on an exec channel of the terminal's own connection, so listings,
//! downloads, uploads and file operations through it run as root.
//!
//! * **The server** is found with [`SFTP_SERVER_PROBE`] (a read, as the login user): the distributions' usual places,
//!   else `sftp-server` on the PATH. It starts under `sudo -S` ([`crate::adapters::remote::sftp_root`]).
//! * **sudo's password** is BX-07's: the vault password chosen for it, else the session's own login password, else a
//!   password typed for this terminal's login; none when sudo asks for none. Rule 7: a vault password that would go
//!   somewhere it doesn't go yet asks for the vault password first ([`SecretBindings::may_go`],
//!   [`SecretBindings::confirm`]), and may go there from then on.
//! * **A refused password parks** sudo for the session ([`LoginGuard`], [`ParkScope::Sudo`]): Remotely won't try it
//!   again (each try is a failed sudo in the host's logs, which pam_faillock may count) until the password or the
//!   choice changes, the vault unlocks, or the user asks to retry.
//! * **It ends** when the user stops it, the connection drops or reconnects, the vault locks, or the terminal closes.
//!   Starting and stopping are audited. Every change made through it is one tier higher (the bus rates `as_root`).

use std::sync::Arc;

use serde::Serialize;
use uuid::Uuid;

use super::{audit, quoted_name, Control, PaneKind, Terminals};
use crate::adapters::remote::{parse_sftp_server, AuthMethod, RemoteFiles, SFTP_SERVER_PROBE};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::locks;
use crate::login_guard::{self, ParkReason, ParkScope, Parked};
use crate::vault::{SecretId, SecretString};

/// SS-14: a terminal's root browsing while it lasts.
pub(crate) struct RootFiles {
    pub(crate) files: Arc<dyn RemoteFiles>,
    /// What sudo took (for `cp -a` as root); `None`: sudo asked for none.
    pub(crate) password: Option<SecretString>,
    /// The SFTP server under sudo.
    pub(crate) server: String,
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
                "no sftp-server was found on {}'s host (in /usr/lib/openssh, /usr/libexec/openssh or the PATH), so it \
                 can't be browsed as root",
                quoted_name(&control)
            ))
        })?;
        let sudo = self.sudo_for(ctx, &control, &request).await?;
        let (place, session) = self.place_of(ctx, &control, None).await?;
        let park_key = format!(
            "root-sftp {}:{} {:?} {:?}",
            place.host, place.port, place.jump, sudo.secret
        );
        if let Some((session_id, _)) = &session {
            if let Some(guard) = self.inner.guard.get() {
                if request.retry {
                    guard.retry(*session_id);
                } else if let Some(parked) = guard.parked(*session_id, ParkScope::Sudo, &park_key) {
                    return Err(parked.error());
                }
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
                let parked = Parked {
                    reason: ParkReason::SudoRefused,
                    message: login_guard::parked_message(&format!(
                        "sudo on {} refused the password for root browsing",
                        quoted_name(&control)
                    )),
                };
                if let (Some((session_id, _)), Some(guard)) = (&session, self.inner.guard.get()) {
                    guard.park(*session_id, ParkScope::Sudo, &park_key, parked.clone());
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
        *locks::lock(&control.root) = Some(RootFiles {
            files: root.files,
            // A sudo that asked for none gets none for a copy either (`sudo -n`).
            password: sudo.password.filter(|_| with_password),
            server: server.clone(),
        });
        Ok(RootBrowsing { server, with_password })
    }

    /// SS-14: ends root browsing on a terminal, audited. False when it wasn't on.
    pub async fn stop_root(&self, ctx: &Context, id: Uuid) -> Result<bool> {
        let Some(control) = self.control(id) else {
            return Ok(false);
        };
        let Some(root) = locks::lock(&control.root).take() else {
            return Ok(false);
        };
        drop(root);
        audit(
            &self.inner.store,
            ctx,
            "files_root_stopped",
            &format!("Stopped browsing {} as root", quoted_name(&control)),
            control.targets(),
            "stopped by the user",
        )
        .await?;
        Ok(true)
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

/// SS-14: root browsing ends with the connection (and so on a reconnect) and when the vault locks.
pub(super) fn end(control: &Control) {
    locks::lock(&control.root).take();
}
