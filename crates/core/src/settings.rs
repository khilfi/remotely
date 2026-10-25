//! QL-15: saved settings this version can't read fall back to their defaults instead of stopping the app.
//!
//! A setting written by a newer version, or damaged on disk, would otherwise fail every read of it: at start (the
//! app would not open) or each time it is used (no terminal could open with unreadable terminal settings). So at
//! start each known setting is read once; one that can't be read is set aside (kept as `<key>.unreadable`, never
//! deleted), its default applies from then on, and the audit log says so, as invalid approval rules already do.
//! A database error still stops the start: that is not a setting's problem.
//!
//! FD-03's presentation mode is not here: it fails closed on its own (presenting, locked).

use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::containers::DOCKER_PATH_KEY;
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::metrics::guest::{POLL_KEY, WATCHED_KEY};
use crate::policy::PolicyRules;
use crate::store::{self, NewAuditEntry, Store};
use crate::terminal::{TerminalSettings, TERMINAL_SETTINGS_KEY};
use crate::updates::{UPDATE_TOKEN_EXPIRES_KEY, UPDATE_TOKEN_KEY};
use crate::vault::SecretId;

/// Reads every known setting once and sets aside the ones that can't be read. Returns their keys.
pub async fn repair(store: &Store, ctx: &Context) -> Result<Vec<&'static str>> {
    let mut reset = Vec::new();
    check::<PolicyRules>(store, ctx, store::POLICY_RULES_KEY, "the approval rules", &mut reset).await?;
    check::<Option<String>>(store, ctx, store::VMRUN_PATH_KEY, "the vmrun.exe path", &mut reset).await?;
    check::<Option<String>>(
        store,
        ctx,
        store::VBOXMANAGE_PATH_KEY,
        "the VBoxManage.exe path",
        &mut reset,
    )
    .await?;
    check::<Option<String>>(store, ctx, DOCKER_PATH_KEY, "the docker.exe path", &mut reset).await?;
    check::<Vec<String>>(
        store,
        ctx,
        store::SCAN_FOLDERS_KEY,
        "the VM folders to scan",
        &mut reset,
    )
    .await?;
    check::<usize>(
        store,
        ctx,
        store::POWER_ON_LIMIT_KEY,
        "the parallel power-on limit",
        &mut reset,
    )
    .await?;
    check::<u64>(store, ctx, store::SHUTDOWN_WAIT_KEY, "the shutdown wait", &mut reset).await?;
    check::<usize>(
        store,
        ctx,
        store::REMOTE_LIMIT_KEY,
        "the hosts a bulk run reaches at once",
        &mut reset,
    )
    .await?;
    check::<bool>(store, ctx, store::UPDATE_CHECKS_KEY, "update checks", &mut reset).await?;
    check::<Option<SecretId>>(
        store,
        ctx,
        UPDATE_TOKEN_KEY,
        "the GitHub update token's vault item",
        &mut reset,
    )
    .await?;
    check::<Option<String>>(
        store,
        ctx,
        UPDATE_TOKEN_EXPIRES_KEY,
        "the update token's expiry",
        &mut reset,
    )
    .await?;
    check::<TerminalSettings>(store, ctx, TERMINAL_SETTINGS_KEY, "the terminal settings", &mut reset).await?;
    check::<Vec<Uuid>>(store, ctx, WATCHED_KEY, "the hosts the dashboard watches", &mut reset).await?;
    check::<u64>(
        store,
        ctx,
        POLL_KEY,
        "how often the dashboard polls watched hosts",
        &mut reset,
    )
    .await?;
    Ok(reset)
}

async fn check<T: DeserializeOwned>(
    store: &Store,
    ctx: &Context,
    key: &'static str,
    what: &str,
    reset: &mut Vec<&'static str>,
) -> Result<()> {
    let err = match store.get_setting::<T>(ctx, key).await {
        Ok(_) => return Ok(()),
        Err(CoreError::Json(err)) => err,
        Err(other) => return Err(other),
    };
    tracing::error!(setting = key, error = %err, "a saved setting can't be read; its default applies");
    // Audited first: if the audit can't be written, the setting stays as it was and the start fails as before.
    let detail = format!("{what} ({key}) could not be read ({err}); the default applies, and the saved value is kept as {key}.unreadable");
    store
        .append_audit(
            ctx,
            NewAuditEntry {
                event: "setting_changed",
                action: "Reset an unreadable setting to its default",
                tier: None,
                job_id: None,
                targets: &[],
                approval: None,
                result: None,
                detail: Some(&detail),
            },
        )
        .await?;
    store.set_setting_aside(ctx, key).await?;
    reset.push(key);
    Ok(())
}
