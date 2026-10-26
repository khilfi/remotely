//! QL-15: saved settings this version can't read fall back to their defaults instead of stopping the app.
//!
//! A setting written by a newer version, or damaged on disk, would otherwise fail every read of it: at start (the
//! app would not open) or each time it is used (no terminal could open with unreadable terminal settings). So at
//! start each known setting is read once; one that can't be read is set aside (kept as `<key>.unreadable`, never
//! deleted), its default applies from then on, and the audit log says so, as invalid approval rules already do.
//! A database error still stops the start: that is not a setting's problem.
//!
//! FD-03's presentation mode is not here: it fails closed on its own (presenting, locked).
//!
//! FD-02: a setting is either this PC's ([`MACHINE_KEYS`]: kept in the home workspace, the same whatever workspace is
//! shown) or an engagement's ([`WORKSPACE_KEYS`]: each workspace its own). The store routes each read and write by
//! its key, so no caller can save a PC setting in one engagement only.

use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::command_bus::{ChangeIdRules, CHANGE_ID_KEY};
use crate::containers::DOCKER_PATH_KEY;
use crate::dashboard::{DashboardLayout, LAYOUT_KEY};
use crate::domain::Context;
use crate::error::{CoreError, Result};
use crate::metrics::guest::{POLL_KEY, WATCHED_KEY};
use crate::metrics::history::{HistoryRetention, HISTORY_RETENTION_KEY};
use crate::policy::PolicyRules;
use crate::presentation::PRESENTATION_KEY;
use crate::retention::{Retention, RETENTION_KEY};
use crate::schedules::{ChainLimits, CHAIN_LIMITS_KEY};
use crate::store::{self, NewAuditEntry, Store};
use crate::terminal::{TerminalSettings, TERMINAL_SETTINGS_KEY};
use crate::updates::{UPDATE_TOKEN_EXPIRES_KEY, UPDATE_TOKEN_KEY};
use crate::vault::SecretId;
use crate::vm_settings::ADDED_VMS_KEY;
use crate::workspaces::CURRENT_WORKSPACE_KEY;

/// FD-02: this PC's settings, the same in every workspace: where the tools are and which VMs the PC has, how many
/// jobs it runs at once, update checks, how long the journal and the dashboard's history are kept, the terminal and
/// presentation settings, the approval rules (one safety policy for the one user), the snapshot chain warnings, and
/// which workspace was shown last.
pub const MACHINE_KEYS: [&str; 21] = [
    store::POLICY_RULES_KEY,
    store::VMRUN_PATH_KEY,
    store::OVFTOOL_PATH_KEY,
    store::VBOXMANAGE_PATH_KEY,
    store::QEMU_IMG_PATH_KEY,
    DOCKER_PATH_KEY,
    store::SCAN_FOLDERS_KEY,
    ADDED_VMS_KEY,
    store::POWER_ON_LIMIT_KEY,
    store::SHUTDOWN_WAIT_KEY,
    store::REMOTE_LIMIT_KEY,
    store::UPDATE_CHECKS_KEY,
    UPDATE_TOKEN_KEY,
    UPDATE_TOKEN_EXPIRES_KEY,
    RETENTION_KEY,
    HISTORY_RETENTION_KEY,
    POLL_KEY,
    TERMINAL_SETTINGS_KEY,
    PRESENTATION_KEY,
    CHAIN_LIMITS_KEY,
    CURRENT_WORKSPACE_KEY,
];

/// FD-02: each engagement's own settings: the dashboard's layout, the hosts it watches, and whether a High or
/// Critical action on a Prod target needs a change ID (AP-08).
pub const WORKSPACE_KEYS: [&str; 3] = [LAYOUT_KEY, WATCHED_KEY, CHANGE_ID_KEY];

/// Whether `key` is one of this PC's settings rather than an engagement's.
pub fn is_machine_key(key: &str) -> bool {
    MACHINE_KEYS.contains(&key)
}

/// Reads every known setting once and sets aside the ones that can't be read. Returns their keys.
pub async fn repair(store: &Store, ctx: &Context) -> Result<Vec<&'static str>> {
    let mut reset = repair_workspace(store, ctx).await?;
    check::<PolicyRules>(store, ctx, store::POLICY_RULES_KEY, "the approval rules", &mut reset).await?;
    check::<Option<String>>(store, ctx, store::VMRUN_PATH_KEY, "the vmrun.exe path", &mut reset).await?;
    check::<Option<String>>(store, ctx, store::OVFTOOL_PATH_KEY, "the ovftool.exe path", &mut reset).await?;
    check::<Option<String>>(
        store,
        ctx,
        store::VBOXMANAGE_PATH_KEY,
        "the VBoxManage.exe path",
        &mut reset,
    )
    .await?;
    check::<Option<String>>(store, ctx, DOCKER_PATH_KEY, "the docker.exe path", &mut reset).await?;
    check::<Option<String>>(
        store,
        ctx,
        store::QEMU_IMG_PATH_KEY,
        "the qemu-img.exe path",
        &mut reset,
    )
    .await?;
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
    check::<Retention>(store, ctx, RETENTION_KEY, "how long job outputs are kept", &mut reset).await?;
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
    check::<Vec<String>>(store, ctx, ADDED_VMS_KEY, "the VMs added by hand", &mut reset).await?;
    check::<Option<Uuid>>(
        store,
        ctx,
        CURRENT_WORKSPACE_KEY,
        "the workspace shown last",
        &mut reset,
    )
    .await?;
    check::<u64>(
        store,
        ctx,
        POLL_KEY,
        "how often the dashboard polls watched hosts",
        &mut reset,
    )
    .await?;
    check::<HistoryRetention>(
        store,
        ctx,
        HISTORY_RETENTION_KEY,
        "how long the dashboard keeps its history",
        &mut reset,
    )
    .await?;
    check::<ChainLimits>(store, ctx, CHAIN_LIMITS_KEY, "the snapshot chain warnings", &mut reset).await?;
    Ok(reset)
}

/// FD-02: [`repair`] for one workspace's own settings ([`WORKSPACE_KEYS`]), when it is shown.
pub async fn repair_workspace(store: &Store, ctx: &Context) -> Result<Vec<&'static str>> {
    let mut reset = Vec::new();
    check::<Option<DashboardLayout>>(store, ctx, LAYOUT_KEY, "the dashboard layout", &mut reset).await?;
    check::<Vec<Uuid>>(store, ctx, WATCHED_KEY, "the hosts the dashboard watches", &mut reset).await?;
    check::<ChangeIdRules>(store, ctx, CHANGE_ID_KEY, "the change ID rule", &mut reset).await?;
    Ok(reset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_setting_is_either_this_pcs_or_a_workspaces() {
        for key in MACHINE_KEYS {
            assert!(!WORKSPACE_KEYS.contains(&key), "{key} is in both lists");
            assert!(is_machine_key(key));
        }
        for key in WORKSPACE_KEYS {
            assert!(!is_machine_key(key), "{key}");
        }
        let mut all: Vec<&str> = MACHINE_KEYS.iter().chain(WORKSPACE_KEYS.iter()).copied().collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), MACHINE_KEYS.len() + WORKSPACE_KEYS.len(), "no key twice");
    }

    #[tokio::test]
    async fn a_pc_setting_is_the_same_in_every_workspace_and_a_workspace_setting_is_its_own() {
        let store = Store::open_in_memory().await.unwrap();
        let home = store.ensure_identity(r"LAB\alice", "Alice").await.unwrap();
        let other = Context {
            workspace_id: store::new_workspace_id(),
            user_id: home.user_id,
        };
        store
            .insert_workspace(home.user_id, other.workspace_id, "Acme", "blue")
            .await
            .unwrap();
        store
            .put_setting(&other, store::UPDATE_CHECKS_KEY, &false)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_setting::<bool>(&home, store::UPDATE_CHECKS_KEY)
                .await
                .unwrap(),
            Some(false),
            "saved from another workspace, read in the home one"
        );
        store
            .put_setting(
                &other,
                CHANGE_ID_KEY,
                &ChangeIdRules {
                    required_for_prod: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            store.get_setting::<ChangeIdRules>(&home, CHANGE_ID_KEY).await.unwrap(),
            None
        );
        assert_eq!(
            store.get_setting::<ChangeIdRules>(&other, CHANGE_ID_KEY).await.unwrap(),
            Some(ChangeIdRules {
                required_for_prod: true
            })
        );
    }
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
