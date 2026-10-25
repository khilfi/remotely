//! The Terminal page's helpers (post-MVP P5): BX-08's command panel (favourite and built-in commands,
//! `{{variables}}` filled in before pasting), QL-06 "Type vault password", and QL-07's Windows
//! notification when a long command in a background tab finishes.
//!
//! Pasting a command is the terminal's own input path (`terminal_write`, as if typed), so nothing here
//! sends a command anywhere. A vault password goes from the vault to the shell inside the core: the UI
//! names the secret by id and never sees its value.
//!
//! QL-13: a library entry's "Manual" link opens in the default browser from here, and only when the
//! core's allow-list of documentation sites takes its address (`snippets::manual::checked`).

use std::collections::HashMap;
use std::sync::Arc;

use remotely_core::snippets::manual;
use remotely_core::snippets::{CommandInfo, Favourite, FavouriteInput, LibraryEntry};
use remotely_core::vault::{SecretId, SecretString};
use remotely_core::CoreError;
use tauri::{AppHandle, State};
use tauri_plugin_notification::NotificationExt;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// Longest notification title and text the UI may ask for.
const MAX_TITLE: usize = 120;
const MAX_BODY: usize = 400;

/// BX-08: the favourite commands, folders by name (the top level first), each in the user's order.
#[tauri::command]
pub async fn favourites_list(state: State<'_, AppState>) -> IpcResult<Vec<Favourite>> {
    let core = &state.core;
    Ok(core.snippets.favourites(&core.ctx).await?)
}

/// BX-08: saves a new favourite at the end of its folder. Audited (name and folder, not the command).
#[tauri::command]
pub async fn favourite_add(state: State<'_, AppState>, input: FavouriteInput) -> IpcResult<Favourite> {
    let core = &state.core;
    Ok(core.snippets.add(&core.ctx, input).await?)
}

/// BX-08: changes a favourite; another folder puts it at that folder's end. Audited.
#[tauri::command]
pub async fn favourite_update(state: State<'_, AppState>, id: Uuid, input: FavouriteInput) -> IpcResult<Favourite> {
    let core = &state.core;
    Ok(core.snippets.update(&core.ctx, id, input).await?)
}

/// BX-08. Audited.
#[tauri::command]
pub async fn favourite_delete(state: State<'_, AppState>, id: Uuid) -> IpcResult<()> {
    let core = &state.core;
    Ok(core.snippets.delete(&core.ctx, id).await?)
}

/// BX-08: one folder's favourites in a new order (`folder` null: the top level). Audited.
#[tauri::command]
pub async fn favourites_reorder(
    state: State<'_, AppState>,
    folder: Option<String>,
    ids: Vec<Uuid>,
) -> IpcResult<Vec<Favourite>> {
    let core = &state.core;
    Ok(core.snippets.reorder(&core.ctx, folder.as_deref(), &ids).await?)
}

/// BX-08: the built-in commands, each with what the policy engine makes of it under the current rules.
/// Classifying some 600 commands takes a moment, so it runs on a blocking thread, never on the
/// window's thread (P10).
#[tauri::command]
pub async fn command_library(state: State<'_, AppState>) -> IpcResult<Vec<LibraryEntry>> {
    let core = Arc::clone(&state.core);
    tokio::task::spawn_blocking(move || core.snippets.library())
        .await
        .map_err(|err| IpcError::new("internal", format!("The command library could not be read: {err}")))
}

/// BX-08: a command's `{{variables}}` and what the policy engine makes of it, while it is typed.
#[tauri::command]
pub fn command_inspect(state: State<'_, AppState>, command: String) -> CommandInfo {
    state.core.snippets.inspect(&command)
}

/// QL-13: opens a library entry's manual page in the default browser. An address that isn't https on
/// one of the documentation sites is refused before Windows sees it. Opening a page changes nothing,
/// so it is not audited and the read-only lock doesn't stop it.
#[tauri::command]
pub async fn open_manual(url: String) -> IpcResult<()> {
    tokio::task::spawn_blocking(move || open_checked(&url, open_in_browser))
        .await
        .map_err(|err| IpcError::new("browser", format!("The browser did not open: {err}")))?
}

/// Hands `url` to `open` only when it is a manual page the app may open.
fn open_checked(url: &str, open: impl FnOnce(&str) -> IpcResult<()>) -> IpcResult<()> {
    let url = manual::checked(url)?;
    open(url.as_str())
}

/// The default browser, through the shell's "open" verb, as Explorer opens a link.
#[cfg(windows)]
fn open_in_browser(url: &str) -> IpcResult<()> {
    use windows::core::{w, HSTRING, PCWSTR};
    use windows::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    };
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let file = HSTRING::from(url);
    // SAFETY: plain Win32 calls with valid, NUL-terminated strings that outlive them. ShellExecute
    // wants COM on its thread (apartment-threaded, as Microsoft documents); this blocking-pool thread
    // sets it up for the call and undoes it if it did.
    let result = unsafe {
        let com = CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        let result = ShellExecuteW(None, w!("open"), &file, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL);
        if com.is_ok() {
            CoUninitialize();
        }
        result
    };
    // ShellExecute returns a value above 32 when it worked, an error code otherwise.
    if result.0 as usize > 32 {
        tracing::info!("manual page opened in the browser");
        Ok(())
    } else {
        Err(IpcError::new(
            "browser",
            format!("Windows could not open the page (error {}).", result.0 as usize),
        ))
    }
}

#[cfg(not(windows))]
fn open_in_browser(_url: &str) -> IpcResult<()> {
    Err(IpcError::new("unsupported", "Opening a manual page needs Windows."))
}

/// BX-08: the command with its `{{variables}}` filled in, ready to paste.
#[tauri::command]
pub fn command_fill(state: State<'_, AppState>, command: String, values: HashMap<String, String>) -> IpcResult<String> {
    Ok(state.core.snippets.fill(&command, &values)?)
}

/// QL-06: types a vault password or passphrase into the terminal, then Enter, when it shows a
/// password prompt (or `force`). The value never comes back here. Audited with the label. SS-04, AP-06:
/// `vault_password` is the master password, when the core asked for it (`reauth_required`).
#[tauri::command]
pub async fn terminal_type_secret(
    state: State<'_, AppState>,
    id: Uuid,
    secret_id: SecretId,
    force: bool,
    vault_password: Option<SecretString>,
) -> IpcResult<()> {
    let core = &state.core;
    Ok(core
        .terminals
        .type_secret(&core.ctx, id, secret_id, force, vault_password.as_ref())
        .await?)
}

/// QL-07: a Windows notification that a long command finished in a background tab. The UI decides
/// when (the tab is in the background, notifications are on for it); the text names the terminal and
/// how long the command ran, nothing of its output.
#[tauri::command]
pub fn notify_command_finished(app: AppHandle, title: String, body: String) -> IpcResult<()> {
    let title: String = title.chars().filter(|c| !c.is_control()).take(MAX_TITLE).collect();
    let body: String = body.chars().filter(|c| !c.is_control()).take(MAX_BODY).collect();
    if title.trim().is_empty() {
        return Err(CoreError::InvalidInput("A notification needs a title.".into()).into());
    }
    app.notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .map_err(|err| IpcError::new("notification", format!("the notification could not be shown: {err}")))?;
    tracing::info!("long-command notification shown");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    // Only the check: a test never starts the real browser.

    #[test]
    fn a_manual_page_on_a_documentation_site_reaches_the_browser() {
        let opened = RefCell::new(Vec::new());
        let url = "https://man7.org/linux/man-pages/man1/df.1.html";
        open_checked(url, |u| {
            opened.borrow_mut().push(u.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(opened.into_inner(), [url]);
    }

    #[test]
    fn any_other_address_is_refused_before_the_browser_sees_it() {
        for url in [
            "https://example.com/",
            "http://man7.org/linux/man-pages/man1/df.1.html",
            "file:///C:/Windows/System32/cmd.exe",
            r"C:\Windows\System32\cmd.exe",
            "calc.exe",
            "https://man7.org@example.com/",
            "https://man7.org:8443/",
            "ms-settings:privacy",
            "",
        ] {
            let Err(err) = open_checked(url, |u| panic!("{u} reached the browser")) else {
                panic!("{url} was opened");
            };
            let json = serde_json::to_value(err).unwrap();
            assert_eq!(json["code"], "invalid_input", "{url}");
        }
    }
}
