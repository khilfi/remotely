//! The clipboard, read and written here rather than with the browser's clipboard API.
//!
//! QL-05 right-click paste reads it: WebView2 asks the user for permission the first time a page reads the
//! clipboard, and refuses while the window is not focused. Ctrl+V needs neither: it is the browser's own paste
//! event.
//!
//! QL-05 selection copies (copy-on-select, Ctrl+C, Ctrl+Shift+C) and SS-11 "Copy output" write it: the core
//! scrubs the terminal's secrets from the text first ([`remotely_core::terminal::Terminals::scrub_for_copy`],
//! [`remotely_core::terminal::Terminals::copy_output_text`]), and the text goes on the clipboard marked so that
//! Windows keeps it out of the clipboard history (Win+V), off the cloud clipboard and away from clipboard
//! monitors that honour the mark: terminal output may hold what the core doesn't know is a secret.
//!
//! The text is the user's own data. It goes to the UI or the clipboard only, never into a log, the audit log or
//! an error.

use std::sync::Arc;

use remotely_core::terminal::output::TerminalText;
use tauri::State;
use uuid::Uuid;

use crate::ipc::IpcError;
use crate::AppState;

type IpcResult<T> = Result<T, IpcError>;

/// The clipboard's text; `None` when it holds none (it is empty, or holds only an image or files).
#[tauri::command]
pub async fn clipboard_read_text() -> IpcResult<Option<String>> {
    // Opening the clipboard waits and retries while another app holds it.
    tauri::async_runtime::spawn_blocking(|| text_or_none(arboard::Clipboard::new().and_then(|mut c| c.get_text())))
        .await
        .map_err(|_| IpcError::new("clipboard", "the clipboard couldn't be read"))?
}

/// QL-05: text selected in a terminal, scrubbed of that terminal's secrets by the core, onto the clipboard
/// (kept out of the clipboard history and the cloud clipboard). `id`: the core's terminal, `None` for a pane
/// that never opened. A terminal that has closed is refused: its secrets are gone, so its text can't be checked.
#[tauri::command]
pub async fn terminal_copy_selection(state: State<'_, AppState>, id: Option<Uuid>, text: String) -> IpcResult<()> {
    let core = Arc::clone(&state.core);
    let clean = off_the_window(move || core.terminals.scrub_for_copy(id, &text)).await?;
    write_private(clean).await
}

/// SS-11 "Copy output": the terminals' text with their login secrets scrubbed, one under a header each when
/// there are several, onto the clipboard like a selection.
#[tauri::command]
pub async fn terminal_output_copy(state: State<'_, AppState>, items: Vec<TerminalText>) -> IpcResult<()> {
    let core = Arc::clone(&state.core);
    let clean = off_the_window(move || core.terminals.copy_output_text(items)).await?;
    write_private(clean).await
}

/// Whole scrollbacks can be megabytes, so scrubbing runs on a blocking thread, as printing does.
async fn off_the_window(scrub: impl FnOnce() -> remotely_core::Result<String> + Send + 'static) -> IpcResult<String> {
    Ok(tauri::async_runtime::spawn_blocking(scrub)
        .await
        .map_err(|err| IpcError::new("internal", format!("The text could not be read: {err}")))??)
}

/// Puts text on the clipboard, kept out of Windows' clipboard history, cloud clipboard and clipboard monitors.
async fn write_private(text: String) -> IpcResult<()> {
    // Opening the clipboard waits and retries while another app holds it.
    tauri::async_runtime::spawn_blocking(move || written(set_private(&text)))
        .await
        .map_err(|_| IpcError::new("clipboard", "the clipboard couldn't be written"))?
}

fn set_private(text: &str) -> Result<(), arboard::Error> {
    let mut clipboard = arboard::Clipboard::new()?;
    private(clipboard.set()).text(text)
}

/// With the clipboard formats Windows documents for this:
/// `ExcludeClipboardContentFromMonitorProcessing` (no clipboard history, no cloud sync, and skipped by clipboard
/// managers that honour it), plus `CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard` set to 0, which
/// say the same to the history and the cloud clipboard on their own. arboard's docs suggest the first alone;
/// all three is what password managers set, so a reader that checks only one of them still sees it.
#[cfg(windows)]
fn private(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtWindows;
    set.exclude_from_monitoring()
        .exclude_from_history()
        .exclude_from_cloud()
}

#[cfg(not(windows))]
fn private(set: arboard::Set<'_>) -> arboard::Set<'_> {
    set
}

fn text_or_none(read: Result<String, arboard::Error>) -> IpcResult<Option<String>> {
    match read {
        Ok(text) => Ok(Some(text)),
        Err(arboard::Error::ContentNotAvailable) => Ok(None),
        // arboard's messages say what went wrong (another app holds the clipboard, ...), never what it holds.
        Err(err) => Err(IpcError::new(
            "clipboard",
            format!("the clipboard couldn't be read: {err}"),
        )),
    }
}

fn written(write: Result<(), arboard::Error>) -> IpcResult<()> {
    // As for reads, arboard's messages never hold the text.
    write.map_err(|err| IpcError::new("clipboard", format!("the clipboard couldn't be written: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only the mapping: a test never reads or replaces the real clipboard, which is the user's.

    #[test]
    fn text_is_pasted_as_is() {
        assert_eq!(
            text_or_none(Ok("echo one\r\necho two".into())).map_err(|_| ()),
            Ok(Some("echo one\r\necho two".to_owned()))
        );
    }

    #[test]
    fn no_text_on_the_clipboard_is_nothing_to_paste() {
        assert_eq!(
            text_or_none(Err(arboard::Error::ContentNotAvailable)).map_err(|_| ()),
            Ok(None)
        );
    }

    #[test]
    fn a_busy_clipboard_is_an_error() {
        let Err(err) = text_or_none(Err(arboard::Error::ClipboardOccupied)) else {
            panic!("a busy clipboard read as text");
        };
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], "clipboard");
    }

    #[test]
    fn a_copy_the_clipboard_refused_is_an_error() {
        assert!(written(Ok(())).is_ok());
        let Err(err) = written(Err(arboard::Error::ClipboardOccupied)) else {
            panic!("a busy clipboard took the copy");
        };
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], "clipboard");
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .starts_with("the clipboard couldn't be written: "),
            "{json}"
        );
    }
}
