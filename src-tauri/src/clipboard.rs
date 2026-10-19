//! QL-05 right-click paste: the clipboard's text, read here rather than with the browser's clipboard API.
//! WebView2 asks the user for permission the first time a page reads the clipboard, and refuses while the
//! window is not focused. Ctrl+V needs neither: it is the browser's own paste event.
//!
//! The text is the user's own data. It goes to the UI only, never into a log, the audit log or an error.

use crate::ipc::IpcError;

type IpcResult<T> = Result<T, IpcError>;

/// The clipboard's text; `None` when it holds none (it is empty, or holds only an image or files).
#[tauri::command]
pub async fn clipboard_read_text() -> IpcResult<Option<String>> {
    // Opening the clipboard waits and retries while another app holds it.
    tauri::async_runtime::spawn_blocking(|| text_or_none(arboard::Clipboard::new().and_then(|mut c| c.get_text())))
        .await
        .map_err(|_| IpcError::new("clipboard", "the clipboard couldn't be read"))?
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
}
