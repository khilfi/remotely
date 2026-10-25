//! QL-15: what is left to read when something goes wrong. The app has no console (a release build uses the
//! Windows subsystem) and stops at once on a panic (`panic = "abort"`), so:
//!
//! * Logs go to a file under the app's data folder, `logs\remotely.YYYY-MM-DD.log`, a new one each day and the
//!   last [`KEEP_LOG_FILES`] kept. Each line is written before the next starts, so nothing waits in a buffer when the
//!   app stops. `RUST_LOG` changes the level as before.
//! * A panic writes `logs\crash-<time>.txt` first (time, version, thread, message, where, backtrace), and the log
//!   gets the message too. The last [`KEEP_CRASH_FILES`] are kept.
//! * When the app can't start, a Windows message box says what failed and where the log is. A database that won't
//!   open or migrate can be set aside (renamed, never deleted) to start with an empty one, only if the user says so.
//!
//! What reaches the log has no secret (CLAUDE.md rule 7): the core never logs one, and the text of a panic or a UI
//! error, which could hold anything, is shortened and passes [`redact_secrets`] first.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use remotely_core::export::redact_secrets;
use remotely_core::terminal::log::{clock, local_now, offset_label};
use serde::Serialize;
use tauri::State;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

use crate::ipc::IpcError;

/// The folder under the app's data folder (Tauri's `app_log_dir`).
pub const LOG_FOLDER: &str = "logs";
pub const LOG_PREFIX: &str = "remotely";
pub const LOG_SUFFIX: &str = "log";
/// Days of logs kept.
pub const KEEP_LOG_FILES: usize = 7;
/// Crash files kept.
pub const KEEP_CRASH_FILES: usize = 7;
/// What is logged unless `RUST_LOG` says otherwise.
pub const DEFAULT_FILTER: &str = "info,sqlx=warn,tao=warn,wry=warn";
/// The longest panic or UI error message kept, in characters.
const MAX_MESSAGE_CHARS: usize = 2_000;
/// The longest backtrace kept in a crash file, in bytes.
const MAX_BACKTRACE_BYTES: usize = 64 * 1024;

/// Set once a message box has told the user why the start failed, so a second one doesn't repeat it.
static EXPLAINED: AtomicBool = AtomicBool::new(false);

/// A daily log file in `dir`, the last [`KEEP_LOG_FILES`] kept.
pub fn file_appender(dir: &Path) -> Result<RollingFileAppender, String> {
    std::fs::create_dir_all(dir).map_err(|err| format!("can't create {}: {err}", dir.display()))?;
    RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(LOG_PREFIX)
        .filename_suffix(LOG_SUFFIX)
        .max_log_files(KEEP_LOG_FILES)
        .build(dir)
        .map_err(|err| format!("can't open a log file in {}: {err}", dir.display()))
}

/// Logs to stdout (seen in `npm run tauri dev`) and to the daily file in `log_dir`. Call once, first thing.
/// Returns why there is no log file, if there isn't one.
pub fn init_logging(log_dir: Option<&Path>) -> Option<String> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    let (file, problem) = match log_dir.map(file_appender) {
        Some(Ok(appender)) => (Some(fmt::layer().with_ansi(false).with_writer(appender)), None),
        Some(Err(problem)) => (None, Some(problem)),
        None => (None, Some("the app's data folder is not known".to_owned())),
    };
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .with(file)
        .try_init();
    problem
}

/// Writes a crash file in `log_dir` (and the message to the log) before a panic ends the app.
pub fn install_panic_hook(log_dir: Option<PathBuf>) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let report = CrashReport::of(info);
        tracing::error!(location = %report.location, thread = %report.thread, "panic: {}", report.message);
        if let Some(dir) = &log_dir {
            match report.write(dir) {
                Ok(path) => tracing::error!(file = %path.display(), "crash report written"),
                Err(err) => tracing::error!(error = %err, "could not write a crash report"),
            }
        }
        previous(info);
    }));
}

/// What a crash file holds.
pub struct CrashReport {
    pub time: String,
    pub version: &'static str,
    pub thread: String,
    pub message: String,
    pub location: String,
    pub backtrace: String,
}

impl CrashReport {
    fn of(info: &std::panic::PanicHookInfo<'_>) -> Self {
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "(no message)".to_owned());
        let location = info.location().map_or_else(
            || "unknown".to_owned(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );
        Self::new(
            &message,
            location,
            std::backtrace::Backtrace::force_capture().to_string(),
        )
    }

    pub fn new(message: &str, location: String, backtrace: String) -> Self {
        let now = local_now();
        let mut backtrace = backtrace;
        if backtrace.len() > MAX_BACKTRACE_BYTES {
            let mut cut = MAX_BACKTRACE_BYTES;
            while !backtrace.is_char_boundary(cut) {
                cut -= 1;
            }
            backtrace.truncate(cut);
            backtrace.push_str("\n(cut)");
        }
        Self {
            time: format!("{} {}", clock(now), offset_label(now)),
            version: env!("CARGO_PKG_VERSION"),
            thread: std::thread::current().name().unwrap_or("unnamed").to_owned(),
            message: clean_text(message),
            location,
            backtrace,
        }
    }

    pub fn text(&self) -> String {
        let mut text = String::new();
        let _ = writeln!(text, "Remotely {} panicked. A release build stops here.", self.version);
        let _ = writeln!(text, "Time: {}", self.time);
        let _ = writeln!(text, "Thread: {}", self.thread);
        let _ = writeln!(text, "Message: {}", self.message);
        let _ = writeln!(text, "Location: {}", self.location);
        let _ = writeln!(text, "Backtrace:\n{}", self.backtrace);
        text
    }

    /// `crash-YYYYMMDD-HHMMSS.txt` in `dir`; older ones beyond [`KEEP_CRASH_FILES`] go.
    pub fn write(&self, dir: &Path) -> io::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let path = unique(dir, &format!("crash-{}", stamp()), "txt");
        std::fs::write(&path, self.text())?;
        prune(dir, "crash-", ".txt", KEEP_CRASH_FILES);
        Ok(path)
    }
}

/// Text from outside (a panic, the UI) as the log may keep it: one paragraph, shortened, secrets redacted.
pub fn clean_text(text: &str) -> String {
    let short: String = text.chars().take(MAX_MESSAGE_CHARS).collect();
    let mut clean = redact_secrets(&short).0;
    if text.chars().count() > MAX_MESSAGE_CHARS {
        clean.push_str(" (cut)");
    }
    clean
}

/// `20261022-140322`, local time.
pub fn stamp() -> String {
    clock(local_now()).replace('-', "").replace(' ', "-").replace(':', "")
}

/// `<dir>\<stem>.<ext>`, or with `-2`, `-3`... when that is taken.
fn unique(dir: &Path, stem: &str, ext: &str) -> PathBuf {
    let mut path = dir.join(format!("{stem}.{ext}"));
    let mut n = 2;
    while path.exists() {
        path = dir.join(format!("{stem}-{n}.{ext}"));
        n += 1;
    }
    path
}

/// Keeps the newest `keep` files named `<prefix>...<suffix>` in `dir` (by name, which starts with the time).
fn prune(dir: &Path, prefix: &str, suffix: &str, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut names: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|n| n.starts_with(prefix) && n.ends_with(suffix))
        })
        .collect();
    names.sort();
    let extra = names.len().saturating_sub(keep);
    for old in names.into_iter().take(extra) {
        let _ = std::fs::remove_file(old);
    }
}

// ---- startup failures -------------------------------------------------------------------------------------------

/// Tells the user the app could not start, once (a second failure stays in the log only).
pub fn explain_startup_failure(what: &str, log_dir: Option<&Path>) {
    if EXPLAINED.swap(true, Ordering::SeqCst) {
        return;
    }
    let text = format!(
        "Remotely could not start.\n\n{}\n\n{}",
        clean_text(what),
        where_the_log_is(log_dir)
    );
    message_box("Remotely could not start", &text, Buttons::Ok);
}

/// The user has been told why the app quits (they declined a fresh database); nothing more to show.
pub fn mark_explained() {
    EXPLAINED.store(true, Ordering::SeqCst);
}

/// QL-15: the database won't open or migrate. Asks whether to set it aside and start with an empty one
/// (default: no, quit). True only on Yes.
pub fn offer_fresh_database(error: &str, newer_version: bool, db: &Path, log_dir: Option<&Path>) -> bool {
    let name = db.file_name().and_then(OsStr::to_str).unwrap_or("remotely.db");
    let newer = if newer_version {
        "A newer version of Remotely used this database last. Installing that version again opens it as it is.\n\n"
    } else {
        ""
    };
    let text = format!(
        "Remotely can't open its database ({name}):\n{}\n\n{newer}\
         Yes: keep it as a backup (renamed, nothing is deleted) and start with an empty database. Sessions, vault \
         items, settings and the audit log stay in the backup.\n\
         No: quit without changing anything.\n\n{}",
        clean_text(error),
        where_the_log_is(log_dir)
    );
    message_box("Remotely can't open its database", &text, Buttons::YesNo)
}

fn where_the_log_is(log_dir: Option<&Path>) -> String {
    match log_dir {
        Some(dir) => format!("The log is in {}", dir.display()),
        None => "There is no log file: the app's data folder could not be found.".to_owned(),
    }
}

/// QL-15: renames the database and its `-wal` and `-shm` files to `<stem>-unopenable-<time>.db` (and its
/// `-wal`, `-shm`), so they stay a working SQLite database together. Never deletes. Returns the new database path.
pub fn set_database_aside(db: &Path) -> io::Result<PathBuf> {
    let dir = db.parent().unwrap_or(Path::new("."));
    let stem = db.file_stem().and_then(OsStr::to_str).unwrap_or("remotely");
    let ext = db.extension().and_then(OsStr::to_str).unwrap_or("db");
    let aside = unique(dir, &format!("{stem}-unopenable-{}", stamp()), ext);
    rename_with_retry(db, &aside)?;
    for side in ["-wal", "-shm"] {
        let from = with_suffix(db, side);
        if from.exists() {
            rename_with_retry(&from, &with_suffix(&aside, side))?;
        }
    }
    Ok(aside)
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// A file the failed start just closed may stay in use for a moment.
fn rename_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    let mut tries = 0;
    loop {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(err) if tries < 20 && err.kind() != io::ErrorKind::NotFound => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(err) => return Err(err),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Buttons {
    Ok,
    YesNo,
}

/// A Windows message box (no window needed); true when the user pressed Yes.
#[cfg(windows)]
fn message_box(title: &str, text: &str, buttons: Buttons) -> bool {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONERROR, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO,
    };
    let style = match buttons {
        Buttons::Ok => MB_OK | MB_ICONERROR,
        Buttons::YesNo => MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
    } | MB_SETFOREGROUND
        | MB_TOPMOST;
    // SAFETY: both strings live until the call returns; no owner window.
    let answer = unsafe { MessageBoxW(None, &HSTRING::from(text), &HSTRING::from(title), style) };
    answer == IDYES
}

#[cfg(not(windows))]
fn message_box(title: &str, text: &str, _buttons: Buttons) -> bool {
    eprintln!("{title}\n{text}");
    false
}

// ---- Settings, About; UI errors -------------------------------------------------------------------------------------

/// Where the logs folder is, for Settings → About.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogsInfo {
    pub folder: Option<String>,
    pub keep_days: usize,
}

/// The logs folder, once known (set before the app starts).
pub struct LogsFolder(pub Option<PathBuf>);

#[tauri::command]
pub fn logs_info(folder: State<'_, LogsFolder>) -> LogsInfo {
    LogsInfo {
        folder: folder.0.as_ref().map(|p| p.display().to_string()),
        keep_days: KEEP_LOG_FILES,
    }
}

/// Settings → About: opens the logs folder in Explorer.
#[tauri::command]
pub fn logs_open(folder: State<'_, LogsFolder>) -> Result<(), IpcError> {
    let dir = folder
        .0
        .as_ref()
        .ok_or_else(|| IpcError::new("io", "There is no logs folder: the app's data folder is not known."))?;
    std::fs::create_dir_all(dir).map_err(|err| IpcError::new("io", format!("The logs folder can't be made: {err}")))?;
    open_folder(dir)
}

#[cfg(windows)]
fn open_folder(dir: &Path) -> Result<(), IpcError> {
    std::process::Command::new("explorer.exe")
        .arg(dir)
        .spawn()
        .map(drop)
        .map_err(|err| IpcError::new("io", format!("Explorer did not open: {err}")))
}

#[cfg(not(windows))]
fn open_folder(_dir: &Path) -> Result<(), IpcError> {
    Err(IpcError::new("unsupported", "Opening a folder needs Windows."))
}

/// QL-15: a page of the UI crashed (a React error boundary caught it). Logged, shortened and redacted, so the
/// log says what broke; nothing else happens here.
#[tauri::command]
pub fn ui_error(page: String, message: String, stack: Option<String>) {
    let page = clean_text(&one_line(&page.chars().take(64).collect::<String>()));
    let stack = stack.map(|s| clean_text(&one_line(&s))).unwrap_or_default();
    tracing::error!(%page, stack = %stack, "the UI crashed: {}", clean_text(&one_line(&message)));
}

/// A component stack (or any text) on one log line: its lines trimmed and joined with ` < `, the innermost first.
fn one_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" < ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("remotely-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_crash_file_says_when_what_and_where() {
        let dir = temp_dir("crash");
        let report = CrashReport::new(
            "index out of bounds: password=hunter2",
            "src\\x.rs:1:2".into(),
            "0: main".into(),
        );
        let path = report.write(&dir).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(path.file_name().unwrap().to_string_lossy().starts_with("crash-"));
        assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
        assert!(text.contains("Location: src\\x.rs:1:2"), "{text}");
        assert!(text.contains("Backtrace:\n0: main"), "{text}");
        assert!(text.contains("index out of bounds"), "{text}");
        assert!(
            !text.contains("hunter2"),
            "a secret in a panic message is redacted: {text}"
        );
    }

    #[test]
    fn only_the_last_crash_files_are_kept() {
        let dir = temp_dir("crashes");
        for i in 0..KEEP_CRASH_FILES + 3 {
            std::fs::write(dir.join(format!("crash-20261001-0000{i:02}.txt")), "old").unwrap();
        }
        std::fs::write(dir.join("remotely.2026-10-01.log"), "log").unwrap();
        prune(&dir, "crash-", ".txt", KEEP_CRASH_FILES);
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(left.len(), KEEP_CRASH_FILES + 1, "{left:?}");
        assert!(
            left.contains(&"remotely.2026-10-01.log".to_owned()),
            "logs are not crash files"
        );
        assert!(
            !left.contains(&"crash-20261001-000000.txt".to_owned()),
            "the oldest went: {left:?}"
        );
    }

    #[test]
    fn a_component_stack_goes_on_one_line() {
        let stack = "
    at KnownHostsPage (http://localhost:1420/src/pages/KnownHostsPage.tsx:23:34)
    at ErrorBoundary (x.tsx:19:8)
";
        assert_eq!(
            one_line(stack),
            "at KnownHostsPage (http://localhost:1420/src/pages/KnownHostsPage.tsx:23:34) < at ErrorBoundary (x.tsx:19:8)"
        );
    }

    #[test]
    fn long_text_is_cut_and_redacted() {
        let long = format!("token=abc123 {}", "x".repeat(5_000));
        let clean = clean_text(&long);
        assert!(clean.ends_with(" (cut)"));
        assert!(clean.chars().count() < 2_100);
        assert!(!clean.contains("abc123"), "{clean}");
    }

    #[test]
    fn a_database_set_aside_keeps_its_wal_and_shm_beside_it() {
        let dir = temp_dir("aside");
        let db = dir.join("remotely.db");
        for (name, body) in [
            ("remotely.db", "db"),
            ("remotely.db-wal", "wal"),
            ("remotely.db-shm", "shm"),
        ] {
            std::fs::write(dir.join(name), body).unwrap();
        }
        let aside = set_database_aside(&db).unwrap();
        let name = aside.file_name().unwrap().to_string_lossy().into_owned();
        let read = |p: PathBuf| std::fs::read_to_string(p).unwrap();
        assert!(
            name.starts_with("remotely-unopenable-") && name.ends_with(".db"),
            "{name}"
        );
        assert_eq!(read(aside.clone()), "db");
        assert_eq!(read(with_suffix(&aside, "-wal")), "wal");
        assert_eq!(read(with_suffix(&aside, "-shm")), "shm");
        assert!(
            !db.exists() && !with_suffix(&db, "-wal").exists(),
            "nothing is left under the old name"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_log_file_is_daily_in_the_logs_folder() {
        use std::io::Write as _;
        let dir = temp_dir("logs");
        let mut appender = file_appender(&dir.join(LOG_FOLDER)).unwrap();
        appender.write_all(b"hello\n").unwrap();
        appender.flush().unwrap();
        let names: Vec<String> = std::fs::read_dir(dir.join(LOG_FOLDER))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(
            names[0].starts_with("remotely.") && names[0].ends_with(".log"),
            "{names:?}"
        );
    }
}
