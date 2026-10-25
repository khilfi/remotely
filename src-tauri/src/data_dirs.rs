//! Where the app keeps its data (the database, WebView2's profile, logs): Tauri's app directories for this build,
//! and the same folder as a path before the app exists (QL-15: the log file starts first).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tauri::utils::config::AppDirectoriesOverride;

/// Moves Tauri's app directories (the database and WebView2's profile) for this build.
///
/// A debug build (`npm run tauri dev`) uses `%LOCALAPPDATA%\com.remotely.desktop.dev`. Otherwise it would share the
/// installed app's folder: a migration it adds would reach the installed app's database, which the older release then
/// refuses to open, and its window would join the installed app's WebView2 browser process, which ignores
/// `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`. A release build keeps Tauri's default, `%LOCALAPPDATA%\com.remotely.desktop`.
/// `REMOTELY_DATA_DIR` overrides both. It must be absolute: Tauri resolves a relative override next to the executable,
/// which for a dev build is inside the working directory.
pub fn app_directories_override(
    data_dir: Option<OsString>,
    identifier: &str,
    debug_build: bool,
) -> Result<Option<AppDirectoriesOverride>, &'static str> {
    match data_dir.filter(|dir| !dir.is_empty()).map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => Ok(Some(AppDirectoriesOverride::Root(dir))),
        Some(_) => Err("REMOTELY_DATA_DIR must be an absolute path outside the repository"),
        None if debug_build => Ok(Some(AppDirectoriesOverride::Root(
            Path::new("$LOCALDATA").join(format!("{identifier}.dev")),
        ))),
        None => Ok(None),
    }
}

/// QL-15: the app's data folder as Tauri will resolve [`app_directories_override`]'s answer, known before the
/// app exists, so the log file can start first: `REMOTELY_DATA_DIR`, else `%LOCALAPPDATA%\<identifier>` (`.dev` for
/// a debug build). Its `logs` folder is Tauri's `app_log_dir`.
pub fn data_root(data_dir: Option<OsString>, identifier: &str, debug_build: bool) -> Result<PathBuf, &'static str> {
    match data_dir.filter(|dir| !dir.is_empty()).map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => Ok(dir),
        Some(_) => Err("REMOTELY_DATA_DIR must be an absolute path outside the repository"),
        None => {
            let local = dirs::data_local_dir().ok_or("Windows did not say where %LOCALAPPDATA% is")?;
            Ok(if debug_build {
                local.join(format!("{identifier}.dev"))
            } else {
                local.join(identifier)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTIFIER: &str = "com.remotely.desktop";

    // That `data_root` is where Tauri puts the app's data and logs is checked on the mock runtime in
    // tests/data_folder.rs: only integration tests get the Common Controls manifest the mock runtime needs (build.rs).

    #[test]
    fn a_relative_data_folder_has_no_log_folder_either() {
        assert!(data_root(Some("data".into()), IDENTIFIER, false).is_err());
    }

    #[test]
    fn release_build_keeps_the_default_folder() {
        assert_eq!(app_directories_override(None, IDENTIFIER, false), Ok(None));
    }

    #[test]
    fn debug_build_uses_a_dev_folder_next_to_it() {
        assert_eq!(
            app_directories_override(None, IDENTIFIER, true),
            Ok(Some(AppDirectoriesOverride::Root(
                Path::new("$LOCALDATA").join("com.remotely.desktop.dev")
            )))
        );
    }

    #[test]
    fn remotely_data_dir_overrides_both_builds() {
        let dir = std::env::temp_dir().join("remotely-data");
        for debug_build in [false, true] {
            assert_eq!(
                app_directories_override(Some(dir.clone().into()), IDENTIFIER, debug_build),
                Ok(Some(AppDirectoriesOverride::Root(dir.clone())))
            );
        }
    }

    #[test]
    fn empty_remotely_data_dir_counts_as_unset() {
        assert_eq!(
            app_directories_override(Some(OsString::new()), IDENTIFIER, false),
            Ok(None)
        );
        assert_eq!(
            app_directories_override(Some(OsString::new()), IDENTIFIER, true),
            app_directories_override(None, IDENTIFIER, true)
        );
    }

    #[test]
    fn relative_remotely_data_dir_is_refused() {
        assert!(app_directories_override(Some("data".into()), IDENTIFIER, true).is_err());
        assert!(app_directories_override(Some("data".into()), IDENTIFIER, false).is_err());
    }
}
