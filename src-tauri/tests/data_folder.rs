//! QL-15: the data folder the app works out before it starts (so the log file can open first) is where Tauri
//! keeps the database, and its `logs` folder is Tauri's own log folder, in every build. On Tauri's mock runtime.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsString;

use remotely_lib::data_dirs::{app_directories_override, data_root};
use remotely_lib::diagnostics::LOG_FOLDER;
use tauri::test::{mock_builder, mock_context, noop_assets};
use tauri::Manager;

const IDENTIFIER: &str = "com.remotely.desktop";

#[test]
fn the_log_folder_is_tauris_app_log_dir() {
    let custom = std::env::temp_dir().join("remotely-data");
    for (data_dir, debug_build) in [
        (None, false),
        (None, true),
        (Some(OsString::from(custom.clone())), false),
        (Some(OsString::from(custom.clone())), true),
    ] {
        let mut context = mock_context(noop_assets());
        context.config_mut().identifier = IDENTIFIER.into();
        context.config_mut().app.app_directories_override =
            app_directories_override(data_dir.clone(), IDENTIFIER, debug_build).unwrap();
        let app = mock_builder().build(context).unwrap();
        let root = data_root(data_dir.clone(), IDENTIFIER, debug_build).unwrap();
        assert_eq!(
            app.path().app_local_data_dir().unwrap(),
            root,
            "{data_dir:?} {debug_build}"
        );
        assert_eq!(
            app.path().app_log_dir().unwrap(),
            root.join(LOG_FOLDER),
            "{data_dir:?} {debug_build}"
        );
    }
}
