fn main() {
    tauri_build::build();

    // tauri-build embeds the app manifest (Common Controls v6) into the app's executable only. The
    // FD-14 updater tests run an app on Tauri's mock runtime, which links Common Controls v6
    // functions too, so the test executables need the same dependency or Windows refuses to start
    // them (STATUS_ENTRYPOINT_NOT_FOUND).
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-tests=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-tests=/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
        );
    }
}
