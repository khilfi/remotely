//! QL-15, CLAUDE.md rule 7: since the app writes its log to a file, every log call in the core and the shell is
//! checked here: no field, value or format argument may name a password, passphrase, secret, token, private key or
//! credential. The message text itself may (it is a fixed string). Values that are secrets never reach a log call in
//! the first place (the vault hands them to adapters only); this catches one being added by mistake.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

const LEVELS: [&str; 5] = ["trace", "debug", "info", "warn", "error"];
const SECRET_WORDS: [&str; 7] = [
    "password",
    "passphrase",
    "secret",
    "token",
    "private_key",
    "credential",
    "expose(",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The text between a macro's `(` at `start` and its matching `)`, with string literals kept whole.
fn macro_args(text: &str, start: usize) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start + 1..i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Splits macro arguments at top-level commas.
fn split_args(args: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for c in args.chars() {
        if in_string {
            current.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                current.push(c);
            }
            '(' | '[' | '{' => {
                depth += 1;
                current.push(c);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => parts.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current);
    }
    parts
}

/// Each log call's non-literal arguments that name a secret: `(file, line, argument)`.
fn findings(files: &[PathBuf]) -> Vec<(String, usize, String)> {
    let mut found = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(file).unwrap();
        for level in LEVELS {
            let needle = format!("tracing::{level}!(");
            let mut from = 0;
            while let Some(at) = text[from..].find(&needle) {
                let open = from + at + needle.len() - 1;
                from = open + 1;
                let Some(args) = macro_args(&text, open) else {
                    continue;
                };
                for arg in split_args(args) {
                    let arg = arg.trim();
                    if arg.starts_with('"') || arg.starts_with("target:") {
                        continue;
                    }
                    let lower = arg.to_lowercase();
                    if SECRET_WORDS.iter().any(|w| lower.contains(w)) {
                        let line = text[..open].lines().count();
                        found.push((file.display().to_string(), line, arg.to_owned()));
                    }
                }
            }
        }
    }
    found
}

#[test]
fn no_log_call_names_a_secret() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&core.join("src"), &mut files);
    rust_files(&core.join("../../src-tauri/src"), &mut files);
    assert!(files.len() > 100, "the sources were found: {}", files.len());
    let found = findings(&files);
    assert!(found.is_empty(), "log calls that name a secret: {found:#?}");
}

#[test]
fn the_check_finds_a_secret_field_and_skips_the_message() {
    let dir = std::env::temp_dir().join(format!("remotely-log-fields-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("sample.rs");
    std::fs::write(
        &file,
        r#"
        fn a() { tracing::warn!(error = %err, "the vault password was wrong"); }
        fn b() { tracing::info!(password = %pw, "logged in"); }
        fn c() { tracing::debug!("token: {}", token.expose()); }
        fn d() { tracing::error!(host = %format!("{}({})", a, b), "x"); }
        "#,
    )
    .unwrap();
    let found = findings(&[file]);
    let _ = std::fs::remove_dir_all(&dir);
    let mut args: Vec<&str> = found.iter().map(|(_, _, arg)| arg.as_str()).collect();
    args.sort_unstable();
    assert_eq!(args, ["password = %pw", "token.expose()"]);
}
