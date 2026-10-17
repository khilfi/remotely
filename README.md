# Remotely

A Windows desktop app for forward deployed engineers and IT admins: bulk control of VMware Workstation Pro VMs, a
performance dashboard, a PuTTY/MobaXterm-style SSH session manager and bulk command execution with grouped output, with
multi-step approvals on every high-impact action.

The requirements are in [docs/PRD.md](docs/PRD.md); project rules for contributors (and Claude Code) are in
[CLAUDE.md](CLAUDE.md). This repository is public: read "Public repository rules" in CLAUDE.md before committing.

**Status:** MVP skeleton. The app lists running Workstation VMs, and every VM action goes through the command bus, policy
engine, approval dialog and job runner with a hash-chained audit log. Auto-update checks this repo's GitHub Releases. SSH,
the vault and metrics are stubs behind their interfaces.

## Prerequisites

- Windows 10 or 11 (x64) with VMware Workstation Pro 17 or later
- Node.js LTS and npm
- Rust (stable, `x86_64-pc-windows-msvc`) via rustup, plus the Microsoft C++ Build Tools ("Desktop development with C++")
- The WebView2 runtime (included in Windows 11)
- Git, the GitHub CLI (`gh`) and [gitleaks](https://github.com/gitleaks/gitleaks) for the pre-commit secret scan

## Build and run

```bash
npm install
git config core.hooksPath .githooks   # once per clone: gitleaks runs before every commit
npm run tauri dev                     # the app, with hot reload for the UI
```

The app keeps its database under `%LOCALAPPDATA%\com.remotely.desktop\`, never in the working directory. It finds
`vmrun.exe` from Settings, then the `REMOTELY_VMRUN` environment variable, then the registry, then the default install
folders.

## Checks

| What                                 | Command                                                                               |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| Rust tests (core and shell)          | `cargo test --workspace`                                                              |
| Rust lint                            | `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` |
| UI lint (types, ESLint, Prettier)    | `npm run lint`                                                                        |
| Format the UI                        | `npm run format`                                                                      |
| Opt-in test against real Workstation | `REMOTELY_IT=1 cargo test -p remotely-core --test workstation_it`                     |

Tests use the fake adapters in `crates/core/src/fakes.rs` and never touch a real VM or host. The opt-in test only runs
`vmrun list`.

## Release

1. Bump the version in `package.json`, `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json` (they must match).
2. Commit, then `git tag -a vX.Y.Z -m "<release notes>"` and `git push origin vX.Y.Z`. The tag message becomes the
   release notes, which installed apps show in their update banner.
3. `.github/workflows/release.yml` builds the NSIS installer on Windows (per-user, so installing and updating need no
   admin rights), signs the update artifacts and creates a **draft** release
   with the installer, its `.sig` file and `latest.json`. It stops if the tag and the three versions differ, or if the
   updater public key in `tauri.conf.json` is still the placeholder. Afterwards it checks the update signatures against
   that public key (`scripts/verify-update-signature.mjs`); if this step fails, the signing secret and the public key
   don't pair, so don't publish the draft.
4. Smoke-test the installer from the draft, then publish it. Installed apps only see published releases; they check at
   start and every 24 hours (FD-14), and installing asks first.

`.github/workflows/ci.yml` runs on every push to `main` and every pull request: a gitleaks scan of the full history, UI
lint and build, and Rust fmt, clippy and tests.

### Update signing

Updates are signed with a key pair. Only the public key is in the repo (`plugins.updater.pubkey` in
`src-tauri/tauri.conf.json`). The private key and its password live outside the repo, in a password manager and in the
GitHub Actions secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. Losing them means installed
apps can no longer verify updates, so each machine would need a manual reinstall.

A local `npm run tauri build` needs the same two values as environment variables, because `createUpdaterArtifacts` is on.

## Layout

```text
crates/core/          Rust core, no Tauri types (reusable by a future CLI or plugins, FD-12)
  migrations/         sqlx migrations (SQLite, WAL mode)
  src/                command bus, policy engine, job runner, adapters, metrics, vault, store
  tests/              end-to-end tests with fake adapters; opt-in Workstation test
src-tauri/            Tauri 2 shell: window, IPC commands, terminal bridge
src/                  React + TypeScript UI (shadcn/ui on Tailwind CSS)
  components/ui/      shadcn/ui components, kept as generated
docs/                 PRD and diagrams
```

The core is its own crate so its tests build without Tauri and so it cannot depend on UI types.

### UI components

The UI uses [shadcn/ui](https://ui.shadcn.com) (Radix base, Nova preset, Lucide icons) on Tailwind CSS 4. Add components
with `npx shadcn@latest add <name>`; they land in `src/components/ui/` and are excluded from ESLint and Prettier so
updates diff cleanly. The shadcn base styles are inlined in `src/styles.css` (`shadcn eject`), so the shadcn CLI is not
a dependency of the app. App-specific colours (risk tiers, environment labels) are tokens at the end of that file.

## Modules and requirements

| Module            | Path                                                | PRD requirements                                                           | State                                                                                                                   |
| ----------------- | --------------------------------------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Command bus       | `crates/core/src/command_bus.rs`                    | AP-02, AP-03, AP-06, VM-02, VM-03, VM-04, BX-02, FD-14                     | Working: the only way to enqueue a job                                                                                  |
| Policy engine     | `crates/core/src/policy/`                           | AP-01, AP-04, SS-06 (Prod raises the tier), BX-06                          | Working; every tier rule has a unit test                                                                                |
| Job runner        | `crates/core/src/jobs.rs`                           | VM-05, VM-06, AP-03 (countdown), BX-02, BX-04 (cancel), FD-14 (runs alone) | Working; BX-04 retry is a stub                                                                                          |
| VMware adapter    | `crates/core/src/adapters/vmware.rs`                | VM-01, VM-02, VM-03, VM-04                                                 | `vmrun` list, power and snapshots; vmrest later                                                                         |
| Remote adapter    | `crates/core/src/adapters/remote.rs`                | SS-03, SS-05, BX-02, BX-07, MO-02                                          | Stub; the terminal uses a loopback shell                                                                                |
| Host counters     | `crates/core/src/adapters/host_counters.rs`         | MO-01, MO-04, VM-07                                                        | Stub                                                                                                                    |
| Updater           | `crates/core/src/adapters/updater.rs`               | FD-14                                                                      | Works: checks GitHub Releases; install is a Medium-tier job that runs alone; real adapter in `src-tauri/src/updater.rs` |
| Inventory         | `crates/core/src/inventory.rs`                      | VM-01                                                                      | Running VMs from `vmrun list`                                                                                           |
| Metrics collector | `crates/core/src/metrics.rs`                        | MO-01, MO-02, MO-03, MO-04                                                 | Polling loop works; sources are stubs                                                                                   |
| Vault             | `crates/core/src/vault.rs`                          | SS-04, AP-06                                                               | Stub, always locked, so Critical actions are refused                                                                    |
| Store             | `crates/core/src/store/`, `crates/core/migrations/` | AP-05, VM-01, SS-01, NFR Reliability                                       | Working: hash-chained audit log, job journal                                                                            |
| Fake adapters     | `crates/core/src/fakes.rs`                          | Development safety                                                         | One fake per outside system                                                                                             |
| Tauri shell       | `src-tauri/src/`                                    | All IPC                                                                    | Working                                                                                                                 |
| UI                | `src/`                                              | FD-01, VM-01, VM-02, AP-02, AP-03, AP-05                                   | VM list, approval dialog, terminal, activity, settings                                                                  |
