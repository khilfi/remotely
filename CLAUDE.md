# Remotely

A Windows desktop app for forward deployed engineers and IT admins: bulk control of VMware Workstation Pro VMs, a performance dashboard, a PuTTY/MobaXterm-style SSH session manager, and bulk command execution with grouped output, with multi-step approvals on every high-impact action.

The source of truth is `docs/PRD.md`. Requirements have IDs (VM-xx, SS-xx, BX-xx, AP-xx, MO-xx, FD-xx); refer to them in code comments, tests and commit messages. The PRD uses the working title "VM & SSH Manager"; the product name is **Remotely** (app identifier `com.remotely.desktop`).

## Locked decisions

- Stack: Tauri 2, Rust core (tokio), React + TypeScript + Vite UI, xterm.js, uPlot, SQLite via sqlx, russh for SSH.
- UI components: shadcn/ui (Radix base, Nova preset, Lucide icons) on Tailwind CSS 4. Build screens from shadcn components first; write custom CSS only for what shadcn does not cover (e.g. the xterm.js host).
- Single user only. No team mode, no server component.
- Windows 10/11 x64 with VMware Workstation Pro 17 or later. No Linux host support.
- RDP means launching `mstsc.exe` with a generated .rdp file (v3).
- Ansible: inventory export only (v2). The app never runs playbooks.
- **This repository is public.** Code and releases live in one public GitHub repo. Installed apps auto-update from its GitHub Releases (FD-14). See "Public repository rules" below.
- MVP scope is locked at 32 requirements: VM-01 to VM-07, SS-01 to SS-06, BX-01 to BX-07, AP-01 to AP-06, MO-01 to MO-04, FD-01 and FD-14. Do not build v2/v3 items unless asked. If a change would move something into or out of the MVP, stop and say so.

## Public repository rules (no credentials, PII or secrets)

Everything committed here is public forever, including git history.

- Never commit passwords, tokens, API keys, private keys (SSH, TLS, update-signing), certificates with private keys (`.pfx`, `.p12`), `.env` files, or real session exports (PuTTY `.reg`, MobaXterm `.mxtsessions`).
- Never commit real hostnames, IP addresses, usernames, customer names, logs, terminal recordings, audit or job exports, or app databases. This applies to code, tests, fixtures, docs and screenshots.
- Test data uses reserved examples only: hostnames under `example.com`, `example.org` or `.test`; IPs from `192.0.2.0/24`, `198.51.100.0/24` or `203.0.113.0/24`; usernames like `alice` and `bob`. Generate SSH keys inside tests at run time; never commit them.
- The app keeps its data (database, vault, logs, recordings) under `%APPDATA%` / `%LOCALAPPDATA%`, never in the working directory, so nothing private can land in the repo.
- A gitleaks scan runs as a pre-commit hook and in CI, and a finding fails the build. Never bypass it (`--no-verify`). If a secret was ever committed, stop and tell the user: it has to be revoked and replaced, because deleting it doesn't remove it from public history.
- Commits use the user's GitHub noreply email, never a personal email.
- Only the update-signing **public** key goes in `tauri.conf.json`. The private key and its password live only outside the repo on the user's machine and in the GitHub Actions secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. Claude never reads, prints or handles the private key or its password; the user sets those secrets.
- Pin third-party GitHub Actions to a full commit SHA.

## Releases and auto-update

- The version in `package.json`, `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json` must match. Release by pushing a tag `vX.Y.Z`.
- `.github/workflows/ci.yml` runs on every push and pull request: `cargo fmt --all --check`, clippy, `cargo test --workspace`, `npm run lint`, and gitleaks over the full history.
- `.github/workflows/release.yml` runs on `v*` tags on `windows-latest`. It uses `tauri-apps/tauri-action` to build, sign the update artifacts and create a **draft** GitHub Release with the installer, its `.sig` file and `latest.json`, then checks the signatures against `plugins.updater.pubkey` with `scripts/verify-update-signature.mjs` (a failure means the signing secret and the public key don't pair: don't publish). The user publishes the draft after a smoke test; installed apps only see published releases.
- `tauri.conf.json`: `bundle.createUpdaterArtifacts: true`; `plugins.updater.pubkey` holds the public key; `plugins.updater.endpoints` is `["https://github.com/khilfi/remotely/releases/latest/download/latest.json"]`; `plugins.updater.windows.installMode: "passive"`.
- Windows installer: NSIS only (`bundle.targets: ["nsis"]`), installed per user (`bundle.windows.nsis.installMode: "currentUser"`), so installing and auto-updating never need admin rights. Decided before v0.1.0; switching installer type after release would strand existing installs.
- In the app (FD-14): check at start and every 24 hours, and show the new version and its release notes. Installing is a Medium-tier command through the command bus, and it waits until no job is running. A setting turns update checks off for air-gapped sites.

## Architecture rules (non-negotiable)

1. **One way in for changes.** Every state-changing action (VM power, snapshots, remote commands, file writes, kills) is a typed command submitted to the command bus. It goes command bus -> policy engine -> job runner -> adapter. The UI, a future CLI, plugins and any AI helper never call `vmrun`, `vmrest` or SSH directly.
2. **Policy engine decides the tier** (Low, Medium, High, Critical; a Prod-labelled target moves an action up one tier) and the approval steps. Nothing runs at High or Critical without the approval answer from the UI. See the tier table in `docs/PRD.md`.
3. **Reads skip approval.** Inventory and metrics reads go adapters -> metrics collector -> store -> UI.
4. **Audit everything that changes state.** Append-only audit log, written when an action starts and when it ends, each entry hash-chained to the previous one.
5. **Every record carries `workspace_id` and `user_id`** from day one, even though the MVP has one workspace and one user.
6. **One adapter per outside system** (VMware, remote/SSH, host counters), each behind a Rust trait so tests can use a fake.
7. **Secrets live only in the vault.** Never put passwords, keys or passphrases in logs, audit entries, job output, exports, error messages or the UI state. The vault hands secrets to adapters only.

## Layout

A Cargo workspace: the core is its own crate with no Tauri types, so its tests build without Tauri, it cannot depend on UI code, and a future CLI or plugin host (FD-12) can reuse it.

```text
CLAUDE.md
Cargo.toml            workspace: crates/core + src-tauri; shared lints (no unwrap/expect)
.github/workflows/    ci.yml, release.yml
.githooks/            pre-commit (gitleaks)
docs/                 PRD.md, architecture.png, roadmap.png
crates/core/          remotely-core: all app logic
  migrations/         sqlx migrations
  src/
    command_bus.rs
    policy/
    jobs.rs
    adapters/         vmware.rs, remote.rs, host_counters.rs, updater.rs
    inventory.rs
    capacity.rs       VM-07 capacity check before power-on
    snapshots.rs      VM-04 snapshot trees (from .vmsd), VM-05 safety snapshot names
    impact.rs         AP-02 impact preview for the approval dialog
    export.rs         AP-05 audit log CSV export and secret redaction
    metrics.rs
    vault.rs
    store/
    fakes.rs          one fake per adapter (feature `fakes`; tests only)
  tests/              end-to-end tests with fakes; opt-in workstation_it.rs
src-tauri/            Tauri 2 shell: window, IPC commands (ipc.rs), terminal bridge
src/                  React + TypeScript UI
  components/ui/      shadcn/ui components (generated)
  components/         app components (approval dialog, badges)
  pages/              one file per page
  lib/                api.ts (typed IPC wrappers), theme.ts, utils.ts
```

## VMware Workstation facts

- `vmrun.exe` is under `C:\Program Files (x86)\VMware\VMware Workstation\` in older releases and under `C:\Program Files\VMware\VMware Workstation\` in newer ones (e.g. Workstation 26). Never hard-code it: the app uses the path saved in Settings, then `REMOTELY_VMRUN`, then the registry's `InstallPath`, then both default folders (`adapters::vmware::locate_vmrun`).
- Always pass `-T ws`. `vmrun -T ws list` lists running VMs only. To find all VMs, read Workstation's library (`%APPDATA%\VMware\inventory.vmls`) and scan user-chosen folders for `.vmx` files (`adapters::vmware::parse_vmls`, `scan_for_vmx`). In the library each entry is `vmlistN.config = "<path to .vmx>"` with `vmlistN.DisplayName`; folders have `vmlistN.Type = "2"` and deleted slots an empty `config`.
- Snapshots: vmrun gives names only. The tree and creation times are in `<vm>.vmsd` next to the .vmx (`snapshotN.uid`,
  `.parent`, `.displayName`, `.createTimeHigh`/`.createTimeLow` = microseconds since 1970 split in two 32-bit halves, the
  low one signed; `snapshot.current` is "you are here"). No .vmsd, or an empty one, means no snapshots. vmrun refuses a
  name the VM already has, and reads `/` in a name as a path (`base/child`), so names with `/` can't be reverted or
  deleted by name.
- A running VM's start time (power-on or resume) is the first token of the first line of `vmware.log` in its folder.
- A suspended VM's `.vmx` has a non-empty `checkpoint.vmState`. `guestInfo.detailed.data` holds the guest's `prettyName` once VMware Tools has reported it. Values may escape characters as `|XX` (hex).
- Power: `start <vmx> [gui|nogui]`, `stop <vmx> [soft|hard]`, `reset <vmx> [soft|hard]`, `suspend <vmx> [soft|hard]`, `pause <vmx>`, `unpause <vmx>`.
- Snapshots: `snapshot`, `listSnapshots`, `revertToSnapshot`, `deleteSnapshot`.
- Guest operations (`runProgramInGuest`, file copy) need `-gu`/`-gp` guest credentials on the command line, so other processes on the host can see them. Use guest operations only on demand, and never log the command line.
- `vmrest.exe` (same folder) is a local REST API, by default on 127.0.0.1:8697. It needs a one-time credential setup (`vmrest -C`, which is interactive). Treat it as optional and fall back to `vmrun`.
- Each running VM is a `vmware-vmx.exe` process whose command line contains the `.vmx` path. Use that to map Windows performance counters (CPU, memory, I/O) to a VM.

## Development safety

- Unit and integration tests must never stop, reset, suspend, revert or delete snapshots on real VMs. Use the fake VMware adapter.
- Tests against real Workstation are opt-in: they run only when `REMOTELY_IT=1` is set, and only touch VMs whose display name starts with `it-`.
- Don't connect to real SSH hosts in tests. Use a local test server or a fake.

## Commands

- Install: `npm install`
- Run the app: `npm run tauri dev`. A debug build keeps its data (database, WebView2 profile) in `%LOCALAPPDATA%\com.remotely.desktop.dev`, apart from the installed app's `%LOCALAPPDATA%\com.remotely.desktop`, so its migrations never reach the installed app's database. `REMOTELY_DATA_DIR` (an absolute path outside the repo) overrides both.
- Rust tests: `cargo test --workspace` (run at the repo root; `cargo test` inside `src-tauri/` only tests the shell crate)
- Opt-in test against real Workstation (reads only: the library, `vmrun list`, Tools state and IP of running VMs): `REMOTELY_IT=1 cargo test -p remotely-core --test workstation_it`
- Lint: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `npm run lint` (tsc, ESLint, Prettier)
- Format: `cargo fmt --all`, `npm run format`
- Build the installer: `npm run tauri build`
- Release: bump the version in all three files, commit, then `git tag -a vX.Y.Z -m "<release notes>"` and `git push origin vX.Y.Z`; publish the draft release on GitHub after a smoke test. The tag message is the release notes users see in the update banner, so write it for them.

## Conventions

- Rust stable, edition 2021. Errors with `thiserror`. No `unwrap()`/`expect()` outside tests.
- TypeScript in strict mode. ESLint and Prettier.
- shadcn/ui: add components with `npx shadcn@latest add <name>`. They land in `src/components/ui/` and stay as generated (that folder and `src/hooks/use-mobile.ts` are excluded from ESLint and Prettier so updates diff cleanly). The shadcn base styles are inlined in `src/styles.css` (`shadcn eject`), so the `shadcn` package is not an app dependency; don't add it back. App colour tokens (risk tiers, environment labels) live at the end of `src/styles.css`. Import from `@/…` (alias for `src/`).
- Dark mode is the `dark` class on `<html>`, set by `src/lib/theme.ts` ("system" follows Windows).
- App icon: the master is `src-tauri/app-icon.png` (1024×1024, transparent). After changing it, run `npx tauri icon src-tauri/app-icon.png`, delete the generated `src-tauri/icons/android` and `src-tauri/icons/ios` folders (desktop only), and copy `src-tauri/icons/128x128.png` to `src/assets/remotely-logo.png` and `src-tauri/icons/64x64.png` to `public/favicon.png`.
- Every policy-engine rule has a unit test.
- Commit messages start with the requirement ID where one applies, e.g. `VM-02: bulk suspend and resume`.
