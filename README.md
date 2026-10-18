# Remotely

A Windows desktop app for forward deployed engineers and IT admins: bulk control of VMware Workstation Pro VMs, a
performance dashboard, a PuTTY/MobaXterm-style SSH session manager and bulk command execution with grouped output, with
multi-step approvals on every high-impact action.

The requirements are in [docs/PRD.md](docs/PRD.md); project rules for contributors (and Claude Code) are in
[CLAUDE.md](CLAUDE.md). This repository is private while the app is field-tested, but it may go public later and git
history is forever, so it follows the "Public repository rules" in CLAUDE.md: read them before committing.

**Status:** MVP milestones 1 (VMs and power), 2 (snapshots and approvals) and 3 (vault and session library). The app
lists every Workstation VM (the library, chosen folders and running VMs) with its OS, CPU, RAM, IP and VMware Tools
state; selects by click, shift-click, tag or saved filter; starts, shuts down (then forces off only after a separate
Critical approval), suspends, pauses and resets them in bulk; checks host capacity before a power-on; skips protected
VMs; and labels VMs Lab, Staging or Prod (Prod raises the approval tier). The snapshot manager shows each VM's snapshot
tree with creation times (read from its `.vmsd`), flags snapshots
older than 30 days, and takes, reverts and deletes snapshots in bulk; high-risk VM actions take a named safety snapshot
first. Approval rules are editable in Settings; the approval dialog previews each VM's state, uptime and snapshot count,
and its countdown can be cancelled from the dialog or from Activity. The hash-chained audit log exports to CSV.
Auto-update checks this repo's GitHub Releases, with a read-only GitHub token kept in the vault (see
[GitHub update token](#github-update-token)). The vault keeps passwords, private keys and passphrases encrypted
(AES-256-GCM per item, the key wrapped by DPAPI and an Argon2id-derived vault password), unlocks with the Windows login
or the vault password and locks after 15 minutes idle; Critical actions ask for the vault password again. The session
library stores SSH sessions in folders with tags, colours, search and an environment label (Prod raises the approval
tier). The SSH terminal, imports and bulk runs with grouped output work over russh. The dashboard shows every running VM's CPU, RAM and disk I/O read from its `vmware-vmx.exe` process (no login), and its share of this host's CPU and RAM (also on the VM list), Linux guest metrics over SSH for watched sessions, colour thresholds, live charts and a host capacity panel. Sessions link to the VMs they reach on their own when their host is a VM's guest IP address, so those VMs work in bulk runs and guest metrics without linking by hand. Ctrl+K opens a command palette for pages, VMs, sessions and actions.
Sessions, folders, tags, labels, trusted host keys and (only when ticked) vault secrets move to another laptop in one
encrypted file (Argon2id from a passphrase, AES-256-GCM), imported with a preview that lets you skip, replace or keep
both of each conflicting item. The SSH key manager on the Vault page generates Ed25519 or RSA 4096 keys straight into
the vault, copies their public keys, lets sessions log in with them and pushes a public key to many hosts'
`authorized_keys` through the approval flow.

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

The installed app keeps its database and WebView2 profile under `%LOCALAPPDATA%\com.remotely.desktop\`, never in the
working directory. A development build (`npm run tauri dev`) uses `%LOCALAPPDATA%\com.remotely.desktop.dev\` instead,
so the migrations it applies never reach the installed app's database and the two never share a WebView2 browser
process. To use another folder, set `REMOTELY_DATA_DIR` to an absolute path outside the repository. The app finds
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

Tests use the fake adapters in `crates/core/src/fakes.rs` and never touch a real VM or host. The opt-in test only reads:
Workstation's library, `vmrun list`, the Tools state and IP address of running VMs, and each VM's snapshots (it checks
that the `.vmsd` lists the same snapshots as `vmrun listSnapshots`).

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

`.github/workflows/ci.yml` runs on every push to `main` and every pull request, except changes to documentation only
(Markdown files anywhere, `docs/`): UI lint and build, and Rust fmt, clippy and tests. `.github/workflows/secrets.yml`
runs a gitleaks scan of the full history on every push to `main` and every pull request, documentation included.

### GitHub update token

The repository is private, so an installed app can't see its releases without a token. Each machine keeps a read-only
GitHub token in its vault, and update checks and installs use it. Copies on 0.2.0 or older don't know about the token:
install 0.2.1 by hand once on each machine (download the installer from the release page while signed in to GitHub),
then add the token.

**Create the token** (on GitHub, signed in as the repository owner):

1. Open [Settings → Developer settings → Personal access tokens → Fine-grained tokens](https://github.com/settings/personal-access-tokens)
   and choose **Generate new token**.
2. Name it after the machine, for example "Remotely updates, field laptop 2", so one lost laptop's token can be revoked
   on its own.
3. **Expiration:** pick a date (90 days is a good default). Remotely shows the date and warns two weeks before it.
4. **Resource owner:** the account that owns the repository. **Repository access:** _Only select repositories_, then
   this repository only.
5. **Permissions → Repository permissions → Contents: Read-only.** Leave everything else at _No access_ (GitHub adds
   Metadata: Read-only by itself).
6. **Generate token** and copy it. It starts with `github_pat_`, and GitHub shows it only once.

Contents: Read-only is the narrowest permission that can download release files, and it can also read the repository's
code. Treat the token like a password: one per machine, with an expiry, never in a file, chat or ticket.

**Enter it in Remotely:**

1. Unlock the vault (the lock in the sidebar).
2. Open **Settings → General → Updates → GitHub update token**, paste the token and choose **Save**.
3. Remotely stores it in the vault and tests it at once: "The token works: it can read …, and the latest release is …".
   **Test** repeats that check at any time.
4. Clear the clipboard (`Win+V` keeps a history: delete the entry there).

Without a token, update checks don't fail quietly: the banner and Settings say a token is needed. When the vault is
locked, the check waits and runs once the vault is unlocked.

**Replace it** before it expires, or at once if it may have leaked:

1. On GitHub, open the token and choose **Regenerate token** (same settings, new value; the old value stops working
   at once), or make a new one as above.
2. In Remotely, **Settings → Updates → Replace**, paste the new token and **Save**.
3. If you made a new token, delete the old one on GitHub.

Once a token has expired or been revoked, the banner says so ("The GitHub update token expired on …") until it is
replaced. **Remove** deletes the token from the vault; delete it on GitHub as well.

What the app does with the token: it sends it only to `api.github.com`, to find the latest published release, then to
fetch that release's `latest.json` and installer from their API download URLs. GitHub answers those with a redirect to
its file storage, and the token is not sent there. Every update is still checked against the signing public key before
it installs. The token never appears in logs, error messages, the audit log, exports or the UI.

### CI minutes

With the repository private, GitHub Actions minutes come out of the account's monthly allowance (2,000 minutes on GitHub
Free; Settings → Billing and plans shows what is left). Jobs on Windows runners count double, and each job is rounded up
to whole minutes:

| Workflow      | Runs on                                           | Billed minutes per run                                           |
| ------------- | ------------------------------------------------- | ---------------------------------------------------------------- |
| `ci.yml`      | every pull request push and every merge to `main` | about 12 to 16 (the Windows Rust job is 5 to 7 minutes, doubled) |
| `secrets.yml` | every pull request push and every merge to `main` | about 1 (Linux)                                                  |
| `release.yml` | every `v*` tag                                    | about 28 (14 minutes on Windows, doubled)                        |

To make them last: documentation-only changes skip `ci.yml`; a new push to a branch cancels the run it supersedes, so
push when a change is ready rather than after every small commit; and group documentation edits.

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
  src/                command bus, policy engine, job runner, adapters, metrics, vault, sessions, store
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

| Module            | Path                                                | PRD requirements                                                                                           | State                                                                                                                         |
| ----------------- | --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Command bus       | `crates/core/src/command_bus.rs`                    | AP-01 (saves rules), AP-02, AP-03, AP-06, VM-02, VM-03, VM-04, BX-02, FD-14                                | Working: the only way to enqueue a job; checks snapshot names; audits rule changes                                            |
| Policy engine     | `crates/core/src/policy/`                           | AP-01, AP-04, SS-06 (Prod raises the tier), BX-06, VM-05, VM-07 (warnings add a confirm)                   | Working; rules are checked before they are saved; every tier rule has a unit test                                             |
| Impact preview    | `crates/core/src/impact.rs`                         | AP-02                                                                                                      | Working: state, uptime (from `vmware.log`) and snapshot count per VM; logged-in users and dependent VMs later                 |
| Snapshot reads    | `crates/core/src/snapshots.rs`                      | VM-04, VM-05                                                                                               | Working: tree order, 30-day flag, safety snapshot names                                                                       |
| Audit export      | `crates/core/src/export.rs`                         | AP-05                                                                                                      | Working: CSV with hashes, secrets redacted, formula cells guarded                                                             |
| Job runner        | `crates/core/src/jobs.rs`                           | VM-03 (shutdown wait), VM-05, VM-06, AP-03 (countdown), AP-04, BX-02, BX-04 (cancel), FD-14 (runs alone)   | Working; BX-04 retry is a stub                                                                                                |
| VMware adapter    | `crates/core/src/adapters/vmware.rs`                | VM-01, VM-02, VM-03, VM-04, AP-02                                                                          | Library, folder scan, `.vmx` and `.vmsd` reading, `vmware.log` start time, `vmrun` list, power and snapshots; vmrest later    |
| Remote adapter    | `crates/core/src/adapters/remote.rs`                | SS-03, SS-05, BX-02, BX-07, MO-02                                                                          | Working: terminal shells, bulk exec with sudo, and connections kept open between guest-metric rounds                          |
| Host counters     | `crates/core/src/adapters/host_counters.rs`         | MO-01, MO-04, VM-07                                                                                        | Working: host RAM, CPUs, CPU times, free disk, and each `vmware-vmx.exe` process's CPU, working set and I/O                   |
| Updater           | `crates/core/src/adapters/updater.rs`, `github.rs`  | FD-14                                                                                                      | Works: GitHub Releases of the private repo with the token from the vault; install is a Medium-tier job that runs alone        |
| Inventory         | `crates/core/src/inventory.rs`                      | VM-01, VM-02, SS-06 (VM labels)                                                                            | Every VM from the library, chosen folders and `vmrun list`; filters; audited environment labels                               |
| Capacity check    | `crates/core/src/capacity.rs`                       | VM-07, MO-04                                                                                               | Working: host RAM vs assigned RAM, free disk on VM drives; the dashboard's capacity panel                                     |
| Metrics collector | `crates/core/src/metrics/`                          | MO-01, MO-02, MO-03, MO-04                                                                                 | Working: host-side and SSH guest sources every 5 s, 30 minutes of history in memory, collector cost                           |
| Vault             | `crates/core/src/vault/`                            | SS-04, AP-06                                                                                               | Working: AES-256-GCM per item; DPAPI and Argon2id key wrapping; 15-minute idle lock; values never leave it except to adapters |
| Session library   | `crates/core/src/sessions.rs`                       | SS-01, SS-06                                                                                               | Working: folders, tags, colours, search, credentials from the vault, jump host checks, audited changes                        |
| Export and import | `crates/core/src/transfer/`                         | FD-07                                                                                                      | Working: one encrypted file per export; preview with per-item conflict choices; audited with counts and the file path         |
| SSH key manager   | `crates/core/src/ssh_keys.rs`                       | SS-09                                                                                                      | Working: Ed25519 or RSA 4096 keys in the vault; public keys; attach to sessions; push to authorized_keys as a bus command     |
| VM links          | `crates/core/src/vm_links.rs`                       | QL-01, BX-01                                                                                               | Working: sessions linked to VMs by guest IP (or a name resolving to it) or by hand; manual links kept                         |
| DNS adapter       | `crates/core/src/adapters/dns.rs`                   | QL-01                                                                                                      | Working: host names to IP addresses through Windows, cached, with a time limit per refresh                                    |
| Store             | `crates/core/src/store/`, `crates/core/migrations/` | AP-05, VM-01, VM-02, SS-01, SS-04, NFR Reliability                                                         | Working: hash-chained audit log, job journal, inventory, sessions, vault ciphertext, tags, saved filters                      |
| Fake adapters     | `crates/core/src/fakes.rs`                          | Development safety                                                                                         | One fake per outside system                                                                                                   |
| Tauri shell       | `src-tauri/src/`                                    | All IPC                                                                                                    | Working                                                                                                                       |
| UI                | `src/`                                              | FD-01, FD-07, VM-01 to VM-06, AP-01 to AP-06, SS-01 to SS-06, SS-09, BX-01 to BX-07, MO-01 to MO-04, QL-01 | All pages, the approval dialog with countdown, the dashboard with live uPlot charts, the Ctrl+K command palette               |
