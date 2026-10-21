# Remotely

A Windows desktop app for forward deployed engineers and IT admins: bulk control of VMware Workstation Pro VMs (and, from 0.4.0, Oracle VirtualBox VMs), a performance dashboard, a PuTTY/MobaXterm-style SSH session manager, and bulk command execution with grouped output, with multi-step approvals on every high-impact action.

The source of truth is `docs/PRD.md`, plus `docs/post-mvp-plan.md` for the work after the MVP (0.2.1 and 0.3.0), which moves some v2/v3 items into scope and replaces the Bulk run page with MultiExec and Compare in the Terminal page, and `docs/plan-0.4.md` for 0.4.0 (VirtualBox, containers, host details, MultiExec recording and terminal fixes). Requirements have IDs (VM-xx, SS-xx, BX-xx, AP-xx, MO-xx, FD-xx, QL-xx for post-MVP quality-of-life items, and CT-xx for containers); refer to them in code comments, tests and commit messages. The PRD uses the working title "VM & SSH Manager"; the product name is **Remotely** (app identifier `com.remotely.desktop`).

## Locked decisions

- Stack: Tauri 2, Rust core (tokio), React + TypeScript + Vite UI, xterm.js, uPlot, SQLite via sqlx, russh for SSH.
- UI components: shadcn/ui (Radix base, Nova preset, Lucide icons) on Tailwind CSS 4. Build screens from shadcn components first; write custom CSS only for what shadcn does not cover (e.g. the xterm.js host).
- Single user only. No team mode, no server component.
- Windows 10/11 x64 with VMware Workstation Pro 17 or later, and from 0.4.0 Oracle VirtualBox (`docs/plan-0.4.md`, VM-18). No Linux host support. macOS on Apple Silicon is a separate track after 0.4.0 with its own plan; until then nothing is built for it.
- RDP means launching `mstsc.exe` with a generated .rdp file (v3).
- Ansible: inventory export only (v2). The app never runs playbooks.
- **The repository is private while the app is field-tested** (since 0.2.0), but follow the "Public repository rules" below anyway: it may go public later, and git history is forever. Code and releases live in one GitHub repo, and installed apps auto-update from its GitHub Releases (FD-14); with the repo private, that needs a read-only token in each app's vault (`docs/post-mvp-plan.md`, P1).
- The MVP (32 requirements: VM-01 to VM-07, SS-01 to SS-06, BX-01 to BX-07, AP-01 to AP-06, MO-01 to MO-04, FD-01 and FD-14) shipped in 0.2.0. Post-MVP scope is exactly what `docs/post-mvp-plan.md` and `docs/plan-0.4.md` list. Do not build other v2/v3 items unless asked; if a change would add or drop scope, stop and say so.

## Public repository rules (no credentials, PII or secrets)

Everything committed here may become public, and git history is forever, so treat it as public now.

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
- `.github/workflows/ci.yml` runs on every push to main and every pull request, except documentation-only changes (`paths-ignore`: `**/*.md`, `docs/**`): `cargo fmt --all --check`, clippy, `cargo test --workspace`, `npm run lint`, `npm test`. `.github/workflows/secrets.yml` runs gitleaks over the full history on every push to main and every pull request, documentation included. Both cancel a run a newer push supersedes.
- CI minutes: the repo is private, so Actions minutes come out of the owner's monthly allowance (2,000 on GitHub Free), and Windows minutes count double. A `ci.yml` run bills about 12 to 16 minutes, a release about 28. Don't push for every small commit, and keep `paths-ignore` working (README "CI minutes").
- `.github/workflows/release.yml` runs on `v*` tags on `windows-latest`. It uses `tauri-apps/tauri-action` to build, sign the update artifacts and create a **draft** GitHub Release with the installer, its `.sig` file and `latest.json`, then checks the signatures against `plugins.updater.pubkey` with `scripts/verify-update-signature.mjs` (a failure means the signing secret and the public key don't pair: don't publish). The user publishes the draft after a smoke test; installed apps only see published releases.
- `tauri.conf.json`: `bundle.createUpdaterArtifacts: true`; `plugins.updater.pubkey` holds the public key; `plugins.updater.endpoints` is `["https://github.com/khilfi/remotely/releases/latest/download/latest.json"]`, which names the repository the app updates from (the app doesn't fetch that URL, see the next point); `plugins.updater.windows.installMode: "passive"`.
- Private repo (FD-14, `docs/post-mvp-plan.md` P1): update checks need the **GitHub update token**, a fine-grained token for this repository only with Contents: Read-only and an expiry, which the owner enters in Settings → Updates on each machine (README "GitHub update token" says how to create, enter and replace it). It is a vault secret (`password` kind, label "GitHub update token"; its id is the setting `updates.tokenId`, the expiry GitHub reports is `updates.tokenExpiresOn`), write-only in the UI with Test, Replace and Remove. The updater (`src-tauri/src/updater.rs`) finds the latest release through the GitHub API with it (`crates/core/src/adapters/github.rs`), then has `tauri-plugin-updater` fetch `latest.json` and the installer from their API asset URLs with `Authorization` and `Accept: application/octet-stream`; GitHub redirects to its storage, and reqwest drops the token on that redirect. tauri-action writes API asset URLs into `latest.json`; any other URL is mapped to the release's file of the same name, or refused, so the token only goes to the API. Signatures are verified against the public key exactly as before. Without a token, or with the vault locked, a check makes no network call and says why (`updates::UpdateCheck`). The token never reaches logs, errors, the UI state, the audit log or exports. Tests use `fakes::github_server::FakeGithub` (API and storage on 127.0.0.1) and `UpdateSigner` (a throwaway minisign key); never a real token. Copies on 0.2.0 or older can't update from the private repo and need one manual install of 0.2.1.
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
.github/workflows/    ci.yml, secrets.yml, release.yml
.githooks/            pre-commit (gitleaks)
docs/                 PRD.md, architecture.png, roadmap.png
crates/core/          remotely-core: all app logic
  migrations/         sqlx migrations
  src/
    command_bus.rs
    policy/           tiers and steps; FD-03 read_only_refusal: the read-only lock refuses every command and edit
    presentation.rs   FD-03 presentation mode (saved, fail closed, audited) and ReadOnlyLock, which the store shares
                      with the bus and every service that edits the app's data (Change)
    jobs.rs
    adapters/         vmware.rs, remote.rs (SSH shell and exec, every path through the SS-07 jump host chain over
                      direct-tcpip channels, each hop's own host key check and login; remote/sftp.rs SS-08 SFTP on a
                      terminal's own connection, behind the RemoteFiles trait; remote/forward.rs SS-07 port forwards on
                      it, local, remote and SOCKS, behind RemoteForwards; remote/socks.rs SOCKS 4/4a/5),
                      exec_output.rs (BX-02/BX-07 output cap, hashes,
                      secret scrubbing), host_counters.rs, updater.rs, github.rs (FD-14 GitHub Releases API with the
                      update token), network.rs (DNS for QL-01 auto-linking and QL-03 host name and IP, QL-04
                      TCP probe)
    updates.rs        FD-14 update checks and the GitHub update token in the vault
    inventory.rs
    capacity.rs       VM-07 capacity check before power-on
    snapshots.rs      VM-04 snapshot trees (from .vmsd), VM-05 safety snapshot names
    impact.rs         AP-02 impact preview for the approval dialog
    export.rs         AP-05 audit log CSV export and secret redaction
    metrics/          MO-01 to MO-04: mod.rs (collector, in-memory history, dashboard rows), guest.rs (MO-02 SSH
                      polling, kept connections, backoff), procfs.rs (/proc and df parsers)
    sessions.rs       SS-01 session library, SS-06 labels (audited, no approval tier); sessions/tree.rs the QL-04
                      tree (by folder, tag or label) for the Terminal page
    forwards.rs       SS-07 saved port forwards per session (audited like the library; opening one is
                      Command::OpenTunnel on the bus)
    vm_links.rs       QL-01 sessions linked to the VMs they reach: automatically by guest IP, or by hand (audited)
    terminal/         SS-03 terminal panes (mod.rs): one supervised SSH connection each (keep-alive, auto-reconnect,
                      QL-03 host name and IP, QL-06 a vault password typed at a prompt); quick.rs QL-02 quick connect;
                      log.rs and output.rs SS-11 session logs and saved, printed or copied output (secrets scrubbed);
                      activity.rs the cursor's line, full-screen programs (alternate screen) and QL-07 long-run
                      detection (prompt back, or quiet); multiexec.rs SS-10 MultiExec: keys to every picked terminal,
                      a line buffer, Enter held and the line rated on the bus (Command::TerminalLine), password prompts
                      and full-screen programs passed straight through, QL-07 one LineFinished per line (never one
                      notification per terminal); record.rs QL-12 MultiExec recording: each sent line's output per
                      terminal from Enter until the prompt is back (TextRenderer drops escapes and replays line
                      redraws; RecordSlot handed to the pane through its input before the Enter; Recorder keeps the
                      session's lines in memory with caps, grouped and diffed through bulk.rs); folder.rs SS-08 the
                      shell's folder (OSC 7) and
                      the invisible prompt hook typed into bash and zsh on connect (hidden from the terminal, logs,
                      MultiExec and QL-07; the startup command waits for it), QL-09 its user report next to the folder
                      (private OSC 7777, hidden the same way); shell_user.rs QL-09 who transfers run as (the SSH login,
                      RemoteFiles::user) and who the shell may run as (the hook's report, a prompt that stopped
                      reporting after su or sudo -i, a prompt naming a user); files.rs SS-08 the "Files here" listing
                      (QL-09: a folder that can't be opened comes back with its path and the reason; typed paths go on
                      from the folder shown; Back through the folders that opened), downloads (audited reads), the
                      upload job's work (Command::FileUpload on the bus), the transfers list with cancel and retry, and
                      FileTransfers (Core.files: staged files, uploads, retries);
                      tunnels.rs SS-07 a terminal's tunnels: start (Command::OpenTunnel on the bus, also for forwards
                      that start with the terminal), approve, stop, the job's open_tunnel, reopened after a reconnect,
                      closed with the terminal, audited tunnel_opened and tunnel_closed
    snippets/         BX-08 command panel: favourite commands (mod.rs; audited, no approval tier), the built-in
                      library (library.rs: ~525 Linux commands in 30 area groups plus TROUBLESHOOT symptom runbooks
                      that reference them; two LibrarySections), {{variables}} (variables.rs); classified by the bus's
                      policy engine (read-only additions in policy/commands.rs, writing forms in commands/writes.rs);
                      QL-13 each entry's manual page (manual.rs: Manual, MANUAL_HOSTS, `checked` refuses any other
                      address; opening one is not audited and the read-only lock allows it)
    reachability.rs   QL-04 background TCP checks of the sessions the tree shows (reads only); SS-07 the first jump
                      host's for a session behind one, never the session itself
    bulk.rs           BX-01 targets (picked tabs, tree sessions, VMs, tags, filters), BX-03 grouped results and diff,
                      BX-05 exports: the Terminal page's Compare output (running is RemoteExec on the bus); QL-12
                      recorded MultiExec lines group (group_with_output), diff and export (export_recorded, audited
                      multiexec_exported) through the same code
    known_hosts.rs    SS-05 trusted host keys (first-use prompt, changed key blocks; audited)
    ssh_keys.rs       SS-09 SSH keys: generated into the vault, public halves, attach to sessions, the
                      authorized_keys push script (the push itself is Command::PushSshKey on the bus)
    transfer/         FD-07 encrypted export/import between laptops: file.rs (Argon2id + AES-256-GCM envelope,
                      format version), preview with conflicts (skip, replace, keep both), commit; audited
    import/           SS-02 parsers (PuTTY, MobaXterm, OpenSSH config, CSV), preview and commit; guide.rs QL-10 a
                      format guide and a sample file per format (the CSV guide is made from csv.rs's COLUMNS,
                      ENVIRONMENTS and AUTH_METHODS tables; tests/import.rs imports every sample)
    vault/            SS-04 vault: crypto (AES-256-GCM, Argon2id), DPAPI, LocalVault, VaultService
    store/
    fakes.rs          one fake per adapter (feature `fakes`; tests only)
    fakes/ssh_server.rs  russh server on 127.0.0.1 with run-time keys, for SSH tests; ssh_server/sftp.rs its SFTP
                      subsystem on a temp folder (SS-08; QL-09 with_unreadable folders it can't open); SS-07
                      direct-tcpip (with_route names reach another port on 127.0.0.1, so a server is reachable only
                      through another) and tcpip-forward; QL-09 `su [-] [user]` in its shell, a shell without the hook
    fakes/github_server.rs  FD-14 fake GitHub API and release storage on 127.0.0.1, throwaway update-signing key
  examples/           dev_ssh_server.rs: that server on a fixed port, to try the terminal, MultiExec, Compare, jump host
                      chains and tunnels by hand
  tests/              end-to-end tests with fakes; opt-in workstation_it.rs
src-tauri/            Tauri 2 shell: window, IPC commands (ipc.rs), terminal bridge, MultiExec (multiexec.rs), command
                      panel, notifications and QL-13 manual links opened with ShellExecute after the core's check
                      (command_panel.rs), clipboard read for right-click paste, SS-08 file
                      transfer (files.rs: upload and folder dialogs, drops caught in Rust, Explorer for "Open folder"),
                      SS-07 port forwards and tunnels (tunnels.rs)
src/                  React + TypeScript UI
  components/ui/      shadcn/ui components (generated)
  components/         app components (approval dialog, badges, Compare panel with its one-shot and MultiExec views
                      (RecordedLinesView, QL-12; BulkResultsView's GroupCard and OutputDiffDialog serve both), MultiExec
                      bar, WhyDisabled for QL-08,
                      FilesDrawer and TransfersList for SS-08, ForwardsEditor and TunnelsPanel for SS-07, Presentation
                      for FD-03: the Present button and menu, the confirm, the frame, page notices, the Settings card;
                      VmDetailsPanel and SnapshotTree for QL-14: a VM's Details and Snapshots tabs beside the list)
  pages/              one file per page (bulk execution is in TerminalPage: MultiExec and Compare output; QL-14 VmsPage
                      is VMs and snapshots, with the selection's bulk snapshot actions and the details panel)
  lib/                api.ts (typed IPC wrappers; FD-03: every answer's host, IP and user fields are learnt by the
                      masker), theme.ts, utils.ts, multiexec.ts, recordings.ts (QL-12 view texts, QL-07 notify choice
                      and the one notification per MultiExec line), transfers.ts, tunnels.ts (SS-07 chains and forwards),
                      navigation.ts (page shortcuts by page; the old Snapshots id and Ctrl+3 open the VM page's snapshot
                      view until Containers takes slot 3), vm-snapshots.ts (QL-14 snapshot reasons, picks, tier hints),
                      presentation.ts (FD-03 masking: stand-ins, patterns, known values, TerminalMasker),
                      presentation-dom.ts (masks every text node and text attribute before paint, `data-mask` fields,
                      `data-presentation-skip` for terminals), presentation-state.ts; pure helpers with
                      *.test.ts
                      next to them (Node's test runner: `npm test`)
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
- `soft` goes through VMware Tools. Without Tools running, vmrun waits instead of failing (Workstation 26: `suspend soft` waited until the VM was powered off from outside, then said "The VMware Tools are not running"), so the job runner checks `checkToolsState` first. vmrun power calls also wait while the VM shows a question or message in Workstation, so they get per-op timeouts (`adapters::vmware::power_timeout`) and job cancel kills an in-flight power call.
- Snapshots: `snapshot`, `listSnapshots`, `revertToSnapshot`, `deleteSnapshot`.
- Guest operations (`runProgramInGuest`, file copy) need `-gu`/`-gp` guest credentials on the command line, so other processes on the host can see them. Use guest operations only on demand, and never log the command line.
- `vmrest.exe` (same folder) is a local REST API, by default on 127.0.0.1:8697. It needs a one-time credential setup (`vmrest -C`, which is interactive). Treat it as optional and fall back to `vmrun`.
- Each running VM is a `vmware-vmx.exe` process whose command line contains the `.vmx` path. Use that to map Windows performance counters (CPU, memory, I/O) to a VM.

## Development safety

- Unit and integration tests must never stop, reset, suspend, revert or delete snapshots on real VMs. Use the fake VMware adapter.
- Tests against real Workstation are opt-in: they run only when `REMOTELY_IT=1` is set, and only touch VMs whose display name starts with `it-`.
- Don't connect to real SSH hosts in tests. Use a local test server or a fake: `fakes::ssh_server::TestSshServer`
  (russh on 127.0.0.1, keys made at run time; it can drop or freeze its connections, and runs exec requests in a toy
  shell with sudo modes, /proc files and fake programs such as `df`; its interactive shell has `sudo`, Ctrl+C, a
  full-screen `top`, and the exec shell's `hostname`, `uptime`, `cat`, `seq`... and fake programs, slowed by
  `with_exec_delay`), with `common::Setup::with_ssh()` for the real russh adapter. MultiExec tests open several of
  them (`tests/multiexec.rs`, QL-12 recording included). SS-08: it serves SFTP from a temp folder deleted with it
  (`with_sftp_file`, `with_protected`, `with_unreadable`, `without_sftp`), and with `with_login_shell("bash")` its
  shell answers the folder hook (OSC 7 and the QL-09 user report) and knows `cd`, `pwd` and `su [-] [user]` (a shell
  without the hook, as a real switch); `fakes::FakeFiles` is the in-memory version for the fake remote adapter
  (`tests/files.rs`). Uploads
  and downloads in tests use files made at run time in the system temp folder, never in the repo. SS-07: it forwards
  like OpenSSH (direct-tcpip, tcpip-forward on 127.0.0.1 only); `with_route("db01.test", port)` makes a name only it
  resolves, so `tests/jump_hosts.rs` chains three servers, and `tests/tunnels.rs` carries bytes to an echo service on
  127.0.0.1. Tunnel tests bind loopback with port 0; never a network address.

## Commands

- Install: `npm install`
- Run the app: `npm run tauri dev`. A debug build keeps its data (database, WebView2 profile) in `%LOCALAPPDATA%\com.remotely.desktop.dev`, apart from the installed app's `%LOCALAPPDATA%\com.remotely.desktop`, so its migrations never reach the installed app's database. `REMOTELY_DATA_DIR` (an absolute path outside the repo) overrides both.
- Rust tests: `cargo test --workspace` (run at the repo root; `cargo test` inside `src-tauri/` only tests the shell crate)
- Try the terminal, MultiExec or Compare output without a real host:
  `cargo run -p remotely-core --example dev_ssh_server --features fakes [port] [count]` (default 2222 and 1 server;
  prints the user, one fresh password for all of them, which sudo takes too, and each host key fingerprint). Each also
  serves moving /proc counters, so watching it on the dashboard shows live guest metrics, and SFTP from a temp folder
  (SS-08) with a bash login, so the "Files here" drawer follows `cd` (QL-09: `cd /home/bob/.app`, a folder alice
  can't open over SFTP, and `su bob` to switch user). SS-07: the servers reach each other as
  `dev-host-01.test`, `dev-host-02.test`... (names this PC can't resolve, so they need a jump host) and a web page as
  `web.test:80`, for trying chains and tunnels.
- Opt-in test against real Workstation (reads only: the library, `vmrun list`, Tools state and IP of running VMs, and their processes' counters): `REMOTELY_IT=1 cargo test -p remotely-core --test workstation_it`
- Lint: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `npm run lint` (tsc, ESLint, Prettier)
- UI tests: `npm test` (Node's own test runner over `src/**/*.test.ts`: pure helpers only, no DOM)
- Format: `cargo fmt --all`, `npm run format`
- Build the installer: `npm run tauri build`
- Release: bump the version in all three files, commit, then `git tag -a vX.Y.Z -m "<release notes>"` and `git push origin vX.Y.Z`; publish the draft release on GitHub after a smoke test. The tag message is the release notes users see in the update banner, so write it for them.

## Conventions

- Rust stable, edition 2021. Errors with `thiserror`. No `unwrap()`/`expect()` outside tests.
- TypeScript in strict mode. ESLint and Prettier.
- shadcn/ui: add components with `npx shadcn@latest add <name>`. They land in `src/components/ui/` and stay as generated (that folder and `src/hooks/use-mobile.ts` are excluded from ESLint and Prettier so updates diff cleanly). The shadcn base styles are inlined in `src/styles.css` (`shadcn eject`), so the `shadcn` package is not an app dependency; don't add it back. App colour tokens (risk tiers, environment labels) live at the end of `src/styles.css`. Import from `@/…` (alias for `src/`).
- Dark mode is the `dark` class on `<html>`, set only by `src/lib/theme.ts`. QL-11: the top bar's Dark mode switch picks
  dark or light; "Follow Windows" (Settings, General; the default, "system") lets Windows decide, and using the switch
  turns it off.
- App icon: the master is `src-tauri/app-icon.png` (1024×1024, transparent). After changing it, run `npx tauri icon src-tauri/app-icon.png`, delete the generated `src-tauri/icons/android` and `src-tauri/icons/ios` folders (desktop only), and copy `src-tauri/icons/128x128.png` to `src/assets/remotely-logo.png` and `src-tauri/icons/64x64.png` to `public/favicon.png`.
- Every policy-engine rule has a unit test.
- FD-03 presentation mode masks what is on screen at the DOM (`src/lib/presentation-dom.ts`), so new UI needs nothing
  for text. An element or input that holds exactly one host, IP, user or `user@host:port` gets
  `data-mask="host|ip|user|address"` (inputs then show dots while presenting). Text shown outside the window (Windows
  notifications) goes through `maskedOutside`. A new IPC field holding a host, IP or user should use one of the names
  `learnFields` knows (`host`, `hostname`, `ip`, `username`, ...). A new state-changing core method that skips the bus
  starts with `store.read_only().check(Change::…)`.
- Commit messages start with the requirement ID where one applies, e.g. `VM-02: bulk suspend and resume`.
