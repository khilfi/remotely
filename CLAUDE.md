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
- **The repository is public** (the owner's decision, confirmed on 22 Oct 2026; it was private while field-tested from 0.2.0 to 0.4.0), so the "Public repository rules" below apply to everything, including history. Code and releases live in one GitHub repo, and installed apps auto-update from its GitHub Releases (FD-14). The updater still reads them with a read-only token in each app's vault (`docs/post-mvp-plan.md`, P1), built while the repo was private, until it is changed to read public releases without one.
- The MVP (32 requirements: VM-01 to VM-07, SS-01 to SS-06, BX-01 to BX-07, AP-01 to AP-06, MO-01 to MO-04, FD-01 and FD-14) shipped in 0.2.0. Post-MVP scope is exactly what `docs/post-mvp-plan.md` and `docs/plan-0.4.md` list. Do not build other v2/v3 items unless asked; if a change would add or drop scope, stop and say so.

## Public repository rules (no credentials, PII or secrets)

Everything committed here is public, and git history is forever.

- Never commit passwords, tokens, API keys, private keys (SSH, TLS, update-signing), certificates with private keys (`.pfx`, `.p12`), `.env` files, or real session exports (PuTTY `.reg`, MobaXterm `.mxtsessions`).
- Never commit real hostnames, IP addresses, usernames, customer names, logs, terminal recordings, audit or job exports, or app databases. This applies to code, tests, fixtures, docs and screenshots.
- Test data uses reserved examples only: hostnames under `example.com`, `example.org` or `.test`; IPs from `192.0.2.0/24`, `198.51.100.0/24` or `203.0.113.0/24`; usernames like `alice` and `bob`. Generate SSH keys inside tests at run time; never commit them.
- The app keeps its data (database, vault, logs, recordings) under `%APPDATA%` / `%LOCALAPPDATA%`, never in the working directory, so nothing private can land in the repo.
- A gitleaks scan runs as a pre-commit hook and in CI, and a finding fails the build. Never bypass it (`--no-verify`). If a secret was ever committed, stop and tell the user: it has to be revoked and replaced, because deleting it doesn't remove it from public history.
- Commits use the user's GitHub noreply email, never a personal email.
- Only the update-signing **public** key goes in `tauri.conf.json`. The private key and its password live only outside the repo on the user's machine and in the secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` of the GitHub Environment `release` (never repository-level secrets, which any workflow on any branch can read). Claude never reads, prints or handles the private key or its password; the user sets those secrets. No build step may need the key: `bundle.createUpdaterArtifacts` stays off, and only release.yml's publish job signs.
- Pin third-party GitHub Actions to a full commit SHA.

## Releases and auto-update

- The version in `package.json`, `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json` must match. Release by pushing a tag `vX.Y.Z`.
- `.github/workflows/ci.yml` runs on every push to main and every pull request, except documentation-only changes (`paths-ignore`: `**/*.md`, `docs/**`): `cargo fmt --all --check`, clippy, `cargo test --workspace`, `npm run lint`, `npm test`, and a Linux dependency scan (C4): `cargo deny --locked check advisories bans sources` with `deny.toml` (crates.io only, no git sources; each accepted advisory is listed there with its reason), `npm audit --omit=dev` and `npm audit signatures`. `.github/workflows/secrets.yml` runs gitleaks over the full history on every push to any branch and every pull request, documentation included. Both cancel a run a newer push supersedes. `.github/dependabot.yml` opens one grouped pull request a week each for Cargo, npm and GitHub Actions.
- Toolchains are pinned (C5): Rust in `rust-toolchain.toml`, Node in `.node-version`; CI and releases use them. Bump them on purpose, in their own commit.
- CI minutes: the repo is public, so Actions runs on standard GitHub-hosted runners don't use the owner's minutes. Still keep CI lean: a `ci.yml` run takes about 6 to 8 minutes of runner time and a release about 14, so push when a change is ready rather than after every small commit, and keep `paths-ignore` working (README "CI minutes"). If the repo ever goes private again, runs bill against the 2,000-minute GitHub Free allowance and Windows minutes count double.
- `.github/workflows/release.yml` runs on `v*` tags in two jobs (C1). **build** (`windows-latest`, no secrets, read-only token): the tagged commit must be on main and match the three version files; it builds the NSIS installer with `--locked`, the pinned toolchains and no cache, and uploads it as a workflow artifact. **publish** (`ubuntu-latest`, Environment `release`: the owner approves each run, `v*` tags only): signs the installer with `tauri signer sign --app-version`, checks the signature with `scripts/verify-update-signature.mjs --version`, then `scripts/publish-release.mjs` creates the **draft** release with the installer, its `.sig` and `latest.json` (tauri-action's format, API asset URLs), checking `latest.json` and fetching the installer back before it uploads it, and deleting the draft if anything fails (C6). The tag message is the release notes (written to a file, never `$GITHUB_OUTPUT`). README "Release settings on GitHub" has the owner's settings (Environment, secrets, tag ruleset) and "Signing key compromise or loss" the runbook. The user publishes the draft after a smoke test; installed apps only see published releases.
- `tauri.conf.json`: `bundle.createUpdaterArtifacts: false` (the publish job signs, so no build needs the key); `plugins.updater.pubkey` holds the public key; `plugins.updater.requireSignedVersion: true` (C3: the plugin refuses a signature whose trusted comment names another version than `latest.json`); `plugins.updater.endpoints` is `["https://github.com/khilfi/remotely/releases/latest/download/latest.json"]`, which names the repository the app updates from (the app doesn't fetch that URL, see the next point); `plugins.updater.windows.installMode: "passive"`.
- Update token (FD-14, `docs/post-mvp-plan.md` P1, built while the repo was private; the releases are public now, but the updater still requires it): update checks need the **GitHub update token**, a fine-grained token for this repository only with Contents: Read-only and an expiry, which the owner enters in Settings → Updates on each machine (README "GitHub update token" says how to create, enter and replace it). It is a vault secret (`password` kind, label "GitHub update token"; its id is the setting `updates.tokenId`, the expiry GitHub reports is `updates.tokenExpiresOn`), write-only in the UI with Test, Replace and Remove. The updater (`src-tauri/src/updater.rs`) finds the latest release through the GitHub API with it (`crates/core/src/adapters/github.rs`), then has `tauri-plugin-updater` fetch `latest.json` and the installer from their API asset URLs with `Authorization` and `Accept: application/octet-stream`; GitHub redirects to its storage, and reqwest drops the token on that redirect. The release workflow writes API asset URLs into `latest.json`; any other URL is mapped to the release's file of the same name, or refused, so the token only goes to the API. Signatures are verified against the public key exactly as before. Before an update is offered, `adapters::updater::check_signed_release` (C3) checks the signature's trusted comment against the public key and requires `file:<productName>_<version>_x64-setup.exe` and `version:<version>` for the version `latest.json` announces, so an old signed installer can't come back as a newer version. Without a token, or with the vault locked, a check makes no network call and says why (`updates::UpdateCheck`). The token never reaches logs, errors, the UI state, the audit log or exports. Tests use `fakes::github_server::FakeGithub` (API and storage on 127.0.0.1) and `UpdateSigner` (a throwaway minisign key); never a real token. Copies on 0.2.0 or older can't update this way and need one manual install of 0.2.1 or later.
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
.github/workflows/    ci.yml, secrets.yml, release.yml; .github/dependabot.yml
deny.toml             cargo-deny: advisories, bans, sources (C4)
rust-toolchain.toml   pinned Rust; .node-version pinned Node (C5)
scripts/              verify-update-signature.mjs, publish-release.mjs (release.yml's publish job) and their tests
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
    adapters/         vmware.rs, virtualbox.rs (VM-18 VBoxManage: list, showvminfo, guest properties, power,
                      snapshots; SwitchableVirtualBox for the Settings path), hypervisor.rs (VM-18 Hypervisor, and
                      Hypervisors: both adapters, each VM routed by its key), remote.rs (SSH shell and exec, every path
                      through the SS-07 jump host chain over
                      direct-tcpip channels, each hop's own host key check and login; remote/sftp.rs SS-08 SFTP on a
                      terminal's own connection, behind the RemoteFiles trait; remote/forward.rs SS-07 port forwards on
                      it, local, remote and SOCKS, behind RemoteForwards; remote/socks.rs SOCKS 4/4a/5),
                      exec_output.rs (BX-02/BX-07 output cap, hashes,
                      secret scrubbing), host_counters.rs (MO-01 VM processes: vmware-vmx.exe, VirtualBoxVM.exe,
                      VBoxHeadless.exe; MO-15 `paging()`), paging.rs (MO-15 this PC's paging files and commit charge:
                      GlobalMemoryStatusEx and NtQuerySystemInformation's page file list), vm_hardware.rs (MO-13 a VM's
                      hardware from its .vmx or showvminfo; VMDK descriptor and sparse header, VDI, VHD and qcow2
                      headers for provisioned sizes; size on disk down a snapshot chain), updater.rs, github.rs (FD-14
                      GitHub Releases API with the
                      update token), network.rs (DNS for QL-01 auto-linking and QL-03 host name and IP, QL-04
                      TCP probe), containers/ (CT-01, CT-02: the ContainerEngine and ContainerEngines traits; cli.rs
                      the docker and podman CLIs over a kept SSH connection's exec channels, with sudo from the vault
                      (ExecSession::run_sudo) or NOPASSWD, and docker.exe on this PC, found like vmrun; parse.rs both
                      CLIs' JSON field by field (env values never leave it); names.rs checked ids, volume names and
                      image references, every word shell-quoted on hosts)
    containers/       CT-01, CT-02 container hosts: marks.rs (sessions marked Docker or Podman, how each runs: as the
                      user or with sudo; migration 0013, audited like session edits, Change::ContainerHosts, FD-07);
                      mod.rs the Containers service: detection, reads on kept connections (closed when idle), target
                      names from the engines' own lists (StoreDirectory), the AP-02 impact preview, ContainerActions
                      for the job runner (Command::Container), and "Open a shell" (Terminals::open_container_shell
                      types docker/podman exec -it instead of the startup command); logins and sudo go through
                      login_guard (SudoWatch parks a refused sudo password; Containers::retry)
    login_guard.rs    MO-02, CT-01 background logins (dashboard guest polling, Containers reads): a refused login or
                      agent, refused sudo, changed host key or missing secret parks the session until its login key
                      changes, credentials_changed (vault unlock, secret add/replace/delete, host key trust/remove) or
                      Retry (Core::retry_background_logins); at most 10 logins per host per hour, jump hosts included
    updates.rs        FD-14 update checks and the GitHub update token in the vault
    inventory.rs      VM-01 Workstation's and (VM-18) VirtualBox's VMs; a VirtualBox VM is kept when VirtualBox can't
                      be asked
    capacity.rs       VM-07 capacity check before power-on
    snapshots.rs      VM-04 snapshot trees (from .vmsd, or VirtualBox's showvminfo and .vbox), VM-05 safety snapshot
                      names
    impact.rs         AP-02 impact preview for the approval dialog
    export.rs         AP-05 audit log CSV export and secret redaction
    metrics/          MO-01 to MO-04: mod.rs (collector, in-memory history, dashboard rows; MO-15 allocated memory, swap
                      and this PC's RAM and paging files per round), guest.rs (MO-02 SSH polling, kept connections,
                      backoff for unreachable hosts, login_guard parks and caps, GuestState::Paused and
                      GuestStatus.parked; MO-13 reads a host's facts on its kept connection when they are old),
                      procfs.rs (/proc and df parsers)
    host_details/     MO-13, MO-14 (reads only: no bus, no audit, not stopped by the read-only lock): mod.rs
                      (SpecsCollector: a session's facts read when a terminal connects, on its own connection's exec
                      channel, or by the dashboard; HostDetails: Refresh, admin reads and updates on a terminal's, the
                      dashboard's or its own kept connection; VM specs from the hypervisor's files; facts stored per
                      session and VM, migration 0014), linux.rs (SPECS_SCRIPT and its parsers: os-release, uname,
                      lscpu or /proc/cpuinfo, meminfo, swaps, lsblk JSON or pairs, df, systemd-detect-virt), admin.rs
                      (ADMIN_SCRIPT and UPDATES_SCRIPT: systemctl or rc-status/service, ss or netstat, who, last, ps,
                      apt or dnf; every command checked read-only by `classify_script` in tests)
    sessions.rs       SS-01 session library, SS-06 labels (audited, no approval tier); rate_startup rates a startup
                      command like a run on the session (editor, SS-02 and FD-07 previews, audit); startup_on_reconnect
                      and prompt_hook per session (migration 0015); sessions/tree.rs the QL-04 tree (by folder, tag
                      or label) for the Terminal page
    forwards.rs       SS-07 saved port forwards per session (audited like the library; opening one is
                      Command::OpenTunnel on the bus)
    vm_links.rs       QL-01 sessions linked to the VMs they reach: automatically by guest IP, or by hand (audited)
    terminal/         SS-03 terminal panes (mod.rs): one supervised SSH connection each (keep-alive, auto-reconnect,
                      QL-03 host name and IP, QL-06 a vault password typed at a prompt; SS-01 the startup command typed
                      at the first shell prompt, or not at all within STARTUP_WAIT, and after an automatic reconnect
                      only with startup_on_reconnect); quick.rs QL-02 quick connect;
                      log.rs and output.rs SS-11 session logs and saved, printed or copied output (secrets scrubbed);
                      activity.rs the cursor's line, full-screen programs (alternate screen) and QL-07 long-run
                      detection (prompt back, or quiet); multiexec.rs SS-10 MultiExec: keys to every picked terminal,
                      a line buffer, Enter and every other key that runs a line in bash or zsh held (RunKey: Ctrl+O,
                      Esc then Enter...; a lone Esc waits for its next key; the table of bindings is in the file) and
                      the line rated on the bus (Command::TerminalLine; the bus and the job runner send only the held
                      keys of the rated line, check_keys), edit-and-execute keys refused (Ctrl+X Ctrl+E, v after Esc),
                      password prompts and full-screen programs passed straight through, QL-07 one LineFinished per
                      line (never one notification per terminal); record.rs QL-12 MultiExec recording: each sent line's
                      output per terminal from Enter until the prompt is back (TextRenderer drops escapes and replays line
                      redraws; RecordSlot handed to the pane through its input before the Enter; Recorder keeps the
                      session's lines in memory with caps, grouped and diffed through bulk.rs); folder.rs SS-08 the
                      shell's folder (OSC 7) and
                      the invisible prompt hook typed into bash and zsh on connect (hidden from the terminal, logs,
                      MultiExec and QL-07; the startup command waits for it; typed only at a line that looks like a
                      shell prompt; never edits the history; audited once per connection, folder_hook_installed;
                      PromptHook::off for Settings' prompt_hook, a session's prompt_hook, or Prod by default, with
                      FolderTracking::Off), QL-09 its user report next to the folder
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
    reachability.rs   QL-04 background TCP checks of the sessions the tree shows (reads only; each shows in the host's
                      sshd log): every 5 minutes by default, a host that is down less often (next_check_after: doubling
                      up to 30 minutes), none for a host with an open connection (OpenConnections: connected terminals,
                      and TrackedRemote, the remote adapter every service uses, noting kept connections: dashboard,
                      Containers page, host details); SS-07 the first jump host's for a session behind one, never the
                      session itself
    bulk.rs           BX-01 targets (picked tabs, tree sessions, VMs, tags, filters), BX-03 grouped results and diff,
                      BX-05 exports: the Terminal page's Compare output (running is RemoteExec on the bus); QL-12
                      recorded MultiExec lines group (group_with_output), diff and export (export_recorded, audited
                      multiexec_exported) through the same code
    known_hosts.rs    SS-05 trusted host keys (first-use prompt, changed key blocks; audited; a new key type for a host
                      with a trusted key blocks in bulk runs and is an FD-07 conflict; key_types for the handshake's
                      preferred host key algorithms)
    ssh_keys.rs       SS-09 SSH keys: generated into the vault, public halves, attach to sessions, the
                      authorized_keys push script (the push itself is Command::PushSshKey on the bus)
    transfer/         FD-07 encrypted export/import between laptops: file.rs (Argon2id + AES-256-GCM envelope,
                      format version), preview with conflicts (skip, replace, keep both), commit; audited
    import/           SS-02 parsers (PuTTY, MobaXterm, OpenSSH config, CSV), preview and commit; guide.rs QL-10 a
                      format guide and a sample file per format (the CSV guide is made from csv.rs's COLUMNS,
                      ENVIRONMENTS and AUTH_METHODS tables; tests/import.rs imports every sample)
    vault/            SS-04 vault: crypto (AES-256-GCM, Argon2id), DPAPI, LocalVault, VaultService
    store/
    fakes.rs          one fake per adapter (feature `fakes`; tests only); FakeVirtualBox for VM-18
    fakes/ssh_server.rs  russh server on 127.0.0.1 with run-time keys, for SSH tests; ssh_server/sftp.rs its SFTP
                      subsystem on a temp folder (SS-08; QL-09 with_unreadable folders it can't open); SS-07
                      direct-tcpip (with_route names reach another port on 127.0.0.1, so a server is reachable only
                      through another) and tcpip-forward; QL-09 `su [-] [user]` in its shell, a shell without the hook;
                      ssh_server/docker.rs CT-01 its `docker` and `podman` programs (each CLI's JSON from a fixture);
                      ssh_server/host.rs MO-13, MO-14 a HostFixture (ubuntu, rhel) its exec shell describes itself with
    fakes/containers.rs  CT-01, CT-02 the container Fixture (sample, hostile names) and FakeContainers (engines in memory)
    fakes/github_server.rs  FD-14 fake GitHub API and release storage on 127.0.0.1, throwaway update-signing key
  examples/           dev_ssh_server.rs: that server on a fixed port, to try the terminal, MultiExec, Compare, jump host
                      chains, tunnels, the Containers page and host details by hand
  tests/              end-to-end tests with fakes (virtualbox.rs: VM-18, mixed with Workstation); opt-in
                      workstation_it.rs and virtualbox_it.rs
src-tauri/            Tauri 2 shell: window, IPC commands (ipc.rs), terminal bridge, MultiExec (multiexec.rs), command
                      panel, notifications and QL-13 manual links opened with ShellExecute after the core's check
                      (command_panel.rs), clipboard read for right-click paste, SS-08 file
                      transfer (files.rs: upload and folder dialogs, drops caught in Rust, Explorer for "Open folder"),
                      SS-07 port forwards and tunnels (tunnels.rs), CT-01 the Containers page's reads, marks and
                      container shells (containers.rs), MO-13 to MO-15 host details and this PC's memory
                      (host_details.rs)
src/                  React + TypeScript UI
  components/ui/      shadcn/ui components (generated)
  components/         app components (approval dialog, badges, Compare panel with its one-shot and MultiExec views
                      (RecordedLinesView, QL-12; BulkResultsView's GroupCard and OutputDiffDialog serve both), MultiExec
                      bar, WhyDisabled for QL-08,
                      FilesDrawer and TransfersList for SS-08, ForwardsEditor and TunnelsPanel for SS-07, Presentation
                      for FD-03: the Present button and menu, the confirm, the frame, page notices, the Settings card;
                      VmDetailsPanel and SnapshotTree for QL-14: a VM's Details and Snapshots tabs beside the list;
                      ContainerHostDialog, ContainerDetailsPanel (Overview, Logs, Stats) and ContainerResources (images,
                      volumes, networks) for CT-01; HostDetailsSheet (MO-13 System, MO-14 Admin) for a session,
                      VmSystemTab (MO-13: a VM's System tab), ThisPcMemoryChart (MO-15) and MetricChart's own legend
                      and dashed limit lines)
  pages/              one file per page (bulk execution is in TerminalPage: MultiExec and Compare output; QL-14 VmsPage
                      is VMs and snapshots, with the selection's bulk snapshot actions and the details panel;
                      ContainersPage at Ctrl+3)
  hooks/              use-poll.ts (CT-01 usePoll: a background read while the page shows and the window is visible,
                      each timed from when the last one finished; useVisibility); use-mobile.ts is shadcn's
  lib/                api.ts (typed IPC wrappers; FD-03: every answer's host, IP and user fields are learnt by the
                      masker), theme.ts, utils.ts, multiexec.ts, recordings.ts (QL-12 view texts, QL-07 notify choice
                      and the one notification per MultiExec line), transfers.ts, tunnels.ts (SS-07 chains and forwards),
                      navigation.ts (page shortcuts by page; the old Snapshots id opens the VM page's snapshot view;
                      Containers has Ctrl+3), vm-snapshots.ts (QL-14 snapshot reasons, picks, tier hints), containers.ts
                      (CT-01 target keys, actions and their QL-08 reasons, filters, ports, log follow, how often stats
                      and a followed log are read), polling.ts (CT-01 when a background read may run, the next one's
                      delay, longer after failures), host-details.ts
                      (MO-13, MO-14 summaries, wording and the commands offered to copy),
                      presentation.ts (FD-03 masking: stand-ins, patterns, known values, TerminalMasker; MO-13 MAC
                      addresses as `mac-N`),
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
- MO-13 hardware keys in the .vmx: `numvcpus` (absent means 1), `cpuid.coresPerSocket`, `memsize`, `firmware = "efi"`
  (absent is BIOS), `virtualHW.version`; disks are `<scsi|sata|nvme|ide>X:Y.fileName` (relative to the .vmx's folder)
  with `.present` and `.deviceType` (`cdrom-image` and the like are not disks); adapters are `ethernetN.present`,
  `.connectionType` (absent is bridged; `custom` names `.vnet`), `.virtualDev`, `.addressType` (`static` uses
  `.address`, else `.generatedAddress`) and `.startConnected`. `guestInfo.detailed.data` also has `kernelVersion`.
- A VMDK is a text descriptor (`createType`, extent lines `RW <sectors> SPARSE|FLAT "<file>"`, a snapshot's delta has
  `parentFileNameHint`) or a sparse file starting with `KDMV` (capacity in sectors at byte 12, the embedded
  descriptor's offset and size in sectors at 28 and 36). A snapshot's delta disk names its parent; the chain's files
  together are what the disk takes on this PC.

## VirtualBox facts

VM-18, from 0.4.0 (`docs/plan-0.4.md`, Q5). VirtualBox 7.0 or later: `controlvm reboot` came with 7.0.

- `VBoxManage.exe` is in `C:\Program Files\Oracle\VirtualBox\` by default, and `HKLM\SOFTWARE\Oracle\VirtualBox`
  `InstallDir` names its folder. Never hard-code it: the app uses the path saved in Settings, then
  `REMOTELY_VBOXMANAGE`, then the registry (and the installer's `VBOX_MSI_INSTALL_PATH`), then the default folder
  (`adapters::virtualbox::locate_vboxmanage`). Without it the list simply has no VirtualBox VMs (no warning); an action
  on one fails with `vboxmanage_not_found`. With VirtualBox found and no Workstation VM at all, a missing vmrun is no
  warning either.
- A VirtualBox VM's key (`vms.vmx_path`, `TargetRef::Vm`, job targets, the audit log) is its UUID in lower case without
  braces; `vms.hypervisor` says `virtualbox` and `vms.config_path` holds its .vbox (migration 0012). No .vmx path can be a
  UUID, so `Hypervisor::of_key` routes each VM by its key. VBoxManage takes the UUID wherever it takes a VM name, and it
  stays the same when the VM is renamed or moved (its files move with a rename).
- `list vms` prints `"name" {uuid}` per line (`"<inaccessible>"` for a VM whose settings file is gone); `list
  runningvms` the same for running and paused VMs.
- `showvminfo <uuid> --machinereadable`: `key=value` lines. Strings are quoted, with `"` and `\` escaped by a backslash
  (Windows paths print as `C:\\Users\\...`); a value may run over lines (a snapshot description). Numbers are bare.
  Storage keys are quoted: `"SATA-0-0"="...vdi"`, `"SATA-ImageUUID-0-0"`, `emptydrive` or `none` for an empty drive.
  Keys used: `name`, `UUID`, `ostype` (the chosen type's description, "Ubuntu (64-bit)"), `memory` (MB), `cpus`,
  `VMState`, `VMStateChangeTime` (UTC without an offset, 9 fraction digits: the VM's start or resume while it runs),
  `CfgFile`, `accessible` (`off` when its settings file is gone: the VM is left out), `nicN` and `macaddressN`,
  `GuestAdditionsRunLevel` (only while they run: 1 VBoxService, 2 user, 3 desktop) and `GuestAdditionsVersion`. `VMState`
  is `running`, `paused` (VirtualBox reports a pause itself, unlike vmrun), `saved` (suspended), `poweroff`, `aborted`
  (crashed or killed: off), `aborted-saved`, or a busy state (`starting`, `stopping`, `saving`, `restoring`,
  `livesnapshotting`...; `adapters::virtualbox::power_state_of`).
- Snapshots: `showvminfo` (like `snapshot <uuid> list --machinereadable`) gives `SnapshotName`, `SnapshotUUID` and
  `SnapshotDescription` for the first snapshot, `-1`, `-2` for its children, `-1-1` for theirs, and
  `CurrentSnapshotNode="SnapshotName-1"` for "you are here". There is one root. Neither prints times: each
  `<Snapshot uuid="{...}" timeStamp="2026-10-18T01:59:23Z">` in the .vbox file has one. `snapshot list` fails (with a
  translated message) on a VM without snapshots, so the app reads the tree from `showvminfo`.
- Snapshot names: any text, `/` included (there is no path form). VirtualBox takes a second snapshot with a name the VM
  has, and `restore` and `delete` take the first by name, or a snapshot's UUID; so Remotely refuses a name the VM already
  has, and names a twin by its UUID (`SnapshotNode.path`). VirtualBox restores only a VM that is not running: the adapter
  powers a running or paused one off first, and the bus adds a warning to the approval. It can't delete a snapshot with
  two or more children. A snapshot of a running VM saves its memory (paused while it does; no `--live`).
- Power: `startvm <uuid> --type headless|gui` (a saved VM resumes); `controlvm <uuid>` `acpipowerbutton` (soft stop:
  returns at once, and works only if the guest OS handles ACPI, with or without Guest Additions; the adapter polls
  `showvminfo` until the VM is off, and the job runner stops waiting after the shutdown wait, VM-03), `poweroff`, `reset`
  (hard), `reboot` (soft restart through the Guest Additions, so the job runner checks their run level first, as it
  checks VMware Tools), `savestate` (suspend; needs nothing from the guest), `pause`, `resume`. `controlvm` on a VM that
  is not running fails ("is not currently running"). Each call has vmrun's time limit for its operation
  (`adapters::vmware::power_timeout`); job cancel kills VBoxManage, but VirtualBox may still finish.
- Guest properties (`guestproperty get <uuid> <name>` prints `Value: <value>` or `No value set!`):
  `/VirtualBox/GuestInfo/Net/Count`, `/Net/N/V4/IP`, `/Net/N/MAC` (as in `macaddressN`), `/OS/Product` ("Linux" for any
  distribution, "Windows 11"), `/OS/Release`. A NAT adapter's guest address (10.0.2.15 by default, in every VM) can't be
  reached from the host, so with a NAT and a host-only or bridged adapter the app takes the other one's address, matched
  by MAC (`adapters::virtualbox::guest_ip`).
- Each running VM is a `VirtualBoxVM.exe` (window) or `VBoxHeadless.exe` (headless) process with `--comment <name>
  --startvm <uuid>` on its command line. On Windows hardening starts it through two stub processes with the same command
  line, so the processes of one VM count as one (`host_counters::merge_vm_processes`).
- VBoxManage writes errors to stderr as `VBoxManage.exe: error: <message>` lines, then `Details:` and `Context:` lines;
  the app keeps the first kind. Guest control (`guestcontrol`) would put guest credentials on the command line: the app
  never uses it.
- MO-13: `showvminfo` also gives `firmware` (`BIOS`, `EFI`...), `nictypeN` (the card, e.g. `82540EM`, `virtio`) and
  `cableconnectedN` (`on`/`off`); the storage key (`"SATA-0-0"`) is the disk's slot. A VDI's header has the signature
  0xbeda107f at 0x40, its type at 0x4c (4 is a snapshot's differencing image) and the disk size at 0x170; a VHD's
  footer (`conectix`, big-endian) has the size at 48, at the start of a dynamic one and the end of a fixed one.

## Development safety

- Unit and integration tests must never stop, reset, suspend, revert or delete snapshots on real VMs. Use the fake VMware adapter, and `fakes::FakeVirtualBox` for VirtualBox.
- Tests against real Workstation or VirtualBox are opt-in: they run only when `REMOTELY_IT=1` is set, read only, and only touch VMs whose display name starts with `it-`.
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
- Containers (CT-01, CT-02): never start, stop, remove or prune real containers. Bus and policy tests use
  `fakes::FakeContainers` (`tests/containers.rs`); end-to-end tests use the test server's `docker` and `podman`
  (`with_containers(engine, Fixture::sample())`, `without_docker_group()` for sudo; `tests/containers_ssh.rs`).
  `Setup::with_ssh()` uses `CliEngines::without_this_pc()`, so no test ever finds or runs this PC's Docker Desktop.
- Host details (MO-13, MO-14): never read a real host. The test server's `with_host_facts(HostFixture::ubuntu())` (or
  `rhel()`: no lscpu, an lsblk without JSON, dnf) answers the specs, admin and updates scripts from real hosts'
  samples, and its toy shell knows `type`, `$?` and `NAME=value` before a command (`tests/host_details.rs`). VM
  hardware tests use `FakeVmware::with_hardware` or disk files made at run time in the system temp folder. Every
  command the scripts use must classify as read-only under the default rules (the tests check each one): naming
  `reboot` or `shutdown` as a word, even as `last reboot`, trips the dangerous-command rule.

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
  `web.test:80`, for trying chains and tunnels. CT-01: each has `docker` and `podman` with a small shop of containers
  (from the second server on, docker needs sudo); mark a session as a container host on the Containers page.
- Opt-in test against real Workstation (reads only: the library, `vmrun list`, Tools state and IP of running VMs, and their processes' counters): `REMOTELY_IT=1 cargo test -p remotely-core --test workstation_it`
- Opt-in test against real VirtualBox (reads only: `list vms`, then for `it-` VMs only `showvminfo`, snapshots, guest properties and their processes): `REMOTELY_IT=1 cargo test -p remotely-core --test virtualbox_it`
- Lint: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `npm run lint` (tsc, ESLint, Prettier)
- UI tests: `npm test` (Node's own test runner over `src/**/*.test.ts`: pure helpers only, no DOM; and the release scripts' tests, `scripts/*.test.mjs`, against a fake GitHub on 127.0.0.1)
- Dependency scan, as CI runs it: `cargo deny --locked check advisories bans sources` (cargo-deny is not a project dependency), `npm audit --omit=dev`
- Format: `cargo fmt --all`, `npm run format`
- Build the installer: `npm run tauri build`
- Release: bump the version in all three files, commit, then `git tag -a vX.Y.Z -m "<release notes>"` and `git push origin vX.Y.Z`; publish the draft release on GitHub after a smoke test. The tag message is the release notes users see in the update banner, so write it for them.

## Conventions

- Rust stable (the version in `rust-toolchain.toml`), edition 2021. Errors with `thiserror`. No `unwrap()`/`expect()` outside tests.
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
