# Remotely

A Windows desktop app for forward deployed engineers and IT admins: bulk control of VMware Workstation Pro VMs (and, from 0.4.0, Oracle VirtualBox VMs), a performance dashboard, a PuTTY/MobaXterm-style SSH session manager, and bulk command execution with grouped output, with multi-step approvals on every high-impact action.

The source of truth is `docs/PRD.md`, plus `docs/post-mvp-plan.md` for the work after the MVP (0.2.1 and 0.3.0), which moves some v2/v3 items into scope and replaces the Bulk run page with MultiExec and Compare in the Terminal page, `docs/plan-0.4.md` for 0.4.0 (VirtualBox, containers, host details, MultiExec recording and terminal fixes), and `docs/plan-0.5.md` for 0.5.0 (VM sizes, images and launch templates with deploy, full VM settings and lifecycle, VM and disk conversion, stacks, schedules, dashboard history and alerts, navigation, customer workspaces), `docs/plan-0.6.md` for 0.6.0 (decluttering the UI so it reads without a manual; the UI rules under Conventions), and `docs/plan-0.7.md` for 0.7.0 (the toolbox and health checks; RDP, VNC, Telnet, serial and WinRM sessions with Windows guest metrics and bulk runs; notes, favourites, the trash and bulk session edit; inventory, Ansible and handover exports, support bundles and a quick file server). Requirements have IDs (VM-xx, SS-xx, BX-xx, AP-xx, MO-xx, FD-xx, QL-xx for post-MVP quality-of-life items, CT-xx for containers, CV-xx for conversion, and UX-xx for the 0.6.0 declutter); refer to them in code comments, tests and commit messages. The PRD uses the working title "VM & SSH Manager"; the product name is **Remotely** (app identifier `com.remotely.desktop`).

## Locked decisions

- Stack: Tauri 2, Rust core (tokio), React + TypeScript + Vite UI, xterm.js, uPlot, SQLite via sqlx, russh for SSH.
- UI components: shadcn/ui (Radix base, Nova preset, Lucide icons) on Tailwind CSS 4. Build screens from shadcn components first; write custom CSS only for what shadcn does not cover (e.g. the xterm.js host).
- Single user only. No team mode, no server component.
- Windows 10/11 x64 with VMware Workstation Pro 17 or later, and from 0.4.0 Oracle VirtualBox (`docs/plan-0.4.md`, VM-18). Other hypervisors are not managed; from 0.5.0 Remotely reads and writes their VM and disk formats (`docs/plan-0.5.md`, CV-01 to CV-03). No Linux host support. macOS on Apple Silicon is a separate track after 0.4.0 with its own plan; until then nothing is built for it.
- RDP means launching `mstsc.exe` with a generated .rdp file (SS-12, 0.7.0); mstsc asks for the password, never the vault.
- Ansible: inventory export only (v2). The app never runs playbooks.
- **The repository is public** (the owner's decision, confirmed on 22 Oct 2026; it was private while field-tested from 0.2.0 to 0.4.0), so the "Public repository rules" below apply to everything, including history. Code and releases live in one GitHub repo, and installed apps auto-update from its GitHub Releases (FD-14). The updater reads the public releases without a token; the read-only token in each app's vault (`docs/post-mvp-plan.md`, P1, built while the repo was private) is optional.
- The MVP (32 requirements: VM-01 to VM-07, SS-01 to SS-06, BX-01 to BX-07, AP-01 to AP-06, MO-01 to MO-04, FD-01 and FD-14) shipped in 0.2.0. Post-MVP scope is exactly what `docs/post-mvp-plan.md`, `docs/plan-0.4.md`, `docs/plan-0.5.md`, `docs/plan-0.6.md` and `docs/plan-0.7.md` list. Do not build other v2/v3 items unless asked; if a change would add or drop scope, stop and say so.

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
- `.github/workflows/release.yml` runs on `v*` tags in two jobs (C1). **build** (`windows-latest`, no secrets, read-only token): the tagged commit must be on main and match the three version files; it builds the NSIS installer with `--locked`, the pinned toolchains and no cache, and uploads it as a workflow artifact. **publish** (`ubuntu-latest`, Environment `release`: the owner approves each run, `v*` tags only): signs the installer with `tauri signer sign --app-version`, checks the signature with `scripts/verify-update-signature.mjs --version`, then `scripts/publish-release.mjs` creates the **draft** release with the installer, its `.sig` and `latest.json` (tauri-action's format, API asset URLs), checking `latest.json` and fetching the installer back before it uploads it, and deleting the draft if anything fails (C6). The tag message is the release notes (written to a file, never `$GITHUB_OUTPUT`); the release page adds the installer's SHA-256 and how to check it (`releaseBody`; the installer isn't Authenticode-signed, by the owner's choice for now, so SmartScreen warns on a manual install: README "Installing"), while `latest.json`'s notes, which the update banner shows, stay the tag message alone. README "Release settings on GitHub" has the owner's settings (Environment, secrets, tag ruleset) and "Signing key compromise or loss" the runbook. The user publishes the draft after a smoke test; installed apps only see published releases.
- `tauri.conf.json`: `bundle.createUpdaterArtifacts: false` (the publish job signs, so no build needs the key); `plugins.updater.pubkey` holds the public key; `plugins.updater.requireSignedVersion: true` (C3: the plugin refuses a signature whose trusted comment names another version than `latest.json`); `plugins.updater.endpoints` is `["https://github.com/khilfi/remotely/releases/latest/download/latest.json"]`, which names the repository the app updates from (the app doesn't fetch that URL, see the next point); `plugins.updater.windows.installMode: "passive"`.
- Update checks and the update token (FD-14; the token is `docs/post-mvp-plan.md` P1, built while the repo was private, and **optional while it is public**): the updater (`src-tauri/src/updater.rs`) finds the latest release through the GitHub API (`crates/core/src/adapters/github.rs`), then has `tauri-plugin-updater` fetch `latest.json` and the installer. **Without a token** (none in the vault, or the vault locked) no request carries `Authorization`: the API call goes without one, and the files come from the release's public download links (`browser_download_url` on github.com, which redirect to GitHub's storage; `latest.json`'s API asset URLs are mapped to the same file's link, anything else is refused). GitHub allows 60 API calls an hour per internet address without a token (one per check; the downloads don't count). A 403 or 429 for a used-up limit backs off until GitHub's reset (`retry-after`, else `x-ratelimit-reset`; at least a minute, at most a day; `github::rate_limited_until`): until then a check makes no call and says `UpdateCheck::RateLimited`, and the UI checks once more after the reset. A 404 without a token means the repo went private again: `UpdateCheck::TokenNeeded`, or `VaultLocked` when the vault holds a token but is locked. **With the GitHub update token** (a fine-grained token for this repository only with Contents: Read-only and an expiry, entered in Settings → Updates; README "GitHub update token" says when it's worth having and how to create, enter and replace it), every check and install uses it as while the repo was private: the API with `Authorization`, then `latest.json` and the installer from their API asset URLs with `Accept: application/octet-stream`; GitHub redirects to its storage, and reqwest drops the token on that redirect. Any other URL is mapped to the release's file of the same name, or refused, so the token only goes to the API, never to github.com; an install maps the installer's URL again for its own way (the vault may have locked or unlocked since the check). A refused token or one without access is an error that says to replace or remove it; it doesn't fall back to no token. The token is a vault secret (`password` kind, label "GitHub update token"; its id is the setting `updates.tokenId`, the expiry GitHub reports is `updates.tokenExpiresOn`), write-only in the UI with Test, Replace and Remove. The release workflow keeps writing API asset URLs into `latest.json`: copies from 0.2.1 to 0.4.2 require a token and fetch through them. Signatures are verified against the public key exactly as before, either way. Before an update is offered, `adapters::updater::check_signed_release` (C3) checks the signature's trusted comment against the public key and requires `file:<productName>_<version>_x64-setup.exe` and `version:<version>` for the version `latest.json` announces, so an old signed installer can't come back as a newer version. The token never reaches logs, errors, the UI state, the audit log or exports. Tests use `fakes::github_server::FakeGithub` (API, github.com and storage on 127.0.0.1; private until `set_public`; both rate limits) and `UpdateSigner` (a throwaway minisign key); never a real token. Copies on 0.2.0 or older can't update this way and need one manual install of 0.2.1 or later.
- Windows installer: NSIS only (`bundle.targets: ["nsis"]`), installed per user (`bundle.windows.nsis.installMode: "currentUser"`), so installing and auto-updating never need admin rights. Decided before v0.1.0; switching installer type after release would strand existing installs.
- In the app (FD-14): check at start and every 24 hours (and once more after a used-up GitHub limit resets), and show the new version and its release notes. Installing is a Medium-tier command through the command bus, and it waits until no job is running. A setting turns update checks off for air-gapped sites.

## Architecture rules (non-negotiable)

1. **One way in for changes.** Every state-changing action (VM power, snapshots, remote commands, file writes, kills) is a typed command submitted to the command bus. It goes command bus -> policy engine -> job runner -> adapter. The UI, a future CLI, plugins and any AI helper never call `vmrun`, `vmrest` or SSH directly.
2. **Policy engine decides the tier** (Low, Medium, High, Critical; a Prod-labelled target moves an action up one tier) and the approval steps. Nothing runs at High or Critical without the approval answer from the UI. See the tier table in `docs/PRD.md`.
3. **Reads skip approval.** Inventory and metrics reads go adapters -> metrics collector -> store -> UI.
4. **Audit everything that changes state.** Append-only audit log, written when an action starts and when it ends, each entry hash-chained to the previous one.
5. **Every record carries `workspace_id` and `user_id`** from day one. Still one user; from 0.5.0 (FD-02) there are several workspaces, and rule 8 says what that asks of every feature.
6. **One adapter per outside system** (VMware, remote/SSH, host counters), each behind a Rust trait so tests can use a fake.
7. **Secrets live only in the vault.** Never put passwords, keys or passphrases in logs, audit entries, job output, exports, error messages or the UI state. The vault hands secrets to adapters only. A vault password goes to a host without the vault password being asked again only where it already goes (`vault::bindings`): anything that sends one somewhere new checks `SecretBindings::may_go` and asks with `SecretBindings::confirm` (`reauth_required`).
8. **Workspaces (FD-02).** What the user makes belongs to the shown workspace: read it with `core.ctx()` per call (never a context kept from start-up) and store it with that `workspace_id`; a service that keeps state takes `workspaces::Current` and lets go of the old workspace's when it changes. A VM is reached only after `Store::require_vm_here` or the bus's target resolution (`NotInWorkspace` for another workspace's, `VmUnassigned` for one no workspace has; a deploy's source VMs too, `DeploySpec::require_sources_here`); a VM a feature makes is `assign_vm`ed to the job's workspace, one it deletes `release_vm`d. A new setting is per workspace unless it describes this PC: then it goes in `settings::MACHINE_KEYS` (kept in the home workspace), else `WORKSPACE_KEYS` if `repair` must check it. An event stream the window shows is filtered to the shown workspace in the shell (jobs by `JobRunner::workspace_of`, schedules by `subscribe_scoped`). Work that goes on in hidden workspaces (schedule runs) uses that workspace's own ctx and audits there. An FD-07 export holds one workspace. A new per-workspace store gets a case in `tests/workspaces.rs`.

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
    command_bus.rs    AP-01 approvals expire after APPROVAL_TTL (15 min, audited approval_expired); one whose target
                      became Prod or protected since is asked again (ApprovalChanged, same id) instead of running;
                      AP-06 set_rules_with: a change PolicyRules::loosened names needs the vault password; BX-07 a
                      sudo password new to some targets adds VaultReauth to the approval, then they may use it;
                      command_bus/standing.rs VM-14, VM-27 standing approvals: ask_standing at a schedule's save (the
                      steps of its highest command, no countdown; Low granted at once), approve_standing records a
                      StandingGrant (content hash, PolicyRules::fingerprint of the rules that rated it, tier, command
                      templates, targets with their labels then, the answers; migration 0025), submit_standing checks
                      each scheduled command (read-only lock; edited, new, Prod or protected targets, rules changed:
                      StandingChanged, nothing runs; another command or a revoked grant refused, approval_refused),
                      audits approval_used; ApprovalRecord.standing names the schedule and run in the job's entries;
                      command_bus/change_id.rs AP-08 ChangeIdRules (`approvals.changeIds`, per workspace: required for
                      Prod) and clean_change_id (one line, 64 characters, export::redact_secrets); ApprovalStep::ChangeId
                      on High and Critical, made required by apply_change_id_rule (submit, preview, ask_again,
                      ask_standing); kept in ApprovalRecord.change_id, jobs.change_id (migration 0029), the audit CSV's
                      change_id and the Compare and MultiExec exports; a standing grant without one asks again once the
                      rule requires it; FD-02 resolve_targets refuses another workspace's VM, a Register of one too
    settings.rs       QL-15 settings this version can't read are set aside (`<key>.unreadable`), audited, and get
                      their defaults at start, instead of stopping the app; FD-02 MACHINE_KEYS, this PC's settings,
                      which the store keeps in the home workspace whichever is shown, and WORKSPACE_KEYS
    policy/           tiers and steps; FD-03 read_only_refusal: the read-only lock refuses every command and edit;
                      AP-01 RUNS_ANYTHING: shells, interpreters and command runners can't be read-only entries
                      SS-07 a loopback SOCKS tunnel is at least Medium while other users are signed in to this PC
                      (set_other_users, from HostCounters::other_users_signed_in: WTSEnumerateSessionsW);
                      standing.rs VM-14, VM-27 evaluate_standing (a schedule rated as the highest of its commands, no
                      countdown) and PolicyRules::fingerprint (the tiers, thresholds, Prod rule, countdown and safety
                      default that rate given actions)
    presentation.rs   FD-03 presentation mode (saved, fail closed, audited) and ReadOnlyLock, which the store shares
                      with the bus and every service that edits the app's data (Change)
    workspaces.rs     FD-02 (migration 0029): Workspaces (create, rename, colour, archive, restore; audited in the
                      workspace, Change::Workspaces), Current (the shown workspace, a watch every service reads),
                      Core::switch_preview and switch_workspace (refused while a job started from the UI in the shown
                      workspace is open, WorkspaceBusy; closes MultiExec, terminals with their tunnels, approvals, kept
                      connections, the metrics hub and an opened FD-07 file; history minutes written to the old one;
                      audited workspace_left and workspace_opened; `workspaces.current` saved), and FD-07's
                      import_into_new_workspace. One vault key for all workspaces (each item's AAD names its workspace)
    jobs.rs           QL-15: a failing journal or audit write is logged and the job goes on to its real result
                      (job_finished always tried); the update install races the job's cancel token; BX-02 when_idle:
                      compaction holds new jobs back and runs only while none is open. H9 `Rollout` of
                      a RemoteExec: canary (first host alone, then JobEvent::CanaryWaiting until CommandBus::go_on,
                      CANARY_WAIT 15 min, audited canary_go_on) and stop_after_failures (no new hosts; running ones
                      finish; skipped); TargetStatus::Unknown for CommandTimedOut and in-flight cancels (retry_failed
                      leaves them out unless include_unknown, and refuses redacted or purged runs); each remote target
                      journals peer_ip and the accepted host_key (BulkVerifier; migration 0018), listed at job_finished;
                      FD-02 JobOwner: each open job's workspace and whether a schedule started it (workspace_of,
                      open_user_jobs, cancel_in; go_on only from the job's workspace)
    retention.rs      BX-02 how long the job journal keeps outputs and command text (Settings: 30 days, 90 by default,
                      1 year, forever; `jobs.retention`): the purge at start and daily (JournalRetention::run, wall
                      clock), Purge now, audited journal_purged; secure_delete, a WAL checkpoint and VACUUM after a big
                      purge; the read-only lock refuses the setting and Purge now, never the schedule
    save_guard.rs     No save path writes into a Git working tree (audit CSV, Compare and MultiExec exports, saved
                      output, session logs, downloads, FD-07 exports, FD-04 bundles, FD-09's upload folder);
                      write_atomically (a `.part` file, renamed), and AtomicFile, the same for a file written bit by bit
                      (a bundle's zip; its `.part` goes on every failure, a failed commit's too)
    adapters/         vmware.rs (VM-23 also the .vmx's backup, atomic write and restore, vdiskmanager and vmware.exe
                      found beside vmrun, vmrun_change; VM-21 ovftool found like vmrun, Workstation's default VM
                      folder), vmx_file.rs (VM-23 a .vmx as its lines: unknown keys, order,
                      comments and line endings kept; |XX escapes; non-UTF-8 refused), virtualbox.rs (VM-18
                      VBoxManage: list, showvminfo, guest properties, power,
                      snapshots; SwitchableVirtualBox for the Settings path; VM-23 change(), list ostypes,
                      screenshotpng, VirtualBoxVM --separate, the .vbox's extras; VM-21 the default machine folder,
                      host-only and bridged adapters, unattended detect), hypervisor.rs (VM-18 Hypervisor, and
                      Hypervisors: both adapters, each VM routed by its key), remote.rs (SSH shell and exec;
                      keyboard-interactive answers are SecretStrings until russh's respond call; A9 at most 16 login
                      banners and 64 KB per connection, then one note; every path through the SS-07 jump host
                      chain over
                      direct-tcpip channels, each hop's own host key check and login; remote/sftp.rs SS-08 SFTP on a
                      terminal's own connection, behind the RemoteFiles trait (H8: a replace writes a hidden temp
                      file, keeps mode and owner, posix-rename, else a .bak; RemoteWrite::abort; Written says how; A9
                      a second RawSftpSession for capped listings, MAX_LISTING); remote/forward.rs SS-07 port forwards on
                      it, local, remote and SOCKS, behind RemoteForwards; remote/socks.rs SOCKS 4/4a/5),
                      telnet.rs (SS-12 RFC 854 client: NAWS, TTYPE, ECHO, SGA, Enter as the session's line ending,
                      local echo when the server won't; the same shell channels as SSH), serial.rs (SS-12 COM ports from
                      HARDWARE\DEVICEMAP\SERIALCOMM, opened with CreateFileW and SetCommState behind SerialPorts; one
                      thread per port, Send Break), launcher.rs (SS-12 ConsoleLauncher: mstsc.exe from System32 on a
                      .rdp file in this user's temp folder, deleted once read; the VNC viewer found like the other tools,
                      locate_vnc_viewer, `consoles.vncViewerPath`; NoLauncher under `fakes`),
                      exec_output.rs (BX-02/BX-07 output cap, hashes,
                      secret scrubbing), host_counters.rs (MO-01 VM processes: vmware-vmx.exe, VirtualBoxVM.exe,
                      VBoxHeadless.exe; MO-15 `paging()`), paging.rs (MO-15 this PC's paging files and commit charge:
                      GlobalMemoryStatusEx and NtQuerySystemInformation's page file list), vm_hardware.rs (MO-13 a VM's
                      hardware from its .vmx or showvminfo; VMDK descriptor and sparse header, VDI, VHD and qcow2
                      headers for provisioned sizes; size on disk down a snapshot chain; A3 a disk, extent or parent
                      whose resolved path is on a share or a device path is never opened, so a .vmx kept on a share
                      shows its disks as not read; A9 the .vmx up to 4 MB, a text descriptor up to 1 MB, read whole or
                      refused; VmFiles: LocalFiles, or memory in tests), host_networks.rs (VM-11 the tools' network
                      output: listHostNetworks, listPortForwardings read loosely with vmnetnat.conf's [incomingtcp] and
                      [incomingudp] as the fallback, list hostonlyifs, list --long natnets, a VM's Forwarding(N) by
                      the adapter keys before it; the change arguments; process_elevated; hardware_retrying: asked
                      again while VirtualBox says another client holds the VM's lock), updater.rs, github.rs (FD-14
                      GitHub Releases API without a token or with the optional update token, public download links,
                      rate-limit backoff), network.rs (DNS for QL-01 auto-linking and QL-03 host name and IP, QL-04
                      TCP probe), net_tools.rs (FD-09 the toolbox's NetworkTools trait, behind `Adapters.network_tools`:
                      ICMP echo with a TTL (IcmpSendEcho2, Icmp6SendEcho2), DnsQueryEx with Windows' resolver or a
                      chosen server, a TCP connect, a chain's trust check (CertGetCertificateChain with only what this
                      PC has: no root, intermediate or revocation download), GetAdaptersAddresses, and the Wake-on-LAN
                      datagram; the Windows calls in net_tools/win.rs; remote.rs's ExecSession::open_direct, a
                      direct-tcpip stream from a host, for checks behind a jump host), containers/ (CT-01, CT-02: the
                      ContainerEngine and ContainerEngines traits; cli.rs
                      the docker and podman CLIs over a kept SSH connection's exec channels, with sudo from the vault
                      (ExecSession::run_sudo) or NOPASSWD, and docker.exe on this PC, found like vmrun, its output
                      streamed through exec_output's OutputCollector (A9: capped, never buffered whole); parse.rs both
                      CLIs' JSON field by field (env values never leave it; a command and entrypoint go through
                      export::redact_secrets, parse::command_line); names.rs checked ids, volume names and
                      image references, every word shell-quoted on hosts), disk_tools.rs (CV-01 to CV-03, VM-17 the
                      conversion tools behind DiskTools: qemu-img found from Settings, `REMOTELY_QEMU_IMG`, then
                      QEMU's default folder, never shipped; vdiskmanager, VBoxManage and ovftool from the hypervisor
                      adapters' paths; each run streamed for its own progress, timed, killed on cancel)
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
    updates.rs        FD-14 update checks (UpdateCheck: without a token unless the vault gives one) and the optional
                      GitHub update token in the vault
    inventory.rs      VM-01 Workstation's and (VM-18) VirtualBox's VMs; a VirtualBox VM is kept when VirtualBox can't
                      be asked; P2 refreshes single-flight and coalesced (RefreshGate: requests while one runs share
                      the next run); FD-02 discovery is for this PC, and each VM belongs to one workspace
                      (vm_assignments): the found VMs no workspace has are `unassigned()` (in memory, joining the only
                      active workspace by themselves), claim and release (audited vm_assigned and vm_released; never a
                      protected or Prod VM out, never with one workspace); StoreDirectory refuses another's VM
    capacity.rs       VM-07 capacity check before power-on; VM-02 `bridged`: starting 2+ VMs warns about bridged
                      adapters plugged in at power-on (one confirm)
    capacity_plan.rs  VM-26 the deploy capacity planner: RAM, CPU and disk per drive after a deploy next to now
                      (thin disks at full size; `plan` pure, `deploy_capacity` reads), in DeployCheck, the stack
                      deploy check and the approval (ApprovalRequest.capacity); `suggest_suspend` names running VMs
                      to suspend when RAM won't fit (never protected or paused, Prod last, fewest VMs), also added to
                      VM-07's warning at power-on
    stacks/           VM-08 stacks (migration 0028; audited `stack_changed`, no tier, Change::Stacks, FD-07 inside
                      the catalogue's section): spec.rs StackInput (templates with counts in boot order, Readiness
                      none, tools or a port, wait and delay per step) and StackOp, what Command::Stack carries:
                      Deploy (each step a whole DeploySpec tagged with `stack: StackTag`, so R2's runner records each
                      VM in the instance as it is made), Power (start in boot order with the readiness checks and
                      delays, shut down or suspend the last step first; the power op's own ActionKind) and Teardown
                      (R3's delete on each VM, linked-clone guard included; ActionKind::StackTeardown, Critical;
                      hand-added VMs only when picked);
                      mod.rs Stacks (Core.stacks: CRUD, check, deploy, instances, power, teardown, add or take a VM
                      out by hand, forget, `stack_vms` for R7); runner.rs StackRunner, the job runner's StackActions
                      (instance records, readiness waits and delays on a StackClock: fakes/stack_clock.rs in tests);
                      preview.rs StackDetails for AP-02. The job runner runs a stack's steps in order (`run_stack`): a
                      step that fails or isn't ready in time skips the steps after it; a retry runs those too
    snapshots.rs      VM-04 snapshot trees (from .vmsd, or VirtualBox's showvminfo and .vbox), VM-05 safety snapshot
                      names
    catalog/          VM-19 to VM-21 the spec catalogue (migration 0019; audited `catalog_changed`, no tier,
                      Change::Catalog): sizes.rs (the twelve built-ins, read only, named by their name; own sizes by
                      UUID), profiles.rs (OS profiles: firmware, controller, NIC, guestOS / --ostype, hardware version
                      20; Windows 11 on VirtualBox only), images.rs (golden VM + snapshot id, cloud image, ISO,
                      OVA/OVF; format by extension checked against the first bytes; SHA-256 on a blocking thread with
                      progress and cancel; untrusted::path_refusal first; IMAGE_SITES and checked_site, the cloud
                      image pages allow-list), templates.rs (check_template, problems, naming {n} {template} {date},
                      resolve: a template and a count into a DeployPlan per VM, pure; VM-22 the guest user,
                      packages and full or linked clone, migration 0023); mod.rs the Catalog service (Core.catalog;
                      `plan`, and `plan_input` for the Deploy dialog's Custom, are the deploy's entry)
    deploy/           VM-21, VM-22, VM-10 deploy. spec.rs DeploySpec: what is approved is what runs (Command::Deploy,
                      built only by Core.deploy, never from the UI: check_from_ui); one job step per new VM
                      (TargetRef::NewVm, `new-vm/<hypervisor>/<name>`, target kind `new_vm`, migration 0023);
                      ActionKind::VmDeploy is Medium, High from PolicyRules.deploy_bulk_threshold VMs (5) or for Prod
                      (policy/deploy_tests.rs). preview.rs the AP-02 preview: names, hypervisor, folder, size, disk
                      space per VM and in all (thin disks at full size), network; a thick disk that doesn't fit or a
                      VM folder that is there already refuses, thin disks that may not fit warn; a Workstation linked
                      clone is refused while Workstation holds the golden VM (`vm_settings::workstation_lock`, VM-23's
                      rule: the clone writes the golden VM's .vmsd), checked again by the runner, and warned about
                      while Workstation's window is open; a full clone only reads the golden VM. service.rs Deploys
                      (Core.deploy: check and submit, check_clone and submit_clone for VM-10's bulk clone; a VirtualBox
                      unattended install's vault password adds VaultReauth). runner.rs Deployer, the job runner's
                      DeployActions (PARALLEL_VMS, 2, at a time): each VM made by clone, cloud image, ISO or OVA/OVF;
                      the size's CPU and memory, the boot disk grown to the size's (never shrunk; not for a linked
                      clone); its folder joins the scanned folders; the clean snapshot before the first boot; power on
                      (a bulk clone's copy stays off, like its source);
                      the IP waited for (300 s; a report, not a failure); its SSH session saved and linked by hand
                      (QL-01); the console. A failure or a cancel removes only what that VM's step made (`Made`:
                      deleteVM, or unregistervm --delete, retried, and closemedium for its seed; then its folder;
                      never a folder that was there);
                      VMs already made stay. workstation.rs and virtualbox.rs the command lines, pure; vmx.rs a new
                      VM's .vmx; cloud_init.rs VM-22 meta-data and user-data (hostname, guest user with sudo, SSH
                      public key, packages; never a password) and Workstation's guestinfo keys; seed.rs the NoCloud
                      seed (ISO 9660 with Joliet, label `cidata`) and its reader for tests; ovf.rs an OVF's or OVA's
                      disk capacities for the preview (an OVA's first tar members only) and its descriptor (CV-01);
                      CV-01 service/import.rs: an import is a deploy (ImportRequest, check_import, submit_import;
                      DeploySource::Import, DeployOrigin::Import); the runner copies VMDK and raw (Workstation) or
                      VMDK, VDI, VHD and raw (VirtualBox) itself and converts the rest (qcow2, VHDX; VHD and VDI on
                      Workstation) through Converter::convert_into, which also makes R1's qcow2 cloud images deploy
    convert/          CV-01 to CV-03, VM-17 conversion (other hypervisors' formats read and written, never managed).
                      formats.rs DiskFormat and OutputKind (VMDK sparse, flat, stream-optimized, ESXi's vmfs; VDI,
                      VHD, VHDX dynamic or fixed; qcow2; raw); inspect.rs CV-03 Inspect from each header (MO-13's
                      readers, VHDX's region and metadata tables, qcow2's backing file and encryption, a raw disk's
                      MBR or GPT; a parent or backing file is a problem but a Workstation delta, which vdiskmanager
                      flattens); plan.rs which tools, pure: the hypervisors' own first (vdiskmanager for VMDK,
                      VBoxManage for VDI, VHD and raw, VirtualBox's own differencing chains), qemu-img for qcow2 and
                      VHDX, at most two steps through a growable VMDK or VDI, Azure's whole MB through a VDI or qcow2
                      a tool resizes; qemu-img never reads a disk with a parent; NoPlan::NeedsQemuImg says what
                      needs it; args.rs every command line (qemu-img always with `-f`/`-F`); spec.rs ConvertSpec
                      (Command::ImageConvert, TargetRef::DiskImage `disk-image/<path>`, migration 0027) and
                      ExportSpec (Command::VmExport, the VM as target), both refused from the UI and Low (a Prod
                      VM's export Medium; policy/convert_tests.rs); runner.rs Converter, the job runner's
                      ConvertActions: a work folder `.remotely-<job>` beside the output, files moved into place,
                      nothing ever replaced, a free-space check first, VirtualBox's media list restored (clonemedium
                      registers its source and target), the job's progress (JobEvent::TargetProgress), everything
                      the job made removed on failure or cancel; an export makes `<folder>\<vm>-<target>`; targets.rs
                      each target's README (how to import, driver changes), the libvirt domain XML and the Proxmox
                      script (names are slugs); describe.rs OVF, libvirt XML and Proxmox .conf read as untrusted
                      (1 MB cap, no DTD, depth and element caps); import.rs CV-01 what a picked file is and brings;
                      verify.rs CV-03 Verify (sizes, SHA-256 of each file, qemu-img compare); service.rs
                      Conversions (Core.convert): tools, Inspect, options and submits, Verify, QEMU's download page
                      (checked_qemu_site)
    impact.rs         AP-02 impact preview for the approval dialog
    export.rs         AP-05 audit log CSV export and secret redaction; A10 every CSV the core writes (audit, BX-05
                      Compare, QL-12 MultiExec) goes through push_row/csv_cell: a `'` before a cell that starts a
                      formula (=, +, -, @, their full-width forms, tab or CR, also after leading whitespace), quoted
                      for `,` `"` `;` tab and line breaks
    untrusted.rs      A3, A8, A9 hostile input: path_refusal (shares `\\x` `//x`, `\\?\` `\\.\` `\??\`, DOS device
                      names; by text alone, never the file system), read_capped (a file whole up to a cap, or
                      TooLarge; MAX_VM_CONFIG_BYTES 4 MB), is_format_char (Unicode 16.0's Cf table), is_device_name
    metrics/          MO-01 to MO-04: mod.rs (collector, in-memory history, dashboard rows; MO-15 allocated memory, swap
                      and this PC's RAM and paging files per round; RoundObserver: after each round, history.rs and
                      alerts; collect_once_at for tests' own clock), history.rs (MO-06 Rollup: 1-minute averages with
                      min and max, written once a minute in one transaction; bucket: ranges of 1 h to 7 d;
                      HistoryRetention 1 to 30 days, 7 by default, `metrics.historyRetention`; the daily prune with
                      resolved alerts, checkpoint and VACUUM through when_idle, audited history_pruned), guest.rs (MO-02 SSH polling, kept connections,
                      backoff for unreachable hosts, login_guard parks and caps, GuestState::Paused and
                      GuestStatus.parked; MO-13 reads a host's facts on its kept connection when they are old; P8
                      POLL_KEY: every 5, 15, 30 or 60 s), procfs.rs (one `grep` of the /proc files, `df` once a
                      minute (DF_EVERY), and their parsers); HostProcessSource reads no inventory with no VM process;
                      FD-02 the samples are the shown workspace's VMs, and other workspaces' running VMs go only to
                      their own workspace's history (SourceRound::elsewhere, one Rollup per workspace) so VM-14's idle
                      check works in a hidden workspace; guest polling, the hub and MO-07 alerts follow the shown
                      workspace only; a round during a switch is dropped
    host_details/     MO-13, MO-14 (reads only: no bus, no audit, not stopped by the read-only lock): mod.rs
                      (SpecsCollector: a session's facts read when a terminal connects, on its own connection's exec
                      channel, or by the dashboard; HostDetails: Refresh, admin reads and updates on a terminal's, the
                      dashboard's or its own kept connection; VM specs from the hypervisor's files; facts stored per
                      session and VM, migration 0014), linux.rs (SPECS_SCRIPT and its parsers: os-release, uname,
                      lscpu or /proc/cpuinfo, meminfo, swaps, lsblk JSON or pairs, df, systemd-detect-virt), admin.rs
                      (ADMIN_SCRIPT and UPDATES_SCRIPT: systemctl or rc-status/service, ss or netstat, who, last, ps,
                      apt or dnf; every command checked read-only by `classify_script` in tests; FD-05 PORTS_SCRIPT),
                      networks.rs (QL-21 every VM's adapters for the map from the stored hardware; only VMs never read
                      are read, `fresh` reads all, NETWORK_READS_AT_ONCE; VM-11's report takes its VMs' adapters from
                      here too), packages.rs (FD-05 PACKAGES_SCRIPT: `dpkg-query -W -f=...` or `rpm -qa`, never stored,
                      MAX_PACKAGES); FD-05 HostDetails::inventory_read (facts stored, ports, and as asked updates and
                      packages, on the connection a Refresh uses; its own logins through the LoginGuard: parks, cap)
    alerts/           MO-07 rules.rs (metrics, scopes, BUILTINS and why some start off, checks, messages), eval.rs (the
                      Evaluator: threshold and duration, resolve after a minute clear, cooldown, unreachable, VMs
                      stopped without a Remotely job; no I/O), mod.rs (Alerts: the RoundObserver, the round's targets
                      as the grid shows them, rule edits and acknowledge audited and locked (Change::Alerts), the
                      alert list, AlertEvent for the UI and QL-25; open alerts closed at start; MO-08 checkDown,
                      checkSlow (ms) and certExpiring (days, fires below) on the allChecks and check scopes, built-ins
                      check-down and cert-expiring on, each round adding CheckReadings from the checks; migration 0030)
    schedules/        VM-14, VM-27 (migration 0025, Core.schedules, Change::Schedules): spec.rs ScheduleSpec (action:
                      snapshot keep N, start, stop, suspend, resume; targets: VMs, tags, VM-08 stacks (every VM of every
                      instance, via_stack for the ask-again message);
                      content_hash; snapshot_name `Remotely schedule '<name>' <local time> (run <id>)`), timing.rs
                      (hourly, daily, weekly in local time, idle; next_after: a time the clocks jump over runs at the
                      first minute after, a repeated one once, both noted; due_between for missed runs), clock.rs
                      (Clock: SystemClock, Windows' zone; fakes/clock.rs FakeClock and FakeZone with EU and US rules),
                      idle.rs (VM-14 auto-suspend from the history's 1-minute averages and the live rounds; a gap is
                      not idle), chains.rs (VM-27 ChainLimits `schedules.chainLimits`, assess from MO-13's disk
                      chains), mod.rs Schedules: save asks the bus (an edit of the content withdraws the approval),
                      tick (each active schedule checked: changes pause it, NeedsApproval; due runs start; over 2 min
                      late is missed, reported once, never caught up; the read-only lock skips; a run still going
                      skips), runs on the bus under the grant (power runs leave VMs already in the state alone;
                      snapshot runs record each new snapshot by id, retention deletes only those whose id and name
                      still match), ScheduleEvent for the UI and QL-25, schedule_* audit events
    dashboard.rs      MO-16 the layout (`dashboard.layout`, per workspace, null is the default): widgets on 4 columns
                      and 1 to 6 rows, checks, audited dashboard_layout_changed, Change::DashboardLayout
    notifications.rs  QL-25 the notification centre's history in memory (no migration; the module says why): the UI
                      adds entries, titles and bodies through export::redact_secrets and without control or Cf
                      characters, MAX_NOTIFICATIONS 500, per workspace, read, unread, clear, `once` keys; links are the
                      UI's AppLink JSON, kept as given; not audited, not locked
    notes/            FD-06 (0.7.0, migration 0033): mod.rs Notes (Core.notes): one markdown note per session, VM (by
                      its key) and folder; save, set_handover, list (QL-20), import (FD-07), audited note_changed
                      without the text, Change::Notes; for_handover (F6) renders the marked ones with LinkMode::Static,
                      which redacts secrets first (rule 7: the pack is an unencrypted file), makes a web link its text
                      and address as text (no href or title in the pack), and redacts their body too;
                      a session's note goes to the trash with it, a folder's is deleted with it; render.rs
                      pulldown-cmark (tables, task lists, strikethrough): raw HTML and images become text, only http(s)
                      and app links (session:, vm:, vault: by label, command:, runbook:) are links, each
                      `data-note-link="N"` with no address (RenderedNote.links), code blocks `data-note-code="N"`
                      (codeBlocks, for Send to terminal), looks_secret from export::redact_secrets
    stars.rs          QL-26 (migration 0033): Stars (Core.stars): stars on sessions, VMs (by key) and commands
                      (`favourite:<id>`, `library:<id>`), and the MAX_RECENTS (20) sessions, VMs and pages opened last
                      (a terminal's session notes itself in Store::record_session_opened); per workspace, not audited,
                      not locked, kept by key so a restored session keeps its star
    trash/            QL-27 (migration 0033): mod.rs Trash (Core.trash): move_to_trash, in the delete's transaction, for
                      a session (its whole row, SS-12's protocol and kind_options too, with its port forwards, container
                      marks, saved group places, secret grants, its own QL-17 highlight rules (reloaded on restore),
                      its MO-08 health checks (without their results; Checks reloaded on delete and restore, under
                      MAX_CHECKS), tags, note, where it went and what it sent, SentThen, and the sessions and folders
                      whose jump host it was, named on restore), a favourite command, size, image, launch template or
                      stack
                      (SessionLibrary, Snippets, Catalog and Stacks call it); restore under the item's own id (a new one
                      if taken), " (restored)" for a taken name, gone folders, jump hosts (or one that is no longer an
                      SSH session), VMs, vault items and groups left out with notes, AP-06 confirm when a restored
                      session would send a vault password somewhere new; undo (a delete's toast), delete_now, empty,
                      purge (KEEP_DAYS 30, daily, every workspace; run); audited trash_restored, trash_deleted,
                      trash_emptied, trash_purged; Change::Trash; never in FD-07; rows.rs rows as JSON column by column
                      (TABLES only; a restore writes the columns the table has now, names quoted)
    sessions.rs       SS-01 session library, SS-06 labels (audited, no approval tier); QL-28 bulk_preview and
                      bulk_edit (BulkEdit: folder, port, user, login, jump host, environment, tags added or removed;
                      each checked like an edit, so the preview shows what `tidy` keeps for each kind and
                      BulkEditRow.skipped names the fields a kind doesn't take; Store::update_sessions in one
                      transaction, one audit entry naming every session, confirm_folder_change once for AP-06);
                      rate_startup rates a startup command like a run on the session (editor, SS-02 and FD-07
                      previews, audit); startup_on_reconnect
                      and prompt_hook per session (migration 0015); sessions/tree.rs the QL-04 tree (by folder, tag
                      or label) for the Terminal page; sessions/defaults.rs QL-16 folder defaults (user, login, jump
                      host, label, tags; migration 0021) and Folders::resolve, the one resolver: a session's own
                      value, then the nearest folder up the path, then the app's default (tags add up; labels only
                      add; a folder's jump host never applies to itself). The store resolves every session it reads
                      (SessionRecord's fields are what applies, `own` what the editor edits, `inherited` the folders),
                      so every consumer gets it; set_folder_defaults, move_to, move_folder, delete_folder and restore
                      check SecretBindings like a session edit (confirm_folder_change, SecretPlaces read once);
                      sessions/kinds.rs SS-12 SessionKind (the `protocol` column; each kind's fields in `kind_options`,
                      migration 0031): SSH, RDP (screen, clipboard, drives, printers, audio, admin), VNC (view only),
                      Telnet (line ending), serial (the host is the COM port; speed, framing, flow control, line ending,
                      local echo). Only SSH logs in with the vault (others: "asked when connecting"), a jump host is an
                      SSH session and only SSH, RDP and VNC take one; Store::session_spec refuses every other kind, so
                      no SSH feature (bulk runs, MultiExec, guest polling, containers, host details) reaches one
    forwards.rs       SS-07 saved port forwards per session (audited like the library; opening one is
                      Command::OpenTunnel on the bus)
    vm_links.rs       QL-01 sessions linked to the VMs they reach: automatically by guest IP, or by hand (audited);
                      P3 a name looked up once at a time and cached, lookups done by the deadline kept and the rest
                      finished in the background, sessions behind a jump host never looked up; A4 never linked
                      behind a jump host or across environment labels (not_linkable)
    vm_settings/      VM-11, VM-12, VM-15, VM-16, VM-23, VM-24: ops.rs the typed edits (Command::VmConfig, VmDevice,
                      VmDisk, VmLifecycle), their checks and summaries; vmware.rs each edit as changes to a VmxFile, new
                      disk slots and vdiskmanager arguments, what deleteVM deletes; virtualbox.rs each edit as VBoxManage
                      calls; mod.rs VmEditor: plans from the VM's state (refused while running, suspended, with
                      snapshots under a disk change, a disk outside its folder), the approval preview (VmChangePreview:
                      before and after, every file deleted) and the job's work (.vmx backup beside it, atomic write,
                      restored on failure, deleted once it went well; vmware.addedVms for Add existing VM); service.rs
                      Core.vm_settings: ISOs, shared folders and existing VMs from the shell's dialogs and drops (never
                      from the UI: check_from_ui), guest OS types, VirtualBox screenshots, Open console (audited
                      vm_console_opened, no tier, refused by the read-only lock)
    host_networks/    VM-11 (Core.networks): mod.rs the report (vmnets with a NAT vmnet's forwards, VirtualBox's
                      host-only interfaces, NAT networks and rules, each VM's NAT adapter rules, the VMs on each from
                      QL-21's fresh adapter read, host_details::networks), networks_only (the networks alone: one vmrun
                      and two VBoxManage lists, no VM read; the map's network nodes), network targets (Prod when a VM
                      on it is, from the stored adapters), the approval's warnings, the submit-time refusal
                      (Workstation's forwards need administrator rights: nat_refusal), and apply for the job runner (a
                      forward on a host port in use is refused, never replaced); ops.rs Command::HostNetwork's
                      HostNetworkOp (AddForward, RemoveForward of a NatForward), ForwardPlace from the one target, the
                      checks
    vm_insight/       VM-25 (Core.insight, reads only): logs.rs a VM's vmware.log/vmware-N.log or VBox.log/VBox.log.N,
                      a tail of at most 2 MB (256 KB by default), following from an offset (512 KB a read, a skip to
                      the tail beyond that, a replaced log reset), whole lines only, names only from the listing, A3
                      folders refused unopened; mod.rs the Timeline: audit entries naming the VM, newest first, with
                      the VM's own job rows, paged by seq
    waste/            VM-16, VM-14 (Core.waste, reads only): rules.rs idle_verdict (busiest hour under 2% of this PC's
                      CPU, guest under 5% and 20 KB/s when watched, history covering a third of the window and starting
                      in its first quarter), chain depth, Workstation's snapshot and suspend files; folders.rs folder
                      sizes and orphans (folders with VM files no known VM uses, only under the scanned folders and the
                      hypervisors' and templates' VM folders, 4 levels and 20,000 folders a root, links, junctions and
                      .lck left alone, A3); mod.rs the report and folder_to_open (only folders the report or a known VM
                      names)
    terminal/         SS-12 console.rs: PaneKind (SSH, Telnet, serial, a tunnel tab); Telnet and serial panes connect
                      through their adapters into the same supervisor (logs and output scrubbed, reconnects, alerts; no
                      SFTP, tunnels, hook or startup command; never MultiExec or Compare); one pane per COM port,
                      reopened only once the last connection's thread let go of it (SerialShell::released); local
                      echo shows nothing at a secret prompt, nor a typed vault secret (ShellInput::Secret);
                      a vault password typed into Telnet asks for the vault password on each connection
                      (SecretBindings::confirm_given); Send break audited (terminal_break_sent), confirmed on Prod or
                      protected; open_window starts RDP or VNC (audited rdp_opened, vnc_opened, before it starts);
                      behind a jump host, a tunnel tab to it opens a loopback forward through the bus, then the window
                      on it, and closes when the window does; rdp_file;
                      SS-03 terminal panes (mod.rs): one supervised SSH connection each (keep-alive, auto-reconnect:
                      R9 TerminalTuning::retry_delay, 10 fast tries then 12 slow ones, each spread at random;
                      Terminals::wake_reconnects on a resume or a new address, from the shell's wake.rs,
                      QL-03 host name and IP, QL-06 a vault password typed at a prompt (a new place, or with force,
                      asks for the vault password; a jump host's login prompt is that hop's place; forget_logins on
                      lock); SS-01 the startup command typed
                      at the first shell prompt, or not at all within STARTUP_WAIT, and after an automatic reconnect
                      only with startup_on_reconnect); quick.rs QL-02 quick connect;
                      log.rs and output.rs SS-11 session logs (secrets scrubbed from the raw bytes and again from each
                      rendered line, so one split by colour codes or backspaces is caught; one that can't be written
                      stops: LogStopped, audited; stopping waits for the last lines) and saved, printed or copied
                      output (secrets scrubbed); QL-05 selections copied (copy-on-select, Ctrl+C, Ctrl+Shift+C,
                      Ctrl+Insert) are scrubbed by Terminals::scrub_for_copy (a closed terminal's are refused);
                      activity.rs the cursor's line, full-screen programs (alternate screen) and QL-07 long-run
                      detection (prompt back, or quiet); password prompts (QL-06) and, wider, secret prompts (SS-10:
                      passwords, passphrases, PINs, one-time codes and tokens, in English and translated); multiexec.rs SS-10 MultiExec: keys to every picked terminal,
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
                      from the folder shown; Back through the folders that opened), downloads (audited reads; A8 Cf
                      characters such as U+202E in a name become `_`, and each file gets a Mark of the Web, its
                      `Zone.Identifier` stream with ZoneId=3 and no host, or a note when its drive has no streams), the
                      upload job's work (Command::FileUpload on the bus), the transfers list with cancel and retry, and
                      FileTransfers (Core.files: staged files, uploads, retries);
                      tunnels.rs SS-07 a terminal's tunnels: start (Command::OpenTunnel on the bus, also for forwards
                      that start with the terminal), approve, stop, the job's open_tunnel, reopened after a reconnect,
                      closed with the terminal, audited tunnel_opened and tunnel_closed;
                      rules.rs QL-17 highlight and alert rules: built-ins (Error, Fatal, Panic, Python traceback,
                      Warning; alerts off by default), the user's own (at most 50, audited terminal_rule_changed
                      without the pattern, read-only lock Change::TerminalRules), check_pattern (a subset Rust regex
                      and JS with the u flag read alike; \d \w \s \b . compiled with their JS meaning; nested
                      repeats refused), RuleBook on a watch channel; alerts.rs per-pane AlertWatch: completed lines
                      (log.rs ScrubbedLines, secrets scrubbed) matched on 2,000 characters, never full-screen,
                      secret-prompt or typed lines; one TerminalEvent::Alert per 2 s burst, then a 60 s cooldown per
                      rule per pane
    snippets/         BX-08 command panel: favourite commands (mod.rs; audited, no approval tier), the built-in
                      library (library.rs: ~525 Linux commands in 30 area groups plus TROUBLESHOOT symptom runbooks
                      that reference them; two LibrarySections), {{variables}} (variables.rs); classified by the bus's
                      policy engine (read-only additions in policy/commands.rs, writing forms in commands/writes.rs);
                      QL-13 each entry's manual page (manual.rs: Manual, MANUAL_HOSTS, `checked` refuses any other
                      address; opening one is not audited and the read-only lock allows it)
    toolbox/          FD-09 (Core.toolbox; reads only: no bus, no audit, not stopped by the read-only lock): mod.rs
                      Toolbox (ProbeTarget: a typed host, a session, a VM's guest IP; Route with the session's own jump
                      host; each probe callable on its own with a cancel token and ProbeProgress as it goes, which F2's
                      health checks reuse), icmp.rs (ping, at most 1,000 requests a second apart; trace route, 30 hops,
                      3 requests each, names only when asked; both refuse a session behind a jump host and say why),
                      dns.rs (A to CAA, PTR's arpa name, which server answered), ports.rs (at most MAX_PORTS, 100, a
                      run; banners of 256 bytes without control or Cf characters), certs.rs (a rustls handshake with
                      SNI that keeps any chain, its signature still checked, then the trust check and the name; a
                      `.crt`, `.cer` or `.pem` file after untrusted::path_refusal, 1 MB), x509.rs (a bounds-checked DER
                      reader: names in RFC 4514's order, alternative names, key, signature, fingerprints, RFC 6125 name
                      match), jump.rs (SS-07: an open terminal's connection to the jump host, else a kept one through
                      login_guard's parks and caps, closed by a sweep after 2 minutes idle (never while a check holds
                      it), on a vault lock and a workspace switch; every ExecSession wrapper forwards open_direct, the
                      terminal's ScrubbedCommands included), wake.rs
                      (WakeSpec: MAC, an adapter's subnet broadcast or a typed address, port 9; the magic packet;
                      Command::WakeOnLan is Low, Medium on Prod, audited; one target: the session, the VM, or
                      TargetRef::App named "MAC ..." for a MAC typed alone), file_server/ (F9: Command::FileServer,
                      Medium serving, High with uploads (ActionKind::FileServer, FileServerUploads), target
                      TargetRef::App named "this PC (<address>)"; never built by the UI: Core.file_server's
                      FileServers::submit checks the root, the empty upload folder (save_guard) and that the address is
                      this PC's; no path comes from the window: the shell's dialogs hand the core each choice
                      (remember_pick) and the window sends back its token (PathChoice::Picked) or PathChoice::Last,
                      this workspace's last choice, checked again; Runner::protect: Remotely's data folder (the
                      database's, set at init; the shell adds the logs folder), anything in it or holding it, a drive's
                      root and the user profile's own folder are never served or written into; the job runs as long as
                      the server, its output the request log (MAX_JOB_OUTPUT, 8 MB), its end note the
                      uploads; Runner serves for the job runner, one at a time, and stops on Stop, the time limit (30
                      minutes by default, 8 hours at most), the job's cancel, a workspace switch (open_user_jobs leaves
                      it out, switch_workspace stops it), a vault lock, release_ui and Core::shutdown; the last choices
                      are `fileServer.last`, per workspace): paths.rs (a request as text: `.` `..` `\` `//`, drives,
                      `:` (streams), trailing dots and spaces, control and Cf characters, device names, one
                      percent-decoding and nothing still encoded; an upload name is one part, Cf to `_`, never a file
                      Explorer acts on by itself: is_shell_file, `.lnk`, `.url`, `.scf`, `.library-ms`, desktop.ini...),
                      served.rs
                      (each part looked up without following links or junctions; a file served only when its handle's
                      final path is under the root; folder listings), tftp.rs (RFC 1350, blksize and tsize; a socket
                      per transfer connected to the client; resent only on timeout; at most 65,535 blocks, so no
                      wraparound; transfers capped in all and per client), http.rs (httparse: GET, HEAD, PUT with a
                      Content-Length, Expect: 100-continue; the head within its timeout, 16 KB, 32 headers, a 4 KB
                      target; one request a connection; check_host: `Host` must be the bound IP literal and port, 421
                      otherwise (DNS rebinding), none only for HTTP/1.0; nosniff, attachments, an escaped listing with
                      a CSP), uploads.rs (create_new in the folder, never a replace; caps per file and in all, counted
                      as bytes arrive (a declared size is checked, never set aside); UploadLimits: 2 uploads per
                      client, at least 60 KB a minute; a part deleted; the Mark of the Web through
                      terminal::files::mark_downloaded), log.rs (transfers kept, repeats summed, never pushed out;
                      refusals folded per client, past 1,000 clients counted only; totals of all); MO-08: reach_held,
                      session_connection and release_holds: a check holds a kept connection until its next run (one
                      login, not one a run)
    checks/           MO-08 health checks (migration 0030; Core.checks; edits audited check_changed, no tier,
                      Change::HealthChecks; runs are reads, not audited): spec.rs CheckSpec (ping, tcp, http,
                      certificate, dns, service), CheckInput and its checks (30 s to 1 h, timeout, failures before down;
                      check_unit: a systemd unit by a strict pattern), probe.rs one run with F1's probes (up, down, or
                      unknown when Remotely couldn't check: vault locked, login parked or capped; hold_for; Backoffs:
                      a host or jump host that couldn't be reached waits 1 minute doubling to 15 before the next login
                      try, and the runs between are skipped: nothing kept, the status stays, waiting_until shown),
                      http.rs a GET with hyper over Reach's stream (direct or a jump host's channel, never a proxy;
                      headers 64 KB, body 256 KB read only to find text, 5 redirects to http(s) only; HTTPS checked by
                      Windows' trust and the name unless allowed), service.rs the ServiceReader trait (F4 adds Windows
                      services; check_service_name by the session's kind) and SystemdOverSsh (`systemctl is-active
                      'unit'` on the session's connection), mod.rs Checks: the runner (tick each second on a Clock for
                      the shown workspace only, 8 at once; leave() on a switch, which loads nothing of the workspace
                      left until another is shown, resume() when the switch fails), history and sparkline buckets,
                      CheckReadings for MO-07 (unknown after down stays down), overview, attention (the widget's read,
                      no history), summary and CheckEvent for the UI; results kept with metrics.historyRetention and
                      pruned with MO-06; store/checks.rs check_uptime: uptime over any range for one workspace (F6)
    reachability.rs   QL-04 background TCP checks of the sessions the tree shows (reads only; each shows in the host's
                      sshd log): every 5 minutes by default, a host that is down less often (next_check_after: doubling
                      up to 30 minutes), none for a host with an open connection (OpenConnections: connected terminals,
                      and TrackedRemote, the remote adapter every service uses, noting kept connections: dashboard,
                      Containers page, host details); SS-07 the first jump host's for a session behind one, never the
                      session itself
    bulk.rs           BX-01 targets (picked tabs, tree sessions, VMs, tags, filters; A4, H11 a VM only through a
                      chosen or confirmed link, else ResolvedTargets::vms_unconfirmed), BX-03 grouped results and diff,
                      BX-05 exports: the Terminal page's Compare output (running is RemoteExec on the bus); QL-12
                      recorded MultiExec lines group (group_with_output), diff and export (export_recorded, audited
                      multiexec_exported) through the same code
    support_bundle/   FD-04 support bundles (no migration): spec.rs BundleSpec (Command::SupportBundle; presets expanded
                      into its items before the bus rates them; refused from the UI: the zip's place comes from the
                      shell's save dialog; never retried), its checks, entry names safe for Windows and the file name
                      `remotely-bundle-<workspace>-<UTC time>.zip`; presets.rs PRESETS (System, Logs, Containers,
                      Network) by HostKind, every command read-only by the default rules (policy/bundle_tests.rs);
                      collect.rs the BundleHost trait (SshHost: commands on a kept connection's exec channels, sudo
                      through BX-07; files over SFTP on the same connection as the login user, ExecSession::files; F8
                      adds Windows) and collect_host (caps 10 MB a file, 100 MB a host, 1 GB a bundle; ItemLimits: a
                      command 60 s, a file read 180 s, then the item is noted as timed out and the host goes on;
                      exec_output's scrubber, redact_secrets and private keys: PEM and PGP blocks, a key whose BEGIN was
                      cut away, PuTTY's private lines, kubeconfig's client-key-data; a file with a NUL byte left out);
                      writer.rs OpenBundle (the zip through save_guard::AtomicFile, written as hosts give files, on
                      blocking threads; Reservation gives an item's bytes of the cap back however it ends; add_file
                      puts a file and its manifest record in together; manifest.json); runner.rs BundleRunner, the job
                      runner's BundleActions (begin, collect, each host's end, save and audit `data_exported`; a
                      cancelled job saves nothing); mod.rs SupportBundles (Core.bundles: presets, preview, check,
                      submit, saved_at for Show folder; SS-12 SSH sessions only, another kind refused by name,
                      HOSTS_NEED); spec.rs zip_path (a name given `.zip` never replaces a file
                      unasked). The policy engine rates a bundle's commands as a Compare hosts run
                      (Command::rated_script). FD-03: presentation.ts masks the workspace in a bundle's file name
    reports/          0.7.0 F6 exports (Core.reports; reads only: no tier, no bus, allowed by the read-only lock like
                      FD-07's and the audit log's exports; each audited `data_exported`; one workspace each, the ctx
                      the shell passes; the path from the shell's save dialog, save_guard::refuse_repository, written
                      through a `.part`): table.rs one Sheet and Cell model for Excel, CSV (export::push_row, A10) and
                      HTML, every text through `clean` (redact_secrets, no control or Cf characters, capped by
                      character); inventory.rs FD-05 the sheets (VMs with MO-13's stored hardware, hosts: every session,
                      an SSH host's facts, ports, updates; VM-11's networks; MO-08's checks with 24 h and 7 day uptime;
                      packages), "Read again first" through HostDetails::inventory_read, READS_AT_ONCE (4),
                      HOST_READ_LIMIT; xlsx.rs rust_xlsxwriter, text always `write_string`, never a formula; ansible.rs
                      BX-12 YAML and INI from BX-01's targets (none picked: every SSH session), groups by folder
                      (nested), tag, environment, workspace, and `protected`; names made valid, YAML keys and strings
                      double-quoted, Jinja markers `!unsafe` (INI leaves such a value out), hosts and users ssh could
                      read as options refused, ProxyJump in ansible_ssh_common_args; F4's WinRM hook is
                      `connection_vars`; activity.rs FD-08 the Activity page's grouping (jobs with their approvals and
                      entries; other changes, this PC's own events left out); topology.rs QL-21's graph and layered
                      layout ported, drawn as plain SVG (rect, path, text); html.rs escape, the page with its CSP (only
                      the style's hash and data: images); pack.rs index.html (cover, inventory, the diagram as an
                      `<img>` of a data: SVG, what was done with outputs only when chosen and capped, uptime from
                      Store::check_uptime, Notes::for_handover) and the zip (index.html, inventory.xlsx, a CSV per
                      table) through AtomicFile; mod.rs Reports, ReportClock (times in the window's offset), file names
    multiexec_groups.rs QL-19 saved MultiExec groups (Core.groups): named sets of saved sessions in order (1 to 60
                      characters, 1 to 100 sessions, 200 groups); audited multiexec_group_changed with the member
                      sessions as targets, refused by the read-only lock (Change::MultiExecGroups); a deleted session
                      leaves its groups; open_terminals lists a group's open terminals. Groups only choose MultiExec's
                      targets
    known_hosts.rs    SS-05 trusted host keys (first-use prompt, changed key blocks; audited; a new key type for a host
                      with a trusted key blocks in bulk runs and is an FD-07 conflict; key_types for the handshake's
                      preferred host key algorithms)
    linked_clones.rs  VM-04, VM-21, VM-24 linked clones: Workstation's from the golden VM's .vmsd (SnapshotInfo's
                      linked_clones; a clone whose .vmx is gone left out, one on a share counted unopened), VirtualBox's
                      from `list --long hdds` (vbox_clones: other VMs on disks made from a snapshot's). A snapshot or VM
                      delete (a VM-08 stack teardown too) they depend on is refused (CoreError::LinkedClones, the
                      clones named): by the bus before
                      it asks when every VM would be, else an approval warning and the AP-02 preview
                      (TargetImpact.linked_clones, VM-24's problem), and by the job runner just before it deletes; a
                      read failure refuses too. The snapshot list shows them (SnapshotNode.linked_clones); VM-27
                      retention keeps such a snapshot (its record too, so it goes once the clones are gone)
    ssh_keys.rs       SS-09 SSH keys: generated into the vault, public halves, attach to sessions, the
                      authorized_keys push script with KeyOptions (expiry-time, from) and remove_key_script (the push
                      and the removal are Command::PushSshKey and Command::RemoveSshKey on the bus, both Medium)
    transfer/         FD-07 encrypted export/import between laptops: file.rs (Argon2id + AES-256-GCM envelope,
                      format version 2 for an export that uses QL-16 folder defaults, else 1, which 0.4.x reads; new
                      exports use file::KDF, 256 MiB and 3 passes, and a file opens with the parameters in its header,
                      so older 64 MiB files still import), preview with conflicts (skip, replace, keep both), commit;
                      audited; an export refuses the vault password as its passphrase; catalog.rs VM-19 to VM-21 own
                      sizes, images by path (a note when the file isn't here; a refused path can only be skipped) and
                      templates mapped to this laptop's images, sizes and keys; QL-16 sessions travel with what they
                      set themselves and folders with their defaults (a folder here with other defaults: keep or
                      replace); groups.rs QL-19 MultiExec groups by name with their sessions' ids (members become the
                      sessions imported or matched here, the rest left out with a note); stacks.rs VM-08 stacks with
                      the catalogue, each step's template mapped to what it became here (instances stay out);
                      checks.rs MO-08 check definitions by name (a session target mapped to the session it became, a VM
                      only when it is here; results never travel), saved through Checks; FD-06 notes ride with their
                      session and folder (`note`) and VMs' in `vmNotes` (optional fields, so older files read as before
                      and 0.6.x ignores them); the trash never travels
    import/           SS-02 parsers (PuTTY, MobaXterm, OpenSSH config, CSV), preview and commit; guide.rs QL-10 a
                      format guide and a sample file per format (the CSV guide is made from csv.rs's COLUMNS,
                      ENVIRONMENTS and AUTH_METHODS tables; tests/import.rs imports every sample); A3 a key path or
                      Include on a share or a device path is never opened (a note or warning; the key or include left
                      out); A9 the source up to 10 MB, included files 1 MB each and 4 MB and 256 files in all
                      (openssh.rs IncludeFiles: DiskIncludes, or memory in tests)
    vault/            SS-04 vault: crypto (AES-256-GCM, Argon2id), DPAPI (opt-in for new vaults; turn_off_windows_login
                      needs no password), LocalVault (idle lock from note_activity only, never from get; a password
                      change makes a new data key and reseals every item in one transaction; secure_delete and a WAL
                      checkpoint after vault changes), VaultService; bindings.rs SS-04, AP-06 SecretBindings: where a
                      vault password may go without asking (a saved session at that host, port and jump host logs in
                      with it, gives it to sudo, or a session_secret_grants row from an earlier answer, migration
                      0016; one added since the unlock goes to its first place free; keys and key passphrases never
                      ask; a right answer covers REAUTH_GRACE, 5 min, ended by a lock; QL-16 SecretPlaces: every
                      session's place and what it sends, its folders' login included, read once per change);
                      Core::spawn_lock_watch closes kept connections, forgets typed logins and an open FD-07 file;
                      strength.rs (a new vault password or FD-07 export passphrase: 10 to 1024 characters and a
                      zxcvbn-style score of at least 3 of 4: common passwords and words, repeats, sequences,
                      keyboard rows, years and dates; hints never quote it), passphrase.rs (Generate: six words from
                      a built-in list of 1327, the OS CSPRNG)
    store/            jobs.rs: the journal stores Command::for_journal (scripts and lines redacted), command_type
                      (migration 0017) for the lists, which pick a page of ids on an index first (AP-03, BX-03);
                      purge_job_bodies and redact_old_commands; audit.rs redacts every entry's text before hashing it,
                      and verifies and exports with row streams; multiexec_groups.rs (QL-19, migration 0021);
                      terminal_rules.rs (QL-17 rules and built-in overrides, migration 0021); timeline.rs (VM-25 the
                      audit entries whose targets hold `"vmxPath":<key>`, any letter case, and the VM's job rows;
                      migration 0024 lets job_targets take 'network' and indexes it by key); schedules.rs (VM-14,
                      VM-27 schedules, their runs (200 kept), the snapshots they took, standing approvals);
                      workspaces.rs (FD-02 rows, the home workspace, vm_assignments: require_vm_here, assign_vm,
                      release_vm); audit.rs one hash chain per workspace from chain_start, entries up to
                      `audit_legacy_until` checked against the old single chain; workspace_upgrade_tests.rs a database
                      at migration 0028 with a row in every table, opened by 0029; reports.rs (FD-08 audit_between,
                      user_display_name, workspace_name) and jobs.rs jobs_between (with each job's approval JSON)
    fakes.rs          one fake per adapter (feature `fakes`; tests only); FakeVirtualBox for VM-18; vmrun_runs and
                      vboxmanage_runs count the processes the real adapters would start (VM-01 refresh cost)
    fakes/ssh_server.rs  russh server on 127.0.0.1 with run-time keys, for SSH tests; ssh_server/sftp.rs its SFTP
                      subsystem on a temp folder (SS-08; QL-09 with_unreadable folders it can't open); SS-07
                      direct-tcpip (with_route names reach another port on 127.0.0.1, so a server is reachable only
                      through another) and tcpip-forward; QL-09 `su [-] [user]` in its shell, a shell without the hook;
                      ssh_server/docker.rs CT-01 its `docker` and `podman` programs (each CLI's JSON from a fixture);
                      ssh_server/host.rs MO-13, MO-14 a HostFixture (ubuntu, rhel; FD-05 `dpkg-query` or `rpm -qa`
                      from `installed`) its exec shell describes itself with
    fakes/containers.rs  CT-01, CT-02 the container Fixture (sample, hostile names) and FakeContainers (engines in memory)
    fakes/consoles.rs  SS-12 FakeLauncher (records each .rdp file and viewer command; windows close on cue) and
                      FakeSerialPorts (COM ports in memory, one open at a time, unplug, breaks)
    fakes/telnet_server.rs  SS-12 TelnetTestServer: a router console on 127.0.0.1 with a login (sizes, terminal type
                      and raw bytes kept; a dropped connection resets), also in dev_ssh_server
    fakes/github_server.rs  FD-14 fake GitHub API, github.com download links and release storage on 127.0.0.1
                      (private or public, rate limits), throwaway update-signing key
    fakes/net_tools.rs  FD-09 FakeNetworkTools: echoes along routes the test sets, DNS answers from a table, ports that
                      refuse, stay silent, send a banner or pass on to a server on 127.0.0.1, a set trust verdict, and
                      datagrams recorded, never sent
    fakes/stack_clock.rs  VM-08 FakeStackClock: a stack job's readiness waits and delays move fake time at once,
                      run `at` hooks (a port opening, a tool failing) and record each sleep
    fakes/host_networks.rs  VM-11 the fakes' vmnets and forwards (as_admin, with_forwards_in_conf_only) and VirtualBox's
                      host-only interfaces, NAT networks, VM NAT rules and showvminfo paths, with the tools' refusals
    fakes/disk_tools.rs  CV-01 to CV-03 FakeDiskTools: no program runs; each tool's arguments read and small files
                      with the right header written (VirtualBox's media list kept as VirtualBox keeps it), failing
                      tools, delays, qemu-img only with_qemu_img; fakes/disk_images.rs small test images of every
                      format (VMDK sparse and stream, VDI, VHD, VHDX, qcow2, raw, OVA tars, OVF text), TempFolder
  examples/           dev_ssh_server.rs: that server on a fixed port, to try the terminal, MultiExec, Compare, jump host
                      chains, tunnels, the Containers page and host details by hand
  tests/              end-to-end tests with fakes (virtualbox.rs: VM-18, mixed with Workstation; folder_defaults.rs:
                      QL-16; multiexec_groups.rs: QL-19; alerts.rs and dashboard.rs: MO-06, MO-07, MO-16;
                      host_networks.rs: VM-11; vm_insight.rs: VM-25; waste.rs: VM-16, VM-14; schedules.rs: VM-14,
                      VM-27 on a FakeClock, no sleeping; stacks.rs: VM-08 and VM-26 on the fakes and FakeStackClock;
                      conversion.rs: CV-01 to CV-03, VM-17; workspaces.rs: FD-02 isolation of every service and
                      switching; change_ids.rs: AP-08; support_bundle.rs: FD-04 on the test SSH server, zips in the
                      temp folder; reports.rs: FD-05, BX-12, FD-08 on the test SSH server's Ubuntu and RHEL hosts and
                      the fakes, files in the temp folder read back (the xlsx's XML, both Ansible formats, the zip's
                      members, the page's CSP and attributes, a secret in a note, an output, a name and a tag found in
                      none); toolbox.rs: FD-09 on FakeNetworkTools, a TLS server with an
                      rcgen certificate made at run time, jump hosts through the test SSH server, Wake-on-LAN to
                      127.0.0.1; consoles.rs: SS-12 RDP, VNC, Telnet, serial and tunnel tabs; checks.rs: MO-08 on a
                      FakeClock with FakeNetworkTools, HTTP and TLS servers on 127.0.0.1 (rcgen), the test SSH server's
                      `systemctl is-active` and a jump host held to one login; file_server.rs: FD-09 TFTP and HTTP on
                      127.0.0.1 with port 0 and the test's own clients, folders made in the temp folder: every
                      traversal form on both protocols, links, junctions and streams, uploads and their caps, slow and
                      flooding clients, every stop path giving the ports back); opt-in workstation_it.rs,
                      virtualbox_it.rs and
                      conversion_it.rs (the real conversion tools on small images in the temp folder)
src-tauri/            Tauri 2 shell: window, IPC commands (ipc.rs), terminal bridge, MultiExec (multiexec.rs; groups.rs
                      QL-19 saved MultiExec groups; terminal_rules.rs QL-17 rules), command
                      panel, notifications and QL-13 manual links opened with ShellExecute after the core's check
                      (command_panel.rs; QL-17 notify_terminal_alert), clipboard.rs (the clipboard read for right-click paste, and QL-05/SS-11
                      copies: selections through terminal_copy_selection, Copy output through terminal_output_copy,
                      scrubbed by the core and written with Windows' clipboard-history, cloud and monitor exclusion
                      formats), SS-08 file
                      transfer (files.rs: upload and folder dialogs, drops caught in Rust, Explorer for "Open folder"),
                      SS-07 port forwards and tunnels (tunnels.rs), VM-19 to VM-21 the Templates page (catalog.rs:
                      image and folder dialogs, `catalog://hash` progress, cloud image pages after checked_site),
                      CT-01 the Containers page's reads, marks and
                      container shells (containers.rs), MO-13 to MO-15 host details and this PC's memory
                      (host_details.rs), MO-06, MO-07, MO-16 the dashboard's history, alerts, layout and
                      services widget, and the alerts' Windows notification (dashboard.rs); R10 navigation.rs (QL-25
                      notifications_*, QL-21 topology_vm_networks, QL-23 vm_folder_pick); QL-15 diagnostics.rs (the daily log file, crash files from the panic hook,
                      startup message boxes, setting an unopenable database aside, Settings About's logs folder, UI
                      crash reports) and data_dirs.rs (the data folder, known before Tauri starts); lib.rs runs one
                      instance (release builds), closes what a reloaded page had open (on_page_load), and turns
                      WebView2's browser keys off in release builds; updater.rs timeouts and core.shutdown() before
                      the installer exits the app; SS-03 (R9) wake.rs: Windows resume
                      (PowerRegisterSuspendResumeNotification) and new-address (NotifyUnicastIpAddressChange)
                      notifications wake terminals waiting to reconnect; P10 heavy commands (terminal output scrub,
                      the command library) run on spawn_blocking, never on the window's thread; VM-23, VM-24
                      vm_settings.rs (ISO, shared folder and existing VM dialogs opened here, ISO drops taken from the
                      staged drop, Open console, screenshots, guest OS types); VM-21, VM-10 deploy.rs (the Deploy and
                      Clone dialogs' checks and submits, host adapters, the default VM folder); R4 vm_insight.rs (VM-25
                      logs and the timeline, VM-11 host networks, VM-16 the waste report and Explorer at a folder the
                      core names); VM-14, VM-27 schedules.rs (the scheduler's loop, `schedules://event`, the
                      Schedules page's and VM tab's commands); VM-08 stacks.rs (stacks, their deploy, instances' power
                      and teardown, VMs added or taken out by hand); CV-01 to CV-03, VM-17 convert.rs (Image tools'
                      file dialog, Inspect, Convert's options and its save dialog, Verify with `convert://verify`
                      progress, Export's options and folder dialog, Import's analysis, check and submit, QEMU's page
                      after checked_qemu_site; Settings' qemu-img path in ipc.rs); FD-02, AP-08 workspaces.rs (the
                      switcher's commands, Unassigned VMs, the change ID rule, FD-07 import into a new workspace); FD-04
                      support_bundle.rs (presets, the tier preview, the zip's save dialog in Downloads, Show folder by
                      job id); FD-05, BX-12, FD-08 reports.rs (each export's save dialog in Documents, chosen_path,
                      Show in folder by the id the export returned, SavedReports); FD-09 toolbox.rs (each tool's run
                      under an id the UI chose, `toolbox://progress` events,
                      toolbox_cancel, the certificate file dialog, Wake up's adapters and MACs), file_server.rs (the File
                      server tab's options, file and folder dialogs, start, Stop and status, `fileserver://event`);
                      MO-08 checks.rs (the runner, `checks://event`, the Checks tab's commands); 0.7.0 F5 comfort.rs
                      (FD-06 notes, render, a note's web link through ShellExecute after the window's confirm, http(s)
                      only; QL-26 stars and recents; QL-27 the trash, its Undo, and its daily purge started in lib.rs;
                      QL-28 bulk edit preview and save); lib.rs and schedules.rs pass job and schedule events to the
                      window only for the shown workspace
src/                  React + TypeScript UI
  components/ui/      shadcn/ui components (generated)
  components/         app components (approval dialog, badges, Compare panel with its one-shot and MultiExec views
                      (RecordedLinesView, QL-12; BulkResultsView's GroupCard and OutputDiffDialog serve both), MultiExec
                      bar, WhyDisabled for QL-08, PasteConfirmDialog for QL-05,
                      FilesDrawer and TransfersList for SS-08, ForwardsEditor and TunnelsPanel for SS-07, Presentation
                      for FD-03: the Present button and menu, the confirm, the frame, page notices, the Settings card;
                      VmDetailsPanel and SnapshotTree for QL-14: a VM's Details and Snapshots tabs beside the list;
                      VmSettingsTab and VmSettingsDialogs for VM-23: the Settings tab and its edit dialogs (bulk
                      resize too, VM-12); VmLogTab (follows through usePoll) and VmTimelineTab for VM-25;
                      HostNetworksSheet (VM-11, its add-forward dialog) and WasteFinderSheet (VM-16, VM-14), opened from
                      the VMs page's Networks and Waste finder buttons or the palette;
                      ContainerHostDialog, ContainerDetailsPanel (Overview, Logs, Stats) and ContainerResources (images,
                      volumes, networks) for CT-01; HostDetailsSheet (MO-13 System, MO-14 Admin) for a session,
                      VmSystemTab (MO-13: a VM's System tab), ThisPcMemoryChart (MO-15) and MetricChart's own legend
                      and dashed limit lines; MO-06, MO-07, MO-16 RangePicker, AlertsWidget, AlertRulesSheet,
                      AlertNotifier (one Windows notification per round of alerts, masked), DashboardGrid (pointer
                      drag, keyboard moves, resize; no drag-and-drop library), WidgetSettings, ServicesWidget,
                      MetricChartWidget, DashboardHistoryCard; QL-15 ErrorBoundary: one per page and one for the app, with Reload;
                      SS-04: NewPasswordField (strength meter from password_strength, Generate, hidden while
                      presenting), ReauthDialog (the vault password asked again); VM-19 to
                      VM-21: SizeDialog, ImageDialog (hash progress, Stop), TemplateDialog (the core's live check);
                      VM-21, VM-22, VM-10: TemplateFields (the template editor's fields, also the Deploy dialog's
                      Custom), DeployDialog (a template or Custom, count, names, the preview, then the job's step per
                      VM: DeployProgressView, useDeployProgress), DeployPreviewView (also in the approval dialog),
                      CloneDialog; VM-08, VM-26: StacksTab (the Templates page's Stacks tab: stacks and instances),
                      StackDialog, StackDeployDialog, StackDetailsView (also in the approval dialog), StackGroupRow
                      (an instance's header row on the VMs page), CapacityPlanView (the Deploy, Clone, Import and stack
                      deploy dialogs and the approval; Suspend what it suggests); CV-01 VmImportDialog (a file analysed,
                      then a deploy with DeployPreviewView, CapacityPlanView and DeployProgressView), VM-17
                      VmExportDialog (each target with its plan or why not) (ImportDialog and ExportDialog are SS-02's
                      and FD-07's);
                      QL-16 FolderDefaultsDialog (a folder's Defaults…) and SessionDialog's "from folder X" values;
                      SS-12 SessionDialog's kind first and SessionKindFields (each kind's fields, the COM port);
                      MultiExecGroupsMenu and MultiExecGroupsDialog for QL-19; ScrollbackSearchPanel for QL-18
                      (Ctrl+Shift+G); TerminalRulesCard for QL-17; R10: StatusBar (QL-22), NotificationCentre and
                      NotificationSources (QL-25: jobs and MO-07 alerts kept whatever page shows), ShortcutSheet
                      (QL-24, Ctrl+/), FirstRunWizard (QL-23: the Vault page's SetupCard, the import dialog); VM-14,
                      VM-27 ScheduleDialog (the core's preview of next runs and warnings), ScheduleRunsSheet,
                      VmSchedulesTab (a VM's Schedules tab and chain), ApprovalDialog's StandingSummary; FD-04
                      SupportBundleDialog (hosts, presets, commands and files, options; then BulkResultsView's bundle
                      mode with Show folder; the Sessions page's "⋯" and Ctrl+K open it) and ApprovalDialog's
                      BundleSummary; 0.7.0 F6 InventoryExportDialog (FD-05; the Sessions and VMs pages' "⋯", Ctrl+K),
                      AnsibleExportDialog (BX-12; BulkTargetPicker, YAML or INI, groups, the file's preview; the
                      Sessions page's "⋯" and selection bar, Ctrl+K), HandoverPackDialog (FD-08; the Activity page's
                      "⋯" on its date filter's days, Ctrl+K on the last 30); FD-02
                      WorkspaceSwitcher (the top bar's menu, the switch, edit and manage dialogs; the window loads again
                      after a switch), UnassignedVmsSheet; AP-08 ChangeIdSetting (ChangeIdCard.tsx, a row of the
                      approval rules' card) and the approval dialog's one reason or change ID field; UX-10 Settings:
                      SaveStatus (useSaveStatus, SaveStatus: "Saved" with Undo in a card's header; NumberSetting saves
                      on Enter or blur), ToolPathsCard (every tool path in one table, Change opens a dialog; qemu-img
                      too), ApprovalRulesCard (the summary, the change ID rule, PolicyRulesEditor under Advanced with
                      its sticky Save bar); the Vault page's Unlocking card holds the Windows-login switch and warning;
                      UX-01 to UX-13 (0.6.0), the shared pieces every page uses ("UI rules" under Conventions):
                      PageHeader, HelpTip, Term, SelectionBar, RowMenu, EmptyState, Tip and ShowTipsAgainButton,
                      RefreshButton; FD-09 toolbox/: the Toolbox's tabs (ProbeTools: Ping, Trace route, DNS lookup,
                      Check ports; CertificateTool, SubnetTool, WakeTool, FileServerTool: the form, the running server
                      and its requests), TargetField and ToolboxMenu, the "Toolbox"
                      submenu of session rows and the palette's VM and session views, and ToolboxIconMenu in the VM
                      details panel's header; no recent inputs are offered while presenting, since a native dropdown
                      is out of the masker's reach); MO-08 checks/: ChecksTab (the Dashboard's Checks tab), CheckDialog,
                      CheckHistorySheet, ChecksWidget (MO-16) and CheckBits (status badge, sparkline); the row menus'
                      "Add a check" opens a `checks` link; 0.7.0 F5: NoteSheet (FD-06, hosted once by App and opened by
                      a `note` AppLink; the core's HTML, the web link confirm, Send to terminal), StarButton (QL-26),
                      TrashCard (QL-27, Settings › Privacy and data), BulkEditDialog (QL-28, the Sessions page's selection
                      bar, which also has FD-04's Support bundle for the SSH sessions picked)
  pages/              one file per page (bulk execution is in TerminalPage: Type in all tabs (MultiExec) and Compare
                      hosts; QL-14 VmsPage
                      is VMs and snapshots, with the selection's bulk snapshot actions and the details panel;
                      UX-08 the sidebar's order and shortcuts are lib/navigation.ts's: Machines (VMs Ctrl+1, Templates
                      Ctrl+2, Schedules Ctrl+3), Remote (Sessions Ctrl+4, Terminal Ctrl+5, Containers Ctrl+6, and
                      FD-09's ToolboxPage, which has no digit and opens from Ctrl+K, rows and `toolbox` links),
                      Overview (Dashboard Ctrl+7, Activity Ctrl+8), then Vault Ctrl+9 and Settings Ctrl+,;
                      TemplatesPage: VM-19 to VM-21 sizes, images and launch
                      templates, Deploy on a template's row; the VMs page's Deploy, and Clone for the selection,
                      VM-21 and VM-10, Import... and the selection's Export..., CV-01 and VM-17; ImageToolsPage
                      (UX-08: the Templates page's Disk images tab, Ctrl+; still opens it): CV-03 Inspect, Convert,
                      Verify, the tools found and QEMU's link; MapPage (UX-08: the Dashboard's Map tab, Ctrl+0 still
                      opens it): QL-21 HTML nodes over an SVG of lines only, so FD-03's DOM masking covers it;
                      KnownHostsPage (UX-08: the Vault page's Known hosts tab); App keeps the Dashboard's and Vault's
                      tab so links open either; SchedulesPage (VM-14, VM-27; Ctrl+. still opens it), also from the
                      palette and a VM's Schedules tab open it). R10: App's `openLink` opens every AppLink (lib/links.ts), and pages
                      take a request to show one item (Sessions `focus`, Activity `focusJob`, Settings `focus` by
                      settings-index.ts, Containers `request`, Terminal `focusRequest` and `snippetRequest`,
                      Templates `request.id`). P6: App memoises every page and passes
                      stable callbacks, and renders
                      only when a job is queued or ends; pages that are hidden read nothing (VmsPage refreshes when it
                      shows again if a VM job or setting moved its key; the dashboard follows rounds only while shown)
  hooks/              use-poll.ts (CT-01 usePoll: a background read while the page shows and the window is visible,
                      each timed from when the last one finished; useVisibility); use-transfers.ts (SS-08, P6 the
                      transfers store through useSyncExternalStore); use-debounced.ts (Compare reloads once per burst
                      of job events; Activity coalesces its own asks, at most one read a second);
                      use-chart-points.ts (MO-06 a series' live rounds, or a history range carried on with them);
                      use-password-strength.ts; use-mobile.ts is shadcn's
  lib/                api.ts (typed IPC wrappers; FD-03: every answer's host, IP and user fields are learnt by the
                      masker), reauth.ts and reauth-prompt.ts (SS-04, AP-06: on `reauth_required` ask for the vault
                      password in ReauthDialog and send the request again; the vault idle lock's activity ping),
                      clipboard-copy.ts (QL-05 terminal copies one at a time, the last selection last), theme.ts,
                      utils.ts, terminal-session.ts (SS-03 a pane: its xterm.js, its connection, every paste
                      through paste.ts, every selection copy scrubbed by the core, OSC 8 links never opened), paste.ts (QL-05 paste cleaning, the
                      multi-line confirm's preview; TerminalSettings.confirm_multiline_paste, on by default),
                      terminal-input.ts (SS-10 input told from xterm.js's replies to the host, which skip MultiExec:
                      xterm's internal onUserInput, checked by a test), session-kinds.ts (SS-12 each kind's defaults,
                      ports, checks, one-line summaries and why a tab can't join), console-open.ts (SS-12 an RDP or VNC
                      window from the Terminal or Sessions page; the presenting notice), multiexec.ts,
                      multiexec-groups.ts (QL-19 which
                      tabs a group picks or opens, saving picked tabs, editor checks), scrollback-search.ts (QL-18
                      logical lines, matching, caps, grouping by tab), scrollback-xterm.ts (QL-18 reading a pane's
                      buffer, showing a match with a decoration), highlight-rules.ts (QL-17 scope, compile, match a
                      logical line to cells, colours per theme, time budget), terminal-highlights.ts (QL-17 xterm
                      decorations for lines the cursor passed, from a marker; CSI J/K recheck; hidden on the alternate
                      screen; one per terminal including the FD-03 masked twin), terminal-alerts.ts (QL-17 recent
                      alerts with subscribe, for QL-25; notification text), recordings.ts (QL-12 view texts,
                      QL-07 notify choice and the one notification per MultiExec line), transfers.ts,
                      transfers-store.ts (SS-08, P6 every transfer outside React state), job-events.ts (P6, VM-01
                      which job events and setting changes render or refresh what), chart-gaps.ts (MO-02 a guest
                      polled less often keeps its line on a VM's charts), terminal-render.ts (SS-03 WebGL for panes on
                      screen, at most 12, released 2 s after a pane hides, DOM after failures; FD-03 the masked copy's
                      1,000 lines written in pieces), tunnels.ts (SS-07 chains and forwards),
                      navigation.ts (UX-08 the page registry: ids, sidebar names (the headers' titles), groups and
                      shortcuts in sidebar order; MOVED_PAGES: the old Snapshots, Image tools, Map and Known hosts ids
                      open their home page's view or tab, and OLD_SHORTCUTS the 0.5.0 shortcuts no page took),
                      help.ts (UX-04 the help registry: every explanation longer than a line, by key, for HelpTip and
                      the headers' "?"), glossary.ts (UX-05 one sentence per term, for Term and the palette's Terms),
                      tips.ts (UX-09 dismissed tips in local storage), requirement-ids.test.ts (UX-06 no requirement
                      ID in any UI string), links.ts's requestLink (a link opened without an onOpenLink prop),
                      activity.ts (UX-02, UX-06 Activity: jobs with their audit entries and approvals folded, plain
                      event names, filters), palette.ts (UX-07 Ctrl+K's order; bulk actions only when searched for),
                      update-notice.ts (FD-14 the one update notice), catalog.ts (VM-19
                      to VM-21 texts, the size form), deploy.ts (VM-21, VM-10 the dialogs' reasons, counts and
                      packages, a job's steps from its events and targets), vm-insight-api.ts and vm-insight.ts (R4
                      wrappers; a followed log, search, timeline groups, the forward form and its command, the waste
                      rows' QL-08 reasons), stacks.ts and stacks-api.ts (VM-08, VM-26 texts, QL-08 reasons, the VMs
                      page's grouping by instance; types and IPC wrappers), convert.ts and convert-api.ts (CV-01 to
                      CV-03, VM-17 texts, QL-08 reasons, the Verify verdict; the conversion IPC's types and wrappers),
                      vm-snapshots.ts (QL-14 snapshot reasons, picks, tier hints), vm-settings.ts
                      (VM-23 the Settings tab's QL-08 reasons, bulk resize targets, sizes, MACs, networks), containers.ts
                      (CT-01 target keys, actions and their QL-08 reasons, filters, ports, log follow, how often stats
                      and a followed log are read), polling.ts (CT-01 when a background read may run, the next one's
                      delay, longer after failures), host-details.ts
                      (MO-13, MO-14 summaries, wording and the commands offered to copy), dashboard-api.ts (MO-06,
                      MO-07, MO-16 wrappers and types), history.ts (MO-06 ranges, buckets, stored minutes carried on
                      with live rounds, gaps), alerts.ts (MO-07 wording, the editor's checks, one notification per
                      round), dashboard-layout.ts (MO-16 add, remove, move, resize, drag snapping),
                      ui-errors.ts (QL-15 a crashed page's text, the browser keys a release build ignores),
                      debounce.ts (when a reload after job events runs), schedules-api.ts and schedules.ts (VM-14,
                      VM-27 wrappers and types; the editor's form, checks and wording), retention.ts (BX-02 the retention choices
                      and a purge's summary for Settings' DataRetentionCard),
                      presentation.ts (FD-03 masking: stand-ins, patterns, known values, TerminalMasker; MO-13 MAC
                      addresses as `mac-N`; FD-02 workspace names, `data-mask="workspace"`, learnWorkspace),
                      workspaces.ts and workspaces-api.ts (FD-02 checks and texts; wrappers that teach the masker every
                      workspace name), rollout.ts (H9 canary, stop after failures, retry choices),
                      support-bundle.ts (FD-04 the dialog's typed lines, item count, QL-08 reasons and caps),
                      reports.ts and reports-api.ts (0.7.0 F6: local days as the core's range, the Activity filter as
                      days, the dialogs' QL-08 reasons and toasts; the exports' types and wrappers),
                      key-options.ts (SS-09 expiry-time and from for a pushed key),
                      presentation-dom.ts (masks every text node and text attribute before paint, `data-mask` fields,
                      `data-presentation-skip` for terminals; a value learnt later re-masks only the text that
                      mentions it, presentation-rescan.ts), presentation-state.ts; R10: links.ts (AppLink, isAppLink:
                      every search result, map node, status bar item and notification), search.ts (QL-20 ranking:
                      every word matches a field, name > address > tag > detail), search-sources.ts (each kind's
                      items), search-providers.ts (SEARCH_PROVIDERS: later packages add theirs), settings-index.ts
                      (UX-10 Settings' groups for the side list and its sections by label, for the page's search and
                      the palette's), settings-summary.ts (UX-10 the tools table's rows and the approval rules'
                      summary), approval.ts (UX-11 the approval dialog's tier line, type-to-confirm phrase, and the
                      reason and change ID read from one field), container-cache.ts (what the Containers page read last; search
                      makes no logins), host-networks-cache.ts (VM-11 the host networks the map or the networks view
                      read last, for search), topology.ts and topology-layout.ts (QL-21 graph, networkKey for R4's
                      host networks: vm-insight.ts topologyHostNetworks keys them alike and links them to the VM
                      page's Networks sheet, AppLink `hostNetworks`; layered layout), open-tunnels.ts (every pane's
                      tunnels, from their events), status-bar.ts (QL-22 texts, the vault countdown store, OpenJobs),
                      notifications.ts and notifications-store.ts (QL-25 entries per source, JobNotes, grouping),
                      navigation-api.ts,
                      density.ts (QL-24 `--spacing` and `--radius` through `data-density`), shortcuts.ts (QL-24 every
                      shortcut), first-run.ts (QL-23); FD-09 toolbox.ts (the tools, row targets, the last 20 inputs
                      per tool and workspace in local storage, every access in try/catch, result wording),
                      toolbox-api.ts (wrappers
                      and types), subnet.ts (the subnet calculator, IPv4 and IPv6 with BigInt), file-server.ts and
                      file-server-api.ts (the File server tab's form, checks and wording; wrappers and types) and
                      hooks/use-probe-run.ts (a run's id, progress and Stop); MO-08 checks.ts (kinds, defaults, the
                      editor's checks, wording, the sparkline's path) and checks-api.ts; 0.7.0 F5: comfort-api.ts
                      (notes, stars, recents, trash, bulk edit: types and wrappers), notes.ts (FD-06 link actions and
                      titles, excerpts, the note link), note-send.ts (a code block to the Terminal page's current pane, its
                      last line break taken off, and asked about whatever the paste setting when it has more lines:
                      PaneSession.paste's alwaysAsk), stars.ts and stars-store.ts (QL-26 sets, starred first, the search
                      boost; one shared store), trash.ts and undo-delete.ts (QL-27 names, messages, the delete toast's
                      Undo), bulk-edit.ts (QL-28 the form as a BulkEdit); pure helpers with
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
- VM-23 more .vmx keys: `vhv.enable` (nested virtualization), `uefi.secureBoot.enabled`, `vtpm.present` (a vTPM needs
  the VM encrypted: Remotely only reads it), CD/DVD drives are `<slot>.deviceType` `cdrom-image` (an ISO in
  `.fileName`) or `atapi-cdrom`/`cdrom-raw` (a host drive), `usb.present`, `ehci.present`, `usb_xhci.present`,
  `sound.present` and `.virtualDev` (`hdaudio`), `svga.graphicsMemoryKB`, `mks.enable3d`, `serialN.present` with
  `.fileType` and `.fileName`, shared folders `sharedFolderN.present`, `.enabled`, `.readAccess`, `.writeAccess`,
  `.hostPath`, `.guestName`, `.expiration`, `sharedFolder.maxNum`, and `isolation.tools.hgfs.disable = "FALSE"`.
  Workstation itself reorders keys when it writes a .vmx (`upgradevm` moved `config.version` and `virtualHW.version`);
  Remotely's own edits keep the order (`adapters::vmx_file`). A minimal .vmx with `scsi0.virtualDev = "lsisas1068"`
  needs `pciBridge0` and `pciBridge4` to `pciBridge7` (`pcieRootPort`, 8 functions), else power-on fails with "No PCIe
  slot available for SCSI0"; a stale `*.pciSlotNumber` gives the same error.
- `vmware-vdiskmanager.exe` sits beside vmrun (`adapters::vmware::locate_vdiskmanager`, `REMOTELY_VDISKMANAGER`):
  `-c -s <n>MB -a lsilogic|buslogic|ide -t 0` (thin) or `-t 2` (thick), `-x <n>MB` (expand; it says to grow the
  partition in the guest), `-k` (shrink), `-d` (defragment). It reports failures on stdout with a non-zero exit code.
  `vmware.exe <vmx>` opens Workstation's window on the VM (a tab, not powered on); Workstation adds the VM to its library.
- vmrun (Workstation 26): `upgradevm <vmx>` (VM off; 19 went to 22), `installTools <vmx>` (VM running; "No VMware Tools
  image exists for the guest operating system" for a guest type without one), `connectNamedDevice` /
  `disconnectNamedDevice <vmx> <ethernet0|sata0:1>` on a running VM. vmrun answers 0 even for a device the VM doesn't
  have (only `vmware.log` warns), so Remotely checks the .vmx first. A running VM's ISO changes with `writeVariable
  <vmx> runtimeConfig <slot>.fileName <iso>` then `connectNamedDevice <vmx> <slot>`; runtime changes are not written to
  the .vmx and are gone at the next power-on. `readVariable runtimeConfig ethernet0.connected` returns nothing, so a
  running Workstation VM's cable state can't be read. `deleteVM <vmx>` deletes the VM's own files (the .vmx, .vmxf,
  .vmsd, snapshot states, NVRAM, logs, its disks and their snapshot deltas, which sit in the VM's folder even for a disk
  outside it) and the folder when it is then empty; a disk outside the folder and files of other kinds stay.
- Workstation's locks: a VM that is running or open in a Workstation tab has a `<name>.vmx.lck` folder beside its .vmx
  and a `<disk>.vmdk.lck` folder beside each disk. A VM that is off but open in a tab keeps its settings in memory, and
  Workstation may write them back over a change, so Remotely refuses every change that writes the .vmx or a disk while
  a lock is there (`VmEditor::require_unlocked`; a lock left after a crash can be deleted once Workstation is closed;
  Remotely never deletes one), and warns in the approval and the edit dialogs while `vmware.exe` runs
  (`VmwareAdapter::workstation_window_open`, `WORKSTATION_OPEN_WARNING`).
- VM-11 host networks (Workstation 26): `vmrun -T ws listHostNetworks` prints `Total host networks: N`, then a table
  `INDEX NAME TYPE DHCP SUBNET MASK` (`8 vmnet8 nat true <subnet> 255.255.255.0`; types `hostOnly`, `nat`); vmnet0
  (bridged) isn't listed. A .vmx adapter's `nat` is the NAT vmnet, `hostonly` vmnet1, no type bridged (vmnet0),
  `custom` its `.vnet`. `listPortForwardings <vmnet>` prints `Total port forwardings: N` (0 here; the lines of a
  non-empty list were not seen, so Remotely reads them loosely and falls back to `vmnetnat.conf`), and refuses a
  host-only vmnet ("Host network type is not nat") or an unknown one ("Invalid host network"). `setPortForwarding
  <vmnet> <tcp|udp> <host port> <guest ip> <guest port> [description]` adds or replaces the forward on that host
  port; `deletePortForwarding <vmnet> <tcp|udp> <host port>` removes one. Forwards live in
  `C:\ProgramData\VMware\vmnetnat.conf` (`[host] device = VMnet8`; `[incomingtcp]` / `[incomingudp]` lines
  `<host port> = <guest ip>:<guest port>`), which SYSTEM and Administrators may change and Users only read; Windows has
  one NAT network. So changing a forward needs administrator rights: Remotely, never elevated, refuses it with that
  reason unless the app itself was started as administrator (`host_networks::nat_refusal`). Forwards listen on every
  address of this PC.
- VM-25: Workstation writes `vmware.log` in the VM's folder and keeps the older ones as `vmware-0.log` to
  `vmware-2.log`.
- VM-21, VM-10 deploy (`deploy::workstation`): `vmrun -T ws clone <vmx> <new vmx> full|linked [-snapshot=<path>]
  -cloneName=<name>` (a linked clone needs the golden VM's snapshot and shares its disk, so its disk can't grow). A
  cloud image is copied, never changed, by `vmware-vdiskmanager -r <image> -t 0|2 <new disk>` (0 growable, 2
  preallocated); a raw image goes through a flat-extent VMDK descriptor Remotely writes beside the new disk and deletes
  after; qcow2 needs converting first. A new VM is a written .vmx (with `pciBridge` entries) plus `vdiskmanager -c`.
  `ovftool --name=<name> --diskMode=monolithicSparse|monolithicFlat --noSSLVerify <ova|ovf> <new vmx>` imports an
  appliance; without `--acceptAllEulas` one with a licence fails, and the job says so. ovftool.exe is in `OVFTool\`
  beside vmrun (`adapters::vmware::locate_ovftool`: the Settings path, `REMOTELY_OVFTOOL`, then that folder).
  Workstation 26 (hand check): a full clone's disk keeps the source's name with `-cl1` (`golden-cl1.vmdk`), and a
  linked clone's is a delta whose `parentFileNameHint` is the golden VM's disk by absolute path. A full clone writes
  nothing of the golden VM's; a linked clone adds `snapshotN.cloneM = "<clone's .vmx>"` and `snapshotN.numClones` to
  its .vmsd, yet `vmrun deleteSnapshot` of that snapshot and `vmrun deleteVM` of the golden VM break the clone without a
  word (it no longer powers on), while deleting the snapshot's parent or a later one is safe; `deleteVM` of a clone
  lowers `numClones` but may leave its last `cloneM` line, so only the first `numClones` count (`linked_clones`
  refuses both deletes, naming the clones). Both clone a
  running golden VM from its snapshot, and the golden VM runs on; a VM started with `vmrun start ... nogui` has
  `<disk>.vmdk.lck` folders (and a `.vmem.lck`) but no `.vmx.lck`; and vmrun ignores a `.vmx.lck` (an open tab's): it
  clones beside one and writes the linked clone's record anyway, so only Remotely's own check stops it; ovftool writes .vmx
  keys in lower case (`displayname`, `virtualhw.version`; keys match without case, and `VmxFile` keeps one) and names
  an import's disk `<name>-disk1.vmdk`; a truncated OVA fails with "Disk (...) could not be found".
  cloud-init's VMware datasource reads `guestinfo.metadata` and `guestinfo.userdata` from the .vmx, each with
  `.encoding = "base64"`. Workstation's default VM folder is `prefvmx.defaultVMPath` in
  `%APPDATA%\VMware\preferences.ini`, else Documents\Virtual Machines.

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
- Guest properties: the app reads them all with one `guestproperty enumerate <uuid>` (VirtualBox 7 prints
  `<name> = '<value>' @ <time> (<flags>)` a line, the name padded; before 7.0 `Name: <name>, value: <value>, timestamp:
  <ns>, flags: <flags>`; `adapters::virtualbox::parse_guest_properties` reads both). Used:
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
- VM-21, VM-10 deploy (`deploy::virtualbox`): a new VM is `createvm --name --uuid --ostype --basefolder --register`,
  then `modifyvm`, `storagectl`, `createmedium disk --format VDI --variant Standard|Fixed` (thin or thick) and
  `storageattach`. A cloud image becomes the boot disk with `clonemedium disk` (VMDK) or `convertfromraw` (raw),
  grown with `modifymedium disk --resize <MB>` (it never shrinks). `clonevm <uuid> [--snapshot <uuid>]
  [--options=Link] --name --uuid --basefolder --register`; `import <ova|ovf> --vsys 0 --vmname --basefolder --cpus
  --memory`. `unattended detect --iso` says whether VirtualBox can install an ISO; `unattended install <uuid> --iso
  --user --password-file <file> --hostname <name>.localdomain --install-additions` prepares it (VirtualBox wants a
  domain in the name). The password goes only into a file this Windows user alone can read, deleted at once. A cloud
  image's first boot reads a NoCloud seed: an ISO labelled `cidata` with `user-data` and `meta-data`, attached as a
  DVD, then ejected (`storageattach --medium emptydrive`) and closed after the first boot. `list systemproperties`
  gives `Default machine folder:`; `list hostonlyifs` and `list bridgedifs` the adapters a network can use. A cancelled
  `clonevm` may hold the VM for a moment, so cleanup tries `unregistervm --delete` again a few times. VirtualBox 7.2
  (hand check): `unregistervm --delete` deletes a VM's disks but leaves its DVD images in the media list, so cleanup
  closes the seed with `closemedium dvd`; a linked clone's differencing disk sits under the snapshot's disk in the golden
  VM's media registry (`list --long hdds`: each disk's `Parent UUID`, and in `In use by VMs` the VMs and `[snapshots]`
  using it): `snapshot delete` of that snapshot fails ("more than one child hard disk") while the golden VM's own disk
  is a child too, but once the golden VM restored an older snapshot it merges the clone's disk away (the clone no longer
  starts), and `unregistervm --delete` of the golden VM unregisters it and deletes its current disk before it fails
  ("Cannot close medium ... because it has 1 child media"); deleting the snapshot's parent is safe (`linked_clones`
  refuses the other two up front); `unattended detect` on an ISO it doesn't know exits 1 (E_FAIL) after printing `IsInstallSupported="off"`, and
  Remotely takes any failure as "can't install it by itself"; `import` takes an OVA that ovftool made, and a truncated
  one fails with VERR_EOF. Windows' own `tar.exe` (libarchive) lists a seed's Joliet names, a check that doesn't use
  Remotely's reader.
- MO-13: `showvminfo` also gives `firmware` (`BIOS`, `EFI`...), `nictypeN` (the card, e.g. `82540EM`, `virtio`) and
  `cableconnectedN` (`on`/`off`); the storage key (`"SATA-0-0"`) is the disk's slot. A VDI's header has the signature
  0xbeda107f at 0x40, its type at 0x4c (4 is a snapshot's differencing image) and the disk size at 0x170; a VHD's
  footer (`conectix`, big-endian) has the size at 48, at the start of a dynamic one and the end of a fixed one.
- VM-23 (checked on 7.2.22): `showvminfo` also gives `nested-hw-virt`, `SecureBoot` (only once the VM has a UEFI
  variable store), `vram`, `accelerate3d`, `monitorcount`, `graphicscontroller`, `usb`/`ehci`/`xhci` (`on`/`off`),
  `audio` (the host driver, `none` for no sound card), `uartN` (`off` or `0x03f8,4`) with `uartmodeN` (`file,<path>`,
  its path not escaped), `storagecontrollernameN`/`typeN`/`portcountN`, `SharedFolderNameMachineMappingN` and
  `...PathMachineMappingN`, and `bridgeadapterN`, `hostonlyadapterN`, `nat-networkN`, `intnetN`. A DVD drive is a slot
  with a `"<ctl>-IsEjected-<port>-<dev>"` key; its value is an image, `emptydrive`, or `host:<drive>`. It doesn't print the
  TPM, the shared folders' flags or the sound card: the .vbox has `<TrustedPlatformModule type="v2_0"/>`, `<SharedFolder
  writable=... autoMount=...>` and `<AudioAdapter controller="HDA">`. `list ostypes` prints `ID / Description: <id> --
  <description>` (7.1+). VBoxManage writes its `0%...100%` progress to stderr.
- Changes (VM off unless said): `modifyvm` (`--cpus`, `--memory`, `--nested-hw-virt`, `--firmware bios|efi`, `--tpm-type
  none|2.0`, `--name` (renames the folder and files too), `--ostype <id>`, `--nicN`, `--nictypeN`, `--macaddressN
  auto|<hex>`, `--cableconnectedN`, `--bridgeadapterN`...), Secure Boot through `modifynvram <uuid> inituefivarstore`,
  `enrollmssignatures`, `enrollorclpk`, `secureboot --enable|--disable`; `sharedfolder add|remove`; `storagectl
  --portcount`; `storageattach ... --type dvddrive|hdd --medium <file>|emptydrive|none` (a DVD's medium changes on a
  running VM too); `createmedium disk --filename --size <MB> --format VDI [--variant Fixed]`; `modifymedium disk <file>
  --resize <MB>|--compact`; `closemedium disk <file> --delete`; `controlvm <uuid> setlinkstateN on|off` (running).
  `modifymedium --resize` on a base disk under a snapshot resizes the base while the guest keeps seeing the
  differencing image's old size, so Remotely refuses disk changes on a VM with snapshots. `unregistervm <uuid>` keeps
  the files; `--delete` removes the .vbox, .vbox-prev, .nvram, attached disks (snapshot ones too), Logs and Snapshots,
  and keeps other files and the folder. After a snapshot the VM runs on differencing images (`Snapshots/{uuid}.vdi`)
  and the snapshot keeps the base disks; `--delete` deletes both, so the preview reads every `<Image uuid>` under an
  `<AttachedDevice type="HardDisk">` in the .vbox (machine and snapshots) by its `<HardDisk location>` in the media
  registry. `registervm <file.vbox>` refuses a VM whose UUID is registered already.
  `controlvm <uuid> screenshotpng <file>` (running), `VirtualBoxVM.exe --startvm <uuid> --separate` (a window on a
  running VM), `VBoxGuestAdditions.iso` beside VBoxManage.
- VM-11 (checked on 7.2.22): `list hostonlyifs` prints blocks of `Key: value` (`Name`, `GUID`, `DHCP`
  Enabled/Disabled, `IPAddress`, `NetworkMask`, `Status` Up/Down, `VBoxNetworkName`), the `Name` being what
  `--hostonlyadapterN` takes; `list hostonlynets` is macOS only ("Unknown subcommand" on Windows). `list natnets` leaves
  the rules out: `list --long natnets` prints `Name:` (6.1: `NetworkName:`), `Enabled`, `Network` (CIDR), `Gateway`,
  `DHCP Server`, `IPv6`, then `Port-forwarding (ipv4)` and indented rules `name:proto:[host ip]:host port:[guest
  ip]:guest port` (`[]` for any), then `loopback mappings (ipv4)`. `natnetwork modify --netname <n> --port-forward-4
  <rule>` adds one, `... --port-forward-4 delete <name>` removes one; a taken name ("A NAT rule of this name already
  exists") or a missing one ("Failed to delete pf") is an error. A rule name may hold spaces. A VM's NAT rules are
  `Forwarding(N)="name,proto,host ip,host port,guest ip,guest port"` in `showvminfo --machinereadable`, right after
  their adapter's `natnetN`, `macaddressN`, `cableconnectedN`, `nicN`, `nictypeN` and `nicspeedN` keys (the key doesn't
  name the adapter; N restarts at 0 per adapter). `modifyvm <uuid> --natpfN <rule>` while off, `controlvm <uuid>
  natpfN <rule>` while running (kept after power-off; on a VM that is off: "is not currently running"), `delete
  <name>` to remove; none needs administrator rights.
- VM-25, VM-16: `showvminfo --machinereadable` also gives `LogFldr` (`Logs` beside the .vbox: `VBox.log`, kept as
  `VBox.log.1` to `.3`, and `VBoxHardening.log`), `SnapFldr`, and for a saved VM `VMStateFile` (the `.sav` in the
  snapshot folder), which, unlike `CfgFile`, is printed without escaping its backslashes. `list systemproperties` has
  `Default machine folder:`.
- Two `showvminfo` calls on the same VM at the same moment: the second fails ("The machine '<name>' already has a lock
  request pending", or "The session is not locked", "The object is not ready" around a state change). R4's reads ask
  again up to three times (`host_networks::showvminfo_pairs`, `vbox_busy`), and the waste finder reads each VM once
  per report, in sequence.

## Conversion tools facts

CV-01 to CV-03, VM-17, from 0.5.0 (`docs/plan-0.5.md`, R5). Checked by hand with Workstation 26's vdiskmanager and
ovftool 5.0, VirtualBox 7.2.22 and qemu-img 10.1 on images of a few MB.

- vmware-vdiskmanager `-r <src> -t <n> <dst>` reads any VMDK, a snapshot delta with its whole chain (it flattens it),
  and a raw disk through a flat-extent descriptor. `-t 0` growable, `-t 2` preallocated (`<name>.vmdk` with
  createType `monolithicFlat` and a `<name>-flat.vmdk` extent holding the raw bytes), `-t 4` ESXi's preallocated
  layout (createType `vmfs`, the same two files), `-t 5` stream-optimized (a `KDMV` file). It prints
  `\r  Convert: NN% done.` and refuses a target that is there. It reads no VHD, VDI, VHDX or qcow2.
- `ovftool <vmx> <file.ova|.ovf>` exports the VM as it is now; it has no OVF 2.0 option (OVF 1.0 only), and
  `--shaAlgorithm=SHA256` (the default) writes the manifest. `--noImageFiles` leaves an attached ISO out.
- `VBoxManage clonemedium disk <src> <dst> --format VDI|VMDK|VHD|RAW [--variant Standard|Fixed|Stream]` registers
  **both** the source and the target in VirtualBox's media list (`list hdds`); `closemedium disk <file>` takes one
  out (the file stays). `convertfromraw` registers nothing. A VirtualBox VM's current disk (its snapshot's
  differencing image) is cloned whole, its chain merged. Progress is `0%...10%...` on stderr. Its VHDX backend
  (`list hddbackends`: capabilities 0x0240, no create) is read-only and refused qemu-img's own VHDX ("BAT region not
  marked as required"), so VHDX goes through qemu-img; its QCOW backend isn't used either. `VBoxManage export
  <uuid> --output <file> --ovf10|--ovf20 --manifest` writes an appliance of the VM as it is now.
- qemu-img (QEMU for Windows, `C:\Program Files\qemu\qemu-img.exe` by default; GPL, never shipped): `convert -p -f <in>
  -O <out> [-o ...]` prints `    (NN.NN/100%)\r`; `-O vpc -o subformat=fixed,force_size=on` keeps a VHD's exact size
  (without force_size it rounds to a CHS geometry), `-O vhdx -o subformat=dynamic|fixed`, `-O vdi -o static=on`,
  `-O qcow2 -o preallocation=metadata` (on Windows its file driver refuses `full` and `falloc`, and `metadata` makes the file its full size), `-O vmdk -o subformat=monolithicSparse|monolithicFlat|streamOptimized` (no
  `vmfs`). A failure prints `C:\...\qemu-img.exe: <message>` and exits 1. `compare -f A -F B a b` exits 0 ("Images
  are identical."), 1 when they differ ("Content mismatch at offset N!"), 2 on an error. Remotely always passes `-f`
  (and `-F`), so it never probes, and never gives it a disk with a parent or a backing file.

## Development safety

- Unit and integration tests must never stop, reset, suspend, revert or delete snapshots on real VMs. Use the fake VMware adapter, and `fakes::FakeVirtualBox` for VirtualBox.
- VM settings (VM-23 and on): never edit, resize, delete or register a real VM in a test. `FakeVmware::with_vmx_text`,
  `with_disk` and `with_file` hold a VM's .vmx, disks and files in memory, and the fake applies every edit, vdiskmanager
  call and vmrun verb to them (`vmx_text`, `backups`, `disk_size_mb`, `calls`); `FakeVirtualBox` interprets the
  VBoxManage calls (`change ...` in `calls`, `info`, `disk_size_mb`, `registerable`). Adapter tests run the real
  `VmrunAdapter` against a stand-in `vmware-vdiskmanager.cmd` written at run time in the system temp folder
  (`tests/vm_settings.rs`, `adapters/vmware.rs`).
- Host networks (VM-11): never add or remove a forward or a network on this PC in a test. `FakeVmware` and
  `FakeVirtualBox` hold vmnets, NAT networks and rules in memory (`fakes/host_networks.rs`); the waste finder's and
  the Log tab's tests use folders and log files made at run time in the system temp folder.
- Never let a `\\server\share`, `//server/share`, `\\?\` or `\\.\` path reach the real file system in a test, not
  even a made-up one (Windows would send the sign-in to it). Tests of refused paths (A3) go through in-memory fakes
  that fail when asked for one (`import::openssh::IncludeFiles`, `adapters::vm_hardware::VmFiles`) or an injected
  check (`import::importer::key_file`); an end-to-end test may use a DOS device name such as `NUL` instead.
- Tests against real Workstation or VirtualBox are opt-in: they run only when `REMOTELY_IT=1` is set, read only, and only touch VMs whose display name starts with `it-`.
- Consoles (SS-12): never start mstsc.exe or a VNC viewer, or open a real COM port, in a test. Under the `fakes`
  feature `Terminals` starts with `NoLauncher` and an empty `FakeSerialPorts`, so a test that forgets its fakes fails
  instead; tests give `FakeLauncher` and `FakeSerialPorts` (`set_launcher`, `set_serial_ports`) and talk Telnet to
  `fakes::TelnetTestServer` on 127.0.0.1 (`tests/consoles.rs`).
- Don't connect to real SSH hosts in tests. Use a local test server or a fake: `fakes::ssh_server::TestSshServer`
  (russh on 127.0.0.1, keys made at run time; it can drop or freeze its connections, or refuse new ones for a while
  (`set_refusing`, R9 reconnect tests), and runs exec requests in a toy shell with sudo modes, /proc files, a `grep`
  that reads several files the way the guest metrics script does, and fake programs such as `df`; its interactive
  shell has `sudo`, Ctrl+C, a
  full-screen `top`, and the exec shell's `hostname`, `uptime`, `cat`, `seq`... and fake programs, slowed by
  `with_exec_delay`), with `common::Setup::with_ssh()` for the real russh adapter. MultiExec tests open several of
  them (`tests/multiexec.rs`, QL-12 recording included). SS-08: it serves SFTP from a temp folder deleted with it
  (`with_sftp_file`, `with_protected`, `with_unreadable`, `without_sftp`; H8 renames like OpenSSH's, with
  `posix-rename` unless `without_posix_rename`, modes and owners from `with_sftp_owner`; A9 `with_endless_folder`),
  its exec shell knows `rm`, `mv` and `grep -v` (SS-09 key removal), and with `with_login_shell("bash")` its
  shell answers the folder hook (OSC 7 and the QL-09 user report) and knows `cd`, `pwd` and `su [-] [user]` (a shell
  without the hook, as a real switch); `fakes::FakeFiles` is the in-memory version for the fake remote adapter
  (`tests/files.rs`). Uploads
  and downloads in tests use files made at run time in the system temp folder, never in the repo. SS-07: it forwards
  like OpenSSH (direct-tcpip, tcpip-forward on 127.0.0.1 only); `with_route("db01.test", port)` makes a name only it
  resolves, so `tests/jump_hosts.rs` chains three servers, and `tests/tunnels.rs` carries bytes to an echo service on
  127.0.0.1. Tunnel tests bind loopback with port 0; never a network address.
- Deploy (VM-21, VM-22, VM-10): never create, clone, import or delete real VMs in tests. `tests/deploy.rs` runs
  deploys through the bus and the job runner on `FakeVmware` and `FakeVirtualBox` (clone, import, create, media copies,
  `set_failing` for cleanup, `with_clone_delay` to cancel mid-way) in temp folders; the real adapters' command lines
  are checked against stand-in vmrun, ovftool and VBoxManage `.cmd` files made at run time (a batch file gets an
  argument with `=` quoted).
- Stacks (VM-08): `tests/stacks.rs` deploys, starts, stops and tears down stacks on the same fakes, with
  `Core::set_stack_clock(FakeStackClock)` so readiness waits and delays never sleep (`at` hooks open a `FakeNetwork`
  port or make a fake fail at a given fake time).
- Conversion (CV-01 to CV-03, VM-17): never convert, export or import a real VM's disks or a downloaded image in a
  test. `tests/conversion.rs` runs through the bus with `fakes::FakeDiskTools` (it runs no program and writes small
  files with each format's header) on images from `fakes::disk_images` made at run time in the system temp folder;
  never an image on a network share. The opt-in `conversion_it.rs` runs the real tools on 64 MB images in the temp
  folder and exports an `it-` Workstation VM made of files there, never registered; it checks VirtualBox's media
  list is as it was.
- Support bundles (FD-04): tests collect from `TestSshServer` (its exec shell and SFTP) or in-memory hosts, and write
  their zips to the system temp folder, never the repo (`tests/support_bundle.rs`).
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
- Logs (QL-15): `logs\` in that data folder (`%LOCALAPPDATA%\com.remotely.desktop\logs`, `...desktop.dev\logs` for a debug
  build, or `logs` under `REMOTELY_DATA_DIR`): `remotely.YYYY-MM-DD.log`, one a day, 7 kept (`RUST_LOG` sets the level;
  default `info,sqlx=warn,tao=warn,wry=warn`), and `crash-YYYYMMDD-HHMMSS.txt` from the panic hook, 7 kept. Settings,
  About opens the folder; a debug build also logs to stdout. Never log a secret: `crates/core/tests/log_fields.rs` fails
  on a log call that names one, and `src-tauri/tests/log_secrets.rs` reads the log file of a run that uses vault
  secrets. A release build runs once (a second start shows the open window); a debug build can run beside it.
- Rust tests: `cargo test --workspace` (run at the repo root; `cargo test` inside `src-tauri/` only tests the shell crate)
- Try the terminal, MultiExec or Compare output without a real host:
  `cargo run -p remotely-core --example dev_ssh_server --features fakes [port] [count]` (default 2222 and 1 server;
  prints the user, one fresh password for all of them, which sudo takes too, and each host key fingerprint). Each also
  serves moving /proc counters, so watching it on the dashboard shows live guest metrics, and SFTP from a temp folder
  (SS-08) with a bash login, so the "Files here" drawer follows `cd` (QL-09: `cd /home/bob/.app`, a folder alice
  can't open over SFTP, and `su bob` to switch user). SS-07: the servers reach each other as
  `dev-host-01.test`, `dev-host-02.test`... (names this PC can't resolve, so they need a jump host) and a web page as
  `web.test:80`, for trying chains and tunnels. CT-01: each has `docker` and `podman` with a small shop of containers
  (from the second server on, docker needs sudo); mark a session as a container host on the Containers page. SS-12: a
  Telnet router console listens on the port after the web page (alice and the same password), for a Telnet session.
- Opt-in test against real Workstation (reads only: the library, `vmrun list`, Tools state and IP of running VMs, and their processes' counters): `REMOTELY_IT=1 cargo test -p remotely-core --test workstation_it`
- Opt-in test against real VirtualBox (reads only: `list vms`, then for `it-` VMs only `showvminfo`, snapshots, guest properties and their processes): `REMOTELY_IT=1 cargo test -p remotely-core --test virtualbox_it`
- Opt-in test against the real conversion tools (vdiskmanager, VBoxManage, qemu-img when installed, ovftool; temp images and an `it-` VM's files only): `REMOTELY_IT=1 cargo test -p remotely-core --test conversion_it -- --nocapture`
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
  `data-mask="host|ip|user|address"` (inputs then show dots while presenting), and a workspace name
  `data-mask="workspace"`. Text shown outside the window (Windows
  notifications) goes through `maskedOutside`. A new IPC field holding a host, IP or user should use one of the names
  `learnFields` knows (`host`, `hostname`, `ip`, `username`, ...). A new state-changing core method that skips the bus
  starts with `store.read_only().check(Change::…)`.
- A new path that saves a file the user chose calls `save_guard::refuse_repository` (or `_folder`) first, so customer
  data never lands in a Git working tree. Free text kept in the journal or the audit log goes through
  `export::redact_secrets` (the audit store and `Command::for_journal` already do it).
- Commit messages start with the requirement ID where one applies, e.g. `VM-02: bulk suspend and resume`.

### UI rules (0.6.0, UX-01 to UX-13; `docs/plan-0.6.md`)

Every page and dialog follows these; a change that can't says why in its PR.

- **Header.** A page opens with `PageHeader` (`src/components/PageHeader.tsx`): the title from the page registry
  (`src/lib/navigation.ts`, so it matches the sidebar), its "?" (`help`, `page.<id>` by default), search and filters as
  `children`, at most one `primary` button, everything else page-wide in `tools` (the "⋯" menu), and tabs as a `TabsList`
  in `tabs`. A new page goes in the registry, in its sidebar group, and gets a `page.<id>` help entry.
- **One primary per view.** One filled (default variant) button per page, dialog or empty state. Buttons use three
  variants (default for the primary, `outline` for secondary, `ghost` for toolbars, rows and menus; `destructive` only
  for a delete's confirm) and two sizes (`default`, `sm`, with `icon`/`icon-sm` for icon buttons). Icon buttons have an
  `aria-label` and a tooltip; refreshing is always `RefreshButton` (the tooltip "Refresh").
- **Selection bar.** Bulk actions show only while rows are selected, in `SelectionBar` ("N selected", ghost `sm`
  actions, ✕ and Esc to clear), which replaces the page's search row. Never a bulk bar that sits there disabled.
- **Row menu.** Every list's row actions are one `RowMenu` (the "⋯", `ghost` `icon-sm`, "Actions for <name>"). A row's
  main action may also be its click or a hover icon, never a third copy; each action has one home plus the palette.
- **Help budget.** At most one line of help shows by default per card, dialog, alert or empty state. More goes in a
  `HelpTip` (`src/components/HelpTip.tsx`) whose text is one entry of `src/lib/help.ts`, written once and referenced by
  key; an explanation needed in two places is one key. A term of the app's own gets a `Term` (`src/components/Term.tsx`,
  `src/lib/glossary.ts`, one sentence each) where it first shows. Shortcut lists live in the shortcut sheet (Ctrl+/),
  not in footers.
- **Empty states.** `EmptyState` (`src/components/EmptyState.tsx`): a title naming the space ("No images yet"), one
  line on what it is for, and the one action that fills it. A disabled control says why next to it (`WhyDisabled`).
- **Tips.** A first use that needs a sentence of guidance gets a one-time `Tip` (`src/components/Tip.tsx`, id
  `<page>.<what>`); Settings › General's "Show tips again" resets them. Never a tour.
- **Copy.** Sentence case everywhere (titles, buttons, menu items, tabs); buttons start with a verb ("Add an image",
  "Deploy"); one name per concept: **Protected**, **Environment**, **Compare hosts**, **Type in all tabs** (code keeps
  `multiExec`), page names as in the sidebar. No requirement IDs in anything shown (`src/lib/requirement-ids.test.ts`
  fails the build on one in a string or JSX text; comments keep them), no "please" or "successfully", no internal names
  (`AP-04`, `DPAPI`, `AES-256-GCM`) where a plain word does, and status in words ("2 snapshots · OK"), with rules in a
  tooltip.
