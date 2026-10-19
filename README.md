# Remotely

A Windows desktop app for forward deployed engineers and IT admins: bulk control of VMware Workstation Pro VMs, a
performance dashboard, a PuTTY/MobaXterm-style SSH session manager with MultiExec (type into several terminals at once)
and Compare output (one command on many hosts, answers grouped), with multi-step approvals on every high-impact action.

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
tier). The SSH terminal, imports, MultiExec and Compare output work over russh. The Terminal page has a session tree with reachability dots, quick connect (saved or not), the host's own name and IP on each tab, search, saving, printing or logging the output of one terminal or several at once, a command panel with your favourite commands and a library of common ones (with `{{variables}}`, marked by the approval rules), "Type vault password" for sudo prompts, a Windows notification when a long command finishes in a background tab, file transfer over the terminal's own connection, MultiExec and Compare output (below). The dashboard shows every running VM's CPU, RAM and disk I/O read from its `vmware-vmx.exe` process (no login), and its share of this host's CPU and RAM (also on the VM list), Linux guest metrics over SSH for watched sessions, colour thresholds, live charts and a host capacity panel. Sessions link to the VMs they reach on their own when their host is a VM's guest IP address, so those VMs work in Compare runs and guest metrics without linking by hand. Ctrl+K opens a command palette for pages, VMs, sessions and actions.
Sessions, folders, tags, labels, trusted host keys and (only when ticked) vault secrets move to another laptop in one
encrypted file (Argon2id from a passphrase, AES-256-GCM), imported with a preview that lets you skip, replace or keep
both of each conflicting item. The SSH key manager on the Vault page generates Ed25519 or RSA 4096 keys straight into
the vault, copies their public keys, lets sessions log in with them and pushes a public key to many hosts'
`authorized_keys` through the approval flow.

### Command panel

BX-08, on the right of the Terminal page: a click pastes a command into the current terminal, Shift+click also presses
Enter, and with MultiExec on it goes to every picked terminal through MultiExec's checks. Every command shows what the
approval rules make of it (read-only, changes, dangerous), so you see before you run it what a bulk send would ask for.

- **Favourites**: your own saved commands, in one level of folders, reordered by hand, with optional `{{variables}}`
  (`{{service}}`, `{{host:db01.test}}`) asked when you paste. Adding, editing and reordering are audited by name and
  folder, never the command text. Any library command can be copied into your favourites.
- **Library**: a large built-in set of Linux commands for day-to-day admin and troubleshooting (RHEL/Rocky/Alma 8–9,
  Ubuntu 22.04/24.04, Debian 12; apt and dnf, ufw and firewalld both given where they differ). None opens a pager or
  hangs. It has two sections, searchable together with collapsible groups:
  - **Troubleshoot** — runbooks by symptom (host is slow, out of memory, disk is full, can't reach a service, DNS
    fails, service won't start, can't log in over SSH, clock is wrong, certificate expired or failing, package manager
    broken), each listing the checks to run in order.
  - **By area** — 25 groups by topic: system info; disk and filesystems; storage (LVM, RAID, SMART, SAN, NFS/SMB);
    memory; CPU and processes; network; services; logs; packages (apt and dnf); users and groups; security and access
    (SELinux, AppArmor, sudo, `sshd -T`, auditd, fail2ban); TLS certificates; firewall; web servers (nginx, Apache);
    databases (MySQL/MariaDB, PostgreSQL); cron and timers; time sync (NTP/chrony); identity (AD/LDAP, SSSD); VMware
    Tools in the guest; Docker; Podman; Kubernetes; Helm.
    Most entries are read-only checks; the fixes (restart or reload a service, vacuum the journal, extend an LV and grow
    its filesystem, resync the clock, clear a failed unit, open a firewall port) are marked as changes and ask before
    they run. A command can appear both in a symptom runbook and in its area group.

### MultiExec and Compare output

Bulk execution lives in the Terminal page (it replaced the MVP's Bulk run page):

- **MultiExec** (SS-10): the toolbar switch makes the picked tabs receive what you type into any of them, as in
  MobaXterm, and can show them side by side; each terminal shows its own output. Pick tabs with Ctrl+click and
  Shift+click, or all of them, a folder's or a label's from the MultiExec bar. The command panel's paste and Shift+click
  go to them too. Safety: Remotely follows the line as it is typed, holds Enter and rates the line like any remote
  command (read-only, other, dangerous; a Prod tab raises the tier). A read-only line goes at once; anything higher
  opens the approval dialog with the line and the terminals, and Cancel sends Ctrl+C to each. A line edited with keys
  Remotely can't follow (Tab completion, arrow keys, history search), or a tab that already had text on its line, is at
  least a confirm. Every line sent is in the audit log with the command, the sessions and the tier, never the output.
  Two exceptions pass keys straight through, unrated: at a password prompt (the keys go only to the tabs showing one,
  and are never kept or logged) and to a full-screen program such as vim, less or top (only to the tabs that have one
  open; what is typed there, like vim's `:!command`, is not rated). Protected sessions are left out.
- **Compare output** (BX-03): runs one command once on the hosts of the picked tabs and of sessions Ctrl+clicked in the
  session tree (Ctrl+click a folder for all of it, handy for 50 hosts), over separate exec channels with the usual
  approval tiers, sudo from the vault, a time limit and the parallel limit from Settings. The results are grouped by
  output ("48 hosts same, 2 differ"), with a diff between groups, retry of the failed hosts and CSV, JSON or HTML
  export. Quick connections that were not saved as sessions can't be compared.

### File transfer in the terminal

SS-08: files go up and down over SFTP on each terminal's own SSH connection, so there is no second login or window.

- **Files here**: the drawer (the folder button in the Terminal toolbar) lists the current terminal's folder. For bash
  and zsh it follows the shell as you `cd`: on connect Remotely types a small prompt hook that reports the folder (OSC 7) before each prompt, and hides it completely: it never shows in the terminal, its scrollback, saved output, session
  logs or MultiExec, and it starts with a space and removes itself from bash's history. It is only typed while nothing
  has been typed in the new shell yet, after its first prompt; a session's startup command waits for it. Other shells
  (sh, fish, network gear) get nothing typed: the drawer starts in the home folder, and you open folders by
  double-clicking, the breadcrumb, Up or a typed path. Sort by name, size or date; tick files to download them.
- **Download**: to Downloads, or a folder you pick (Download to…). A file of the same name there is kept; the new one
  gets a number. Right-click a file name in the terminal's output (`ls`, an error message) to download it; elsewhere
  right-click pastes as before. "Open folder" in the transfers list shows a finished download in Explorer. Each download
  is in the audit log with the file's name, size, host path, where it was saved and its SHA-256, never its content.
- **Upload**: drop files on a terminal, or use the upload button (toolbar or drawer). They go into the terminal's
  folder (the drawer's upload goes into the folder it shows). Uploads are changes, so they go through the command bus:
  Low, a Prod session raises it one tier, and a file that is there already is replaced only after you say so and
  confirm (replacing is at least Medium; Settings won't take less). Files are written as the logged-in user and never
  with sudo: a folder you can't write to fails with a message saying so. Each uploaded file is audited with its name,
  size, destination and SHA-256. Folders aren't uploaded or downloaded (zip them, or pick their files).
- **Transfers**: the list under the drawer shows each file's progress, speed and time left, with cancel and retry (a
  retried upload asks again if it now replaces a file). A new file that fails or is cancelled part way is deleted from
  the host; a replaced one is left as far as it got, and the message says so.
- With MultiExec on, uploads and downloads still go through one terminal: the current one. ZMODEM (`sz`/`rz`) is not
  supported.

### Jump hosts and tunnels

SS-07: a session can name another session as its jump host, and that one its own, and so on (up to 8 hops). Remotely
connects through each in turn over SSH direct-tcpip channels, as `ssh -J` does, so a session's name only has to resolve
on its jump host.

- **Every hop checks its host key** with the usual first-use question, which names the jump host it is about; a changed
  key at any hop blocks the connection there and names that hop. Each hop logs in with its own session's login: a
  password or key from the vault, the SSH agent, or (in a terminal) a password typed at `bob@bastion's password:`, kept
  for that terminal's reconnects like the session's own. Jump hosts that lead back to a session on the way are refused
  when the session is saved and again when connecting.
- **Everything goes through the chain**: terminals (keep-alive, reconnect, SFTP), Compare output and other commands, SSH
  key pushes and the dashboard's guest metrics. The tab and the session tree say "via <jump host>", and the tooltip
  shows the whole route.
- **Reachability**: a session behind jump hosts is not probed from this PC. Its dot is a ring with the first jump host's
  state (the one this PC dials), never red because the session itself can't be reached from here.
- **Port forwards**: each session keeps local (`ssh -L`), remote (`ssh -R`) and SOCKS (`ssh -D`, SOCKS 4, 4a and 5)
  forwards, edited with the session. They listen on 127.0.0.1 unless you type another address (the host side of a
  remote forward defaults to localhost); port 0 takes any free port. Those marked "starts with the terminal" open when
  the terminal first connects; the terminal's Tunnels button lists them with their state (listening where and how many
  connections, waiting for a reconnect, failed and why) and starts or stops them. A tunnel rides the terminal's
  connection: behind jump hosts it starts from the session's host, it opens again by itself after a reconnect, and it
  closes with the terminal.
- **Approvals**: opening a tunnel is a command on the bus. A local or SOCKS tunnel only this PC can use is Low (so
  Medium on a Prod host, as the PRD's tier table says). A remote tunnel is Medium: the host listens, and whatever
  reaches that port gets into the network this PC is on. A tunnel that listens on a network address (0.0.0.0, a LAN
  IP), on either side, is Medium and never lower: other computers can use it without logging in, and the dialog says
  so. Forwards that start with the terminal go through the same approval. Opening and closing are audited with the
  session, kind, addresses and ports, never what goes through.
- Exports to another laptop carry each session's jump host and port forwards.

Not done here: importing port forwards from PuTTY, MobaXterm or OpenSSH config files (the jump host link is imported),
and a jump host in quick connect.

### Presentation mode

FD-03, for screen shares on customer calls. **Present** in the top bar (or "Present" in the Ctrl+K palette, or Settings,
General) masks host names, IP addresses, user names and your Windows user name in local paths everywhere on screen:
tab titles and the "via" line, the session tree, every table, dialogs (approval, host key, session editor, port
forwards, quick connect, import and export previews), toasts, tooltips, the Files here drawer, the transfers list, the
Tunnels panel, the command panel, error messages and the long-command Windows notifications. While it is on, the button
reads **Presenting** in purple and a purple frame runs round the window. Remotely starts presenting if it was presenting
when it closed (and presents if that setting can't be read). Stopping asks once. Starting and stopping are in the audit
log.

- **Stand-ins**: each value gets one for as long as Remotely runs (`host-3`, `user-2`, `ip-5`), so rows stay apart on a
  call. They are counters, not hashes, kept in memory only, never saved or shown with the real value.
- **What is recognised**: values the app knows as hosts, IPs and users (session hosts and users, VM guest IPs, host
  names and IPs a terminal reported, known hosts, quick connect history, tunnel destinations), wherever they appear as a
  whole word; and in any text, IPv4 and IPv6 addresses (compressed forms too), FQDN-like names (a known top-level domain
  or three labels or more, not a file name: `web01.example.com.log` shows as `host-1.log`, `README.md` stays),
  `user@host`, `C:\Users\<name>\…` and `/home/<name>`. Session and VM names are labels and stay visible unless they
  look like a host or hold a known one. Loopback and "any" addresses (127.0.0.1, ::1, 0.0.0.0, localhost) stay, so
  "listening on 127.0.0.1:8080" still reads right. Ports stay. Common account names (root, admin, ubuntu…) are masked
  in their own field and in `user@host`, not as bare words in sentences.
- **Inputs** keep their real value (it is what you edit and save). Those that hold a host, user or address (the session
  editor, quick connect, port forwards, a command's `{{host}}`-like variables), and any other one whose value holds
  something to mask, show dots while presenting.
- **Terminals**: output is masked as it arrives, on screen only. The pane shows a masked copy of the terminal in front of
  the real one; stand-ins keep the width of what they replace (`ip-1······` for `192.0.2.10`), so columns, line wraps and
  the cursor stay where the host put them. A value split across reads or with colour changes inside it is still found
  (the last word of a read waits up to 25 ms for the rest). What you type goes to the host unchanged. Copying (a
  selection, Ctrl+Shift+C, copy-on-select), Copy all, Save, the session log and right-click Download read the real
  text: they don't go on screen, and the Presenting menu says so. Print shows a preview on screen, so it prints the
  masked text while presenting.
- **Not masked**: Windows' own dialogs (file pickers show real paths), anything outside Remotely's window, screenshots
  and recordings. In terminals: what you type as you type it (the echo arrives one key at a time), a full-screen program
  (top, htop, vim, less) that redraws only part of a name, a value split by a pause of more than 25 ms in the output,
  and secrets a remote program prints (Remotely never sees vault values in the UI, so it can't recognise them on
  screen). For those, **Hide terminal output** in the Presenting menu blurs the terminals; typing still works.
- **Read-only lock** (optional, in the Presenting menu, the palette or Settings; kept for next time): while presenting
  with it on, the core refuses every command on the bus, whatever its tier (VM power and snapshots, protection, remote
  commands including read-only ones, MultiExec lines, uploads, tunnels, SSH key pushes, updates), and every edit of the
  app's data (sessions, folders, labels, tags, saved filters, VM links, imports, the vault and SSH keys, favourites, port
  forwards, settings, approval rules, replacing or removing trusted host keys, turning MultiExec on). An approval asked
  before the lock came on waits until it is off. Still allowed, because they change nothing outside this PC or are part
  of connecting: reading everything, connecting, typing into one terminal (it is your own shell), trusting a new host's
  key on first use, downloads and saved or logged output (they only read from the host and write files on this PC),
  exports, the vault's lock and unlock, update checks, stopping tunnels and cancelling jobs. Disabled buttons say why,
  each page says what the lock blocks there, and turning the lock off while presenting asks once.

Disabled buttons say why they are disabled (QL-08), in a tooltip or under the menu item.

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

To try the terminal, MultiExec, Compare output, guest metrics, file transfer, jump hosts and tunnels without a real
host, run the toy SSH servers (they print the user, one fresh password and each host key):

```bash
cargo run -p remotely-core --example dev_ssh_server --features fakes 2222 3
```

They listen on 127.0.0.1:2222 to 2224 and reach each other by the names `dev-host-01.test` to `dev-host-03.test`,
which this PC can't resolve. For a two-hop chain, save `dev-host-01` as 127.0.0.1:2222, then `dev-host-02.test` (port 22) with it as the jump host, then `dev-host-03.test` with that one as its jump host. `web.test:80` is a small web page
they all reach: a local forward `127.0.0.1:8080 -> web.test:80` on any of them serves it at http://127.0.0.1:8080, and a
SOCKS forward on 1080 serves it to `curl --socks5-hostname 127.0.0.1:1080 http://web.test/`.

## Checks

| What                                 | Command                                                                               |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| Rust tests (core and shell)          | `cargo test --workspace`                                                              |
| Rust lint                            | `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` |
| UI lint (types, ESLint, Prettier)    | `npm run lint`                                                                        |
| UI tests (pure helpers)              | `npm test`                                                                            |
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

| Module            | Path                                                          | PRD requirements                                                                                                                    | State                                                                                                                                                                          |
| ----------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Command bus       | `crates/core/src/command_bus.rs`                              | AP-01 (saves rules), AP-02, AP-03, AP-06, VM-02, VM-03, VM-04, BX-02, SS-07, SS-08, SS-10, FD-14                                    | Working: the only way to enqueue a job (MultiExec lines, uploads and tunnels too); checks snapshot names; audits rule changes                                                  |
| Policy engine     | `crates/core/src/policy/`                                     | AP-01, AP-04, SS-06 (Prod raises the tier), SS-07, SS-08, SS-10, BX-06, VM-05, VM-07 (warnings add a confirm)                       | Working; every tier rule has a unit test; a MultiExec line it could not follow, replacing a file or a tunnel other computers can use is at least a confirm                     |
| Impact preview    | `crates/core/src/impact.rs`                                   | AP-02                                                                                                                               | Working: state, uptime (from `vmware.log`) and snapshot count per VM; logged-in users and dependent VMs later                                                                  |
| Snapshot reads    | `crates/core/src/snapshots.rs`                                | VM-04, VM-05                                                                                                                        | Working: tree order, 30-day flag, safety snapshot names                                                                                                                        |
| Audit export      | `crates/core/src/export.rs`                                   | AP-05                                                                                                                               | Working: CSV with hashes, secrets redacted, formula cells guarded                                                                                                              |
| Job runner        | `crates/core/src/jobs.rs`                                     | VM-03 (shutdown wait), VM-05, VM-06, AP-03 (countdown), AP-04, BX-02, BX-04, SS-08, SS-10, FD-14 (runs alone)                       | Working; sends a MultiExec line's held Enter to its terminals; carries out uploads through a terminal                                                                          |
| VMware adapter    | `crates/core/src/adapters/vmware.rs`                          | VM-01, VM-02, VM-03, VM-04, AP-02                                                                                                   | Library, folder scan, `.vmx` and `.vmsd` reading, `vmware.log` start time, `vmrun` list, power and snapshots; vmrest later                                                     |
| Remote adapter    | `crates/core/src/adapters/remote.rs`, `remote/`               | SS-03, SS-05, SS-07, SS-08, BX-02, BX-07, MO-02                                                                                     | Working: jump host chains, terminal shells, SFTP and port forwards (local, remote, SOCKS) on a terminal's connection, bulk exec with sudo, kept connections for guest metrics  |
| Host counters     | `crates/core/src/adapters/host_counters.rs`                   | MO-01, MO-04, VM-07                                                                                                                 | Working: host RAM, CPUs, CPU times, free disk, and each `vmware-vmx.exe` process's CPU, working set and I/O                                                                    |
| Updater           | `crates/core/src/adapters/updater.rs`, `github.rs`            | FD-14                                                                                                                               | Works: GitHub Releases of the private repo with the token from the vault; install is a Medium-tier job that runs alone                                                         |
| Inventory         | `crates/core/src/inventory.rs`                                | VM-01, VM-02, SS-06 (VM labels)                                                                                                     | Every VM from the library, chosen folders and `vmrun list`; filters; audited environment labels                                                                                |
| Capacity check    | `crates/core/src/capacity.rs`                                 | VM-07, MO-04                                                                                                                        | Working: host RAM vs assigned RAM, free disk on VM drives; the dashboard's capacity panel                                                                                      |
| Metrics collector | `crates/core/src/metrics/`                                    | MO-01, MO-02, MO-03, MO-04                                                                                                          | Working: host-side and SSH guest sources every 5 s, 30 minutes of history in memory, collector cost                                                                            |
| Vault             | `crates/core/src/vault/`                                      | SS-04, AP-06                                                                                                                        | Working: AES-256-GCM per item; DPAPI and Argon2id key wrapping; 15-minute idle lock; values never leave it except to adapters                                                  |
| Session library   | `crates/core/src/sessions.rs`, `forwards.rs`                  | SS-01, SS-06, SS-07, QL-04                                                                                                          | Working: folders, tags, colours, search, vault credentials, jump host chains, saved port forwards, audited changes, the tree                                                   |
| Export and import | `crates/core/src/transfer/`                                   | FD-07                                                                                                                               | Working: one encrypted file per export; preview with per-item conflict choices; audited with counts and the file path                                                          |
| SSH key manager   | `crates/core/src/ssh_keys.rs`                                 | SS-09                                                                                                                               | Working: Ed25519 or RSA 4096 keys in the vault; public keys; attach to sessions; push to authorized_keys as a bus command                                                      |
| Terminal          | `crates/core/src/terminal/`                                   | SS-03, SS-07, SS-08, SS-10, SS-11, QL-02, QL-03, QL-06, QL-07                                                                       | Working: supervised panes through jump hosts, tunnels on the bus, quick connect, host name and IP, output saved or logged, vault passwords typed at prompts, MultiExec         |
| MultiExec         | `crates/core/src/terminal/multiexec.rs`                       | SS-10                                                                                                                               | Working: keys to the picked terminals, line buffer, Enter held and rated on the bus, password prompts and full-screen programs passed through, never logged                    |
| File transfer     | `crates/core/src/terminal/files.rs`, `folder.rs`              | SS-08                                                                                                                               | Working: the shell's folder (OSC 7, a hidden prompt hook for bash and zsh), listing, downloads (audited), uploads on the bus, transfers with cancel and retry                  |
| Compare output    | `crates/core/src/bulk.rs`                                     | BX-01, BX-03, BX-05                                                                                                                 | Working: hosts from picked tabs and tree sessions, results grouped by output, diff, CSV, JSON and HTML export                                                                  |
| Command panel     | `crates/core/src/snippets/`                                   | BX-08                                                                                                                               | Working: favourite commands in folders (audited), a large built-in Linux library (Troubleshoot runbooks and 25 area groups), variables, marks from the policy engine           |
| Reachability      | `crates/core/src/reachability.rs`                             | QL-04 (MO-08 lite), SS-07                                                                                                           | Working: TCP checks of the sessions the tree shows, once per host and port, a few at a time; the first jump host's for sessions behind one                                     |
| VM links          | `crates/core/src/vm_links.rs`                                 | QL-01, BX-01                                                                                                                        | Working: sessions linked to VMs by guest IP (or a name resolving to it) or by hand; manual links kept                                                                          |
| Network adapter   | `crates/core/src/adapters/network.rs`                         | QL-01, QL-03, QL-04                                                                                                                 | Working: DNS lookups (forward and reverse, with a time limit) and the TCP probe                                                                                                |
| Store             | `crates/core/src/store/`, `crates/core/migrations/`           | AP-05, VM-01, VM-02, SS-01, SS-04, NFR Reliability                                                                                  | Working: hash-chained audit log, job journal, inventory, sessions, vault ciphertext, tags, saved filters                                                                       |
| Fake adapters     | `crates/core/src/fakes.rs`                                    | Development safety                                                                                                                  | One fake per outside system; the test SSH server has SFTP on a temp folder and forwards (direct-tcpip, tcpip-forward) with internal names                                      |
| Presentation mode | `crates/core/src/presentation.rs`, `src/lib/presentation*.ts` | FD-03                                                                                                                               | Working: masking by field and pattern in the DOM and in terminal output (same width), stand-ins in memory, saved and audited, a read-only lock enforced by the policy engine   |
| Tauri shell       | `src-tauri/src/`                                              | All IPC                                                                                                                             | Working                                                                                                                                                                        |
| UI                | `src/`                                                        | FD-01, FD-03, FD-07, VM-01 to VM-06, AP-01 to AP-06, SS-01 to SS-06, SS-08 to SS-11, BX-01 to BX-08, MO-01 to MO-04, QL-01 to QL-08 | All pages, the approval dialog with countdown, MultiExec, Compare output and Files here in the Terminal page, the dashboard with live uPlot charts, the Ctrl+K command palette |
