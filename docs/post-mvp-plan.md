# Post-MVP plan (0.2.1 and 0.3.0)

Agreed with the owner on 19 Oct 2026, after field feedback on 0.2.0. It moves several v2/v3 items from
`docs/PRD.md` into scope and changes how bulk execution works. Requirement IDs are the PRD's where one exists; new
items get `QL-xx` (quality of life). Commit messages start with these IDs.

## Decisions

| Question | Decision |
| --- | --- |
| Repository visibility | **Private** while the app is field-tested. Keep following the public-repository rules in CLAUDE.md anyway: it may go public later, and history is forever. |
| Auto-update with a private repo | The app updates from the private repo's GitHub Releases using a **read-only fine-grained token** the owner enters in Settings, stored in the vault on each machine (P1). Copies on 0.2.0 or older cannot update and need one manual install of 0.2.1. |
| Bulk execution | The Bulk run page is replaced by **MultiExec in the Terminal page** (MobaXterm-style: type once into several open terminals). The grouped **Compare output** view (BX-03) stays, inside the Terminal page, for both MultiExec and one-shot runs. Safety stays: every MultiExec line is checked by the policy engine on Enter (P6). |
| Scope | All items below are in scope for 0.3.0, including PRD v2/v3 items SS-07, SS-08, SS-09, SS-10, SS-11, BX-08, MO-08 (reachability only), FD-03 and FD-07. Other v2/v3 items stay out unless asked. |

## Packages and order

Each package is one session and one pull request. P1 to P4 can run at the same time; P5 to P9 rework the Terminal
page, so they run one after another, in this order.

| # | Package | IDs | After |
| --- | --- | --- | --- |
| P1 | Private updates and CI minutes | FD-14 | now |
| P2 | Host usage per VM, auto-link VMs to sessions | MO-01, QL-01 | now |
| P3 | Session export/import and SSH key manager | FD-07, SS-09 | now |
| P4 | Terminal workspace | QL-02 to QL-05, SS-11 | now |
| P5 | Commands and helpers | BX-08, QL-06, QL-07 | P4 |
| P6 | MultiExec and Compare | SS-10, BX-03, QL-08 | P5 |
| P7 | File transfer in the terminal | SS-08 | P6 |
| P8 | Jump hosts and tunnels | SS-07 | P7 |
| P9 | Presentation mode | FD-03 | P8 |

Release 0.2.1 as soon as P1 is merged (one manual install per machine), and 0.3.0 when all packages are merged.

## P1: private updates and CI minutes (FD-14)

- The updater reads releases from the private repo with a token from the vault. Settings gets "GitHub update token"
  (write-only, like other secrets) with a "Test" button. Without a token, update checks say so instead of failing
  quietly.
- Find the latest release through the GitHub API with the token, then let `tauri-plugin-updater` fetch `latest.json`
  and the installer from the API asset URLs with `Authorization` and `Accept: application/octet-stream` headers.
  Signatures are still verified with the public key. The token never reaches logs, errors, the UI state or the
  audit log.
- Document how the owner creates the token: fine-grained, this repository only, Contents read-only, with an expiry,
  and how to replace it.
- CI minutes: skip CI for documentation-only changes (`paths-ignore` for `**/*.md`, `docs/**`) and keep cancelling
  superseded runs. Document the private-repo minute budget (Windows minutes count double).
- Update CLAUDE.md (Releases and auto-update) and README.

## P2: host usage per VM, auto-link (MO-01, QL-01)

- Dashboard and VM list: "% of host CPU" and "% of host RAM" columns for each running VM, from the samples the
  metrics collector already takes (no extra polling). Sortable, with the existing thresholds.
- QL-01: link VMs to saved sessions automatically when a session's host or resolved IP matches a VM's guest IP
  (VMware Tools). Show the link on both sides; the user can confirm, change or remove it. Linking is local data,
  audited like settings.

## P3: session export/import and SSH key manager (FD-07, SS-09)

- FD-07: export sessions, folders, tags, labels, known hosts and optionally vault secrets to one encrypted file
  (Argon2id from a passphrase the user chooses, AES-256-GCM), and import it on another laptop with a preview and
  conflict handling. This is how sessions move between the owner's laptops. Never write an export into the repo
  folder by default.
- SS-09: generate SSH keys (ed25519 default, RSA optional) into the vault, show and copy the public key, and push a
  public key to many hosts (append to `~/.ssh/authorized_keys` without duplicates). The push is a remote command
  through the command bus with the usual tiers.

## P4: terminal workspace (QL-02 to QL-05, SS-11)

- QL-02 quick connect: "New terminal" opens a form (host, port, user, auth method, optional vault secret or a typed
  password) with a **Save as session** checkbox (folder, label). Unsaved connections keep nothing after the tab
  closes. Keep a quick-connect history and a "Recent sessions" list.
- QL-03 hostname and IP: on connect, record the IP actually reached and the server's own hostname (one `hostname`
  exec on the same connection). Before connecting, resolve whichever one is missing by DNS. Show both in the tab
  title and in session details, for example `web01 · 192.0.2.10`, and keep the last seen values on the session.
- QL-04 session tree in the Terminal page: a collapsible left panel with the same folders, groups, tags and labels
  as the Sessions page; double-click opens a tab; tabs take the session's colour and label. Reachability dots
  (MO-08 lite): a cheap TCP check of each session's port in the background, at a modest interval, off by default
  for large lists.
- QL-05 terminal comfort: search in the terminal (Ctrl+Shift+F), Ctrl+Shift+C / Ctrl+Shift+V, right-click paste,
  font size, scrollback length and copy-on-select settings.
- SS-11 output: copy the whole scrollback, save it to a `.txt` file, print it, and an optional "log this session to
  a file" toggle with timestamps. **Bulk:** select several tabs and copy, save (one file per terminal or one
  combined file with a header per terminal) or print them together. Audit that output was saved (sessions, file
  path), never the output itself.

## P5: commands and helpers (BX-08, QL-06, QL-07)

- BX-08 command panel in the Terminal page with two sections:
  - **Favourites**: the user's saved commands, with folders and optional `{{variables}}` asked at run time.
  - **Library**: built-in common commands, grouped: system info, disk and filesystems, memory, CPU and processes,
    network, services (systemd), logs (journalctl), packages (apt, dnf/yum), users and groups, firewall, Docker,
    Kubernetes. Each entry has a short description. Entries a dangerous-command rule matches are marked.
  - Click pastes into the current terminal; Shift+click also presses Enter; with MultiExec on (P6), the line goes
    to every selected terminal through MultiExec's checks. Any library entry can be copied into Favourites.
- QL-06 "Type vault password": sends a chosen vault password into the current terminal (for sudo or su prompts)
  without the clipboard and without showing it. Audited as used (secret label, session), never the value.
- QL-07 notifications: when a command in a background tab finishes after a long run (shell prompt returns, or the
  tab goes quiet after output), show a Windows notification. Configurable threshold; off per tab.

## P6: MultiExec and Compare (SS-10, BX-03, QL-08)

- SS-10 MultiExec in the Terminal page: a toggle, then pick which open tabs receive input (all, by folder, by label,
  or by hand). Keystrokes go to every selected terminal at once; each terminal still shows its own output.
- Safety: in MultiExec, the line is held when Enter is pressed and classified by the policy engine (read-only,
  other, dangerous; Prod raises the tier). Low sends at once; anything higher shows the approval dialog first.
  Every broadcast line is audited (the command and the hosts, never the output). Typed passwords at prompts are not
  classified or logged.
- BX-03 Compare output in the Terminal page: run one command on the selected terminals' hosts as a one-shot job
  (the existing bulk engine: exec channels, grouping, diff, retry failed, export, sudo from the vault) and show the
  grouped view in a panel. This replaces the Bulk run page, which is removed; its target picking moves into the tab
  and tree selection.
- QL-08: every disabled action button says why it is disabled (for example "No saved sessions on this computer").
- Update the PRD-derived docs (CLAUDE.md, README) to describe MultiExec and Compare instead of the Bulk run page.

## P7: file transfer in the terminal (SS-08)

- Transfers use SFTP over the terminal's existing SSH connection (a new channel): no second login or window.
- Current folder: shell integration through OSC 7. For bash and zsh, Remotely adds an invisible prompt hook on
  connect that reports the folder; other shells fall back to the home folder with a folder picker.
- Upload: drag files onto the terminal, or use the upload button. They go to the current folder, with a transfers
  panel (file, size, progress, speed, time left, cancel, retry). Ask before overwriting.
- Download: a "Files here" drawer that follows the terminal's current folder (list, sort, multi-select, download to
  a chosen folder or Downloads, "Open folder" afterwards); right-click a file name in the terminal output to
  download it. ZMODEM (`sz`/`rz`) is optional, only if `lrzsz` is present on the host.
- Uploads are changes: they go through the command bus (Low; Prod raises the tier; overwriting asks), audited with
  file names, sizes, destination and SHA-256, never the content. SFTP writes as the logged-in user; protected
  folders fail with a clear message.

## P8: jump hosts and tunnels (SS-07)

- Jump host chains through russh direct-tcpip channels, using the session's jump host (and the jump host's own),
  with host key checks at every hop.
- Saved port forwards per session (local, remote, SOCKS) that start with the session, shown with their state.
  Opening a tunnel to a Prod host is Medium (PRD tier table).

## P9: presentation mode (FD-03)

- A toggle (and palette command) that masks IP addresses, hostnames, usernames and secrets everywhere in the UI,
  including tab titles, the session tree, tables, dialogs and, where it can be done reliably, terminal output.
  Optional read-only lock that blocks actions while presenting.
