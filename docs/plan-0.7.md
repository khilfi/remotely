# Plan for 0.7.0

Agreed with the owner on 1 Nov 2026, after 0.6.0. It details the feature groups `docs/plan-0.6.md` picked for 0.7.0
(toolbox and health checks, Windows and network gear, notes and everyday comfort, handover and reports) and adds four
PRD items the owner chose to bring in: the subnet calculator, VNC sessions, bulk runs on Windows hosts, and a quick
TFTP and HTTP file server. Every page and dialog follows 0.6.0's UI rules (CLAUDE.md, Conventions, "UI rules").

Requirement IDs are the PRD's where one exists (FD-04, FD-05, FD-06, FD-08, FD-09, MO-05, MO-08, SS-12, BX-12); new
ones continue the PRD's numbering (`BX-13`), and quality-of-life items continue `QL-xx` (`QL-26` to `QL-28`). Commit
messages start with them.

## Decisions

| Question | Decision |
| --- | --- |
| Where network tools and checks run | **From this PC.** Ping and trace route use Windows' ICMP API (no administrator rights). Port, certificate, HTTP and DNS reach a session behind a jump host through its SS-07 chain (direct-tcpip on a kept connection, `login_guard`'s caps); ping and trace route can't, and say so. |
| Toolbox reads | Ping, trace route, DNS lookup, port check, the certificate viewer and the subnet calculator **only read**: no tier, not audited, allowed by the read-only lock, like QL-04's checks. A port check takes at most 100 ports a run, so it isn't a scanner (FD-10 subnet discovery stays out). |
| RDP | **mstsc asks for the password.** Remotely writes a `.rdp` file (host, user, display, redirections) only this Windows user can read, starts `mstsc.exe` on it and deletes it; Windows asks for the password and may remember it itself. No vault password reaches mstsc or Windows' credential store. |
| VNC | **The owner's own viewer**, found like the other tools (Settings' tool paths, then default folders): TigerVNC, TightVNC, RealVNC or UltraVNC. The viewer asks for the password. No viewer is bundled. |
| Jump hosts for RDP and VNC | Through an SS-07 local forward on the session's chain (`Command::OpenTunnel`, its own tier), opened first and closed when the window closes. |
| Telnet and serial | **Terminal panes** like SSH's (xterm.js, logs and saved output scrubbed of secrets, reconnect for Telnet). A vault password typed at a Telnet prompt (QL-06) asks for the vault password again on each connection, since Telnet sends it in clear text. Neither joins Type in all tabs or Compare hosts in 0.7.0: their rules are for shells, not network gear. |
| WinRM | **Remotely's own client**, in the core behind a trait: HTTPS (5986), or HTTP (5985) with the message encrypted by the Windows sign-in (Kerberos through Windows' SSPI for domain hosts, NTLM for workgroup hosts). Basic only over HTTPS; never a password in clear; nothing on this PC is changed (no TrustedHosts). An HTTPS certificate Windows doesn't trust can be trusted per host by its fingerprint, like an SSH host key (SS-05). |
| PowerShell console | A WinRM shell running `powershell.exe -NoLogo -NoProfile -Command -` with lines sent as typed: a prompt Remotely draws, output streamed, no PSReadLine or tab completion. A reconnect starts a new shell (its state is gone, and the pane says so). |
| Bulk runs on Windows (BX-13) | Compare hosts and Type in all tabs work on WinRM hosts, rated by **PowerShell rules** in the policy engine (read-only cmdlets Low; `Stop-Computer`, `Remove-Item -Recurse`, `Format-Volume`, `Invoke-Expression`... High from an editable list; anything else Medium), each rule with a unit test. A selection with SSH and WinRM hosts rates each host by its own rules. |
| Notes | **Markdown** (CommonMark with tables and task lists), rendered by the core with `pulldown-cmark`: raw HTML shown as text, only `http(s)` links (opened after a confirm that shows the address) and the app's own links (a vault item by name, never its secret; a command or runbook; a session or VM). A code block in a note can be sent to the open terminal through the multi-line paste confirm (QL-05); nothing runs by itself. |
| Trash | Deleting a session, favourite command, size, image, launch template or stack moves it, with what hangs off it (port forwards, VM links, container marks, group places, its note), into a **trash table as a snapshot**; the live tables keep their hard deletes, so no read changes. Restore puts it back (a taken name gets " (restored)"; a jump host, folder or image that is gone is left out with a note). Kept 30 days, then purged daily, like BX-02's journal. Per workspace; not in FD-07 exports. A session's vault secrets stay in the vault, as today. |
| Handover pack | **HTML in a zip**: one self-contained `index.html` (no scripts, no outside requests; prints to PDF from any browser) with the inventory, the topology diagram, what was done and the chosen notes, beside `inventory.xlsx` and CSVs. |
| Quick file server | TFTP and HTTP **from one chosen file or folder**, bound to **one chosen address** of this PC (never all of them by default), for a time limit (30 minutes by default) or until stopped or Remotely closes. Serving only, unless "Accept uploads" is on: then into one empty folder, with a size cap, each file marked with the Mark of the Web, never into a Git working tree. Every request is listed in the job. Windows Firewall may ask the first time (its own dialog; Remotely changes no firewall rule). |
| New dependencies | Windows APIs first (ICMP, DNS, certificate chains, SSPI, serial ports: features of the `windows` crate). New crates: `pulldown-cmark` (notes and the handover pack), `rust_xlsxwriter` (FD-05), `zip` (FD-04, FD-08), and `rcgen` for tests' run-time certificates. Each passes `cargo deny`. |
| Releases | **One release, 0.7.0**, when F1 to F9 are merged. |

## Approval tiers

The PRD's tier tables gain these rows (each package adds its own to `docs/PRD.md`). A Prod-labelled target moves an
action up one tier, and protected targets are skipped, as before.

| Action | Tier |
| --- | --- |
| Ping, trace route, DNS lookup, port check, view a certificate, the subnet calculator | Not a command: no tier, not audited (reads) |
| Wake-on-LAN | Low |
| Run the quick file server (serving only) | Medium |
| Run the quick file server accepting uploads | High |
| Health check runs, and the service status they read over SSH or WinRM | Reads: not audited; results kept in the checks' history |
| Add, edit, pause or delete a health check | No tier; audited, refused by the read-only lock |
| Open an RDP, VNC, Telnet, serial or PowerShell console (RDP and VNC through a jump host also open a tunnel, at SS-07's tier) | No tier; audited like opening a terminal |
| A PowerShell line in Type in all tabs, or a Compare hosts run on WinRM hosts | By the PowerShell rules: read-only Low, others Medium, dangerous High |
| Collect a support bundle (its commands rated as in Compare hosts; read-only presets are Low) | Low; Medium on Prod |
| Write or delete a note; move to the trash, restore, empty the trash; bulk edit sessions | No tier; audited (a note's entry without its text), refused by the read-only lock; a bulk edit that sends a vault password somewhere new asks for it again (AP-06) |
| Favourites and recents | Not audited, not locked (like the notification centre) |
| Export the inventory (Excel), an Ansible inventory or a handover pack | No tier; audited (`data_exported`), never into a Git working tree |

## Packages and order

Each package is one session and one pull request. F1, F3, F5 and F7 start now. F2 and F9 start after F1, F4 after F3,
F6 after F2 and F5, and F8 after F4.

| # | Package | IDs | After | Migration |
| --- | --- | --- | --- | --- |
| F1 | Toolbox: ping, trace route, DNS, port check, certificates, subnet calculator, Wake-on-LAN | FD-09 | now | none |
| F2 | Health checks with history and alerts | MO-08 | F1 | 0030 |
| F3 | Remote desktop and consoles: RDP, VNC, Telnet, serial | SS-12 | now | 0031 |
| F4 | WinRM: PowerShell console, Windows guest metrics and facts | SS-12, MO-05, MO-13 | F3 | 0032 if needed |
| F5 | Notes, favourites and recents, trash, bulk edit | FD-06, QL-26, QL-27, QL-28 | now | 0033 |
| F6 | Exports: inventory to Excel, Ansible inventory, handover pack | FD-05, BX-12, FD-08 | F2, F5 | none |
| F7 | Support bundle from many hosts | FD-04 | now | none |
| F8 | Windows in bulk: PowerShell rules, Compare hosts and Type in all tabs on WinRM hosts, Windows support bundles | BX-13 | F4 | none |
| F9 | Quick file server: TFTP and HTTP | FD-09 | F1 | none |

Migration numbers are set here so packages running at the same time don't take the same one; a package that finds it
needs none leaves its number unused (the folder already skips 0026). Shared files: F3 and F5 both touch the session
editor and `sessions.rs`, and F1 and F9 the Toolbox page; the later one merges main first, as in 0.5.0.

## F1: toolbox (FD-09)

- A **Toolbox** page in the sidebar's Remote group (Sessions, Terminal, Containers, Toolbox; no digit shortcut is free,
  so it opens from the palette and from rows), with a tab per tool. A session's or VM's row menu gains Ping, Trace route,
  Check ports, View certificate and Wake up, which open the tool with the target filled in. The last 20 inputs per
  tool are kept in the window's local storage.
- **Ping**: `IcmpSendEcho2` and `Icmp6SendEcho2` (IPv4 and IPv6), count, interval (at least 1 s), size and timeout;
  min, average, max and loss. **Trace route**: ICMP with rising TTL, 30 hops at most, 3 probes each, names looked up
  only when asked.
- **DNS**: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV and CAA through Windows' resolver or a chosen server
  (`DnsQueryEx`), with TTLs and the server that answered.
- **Port check**: TCP connect with a timeout to up to 100 ports; an optional banner read (256 bytes, control and Cf
  characters removed).
- **Certificate**: a TLS handshake to host and port (with SNI), any chain accepted to read it, then checked against
  Windows' trust store (`CertGetCertificateChain`) and the name; subject, alternative names, issuers, validity and days
  left, key, signature algorithm, fingerprints. A `.crt`, `.cer` or `.pem` file can be opened too (`untrusted` path
  rules).
- **Subnet calculator**: IPv4 and IPv6 CIDR to network, mask, wildcard, broadcast, first and last host and count, and a
  split into smaller subnets. Pure TypeScript.
- **Wake-on-LAN**: a magic packet (UDP 9) to the subnet broadcast of a chosen adapter, or a typed directed broadcast,
  for a MAC from a VM's hardware (MO-13), a session's facts or typed. `Command::WakeOnLan` on the bus, Low, audited.
- The core's `NetworkTools` trait (ICMP, DNS, TCP, TLS), with a fake for tests.

## F2: health checks (MO-08)

- A check is a kind and a target (a session, a VM's guest IP or an address), with an interval (30 s to 1 h; 1 minute
  by default), a timeout and failures before it counts as down (2). Kinds: **ping**, **TCP port**, **HTTP(S)**
  (expected status range, optional text in the body, redirects followed or not, certificate errors allowed per check,
  never the system proxy for addresses inside the customer's network), **certificate** (days left), **DNS** (resolves,
  optionally to a given address) and **service** (a systemd unit over SSH with `systemctl is-active`, on kept
  connections through `login_guard`; F4 adds Windows services).
- Checks run for the shown workspace only, like MO-07's alerts (rule 8). Each result (time, up or down, time taken, a
  one-line detail) is kept in a history table with `metrics.historyRetention`'s retention and pruned with it.
- MO-07 gains three metrics: a check **down** (a state), **slow** (a time threshold) and **certificate expiring** (days
  left); built-in rules for down (on) and under 14 days (on). Alerts reach the notification centre (QL-25) and Windows
  notifications as today.
- A **Checks** tab on the Dashboard (status, last result, a sparkline of the time taken, uptime over the range), a
  Checks widget for MO-16's grid, the failing count in the status bar (QL-22), "Add a check" on session and VM rows, and
  a check's history in a sheet. Definitions travel in FD-07 exports; edits are audited and refused by the read-only
  lock.

## F3: remote desktop and consoles (SS-12)

- Sessions get a **kind** (the `protocol` column, which already allows `rdp`, `vnc`, `telnet`, `serial` and `winrm`),
  chosen first in the session editor, with each kind's own fields under Advanced (migration 0031 adds them): RDP's
  screen (full screen, size, all monitors), clipboard (on), drives, printers and audio (off), admin session; VNC's view
  only; Telnet's port and line ending; serial's port, speed, data bits, parity, stop bits, flow control, line ending and
  local echo. Folder defaults (QL-16), tags, environment and the tree work for every kind.
- **RDP**: the `.rdp` file and `mstsc.exe` from System32, as decided; audited `rdp_opened`. While presenting (FD-03), a
  notice says the remote desktop window isn't masked. **VNC**: the viewer from the tool paths table (UX-10), started
  with host and port; a notice that many VNC servers don't encrypt.
- **Telnet**: a transport in the core (RFC 854 with NAWS, TTYPE, ECHO and SGA), a pane with reconnect, a "clear text"
  badge on its tab. **Serial**: Windows' COM ports listed (`HARDWARE\DEVICEMAP\SERIALCOMM`), opened with the session's
  settings, Send Break in the pane's menu, one pane per port.
- QL-04's reachability checks cover RDP, VNC and Telnet ports. SS-02 imports PuTTY's and MobaXterm's Telnet, serial,
  RDP and VNC sessions as those kinds instead of leaving them out (the format guides and samples change with it); FD-07
  carries them.
- Fakes: a launcher trait records each `.rdp` file and viewer command instead of starting it; a Telnet server on
  127.0.0.1; a serial port trait with an in-memory port. `dev_ssh_server` also serves Telnet, for trying by hand.

## F4: WinRM (SS-12, MO-05, MO-13)

- A **WinRM** session kind: HTTPS or HTTP, port, sign-in (the session's user with its vault password, or "my Windows
  sign-in" for Kerberos), and the HTTPS certificate rule. The client in `adapters/winrm/`: WS-Management shells
  (create, command, send, receive, signal, delete), SSPI for Kerberos, NTLM with message sealing in Remotely's own
  code, the vault password handed over like SSH's (`SecretBindings`).
- The **PowerShell console** pane, as decided; session logs and saved output scrubbed like SSH's.
- **MO-05**: one PowerShell script of CIM reads (processor, memory, fixed volumes, network interfaces, uptime) on each
  dashboard round's interval (P8), on a kept connection with `login_guard`'s parks and caps; Windows guests on the grid,
  in the history (MO-06) and in alerts (MO-07) like Linux guests.
- **MO-13 for Windows**: the System tab from CIM (edition, version and build, CPU, RAM, disks, adapters with MACs and
  addresses, domain, last boot, listening ports), stored like a Linux host's facts, for F6's inventory. F2's service
  checks gain Windows services (`Get-Service`).
- Fakes: a WinRM server on 127.0.0.1 (HTTPS with a run-time certificate and Basic; HTTP with NTLM sealing, checked
  against MS-NLMP's published test values); Kerberos can only be tried by hand. `dev_ssh_server` also serves the fake
  WinRM endpoint.

## F5: notes and everyday comfort (FD-06, QL-26, QL-27, QL-28)

- **FD-06 notes**: one markdown note per session, VM and folder, in a Notes tab or sheet, as decided; links to vault
  items, commands, runbooks, sessions and VMs; a code block's "Send to terminal". A note whose text looks like a secret
  (`export::redact_secrets` finds something) says so and suggests the vault. Notes show in QL-20 search, travel in
  FD-07, are masked while presenting (the DOM does it), and can be marked for the handover pack (F6).
- **QL-26 favourites and recents**: a star on session, VM and command rows; favourites first in the session tree, the
  VMs list's filter and Ctrl+K; the 20 recently opened sessions, VMs and pages under "Recent" in Ctrl+K and the
  Terminal page's new-tab menu. Per workspace.
- **QL-27 trash**: as decided, with a Trash view (Settings › Privacy and data) listing what, when and from where, Restore, Delete
  now and Empty trash (a destructive confirm), and an Undo in the toast after each delete.
- **QL-28 bulk edit**: the Sessions page's selection bar gains Edit: folder, port, user, login, jump host, environment
  and tags (add or remove), with a before-and-after preview per session; one audit entry naming every session;
  `SecretBindings::confirm` once when a login would send a vault password somewhere new.

## F6: exports and handover (FD-05, BX-12, FD-08)

- **FD-05 inventory to Excel** (`rust_xlsxwriter`, strings always written as text): sheets for VMs (hypervisor, state,
  OS, vCPU, RAM, disks, addresses, MACs, folder, environment, tags), hosts (OS, kernel or build, CPU, RAM, disks and
  addresses from MO-13, listening ports and pending updates from MO-14), networks (VM-11), checks (F2), and an optional
  package list and count per host (a read-only `dpkg-query -W` or `rpm -qa` read, which MO-14 doesn't make today).
  From the stored facts, with "Read again first" for reachable hosts.
- **BX-12 Ansible inventory**: YAML or INI from BX-01's targets; groups by folder, tag, environment and workspace;
  `ansible_host`, `ansible_port`, `ansible_user`, `ProxyJump` through `ansible_ssh_common_args`, and WinRM hosts with
  `ansible_connection: winrm`, port and transport. Never a password, key or vault item; names made valid for Ansible.
- **FD-08 handover pack**, as decided: a cover (workspace, dates, prepared by), the inventory, the QL-21 topology
  diagram (SVG from the Map, embedded as an image so nothing in it runs), what was done in the chosen dates (jobs with
  their approvals, change IDs and results, grouped as Activity groups them; outputs left out unless chosen; everything
  through `export::redact_secrets`), the checks' uptime (F2) and the notes marked for it (F5). CSVs follow A10's rules.
- All three save through `save_guard` and are audited `data_exported`; one workspace each (rule 8).
- F6 merged before F4, so BX-12 takes SSH sessions only for now: F4 adds WinRM hosts in
  `reports::ansible::connection_vars`, and Windows facts in the inventory's hosts sheet.

## F7: support bundle (FD-04)

- Pick hosts (BX-01's targets) and presets: **System** (`/etc/os-release`, `uname -a`, `uptime`, `df -h`, `free -m`,
  `ip addr`, `ip route`, `ss -tulpn`, `systemctl --failed`), **Logs** (`journalctl -p err -n 500`, `dmesg`, the last
  lines of `/var/log/syslog` or `messages`), **Containers** (`docker ps -a`, `docker info`) and **Network**; plus
  custom commands and files.
- One job on the bus (`Command::SupportBundle`): commands rated as in Compare hosts (read-only presets are Low), sudo
  through BX-07, files read over SFTP, BX-02's parallelism and H9's rollout options; caps of 10 MB a file, 100 MB a
  host and 1 GB a bundle, with what was cut in the manifest.
- Every text file scrubbed of secrets (`exec_output`); a zip `remotely-bundle-<workspace>-<UTC time>.zip` with a folder
  per host and a `manifest.json` (commands, exit codes, sizes, SHA-256, what was redacted or cut), saved through
  `save_guard`. Windows hosts come in F8.

## F8: Windows in bulk (BX-13)

- The PowerShell rules, as decided: a parser of PowerShell's command and pipeline syntax enough to find each cmdlet,
  alias (`iex`, `rm`, `del`, `gwmi`...) and script block, unit tests for every rule, and the rules editable in
  Settings' Approval rules under Advanced, like the shell rules.
- Compare hosts on WinRM hosts (grouped output, diff, export, retry, rollout) and Type in all tabs on PowerShell panes,
  through the same bus paths as SSH; a mixed selection rates each host by its own rules.
- F7's support bundle on Windows: presets of PowerShell reads (`Get-ComputerInfo`, `Get-WinEvent` errors,
  `Get-Service`, `Get-HotFix`, `ipconfig /all`, `Get-NetTCPConnection -State Listen`).

## F9: quick file server (FD-09)

- A File server tab in the Toolbox, as decided: TFTP (RFC 1350 with blksize and tsize, port 69 or another) and HTTP
  (GET only, a file list for a folder) from one file or folder, bound to one address, with a time limit.
  `Command::FileServer` on the bus: Medium serving, High with uploads (TFTP WRQ or HTTP PUT into the chosen empty
  folder, capped, Mark of the Web, `save_guard`).
- The job lists every request (address, file, bytes, result); start and stop are audited; it stops when Remotely
  closes, the workspace switches or the vault locks.
- Tests bind 127.0.0.1 with port 0 and fetch with their own TFTP and HTTP clients.

## Development safety for 0.7.0

- No test sends a packet beyond 127.0.0.1: ICMP, DNS, TCP and TLS go through `NetworkTools`' fake or servers on
  127.0.0.1; Wake-on-LAN tests send to 127.0.0.1, never a broadcast; the file server binds loopback with port 0.
- Tests never start `mstsc.exe` or a VNC viewer, open a real COM port, or reach a real Windows host: the launcher and
  serial traits have fakes, and WinRM runs against the fake server. Certificates and keys are made at run time
  (`rcgen`), never committed.
- Support bundles and exports in tests read from `TestSshServer` and write to the system temp folder, never the repo.
- Hand checks use demo data only (a temp `REMOTELY_DATA_DIR`, `dev_ssh_server` with its Telnet and WinRM stand-ins),
  never the owner's hosts, as in 0.6.0. Screenshots stay out of the repo.
