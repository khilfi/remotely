# Plan for 0.4.0

Agreed with the owner on 21 Oct 2026, after field use of 0.3.1. Like `docs/post-mvp-plan.md`, it moves items into
scope and adds new ones. Requirement IDs are the PRD's where one exists; new ones continue the PRD's numbering
(`VM-18`, `MO-13` to `MO-15`), quality-of-life items continue `QL-xx`, and containers get their own prefix (`CT-xx`).
Commit messages start with these IDs.

## Decisions

| Question | Decision |
| --- | --- |
| Hypervisors | **VMware Workstation Pro and Oracle VirtualBox**, both on Windows. This changes the locked decision in CLAUDE.md (Workstation only). Other hypervisors stay out (PRD "Out of scope"). |
| macOS on Apple Silicon | **A separate track after 0.4.0**, with its own plan. It needs a Mac to test on, an Apple Developer ID for signing and notarization, VMware Fusion or VirtualBox instead of Workstation, and the Keychain instead of DPAPI. macOS Actions minutes count 10x on a private repo, so its CI has to be planned. 0.4.0 stays Windows only. |
| Containers | **Docker and Podman on SSH hosts**, through their CLIs over the session's SSH connection, and **Docker Desktop on this PC**. A new Containers page. Every change goes through the command bus with tiers like the VM ones. |
| Files here when the shell switches user | **Show both users**: the user transfers run as (the login user) and, when it differs, the shell's current user, so a permission error is explained. No sudo transfers. |
| Releases | **One release, 0.4.0**, when all packages below are merged. |

## Packages and order

Each package is one session and one pull request. Q1 to Q4 can run at the same time. Q5 and Q6 start after Q4 (they
both build on its VMs page and navigation), and Q7 after Q5 (it shows details for both hypervisors).

| # | Package | IDs | After |
| --- | --- | --- | --- |
| Q1 | Terminal fixes | QL-09, QL-10, QL-11 | now |
| Q2 | MultiExec recording and Compare | SS-10, BX-03, QL-07, QL-12 | now |
| Q3 | Library additions and manual links | BX-08, QL-13 | now |
| Q4 | VMs and snapshots in one page | QL-14 | now |
| Q5 | Oracle VirtualBox | VM-18 | Q4 |
| Q6 | Containers | CT-01, CT-02 | Q4 |
| Q7 | Host details | MO-13, MO-14, MO-15 | Q5 |

Release 0.4.0 when all seven are merged.

## Q1: terminal fixes (QL-09, QL-10, QL-11)

- QL-09 Files here:
  - After an error (for example a folder the user can't open), the drawer keeps working: Up, the breadcrumbs, Home and a typed path still go somewhere, the path box shows the folder that failed, and "Back" returns to the last folder that opened.
  - The drawer shows which user transfers run as (the SSH login user). When the shell's current user differs (after `su` or `sudo -i`), it shows that too and explains that transfers still run as the login user. The prompt hook reports the user next to the folder where it can.
- QL-10 Import templates: the import dialog offers a sample file and a short format guide for each format it reads (CSV columns and accepted values, PuTTY, MobaXterm, OpenSSH config), saved through a Rust dialog. Samples use only example.com/.test names, 192.0.2.0/24-style addresses and users like alice and bob.
- QL-11 Theme: the theme control in the top bar becomes a shadcn Switch (dark on/off). "Follow Windows" moves to Settings; using the switch turns it off.

## Q2: MultiExec recording and Compare (SS-10, BX-03, QL-07, QL-12)

- QL-12: while MultiExec is on, each line sent is recorded with each terminal's output, from Enter until the prompt returns (the QL-07 prompt detection), with escape sequences removed and secrets scrubbed as in saved output. The Compare panel shows the recorded lines and, for any line, the grouped view and diff of its output across terminals, at any time during MultiExec. Lines at password prompts and in full-screen programs are not recorded. A one-shot run in Compare (the current feature) stays.
- Recorded comparisons export like Compare runs (CSV, JSON, HTML, with groups and diff). Recording keeps the session's lines until MultiExec is turned off or the terminals close, with a cap per line and per session.
- BX-03 layout: the Compare panel's settings column and results don't overlap at any window width (they did at about 2000 px wide in 0.3.1).
- QL-07: a new choice, "Any command that finishes while I'm away" (the tab isn't visible or Remotely isn't in front), whatever its length. The existing threshold (5 to 3600 s) stays as the other choice. Lines sent by MultiExec give one notification per line, not one per terminal.

## Q3: library additions and manual links (BX-08, QL-13)

- BX-08: add scp and rsync (with --dry-run forms), NTP and chrony configuration files, timedatectl, systemd-timesyncd, iSCSI (iscsiadm discovery, login and sessions), /etc/fstab checks and safe edits, resizing a volume and its filesystem, attaching a disk (rescanning the SCSI bus for a disk added to a VM), finding folders by name, files by name, and a string inside files, plus what completes them. Each new read-only entry gets the same review and tests as in PR #25.
- QL-13: every library entry links to its official manual page (the man-pages project, or the project's own documentation for tools such as docker, kubectl, nginx and podman). Links open in the default browser through Rust, only for an allow-list of documentation sites.

## Q4: VMs and snapshots in one page (QL-14)

- The VMs page and the Snapshots page become one Virtual machines page: a VM's snapshot tree, snapshot actions and safety snapshots live in its detail panel, and the bulk snapshot actions stay on the selection. The sidebar frees a slot for Containers (Q6). Keyboard shortcuts and the command palette follow.

## Q5: Oracle VirtualBox (VM-18)

- A VirtualBox adapter (`VBoxManage`) behind the same hypervisor trait as VMware, with a fake for tests: inventory (registered VMs), power (start headless or with a window, ACPI shutdown, power off, reset, pause, resume, save state), snapshots (tree, take, restore, delete), guest IP and OS from Guest Additions properties, host usage per VM from its process, the VM-07 capacity check, QL-01 auto-linking, and the same approval tiers. The VMs page shows each VM's hypervisor.
- Find `VBoxManage.exe` like vmrun: a path in Settings, then an environment variable, then the registry, then the default folder.
- Opt-in tests against a real VirtualBox follow the Workstation rules: `REMOTELY_IT=1`, reads only, and only VMs named `it-*`.

## Q6: containers (CT-01, CT-02)

- CT-01: Docker and Podman on SSH hosts, through their CLIs over the session's SSH connection (and its jump hosts). A Containers page lists each host's containers with state, image, ports, uptime and resource use; details, logs (follow, search) and stats; images, volumes and networks. Actions: start, stop, restart, pause, remove, pull, prune. "Open a shell" opens a terminal tab inside the container (`docker exec -it` / `podman exec -it`), audited like opening a terminal.
- CT-02: Docker Desktop on this PC, through the local docker CLI or engine, with the same page and actions.
- Tiers (the PRD table's VM rules applied to containers, Prod raises one tier): start is Low; stopping, restarting or pausing one container is Medium, and 2 or more is High; removing containers or images and pruning are High; removing volumes, which deletes data, is Critical. Every change is a typed command on the bus and audited; each new policy rule gets a unit test.

## Q7: host details (MO-13, MO-14, MO-15)

- MO-13: OS and specs for each VM and each SSH host: OS name and version, kernel, CPU model and count, RAM, disks and filesystems with size and use. VMs read their configuration (VMware `.vmx`, VirtualBox `showvminfo`) and what the guest tools report; SSH hosts are read over SSH when a terminal opens, when the dashboard polls them, and on Refresh. Shown in VM and session details and the dashboard.
- MO-14: admin details on demand for an SSH host: running and failed services, listening ports, logged-in users, last boot, pending updates and top processes (read only; killing a process stays out of scope).
- MO-15: memory charts draw the allocated memory (a VM's configured RAM, a host's total) next to what is in use, and show the paging file (this PC) and swap (Linux guests and hosts) where they are known.
- Reads only, so no approval tier (architecture rule 3); collection reuses the dashboard's kept connections and never adds a login per refresh beyond them.
