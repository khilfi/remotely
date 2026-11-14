# Plan for 0.8.0

Drafted on 12 Nov 2026 from the owner's feedback after a few days with 0.7.2:

1. A cloud server's export comes as one image per disk, a system disk and a data disk, and Remotely can import the
   first but not attach the second.
2. The file panel should work like WinSCP, and double-clicking a file should open it in an editor the host has (vi,
   nano or another).
3. Remotely should install Linux unattended from templates (Ubuntu's autoinstall YAML and the other distributions'
   equivalents), many VMs at once, each with its own values; and whatever else makes that truly useful.

The owner decided on 12 Nov 2026: double-clicking a file opens it in a terminal editor on the host; files can be
browsed and changed as root, one tier higher; Windows unattended installs are part of 0.8.0; and everything ships
together as 0.8.0. Rows marked **(proposed)** stand unless the owner changes them; the delivery row waits for spikes S1
to S3.

Requirement IDs: SS-08's last part (edit a remote file on this PC with auto-upload, PRD v2) and BX-10 (bulk upload
and download with checksums, PRD v2) are brought in; new ones continue the PRD's numbering: SS-14 (the file manager),
VM-28 (install configs), VM-29 (unattended deploy), VM-30 (golden image builds), VM-31 (attach an existing disk),
VM-32 (address pools) and CV-04 (a cloud server's disks imported as one VM).

## Decisions

| Question | Proposal |
| --- | --- |
| Where files are managed | A **Files** page in the Remote group: two panes, this PC on the left and a host on the right, a tab per host. The Terminal's "Files here" drawer stays and gets "Open in Files" at the same folder. |
| Every change to a host's files | A command on the bus, like uploads today: rename, move, new folder, new file, delete, permissions and owner over SFTP; a copy within the host as `cp -a` on an exec channel, rated by the shell rules. Reads (listing, preview, find, checksums) skip approval; downloads stay audited reads. |
| Files as root | **Agreed.** "Browse as root": an SFTP server started with sudo on an exec channel (`sudo -S` with BX-07's password from the vault; the server's path found per distribution, `/usr/lib/openssh/sftp-server` or `/usr/libexec/openssh/sftp-server`). Every change made this way is one tier higher, and the pane says "as root". |
| Double-click a file | **Agreed.** It opens in a **terminal editor on the host**: a new tab at the file's folder running the session's editor setting, else the first of `nano`, `micro`, `vim`, `vi` the host has (found once with `command -v`, a read). As root it runs `sudoedit`, which edits a copy and writes it back as root. The file's menu also has "Edit on this PC" (below); a setting can make double-click do that instead. |
| Rating "Open in editor" | **(proposed)** Remotely types a fixed line (the editor and the quoted path), so it is rated by its kind: Low and audited, Medium on Prod or as root (one confirm). Rating it by the shell rules would ask every time, since an editor can run commands; the user could type the same line in their own terminal anyway. |
| Edit on this PC (SS-08) | The file is downloaded into a folder only this Windows user can read and opened in the editor chosen in Settings (Notepad, Notepad++, VS Code...), never Windows' default "open" action, which would run a `.bat`, `.ps1` or `.vbs`. Each save is uploaded after checking the host's copy hasn't changed since it was opened (if it has: overwrite, save beside it, or compare). Saves are replacements (Medium), approved once for the editing session (until the editor closes, at most 4 hours) and audited each time. The local copy is deleted when the session ends. |
| Compare and sync folders | A preview of what differs (missing, newer, larger, and with "Compare contents" the SHA-256 of each file), then one job. Deleting on the other side happens only when chosen, and is High. |
| Keep a folder up to date | **(proposed: later)** WinSCP's "keep remote directory up to date": a local folder watched and each change uploaded. It needs a standing approval for the folder (VM-14's kind) and is easy to get wrong, so it is proposed for later. |
| Protocols | **(proposed)** SFTP, plus SCP for hosts that have no SFTP subsystem. FTP, FTPS, WebDAV and S3 stay out. |
| Many hosts at once (BX-10) | Push files to every picked host (BX-01's targets), or fetch the same file from each, with SHA-256 checksums and Compare hosts' grouped results and diff. |
| Install configs (VM-28) | A new catalogue kind, a tab on the Templates page: **Ubuntu autoinstall** (YAML), **Kickstart** (RHEL, Rocky, Alma, Oracle Linux, Fedora, CentOS Stream), **Debian preseed**, **cloud-init user-data** for cloud images (VM-22 grows into it), and **Windows unattend** (`autounattend.xml`; agreed for 0.8.0), which also turns on WinRM over HTTPS so a new Windows VM is manageable at once (F4). SUSE's AutoYaST comes later. |
| Editing an install config | A form for the common parts (hostname, locale, keyboard, time zone, disk layout and LVM, swap, network, users and keys, packages, updates, proxy and mirror, commands after the install) and the raw file beside it; both edit the same file. Checks: YAML or kickstart syntax, Ubuntu's published autoinstall schema, and lint for mistakes that lock you out (no key and password logins off, a disk layout the size can't hold). |
| Values per VM | Variables in the file: `{{hostname}}`, `{{ip}}`, `{{n}}`, `{{template}}` and the user's own. The deploy dialog shows a row per VM to fill or paste from CSV, and a preview of each VM's file with secrets masked. |
| Secrets in answer files | Never in a template. A password comes from the vault and is written into the file only as a SHA-512 crypt hash, at deploy time; SSH keys are SS-09's public halves. Windows' unattend can't take a hash: **(proposed)** a random one-time password goes in, and once the install is done Remotely replaces it over WinRM with the vault's. A rendered file lives only in this user's temp folder, goes onto a seed, and is ejected and deleted after the first boot; the journal and the audit log keep only which template and its SHA-256. |
| Zero-touch delivery | **(to decide, after spikes S1 to S3)** Kickstart: a seed labelled `OEMDRV` holding `ks.cfg`, which Anaconda reads with no boot option. Ubuntu: the autoinstall on a `cidata` seed; Ubuntu asks before wiping the disk unless `autoinstall` is on the kernel command line, so Remotely makes a per-deploy copy of the ISO with that word added to its boot menu (`/boot/grub/grub.cfg` changed within its own sectors; the original ISO untouched), or on VirtualBox runs its own `unattended install` with the rendered file as the template. Debian: the same boot-menu change pointing at the preseed. Windows: `autounattend.xml` on the seed, and a way past the "press any key to boot from CD" prompt. |
| Watching an install | One job step per VM with its stages: installer booted, installing, rebooted, first sign-in over SSH (or WinRM), done. The installer's log comes to Remotely through the VM's serial port (Workstation: a serial port to a file or named pipe; VirtualBox: `uartmode file`) where the installer writes to it. 60 minutes by default before it counts as failed; VirtualBox takes a screenshot when it fails. |
| After an install | Seeds ejected and deleted, a "clean install" snapshot, the SSH session saved with the key (QL-01's link to the VM), and optionally commands from the command panel (rated like a Compare hosts run on the new VMs), health checks (MO-08) and a stack (VM-08). |
| Addresses (VM-32) | DHCP, or a static address from a pool per network (range, gateway, DNS servers). An address is handed out only when nothing answers on it (the toolbox's ping) and stays the VM's until the VM is deleted. |
| Golden images (VM-30) | "Build an image": an install from a config, then the VM made generic (`cloud-init clean`, a new machine id and SSH host keys on next boot; Windows' `sysprep` was deferred to a later release, see G7), shut down, snapshotted and registered as a VM-20 golden image with a version. A schedule (VM-14) can rebuild it, say monthly, so launch templates deploy patched systems; the old version stays until no linked clone needs it. |
| A cloud server's disks (CV-04, VM-31) | Import several disks as one VM: the system disk boots and the data disks are attached in order; picking one file of a pair named like `...System_Disk...` and `...Data_Disk...` offers the other. "Attach an existing disk" on a VM's Settings tab, copied into the VM's folder by default and converted when it is another format; never a disk another known VM uses. For a cloud export's first boot: a NoCloud seed with a user and an SSH key from the vault, so you can sign in without the cloud's root password, and DHCP on whatever the network card is called. SATA by default for disks built for KVM, whose boot image often lacks VMware's SCSI drivers. |
| New dependencies | A YAML parser (a maintained crate, chosen in G5, passing `cargo deny`) and `sha-crypt` (RustCrypto) for the password hashes. The ISO copy uses the ISO 9660 code Remotely already has for seeds. |
| Releases | **Agreed.** One 0.8.0 when every package is merged. |

## Approval tiers

The PRD's tier tables gain these rows. A Prod-labelled target moves an action up one tier, and protected targets are
skipped, as before.

| Action | Tier |
| --- | --- |
| List, preview, find, checksum and download files | Reads; downloads stay audited |
| Upload a new file, make a folder or an empty file, rename or move without replacing anything | Low (as an upload today) |
| Replace a file, change its permissions or owner, copy within the host | Medium (as a replacing upload today) |
| Delete a file or an empty folder | Medium |
| Delete a folder with what is in it | High |
| Any of these as root (sudo) | One tier higher |
| Open a file in a terminal editor | Low and audited; Medium on Prod or as root |
| Edit on this PC | Each save a replacement (Medium), approved once for the editing session |
| Sync folders | Its biggest change: uploads Low, replacements Medium, deletes High |
| Push files to many hosts (BX-10) | Medium; High from the bulk threshold (5 hosts) |
| Add, edit or delete an install config or an address pool | No tier; audited, refused by the read-only lock (as the catalogue) |
| Deploy with an install config | As a VM deploy: Medium, High from 5 VMs or for Prod |
| Build a golden image | Medium; a scheduled rebuild runs under a standing approval (VM-27) |
| Attach an existing disk | Medium (VM-23's disk change) |
| Import a cloud server's disks | As an import (CV-01) |

## Packages and order

Each package is one session and one pull request. The spikes are hand checks with the owner on this PC, using the
owner's own ISOs; nothing of them is merged but the facts they find, which go in CLAUDE.md.

| # | Package | IDs | After | Migration |
| --- | --- | --- | --- | --- |
| G1 | A cloud server's disks: attach an existing disk, several disks as one import, first-boot prep | CV-04, VM-31 | now | none |
| G2 | File operations on the bus, root browsing, a better transfer queue | SS-14 | now | none |
| G3 | The Files page: two panes, drag and drop, bookmarks, find, compare and sync, many hosts at once | SS-14, BX-10 | G2 | 0034 |
| G4 | Editing: double-click to a terminal editor, sudoedit, edit on this PC with auto-upload | SS-08, SS-14 | G2 | none |
| S1 to S3 | Spikes: Ubuntu's boot-menu change, Debian's preseed, Windows' unattend boot | VM-29 | now | none |
| G5 | Install configs: the catalogue kind, editor, checks, variables, secrets, a starter library, FD-07 | VM-28 | now | 0035 |
| G6 | Unattended deploy: delivery per system and hypervisor, the install watcher, after-install steps, address pools | VM-29, VM-32 | G5, S1 to S3 | 0036 |
| G7 | Golden image builds: build, make generic, version, scheduled rebuild | VM-30 | G6 | 0037 |

G1, G2, G5 and the spikes can start at once. G3 and G4 both touch the file panel, so the later one merges main first.

## G1: a cloud server's disks (CV-04, VM-31)

- VM-31 "Attach an existing disk" on a VM's Settings tab (VM off, VM-23's checks and backup): a VMDK as it is, or
  another format converted (CV-01's tools); copied into the VM's folder unless "Use it where it is" is chosen; refused
  for a disk another known VM uses or one inside another VM's folder.
- CV-04 the Import dialog takes several disk images: the first boots, the rest attach in order, each converted as
  needed; a `System_Disk` / `Data_Disk` pair in one folder is offered together.
- First-boot prep for a cloud export (an option, on by default for disks that hold cloud-init): a NoCloud seed with
  the hostname, a user with sudo and an SSH key from the vault, and network config that takes DHCP on any network card,
  ejected after the first boot (VM-22's seed). Without cloud-init the dialog says so.
- SATA as the default controller for an imported cloud disk, BIOS or UEFI from what the disk holds (CV-03's Inspect
  reads the partition table), and a note on what to try when it doesn't boot.

## G2: file operations (SS-14)

- `Command::FileOp` on the bus for rename, move, new folder, new file, delete (recursive or not), permissions and owner,
  copy within a host; one job per user action, a step per path; the tiers above; each change audited with its paths.
- Root browsing, as decided: `sudo -S <sftp-server>` on an exec channel, BX-07's password, login_guard's parks for a
  refused sudo; a pane in root mode says so in its header.
- The transfer queue: several transfers at once per host (4), pause and resume (SFTP offsets), retry, what to do when a
  file exists (ask, replace, replace if newer, skip, keep both), keep times and permissions, folders recursively.

## G3: the Files page (SS-14, BX-10)

- Two panes with an address bar, Back, Forward, Up and Home, hidden files, sort and filter, multiple selection, drag and
  drop between the panes and from Explorer, and a row menu per file. Bookmarks per session (migration 0034).
- Find files on the host (`find` with a name pattern under a folder, a read), a text preview for small files, and
  SHA-256 checksums.
- Compare and sync, as decided.
- BX-10: push and fetch across many hosts, with checksums and Compare hosts' grouped results.

## G4: editing (SS-08, SS-14)

- Double-click as decided; the editor found per host and kept with the session's facts; `sudoedit` for root.
- Edit on this PC, as decided: the editor setting in Settings' tools table (UX-10), the change check before each upload,
  the editing session's one approval, the local copy deleted at the end.

## S1 to S3: spikes (VM-29)

- S1 Ubuntu (24.04 and 26.04 server ISOs): a copy of the ISO with `autoinstall` added to its boot menu, installed on
  Workstation and on VirtualBox from a `cidata` seed with no keyboard input; and VirtualBox's own `unattended install`
  given a rendered file as its template.
- S2 Debian (12 and 13): the preseed through the same boot-menu change.
- S3 Windows Server (2022 or 2025): `autounattend.xml` on a seed, and getting past "press any key to boot from CD" on
  UEFI and on BIOS.
- Each records what works in CLAUDE.md, as the hypervisor facts are, and G6 builds only what was seen to work.

## G5: install configs (VM-28)

- The catalogue kind (migration 0035), per workspace, audited `catalog_changed`, in FD-07 exports without secrets.
- The editor, its checks and its lint; the variables and the per-VM preview; secrets as decided.
- A starter library, read only and copyable: Ubuntu 24.04 server (minimal; with Docker), Rocky and Alma 9 (minimal),
  Debian 12 (minimal), and Windows Server 2022 and 2025 with WinRM over HTTPS on.

## G6: unattended deploy (VM-29, VM-32)

- Delivery as S1 to S3 found, per system and hypervisor, through R2's deploy (DeploySpec gains the install config and
  each VM's values: what is approved is what runs).
- The install watcher with the serial log, the stages and the time limit; after-install steps as decided.
- Address pools (migration 0036): per network, the free-address check, the address kept with the VM.

## G7: golden image builds (VM-30)

- "Build an image" from an install config, making it generic, the snapshot and the VM-20 image with versions (migration
  0037); a schedule action "Rebuild the image" under VM-27's standing approval; an old version kept while a linked clone
  depends on it (VM-04's guard).
- **Windows golden images were deferred by the owner on 14 Nov 2026**: 0.8.0 builds Ubuntu and Debian images only. Why:
  on real VMs (Windows Server 2025 on Workstation, 2022 on VirtualBox) the build sealed (sysprep `/quit` returned 0
  with its tag, then the VM shut down), but a clone never read the `autounattend.xml` on its own seed CD after
  sysprep. It ran specialize without it and stopped at OOBE's first page, so it got no name, one-time password or WinRM
  certificate of its own, and the deploy waited to its time limit. The core refuses a Windows build, a rebuild, a
  schedule of one and a clone of one, and says why. The Windows seal and the clone delivery are kept, with their tests
  on the fakes. The later package needs:
  - a delivery a sysprepped clone reads. For example, a generic answer file given to sysprep at build time
    (`/unattend:`), whose specialize step runs the seed's work (the clone's own name, one-time password and WinRM
    certificate), or the clone's file written into its disk before its first boot. Check each by hand on both
    releases and both hypervisors.
  - a reset for a clone's first boot that hangs on VirtualBox under Hyper-V. One clone hung at the firmware logo with
    no disk writes for 17 minutes, until a reset by hand. G6's hang reset covers only an install's known points.

## Development safety for 0.8.0

- No test boots a real ISO or installs a real system: deploys run on `FakeVmware` and `FakeVirtualBox`, and seeds and
  ISO copies are read back with seed.rs's reader from small ISOs made at run time in the system temp folder.
- File operations run against `TestSshServer`'s SFTP temp folder and its toy sudo; never a real host.
- A real cloud export (the owner's disks) is never imported in a test, never copied into the repo, and its file names
  never appear in code, tests or docs. Hand checks use copies.
- Answer files in tests use reserved examples only (`example.com`, `192.0.2.0/24`, alice and bob) and passwords made at
  run time.

## Not in 0.8.0 unless the owner asks

FTP, FTPS, WebDAV and S3; WinSCP-style scripting; installs over the network (PXE); SUSE's AutoYaST; editing files on
Windows hosts over WinRM; running Ansible playbooks (a locked decision: inventory export only).
