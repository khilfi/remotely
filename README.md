# Remotely

A Windows desktop app for forward deployed engineers and IT admins: bulk control of VMware Workstation Pro and Oracle
VirtualBox VMs, a performance dashboard, a PuTTY/MobaXterm-style SSH session manager with MultiExec (type into several terminals at once)
and Compare output (one command on many hosts, answers grouped), with multi-step approvals on every high-impact action.

The requirements are in [docs/PRD.md](docs/PRD.md); project rules for contributors (and Claude Code) are in
[CLAUDE.md](CLAUDE.md). This repository is public, and git history is forever, so it follows the "Public repository
rules" in CLAUDE.md: read them before committing.

**Status:** MVP milestones 1 (VMs and power), 2 (snapshots and approvals) and 3 (vault and session library). The app
lists every Workstation VM (the library, chosen folders and running VMs) and every VM registered in VirtualBox (see
[Oracle VirtualBox](#oracle-virtualbox)) with its hypervisor, OS, CPU, RAM, IP and guest tools state; selects by click, shift-click, tag or saved filter; starts, shuts down (then forces off only after a separate
Critical approval), suspends, pauses and resets them in bulk; checks host capacity before a power-on; skips protected
VMs; and labels VMs Lab, Staging or Prod (Prod raises the approval tier). The same page shows a VM's details and its
snapshot tree with creation times (read from its `.vmsd`) in a panel beside the list, flags snapshots older than 30
days, and takes, reverts and deletes snapshots on one VM or in bulk on the selection (see
[Virtual machines and snapshots](#virtual-machines-and-snapshots)); high-risk VM actions take a named safety snapshot
first. Approval rules are editable in Settings; the approval dialog previews each VM's state, uptime and snapshot count,
and its countdown can be cancelled from the dialog or from Activity. The hash-chained audit log exports to CSV. In
every CSV Remotely writes (the audit log, Compare and MultiExec exports) a cell that a spreadsheet could run as a
formula (starting with `=`, `+`, `-` or `@`, also after spaces, or with a tab) gets a `'` in front, and cells with `,`,
`;`, quotes, tabs or line breaks are quoted.
Auto-update checks this repo's public GitHub Releases without a token (an optional read-only GitHub token can be kept in
the vault, see [GitHub update token](#github-update-token)). The vault keeps passwords, private keys and passphrases encrypted
(AES-256-GCM per item, the key wrapped by an Argon2id-derived vault password, and by DPAPI only if you turn on Windows
unlock), and locks after 15 minutes without you typing or clicking in Remotely; Critical actions ask for the vault
password again, and so does sending a vault password to a host that doesn't get it yet (see
[The vault and where its passwords go](#the-vault-and-where-its-passwords-go)). The session
library stores SSH sessions in folders with tags, colours, search and an environment label (Prod raises the approval
tier); a folder can set the user, login, jump host, label and tags for the sessions in it (see
[Folder defaults](#folder-defaults)). Imports read PuTTY, MobaXterm, OpenSSH config and CSV session lists, each with a short format guide and a sample file to start from. A key file or OpenSSH `Include` on a network share or a device path (`\\server\share`, `//server/share`, `\\?\`, `\\.\`) is never opened, since Windows would send your sign-in to that server: the preview says so and leaves it out (copy it to this PC). Included files are read up to 1 MB each, 4 MB and 256 files in all. The SSH terminal, MultiExec and Compare output work over russh. The Terminal page has a session tree with reachability dots, quick connect (saved or not), the host's own name and IP on each tab, search, saving, printing or logging the output of one terminal or several at once, a command panel with your favourite commands and a library of common ones (with `{{variables}}`, marked by the approval rules), "Type vault password" for sudo prompts, a Windows notification when a command finishes while you're away (long ones, or any), file transfer over the terminal's own connection, MultiExec and Compare output (below). The dashboard shows every running VM's CPU, RAM and disk I/O read from its `vmware-vmx.exe` process (no login), and its share of this host's CPU and RAM (also on the VM list), Linux guest metrics over SSH for watched sessions, colour thresholds, live charts (memory in use against what there is, swap, and this PC's paging files) and a host capacity panel. Host details show each VM's virtual hardware and each SSH host's OS and specs, with an admin view of services, ports, users, boots, processes and pending updates (below). Sessions link to the VMs they reach on their own when their host is a VM's guest IP address, so those VMs show guest metrics without linking by hand; a bulk run or key push reaches a VM through such a link once you confirm it. Ctrl+K opens a command palette that searches VMs, sessions, containers, templates, commands and settings, and runs actions (see [Search, map, status bar and notifications](#search-map-status-bar-and-notifications)). The top bar's Dark mode switch picks the theme; "Follow Windows" in Settings, General lets Windows decide (the default), and using the switch turns it off.
Sessions, folders (with their defaults), tags, labels, trusted host keys, VM sizes, images (by path) and launch
templates, saved MultiExec groups, and (only when ticked) vault secrets move to another laptop in one encrypted file
(Argon2id with 256 MiB from a passphrase that is hard to guess and not the vault password,
AES-256-GCM), imported with a preview that lets you skip, replace or keep
both of each conflicting item (startup commands and port forwards come along only when ticked, see
[What Remotely does by itself](#what-remotely-does-by-itself)). The SSH key manager on the Vault page generates Ed25519 or RSA 4096 keys straight into
the vault, copies their public keys, lets sessions log in with them and pushes a public key to many hosts'
`authorized_keys` through the approval flow. The Containers page (0.4.0) lists and controls Docker and Podman
containers on the sessions you mark as container hosts, and Docker Desktop's on this PC (see [Containers](#containers)).

### Virtual machines and snapshots

QL-14 (0.4.0): one page for VMs and their snapshots; the separate Snapshots page is gone.

- **Select** VMs by clicking rows (Shift+click for a range), by tag, saved filter or **By snapshots**: with snapshots
  older than 30 days, with safety snapshots, or with a snapshot whose name contains some text. Power, protection,
  tags, labels and the **Snapshots** button (take, revert or delete a snapshot by name on every selected VM that has
  it) work on the selection.
- **Click a VM's name** for its details beside the list (drag the edge to resize it; the close button or dragging it
  shut hides it). The Details tab has what the inventory knows (guest OS, CPUs, RAM, IP, Tools, share of this host,
  label, protection, tags, linked sessions); **Actions…** opens the Ctrl+K palette on the VM. The Snapshots tab has
  its tree: "You are here", creation times, descriptions, old and safety snapshots marked, and Take, Revert and Delete
  with the tier each would get (Prod raises it), then the approval dialog with its impact preview and the safety
  snapshot offer.
- **Linked clones** (0.5.0): a snapshot a linked clone was made from shows "1 linked clone" (hover for the names),
  and its Delete is off: the clone shares the golden VM's disk as it was then, and Workstation or VirtualBox would
  break it without a word. Delete the clones first; snapshots before or after theirs delete as usual. A delete on
  several VMs leaves that VM out (the approval names its clones), a schedule's retention keeps such a snapshot, and
  deleting the golden VM itself is refused the same way.
- Snapshot trees are read for the VM you open, the selection when you open its Snapshots menu and the VMs shown when
  you select by snapshots, so a long VM list stays quick.
- Ctrl+3 and "Snapshots" in the Ctrl+K palette open the snapshot view of the open or first selected VM; in the palette
  a VM's own entry has "Show its details" and "Snapshots…". The other pages keep their shortcuts.

### Oracle VirtualBox

VM-18 (0.4.0): VirtualBox 7.0 or later, on the same page as Workstation's VMs. Without VirtualBox the list just has no
VirtualBox VMs; the sidebar shows whether it was found.

- **Listing**: every VM registered in VirtualBox, with a **Hypervisor** column and filter. A VirtualBox VM is known by
  its UUID, so renaming or moving it keeps its label, protection, tags and links; the line under its name shows its
  `.vbox` file. While its Guest Additions run, the IP address (the one this PC can reach: a host-only or bridged
  adapter wins over VirtualBox's NAT address) and the OS name come from them, and sessions link to it by IP as to a
  Workstation VM.
- **Actions** are the same commands with the same tiers, Prod label and protection: Start (headless, or with a window),
  Shut down (the ACPI power button: the guest OS must handle it, no Guest Additions needed; a guest that ignores it is
  reported still running after the shutdown wait, like a Workstation VM), Power off (hard), Restart (needs the Guest
  Additions), Reset (hard), Suspend (saves the VM's state), Pause and Unpause. Snapshots: take, revert and delete, with
  the safety snapshot offer and impact preview. VirtualBox restores a snapshot only on a VM that is not running, so a
  revert powers a running VM off first; the approval dialog says so. VirtualBox can't delete a snapshot that has two or
  more children.
- **Host usage** on the dashboard and the VM list comes from each VM's `VirtualBoxVM.exe` or `VBoxHeadless.exe` process,
  and the capacity check before a power-on counts Workstation and VirtualBox VMs together.

### VM settings and lifecycle

0.5.0 (VM-11, VM-12, VM-15, VM-16, VM-23, VM-24), for Workstation and VirtualBox VMs alike. Every change goes through
the approval rules (Settings, Approvals, "VM settings and lifecycle"): a Prod label raises it one tier, protected VMs
are left alone, and the approval dialog shows what changes on each VM before and after, every file a delete removes
with its size, and a VM it would refuse (running, snapshots in the way).

- **Settings tab** in a VM's details: CPU (sockets and cores, nested virtualization), memory, firmware (BIOS or UEFI,
  Secure Boot, TPM), hardware version, guest OS type, the guest tools and their version, each disk (controller, thin
  or thick, size, size on disk, snapshot chain), CD/DVD drives, network adapters (card, network, MAC, connected),
  shared folders, USB, sound, display, serial ports and every guest address. Each section has its Edit button; one
  that is off says why.
- **While the VM is off**: CPU and memory, firmware and Secure Boot (a TPM 2.0 on VirtualBox, for Windows 11:
  Workstation's needs the VM encrypted, which Remotely doesn't do), network adapters (add, remove, card, network, MAC),
  disks (add, expand, compact, defragment on Workstation, remove with its files), shared folders, the name, the guest
  OS type and (Workstation) a hardware version upgrade. Workstation's `.vmx` is changed after a backup copy beside it,
  written whole and put back if anything fails; every other line of it stays as it was. Disks change through
  `vmware-vdiskmanager` (beside `vmrun.exe`) or VBoxManage. A VM with snapshots can't have a disk expanded, compacted
  or removed until they are deleted, and Remotely removes only disks in the VM's own folder. While Workstation has a VM
  open (its `.lck` lock is beside the files), its .vmx and disks aren't changed, because Workstation could write its own
  copy back: close the VM's tab first. The approval and the edit dialogs warn while Workstation's window is open.
- **While it runs**: attach or eject an ISO (or drop an `.iso` on the VM in the list), connect or disconnect a network
  cable, install or upgrade VMware Tools or the Guest Additions (VirtualBox's ISO goes into the DVD drive; nothing
  types guest passwords anywhere), and a screenshot of a running VirtualBox VM (hidden while presenting). On a running
  Workstation VM an ISO stays attached until it powers off.
- **Bulk resize**: More, Resize CPU and memory on the selection changes every selected VM that is off, with one
  approval. More also has Install or upgrade guest tools and Delete with their files.
- **Lifecycle**: Delete (Critical; Workstation deletes the VM's own files and keeps the folder when anything else is in
  it, VirtualBox unregisters it and deletes its files), Rename, **Add VM…** (a `.vmx` joins the list; a `.vbox` is
  registered with VirtualBox) and **Console** (the hypervisor's own window: a Workstation tab without powering the VM on,
  or VirtualBox's window on a running VM; a VirtualBox VM that is off starts with its window). The console changes
  nothing, so it has no tier, but it is in the audit log and off while presenting with the read-only lock. ISOs, shared
  folders and existing VMs are picked in Windows' own dialogs; a network share or a device path is refused.

### VM templates: sizes, images and launch templates

VM-19 to VM-21 (0.5.0): the Templates page (Ctrl+9) describes VMs the way a cloud provider does, and **Deploy**
makes VMs from it (see "Deploy" below).

- **Sizes**: CPU (sockets × cores per socket), RAM and disks (the first boots; each thin, taking only what the guest
  writes, or thick). Twelve built-ins, read only: `gp.nano` (1 vCPU, 512 MB, 8 GB), `gp.micro`, `gp.small`,
  `gp.medium` (2 vCPU, 4 GB, 40 GB, the default), `gp.large`, `gp.xlarge`, `gp.2xlarge` (8 vCPU, 32 GB, 200 GB),
  `cpu.large`, `cpu.xlarge`, `mem.large`, `mem.xlarge` and `disk.large` (with a 500 GB data disk). **Duplicate** makes
  an editable copy; your own sizes can be edited and deleted.
- **OS profiles** set what depends on the guest: firmware (BIOS, EFI, Secure Boot), disk controller, network card
  (`vmxnet3` or `e1000e` on Workstation, `virtio` or `82540EM` on VirtualBox), guest OS type and Workstation's hardware
  version (20, which Workstation 17.0 and later run). Ubuntu, Debian, the RHEL family (RHEL, Rocky, Alma), Windows
  Server, Windows 10, Windows 11 and Other Linux. Windows 11 deploys on VirtualBox only for now (its own TPM and Secure
  Boot): Workstation's virtual TPM needs each VM encrypted with its own password.
- **Images**: a golden VM and one of its snapshots, a cloud image (VMDK, OVA, `.img` or raw; qcow2 too, which deploys
  once it is converted), an ISO, or an OVA/OVF appliance. Remotely checks that a file is what its name says (its first
  bytes) and reads it once for its SHA-256, with progress and Stop. Files on network shares (`\\server\share`) are
  refused: Windows would send your sign-in there, so copy them to this PC first. Deleting an image deletes only its
  entry, never the file or VM. The Images tab links to the official cloud image pages of Ubuntu, Debian, Rocky Linux and
  AlmaLinux; Remotely downloads nothing itself.
- **Launch templates** put an image and a size together with the hypervisor, the VM folder, the network (NAT,
  host-only, bridged, a custom vmnet, or a VirtualBox NAT or internal network), an SSH key (only its public half goes to
  the VMs), a naming pattern (`{n}` the VM's number, `{template}` its name, `{date}` today: `web-{n}`), a default count,
  an environment label and tags, and what happens after each VM is deployed (save an SSH session to its IP, link it to
  the VM, take a "clean" snapshot, open the console). For a cloud image's first boot (cloud-init) a template can name a
  guest user (made with sudo and the SSH key; without one the image's own user, such as `ubuntu`, gets the key) and
  packages to install; for a golden VM it says full clone (the default: a copy that stands alone) or linked clone
  (quicker and smaller, but it needs the golden VM's snapshot, and its disk can't grow). The editor shows the names a
  deploy would give (VMs already here are skipped) and why it couldn't deploy; a template whose image, size or key was
  deleted later stays and says so.
- Every change is in the audit log (no approval: it is the app's own data, like the session library) and is refused
  while presenting with the read-only lock on. Exports to another laptop carry your own sizes, the images by path (the
  import says when a file isn't on that laptop) and the templates, pointed at that laptop's images, sizes and keys.

### Deploy

VM-21, VM-22, VM-10 (0.5.0): **Deploy** on the VMs page, the command palette or a template's row makes VMs from a
launch template, or from **Custom** values typed in the dialog.

- Pick the template (or Custom), how many VMs and their names (from the naming pattern; you can change each). The
  preview says, per VM and in all, the name, hypervisor, folder, size, network and disk space (thin disks counted at
  full size, since they can grow to it). A thick disk that doesn't fit on the drive, or a VM folder that is there
  already, stops the deploy; thin disks that might not fit only warn.
- It goes through the approval like every change: **Medium** for 1 to 4 VMs, **High** for 5 or more (Policy rules:
  "Bulk threshold for deploys") or for Prod. The job has one step per VM, two at a time, and can be cancelled. When a
  VM fails or the job is cancelled, Remotely removes what it made for that VM (never a folder that was there before);
  VMs already made stay. The audit log has the deploy's start and each VM's result.
- **Golden VM**: a full or linked clone of the snapshot the image names. While a linked clone is there, that snapshot
  and the golden VM can't be deleted (see Virtual machines and snapshots). **Cloud image**: a copy of the image (the
  file itself never changes) as the boot disk, grown to the size's disk; its first boot (cloud-init) sets the hostname,
  the guest user, the SSH key's public half and the packages, through the `.vmx`'s `guestinfo` keys on Workstation and
  a small `cidata` disc on VirtualBox, taken out after the first boot. A password never goes into these: they are
  readable on this PC. **ISO**: a blank VM from the size and the OS profile that boots the ISO first; on VirtualBox,
  an ISO it can install unattended can do so with a guest password from the vault (asked for again in the approval,
  and given to VirtualBox only as a file only you can read, deleted at once). **OVA/OVF**: imported (on Workstation
  with VMware's `ovftool.exe`, which Workstation installs; Settings has its path), then given the size's CPU and
  memory.
- After each VM: the size's CPU and memory, the boot disk grown when the size's is larger (never shrunk; not for a
  linked clone, and the job says so), the "clean" snapshot before the first boot, power on, then up to 5 minutes for
  its IP (a VM without VMware Tools or Guest Additions may not report one: the job says so and goes on), its SSH
  session saved and linked to it, and its console, as the template says.
- **Clone** (VM-10): pick shut-down VMs of one hypervisor on the VMs page, then Clone makes a full copy of each in one
  job, named by a pattern (`{template}` is the VM's name: `{template}-clone` by default). The copies stay off, like the
  VMs they copy: started as they are, they would use their source's name and addresses.

### Reachability dots

QL-04: the dots in the Terminal page's session tree. A check opens a TCP connection to the session's SSH port and
closes it at once: no SSH handshake, no login, nothing audited.

- **What is checked**: only the sessions the tree shows (not those in closed groups), each host and port once however
  many sessions share it, while the Terminal page is open. Settings, Terminal, turns the dots on, off, or on unless
  there are more than 200 sessions (the default).
- **How often**: every 5 minutes by default (15 seconds to an hour in Settings, Terminal; a value saved before 0.4.1 is
  kept). A host that is down waits twice as long before each next check, up to 30 minutes, and goes back to the
  interval once it answers.
- **Hosts you are connected to are not checked**: a terminal, the dashboard's guest metrics or the Containers page
  already holds a connection to them, so their dot says "connected". The next check comes one interval after that
  connection closes.
- **In the host's logs**: sshd logs each check as a connection that closed before logging in, and strict fail2ban
  rules may count it. On sites like that, turn the dots off or check less often.
- A session behind jump hosts shows its first jump host's state (see [Jump hosts and tunnels](#jump-hosts-and-tunnels)).

### Schedules

VM-14 and VM-27 (0.5.0): the **Schedules** page (Ctrl+., in the sidebar under Templates; the palette's "New schedule"
and a VM's **Schedules** tab open it too) runs actions on VMs on a timetable, or suspends VMs that sit idle.

- **What**: take a snapshot of each VM, optionally keeping only the last N it took; start; shut down (through the
  guest); suspend; or resume (only the suspended VMs: the ones that are off stay off). A power action leaves alone the
  VMs already in that state, and says so.
- **On**: VMs by name, and tags (every VM with the tag when it runs).
- **When**: every hour at a minute, every day at a time, or on chosen days at a time, in local time; or **when idle**
  (auto-suspend): a running VM whose own CPU stayed under a limit for a set time (10 minutes to 24 hours), measured
  from the dashboard's history and its live readings. A VM Remotely didn't watch for the whole time (closed, asleep,
  just started) waits until it has.
- **Daylight saving** never doubles or skips a run silently: a time the clocks jump over runs at the first minute after
  the jump (02:30 runs at 03:00), a time they repeat runs once, at the first, and the list and the run both say so.
  Hourly runs stay an hour apart.
- **Approval when it is saved**: saving asks with the same steps as running it then (a Prod VM raises the tier, Critical
  asks for the vault password). A snapshot schedule that keeps the last N asks what deleting a snapshot asks (High). The
  countdown is each run's: a High run waits it out and can be cancelled in Activity. Each run then goes through the
  command bus under that approval and is in the audit log as one of its runs (`approval_used`, and the job's entries
  carry the approval). The dialog shows the next runs and what each does.
- **It asks again instead of running** when it was edited (a new name alone doesn't count), a VM became Prod or
  protected, a new VM got its tag, or the approval rules that rated it changed. The schedule then shows "Needs
  approval" and why, a notification says so, and **Review approval…** asks again. Fewer VMs than approved is fine.
- **Missed runs** (the PC asleep or off, Remotely closed, or more than 2 minutes late) are reported once in the run
  history, with how many, and never caught up. While presenting with the read-only lock on, nothing runs (each due run
  is reported as skipped) and schedules can't be changed. Runs never overlap: a run due while the last one still goes is
  skipped and reported.
- **Retention deletes only the schedule's own snapshots**, oldest first: each is recorded by the hypervisor's own id
  for it when it is taken, and named `Remotely schedule '<name>' <date> <time> (run …)`. A snapshot renamed since is
  kept and no longer counted; a snapshot that only looks like one is never touched. Deleting a schedule keeps its
  snapshots on the VMs.
- **Snapshot chain warnings**: the page's limits (5 snapshots deep and 100 GB by default) flag VMs whose disks' snapshot
  chains are deeper or larger, in the list and in each VM's Schedules tab; saving a schedule that would keep enough
  snapshots to pass the depth warns too.
- **Run history** per schedule (the newest 200 runs): when each was due, how it went and why, and its jobs.

### What Remotely does by itself

0.4.1: what Remotely does on customers' hosts without you typing it, and how it stays gentle.

- **Background logins** (MO-02, CT-01): the dashboard's guest metrics and the Containers page log in with the saved
  login and keep the connection. A login the host refuses, a sudo password it refuses, a host key that changed or a
  password that isn't saved **parks** the host: no new login (or sudo) until you change the session or its sudo
  choice, add, replace or delete a vault secret, unlock the vault, trust or remove a host key, or press **Retry** (in the
  dashboard's details, or on the Containers page). So a rotated password costs one failed login, not a locked account
  or a fail2ban ban. A changed host key is audited once per park. Every background login also counts against a cap of
  10 per host per hour (each jump host on the way counts too): past it the host shows "Paused" until the hour has room,
  and Retry gets one login past it. Terminals never retry a refused login on their own.
- **Startup commands** (SS-01): a session's startup command is typed into its shell without asking, so the session
  editor rates it as you type (the tier a command like it gets on this session; Prod raises it), and its audit entry
  says so. Imports (PuTTY, MobaXterm, OpenSSH, CSV) and imports from another laptop list each startup command with its
  rating and a warning, and leave it out unless you tick it; port forwards in an export file likewise. A startup command
  is typed at the first line that looks like a shell prompt (`alice@web01:~$ `), never at a menu or a question; with no
  prompt within 15 s it isn't typed and the terminal says so. It is typed on the connections you open; after the
  terminal reconnects by itself, only if the session asks ("Type it again when the terminal reconnects by itself").
- **The folder prompt hook** (SS-08): see [File transfer in the terminal](#file-transfer-in-the-terminal). Settings,
  Terminal turns it off everywhere; a session can say on or off; a Prod session has it off unless the session turns
  it on. It is typed only at a line that looks like a shell prompt, starts with a space so `ignorespace` keeps it out
  of the history (nothing edits the history), and each one is in the audit log (`folder_hook_installed`, once per
  connection). Off, Files here starts in the home folder.
- **Schedules** (VM-14, VM-27): see [Schedules](#schedules). A schedule acts on VMs only under the approval you gave
  when you saved it, and pauses to ask again when anything that approval depended on changed.
- **Host keys** (SS-05): a bulk run with "Trust new host keys" never trusts a key of a new type for a host that already
  has a trusted key of another type: someone in between can offer any type, and the run would give them the passwords.
  It blocks like a changed key and is audited. An import from another laptop shows such a key as a conflict, skipped
  unless you pick it. Connections ask the host for the key types already trusted for it first, so a host with several
  keys presents the one you trusted. A terminal still asks you, and says another kind of key is trusted.

### Background cost

What Remotely runs while you look at something else, and how it stays light on this PC and on customers' hosts.

- **The VM list** is read again (vmrun, VBoxManage) only while the Virtual machines page shows: after a job that
  touched VMs (power, snapshots, protection), after a change to where VMs are found (vmrun or VBoxManage path, VM
  folders), or on Refresh. Something that changes while another page shows is picked up once, when the page shows
  again. One refresh runs at a time; those asked for meanwhile share one more run after it, so ten uploads finishing
  together cost two refreshes, not ten. A running VirtualBox VM takes two VBoxManage runs (`showvminfo`, then one
  `guestproperty enumerate` for its address and OS) instead of up to seven.
- **Pages that aren't shown read nothing**: the dashboard, its charts and the VM page's host shares stop while another
  page shows or the window is minimised, and read once when they show again. Activity follows a running job about
  once a second while it shows. A file transfer's progress redraws the transfers panel only.
- **Guest metrics** (MO-02): each watched host is polled every 5 seconds by default, or every 15, 30 or 60 seconds
  (Settings, Dashboard). A poll is one command on the kept connection: the login shell and one `grep` of the /proc
  files, plus `df` once a minute, so a SIEM that logs every process start sees two a poll instead of eight.
- **Host names** (QL-01): a session's host name is looked up to link it to a VM's guest address at most once at a time
  and kept for 10 minutes (2 when it didn't resolve); a refresh waits at most 3 seconds for the lookups and uses every
  one that finished. A session behind a jump host is never looked up: its name only means something on the far side,
  and asking this PC's resolvers would send it out on the customer's network (LLMNR, NetBIOS).
- **Terminals** (SS-03): a terminal on screen draws with WebGL (at most 12 at once; one hidden for 2 seconds gives its
  GPU context back; WebGL that fails falls back to the normal renderer). While presenting, the masked copy of each
  terminal keeps the last 1,000 lines and is filled in pieces, so starting to present never freezes the window; search
  while presenting looks that far back. Copying or printing several terminals' output and the command library run off
  the window's thread.
- **Reconnects** (SS-03): a terminal whose connection drops tries 10 times quickly (1 second, doubling to 30 seconds),
  then 12 times 5 minutes apart (about an hour) before it waits for Enter. Each wait is spread at random, so terminals
  behind one jump host don't all log in at the same moment. When Windows resumes from sleep or this PC gets a new
  network address, waiting terminals try within 3 seconds, and one that had given up starts its tries again.
- **Reachability dots** read nothing while they are off or the session tree isn't shown.
- **Dashboard history and alerts** (MO-06, MO-07): one database write a minute for every series together;
  the alert rules run on each round in memory and read names and tags at most once a minute; the services
  widget runs one command a minute on the dashboard's kept connection.

### Safer operations on hosts

0.4.3: how far a change on hosts can spread before you see it, and what the audit trail keeps.

- **Replacing a file** (SS-08): an upload that replaces a file writes a hidden temporary file beside it
  (`.<name>.remotely-<id>.part`), gives it the old file's permissions and owner, and puts it in place in one step
  (OpenSSH's `posix-rename`), so a dropped VPN never leaves `nginx.conf` half written: the old file stays as it was and
  the temporary one is deleted. Through a link, the file it points to is replaced. A server without `posix-rename` keeps
  the old file as `<name>.<time>.bak` and the transfers list says so. Only when the folder takes no new file, or the
  old file belongs to another user whose ownership the login can't keep, is the file written over in place as before,
  and the list says why. Extended attributes, ACLs and other hard links of the old file are not carried over. A folder
  listing stops at 20,000 entries and says so.
- **Rolling out a command** (BX-02, Compare output): "Run on one host first" runs the first host alone; you see its
  result and press **Run on the rest** or **Stop here** (the rest wait up to 15 minutes, then the run stops); a canary
  that fails stops the run. "Stop after N failures" starts no more hosts once N failed or timed out; hosts already
  running finish. Both are off by default: a non-zero exit is normal for read-only checks (`grep`, `test`), and the
  approval tier already rises with the number of hosts. The approval dialog says what was chosen; going on after the
  canary is in the audit log.
- **Outcome unknown** (BX-04): a host that ran past the time limit, or was cancelled while its command ran (or a VM
  whose vmrun or VBoxManage call was cancelled), may have run it, so it is "outcome unknown", not failed. **Retry
  failed** leaves it out; a separate button retries it too, after a warning that the command may run twice.
- **Which host was reached** (AP-05): each remote target of a job is journaled with the address this PC connected to
  (none behind jump hosts) and the host key it accepted (`ssh-ed25519 SHA256:...`), and the job's end in the audit log
  lists them. The results' host view shows them.
- **Automatic VM links** (QL-01): they follow the IP address each guest reports about itself, which a guest can make up
  (a lab VM claiming a production server's address). So they only show on the dashboard and in lists; a bulk run or
  key push picked by VM, tag or filter reaches the VM through one only after you press **Confirm link**. Auto-linking
  also skips sessions behind a jump host and sessions whose environment label is not the VM's (both unlabelled counts
  as the same), and removes an automatic link that breaks either rule.
- **Tunnels** (SS-07): the dialog says that a tunnel on 127.0.0.1 is open to every user signed in to this PC, not only
  you, and that a remote tunnel on localhost listens on every address when the host's sshd has `GatewayPorts yes`.
  A SOCKS tunnel on loopback is Medium (one confirm) while other users are signed in to this PC (a shared jump server);
  otherwise it stays Low.
- **SSH keys** (SS-09): a push can give the key an expiry day (`expiry-time`, at 00:00 UTC; needs OpenSSH 8.2 or later,
  an older sshd refuses the key) and the hosts or networks it may log in from (`from`). A host that has the key already
  is left as it is and fails with why (remove it there first). **Remove from hosts** takes a key off hosts'
  `authorized_keys` (every line holding it, the file replaced in one step): Medium, audited, like a push.
- **Starting several VMs** (VM-02): the approval names the VMs with a bridged network adapter plugged in at power-on,
  which join the network this PC is on, so a clone with a fixed IP address can't take a customer machine's address
  unnoticed. Starting is still Low; the warning adds one confirm.

### What Remotely keeps on this PC

Customer data stays on the laptop only as long as it is useful (BX-02, BX-05, SS-10, SS-11, AP-05).

- **Job outputs and command text**: every job keeps what its hosts printed (stdout and stderr, up to 64 KB each per
  host) and its command (a Compare run's whole script, a MultiExec line), so Activity and Compare can show them. Settings,
  General, **Job outputs** says for how long: 30 days, **90 days** (the default), 1 year or forever. A purge runs at
  start and once a day: older jobs lose their outputs and their script or line text, and keep their rows, summaries,
  tiers, targets, results, exit codes and output hashes, so Activity still lists them and Compare still groups them
  (retrying such a run needs it typed again). **Purge now** applies the setting at once. A purge that removed something
  is in the audit log with what went (`journal_purged`), and so is every Purge now; changing the setting is audited too.
  Presentation mode's read-only lock refuses changing the setting and Purge now, never the daily purge.
- **No secrets in the journal or the audit log**: what looks like a password, token or key in a script, a MultiExec
  line or any audit entry's text (`--password=...`, `TOKEN=...`, `Bearer ...`, a password in a URL) is stored as
  `[redacted]`, as the CSV export always did; a run whose script had one can't be retried as it ran. Jobs from before
  this are redacted once, at start. Keys typed at a password, passphrase or one-time code prompt (sudo, su, ssh, PAM's
  two-factor codes, a cloud CLI's MFA code, in English and the languages Linux translates them into) never reach the
  journal or the audit log at all.
- **Deleted means gone**: the database overwrites what it deletes (`secure_delete`), empties its write-ahead log after a
  purge, and compacts its file (`VACUUM`) after a purge that freed a lot of space, while no job runs (a job submitted
  meanwhile waits for it).
- **Dashboard history** (MO-06, MO-07): 1-minute averages of the VMs, watched hosts and this PC, and the alert
  list, kept 7 days by default (Settings, General, Dashboard history), pruned at start and daily, never exported.
- **The audit log** is never purged: it is append-only and hash-chained. Verify and Export read it row by row, however
  long it is, and the export is written next to the file you chose, then renamed, so a failed export leaves no half
  file.
- **Nothing lands in a Git repository by accident**: no save path writes into a Git working tree (a folder with a
  `.git` folder or file in it or above it): the audit log CSV, Compare and MultiExec exports, saved terminal output,
  session logs, downloads and exports to another laptop. The message names the repository; choose a folder outside it.

### Folder defaults

A session folder can set the **user**, the **login** (a key, a vault password, the SSH agent, or a password asked when
connecting), the **jump host**, the **environment label** and **tags** for the sessions in it and in its subfolders
(Sessions page, a folder's menu, **Defaults…**). A session uses its own value first, then the nearest folder up the path
that sets one, then the app's default (no user, a password asked when connecting, no jump host, no label). Everything
that uses a session follows the same rule: terminals and quick connect, MultiExec, Compare and bulk runs, key pushes,
containers, the dashboard, host details, reachability dots, exports and imports, and presentation mode.

- The session editor shows each value a folder gives as "from folder X"; typing or choosing one overrides it. Login has
  **From folder**, the jump host **No jump host (overrides the folder)**. The session list marks values from a folder.
- **Labels only add**: a session with no label of its own takes its folder's, so a session in a Prod folder is Prod and
  raises the approval tier. There is no "no label" override; a session or subfolder can choose another label. Taking
  Prod off a folder asks first.
- **Tags add up**: a session has its own tags and every folder's up the path.
- A folder's **jump host** never applies to itself: the jump host session, when it sits in that folder, connects as the
  folders above say. A jump host chain that would loop through folders is refused.
- A folder password that would reach hosts that never got it asks for the vault password (below). An SS-02 import into
  a folder takes the folder's key or agent login for sessions the source says nothing about, never its vault password.
- Changes are in the audit log like session edits, with the sessions they change, and the read-only lock refuses them.
- Exports carry folder defaults; an import shows a folder here with other defaults as a choice (keep this laptop's,
  the default, or take the file's). An export that uses folder defaults (a folder that sets one, or a session that
  logs in as its folders say) is file format 2, which 0.4.x refuses ("a newer version of Remotely"), since it would
  drop them; any other export stays format 1, which 0.4.x imports.

### The vault and where its passwords go

An unlocked vault on a laptop at a customer's site shouldn't let whoever sits at it send the stored passwords anywhere.
So a password from the vault goes, without asking, only where it already goes: to the host (and port, and jump host)
of a saved session that logs in with it, gives it to sudo as a container host, or was allowed to use it before.
Anything else asks for the **vault password** first (as Critical actions do), and each answer, right or wrong, is in
the audit log:

- a session saved, or edited, with a vault password no saved session sends to its host yet; moving a session that
  sends vault passwords (its login, a container host's sudo password, ones it was allowed) to another host, port or
  jump host;
- a quick connection with a vault password for a host no saved session sends it to;
- **Type vault password** with a password not used at that host, or "Type it anyway" with no password prompt showing;
- a container host's sudo password (Containers page: marking or detecting) the host doesn't get yet;
- a Compare run whose sudo password is new to some of its hosts: its approval asks for the vault password, even for a
  Low command;
- an import from another laptop whose sessions would use passwords already in this vault (found by label, when the
  file has no values), or that moves a session that sends vault passwords to another host;
- a folder's defaults (0.5.0) that would send a vault password to hosts that don't get it yet: setting a folder's login
  password, giving it a jump host while its sessions send vault passwords, moving sessions or a folder under such a
  folder, or deleting a folder so its sessions move up under one. One prompt covers the whole change, as editing each
  session would.

For a saved session the answer counts from then on (`vault_secret_allowed` in the audit log), so the same password there
doesn't ask again: a session's own login password at its own sudo prompt never asks. A right answer also covers the next
5 minutes (as sudo does), so setting up several sessions that share a password asks once; each step is still audited,
and locking the vault ends it. A password you have just added (on the Vault page, or "New password" in the session
editor) goes to its first place without asking. Private keys and their passphrases never ask: a login only signs with
them on this PC, so no host ever receives them.

- **Approval rules**: any change that loosens them (a lower tier, Prod no longer raising the tier, a dangerous-command
  rule removed or changed, a new read-only command, a higher bulk threshold, a shorter countdown, no safety snapshot by
  default) asks for the vault password; tightening doesn't. Shells, interpreters and programs that run other commands
  (`bash`, `python3`, `perl`, `awk`, `xargs`, `sudo`, `env bash`, ...) can't be read-only commands at all.
- **Windows unlock** (DPAPI) is off for new vaults. With it on, one click unlocks the vault while you are signed in to
  Windows, but any program running under your Windows account could open it too, even from a copy of Remotely's
  database, without the vault password. Vaults set up before keep their setting; the Vault page and Settings, General
  say so plainly and turn it off in one click (no password needed: it deletes the Windows-protected copy of the key).
- **The idle lock** counts from your own typing and clicking in Remotely and the actions you start, not from the
  dashboard's or the Containers page's background reads, so it really locks after 15 minutes away. When the vault locks,
  the dashboard's, the Containers page's and host details' kept connections close, terminals forget passwords typed for
  their logins (open shells stay open; the next login asks again), and an opened import file closes.
- **Copies and logs**: copying from a terminal (a selection, Ctrl+Shift+C, copy-on-select, Copy output) removes the
  passwords Remotely knows for that terminal, and the copy is kept out of Windows' clipboard history (Win+V) and the
  cloud clipboard; other text you copy in Windows still appears there. Session logs scrub those passwords even when the
  terminal draws them in pieces (colour codes, backspaces), and container commands show passwords as `[redacted]`.
- **New passwords**: a new vault password, like an export passphrase, needs 10 characters and must be hard to guess (a
  meter shows why, and common passwords, repeats, keyboard rows and dates count against it); **Generate** makes up six
  random words. An existing vault keeps the password it has.
- **Changing the vault password** makes a new data key and seals every secret with it again, in one go, so an old copy
  of the database or of its wrapped key opens nothing written since. Deleted and rewritten vault data is overwritten in
  the database file (`secure_delete`), and the database's write-ahead log is emptied after each vault change.

### Highlight and alert rules

Settings, Terminal, **Highlight and alert rules** (0.5.0, QL-17) colours what a regular expression matches in
terminals. Built-in rules light up errors, fatal errors, panics, Python tracebacks and warnings; each can be turned off,
and **Duplicate** makes an editable copy. Add your own for every terminal, for sessions with a label (Lab, Staging,
Prod, the label a session has from its folder included), or for one session, as text in a colour or a coloured fill,
with or without case.

- Turn a rule's **alert** on to get a Windows notification when a matching line appears while its tab is in the
  background: one for a burst of lines, then that rule waits a minute in that terminal and counts what it skipped.
  Full-screen programs (vim, less, top), password prompts and the commands you type never alert. The bell in the
  terminal toolbar silences a tab. Alerts are off for the built-in rules until you turn them on.
- Lines are checked once, as they complete, never by rescanning the scrollback. A rule's pattern is at most 200
  characters, there are at most 50 rules of your own, and patterns that can take very long to match (a repeat inside a
  repeat, like `(a+)+`) are refused. While presenting, the masked terminal on screen is highlighted on its own text,
  so a rule naming a real host never lights up its stand-in.
- Rule changes are in the audit log (without the pattern) and the read-only lock refuses them.

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
    broken, added disk isn't visible, disk enlarged but the space didn't grow, mount fails or fstab is wrong, iSCSI
    disk missing), each listing the checks to run in order.
  - **By area** — 30 groups by topic: system info; disk and filesystems; disks: add and grow (rescan the SCSI bus for
    a disk added to a VM, grow a partition, PV, LV and filesystem with sizes before and after, partition, format and
    mount a new disk); mounts and `/etc/fstab` (check it, UUIDs, add an entry safely); storage (LVM, RAID, SMART,
    NFS/SMB); iSCSI and multipath (discovery, login and logout, sessions, rescan); find files and text (folders and
    files by name, `locate`, size, age, owner, text inside files); copy files (`scp` and `rsync`: to and from a host,
    mirror, dry-run previews, resume, speed limits, checksums after a copy); memory; CPU and processes; network;
    services; logs; packages (apt and dnf); users and groups; security and access (SELinux, AppArmor, sudo, `sshd -T`,
    auditd, fail2ban); TLS certificates; firewall; web servers (nginx, Apache); databases (MySQL/MariaDB, PostgreSQL);
    cron and timers; time and NTP (timedatectl, chrony and systemd-timesyncd: status, config, which daemon runs, time
    zone); identity (AD/LDAP, SSSD); VMware Tools in the guest; Docker; Podman; Kubernetes; Helm.
    Most entries are read-only checks; the fixes (restart or reload a service, vacuum the journal, extend an LV and grow
    its filesystem, resync the clock, clear a failed unit, open a firewall port, mount, log in to an iSCSI target) are
    marked as changes and ask before they run. Every `scp` and `rsync` is a change, dry runs included: rsync's options
    can run programs or write files. The partition and format steps are for a new, empty disk; the parted and mkfs
    rules mark them dangerous, as the kubectl delete and Docker or Podman prune rules mark deleting a pod and pruning.
    A command can appear both in a symptom runbook and in its area group.
  - **Manual** (QL-13): each library command has a link to its official manual page (the man-pages project at
    man7.org, freedesktop.org for systemd's tools, a project's own documentation for Docker, Podman, kubectl, Helm,
    nginx, Apache, MySQL, PostgreSQL, chrony, firewalld, OpenSSL and rsync, and Debian's or Ubuntu's manual pages
    otherwise). It opens in your default browser; Remotely opens only addresses on that list of documentation sites.

### MultiExec and Compare output

Bulk execution lives in the Terminal page (it replaced the MVP's Bulk run page):

- **MultiExec** (SS-10): the toolbar switch makes the picked tabs receive what you type into any of them, as in
  MobaXterm, and can show them side by side; each terminal shows its own output. Pick tabs with Ctrl+click and
  Shift+click, or all of them, a folder's or a label's from the MultiExec bar. The command panel's paste and Shift+click
  go to them too. Safety: Remotely follows the line as it is typed, holds Enter (and every other key that runs a line
  in bash or zsh: Ctrl+O, Esc then Enter, Esc then A, Esc then #, # in vi mode...) and rates the line like any remote
  command (read-only, other, dangerous; a Prod tab raises the tier; see "How commands are rated" below, where the
  picked terminals are the hosts). A read-only line goes at once; anything higher
  opens the approval dialog with the line and the terminals, and Cancel sends Ctrl+C to each. A line edited with keys
  Remotely can't follow (Tab completion, arrow keys, history search), or a tab that already had text on its line, is at
  least a confirm, and so is the line after one run with another key than Enter. A pager or editor (less, more, man,
  vim) is never read-only here: it stays open in each tab. Keys that open the line in an editor and run what is saved
  there (Ctrl+X Ctrl+E, v after Esc in vi mode), replay a keyboard macro (Ctrl+X E) or run an editing command by name
  (Esc then x) are not sent, and the MultiExec bar says why. A lone Esc waits for the key after it. Every line sent is
  in the audit log with the command, the sessions and the tier, never the output. Two exceptions pass keys straight
  through, unrated: at a password, passphrase or one-time code prompt (sudo, su, ssh, two-factor codes, in English and
  translated; the keys go only to the tabs showing one, and are never kept, journaled or logged) and
  to a full-screen program such as vim, less or top (only to the tabs that have one open; what is typed there, like
  vim's `:!command`, is not rated). Protected sessions are left out.
- **MultiExec recording** (QL-12): every line MultiExec sends is recorded in each of its terminals, from Enter until
  that terminal's prompt comes back (or its output stops for the quiet spell set in Settings, or 10 minutes pass), so
  you can compare it at any time without typing it again: open Compare from the MultiExec bar, or pick the MultiExec
  view in the Compare panel. It lists the recorded lines, newest first, with their time, terminals and tier; a line
  shows grouped like a Compare run (identical outputs together, A, B..., the diff between groups, ignore trailing
  whitespace), and a line still running fills in as each prompt comes back. Escape sequences are removed and redrawn
  lines (progress bars) read as they ended; secrets are scrubbed like saved output (the login's and vault passwords
  typed into the terminal). Password prompts and keys sent to full-screen programs are never recorded. Recordings are
  kept in memory only, until MultiExec is turned off (or every terminal of a line has closed), at most 200 lines and
  32 MB per session, and 64 KB per terminal per line (the middle of a longer output is cut, as in Compare); the view
  says when a cap was hit. Export a line, or all of them, as CSV, JSON or HTML with groups and diffs; the audit log
  says what was exported and where, never the output.
- **Saved MultiExec groups** (QL-19, 0.5.0): the Groups button next to the MultiExec switch keeps named sets of saved
  sessions, such as "all web servers". **Open group** opens a tab for each session, reusing tabs that are already
  open, and turns MultiExec on for exactly those tabs. **Select group** picks the group's open tabs and says which
  members aren't open. You can also save the picked tabs as a group (quick connections are left out), and rename,
  reorder or delete groups under **Manage groups**. Every line you type still goes through the approval rules. Group
  changes are audited, blocked by the read-only lock while presenting, and carried in the encrypted export to another
  laptop.
- **Search all terminals** (QL-18, 0.5.0): Ctrl+Shift+G, the search-all button or the palette searches the scrollback
  of every open terminal at once, as plain text or a regular expression, with or without case. Results are grouped by
  tab; click one to jump to its tab, scroll to the line and highlight the match. Results are from when you searched:
  press Enter or Search again for newer output. At most 200 matches per terminal and 2,000 in all are shown. While
  presenting, the masked text on screen is what gets searched.
- **Compare output** (BX-03): runs one command once on the hosts of the picked tabs and of sessions Ctrl+clicked in the
  session tree (Ctrl+click a folder for all of it, handy for 50 hosts), over separate exec channels with the usual
  approval tiers, sudo from the vault, a time limit and the parallel limit from Settings. The results are grouped by
  output ("48 hosts same, 2 differ"), with a diff between groups, retry of the failed hosts and CSV, JSON or HTML
  export. Quick connections that were not saved as sessions can't be compared.
- **How commands are rated** (BX-06, AP-01), for Compare and MultiExec alike: a command whose every part starts with
  a command on the read-only list, and that writes no file, is Low. Any other command is one confirm (Medium) on up to
  4 hosts, and the full approval (High: type the number of hosts, a reason, the countdown) on 5 or more; Settings,
  Approval rules sets that number ("Bulk tier for commands on hosts", apart from the bulk threshold of VM and other
  actions). A command that matches a dangerous-command rule is High on any number of hosts. The rules are regular
  expressions, tested against the command as typed and against each of its commands as the shell reads them: quotes
  and backslashes removed (`\rm -rf /` and `"rm" -rf /` read as `rm -rf /`), `sudo`, `env` and `NAME=value` in front
  dropped, and a script given to `sh -c`, `su -c`, `ssh` or `eval` read as a script. The default rules: `rm -r`,
  `mkfs`, `dd`, shutdown and reboot, `iptables -F`, `DROP DATABASE`, and from 0.4.1 wiping or repartitioning disks
  (`wipefs -a`, `sgdisk` zap, new or delete, `parted` mklabel, mkpart or rm, `sfdisk` unless it only lists, dumps,
  shows or verifies, `blkdiscard`, `pvremove`, `vgremove`, `lvremove`, `mdadm --create` and `--zero-superblock`, and
  writing to a disk device such as `> /dev/sdb`, `tee`, `cp` or `shred` onto one), locking everyone out
  (`iptables -P <chain> DROP`, `nft flush ruleset`, `ufw enable`, `ufw default deny [incoming]`,
  `firewall-cmd --panic-on`, stopping, disabling or masking `sshd`/`ssh`, taking a network interface down with
  `ip link set … down`, `ifdown` or `ifconfig … down`, since Remotely can't tell which one its connection uses),
  `kill -9 -1` (any signal to every process), a recursive `chmod`, `chown` or `chgrp` on `/`, `/*` or a system folder
  (`/etc`, `/usr`, `/var`, `/bin`, `/sbin`, `/lib*`, `/boot`, `/home`, `/dev`), the fork bomb, `DROP TABLE` and
  `TRUNCATE`, `kubectl delete` (and `oc delete`), and Docker or Podman prunes (system, container, image, volume,
  builder) and volume removals. Restarting or reloading sshd is not dangerous: it comes back, and open sessions stay
  up. A prune or volume removal is also rated at least like the same action on the Containers page, so
  `docker volume prune`, `docker system prune --volumes` and `docker volume rm` are Critical (the vault password
  again), as a volume prune is there, and editing that rule in Settings changes both; other prunes are High like
  there. **Saved approval rules keep their own lists**: the new patterns and the 5-host step for "Run any other
  command" apply to new and default rules. Rules you saved before 0.4.1 keep their dangerous-command list and their
  tiers ("other" commands stay one confirm on any number of hosts) until you add the patterns and set "Run any other
  command" to High in bulk yourself, or press Reset to defaults, in Settings, Approval rules. The Containers-page rating of prunes is built in, so it applies to
  saved rules too.
- **Notifications** (QL-07): Settings, Terminal, chooses between commands longer than N seconds (5 to 3600) and any
  command that finishes while you're away (the tab isn't on screen or Remotely isn't the window in front), whatever its
  length. A line sent with MultiExec gives one notification once all its terminals are done, never one per terminal.
- **Pasting and links** (QL-05, SS-10, SS-03): a paste loses its control characters (tabs and line breaks aside) and any
  bracketed-paste markers, and text with a line break asks first, showing its first lines and, with MultiExec on, how
  many terminals get it (Settings, Terminal can turn the question off). The terminal's own answers to a host's queries
  (cursor position, colours, focus) go to that host only, never through MultiExec. Links a host prints are never
  opened: a click shows the address, to copy.

### File transfer in the terminal

SS-08: files go up and down over SFTP on each terminal's own SSH connection, so there is no second login or window.

- **Files here**: the drawer (the folder button in the Terminal toolbar) lists the current terminal's folder. For bash
  and zsh it follows the shell as you `cd`: on connect Remotely types a small prompt hook that reports the folder (OSC 7) before each prompt, and hides it completely: it never shows in the terminal, its scrollback, saved output, session
  logs or MultiExec, and it starts with a space so `ignorespace` keeps it out of the history. It is only typed while
  nothing has been typed in the new shell yet, at its first prompt (a line that looks like `alice@web01:~$ `, never a
  menu); a session's startup command waits for it. Each one is audited, and it can be turned off (see
  [What Remotely does by itself](#what-remotely-does-by-itself)): then the drawer starts in the home folder. Other shells
  (sh, fish, network gear) get nothing typed: the drawer starts in the home folder, and you open folders by
  double-clicking, the breadcrumb, Up, Home, Back or a typed path. Sort by name, size or date; tick files to download
  them.
- **A folder that can't be opened** (QL-09), say one only another user may read: the drawer keeps its path in the path
  box and the breadcrumb, says why (`alice can't open the folder /home/bob/.app on the host (permission denied)`), and
  Up, Home, Back (to the last folder that opened), the breadcrumb, a typed path (relative paths go on from the folder
  shown) and Refresh all still work.
- **Which user** (QL-09): the top of the drawer says who transfers run as, "Transfers as alice": always the SSH login
  user, over SFTP, never with sudo. The prompt hook reports its shell's user next to the folder (in a private escape
  sequence that is hidden like OSC 7). After `su`, `sudo -i` or `sudo su bob` the new shell has no hook, so its prompts
  come without a report: the drawer notices, says the shell may have switched (and to whom, when its prompt names a
  user, such as `bob@web01:~$`), that it shows the login user's view, and that transfers still run as the login user,
  so a permission error makes sense. `exit` back to the login shell clears it. Without the hook (sh, fish) the drawer
  goes by the prompt alone.
- **Download**: to Downloads, or a folder you pick (Download to…). A file of the same name there is kept; the new one
  gets a number. Right-click a file name in the terminal's output (`ls`, an error message) to download it; elsewhere
  right-click pastes as before. "Open folder" in the transfers list shows a finished download in Explorer. Each download
  is in the audit log with the file's name, size, host path, where it was saved and its SHA-256, never its content.
  Names are made safe here: what Windows can't hold in a name and invisible Unicode format characters (such as U+202E,
  which makes `invoice[U+202E]fdp.exe` look like `invoiceexe.pdf`) become `_`, and a device name (`nul`, `com1.txt`)
  gets a `_` in front. Each download is marked as from the internet, with the `Zone.Identifier` stream browsers write
  (ZoneId=3, without the host's name), so SmartScreen and Office's Protected View treat it as one; on a FAT or exFAT
  drive, which can't hold the mark, the transfers list says so.
- **Upload**: drop files on a terminal, or use the upload button (toolbar or drawer). They go into the terminal's
  folder (the drawer's upload goes into the folder it shows). Uploads are changes, so they go through the command bus:
  Low, a Prod session raises it one tier, and a file that is there already is replaced only after you say so and
  confirm (replacing is at least Medium; Settings won't take less). Files are written as the logged-in user and never
  with sudo: a folder you can't write to fails with a message saying so. Each uploaded file is audited with its name,
  size, destination and SHA-256. Folders aren't uploaded or downloaded (zip them, or pick their files).
- **Transfers**: the list under the drawer shows each file's progress, speed and time left, with cancel and retry (a
  retried upload asks again if it now replaces a file). A new file that fails or is cancelled part way is deleted from
  the host; a file being replaced stays as it was (see [Safer operations on hosts](#safer-operations-on-hosts)).
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
  state (the one this PC dials), never red because the session itself can't be reached from here. A connection open
  through that jump host counts as one to it, so it is not probed either.
- **Port forwards**: each session keeps local (`ssh -L`), remote (`ssh -R`) and SOCKS (`ssh -D`, SOCKS 4, 4a and 5)
  forwards, edited with the session. They listen on 127.0.0.1 unless you type another address (the host side of a
  remote forward defaults to localhost); port 0 takes any free port. Those marked "starts with the terminal" open when
  the terminal first connects; the terminal's Tunnels button lists them with their state (listening where and how many
  connections, waiting for a reconnect, failed and why) and starts or stops them. A tunnel rides the terminal's
  connection: behind jump hosts it starts from the session's host, it opens again by itself after a reconnect, and it
  closes with the terminal.
- **Approvals**: opening a tunnel is a command on the bus. A local or SOCKS tunnel on loopback is Low (so Medium on a
  Prod host, as the PRD's tier table says); loopback is every user signed in to this PC, so a SOCKS one is Medium
  while others are. A remote tunnel is Medium: the host listens, and whatever
  reaches that port gets into the network this PC is on. A tunnel that listens on a network address (0.0.0.0, a LAN
  IP), on either side, is Medium and never lower: other computers can use it without logging in, and the dialog says
  so. Forwards that start with the terminal go through the same approval. Opening and closing are audited with the
  session, kind, addresses and ports, never what goes through.
- Exports to another laptop carry each session's jump host and port forwards.

Not done here: importing port forwards from PuTTY, MobaXterm or OpenSSH config files (the jump host link is imported),
and a jump host in quick connect.

### Containers

CT-01 and CT-02 (0.4.0), Ctrl+3: Docker and Podman on SSH hosts, and Docker Desktop on this PC.

- **Hosts**: mark a saved session as a container host with **Add a host…** (Docker, Podman or both), or press **Detect**
  in that dialog: Remotely logs in, looks for `docker` and `podman`, and says whether docker works for the login user,
  needs sudo with a password, or works with NOPASSWD sudo. For each engine choose how its CLI runs: as the login user
  (the `docker` group, or rootless Podman), with sudo and the session's login password, a vault password, or none.
  Marks are audited like session edits and move to another laptop with the export. Docker Desktop on this PC shows as
  "This PC" when its `docker.exe` is found (the path in Settings, General, then `REMOTELY_DOCKER`, then Docker
  Desktop's folder).
- **Reads, never in the background**: a host is read when you open it, press Refresh or a job ends. The open host's
  stats are read every 10 s, and a followed log asks for new lines every 2 s, only while the page shows and the window
  is visible (not minimised). Each read waits until the last one came back, so a slow host never has two at once; one
  stats read serves the list and the details panel's Stats tab; a read that fails waits longer each time (up to a
  minute, 30 s for a log). Remotely runs the host's own CLI with JSON output over the session's
  SSH connection (through its jump hosts, with the usual host key checks; saved logins only) and keeps that connection
  for a few minutes for the next read. The list has name, image, state, ports, uptime, CPU and memory, with a filter
  and state buttons; a click on a name opens its details beside the list: **Overview** (image, times, restart policy,
  health, ports, networks, mounts, and environment variables by name only: their values often hold passwords, so they
  are never read out), **Logs** (the last 100 to 5000 lines, follow, search, timestamps; stderr lines tinted) and
  **Stats**. The Images, Volumes and Networks tabs list those, with what uses each image and volume.
- **Changes go through the approval flow**: start and unpause are Low; stop, restart and pause are Medium for one
  container and High for two or more; removing containers or images and pruning (stopped containers, unused images,
  the build cache) are High; removing volumes or pruning them deletes data, so it is Critical (the vault password
  again); pulling an image is Low. A Prod host raises each one tier, and a protected host (one that reaches a protected
  VM) is skipped. The approval dialog lists each container with its state, image and uptime, what uses an image or
  volume, and what a prune would remove. Jobs keep the CLI's output; the audit log names the host, engine and
  container (name and id), never logs or output. Only containers, images and volumes the engine itself listed can be
  acted on, and every id and name is checked and shell-quoted before it reaches the host.
- **Open a shell**: on a running container of an SSH host, a terminal tab named after the container runs
  `docker exec -it <id>` (or podman) with bash, or sh when the image has no bash, on the session's connection, with
  sudo when the host's engine uses it (type the password, or use "Type vault password"). Leaving the container's shell
  ends the tab. Audited like opening a terminal, naming the container.

Not done here: a shell in Docker Desktop's containers (it needs a terminal on this PC, which Remotely doesn't have),
compose stacks as a whole (the Compose project shows on each container), creating containers, and image builds.

### Dashboard: history, alerts and layout

- **History** (MO-06): once a minute the dashboard writes, in one go, an average of each running VM's host-side
  readings, each watched host's guest readings and this PC's CPU, RAM and paging files, with the minute's lowest and
  highest CPU and its highest memory, load and fullest disk. The charts' range picker (Live, 1 h, 6 h, 24 h, 7 d) reads
  it in points of 1 minute (up to 6 hours), 5 minutes (a day) or 30 minutes (a week) and carries on with the live
  rounds; over a range, a chart widget's CPU also shows each point's highest reading. It is kept 7 days by default
  (Settings, General, **Dashboard history**: 1, 3, 7, 14 or 30 days) and pruned at start and daily with the alert
  list's resolved alerts. It stays on this PC: no export carries it. A VM or host takes about 180 bytes a minute, so 50
  VMs and 20 watched hosts running around the clock for a week take about 125 MB, and ten VMs on working days with five
  watched hosts about 15 MB.
- **Alerts** (MO-07): a rule watches CPU, memory, disk or swap above a threshold for a while, a watched host that
  can't be reached, or a VM that stopped with no Remotely job on it (powered off, suspended or crashed outside the
  app), on every VM, one VM, a tag, every watched host, one watched host or this PC, as a warning or critical. Rules
  run on every round; an alert resolves after a minute back under its threshold. Windows notifies at most once per rule
  and target in half an hour, one notification for the alerts of a round, masked while presenting. Built-in rules, on:
  a VM stopped without a Remotely action, a watched host's disk above 85% for 5 minutes, a watched host unreachable for
  5 minutes, this PC's memory above 90% for 5 minutes; off until you turn them on: a VM's CPU above 90% for 5 minutes,
  a VM's memory above 95% for 10 minutes and a watched host's CPU above 90% for 5 minutes (builds and caches push these
  high on purpose). The Rules button on the alert list edits them. Rule changes and acknowledgements are audited, and
  the read-only lock refuses them. Desktop only: no email, Teams or Slack.
- **Layout** (MO-16): **Customize** adds, removes, moves and resizes the widgets (the overview grid, host capacity,
  this PC's memory, the alerts, a watched host's services, and charts of a VM, a watched host or this PC) on a grid of
  four columns: drag a widget's handle or press the arrow keys on it, drag its corner or pick its size. **Save** keeps
  the layout for this workspace (audited); **Reset to default** brings back the standard dashboard. The services widget
  reads a watched host's services once a minute on the dashboard's own connection to it, so it adds no logins; a host
  that isn't watched shows nothing until you watch it. Widgets read only while the dashboard shows and the window is
  visible, and none while you customize.

### Search, map, status bar and notifications

0.5.0 (QL-20 to QL-25):

- **Search** (QL-20): type in the Ctrl+K palette to find VMs (by name, IP, tag, guest OS), sessions (name, host, the
  address and name they last reached, user, tag), containers, launch templates, sizes, images, commands (favourites and
  the library) and settings (by their cards' names and what they cover, such as "vmrun" or "idle lock"), with the pages
  and actions. Every word has to match; names count most, then addresses, tags and details, and the best match is first,
  so Enter takes it. Choosing a VM or session shows its actions as before; anything else opens where it lives. Search
  reads only what Remotely already has, once per opening of the palette: containers are the ones the Containers page
  read last (listing them logs in, and search never does), and it polls nothing.
- **Map** (QL-21, Ctrl+0): this PC, the networks its VMs are on (Workstation's VMnets and VirtualBox's NAT, bridged,
  host-only, NAT and internal networks, from each VM's settings), the VMs, the sessions that reach them, the jump hosts
  on the way and the tunnels open on their terminals, in columns from left to right. Read only: click a node to open
  it; pointing at one lights up what it connects to. Sessions show when they reach a VM, go through or are a jump host,
  or have a tunnel open; a switch shows the rest. Opening the map reads no VM file it has read before; **Read the VMs
  again** reads every one. Presentation mode masks the map like every other page.
- **Status bar** (QL-22): along the bottom, the vault's lock countdown, the jobs running, the tunnels open, the open
  alerts and the update state; each opens what it is about. It reads nothing on its own: the countdown starts again
  each time you type or click.
- **Notification centre** (QL-25): the bell at the right of the status bar lists what notified since Remotely started:
  metric alerts (fired and resolved), terminal alert rules, long commands that finished, jobs that finished or failed,
  an update, and toasts worth keeping (protected targets skipped, a VM still running after its shutdown, a canary
  waiting). Each entry opens what it is about; read and unread, Mark all read, Clear. The list is kept in memory, not
  on disk: jobs and alerts stay in Activity and on the dashboard with their own retention, and a terminal's lines are
  written to disk only by a session log you turn on. Its text is redacted like the audit log's.
- **First-run wizard** (QL-23): on a PC with no vault and no session, Remotely offers to find Workstation and
  VirtualBox, create the vault (Windows unlock off unless you turn it on), add folders of VMs and import sessions.
  Each step is optional and saves exactly what Settings, the Vault page and the Sessions page would. **Skip for now**
  remembers it on this PC; Settings, General, **Setup guide** opens it again.
- **Density and shortcuts** (QL-24): Settings, General, **Appearance** has Comfortable (the default) and Compact
  spacing, kept on this PC like the theme. Ctrl+/ (Ctrl+Shift+/ inside a terminal, where Ctrl+/ is the shell's) lists
  every keyboard shortcut, with a filter.

### Host details

MO-13, MO-14 and MO-15 (0.4.0): what a VM or an SSH host is, and what an admin checks first. All of it reads only: no
approval, nothing audited, nothing changed on the host, and the read-only lock doesn't stop it.

- **SSH hosts (MO-13)**: **Host details…** in a session's menu (Sessions page, the Terminal page's tree) or the
  dashboard's drill-down. The System tab shows the OS (`/etc/os-release`, or `/etc/redhat-release` on old hosts),
  kernel and architecture, host name, virtualization (`systemd-detect-virt`, or lscpu's hypervisor), CPU model with
  sockets, cores and threads (`lscpu`, or `/proc/cpuinfo` without it), memory and swap (`/proc/meminfo`,
  `/proc/swaps`), disks and partitions (`lsblk`, in JSON or the `KEY="value"` form older util-linux prints) and local
  filesystems with use (`df`; network mounts are left out because a dead one can hang df), and when it last booted.
  The facts are read on an exec channel, never typed into a shell, so nothing shows in a terminal, its log, MultiExec
  or the long-command notifications. They are read when a terminal to the session connects (on that terminal's own
  connection, unless they are less than 10 minutes old), by the dashboard on its kept connection when they are more
  than 6 hours old, and on **Refresh**. The latest read is kept per session with its time, so it shows while the host
  is offline. Refresh with no open terminal and no dashboard connection logs in once with the saved login and keeps
  that connection for 3 minutes for the next read; it closes with the panel.
- **Admin (MO-14)**: the Admin tab reads, when you open it or press Refresh, running and failed services (systemd, or
  OpenRC's `rc-status` and SysV's `service --status-all` without it), listening ports (`ss`, or `netstat`; programs
  show only for the login user's own sockets, since Remotely doesn't use sudo here, and the tab says so), who is
  logged in and from where, the last boot and recent boots and shutdowns (`last -x`), and the top 10 processes by CPU
  and by memory (`ps`; program names only, never command lines, which can hold passwords). **Check for updates** lists
  pending packages from apt's lists as they are (it says when they were last refreshed; refreshing needs root) or from
  dnf, which refreshes its metadata first when it is old, so it can take a minute or two (Remotely waits up to 2½
  minutes). The usual fixes are commands to copy (restart a service, its log, kill a process, upgrade), never run from
  here. Every command the tabs use classifies as read-only under the default approval rules, and a test checks it.
- **VMs (MO-13)**: the VM details panel's **System** tab reads the VM's files when it opens: vCPUs and cores per
  socket, memory, firmware, VMware's hardware version, each virtual disk with its provisioned size (from the VMDK
  descriptor or sparse header, a VDI header, a VHD footer or a qcow2 header) and its size on this PC (a snapshot's
  delta disk counts its parents down to the base), and each network adapter with its connection, card and MAC. The
  guest OS comes from VMware Tools (`guestInfo.detailed.data`: the distribution and kernel) or the Guest Additions.
  What was read is kept, so the tab still shows it (with why) when the files can't be read. **From the guest** shows
  a linked session's own facts. A disk, extent or parent disk named on a network share or a device path is never
  opened (Windows would send your sign-in there): it shows its path with a note and no sizes, so a VM kept on a share
  shows its disks as not read. A .vmx over 4 MB or a disk descriptor over 1 MB is reported, never read in part.
- **Dashboard**: each row says "4 vCPU · 8 GB · Ubuntu 24.04" under its address (a host's from its stored facts).
- **Memory charts (MO-15)**: the drill-down's memory chart draws what there is as a dashed line next to what is in
  use: a VM's configured RAM next to its process's working set (and the guest's own use when watched), a host's total
  next to its use. Linux hosts get a swap chart. **This PC's memory** under the capacity panel draws RAM in use
  against all of it, and the paging files in use against their size (read with the host counters each round:
  `GlobalMemoryStatusEx` and the system's page file list, a few microseconds); the RAM card adds the paging file and
  the commit charge. Each chart's legend shows the latest values, and the hovered ones under the pointer.

Not done here: killing processes or restarting services from Remotely (copy the command), sudo for these reads, network
mounts in the filesystem list, VirtualBox snapshot chains on disk (a differencing image counts alone, and says so), and
Windows hosts over SSH.

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
  `user@host`, `C:\Users\<name>\…`, `/home/<name>` and MAC addresses (`mac-1`, for a VM's adapters). Session and VM
  names are labels and stay visible unless they
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
  forwards, settings, approval rules, how long job outputs are kept and Purge now, replacing or removing trusted host
  keys, turning MultiExec on). The daily purge of old job outputs still runs. An approval asked
  before the lock came on waits until it is off. Still allowed, because they change nothing outside this PC or are part
  of connecting: reading everything, connecting, typing into one terminal (it is your own shell), trusting a new host's
  key on first use, downloads and saved or logged output (they only read from the host and write files on this PC),
  exports, the vault's lock and unlock, update checks, stopping tunnels and cancelling jobs. Disabled buttons say why,
  each page says what the lock blocks there, and turning the lock off while presenting asks once.

Disabled buttons say why they are disabled (QL-08), in a tooltip or under the menu item.

## Installing

Download `Remotely_<version>_x64-setup.exe` from the [latest release](https://github.com/khilfi/remotely/releases/latest)
and run it. It installs for your Windows account only, so it needs no admin rights. After that, Remotely updates itself
from the releases (see [GitHub update token](#github-update-token)).

The installer isn't code-signed (Authenticode) yet, so Windows SmartScreen may show **"Windows protected your PC"**
with an unknown publisher when you run it by hand. Before you let it run, check that the file is the one the release
published: each release page lists the installer's SHA-256 under **Checksum**. In PowerShell, in the folder you
downloaded it to:

```powershell
Get-FileHash .\Remotely_<version>_x64-setup.exe -Algorithm SHA256
```

If the hash matches the release page, choose **More info**, then **Run anyway**. If it doesn't match, don't run it.
Automatic updates don't need this check: the app verifies every update's signature against its built-in public key
before installing it (see [Update signing](#update-signing)).

## Prerequisites

- Windows 10 or 11 (x64) with VMware Workstation Pro 17 or later, Oracle VirtualBox 7.0 or later, or both
- Node.js 24 and npm (`.node-version` has the exact version CI and releases use)
- Rust (`x86_64-pc-windows-msvc`) via rustup, plus the Microsoft C++ Build Tools ("Desktop development with C++").
  `rust-toolchain.toml` pins the version; rustup installs it on the first build.
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
folders, and `VBoxManage.exe` the same way (Settings, `REMOTELY_VBOXMANAGE`, the registry's `InstallDir`, then
`C:\Program Files\Oracle\VirtualBox`). `ovftool.exe`, for OVA and OVF deploys on Workstation, comes from Settings,
then `REMOTELY_OVFTOOL`, then the `OVFTool` folder beside `vmrun.exe`.

Logs and crash reports are in the `logs` folder of the same data folder (`%LOCALAPPDATA%\com.remotely.desktop\logs`,
`...desktop.dev\logs` for a development build, or `logs` under `REMOTELY_DATA_DIR`); Settings, About opens it:

- `remotely.YYYY-MM-DD.log`: one file a day, the last 7 kept. `RUST_LOG` changes what is logged (default
  `info,sqlx=warn,tao=warn,wry=warn`).
- `crash-YYYYMMDD-HHMMSS.txt`: written when the app panics (a release build then stops), with the version, thread,
  message, place and backtrace. The last 7 are kept.
- Neither holds a password, key or token: the core never logs one (`crates/core/tests/log_fields.rs` checks every log
  call, `src-tauri/tests/log_secrets.rs` a run that uses vault secrets), and panic and UI error text is shortened and
  redacted first.

When the app can't start, a message box says why and where the log is. A database that won't open or migrate (damaged,
or last used by a newer version) can be set aside, renamed to `remotely-unopenable-<time>.db` with its `-wal` and `-shm`
files, to start with an empty one; nothing is deleted, and saying No quits without changing anything. A release build
runs once: starting it again brings the open window forward. Reloading the window (a crashed page's "Reload Remotely")
closes the terminals, tunnels and approvals the old page had, so nothing goes on unseen; F5, Ctrl+R and the developer
tools keys are off in a release build.

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
| UI and release-script tests          | `npm test`                                                                            |
| Dependency scan (as CI runs it)      | `cargo deny --locked check advisories bans sources`, `npm audit --omit=dev`           |
| Format the UI                        | `npm run format`                                                                      |
| Opt-in test against real Workstation | `REMOTELY_IT=1 cargo test -p remotely-core --test workstation_it`                     |
| Opt-in test against real VirtualBox  | `REMOTELY_IT=1 cargo test -p remotely-core --test virtualbox_it`                      |

Tests use the fake adapters in `crates/core/src/fakes.rs` and never touch a real VM or host. The opt-in tests only read.
The Workstation one reads Workstation's library, `vmrun list`, the Tools state and IP address of running VMs, and each
VM's snapshots (it checks that the `.vmsd` lists the same snapshots as `vmrun listSnapshots`). The VirtualBox one lists
VirtualBox's VMs, then reads only those named `it-…`: `showvminfo`, their snapshots (checked against `VBoxManage snapshot
list`), the Guest Additions' IP and OS name, and each running one's process.

## Release

1. Bump the version in `package.json`, `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json` (they must match).
2. Commit and push `main`, then `git tag -a vX.Y.Z -m "<release notes>"` and `git push origin vX.Y.Z`. The tag must be
   on a commit `main` contains. Its message becomes the release notes, which installed apps show in their update
   banner.
3. `.github/workflows/release.yml` runs two jobs:
   - **Build** (Windows, no secrets): stops if the tagged commit isn't on `main`, if the tag and the three versions
     differ, or if the updater public key in `tauri.conf.json` is still the placeholder. Then it builds the NSIS
     installer (per-user, so installing and updating need no admin rights) with `--locked`, the Node version in
     `.node-version`, the Rust version in `rust-toolchain.toml` and no cache, and keeps it as a workflow artifact. The
     build needs no signing key: `bundle.createUpdaterArtifacts` is off.
   - **Publish** (Linux, in the protected `release` Environment): waits for your approval. Open the run under
     **Actions**, check that it is the tag you pushed, then **Review deployments → release → Approve and deploy**. It
     signs the installer with the key from the Environment (`tauri signer sign --app-version`), checks the signature
     against `plugins.updater.pubkey` and that it names this installer and version
     (`scripts/verify-update-signature.mjs`), and only then creates a **draft** release with the installer, its `.sig`
     file and `latest.json` (`scripts/publish-release.mjs`). The release page's text is the tag message followed by
     the installer's SHA-256 and how to check it (see [Installing](#installing)); `latest.json`'s notes, which the
     update banner shows, are the tag message alone. Before it uploads `latest.json`, it checks it the way
     installed apps read it and fetches the installer back through its URL. If any check fails, the draft is deleted.
     A signature check failure means the key in the Environment doesn't pair with the public key.
4. Smoke-test the installer from the draft, then publish it. Installed apps only see published releases; they check at
   start and every 24 hours (FD-14), and installing asks first.

Installed apps (0.4.1 and later) refuse an update whose signature names another installer or version than
`latest.json` announces, so an old signed installer can't be offered as a newer version (`requireSignedVersion` in
`tauri.conf.json`, and `check_signed_release` before an update is offered).

`.github/workflows/ci.yml` runs on every push to `main` and every pull request, except changes to documentation only
(Markdown files anywhere, `docs/`): UI lint, tests and build; a dependency scan on Linux (`cargo deny` with `deny.toml`
for advisories, banned crates and sources, `npm audit --omit=dev`, and `npm audit signatures`); and Rust fmt, clippy and
tests. `.github/workflows/secrets.yml` runs a gitleaks scan of the full history on every push to any branch and every
pull request, documentation included. Dependabot (`.github/dependabot.yml`) opens one grouped pull request a week each
for Cargo, npm and GitHub Actions.

When the dependency scan fails on a new advisory: update the crate or package if a fixed version exists
(`cargo update -p <crate>`, `npm update <package>`). If none does and the advisory doesn't apply to how Remotely uses
it, add its ID to `ignore` in `deny.toml` with the reason, as the existing entries do.

### Release settings on GitHub

Set these once, in this order, as the repository owner. They keep the update-signing key away from every job but the
publish job, and away from any workflow pushed to a branch. They rely on the repository being public: on GitHub Free a
private repository has no Environments, required reviewers or rulesets.

1. **Create the Environment.** **Settings → Environments → New environment**, name it `release`, then **Configure
   environment**:
   - **Deployment protection rules:** tick **Required reviewers** and add yourself. Leave **Prevent self-review** off
     (you approve your own releases), and untick **Allow administrators to bypass configured protection rules**.
     **Save protection rules.**
   - **Deployment branches and tags:** choose **Selected branches and tags**, then **Add deployment branch or tag
     rule**, **Ref type: Tag**, **Name pattern:** `v*`. Add no branch rule.
2. **Move the signing secrets into it.** Under **Environment secrets**, **Add environment secret**
   `TAURI_SIGNING_PRIVATE_KEY` (the private key file's content, as before) and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. Or
   from a terminal, with the key file outside the repository:
   `gh secret set TAURI_SIGNING_PRIVATE_KEY --env release < <path-to-key>`, then
   `gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD --env release` (it asks for the value).
3. **Delete the repository-level copies**, which a workflow on any branch can read: **Settings → Secrets and variables
   → Actions → Repository secrets**, delete both (or `gh secret delete TAURI_SIGNING_PRIVATE_KEY` and
   `gh secret delete TAURI_SIGNING_PRIVATE_KEY_PASSWORD`). `gh secret list` should then show neither, and
   `gh secret list --env release` both.
4. **Restrict who can create release tags.** **Settings → Rules → Rulesets → New ruleset → New tag ruleset**: name
   "Release tags", **Enforcement status: Active**; **Bypass list → Add bypass → Repository admin** (that is you);
   **Target tags → Add target → Include by pattern** `v*`; tick **Restrict creations**, **Restrict updates** and
   **Restrict deletions**; **Create**. Nobody else, and no workflow token, can then push, move or delete a `v*` tag.
5. Optional: **Settings → Actions → General → Require actions to be pinned to a full-length commit SHA** (every
   workflow here already is), and **Settings → Advanced Security →** turn on **Dependabot alerts** and **Dependabot
   security updates**.

The first tag after these settings is the real test of the release workflow: check that the build job's log shows no
signing key, that the publish job waits for your approval, and that the draft holds the installer, its `.sig` and
`latest.json`.

### GitHub update token

The repository and its releases are public, so Remotely checks for and installs updates **without a token**. The token
is optional. It is worth having when:

- **Many machines share one internet address** (an office or a customer site behind one NAT). GitHub allows 60 API
  calls an hour from one address without a token, and each check makes one. When that limit is used up, Remotely waits
  until GitHub's reset, checks once more, and Settings and **Check for updates** say until when. A token has a limit
  of its own (5,000 an hour).
- **The repository goes private again.** GitHub then hides its releases from checks without a token, and the banner
  says "Updates need a GitHub update token".

Each machine keeps its token in its vault. While the vault is unlocked, checks and installs use it; while it is locked,
they go without it (and ask you to unlock it only if GitHub doesn't show the releases without a token).

Older copies: 0.2.1 to 0.4.2 still need a token to update, so keep theirs valid until they have installed a version
that reads releases without one. Copies on 0.2.0 or older don't know about the token: install a newer version by hand
once on each machine (download the installer from the release page).

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

Without a token, update checks read the public releases. If GitHub doesn't show them (the repository went private
again), checks don't fail quietly: the banner and Settings say a token is needed, or, with a token in the locked vault,
the check runs again once the vault is unlocked.

**Replace it** before it expires, or at once if it may have leaked:

1. On GitHub, open the token and choose **Regenerate token** (same settings, new value; the old value stops working
   at once), or make a new one as above.
2. In Remotely, **Settings → Updates → Replace**, paste the new token and **Save**.
3. If you made a new token, delete the old one on GitHub.

Once a token has expired or been revoked, the banner says so ("The GitHub update token expired on …") until it is
replaced or removed. **Remove** deletes the token from the vault, and checks go on without one; delete it on GitHub as
well.

What the app sends: without a token, nothing but the release lookup goes to `api.github.com`, with no `Authorization`
header; `latest.json` and the installer come from the release's public download links on `github.com`. With a token,
it sends the token only to `api.github.com`, to find the latest published release, then to fetch that release's
`latest.json` and installer from their API download URLs. GitHub answers those with a redirect to its file storage,
and the token is not sent there, nor ever to `github.com`. Either way, every update is checked against the signing
public key before it installs. The token never appears in logs, error messages, the audit log, exports or the UI.

### CI minutes

The repository is public, so GitHub Actions runs on standard GitHub-hosted runners don't use the account's minutes.
Runs still take time, so keep them lean. If the repository ever goes private again, they bill against the monthly
allowance (2,000 minutes on GitHub Free), Windows jobs count double and each job is rounded up to whole minutes:

| Workflow      | Runs on                                           | Runner time per run                         | Billed if private |
| ------------- | ------------------------------------------------- | ------------------------------------------- | ----------------- |
| `ci.yml`      | every pull request push and every merge to `main` | about 6 to 8 minutes (the Windows Rust job) | about 12 to 16    |
| `secrets.yml` | every pull request push and every merge to `main` | about 1 minute (Linux)                      | about 1           |
| `release.yml` | every `v*` tag                                    | about 14 minutes (Windows)                  | about 28          |

To keep runs quick: documentation-only changes skip `ci.yml`; a new push to a branch cancels the run it supersedes, so
push when a change is ready rather than after every small commit; and group documentation edits.

### Update signing

Updates are signed with a key pair. Only the public key is in the repo (`plugins.updater.pubkey` in
`src-tauri/tauri.conf.json`). The private key and its password live outside the repo: in a password manager, and in the
`release` Environment's secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, which only the
release workflow's publish job reads.

A local `npm run tauri build` needs neither: `bundle.createUpdaterArtifacts` is off, so it builds an unsigned installer.
Don't put the key in your environment or shell profile. If you ever have to sign by hand (the key rotation below), sign
the built installer with the key file, which asks for the password, then check the result:

```bash
npx tauri signer sign -f <path-to-key-outside-the-repo> --app-version X.Y.Z target/release/bundle/nsis/Remotely_X.Y.Z_x64-setup.exe
```

```bash
node scripts/verify-update-signature.mjs --version X.Y.Z target/release/bundle/nsis/Remotely_X.Y.Z_x64-setup.exe.sig
```

`--app-version` is required: installed apps refuse a signature that doesn't name its version.

### Signing key compromise or loss

Installed apps trust exactly one public key: the one in the version they run. Moving them to a new key takes one
release signed with the **old** key whose `tauri.conf.json` holds the **new** public key.

**If the key may have leaked** (with or without its password):

1. Delete the `release` Environment's two secrets at once. Check **Releases** for drafts or releases you didn't make,
   and the Environment's deployment history for runs you didn't approve; delete anything unknown.
2. A malicious update also needs the right to publish a release here: installed apps read only this repository's
   latest published release. Change the GitHub password, and review sessions, personal access tokens, collaborators,
   deploy keys and the tag ruleset.
3. Rotate the key as below, quickly: until an install takes the rotation release, it still trusts the old key.
4. If an unknown release was ever published, reinstall Remotely by hand on every machine that may have taken it.

**To rotate the key** (after a leak, or as planned):

1. Generate a new pair outside the repository, with a strong password:
   `npx tauri signer generate -w <path-outside-the-repo>`. Save the key file and the password in the password manager.
2. Put the new public key (the `.pub` file's content) in `plugins.updater.pubkey`, bump the version, commit, push
   `main`, then tag and push. The build job builds the installer; reject the publish job's deployment (the Environment
   still holds the old key, which no longer matches `tauri.conf.json`). Download the installer:
   `gh run download <run-id> -n installer`.
3. Sign it with the **old** key file as above, and check it against the old public key: add
   `--pubkey <the old public key, as tauri.conf.json had it>` to the `verify-update-signature.mjs` command.
4. Create the draft from your machine, checked against the old key:
   `GITHUB_REPOSITORY=<owner>/<repo> GITHUB_TOKEN=$(gh auth token) node scripts/publish-release.mjs --tag vX.Y.Z --installer Remotely_X.Y.Z_x64-setup.exe --notes <notes file> --pubkey <the old public key>`.
5. Check that an installed copy updates to it, then publish it.
6. Replace the Environment's secrets with the new key and password: releases from now on are signed with it. Destroy
   the old key, or keep it offline if it didn't leak.

**If the key or its password is lost**, installed apps can't verify anything new, and no rotation release is possible.
Generate a new pair (step 1 above), put its public key in `tauri.conf.json`, set the Environment's secrets and release
as usual. Then install that release by hand once on every machine (download the installer from the release page and
run it); the data, the vault and the update token stay. Auto-update works again from there.

## Layout

```text
crates/core/          Rust core, no Tauri types (reusable by a future CLI or plugins, FD-12)
  migrations/         sqlx migrations (SQLite, WAL mode)
  src/                command bus, policy engine, job runner, adapters, metrics, vault, sessions, store
  tests/              end-to-end tests with fake adapters; opt-in Workstation and VirtualBox tests
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

| Module             | Path                                                              | PRD requirements                                                                                                                                    | State                                                                                                                                                                                                                                                          |
| ------------------ | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Command bus        | `crates/core/src/command_bus.rs`                                  | AP-01 (saves rules), AP-02, AP-03, AP-06, VM-02, VM-03, VM-04, BX-02, SS-07, SS-08, SS-10, FD-14                                                    | Working: the only way to enqueue a job (MultiExec lines, uploads and tunnels too); checks snapshot names; audits rule changes; approvals expire after 15 minutes and are asked again when a target became Prod or protected                                    |
| Containers         | `crates/core/src/containers/`, `adapters/containers/`             | CT-01, CT-02, AP-02, FD-07                                                                                                                          | Working: marked hosts and Docker Desktop, reads on kept connections, both CLIs' JSON parsed, changes on the bus with tiers, impact preview, shells in containers                                                                                               |
| Policy engine      | `crates/core/src/policy/`                                         | AP-01, AP-04, SS-06 (Prod raises the tier), SS-07, SS-08, SS-10, BX-06, VM-05, VM-07 (warnings add a confirm)                                       | Working; every tier rule has a unit test; a MultiExec line it could not follow, replacing a file or a tunnel other computers can use is at least a confirm                                                                                                     |
| Impact preview     | `crates/core/src/impact.rs`                                       | AP-02                                                                                                                                               | Working: state, uptime (from `vmware.log`, or VirtualBox's state change time) and snapshot count per VM; logged-in users and dependent VMs later                                                                                                               |
| Snapshot reads     | `crates/core/src/snapshots.rs`                                    | VM-04, VM-05                                                                                                                                        | Working: tree order, 30-day flag, safety snapshot names                                                                                                                                                                                                        |
| Audit export       | `crates/core/src/export.rs`                                       | AP-05                                                                                                                                               | Working: CSV with hashes, secrets redacted, formula cells guarded                                                                                                                                                                                              |
| Job runner         | `crates/core/src/jobs.rs`                                         | VM-03 (shutdown wait), VM-05, VM-06, AP-03 (countdown), AP-04, BX-02, BX-04, SS-08, SS-10, FD-14 (runs alone)                                       | Working; sends a MultiExec line's held Enter to its terminals; carries out uploads through a terminal                                                                                                                                                          |
| VMware adapter     | `crates/core/src/adapters/vmware.rs`                              | VM-01, VM-02, VM-03, VM-04, AP-02                                                                                                                   | Library, folder scan, `.vmx` and `.vmsd` reading, `vmware.log` start time, `vmrun` list, power and snapshots; vmrest later                                                                                                                                     |
| VirtualBox adapter | `crates/core/src/adapters/virtualbox.rs`, `hypervisor.rs`         | VM-18                                                                                                                                               | Working: `VBoxManage` list, `showvminfo`, guest properties (one `enumerate` per VM), power and snapshots; snapshot times from the `.vbox`; each VM routed to its hypervisor by its key                                                                         |
| Remote adapter     | `crates/core/src/adapters/remote.rs`, `remote/`                   | SS-03, SS-05, SS-07, SS-08, BX-02, BX-07, MO-02                                                                                                     | Working: jump host chains, terminal shells, SFTP and port forwards (local, remote, SOCKS) on a terminal's connection, bulk exec with sudo, kept connections for guest metrics                                                                                  |
| Host counters      | `crates/core/src/adapters/host_counters.rs`, `paging.rs`          | MO-01, MO-04, MO-15, VM-07                                                                                                                          | Working: host RAM, CPUs, CPU times, free disk, paging files and commit charge, and each VM process's (`vmware-vmx.exe`, `VirtualBoxVM.exe`, `VBoxHeadless.exe`) CPU, working set and I/O                                                                       |
| Host details       | `crates/core/src/host_details/`, `adapters/vm_hardware.rs`        | MO-13, MO-14                                                                                                                                        | Working: SSH hosts' OS and specs (terminal, dashboard, Refresh; stored), admin reads on demand, VMs' virtual hardware from their files (stored)                                                                                                                |
| Updater            | `crates/core/src/adapters/updater.rs`, `github.rs`                | FD-14                                                                                                                                               | Works: this repository's public GitHub Releases, without a token or with the optional one from the vault; install is a Medium-tier job that runs alone                                                                                                         |
| Inventory          | `crates/core/src/inventory.rs`                                    | VM-01, VM-02, VM-18, SS-06 (VM labels)                                                                                                              | Every VM from the library, chosen folders and `vmrun list`, and VirtualBox's registered VMs; one refresh at a time, requests meanwhile share the next; filters; audited environment labels                                                                     |
| VM settings        | `crates/core/src/vm_settings/`, `adapters/vmx_file.rs`            | VM-11, VM-12, VM-15, VM-16, VM-23, VM-24                                                                                                            | Working: the Settings tab's full read of both hypervisors; .vmx edits after a backup (unknown keys kept), vdiskmanager and VBoxManage disk changes, devices on running VMs, bulk resize, delete, rename, add an existing VM, Open console (audited), ISO drops |
| Capacity check     | `crates/core/src/capacity.rs`                                     | VM-07, MO-04                                                                                                                                        | Working: host RAM vs assigned RAM, free disk on VM drives; the dashboard's capacity panel                                                                                                                                                                      |
| Metrics collector  | `crates/core/src/metrics/`                                        | MO-01, MO-02, MO-03, MO-04, MO-15                                                                                                                   | Working: host-side source every 5 s, SSH guests every 5, 15, 30 or 60 s (one `grep` of /proc, `df` once a minute), 30 minutes of history in memory (allocated memory, swap, this PC's paging files), collector cost                                            |
| Dashboard history  | `crates/core/src/metrics/history.rs`, `store/metrics.rs`          | MO-06                                                                                                                                               | Working: 1-minute averages of VMs, watched hosts and this PC written once a minute; ranges of 1 h to 7 d in buckets; kept 7 days by default, pruned daily and audited; the UI's range picker                                                                   |
| Alerts             | `crates/core/src/alerts/`, `store/alerts.rs`                      | MO-07                                                                                                                                               | Working: rules (threshold and duration, unreachable, stopped outside the app) run each round; alert list with acknowledge; Windows notifications with a cooldown; built-in rules; audited edits                                                                |
| Notifications      | `crates/core/src/notifications.rs`, `src/lib/notifications*.ts`   | QL-25                                                                                                                                               | Working: the notification centre's history in memory, redacted, per workspace; read, unread and clear                                                                                                                                                          |
| Dashboard layout   | `crates/core/src/dashboard.rs`, `src/components/Dashboard*.tsx`   | MO-16                                                                                                                                               | Working: widgets on a four-column grid, saved per workspace and audited; drag, keyboard and size menu; services widget on the kept connection                                                                                                                  |
| Schedules          | `crates/core/src/schedules/`, `command_bus/standing.rs`           | VM-14, VM-27                                                                                                                                        | Working: snapshot (keep the last N), start, shut down, suspend, resume and idle auto-suspend; hourly, daily, weekly in local time across daylight saving; standing approvals at save; missed runs reported; chain warnings                                     |
| Background logins  | `crates/core/src/login_guard.rs`                                  | MO-02, CT-01                                                                                                                                        | Working: refused logins, sudo and changed keys park a host until a change or Retry; 10 logins per host an hour                                                                                                                                                 |
| Vault              | `crates/core/src/vault/`                                          | SS-04, AP-06                                                                                                                                        | Working: AES-256-GCM per item; Argon2id key wrapping, DPAPI opt-in; new data key per password change; idle lock from user activity; vault passwords go only where they already go                                                                              |
| Session library    | `crates/core/src/sessions.rs`, `forwards.rs`                      | SS-01, SS-06, SS-07, QL-04                                                                                                                          | Working: folders, tags, colours, search, vault credentials, jump host chains, saved port forwards, audited changes, the tree                                                                                                                                   |
| Session import     | `crates/core/src/import/`                                         | SS-02, QL-10                                                                                                                                        | Working: PuTTY (registry or a .reg export), MobaXterm, OpenSSH config and CSV, with a preview of duplicates and name conflicts; a format guide (from the parsers' own tables) and a sample file for each                                                       |
| Export and import  | `crates/core/src/transfer/`                                       | FD-07                                                                                                                                               | Working: one encrypted file per export; preview with per-item conflict choices; audited with counts and the file path                                                                                                                                          |
| Spec catalogue     | `crates/core/src/catalog/`                                        | VM-19, VM-20, VM-21, FD-07                                                                                                                          | Working: built-in and own sizes, OS profiles, images (checked and hashed, shares refused), launch templates with their problems and a plan per VM for deploy; audited                                                                                          |
| Deploy             | `crates/core/src/deploy/`                                         | VM-10, VM-21, VM-22, AP-02                                                                                                                          | Working: deploys from a template or Custom values (golden VM clone, cloud image with cloud-init, ISO, OVA/OVF) and bulk clones, one job step per VM with cleanup after a failure or cancel; preview with disk space; Medium, High from 5 VMs                   |
| SSH key manager    | `crates/core/src/ssh_keys.rs`                                     | SS-09                                                                                                                                               | Working: Ed25519 or RSA 4096 keys in the vault; public keys; attach to sessions; push to authorized_keys as a bus command                                                                                                                                      |
| Terminal           | `crates/core/src/terminal/`                                       | SS-03, SS-07, SS-08, SS-10, SS-11, QL-02, QL-03, QL-06, QL-07                                                                                       | Working: supervised panes through jump hosts (reconnects spread at random, fast then slow, woken by a resume or a network change), tunnels on the bus, quick connect, host name and IP, output saved or logged, vault passwords typed at prompts, MultiExec    |
| MultiExec          | `crates/core/src/terminal/multiexec.rs`                           | SS-10, QL-07, QL-12                                                                                                                                 | Working: keys to the picked terminals, line buffer, Enter held and rated on the bus, password prompts and full-screen programs passed through, never logged                                                                                                    |
| Recording          | `crates/core/src/terminal/record.rs`                              | QL-12                                                                                                                                               | Working: each line's output per terminal until the prompt is back, escapes removed, secrets scrubbed, grouped and exported through Compare's code, kept in memory                                                                                              |
| File transfer      | `crates/core/src/terminal/files.rs`, `folder.rs`, `shell_user.rs` | SS-08, QL-09                                                                                                                                        | Working: the shell's folder (OSC 7, a hidden prompt hook for bash and zsh), listing, downloads (audited), uploads on the bus, transfers with cancel and retry                                                                                                  |
| Compare output     | `crates/core/src/bulk.rs`                                         | BX-01, BX-03, BX-05                                                                                                                                 | Working: hosts from picked tabs and tree sessions, results grouped by output, diff, CSV, JSON and HTML export                                                                                                                                                  |
| Command panel      | `crates/core/src/snippets/`                                       | BX-08, QL-13                                                                                                                                        | Working: favourite commands in folders (audited), a built-in Linux library (Troubleshoot runbooks, 30 area groups, manual links), variables, marks from the policy engine                                                                                      |
| Reachability       | `crates/core/src/reachability.rs`                                 | QL-04 (MO-08 lite), SS-07                                                                                                                           | Working: TCP checks of the shown sessions, once per host and port, every 5 min; hosts with an open connection skipped, hosts down checked less often; the first jump host for sessions behind one                                                              |
| VM links           | `crates/core/src/vm_links.rs`                                     | QL-01, BX-01                                                                                                                                        | Working: sessions linked to VMs by guest IP (or a name resolving to it) or by hand; manual links kept; names looked up once at a time, never behind a jump host                                                                                                |
| Network adapter    | `crates/core/src/adapters/network.rs`                             | QL-01, QL-03, QL-04                                                                                                                                 | Working: DNS lookups (forward and reverse, with a time limit) and the TCP probe                                                                                                                                                                                |
| Store              | `crates/core/src/store/`, `crates/core/migrations/`               | AP-05, VM-01, VM-02, SS-01, SS-04, NFR Reliability                                                                                                  | Working: hash-chained audit log (text redacted, streamed), job journal (scripts and lines redacted), inventory, sessions, vault ciphertext, tags, saved filters; secure delete                                                                                 |
| Retention          | `crates/core/src/retention.rs`, `save_guard.rs`                   | BX-02, BX-05, SS-10, SS-11, AP-05                                                                                                                   | Working: job outputs and command text kept 30 days, 90 days (default), 1 year or forever; a purge at start and daily, Purge now, audited; compacting while no job runs; no save path writes into a Git working tree                                            |
| Fake adapters      | `crates/core/src/fakes.rs`                                        | Development safety                                                                                                                                  | One fake per outside system; the test SSH server has SFTP on a temp folder and forwards (direct-tcpip, tcpip-forward) with internal names                                                                                                                      |
| Presentation mode  | `crates/core/src/presentation.rs`, `src/lib/presentation*.ts`     | FD-03                                                                                                                                               | Working: masking by field and pattern in the DOM and in terminal output (same width), stand-ins in memory, saved and audited, a read-only lock enforced by the policy engine                                                                                   |
| Tauri shell        | `src-tauri/src/`                                                  | All IPC                                                                                                                                             | Working; QL-15: daily log file, crash reports, startup message boxes, one instance, a reload closes what the page had open (`diagnostics.rs`, `lib.rs`); SS-03 resume and network notifications (`wake.rs`)                                                    |
| UI                 | `src/`                                                            | FD-01, FD-03, FD-07, VM-01 to VM-06, AP-01 to AP-06, SS-01 to SS-06, SS-08 to SS-11, BX-01 to BX-08, MO-01 to MO-04, MO-13 to MO-15, QL-01 to QL-11 | All pages, the approval dialog with countdown, MultiExec, Compare output and Files here in the Terminal page, the dashboard with live uPlot charts, the Ctrl+K command palette                                                                                 |
