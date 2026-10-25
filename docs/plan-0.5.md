# Plan for 0.5.0

Agreed with the owner on 25 Oct 2026, after 0.4.3. Like `docs/plan-0.4.md`, it moves PRD items into scope and adds new
ones. Requirement IDs are the PRD's where one exists (VM-08, VM-10 to VM-12, VM-14 to VM-17, MO-06, MO-07, FD-02); new
ones continue the PRD's numbering (`VM-19` to `VM-27`, `MO-16`, `AP-08`), quality-of-life items continue `QL-xx`
(`QL-16` to `QL-25`), and conversion gets its own prefix (`CV-xx`). Commit messages start with these IDs.

## Decisions

| Question | Decision |
| --- | --- |
| How VMs are described | **Like a cloud provider**: *sizes* (instance types: CPU, RAM, disks), *images* (where the OS comes from) and *launch templates* (an image and a size, with network, SSH key, naming, count, folder, label, tags and after-deploy steps). Deploy runs a launch template; Custom sets every value by hand. |
| Built-in sizes | **Twelve**, from `gp.nano` to `gp.2xlarge` plus compute, memory and storage sizes (table below). Built-ins can't be edited; Duplicate makes an editable copy. The owner can add any number of their own. |
| Where the OS comes from | **All four**: clone a golden VM (full or linked, from one of its snapshots), a cloud image with cloud-init first-boot setup, an ISO install, and an OVA/OVF import. Plus **conversion** (CV-01 to CV-03). |
| Conversion | **Reads and writes other hypervisors' VM and disk formats** (Hyper-V, KVM/QEMU, Proxmox, ESXi, Xen, cloud imports). Three uses: import a foreign VM or disk as a new local VM, export a local VM to another hypervisor's format, and a standalone image tool (inspect, convert, verify) that makes no VM. Other hypervisors are still **not managed**: Remotely only reads and writes their files. |
| Conversion tools | The hypervisors' own tools first: `vmware-vdiskmanager` and `ovftool` (both ship with Workstation), `VBoxManage clonemedium`, `convertfromraw`, `import` and `export`. `qemu-img` for the formats those can't do (qcow2, VHDX), **only if the owner has installed it** (found like vmrun: a Settings path, `REMOTELY_QEMU_IMG`, the default folder). It is GPL-licensed, so Remotely doesn't bundle it. |
| Console | **Open the hypervisor's own window** (Workstation's tab with `vmware.exe <vmx>`, VirtualBox's `VirtualBoxVM --startvm <uuid> --separate`). No embedded console and no new network listener. VM-13 (live thumbnails) stays out; VirtualBox screenshots on demand are in. |
| Windows 11 guests | On **VirtualBox only** in 0.5.0 (its own vTPM and Secure Boot). Workstation's vTPM needs the VM encrypted with a password per VM; that stays out for now. |
| VirtualBox Extension Pack | **Never required.** Its licence needs payment for commercial use, so nothing depends on VRDE or its other features. |
| Extras | **In**: VM-08 stacks, VM-26 deploy capacity planner, VM-27 snapshot schedules, VM-16 waste finder, VM-14 scheduled power and idle VMs, VM-12 bulk resize and VM-10 bulk clone; QL-16 folder defaults, QL-17 highlight and alert rules, QL-18 search all scrollback, QL-19 saved MultiExec groups; MO-06 history on disk, MO-07 alerts, MO-16 custom dashboard layout; QL-20 global search, QL-21 topology map, QL-22 status bar, QL-23 first-run wizard, QL-24 density and shortcut sheet, QL-25 notification centre, ISO drag and drop; FD-02 customer workspaces and AP-08 change IDs. **Out**: favourites and recents, per-session notes, bulk session edit, trash, RDP, compose stacks, multi-container logs, image freshness, maintenance windows (AP-07), engagement reports, Ansible export, the CLI. |
| Releases | **One release, 0.5.0**, when every package below is merged. |

## Built-in sizes (VM-19)

Disks are thin (they take only what the guest writes) unless a template says thick.

| Size | vCPU | RAM | Disks | Good for |
| --- | --- | --- | --- | --- |
| gp.nano | 1 | 512 MB | 8 GB | tiny services, test boxes |
| gp.micro | 1 | 1 GB | 16 GB | jump host, DNS, NTP |
| gp.small | 1 | 2 GB | 20 GB | small web or agent host |
| gp.medium | 2 | 4 GB | 40 GB | general Linux server (the default) |
| gp.large | 2 | 8 GB | 60 GB | app server, Docker host |
| gp.xlarge | 4 | 16 GB | 100 GB | database, CI runner |
| gp.2xlarge | 8 | 32 GB | 200 GB | heavy lab, Kubernetes node |
| cpu.large | 4 | 4 GB | 40 GB | builds, load generators |
| cpu.xlarge | 8 | 8 GB | 60 GB | parallel builds |
| mem.large | 2 | 16 GB | 60 GB | caches, in-memory databases |
| mem.xlarge | 4 | 32 GB | 100 GB | databases, search |
| disk.large | 2 | 4 GB | 40 GB + 500 GB data disk | file server, backups, logs |

## Approval tiers

The PRD's tier table gains these rows. A Prod-labelled target moves each up one tier, as before, and protected VMs are
skipped.

| Action | Tier |
| --- | --- |
| Deploy 1 to 4 VMs (create, clone, import, convert into a VM) | Medium |
| Deploy 5 or more VMs, or VMs labelled Prod | High |
| Edit CPU, RAM, network cards, firmware, shared folders or the name (VM off) | Medium |
| Attach or eject an ISO; connect a network card (running) | Low |
| Disconnect a network card of a running VM | Medium |
| Add a disk; compact or defragment a disk; install or upgrade Tools | Medium |
| Expand a disk (can't be shrunk back); upgrade the hardware version (can't be undone) | High |
| Change NAT port forwards or a host network (affects every VM on it) | High |
| Remove a disk (deletes its file); delete a VM; tear down a stack | Critical |
| Export, convert or inspect (reads the source, writes new files only) | Low |
| A scheduled action | The action's own tier, approved when it is scheduled (below) |
| Edits to sizes, images, launch templates, stacks, rules and layouts | No tier; audited like the session library |

Scheduled actions (VM-14, VM-27): the approval is given when the schedule is saved, with the same steps as running it
then (AP-06 included). Each run is audited as that approval's run. A schedule whose target became Prod or protected, or
whose rules changed, pauses and asks again instead of running. Snapshot retention deletes only snapshots its own
schedule made.

## Packages and order

Each package is one session and one pull request. R1, R3, R8 and R9 can run at the same time. R2 starts after R1, R4
and R7 after R3, R10 after R8 and R9, R5 and R6 after R2, and R11 after all the others (it touches every page and
query).

| # | Package | IDs | After |
| --- | --- | --- | --- |
| R1 | Spec catalogue: sizes, OS profiles, images, launch templates | VM-19, VM-20, VM-21 | now |
| R2 | Deploy: create, clone, import, first-boot setup, after-deploy steps | VM-10, VM-21, VM-22 | R1 |
| R3 | VM settings and lifecycle | VM-11, VM-12, VM-15, VM-16, VM-23, VM-24 | now |
| R4 | VM insight, host networks and waste finder | VM-11, VM-14, VM-16, VM-25 | R3 |
| R5 | Conversion | VM-17, CV-01, CV-02, CV-03 | R2 |
| R6 | Stacks and the deploy capacity planner | VM-08, VM-26 | R2 |
| R7 | Schedules: snapshots and power | VM-14, VM-27 | R3 |
| R8 | Sessions and terminals | QL-16, QL-17, QL-18, QL-19 | now |
| R9 | Dashboard: history, alerts, layout | MO-06, MO-07, MO-16 | now |
| R10 | Navigation and visuals | QL-20 to QL-25 | R8, R9 |
| R11 | Customer workspaces and change IDs | FD-02, AP-08 | all others |

Release 0.5.0 when all eleven are merged.

## R1: spec catalogue (VM-19, VM-20, VM-21)

- VM-19 Sizes: name, vCPU (sockets and cores per socket), RAM, disks (size, thin or thick, controller), and an optional
  description. The twelve built-ins above, read only; Duplicate, Edit and Delete for the owner's own. OS profiles set
  what depends on the guest: firmware (BIOS, EFI, Secure Boot), disk controller, network card type (`vmxnet3` or `e1000e`
  on Workstation, `virtio` or `82540EM` on VirtualBox), guest OS type (`guestOS` / `--ostype`) and hardware version.
  Profiles for Ubuntu, Debian, RHEL family, Windows Server and Windows 10/11 (11 on VirtualBox only), plus Other Linux.
- VM-20 Images: a golden VM and one of its snapshots (for linked clones), a cloud image file (VMDK, OVA, raw; qcow2
  through CV-03), an ISO, or an OVA/OVF. An image stores its hypervisor, OS profile, a checksum taken when it was added,
  and notes. Images on network shares are refused (`untrusted::path_refusal`). The Images list links to the official
  download pages of Ubuntu, Debian, Rocky and Alma cloud images (an allow-list, opened like QL-13 manual links); Remotely
  doesn't download images itself.
- VM-21 Launch templates: image, size, hypervisor, VM folder, network (NAT, host-only, bridged, a custom vmnet or
  VirtualBox network), SSH key (SS-09, public half only), naming pattern (`web-{n}`, `{template}-{date}`), default
  count, environment label and tags, and after-deploy steps (create the SSH session from the guest IP, link it to the
  VM (QL-01), take a "clean" snapshot, open the console). A template whose image or size is gone shows why and can't
  deploy.
- A Templates page (sizes, images, launch templates as tabs), the command palette, and a Deploy button on the VMs page
  (wired up in R2). Migration for the catalogue; every record carries `workspace_id` and `user_id`. Catalogue edits are
  audited, refused by the read-only lock, and included in FD-07 export and import (images by path, with a note when the
  file isn't on the other laptop).

## R2: deploy (VM-10, VM-21, VM-22)

- Deploy from a launch template or Custom: pick the count and names, see the AP-02 preview (names, hypervisor, folder,
  size, disk space each and in all, network), approve, and watch one job with a step per VM.
- Workstation: a clone with `vmrun -T ws clone <vmx> <new vmx> full|linked [-snapshot=] [-cloneName=]`; a new VM by
  writing its `.vmx` and creating its disks with `vmware-vdiskmanager -c`; an OVA/OVF with `ovftool`. The new VM's folder
  joins the scanned folders, so the VM shows at once; it joins Workstation's own library when first opened there.
- VirtualBox: `clonevm --snapshot --options=Link --register`, `createvm --register` with `modifyvm`, `createmedium` and
  `storageattach`, `import` with `--vsys 0` options, and `unattended install` for an ISO it supports (the user's
  password goes through `--password-file`, a file only this user can read, deleted at once; never on a command line).
- Sizes apply after a clone or import: CPU and RAM always; a disk grows to the size's boot disk when it is larger (the
  guest's cloud-init `growpart` fills it; without cloud-init the after-deploy notes say how). A size never shrinks a
  disk.
- VM-22 First-boot setup with cloud-init: hostname, a user, the SSH public key and an optional package list. On
  Workstation through `guestinfo.metadata` and `guestinfo.userdata` (base64) in the `.vmx`, which cloud-init's VMware
  datasource reads through open-vm-tools; on VirtualBox through a NoCloud seed (a `cidata` volume with `user-data` and
  `meta-data`) Remotely writes and attaches as a CD/DVD, ejected after the first boot. The user data never holds a
  password: the `.vmx` and the seed are readable on this PC.
- ISO install: a blank VM from the size and OS profile with the ISO attached and booting first; Open console follows.
- After-deploy steps run per VM as the template says; a VM whose guest IP doesn't show within the wait is reported,
  not failed. VM-10 bulk clone: selected VMs cloned with a naming pattern, as one job.
- Fakes: `FakeVmware` and `FakeVirtualBox` learn create, clone, import and delete, and a stand-in for `vdiskmanager` and
  `ovftool` in tests. Tests never create, clone or delete real VMs.

## R3: VM settings and lifecycle (VM-11, VM-12, VM-15, VM-16, VM-23, VM-24)

- VM-23 A Settings tab in the VM's details shows everything the hypervisor shows and more: CPU (sockets, cores, nested
  virtualization), memory, each disk (controller and slot, type, provisioned, on disk, snapshot chain), CD/DVD (ISO or
  host drive, connected), each network card (MAC, card type, network, connected at power-on and now), USB, sound,
  display, serial ports, shared folders, firmware, Secure Boot and TPM, hardware version, guest OS type, Tools or Guest
  Additions version and state, all guest IPs.
- Edit while off: CPU and cores, RAM, network cards (add, remove, card type, network, MAC), disks (add, expand, compact,
  defragment, remove), firmware and Secure Boot, shared folders, name, guest OS type, hardware version upgrade
  (`vmrun upgradevm`). Workstation by editing the `.vmx` (after a backup copy beside it, kept until the job ends well) and
  `vmware-vdiskmanager`; VirtualBox through `modifyvm`, `storageattach`, `modifymedium`. A VM with snapshots can't
  expand a disk on Workstation: the dialog says so.
- Edit while running: attach or eject an ISO (drag an ISO onto a VM to attach it), connect or disconnect a network card
  (`connectNamedDevice` / `controlvm setlinkstate`), install or upgrade Tools (VM-15, `vmrun installTools`, bulk for a
  selection), and a VirtualBox screenshot (`controlvm screenshotpng`).
- VM-12 bulk resize: CPU and RAM for selected powered-off VMs, one approval.
- VM-24 Lifecycle: delete (`vmrun deleteVM`, `unregistervm --delete`; Critical; the preview lists every file that goes),
  rename, add an existing VM (a `.vmx` or `.vbox`), Open console. Every change is a typed command on the bus, audited,
  with a tier from the table above and a unit test per new rule.

## R4: VM insight, host networks and the waste finder (VM-11, VM-14, VM-16, VM-25)

- VM-25 A Log tab (`vmware.log`, `VBox.log`, read only, search, follow while running, the last few files) and a
  Timeline tab: everything Remotely did to the VM from the audit log and jobs, newest first.
- VM-11 Host networks: Workstation's vmnets (`vmrun listHostNetworks`) and VirtualBox's host-only and NAT networks, the
  VMs on each, and NAT port forwards (`listPortForwardings`, `setPortForwarding`; VirtualBox `natnetwork` and per-VM
  `--natpf`), with add and remove through the bus (High).
- Waste finder (VM-16, VM-14), read only: running VMs idle for days (host CPU and guest metrics), suspended VMs and
  their size on disk, long or large snapshot chains, and VM folders and disks no library or scanned folder knows about.
  Each row offers the matching action (suspend, delete snapshots, delete VM, open folder) through the usual approvals.

## R5: conversion (VM-17, CV-01, CV-02, CV-03)

- CV-03 Image tools page, no VM made: inspect (format, virtual size, size on disk, backing file or parent, from the
  MO-13 header readers), convert between VMDK (sparse, flat, streamOptimized), VDI, VHD, VHDX, qcow2 and raw, with
  thin or thick output, and verify (sizes, checksums, `qemu-img compare` when present).
- CV-01 Import a foreign VM or disk as a new local VM: OVA/OVF from any vendor; VHD/VHDX (Hyper-V, Azure); qcow2, raw
  and `.img` (KVM, Proxmox, OpenStack); VDI to Workstation and VMDK to VirtualBox. Specs come from the source's own
  description where Remotely can read one (OVF, libvirt domain XML, Proxmox `.conf`), else from a size. Deploys through
  R2.
- VM-17 and CV-02 Export a local VM (off, current state; a snapshot chain is flattened): OVA/OVF 1.0 or 2.0, VMDK for
  ESXi (streamOptimized or thick), VHDX for Hyper-V, fixed VHD for Azure, qcow2 with a libvirt domain XML for KVM, a
  Proxmox import script (`qm importdisk` and `qm set`), and raw for clouds that take it. Each export writes a short
  README for the target: how to import, and the driver changes the guest may need (VMware Tools out, virtio drivers in;
  Windows needs its storage driver before it moves).
- Never changes the source. Each conversion is a Low job on the bus with progress, cancel and a free-space check;
  outputs go through `save_guard`; inputs through `untrusted::path_refusal`. Tools always get an explicit input format
  (never `qemu-img` probing) and size limits.

## R6: stacks and the deploy capacity planner (VM-08, VM-26)

- VM-08 Stacks: a named set of launch templates with counts, boot order, delays and readiness checks (Tools running,
  SSH port open), deployed as one job and torn down as one (Critical). A stack's VMs show as a group on the VMs page and
  in the AP-02 preview.
- VM-26 Before any deploy: RAM, CPU and disk on this PC after it (thin disks at their full size as the worst case),
  next to what runs now; when it won't fit, which running VMs to suspend to make room. Extends VM-07's check, which
  still runs at power-on.

## R7: schedules (VM-14, VM-27)

- VM-27 Snapshot schedules per VM, tag or stack: hourly, daily or weekly at a time, keep the last N. Warnings for chains
  longer than a set depth or larger than a set size.
- VM-14 Scheduled power: start, stop, suspend or resume at set times on set days (a lab started at 08:00 and suspended
  at 19:00), and auto-suspend of VMs idle longer than a set time.
- One scheduler for both: approvals as in "Approval tiers" above, runs audited, a missed run (PC asleep or off) is
  reported and not caught up, and nothing runs while the read-only lock is on.

## R8: sessions and terminals (QL-16 to QL-19)

- QL-16 Folder defaults: a folder can set the user, key or password, jump host, environment label and tags; sessions
  in it use them unless they set their own. The session editor shows which values come from the folder.
- QL-17 Highlight and alert rules: regular expressions that colour matching text in terminals (ERROR red, WARN amber,
  the owner's own), and rules that notify when a pattern appears (through QL-25 and `maskedOutside`). Rules can be
  per session label or global.
- QL-18 Search across every open terminal's scrollback, with results grouped by tab.
- QL-19 Saved MultiExec groups ("all web servers"): pick a group to open or select its terminals.

## R9: dashboard (MO-06, MO-07, MO-16)

- MO-06 History on disk: 1-minute averages kept for 7 days (a setting), trend charts with a range picker, pruned
  daily. Charts read history, then live rounds.
- MO-07 Alerts: thresholds per metric (CPU above 90% for 5 minutes, disk above 85%, a host or VM down) with Windows
  notifications and an alert list with acknowledge. Desktop only; email, Teams and Slack stay out.
- MO-16 Custom layout: pick, arrange and resize dashboard widgets, including a services widget (MO-14) and the alert
  list; saved per workspace.

## R10: navigation and visuals (QL-20 to QL-25)

- QL-20 Global search in the palette: VMs, sessions, containers, templates, snippets and settings by name, IP or tag.
- QL-21 Topology map: VMs, their networks, the sessions that reach them, jump host chains and open tunnels in one
  diagram, read only, with click-through to each item.
- QL-22 Status bar: vault lock countdown, running jobs, open tunnels, update state.
- QL-23 First-run wizard: find Workstation and VirtualBox, create the vault, pick VM folders, import sessions.
- QL-24 Compact and comfortable density, and a keyboard shortcut sheet (Ctrl+/).
- QL-25 Notification centre: the history of notifications, alerts and toasts, with links to what they're about.

## R11: customer workspaces and change IDs (FD-02, AP-08)

- FD-02 Workspaces: one per customer engagement, each with its own sessions, VMs and VM links, templates, vault items,
  jobs, audit log, settings that are per workspace, and dashboard layout; switched from the top bar. Still one user;
  every record already carries `workspace_id`. An FD-07 export holds one workspace and never another's data. Whether
  workspaces share one vault key or have their own is decided in the package; either way a workspace's secrets only go
  to its own sessions (the SS-04 bindings).
- AP-08 Change IDs: an optional ticket or change number on High and Critical approvals (a setting can make it required
  for Prod), kept in the audit log, the job and every export.

## Development safety for 0.5.0

- Tests create, clone, convert and delete only through the fakes and stand-in tools, with disk files made at run time
  in the system temp folder. They never touch real VMs, as before.
- Hand checks with the real Workstation and VirtualBox tools may create VMs only in a temp folder, named `it-`, and may
  delete only VMs they created there. Never the owner's VMs or folders.
- Conversion tests use small images made at run time (a few MB), never downloaded images, and never images from a
  network share.
