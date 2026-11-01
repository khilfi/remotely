// UX-04: the help registry. Every explanation longer than one line is written once here and shown on demand by
// HelpTip (the "?" popover) or a page header's "?", so a card, dialog or empty state shows at most one line by
// default. A key per topic; each entry has a title, one or two short paragraphs, and optionally a link to a Settings
// card or a page. Copy rules (CLAUDE.md, UI rules): sentence case, plain words, short, no requirement IDs. Tested in
// help.test.ts.
//
// A package that needs a new explanation adds a key here rather than a paragraph on its page; one that finds the
// same explanation in two places points both at one key.

import type { AppLink } from "./links.ts";

export interface HelpEntry {
  title: string;
  /** One or two short paragraphs. */
  body: readonly string[];
  /** Where to go for more, or to change it. */
  link?: { label: string; to: AppLink };
}

const setting = (section: string): AppLink => ({ kind: "setting", section });

export const HELP = {
  // ---- Pages (the "?" in each page header) ----
  "page.vms": {
    title: "Virtual machines",
    body: [
      "Every VM in VMware Workstation's library, in the folders you add, and in VirtualBox. Select rows to act on several at once.",
      "Anything that changes a VM goes through the approval rules first.",
    ],
  },
  "page.templates": {
    title: "Templates",
    body: [
      "Describe VMs once, then deploy them. A size sets CPU, memory and disks; an image is where the OS comes from; a launch template puts them together with the network, SSH key and names.",
      "A stack deploys several launch templates in boot order, as one. Disk images reads and converts other hypervisors' disk files.",
    ],
  },
  "page.diskImages": {
    title: "Disk images",
    body: [
      "Inspect, convert and verify disk files from other hypervisors: VMDK, VDI, VHD, VHDX, qcow2 and raw.",
      "A source is never changed: a conversion writes a new file. To make a VM from a disk or an appliance, import it.",
    ],
  },
  "page.schedules": {
    title: "Schedules",
    body: [
      "Snapshots and power actions on a timetable, and suspending idle VMs.",
      "A schedule is approved once, when you save it. Each run then goes through the same checks under that approval.",
    ],
  },
  "page.sessions": {
    title: "Sessions",
    body: [
      "The SSH hosts you work with: address, user, how to log in, a jump host and a startup command.",
      "Sort them into folders. A folder can set defaults, such as the user or the environment, that its sessions inherit.",
    ],
  },
  "page.terminal": {
    title: "Terminal",
    body: [
      "SSH terminals in tabs and split panes, with files, port forwards and saved commands beside them.",
      "Type in all tabs sends your typing to several terminals at once; Compare hosts runs one command on many hosts and groups the answers.",
    ],
  },
  "page.containers": {
    title: "Containers",
    body: [
      "Docker and Podman on the sessions you mark as container hosts, and Docker Desktop on this PC.",
      "Starting, stopping and removing containers go through the approval rules, like every other change.",
    ],
  },
  "page.toolbox": {
    title: "Toolbox",
    body: [
      "Ping, trace route, DNS lookups, port checks, certificates, a subnet calculator and Wake-on-LAN, run from this PC. Only Wake up sends something to a machine, so only it goes through the approval rules.",
      "A session behind a jump host has its ports and certificate checked from the jump host. Ping and trace route can't go that way.",
    ],
  },
  "toolbox.ports": {
    title: "Check ports",
    body: [
      "Opens a connection to each port and closes it again; nothing is sent. Up to 100 ports a check: it checks the ports you name, it doesn't scan.",
      "Read banners shows the first line a service sends, such as SSH's version. Each check shows in the host's logs like any connection.",
    ],
  },
  "toolbox.certificate": {
    title: "Certificate",
    body: [
      "Reads the certificate a TLS server sends, whatever it is, then asks Windows whether it trusts it, with only what this PC already has. Revocation isn't checked.",
      "The name checked is the server name, which is also sent to the server (SNI). Leave it empty to use the host.",
    ],
  },
  "toolbox.wake": {
    title: "Wake up",
    body: [
      "Sends a Wake-on-LAN magic packet for the machine's network card. It works only if the card and its firmware have Wake-on-LAN on, and the packet reaches its network.",
      "From an adapter, the packet goes to that adapter's subnet broadcast. For a subnet behind a router, type its directed broadcast, like 192.0.2.255.",
    ],
  },
  "page.dashboard": {
    title: "Dashboard",
    body: [
      "Live CPU, memory, disk and network for this PC, its running VMs and the hosts you watch over SSH, with alerts and history.",
      "The Checks tab runs health checks on a schedule; the Map tab shows how VMs, networks, sessions and jump hosts connect.",
    ],
  },
  "page.map": {
    title: "Map",
    body: [
      "How your VMs, host networks, sessions and jump hosts connect, drawn from what Remotely already knows.",
      "Select a node to open it. Nothing on the map changes anything.",
    ],
  },
  "page.activity": {
    title: "Activity",
    body: [
      "Every job, newest first, with each target's result and output, and the audit log of everything that changed.",
    ],
    link: { label: "Job output retention", to: setting("retention") },
  },
  "page.vault": {
    title: "Vault",
    body: [
      "Passwords, private keys and passphrases that sessions log in with, encrypted on this PC. A value can be replaced but never shown again.",
      "The Known hosts tab lists the SSH host keys you trusted.",
    ],
  },
  "page.knownHosts": {
    title: "Known hosts",
    body: [
      "The SSH host keys you trusted, one per host and key type.",
      "When a host's key changes, connecting to it is blocked until you check the new key and trust it.",
    ],
  },
  "page.settings": {
    title: "Settings",
    body: [
      "Where Remotely finds its tools, the approval rules, the terminal, and the rest of what's yours to change. Search with Ctrl+K to jump to a setting.",
    ],
  },

  // ---- Explanations that used to be repeated on several pages ----
  windowsUnlock: {
    title: "Unlock with your Windows login",
    body: [
      "One click unlocks the vault while you're signed in to this Windows account. Any program running under that account could unlock it too, even from a copy of Remotely's database.",
      "Turn it on only on a PC that's yours alone. Critical actions still ask for the vault password.",
    ],
    link: { label: "Open the Vault", to: { kind: "vault" } },
  },
  vaultIdleLock: {
    title: "When the vault locks",
    body: [
      "The vault locks itself after a set time without you typing or clicking in Remotely; background reads don't count. You can also lock it yourself from the Vault page or the palette.",
    ],
    link: { label: "Vault settings", to: setting("vault") },
  },
  vaultReauth: {
    title: "Why the vault password is asked again",
    body: [
      "Critical actions ask for the vault password again, however the vault was unlocked. So does sending a saved password to a host it hasn't gone to before.",
      "A right answer covers the next 5 minutes, until the vault locks.",
    ],
  },
  presentationMode: {
    title: "Presentation mode",
    body: [
      "For screen shares: host names, IP addresses, user names and your Windows user name are replaced on screen by stand-ins such as host-3 or ip-5.",
      "Copies, saved output, session logs and exports keep the real text. Printing is masked, since its preview is on screen; Windows file dialogs show real paths.",
    ],
    link: { label: "Presentation settings", to: setting("presentation") },
  },
  hideTerminals: {
    title: "Hide terminal output",
    body: [
      "Terminal output is masked as it arrives, but a full-screen program such as top or vim that redraws part of a name can show that part. This blurs the terminals while you present instead.",
    ],
  },
  readOnlyLock: {
    title: "Read-only lock",
    body: [
      "While you present, it blocks every change: power actions, snapshots, commands, uploads, tunnels, imports and edits.",
      "Reading, downloads and typing into a single terminal still work.",
    ],
    link: { label: "Presentation settings", to: setting("presentation") },
  },
  promptHook: {
    title: "Prompt hook",
    body: [
      "In bash and zsh, Remotely types a one-line hook at the first prompt so Files here follows the shell's folder and user. It sets PROMPT_COMMAND (or a zsh precmd hook) and runs id -un.",
      "It's off for Prod sessions unless a session turns it on. When it's off, Files here starts in the home folder.",
    ],
    link: { label: "Terminal settings", to: setting("terminal") },
  },
  toolPaths: {
    title: "How Remotely finds its tools",
    body: [
      "VM actions run through Workstation's vmrun.exe and VirtualBox's VBoxManage.exe; either is enough. Without VirtualBox, the list simply has no VirtualBox VMs.",
      "Each tool is found in this order: the path set in Settings, its variable (REMOTELY_VMRUN, REMOTELY_VBOXMANAGE, REMOTELY_OVFTOOL, REMOTELY_QEMU_IMG, REMOTELY_DOCKER, REMOTELY_VNC_VIEWER), the registry, then the default install folder (for VNC sessions, your own TigerVNC, TightVNC, RealVNC or UltraVNC viewer).",
    ],
    link: { label: "Tool settings", to: setting("vmware") },
  },
  retention: {
    title: "Job output retention",
    body: [
      "Each job keeps what its hosts printed and the command it ran, so Activity and Compare hosts can show them. After the retention period those are removed; the jobs, their results and the audit log stay.",
      "Passwords and tokens typed into a command are never kept.",
    ],
    link: { label: "Retention settings", to: setting("retention") },
  },
  compareHosts: {
    title: "Compare hosts",
    body: [
      "Runs one command once on each picked host, in its own login shell rather than in your terminals, and groups the hosts whose output is the same.",
      "Its second view compares the lines you typed in all tabs, with what each terminal answered, so you don't type them again.",
    ],
  },
  supportBundle: {
    title: "Support bundle",
    body: [
      "Runs the same commands on each host over SSH and reads the chosen files over SFTP as the session's user (never with sudo), into one zip with a folder per host and a manifest of what ran, sizes and checksums. Remote desktop, VNC, Telnet and serial sessions can't be hosts. The presets only read.",
      "What looks like a password, token or private key is redacted in every file, but look through the zip before you share it. Each file keeps up to 10 MB, each host 100 MB and the bundle 1 GB; what is cut or left out is in the manifest.",
    ],
  },
  recordedLines: {
    title: "Recorded lines",
    body: [
      "While Type in all tabs is on, each line you send is recorded in every terminal, from Enter until its prompt comes back, its output goes quiet, or a time limit passes.",
      "Password prompts and keys sent to full-screen programs are not recorded, and secrets are scrubbed. Recordings stay in memory until Type in all tabs is turned off.",
    ],
  },
  vmLink: {
    title: "VM it reaches",
    body: [
      "Linking a session to its VM lets Compare hosts pick the VM and the dashboard show the guest's own metrics.",
      "A Prod or protected VM makes the session Prod or protected too. Left at None, a session links itself when its host is a running VM's IP address.",
    ],
  },
  prodTier: {
    title: "Prod raises the tier",
    body: [
      "Every action on a Prod VM or session moves up one approval tier, so it needs more steps before it runs.",
      "A session is Prod when it is set to Prod, when its folder is and it doesn't set its own, or when it reaches a Prod VM.",
    ],
    link: { label: "Approval rules", to: setting("rules") },
  },
  approvalTiers: {
    title: "Approval tiers",
    body: [
      "Every action that changes something gets a tier, and the tier sets the steps before it runs. Low runs at once. Medium asks for one confirm.",
      "High adds the impact preview, a safety snapshot, typing to confirm, a reason and a countdown. Critical adds the vault password.",
    ],
    link: { label: "Approval rules", to: setting("rules") },
  },
  safetySnapshot: {
    title: "Safety snapshot",
    body: [
      "Before a risky action on VMs, Remotely takes a snapshot of each one, all with the same name starting “Remotely safety”, so one revert undoes the job.",
      "A VM whose safety snapshot fails is left untouched.",
    ],
  },
  // ---- U4: approvals, Settings and the Vault ----
  reasonOrChangeId: {
    title: "Reason and change ID",
    body: [
      "A few words on why you run it, kept in the audit log. Start with a ticket or change number, such as CHG0012345, INC-42 or #1234, and it is kept as the change ID too, with the job and in the exports.",
      "A workspace can require a change ID for High and Critical actions on Prod targets.",
    ],
    link: { label: "Approval settings", to: setting("change-ids") },
  },
  standingApproval: {
    title: "Standing approval",
    body: [
      "A schedule is approved once, when you save it, and each run goes ahead under that approval until you edit or delete the schedule.",
      "If a target becomes Prod or Protected, a new VM gets its tag or the approval rules change, the schedule pauses and asks again. A run missed while Remotely was closed is reported, not caught up.",
    ],
    link: { label: "Open Schedules", to: { kind: "page", page: "schedules" } },
  },
  bulkTier: {
    title: "In bulk",
    body: [
      "The tier an action gets when it runs on several targets at once, from the numbers set under the table. One mistake in bulk reaches every target, so most actions ask more.",
    ],
  },
  dangerousCommands: {
    title: "Dangerous commands",
    body: [
      "A command that matches one of these regular expressions is High. Each is tested against the command as typed and against each command the shell would run in it: quotes removed, sudo and env dropped, sh -c scripts read too.",
      "A pattern that matches every command is refused. Patterns added in an update reach your rules only when you add them or reset to the defaults.",
    ],
  },
  readOnlyCommands: {
    title: "Read-only commands",
    body: [
      "A command whose every part starts with one of these, and that writes no file, is Low. Entries can't hold shell operators such as ; | > or $.",
      "Forms that change something, such as ip link set or date -s, are never read-only. Nor is a command set up with an environment variable other than the locale, time zone, terminal or colours.",
    ],
  },
  pasteConfirm: {
    title: "Pasting several lines",
    body: [
      "Each line break in a paste presses Enter, so a shell without bracketed paste runs every line as it arrives. Either way a paste loses its control characters, tabs and line breaks aside.",
    ],
  },
  reachabilityChecks: {
    title: "Reachability dots",
    body: [
      "Remotely opens a TCP connection to each shown session's SSH port, or its first jump host, and closes it at once: no login. Hosts you're connected to aren't checked, and a host that's down is checked less often.",
      "Each check shows in the host's sshd log as a connection closed before login, and strict fail2ban rules may count it. On such sites, turn the dots off or check less often.",
    ],
  },
  notifyAway: {
    title: "Notifications when you're away",
    body: [
      "Away means the tab isn't on screen or Remotely isn't the window in front. A line typed in all tabs notifies once, when all its terminals are done.",
      "A command that goes quiet for the time set counts as finished, for prompts Remotely doesn't recognise. The bell in a terminal's toolbar turns notifications off for that tab.",
    ],
  },
  terminalRules: {
    title: "Highlight and alert rules",
    body: [
      "A rule colours what its pattern matches in terminals. With its alert on, a matching line also notifies you while its tab is in the background: once per burst, then not again for a minute.",
      "Where two rules match the same text, the higher one wins. Full-screen programs, password prompts and what you type never alert.",
    ],
  },
  powerActions: {
    title: "Power actions",
    body: [
      "Bulk starts power on a few VMs at a time, since many at once can saturate this PC's disk and CPU.",
      "Shut down asks each guest to stop, then waits. A VM still running after the wait is reported and left running; forcing it off needs its own approval.",
    ],
  },
  dashboardHistory: {
    title: "Dashboard history",
    body: [
      "A 1-minute average of each running VM, watched host and this PC, for the charts' longer ranges and the alert list. It stays on this PC: exports never carry it.",
    ],
  },
  vaultEncryption: {
    title: "How secrets are kept",
    body: [
      "Each value is encrypted on this PC with AES-256-GCM, under a key that only the vault password unlocks (Argon2id), or your Windows login if you turn that on.",
      "A value can be replaced but never shown again. Remotely hands it only to the connection that needs it.",
    ],
  },
  sshKeys: {
    title: "SSH keys",
    body: [
      "Keys are made straight into the vault: Ed25519, or RSA 4096 for older hosts and appliances. The private half never leaves the vault except to log in.",
      "Push a public key to hosts' ~/.ssh/authorized_keys with the approval its tier needs, then let sessions log in with it.",
    ],
  },
  workspaceArchive: {
    title: "Archived workspaces",
    body: [
      "An archived workspace keeps its data and audit log, but can't be opened and runs no schedules until you restore it.",
      "Workspaces are never deleted, so their audit logs are kept for good.",
    ],
  },
  transferExport: {
    title: "What the file holds",
    body: [
      "Your sessions and folders with their tags, environments, jump hosts and port forwards; your favourite commands and saved groups; and your VM sizes, images and launch templates. Image files aren't in it: copy them yourself.",
      "Without the vault secrets, sessions on the other laptop use the secrets with the same labels there, or ask when connecting. The passphrase can't be recovered.",
    ],
  },
  transferExtras: {
    title: "Startup commands and port forwards",
    body: [
      "A startup command is typed into the shell at every connection without asking, and a port forward opens a way into a network.",
      "They are left out unless you tick them; a session that replaces one here keeps its own.",
    ],
  },
  updateChecks: {
    title: "Update checks",
    body: [
      "Remotely checks GitHub Releases at start and every 24 hours. Every update is signature-checked, and installing always asks first.",
      "Turn checks off at air-gapped sites.",
    ],
    link: { label: "Update settings", to: setting("updates") },
  },
  updateToken: {
    title: "GitHub update token",
    body: [
      "Updates work without a token, since Remotely's releases are public. A token helps when many PCs share one internet address (GitHub allows 60 checks an hour without one), or if the repository goes private again.",
      "Use a fine-grained token for that repository only, with Contents: Read-only and an expiry date. It's kept in the vault and never shown again.",
    ],
    link: { label: "Update settings", to: setting("updates") },
  },
  dashboardPolling: {
    title: "Watching a host",
    body: [
      "Watching a host keeps one SSH connection to it, with the session's saved login, and reads /proc there every few seconds. Nothing on the host changes.",
      "Security tools that log every program a host runs will see those reads. Polling less often is gentler; the charts then move in bigger steps.",
    ],
    link: { label: "Dashboard polling", to: setting("dashboard") },
  },
  qemuImg: {
    title: "Converting with qemu-img",
    body: [
      "Converting to or from qcow2 and VHDX needs qemu-img from QEMU for Windows, which Remotely doesn't ship. Install QEMU, or set qemu-img.exe's path in Settings.",
      "Workstation's and VirtualBox's own tools handle the other formats.",
    ],
    link: { label: "Conversion tools", to: setting("qemu-img") },
  },
  // ---- U2: Machines (VMs, Templates, Schedules) ----
  snapshotActions: {
    title: "Revert and delete",
    body: [
      "Reverting puts the VM back as it was at the snapshot and loses what changed since; the approval offers a safety snapshot first.",
      "Deleting a snapshot keeps its children and the VM's current state. Hover a button to see the approval it needs.",
    ],
  },
  chainLimits: {
    title: "Snapshot chain warnings",
    body: [
      "Each snapshot adds a level to a VM's disk chain, which slows the disk, and its files only grow until snapshots are deleted.",
      "VMs past these limits are flagged on the Schedules page and in their Activity tab.",
    ],
  },
  scheduleRetention: {
    title: "Keeping the last snapshots",
    body: [
      "Retention deletes only the snapshots this schedule took, oldest first; others on the VM stay.",
      "Deleting snapshots is High, so the schedule's approval asks for a reason and the number of VMs.",
    ],
  },
  idleSuspend: {
    title: "When a VM counts as idle",
    body: [
      "Measured from the dashboard's history and its live readings of the VM's own CPU.",
      "A VM Remotely didn't watch for the whole time (closed, asleep, just started) waits until it has.",
    ],
  },
  hostNetworks: {
    title: "Host networks",
    body: [
      "Workstation's and VirtualBox's networks on this PC, the VMs on each, and their NAT port forwards.",
      "Adding or removing a forward asks for approval (High): it reaches every VM on the network, and a Prod VM on it moves it up a tier.",
    ],
  },
  natForwardsAdmin: {
    title: "Forwards need administrator rights",
    body: [
      "Workstation keeps its NAT port forwards in a file only administrators can change, and Remotely never asks to run as administrator.",
      "Change them in Workstation's Virtual Network Editor (Edit, Virtual Network Editor, Change Settings), or start Remotely with Run as administrator.",
    ],
  },
  namingPattern: {
    title: "Naming pattern",
    body: [
      "{n} is a number that skips names already taken, {template} the template's (or VM's) name and {date} today as YYYYMMDD.",
    ],
  },
  cloudImages: {
    title: "Cloud images",
    body: [
      "The official download pages open in your browser. Remotely downloads nothing itself: save the file, then add it as an image.",
    ],
  },
  deployPreview: {
    title: "What a deploy makes",
    body: [
      "Before anything is made you see each VM's name, folder, size and disk space, with this PC's room after it, and approve the deploy.",
      "A VM that fails is removed with what it made; VMs already made stay.",
    ],
  },
  containerHosts: {
    title: "Container hosts",
    body: [
      "Remotely runs the host's docker or podman command over the session's SSH connection, through its jump hosts, only while you have the host open on the Containers page.",
      "It logs in with the session's saved login: a session whose password you type in the terminal needs it saved in the vault first. Detect logs in and checks whether docker needs sudo.",
    ],
  },
  alertRules: {
    title: "Alert rules",
    body: [
      "Rules are checked on every metrics round. A rule fires once its condition has held for its duration, and resolves after a minute back under it.",
      "Alerts and their history are kept on this PC only, as long as the dashboard history.",
    ],
  },
  notifications: {
    title: "Notifications",
    body: [
      "What notified since Remotely started: alerts, finished commands and jobs, updates. They're kept until Remotely closes.",
      "Jobs stay in Activity, and alerts on the dashboard, after that.",
    ],
  },
  auditLog: {
    title: "Audit log",
    body: [
      "Every change is written to the audit log when it starts and when it ends, each entry chained to the one before, so a missing or edited entry shows.",
      "Activity shows it, and you can export it as a CSV file.",
    ],
    link: { label: "Open Activity", to: { kind: "page", page: "activity" } },
  },
  notes: {
    title: "Notes",
    body: [
      "One note per session, VM and folder, written in markdown. Link a web page, or the app's own items by name: [db](<vault:DB admin>), <session:web01>, <vm:web-01>, <command:Disk usage> or <runbook:Disk full>.",
      "A vault link names the item and never shows its secret. A code block can be sent to the open terminal without pressing Enter; one with several lines asks first. The handover pack hides what looks like a secret.",
    ],
  },
  trash: {
    title: "Trash",
    body: [
      "A deleted session, favourite command, size, image, launch template or stack waits here for 30 days, with what came with it, such as a session's port forwards, health checks and note. Then it is deleted for good.",
      "Restore puts it back. A name taken since gets (restored); a folder or jump host that is gone is left out.",
    ],
    link: { label: "Open the trash", to: { kind: "setting", section: "trash" } },
  },
  bulkEdit: {
    title: "Edit several sessions",
    body: [
      "Set the folder, port, user, login, jump host or environment of every selected session at once, and add or remove tags. Fields left as they are stay as each session has them.",
      "You see each session before and after first. If a login would send a vault password somewhere new, the vault password is asked once. Only SSH sessions take a login, and Telnet and serial take no jump host, so they keep theirs.",
    ],
  },
  checks: {
    title: "Health checks",
    body: [
      "Each check runs from this PC on its schedule, for the workspace shown: a ping, a TCP port, a web page, a certificate, a DNS name, or a service over SSH. A session behind a jump host is checked through it, on one kept connection.",
      "A check is down after as many failed runs in a row as it allows; an alert rule tells you. Results are kept as long as the dashboard history.",
    ],
    link: { label: "Open the history setting", to: setting("history") },
  },
  checkTiming: {
    title: "Timing",
    body: [
      "A check runs every 30 seconds to 1 hour, and waits up to its timeout for an answer. One failed run makes it Failing; as many failed runs in a row as you allow make it Down.",
      "A run Remotely can't make, say with the vault locked, counts as neither.",
    ],
  },
  workspaces: {
    title: "Workspaces",
    body: [
      "One workspace per engagement or customer. Sessions, VMs, templates, schedules and the audit log belong to the workspace shown; the others stay out of sight.",
      "A new workspace starts empty. VMs join it from the VMs page's Unassigned list, or when it deploys them.",
    ],
  },
} as const satisfies Record<string, HelpEntry>;

export type HelpKey = keyof typeof HELP;

/** The entry for a key. */
export function helpEntry(key: HelpKey): HelpEntry {
  return HELP[key];
}

/** Whether a value is a help key (for keys that come from data, such as the page registry). */
export function isHelpKey(value: string): value is HelpKey {
  return Object.prototype.hasOwnProperty.call(HELP, value);
}
