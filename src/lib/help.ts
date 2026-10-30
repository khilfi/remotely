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
  "page.dashboard": {
    title: "Dashboard",
    body: [
      "Live CPU, memory, disk and network for this PC, its running VMs and the hosts you watch over SSH, with alerts and history.",
      "The Map tab shows how VMs, networks, sessions and jump hosts connect.",
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
      "Each tool is found in this order: the path set in Settings, its variable (REMOTELY_VMRUN, REMOTELY_VBOXMANAGE, REMOTELY_OVFTOOL, REMOTELY_QEMU_IMG, REMOTELY_DOCKER), the registry, then the default install folder.",
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
      "A few words on why you run it, kept in the audit log. A ticket or change number in them, such as CHG0012345, INC-42 or #1234, is kept as the change ID too, with the job and in the exports.",
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
      "It is encrypted with the passphrase you choose here, which can't be recovered.",
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
  auditLog: {
    title: "Audit log",
    body: [
      "Every change is written to the audit log when it starts and when it ends, each entry chained to the one before, so a missing or edited entry shows.",
      "Activity shows it, and you can export it as a CSV file.",
    ],
    link: { label: "Open Activity", to: { kind: "page", page: "activity" } },
  },
  workspaces: {
    title: "Workspaces",
    body: [
      "One workspace per engagement or customer. Sessions, VMs, templates, schedules and the audit log belong to the workspace shown; the others stay out of sight.",
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
