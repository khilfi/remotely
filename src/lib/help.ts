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
      "Copies, saved output, session logs and exports keep the real text. Printing is masked, since its preview is on screen.",
    ],
    link: { label: "Presentation settings", to: setting("presentation") },
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
      "VM actions run through Workstation's vmrun.exe and VirtualBox's VBoxManage.exe. Remotely uses the path saved in Settings, then the registry, then the default install folders.",
      "Either hypervisor is enough. Without VirtualBox, the list simply has no VirtualBox VMs.",
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
