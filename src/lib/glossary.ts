// UX-05: the glossary. Each of the app's own terms gets one plain sentence, written once. `Term` underlines a term
// lightly and shows its definition on hover or focus; the Ctrl+K palette searches the glossary too (search-sources.ts
// glossaryItems). A package that puts a new term on screen adds it here. Tested in glossary.test.ts.

export interface GlossaryEntry {
  /** The term as it reads on screen, in sentence case. */
  term: string;
  /** One plain sentence. */
  definition: string;
  /** Other words the palette finds it by. */
  aliases?: readonly string[];
}

export const GLOSSARY = {
  // ---- Approvals ----
  tier: {
    term: "Tier",
    definition: "How risky an action is (Low, Medium, High or Critical); the tier sets the steps before it runs.",
    aliases: ["risk", "approval tier"],
  },
  low: { term: "Low", definition: "Runs at once, with only an entry in the audit log." },
  medium: { term: "Medium", definition: "Asks for one confirm before it runs." },
  high: {
    term: "High",
    definition:
      "Shows the impact, offers a safety snapshot, and asks you to type to confirm, give a reason and wait for a countdown.",
  },
  critical: { term: "Critical", definition: "Everything High asks, then the vault password again." },
  environment: {
    term: "Environment",
    definition: "Lab, Dev, Test, Staging or Prod: where a VM or session belongs, shown on its tab and rows.",
    aliases: ["label", "environment label"],
  },
  prod: {
    term: "Prod",
    definition: "A production environment: every action on it moves up one approval tier.",
    aliases: ["production"],
  },
  inherited: {
    term: "Inherited",
    definition:
      "Set by a folder or a linked VM rather than by the session itself; the session's own value wins when it has one.",
    aliases: ["inheritance", "from folder", "folder defaults"],
  },
  protected: {
    term: "Protected",
    definition: "Bulk actions, schedules and Type in all tabs leave it alone until you turn Protected off.",
    aliases: ["protect", "do not touch", "unprotect"],
  },
  standingApproval: {
    term: "Standing approval",
    definition: "The approval a schedule gets when you save it, which its runs use; editing what it does asks again.",
  },
  safetySnapshot: {
    term: "Safety snapshot",
    definition: "A snapshot of each VM taken just before a risky action, so one revert undoes the job.",
  },
  changeId: {
    term: "Change ID",
    definition:
      "Your change or ticket number for an approval, kept with the job and the audit log; a workspace can require it for Prod.",
    aliases: ["ticket", "change request"],
  },
  reason: {
    term: "Reason",
    definition: "A few words on why you run a High or Critical action, kept in the audit log.",
  },
  vaultReauth: {
    term: "Vault password again",
    definition:
      "Critical actions, and a saved password going to a new host, ask for the vault password even while the vault is unlocked.",
    aliases: ["reauth", "re-authentication"],
  },
  auditLog: {
    term: "Audit log",
    definition: "The record of every change, when it started and how it ended, chained so a gap or an edit shows.",
  },
  hashChain: {
    term: "Hash chain",
    definition:
      "Each audit entry carries a fingerprint of the one before; verifying the chain shows whether any was changed.",
    aliases: ["verify the hash chain"],
  },
  purge: {
    term: "Purge",
    definition: "Removes job outputs older than the retention period now, rather than at the next daily purge.",
    aliases: ["purge now", "retention"],
  },
  canary: {
    term: "Canary",
    definition: "Runs on the first host alone and waits for you to check its result before the others.",
  },

  // ---- Terminals ----
  typeInAllTabs: {
    term: "Type in all tabs",
    definition: "What you type goes to every picked terminal at once; each line still goes through the approval rules.",
    aliases: ["multiexec", "broadcast"],
  },
  compareHosts: {
    term: "Compare hosts",
    definition: "Runs one command on several hosts and groups the hosts whose output is the same.",
    aliases: ["compare output", "bulk run"],
  },
  winrm: {
    term: "WinRM",
    definition:
      "Windows Remote Management: how Remotely opens a PowerShell console on a Windows host and reads its metrics and facts.",
    aliases: ["windows remote management", "powershell remoting", "wsman"],
  },
  powershellConsole: {
    term: "PowerShell console",
    definition: "A tab that runs PowerShell on a Windows host over WinRM, line by line, with a prompt Remotely draws.",
    aliases: ["powershell", "ps console"],
  },
  powershellRules: {
    term: "PowerShell rules",
    definition:
      "The approval rules for commands on Windows hosts: read-only commands are Low, dangerous ones High, anything else, or anything Remotely can't read, Medium.",
    aliases: ["powershell approval rules", "windows commands"],
  },
  pickedTabs: {
    term: "Picked tabs",
    definition: "The terminal tabs you chose with Ctrl+click or Shift+click, for Type in all tabs and Compare hosts.",
  },
  savedGroup: {
    term: "Saved group",
    definition: "A named set of sessions you open or pick together for Type in all tabs.",
    aliases: ["multiexec group"],
  },
  promptHook: {
    term: "Prompt hook",
    definition: "A one-line hook Remotely types at a bash or zsh prompt so Files here follows the shell's folder.",
  },
  filesHere: {
    term: "Files here",
    definition: "The files in the terminal's current folder, for downloads and uploads over the same connection.",
    aliases: ["folder tracking", "sftp"],
  },
  jumpHost: {
    term: "Jump host",
    definition: "A host Remotely connects through to reach one it can't reach directly.",
    aliases: ["bastion", "proxy jump"],
  },
  reachability: {
    term: "Reachability dots",
    definition:
      "Green when a session's SSH port answered the last check, red when it didn't, grey before the first; a ring is its jump host's.",
    aliases: ["dots", "reachable"],
  },
  hostKey: {
    term: "Host key",
    definition:
      "The key a host proves itself with; Remotely blocks a host whose key changed until you trust the new one.",
    aliases: ["known host", "fingerprint"],
  },

  // ---- Templates and VMs ----
  goldenVm: {
    term: "Golden VM",
    definition: "A VM kept as a master copy: new VMs are cloned from one of its snapshots.",
    aliases: ["master", "base vm"],
  },
  size: {
    term: "Size",
    definition: "A named amount of CPU, memory and disk, such as gp.medium.",
    aliases: ["instance type", "flavour"],
  },
  image: {
    term: "Image",
    definition: "Where a new VM's OS comes from: a golden VM's snapshot, a cloud image, an ISO or an OVA.",
  },
  launchTemplate: {
    term: "Launch template",
    definition: "An image and a size with the network, SSH key, names and setup a deploy needs.",
    aliases: ["template"],
  },
  stack: {
    term: "Stack",
    definition: "Several launch templates deployed, started and stopped together, in boot order.",
  },
  instance: {
    term: "Instance",
    definition: "One deployed copy of a stack: its VMs, which start, stop and tear down together.",
  },
  snapshotChain: {
    term: "Snapshot chain",
    definition: "A VM's snapshots one after another; a long chain makes disks slower and bigger.",
    aliases: ["chain depth"],
  },
  linkedClone: {
    term: "Linked clone",
    definition: "A VM that shares its golden VM's disk, so that snapshot can't be deleted while the clone exists.",
  },

  // ---- Everything else ----
  workspace: {
    term: "Workspace",
    definition:
      "One engagement or customer: its sessions, VMs, templates, schedules and audit log, kept apart from the others.",
    aliases: ["engagement", "customer"],
  },
  unassignedVm: {
    term: "Unassigned VM",
    definition: "A VM on this PC that no workspace has yet; add it to the workspace shown to act on it.",
    aliases: ["take out of this workspace"],
  },
  presentationMode: {
    term: "Presentation mode",
    definition: "Hides host names, IP addresses and user names on screen while you share it.",
    aliases: ["present", "mask"],
  },
  readOnlyLock: {
    term: "Read-only lock",
    definition: "While presenting, blocks every change so nothing is changed by accident on a call.",
  },
  guestOk: {
    term: "Guest OK",
    definition: "Remotely is reading the guest's own metrics over SSH, not just this PC's view of the VM.",
    aliases: ["guest metrics"],
  },
  vault: {
    term: "Vault",
    definition: "Where Remotely keeps passwords and keys, encrypted on this PC; it locks itself when you're away.",
  },
  healthCheck: {
    term: "Health check",
    definition:
      "A ping, port, web page, certificate, DNS name or service Remotely checks on a schedule, alerting you when it goes down.",
    aliases: ["check", "uptime", "monitor"],
  },
  checkDown: {
    term: "Down",
    definition: "A health check that failed as many runs in a row as it allows (two by default).",
    aliases: ["failing check"],
  },
} as const satisfies Record<string, GlossaryEntry>;

export type TermKey = keyof typeof GLOSSARY;

/** The entry for a key. */
export function glossaryEntry(key: TermKey): GlossaryEntry {
  return GLOSSARY[key];
}

/** Every term, A to Z, for the palette and lists. */
export function glossaryTerms(): { key: TermKey; entry: GlossaryEntry }[] {
  return (Object.keys(GLOSSARY) as TermKey[])
    .map((key) => ({ key, entry: GLOSSARY[key] as GlossaryEntry }))
    .sort((a, b) => a.entry.term.localeCompare(b.entry.term));
}

/** Whether a value is a glossary key. */
export function isTermKey(value: string): value is TermKey {
  return Object.prototype.hasOwnProperty.call(GLOSSARY, value);
}
