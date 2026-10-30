// QL-20, UX-10: the Settings page's sections by their labels, so the palette and the page's own search box find a
// setting by what it is called ("vmrun", "idle lock", "density") and open it. The page shows one group at a time from
// a side list; a search shows every section that matches, under its group. Each section has an element id
// (`settingsCardId`), on its card or, for the rows of a shared card (the tools table, the change ID rule), on its row;
// a link to it opens its group, scrolls to it and lights it. A package that adds a setting adds a line here. Tested in
// settings-index.test.ts and search.test.ts.

export type SettingsGroup =
  "general" | "tools" | "terminal" | "approvals" | "privacy" | "dashboard" | "updates" | "about";

/** The side list, in order. */
export const SETTINGS_GROUPS: readonly { id: SettingsGroup; title: string }[] = [
  { id: "general", title: "General" },
  { id: "tools", title: "Tools and VMs" },
  { id: "terminal", title: "Terminal" },
  { id: "approvals", title: "Approvals" },
  { id: "privacy", title: "Privacy and data" },
  { id: "dashboard", title: "Dashboard" },
  { id: "updates", title: "Updates" },
  { id: "about", title: "About" },
];

export interface SettingsSection {
  id: string;
  group: SettingsGroup;
  /** The card it is on, when it is a row of another section's card. */
  card?: string;
  title: string;
  /** Other words it is found by. */
  keywords: string;
}

export const SETTINGS_SECTIONS: readonly SettingsSection[] = [
  {
    id: "appearance",
    group: "general",
    title: "Appearance",
    keywords: "theme dark light follow windows density compact comfortable spacing",
  },
  {
    id: "first-run",
    group: "general",
    title: "Setup guide and tips",
    keywords: "first run wizard welcome start getting started tips show again hints",
  },
  {
    id: "vmware",
    group: "tools",
    card: "tools",
    title: "VMware Workstation",
    keywords: "vmrun path vmrun.exe hypervisor ovftool ova ovf vdiskmanager tool paths",
  },
  {
    id: "virtualbox",
    group: "tools",
    card: "tools",
    title: "Oracle VirtualBox",
    keywords: "vboxmanage path vboxmanage.exe hypervisor tool paths",
  },
  {
    id: "qemu-img",
    group: "tools",
    card: "tools",
    title: "Conversion tools",
    keywords: "qemu qemu-img.exe path qcow2 vhdx convert disk images export import tool paths",
  },
  {
    id: "docker",
    group: "tools",
    card: "tools",
    title: "Docker Desktop on this PC",
    keywords: "docker.exe path containers tool paths",
  },
  { id: "vm-folders", group: "tools", title: "VM folders", keywords: "scan folders vmx library find vms" },
  {
    id: "power",
    group: "tools",
    title: "Power actions",
    keywords: "power on limit at once shutdown wait seconds bulk start",
  },
  {
    id: "terminal",
    group: "terminal",
    title: "Terminal",
    keywords:
      "keep-alive reconnect copy on select paste font scrollback prompt hook reachability dots notifications long commands",
  },
  {
    id: "compare",
    group: "terminal",
    title: "Compare hosts",
    keywords: "compare output hosts at once parallel bulk run",
  },
  {
    id: "terminal-rules",
    group: "terminal",
    title: "Highlight and alert rules",
    keywords: "highlight colour regex error warning alert terminal rules",
  },
  {
    id: "rules",
    group: "approvals",
    title: "Approval rules",
    keywords: "policy tiers low medium high critical read-only commands dangerous prod countdown safety snapshot",
  },
  {
    id: "change-ids",
    group: "approvals",
    card: "rules",
    title: "Change IDs",
    keywords: "ticket change number chg prod required approval workspace",
  },
  {
    id: "presentation",
    group: "privacy",
    title: "Presentation mode",
    keywords: "present mask screen share read-only lock hide terminal output",
  },
  { id: "vault", group: "privacy", title: "Vault", keywords: "windows login dpapi unlock idle lock minutes" },
  {
    id: "retention",
    group: "privacy",
    title: "Job outputs",
    keywords: "data retention job journal outputs command text purge now days keep",
  },
  { id: "dashboard", group: "dashboard", title: "Dashboard polling", keywords: "poll watched hosts guest seconds" },
  { id: "history", group: "dashboard", title: "Dashboard history", keywords: "metrics history retention days prune" },
  { id: "updates", group: "updates", title: "Updates", keywords: "update checks github token release version" },
  { id: "about", group: "about", title: "About and logs", keywords: "version logs crash reports folder" },
];

/** The element id of a section's card or row. */
export function settingsCardId(section: string): string {
  return `settings-${section}`;
}

export function settingsSection(id: string): SettingsSection | undefined {
  return SETTINGS_SECTIONS.find((s) => s.id === id);
}

/** The card a section is shown on. */
export function sectionCard(section: SettingsSection): string {
  return section.card ?? section.id;
}

export function groupTitle(group: SettingsGroup): string {
  return SETTINGS_GROUPS.find((g) => g.id === group)?.title ?? group;
}

/** The sections of a group, in order. */
export function groupSections(group: SettingsGroup): SettingsSection[] {
  return SETTINGS_SECTIONS.filter((s) => s.group === group);
}

/**
 * The page's search: the sections every word of the query starts a word of (in its title, keywords or group), in the
 * page's order. An empty query matches nothing: the page shows its group instead.
 */
export function searchSettings(query: string): SettingsSection[] {
  const words = query.toLocaleLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return [];
  return SETTINGS_SECTIONS.filter((s) => {
    const haystack = `${s.title} ${s.keywords} ${groupTitle(s.group)}`.toLocaleLowerCase().split(/[\s,()]+/);
    return words.every((w) => haystack.some((h) => h.startsWith(w)));
  });
}

/** The cards to show for a search, each once, in order, with the sections that matched on it. */
export function searchCards(query: string): { card: string; group: SettingsGroup; sections: string[] }[] {
  const out: { card: string; group: SettingsGroup; sections: string[] }[] = [];
  for (const s of searchSettings(query)) {
    const card = sectionCard(s);
    const found = out.find((c) => c.card === card);
    if (found) found.sections.push(s.id);
    else out.push({ card, group: s.group, sections: [s.id] });
  }
  return out;
}
