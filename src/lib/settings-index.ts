// QL-20: the Settings page's cards by their labels, so the palette finds a setting by what it is called ("vmrun",
// "idle lock", "density") and opens its card. SettingsPage gives each card the id `settingsCardId(section)` and opens
// the tab a section is on. A package that adds a card adds a line here. Tested in search.test.ts.

export type SettingsTab = "general" | "terminal" | "rules" | "about";

export interface SettingsSection {
  id: string;
  tab: SettingsTab;
  title: string;
  /** Other words it is found by. */
  keywords: string;
}

export const SETTINGS_SECTIONS: readonly SettingsSection[] = [
  {
    id: "appearance",
    tab: "general",
    title: "Appearance",
    keywords: "theme dark light follow windows density compact comfortable spacing",
  },
  {
    id: "presentation",
    tab: "general",
    title: "Presentation mode",
    keywords: "present mask screen share read-only lock hide terminal output",
  },
  {
    id: "first-run",
    tab: "general",
    title: "Setup guide and tips",
    keywords: "first run wizard welcome start getting started tips show again hints",
  },
  {
    id: "vmware",
    tab: "general",
    title: "VMware Workstation",
    keywords: "vmrun path vmrun.exe hypervisor ovftool ova ovf",
  },
  {
    id: "virtualbox",
    tab: "general",
    title: "Oracle VirtualBox",
    keywords: "vboxmanage path vboxmanage.exe hypervisor",
  },
  {
    id: "qemu-img",
    tab: "general",
    title: "Conversion tools",
    keywords: "qemu qemu-img.exe path qcow2 vhdx convert image tools export import",
  },
  { id: "docker", tab: "general", title: "Docker Desktop on this PC", keywords: "docker.exe path containers" },
  { id: "vm-folders", tab: "general", title: "VM folders", keywords: "scan folders vmx library find vms" },
  {
    id: "power",
    tab: "general",
    title: "Power actions",
    keywords: "power on limit at once shutdown wait seconds bulk start",
  },
  { id: "compare", tab: "general", title: "Compare hosts", keywords: "compare output hosts at once parallel bulk run" },
  {
    id: "vault",
    tab: "general",
    title: "Vault",
    keywords: "windows login dpapi unlock idle lock minutes",
  },
  {
    id: "retention",
    tab: "general",
    title: "Data retention",
    keywords: "job journal outputs command text purge now days keep",
  },
  { id: "history", tab: "general", title: "Dashboard history", keywords: "metrics history retention days prune" },
  { id: "dashboard", tab: "general", title: "Dashboard polling", keywords: "poll watched hosts guest seconds" },
  { id: "updates", tab: "general", title: "Updates", keywords: "update checks github token release version" },
  {
    id: "terminal",
    tab: "terminal",
    title: "Terminal",
    keywords: "keep-alive reconnect copy on select paste font notifications long commands scrollback",
  },
  {
    id: "terminal-rules",
    tab: "terminal",
    title: "Highlight and alert rules",
    keywords: "highlight colour regex error warning alert terminal rules",
  },
  {
    id: "change-ids",
    tab: "rules",
    title: "Change IDs",
    keywords: "ticket change number chg prod required approval workspace",
  },
  { id: "rules", tab: "rules", title: "Approval rules", keywords: "policy tiers read-only commands dangerous" },
  { id: "about", tab: "about", title: "About and logs", keywords: "version logs crash reports folder" },
];

/** The element id of a section's card. */
export function settingsCardId(section: string): string {
  return `settings-${section}`;
}

export function settingsSection(id: string): SettingsSection | undefined {
  return SETTINGS_SECTIONS.find((s) => s.id === id);
}
