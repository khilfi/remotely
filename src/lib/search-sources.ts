// QL-20: what each kind of thing is found by, as pure functions from what the app already read to search items
// (search.ts ranks them; search-providers.ts loads the data). Tested in search.test.ts.

import type { Favourite, Image, LaunchTemplate, LibraryEntry, SessionRecord, Size, VmRecord } from "./api.ts";
import type { CachedContainers } from "./container-cache.ts";
import type { SearchField, SearchItem } from "./search.ts";
import type { SettingsSection } from "./settings-index.ts";

function field(text: string | null | undefined, kind: SearchField["kind"]): SearchField[] {
  return text ? [{ text, kind }] : [];
}

function tags(list: readonly string[]): SearchField[] {
  return list.map((text) => ({ text, kind: "tag" as const }));
}

const POWER: Record<string, string> = {
  running: "running",
  paused: "paused",
  suspended: "suspended",
  not_running: "off",
  unknown: "unknown",
};

/** VMs by name, IP, tag, guest OS and hypervisor; choosing one shows its actions. Running VMs come first on a tie. */
export function vmItems(vms: readonly VmRecord[]): SearchItem[] {
  return vms.map((vm) => ({
    id: `vm:${vm.vmxPath}`,
    provider: "vms",
    title: vm.displayName,
    detail: vm.ipAddress ?? undefined,
    detailMask: vm.ipAddress ? "ip" : undefined,
    badge: POWER[vm.powerState] ?? vm.powerState,
    fields: [
      ...field(vm.displayName, "name"),
      ...field(vm.ipAddress, "address"),
      ...tags(vm.tags),
      ...field(vm.environment !== "none" ? vm.environment : null, "tag"),
      ...field(vm.guestOsName ?? vm.guestOs, "detail"),
      ...field(vm.hypervisor === "virtualbox" ? "VirtualBox" : "VMware Workstation", "detail"),
    ],
    target: { drill: "vm", id: vm.vmxPath },
    boost: vm.powerState === "running" ? 2 : 0,
  }));
}

/** Sessions by name, host, the address and name it last reached (QL-03), user and tag; choosing one shows its actions. */
export function sessionItems(sessions: readonly SessionRecord[]): SearchItem[] {
  return sessions.map((s) => ({
    id: `session:${s.id}`,
    provider: "sessions",
    title: s.name,
    detail: s.host,
    detailMask: "host",
    fields: [
      ...field(s.name, "name"),
      ...field(s.host, "address"),
      ...field(s.lastIp, "address"),
      ...field(s.lastHostname, "address"),
      ...field(s.username, "detail"),
      ...tags(s.tags),
      ...field(s.environment !== "none" ? s.environment : null, "tag"),
    ],
    target: { drill: "session", id: s.id },
  }));
}

/** Containers the Containers page read last, by name, image, Compose project and host. */
export function containerItems(lists: readonly CachedContainers[]): SearchItem[] {
  return lists.flatMap((list) =>
    list.containers.map((c) => ({
      id: `container:${list.hostName}:${list.engine}:${c.id}`,
      provider: "containers",
      title: c.name,
      detail: `${c.image} on ${list.hostName}`,
      badge: c.state,
      fields: [
        ...field(c.name, "name"),
        ...field(c.image, "detail"),
        ...field(c.project, "tag"),
        ...field(list.hostName, "detail"),
        ...field(c.id.slice(0, 12), "detail"),
      ],
      target: { open: { kind: "container" as const, host: list.host, engine: list.engine, containerId: c.id } },
      boost: c.state === "running" ? 1 : 0,
    })),
  );
}

/** VM-21 launch templates by name, tag and naming pattern. */
export function templateItems(templates: readonly LaunchTemplate[]): SearchItem[] {
  return templates.map((t) => ({
    id: `template:${t.id}`,
    provider: "templates",
    title: t.name,
    detail: t.problems.length > 0 ? "can't deploy now" : "launch template",
    fields: [...field(t.name, "name"), ...tags(t.tags), ...field(t.namingPattern, "detail")],
    target: { open: { kind: "catalog" as const, tab: "templates" as const, id: t.id } },
  }));
}

function sizeDetail(s: Size) {
  const vcpus = s.sockets * s.coresPerSocket;
  const gb = s.memoryMb >= 1024 ? `${Math.round((s.memoryMb / 1024) * 10) / 10} GB` : `${s.memoryMb} MB`;
  const disk = s.disks.reduce((sum, d) => sum + d.sizeGb, 0);
  return `${vcpus} vCPU, ${gb}, ${disk} GB disk`;
}

/** VM-19 sizes by name and description. */
export function sizeItems(sizes: readonly Size[]): SearchItem[] {
  return sizes.map((s) => ({
    id: `size:${s.id}`,
    provider: "sizes",
    title: s.name,
    detail: sizeDetail(s),
    badge: s.builtIn ? "built-in" : undefined,
    fields: [...field(s.name, "name"), ...field(s.description, "detail")],
    target: { open: { kind: "catalog" as const, tab: "sizes" as const, id: s.id } },
  }));
}

function imageDetail(image: Image) {
  switch (image.source.kind) {
    case "goldenVm":
      return `golden VM ${image.vmName ?? ""}, snapshot ${image.source.snapshotName}`.replace("  ", " ");
    case "cloudImage":
      return `cloud image (${image.source.format})`;
    case "iso":
      return "ISO";
    case "appliance":
      return `appliance (${image.source.format})`;
  }
}

/** VM-20 images by name, file path, golden VM and notes. */
export function imageItems(images: readonly Image[]): SearchItem[] {
  return images.map((image) => ({
    id: `image:${image.id}`,
    provider: "images",
    title: image.name,
    detail: imageDetail(image),
    fields: [
      ...field(image.name, "name"),
      ...field("path" in image.source ? image.source.path : null, "detail"),
      ...field(image.vmName, "detail"),
      ...field(image.notes, "detail"),
      ...field(image.osProfile, "tag"),
    ],
    target: { open: { kind: "catalog" as const, tab: "images" as const, id: image.id } },
  }));
}

/** BX-08 favourite and built-in commands by name, command and group; choosing one shows it in the command panel. */
export function snippetItems(favourites: readonly Favourite[], library: readonly LibraryEntry[]): SearchItem[] {
  const own = favourites.map((f) => ({
    id: `favourite:${f.id}`,
    provider: "snippets",
    title: f.name,
    detail: f.command,
    badge: "favourite",
    fields: [
      ...field(f.name, "name"),
      ...field(f.command, "detail"),
      ...field(f.description, "detail"),
      ...field(f.folder, "tag"),
    ],
    target: { open: { kind: "snippet" as const, command: f.name } },
    boost: 1,
  }));
  const builtIn = library.map((e) => ({
    id: `library:${e.id}`,
    provider: "snippets",
    title: e.name,
    detail: e.command,
    fields: [
      ...field(e.name, "name"),
      ...field(e.command, "detail"),
      ...field(e.groupLabel, "tag"),
      ...field(e.description, "detail"),
    ],
    target: { open: { kind: "snippet" as const, command: e.name } },
  }));
  return [...own, ...builtIn];
}

/** Settings by their cards' labels and the words they cover. */
export function settingItems(sections: readonly SettingsSection[]): SearchItem[] {
  return sections.map((s) => ({
    id: `setting:${s.id}`,
    provider: "settings",
    title: s.title,
    detail: "Settings",
    fields: [...field(s.title, "name"), ...s.keywords.split(/\s+/).flatMap((w) => field(w, "tag"))],
    target: { open: { kind: "setting" as const, section: s.id } },
  }));
}

/** The pages, by their names. */
export function pageItems(pages: readonly { id: string; label: string; shortcut?: string }[]): SearchItem[] {
  return pages.map((p) => ({
    id: `page:${p.id}`,
    provider: "pages",
    title: p.label,
    badge: p.shortcut,
    fields: [...field(p.label, "name"), ...field("go to page", "detail")],
    target: { open: { kind: "page" as const, page: p.id } },
  }));
}

/** The palette's actions, by their labels and keywords. */
export function actionItems(actions: readonly { id: string; label: string; keywords?: string }[]): SearchItem[] {
  return actions.map((a) => ({
    id: `action:${a.id}`,
    provider: "actions",
    title: a.label,
    fields: [...field(a.label, "name"), ...(a.keywords ?? "").split(/\s+/).flatMap((w) => field(w, "tag"))],
    target: { action: a.id },
  }));
}
