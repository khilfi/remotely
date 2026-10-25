/// <reference types="node" />
// QL-20 global search: ranking, the providers' items, the settings index and the containers the page read last.
// Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  ContainerSummary,
  Favourite,
  Image,
  LaunchTemplate,
  LibraryEntry,
  SessionRecord,
  Size,
  VmRecord,
} from "./api.ts";
import type { ScheduleView } from "./schedules-api.ts";
import { cachedContainers, keepContainerHosts, rememberContainers, resetContainerCache } from "./container-cache.ts";
import { groupRanked, matchQuality, normalise, queryWords, rankItems, scoreItem, type SearchItem } from "./search.ts";
import {
  actionItems,
  containerItems,
  imageItems,
  pageItems,
  scheduleItems,
  sessionItems,
  settingItems,
  sizeItems,
  snippetItems,
  templateItems,
  vmItems,
} from "./search-sources.ts";
import { SETTINGS_SECTIONS, settingsCardId, settingsSection } from "./settings-index.ts";

function vm(name: string, extra: Partial<VmRecord> = {}): VmRecord {
  return {
    id: `id-${name}`,
    vmxPath: `C:\\VMs\\${name}\\${name}.vmx`,
    hypervisor: "vmware",
    configPath: null,
    displayName: name,
    guestOs: "ubuntu-64",
    guestOsName: "Ubuntu 24.04 LTS",
    numVcpus: 2,
    memsizeMb: 4096,
    powerState: "not_running",
    ipAddress: null,
    toolsState: null,
    environment: "none",
    protected: false,
    tags: [],
    lastSeenAt: null,
    ...extra,
  };
}

function session(name: string, host: string, extra: Partial<SessionRecord> = {}): SessionRecord {
  return {
    id: `s-${name}`,
    name,
    host,
    port: 22,
    username: "alice",
    tags: [],
    environment: "none",
    lastIp: null,
    lastHostname: null,
    vmId: null,
    jumpSessionId: null,
    ...extra,
  } as unknown as SessionRecord;
}

function item(title: string, fields: SearchItem["fields"], provider = "vms", boost = 0): SearchItem {
  return { id: `${provider}:${title}`, provider, title, fields, target: { action: title }, boost };
}

test("matches rank exact, then prefix, then word start, then inside, then letters in order", () => {
  assert.equal(matchQuality("web01", "web01"), 100);
  assert.equal(matchQuality("web", "web01"), 80);
  assert.equal(matchQuality("prod", "web-prod-1"), 60);
  assert.equal(matchQuality("eb0", "web01"), 40);
  assert.ok(matchQuality("wb1", "web01") > 0 && matchQuality("wb1", "web01") < 40);
  assert.equal(matchQuality("zz", "web01"), 0);
  assert.equal(matchQuality("x", "web01"), 0, "one letter is never a letters-in-order match");
  assert.equal(matchQuality("shop", "dashboard polling"), 0, "too many letters skipped");
  assert.equal(matchQuality("shop", "present: mask host names, ip addresses"), 0);
  assert.ok(matchQuality("sbn", "sub-net") > 0, "a few skipped letters still match");
});

test("text is matched without case or accents", () => {
  assert.equal(normalise("Café ÉTÉ"), "cafe ete");
  assert.deepEqual(queryWords("  Web   Prod "), ["web", "prod"]);
});

test("every word of the query has to match some field", () => {
  const web = item("web01", [
    { text: "web01", kind: "name" },
    { text: "prod", kind: "tag" },
  ]);
  assert.ok(scoreItem(["web", "prod"], web) > 0);
  assert.equal(scoreItem(["web", "staging"], web), 0);
  assert.equal(scoreItem([], web), 0);
});

test("a name that starts with the word beats a keyword that is the word", () => {
  const size = item("disk.large", [{ text: "disk.large", kind: "name" }], "sizes");
  const action = item(
    "VM sizes",
    [
      { text: "VM sizes", kind: "name" },
      { text: "disk", kind: "tag" },
    ],
    "actions",
  );
  assert.equal(rankItems("disk", [action, size], ["actions", "sizes"])[0].item.title, "disk.large");
});

test("a name beats a tag, and a tag beats a detail, for the same match", () => {
  const named = item("web", [{ text: "web", kind: "name" }]);
  const tagged = item("db01", [{ text: "web", kind: "tag" }]);
  const detailed = item("db02", [{ text: "web", kind: "detail" }]);
  const ranked = rankItems("web", [detailed, tagged, named]).map((r) => r.item.title);
  assert.deepEqual(ranked, ["web", "db01", "db02"]);
});

test("letters in order only count in names, never in paths or commands", () => {
  const path = item("ubuntu", [
    { text: "ubuntu", kind: "name" },
    { text: "C:\\Images\\noble.vmdk", kind: "detail" },
  ]);
  assert.equal(scoreItem(["cmk"], path), 0);
  const name = item("web01", [{ text: "web01", kind: "name" }]);
  assert.ok(scoreItem(["wb1"], name) > 0);
});

test("a boost settles ties but never beats a better match", () => {
  const off = item("web01", [{ text: "web01", kind: "name" }], "vms", 0);
  const on = item("web02", [{ text: "web02", kind: "name" }], "vms", 2);
  assert.deepEqual(
    rankItems("web", [off, on]).map((r) => r.item.title),
    ["web02", "web01"],
  );
  const exact = item("web", [{ text: "web", kind: "name" }], "vms", 0);
  assert.equal(rankItems("web", [on, exact])[0].item.title, "web");
});

test("groups show the best group first, each best first, with what is past the limit", () => {
  const items = [
    item("web01", [{ text: "web01", kind: "name" }], "sessions"),
    item("web", [{ text: "web", kind: "name" }], "vms"),
    ...Array.from({ length: 8 }, (_, i) =>
      item(`web-host-${i}`, [{ text: `web-host-${i}`, kind: "name" }], "sessions"),
    ),
  ];
  const groups = groupRanked(rankItems("web", items), 6);
  assert.equal(groups[0].provider, "vms", "the exact match's group comes first");
  assert.equal(groups[1].items.length, 6);
  assert.equal(groups[1].more, 3);
});

test("VMs are found by name, IP, tag and guest OS, and choosing one shows its actions", () => {
  const vms = [
    vm("web01", { ipAddress: "192.0.2.10", tags: ["frontend"], powerState: "running" }),
    vm("db01", { ipAddress: "192.0.2.20", hypervisor: "virtualbox" }),
  ];
  const items = vmItems(vms);
  assert.equal(rankItems("192.0.2.1", items)[0].item.title, "web01");
  assert.equal(rankItems("frontend", items)[0].item.title, "web01");
  assert.equal(rankItems("virtualbox", items)[0].item.title, "db01");
  assert.equal(rankItems("ubuntu", items).length, 2);
  assert.deepEqual(items[0].target, { drill: "vm", id: vms[0].vmxPath });
  assert.equal(items[0].detailMask, "ip", "FD-03: the IP is masked as one value");
  assert.equal(items[0].badge, "running");
});

test("sessions are found by name, host, the address they last reached, user and tag", () => {
  const items = sessionItems([
    session("web", "web01.example.com", { lastIp: "198.51.100.7", tags: ["prod"] }),
    session("jump", "bastion.example.org", { username: "bob" }),
  ]);
  assert.equal(rankItems("example.com", items)[0].item.title, "web");
  assert.equal(rankItems("198.51.100", items)[0].item.title, "web");
  assert.equal(rankItems("bob", items)[0].item.title, "jump");
  assert.equal(rankItems("prod", items)[0].item.title, "web");
  assert.deepEqual(items[0].target, { drill: "session", id: "s-web" });
  assert.equal(items[0].detailMask, "host");
});

test("containers come from what the Containers page read last, and go with their host", () => {
  resetContainerCache();
  const summary = { id: "a1b2c3d4e5f6a7b8", name: "shop-web", image: "nginx:1.27", project: "shop", state: "running" };
  rememberContainers({
    host: { kind: "session", sessionId: "s-1" },
    engine: "docker",
    hostName: "docker01",
    containers: [summary as unknown as ContainerSummary],
    readAt: "2026-10-25T10:00:00Z",
  });
  const items = containerItems(cachedContainers());
  assert.equal(rankItems("nginx", items)[0].item.title, "shop-web");
  assert.equal(rankItems("shop", items).length, 1);
  assert.equal(rankItems("docker01", items).length, 1);
  assert.deepEqual(items[0].target, {
    open: { kind: "container", host: { kind: "session", sessionId: "s-1" }, engine: "docker", containerId: summary.id },
  });
  keepContainerHosts([{ host: { kind: "thisPc" }, engines: [{ engine: "docker" }] }]);
  assert.equal(cachedContainers().length, 0, "the host is no longer marked");
});

test("templates, sizes and images open their rows on the Templates page", () => {
  const template = { id: "t1", name: "web tier", tags: ["web"], namingPattern: "web-{n}", problems: [] };
  const size = {
    id: "gp.medium",
    name: "gp.medium",
    builtIn: true,
    sockets: 1,
    coresPerSocket: 2,
    memoryMb: 4096,
    disks: [{ sizeGb: 40 }],
    description: "general Linux server",
  };
  const image = {
    id: "i1",
    name: "Ubuntu 24.04 cloud",
    source: { kind: "cloudImage", path: "C:\\Images\\noble.vmdk", format: "vmdk" },
    osProfile: "ubuntu-24.04",
    vmName: null,
    notes: null,
  };
  const t = templateItems([template as unknown as LaunchTemplate]);
  const s = sizeItems([size as unknown as Size]);
  const i = imageItems([image as unknown as Image]);
  assert.deepEqual(t[0].target, { open: { kind: "catalog", tab: "templates", id: "t1" } });
  assert.equal(s[0].detail, "2 vCPU, 4 GB, 40 GB disk");
  assert.equal(s[0].badge, "built-in");
  assert.equal(rankItems("general linux", s).length, 1);
  assert.equal(rankItems("noble", i)[0].item.title, "Ubuntu 24.04 cloud");
  assert.deepEqual(i[0].target, { open: { kind: "catalog", tab: "images", id: "i1" } });
});

test("commands are found by name, text and group; favourites first on a tie", () => {
  const favourite = { id: "f1", name: "disk usage", command: "df -h", description: null, folder: "storage" };
  const entry = {
    id: "l1",
    name: "disk usage",
    command: "du -sh *",
    description: "Size of each file",
    groupLabel: "Disks",
  };
  const items = snippetItems([favourite as unknown as Favourite], [entry as unknown as LibraryEntry]);
  const ranked = rankItems("disk", items);
  assert.equal(ranked[0].item.id, "favourite:f1");
  assert.equal(rankItems("df -h", items)[0].item.id, "favourite:f1");
  // A command listed under a runbook and under its area is one result.
  const twice = snippetItems([], [entry, { ...entry, id: "l2", groupLabel: "Slow disk" }] as unknown as LibraryEntry[]);
  assert.equal(twice.length, 1);
  assert.deepEqual(items[1].target, { open: { kind: "snippet", command: "disk usage" } });
});

test("settings are found by their cards' labels and the words they cover", () => {
  const items = settingItems(SETTINGS_SECTIONS);
  assert.equal(rankItems("vmrun", items)[0].item.title, "VMware Workstation");
  assert.equal(rankItems("density", items)[0].item.title, "Appearance");
  assert.equal(rankItems("idle lock", items)[0].item.title, "Vault");
  assert.deepEqual(items.find((i) => i.title === "Updates")?.target, { open: { kind: "setting", section: "updates" } });
});

test("every settings section has a unique id, a known tab and a card id", () => {
  const ids = SETTINGS_SECTIONS.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const s of SETTINGS_SECTIONS) {
    assert.ok(["general", "terminal", "rules", "about"].includes(s.tab), s.id);
    assert.equal(settingsCardId(s.id), `settings-${s.id}`);
    assert.equal(settingsSection(s.id), s);
  }
  assert.equal(settingsSection("nope"), undefined);
});

test("pages and the palette's actions are searched too", () => {
  const pages = pageItems([{ id: "map", label: "Map", shortcut: "Ctrl+0" }]);
  assert.deepEqual(pages[0].target, { open: { kind: "page", page: "map" } });
  assert.equal(pages[0].badge, "Ctrl+0");
  const actions = actionItems([{ id: "lock", label: "Lock the vault", keywords: "secure" }]);
  assert.equal(rankItems("secure", actions)[0].item.title, "Lock the vault");
  assert.deepEqual(actions[0].target, { action: "lock" });
});

test("schedules are found by name, their VMs and tags, and what they do; choosing one shows its runs", () => {
  const schedule = {
    id: "s1",
    name: "nightly lab",
    action: "Take a snapshot, keep the last 7",
    when: "Daily at 02:00",
    state: "needsApproval",
    targets: [
      { target: { kind: "vm", vmKey: "C:\\VMs\\web01\\web01.vmx" }, name: "web01", vms: 1 },
      { target: { kind: "tag", tag: "lab" }, name: "lab", vms: 3 },
    ],
  };
  const items = scheduleItems([schedule as unknown as ScheduleView]);
  assert.deepEqual(items[0].target, { open: { kind: "schedule", scheduleId: "s1" } });
  assert.equal(items[0].badge, "needs approval");
  assert.equal(items[0].detail, "Take a snapshot, keep the last 7 · Daily at 02:00");
  for (const query of ["nightly", "web01", "lab", "snapshot", "daily"]) {
    assert.equal(rankItems(query, items).length, 1, query);
  }
});
