/// <reference types="node" />
// VM-30: the build dialog's form, what it sends and why Build is off, and the words for an image's versions. Run with
// `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { Image, OsProfile } from "./api.ts";
import type { BuildCheck, BuildRecipe, ImageVersion } from "./golden-api.ts";
import type { InstallConfig } from "./install-configs-api.ts";
import {
  buildConfigs,
  buildHypervisors,
  buildReason,
  builtImages,
  defaultForm,
  factsText,
  formOfRecipe,
  formProblem,
  isoImages,
  keepText,
  parseKeep,
  recipeOf,
  requestOf,
  versionStateText,
  versionText,
  withConfig,
  withHypervisor,
  withIso,
  type BuildChoices,
} from "./golden.ts";

const image = (over: Partial<Image>): Image => ({
  id: "iso-ubuntu",
  name: "Ubuntu 24.04 server",
  source: { kind: "iso", path: "C:\\ISOs\\ubuntu-24.04-live-server-amd64.iso" },
  hypervisors: ["vmware", "virtualbox"],
  osProfile: "ubuntu",
  sha256: null,
  sizeBytes: null,
  notes: null,
  createdAt: "",
  updatedAt: "",
  problem: null,
  vmName: null,
  build: null,
  version: null,
  ...over,
});

const profile = (id: string, family: OsProfile["family"], workstation = true): OsProfile =>
  ({ id, name: id, family, workstation: workstation ? {} : null }) as unknown as OsProfile;

const config = (over: Partial<InstallConfig>): InstallConfig => ({
  id: "c-ubuntu",
  name: "Ubuntu minimal",
  kind: "autoinstall",
  body: "",
  variables: [],
  secrets: [],
  notes: null,
  builtIn: false,
  createdAt: null,
  updatedAt: null,
  problems: [],
  diskNeedMb: null,
  ...over,
});

const recipe = (over: Partial<BuildRecipe> = {}): BuildRecipe => ({
  isoImageId: "iso-ubuntu",
  installConfigId: "c-ubuntu",
  sizeId: "gp.medium",
  hypervisor: "vmware",
  network: { kind: "nat" },
  hostAdapter: null,
  vmFolder: null,
  values: {},
  addressPoolId: null,
  installMinutes: 60,
  keep: null,
  ...over,
});

const windowsIso = image({
  id: "iso-win",
  name: "Windows Server 2025",
  source: { kind: "iso", path: "C:\\ISOs\\win2025.iso" },
  osProfile: "windows-server",
});
const win11Iso = image({ id: "iso-win11", name: "Windows 11", osProfile: "windows-11" });
const golden = image({
  id: "img-golden",
  name: "Ubuntu golden",
  source: {
    kind: "goldenVm",
    vmKey: "C:\\VMs\\ubuntu-golden-v3\\ubuntu-golden-v3.vmx",
    snapshotId: "1",
    snapshotName: "Remotely image v3",
  },
  build: recipe(),
  version: 3,
});

const choices: BuildChoices = {
  images: [golden, image({}), windowsIso, win11Iso],
  configs: [
    config({ id: "c-starter", builtIn: true }),
    config({ id: "c-kick", kind: "kickstart", name: "Rocky" }),
    config({ id: "c-broken", problems: [{ severity: "error", line: 3, message: "bad YAML" }] }),
    config({ id: "c-ubuntu", variables: [{ name: "team", default: "lab" }] }),
    config({ id: "c-debian", kind: "preseed", name: "Debian 12" }),
    config({ id: "c-win", kind: "unattend", name: "Server 2025", variables: [{ name: "org", default: null }] }),
  ],
  profiles: [profile("ubuntu", "linux"), profile("windows-server", "windows"), profile("windows-11", "windows", false)],
};

test("only ISO images are built from, and only images with a recipe are rebuilt", () => {
  assert.deepEqual(
    isoImages(choices.images).map((i) => i.id),
    ["iso-ubuntu", "iso-win", "iso-win11"],
  );
  assert.deepEqual(
    builtImages(choices.images).map((i) => i.id),
    ["img-golden"],
  );
});

test("a build takes own configs of the three kinds Remotely delivers, for the ISO's system", () => {
  assert.deepEqual(
    buildConfigs(choices.configs, "linux").map((c) => c.id),
    ["c-broken", "c-ubuntu", "c-debian"],
  );
  assert.deepEqual(
    buildConfigs(choices.configs, "windows").map((c) => c.id),
    ["c-win"],
  );
  assert.equal(buildConfigs(choices.configs).length, 4, "an ISO of no known system takes any of them");
  assert.deepEqual(buildHypervisors(win11Iso, choices.profiles), ["virtualbox"], "Windows 11: VirtualBox only");
  assert.deepEqual(buildHypervisors(image({ hypervisors: ["vmware"] }), choices.profiles), ["vmware"]);
});

test("a new build starts from the first ISO and config that can be used, on NAT, for an hour", () => {
  const form = defaultForm(choices);
  assert.equal(form.isoImageId, "iso-ubuntu");
  assert.equal(form.installConfigId, "c-ubuntu", "the starter, Kickstart and a config with errors are passed over");
  assert.equal(form.hypervisor, "vmware");
  assert.deepEqual(form.network, { kind: "nat" });
  assert.equal(form.sizeId, "gp.medium");
  assert.equal(form.minutes, "60");
  assert.equal(form.keepOn, false, "every version is kept unless asked");
  assert.equal(form.name, "");
  const empty = defaultForm({ images: [], configs: [], profiles: [] });
  assert.equal(empty.isoImageId, "");
  assert.equal(
    formProblem({ ...empty, name: "x" }, "new", { images: [] }),
    "Add an ISO image first: a build installs from one",
  );
});

test("another ISO keeps what still fits and picks what must change", () => {
  const ubuntu = { ...defaultForm(choices), values: { team: "web" } };
  const windows = withIso(ubuntu, "iso-win", choices);
  assert.equal(windows.installConfigId, "c-win", "a Windows ISO takes a Windows unattend");
  assert.deepEqual(windows.values, {}, "the Linux config's variables go");
  const vbox = withHypervisor({ ...ubuntu, network: { kind: "vmnet", number: 3 }, addressPoolId: "p1" }, "virtualbox");
  assert.deepEqual(vbox.network, { kind: "nat" }, "VirtualBox has no vmnets");
  assert.equal(vbox.addressPoolId, null, "a pool is one hypervisor's");
  const win11 = withIso({ ...ubuntu, hypervisor: "vmware" }, "iso-win11", choices);
  assert.equal(win11.hypervisor, "virtualbox");
  assert.deepEqual(withConfig(ubuntu, config({ id: "c-other", variables: [{ name: "team", default: null }] })).values, {
    team: "web",
  });
  assert.equal(withIso(ubuntu, "iso-ubuntu", choices).installConfigId, "c-ubuntu");
});

test("the form's checks come before the core is asked", () => {
  const ok = { ...defaultForm(choices), name: "Ubuntu golden 2" };
  assert.equal(formProblem(ok, "new", choices), null);
  assert.equal(formProblem({ ...ok, name: "  " }, "new", choices), "Give the image a name");
  assert.equal(formProblem({ ...ok, name: "" }, "settings", choices), null, "the settings don't rename the image");
  assert.match(formProblem({ ...ok, name: "x".repeat(81) }, "new", choices) ?? "", /at most 80/);
  assert.match(formProblem({ ...ok, minutes: "0" }, "new", choices) ?? "", /1 to 240/);
  assert.match(formProblem({ ...ok, minutes: "241" }, "new", choices) ?? "", /1 to 240/);
  assert.equal(formProblem({ ...ok, keepOn: true, keep: "21" }, "new", choices), "Keep 1 to 20 versions");
  assert.equal(formProblem({ ...ok, keepOn: false, keep: "21" }, "new", choices), null, "off: not looked at");
  assert.match(formProblem({ ...ok, installConfigId: "" }, "new", choices) ?? "", /install config first/);
  assert.equal(parseKeep(" 5 "), 5);
  assert.equal(parseKeep("0"), null);
  assert.equal(parseKeep("2.5"), null);
});

test("the request carries the recipe as the core reads it", () => {
  const form = {
    ...defaultForm(choices),
    name: " Ubuntu golden 2 ",
    values: { team: " web ", empty: "  " },
    keepOn: true,
    keep: "4",
    hypervisor: "virtualbox" as const,
    network: { kind: "nat" as const },
    hostAdapter: "vboxnet0",
  };
  const request = requestOf(form, "new");
  assert.deepEqual(request?.target, { kind: "new", name: "Ubuntu golden 2" });
  assert.deepEqual(request?.recipe.values, { team: "web" }, "empty values take the config's defaults");
  assert.equal(request?.recipe.keep, 4);
  assert.equal(request?.recipe.installMinutes, 60);
  assert.equal(request?.recipe.hostAdapter, null, "NAT names no adapter");
  assert.equal(recipeOf({ ...form, network: { kind: "hostOnly" } })?.hostAdapter, "vboxnet0");
  assert.equal(recipeOf({ ...form, keepOn: false })?.keep, null);
  assert.equal(recipeOf({ ...form, minutes: "x" }), null);
  assert.deepEqual(requestOf(form, "settings", "img-golden")?.target, { kind: "image", id: "img-golden" });
  assert.equal(requestOf(form, "settings"), null);
});

test("saved build settings come back as they were saved", () => {
  const saved = recipe({ keep: 2, vmFolder: "D:\\Golden", values: { team: "web" }, installMinutes: 90 });
  const form = formOfRecipe("Ubuntu golden", saved);
  assert.equal(form.keepOn, true);
  assert.equal(form.keep, "2");
  assert.equal(form.minutes, "90");
  assert.deepEqual(recipeOf(form), saved);
  assert.equal(formOfRecipe("x", recipe()).keepOn, false);
});

test("Build says why it can't be pressed; Save goes on when only the run itself is refused", () => {
  const base = { mode: "new" as const, readOnly: null, busy: false, problem: null, checking: false, error: null };
  const refused: BuildCheck = { problems: ["The drive has 3 GB free; the build needs 40 GB."], preview: {} as never };
  const unplanned: BuildCheck = { problems: ["The build's install config was deleted: pick another."], preview: null };
  const fine: BuildCheck = { problems: [], preview: {} as never };
  assert.equal(buildReason({ ...base, check: fine }), null);
  assert.equal(buildReason({ ...base, check: refused }), refused.problems[0]);
  assert.equal(buildReason({ ...base, check: unplanned }), unplanned.problems[0]);
  assert.equal(buildReason({ ...base, mode: "settings", check: refused }), null);
  assert.equal(buildReason({ ...base, mode: "settings", check: unplanned }), unplanned.problems[0]);
  assert.equal(buildReason({ ...base, checking: true, check: fine }), "Checking…");
  assert.equal(buildReason({ ...base, check: null }), "Checking…");
  assert.equal(buildReason({ ...base, busy: true, check: fine }), "Submitting…");
  assert.equal(buildReason({ ...base, mode: "settings", busy: true, check: fine }), "Saving…");
  assert.equal(buildReason({ ...base, problem: "Give the image a name", check: fine }), "Give the image a name");
  assert.equal(buildReason({ ...base, readOnly: "Read-only", busy: true, check: fine }), "Read-only");
  assert.equal(buildReason({ ...base, error: "No answer", check: null }), "No answer");
});

test("versions in words", () => {
  const version = (over: Partial<ImageVersion>): ImageVersion => ({
    id: "v",
    number: 3,
    state: "kept",
    hypervisor: "vmware",
    vmKey: "C:\\VMs\\ubuntu-golden-v3\\ubuntu-golden-v3.vmx",
    vmName: "ubuntu-golden-v3",
    snapshotName: "Remotely image v3",
    configName: "Ubuntu minimal",
    builtAt: "2026-11-01T02:00:00Z",
    deletedAt: null,
    linkedClones: [],
    clonesUnread: null,
    facts: {},
    ...over,
  });
  assert.equal(versionText(3), "Version 3");
  assert.equal(versionText(null), "No version yet");
  assert.equal(versionStateText(version({ state: "newest", linkedClones: ["web-1"] })), "Newest");
  assert.equal(versionStateText(version({})), "Kept");
  assert.equal(versionStateText(version({ linkedClones: ["web-1"] })), "Kept: 1 linked clone uses it");
  assert.equal(versionStateText(version({ linkedClones: ["web-1", "web-2"] })), "Kept: 2 linked clones use it");
  assert.equal(versionStateText(version({ state: "deleted" })), "Deleted");
  assert.deepEqual(factsText({ cloudInit: false, vmTools: false }), ["no cloud-init", "no open-vm-tools"]);
  assert.deepEqual(factsText({ cloudInit: true, vmTools: null }), [], "only what is missing, never what wasn't said");
  assert.equal(keepText(null), "Keeps every version");
  assert.equal(keepText(1), "Keeps only the newest version");
  assert.equal(keepText(5), "Keeps the newest 5 versions");
});
