// VM-30 (0.8.0 G7) golden image builds in the window, as pure functions (tested in golden.test.ts): the build dialog's
// form (a recipe's defaults from what is picked, kept consistent as the ISO, the config and the hypervisor change),
// what it sends, its QL-08 reason when Build or Save is off, and the words for versions ("Version 3", "Kept: 2 linked
// clones use it", "no cloud-init"). The core checks everything again.

import type { Hypervisor, Image, OsProfile, TemplateNetwork } from "./api.ts";
import type { BuildCheck, BuildOs, BuildRecipe, BuildRequest, BuildTarget, ImageVersion } from "./golden-api.ts";
import type { InstallConfig, InstallKind } from "./install-configs-api.ts";
import { networkKinds, profileHypervisors } from "./catalog.ts";
import { plural } from "./format.ts";
import { DEFAULT_INSTALL_MINUTES, MAX_INSTALL_MINUTES, parseMinutes } from "./unattended.ts";

/** The config kinds Remotely builds images from (the core refuses the others with a problem). */
export const BUILD_KINDS: readonly InstallKind[] = ["autoinstall", "preseed", "unattend"];
/** The core's limits (golden/spec.rs, catalog/images.rs). */
export const MAX_KEEP_VERSIONS = 20;
export const MAX_IMAGE_NAME = 80;
/** What "Keep only the newest N versions" offers when it is turned on. */
export const DEFAULT_KEEP = 3;
/** A new build's size when nothing else is picked (a built-in). */
export const DEFAULT_SIZE = "gp.medium";

export const BUILD_OS_LABEL: Record<BuildOs, string> = {
  ubuntu: "Ubuntu",
  debian: "Debian",
  windows: "Windows",
};

/** The build dialog: a new image, or the build settings of an image Remotely builds. */
export type BuildMode = "new" | "settings";

/** What the dialog holds while it is filled in. Numbers stay text until they are checked. */
export interface BuildForm {
  /** A new image's name (the settings of an existing image don't rename it). */
  name: string;
  isoImageId: string;
  installConfigId: string;
  sizeId: string;
  hypervisor: Hypervisor;
  network: TemplateNetwork;
  hostAdapter: string | null;
  /** Null: the hypervisor's default folder. */
  vmFolder: string | null;
  /** The install config's own variables, as typed; an empty one takes its default. */
  values: Record<string, string>;
  addressPoolId: string | null;
  /** The install's time limit, in minutes. */
  minutes: string;
  /** Keep only the newest N versions (off: every version). */
  keepOn: boolean;
  keep: string;
}

/** What the dialog picks from. */
export interface BuildChoices {
  images: Image[];
  configs: InstallConfig[];
  profiles: OsProfile[];
}

/** The catalogue's ISO images, which a build installs from. */
export function isoImages(images: Image[]): Image[] {
  return images.filter((i) => i.source.kind === "iso");
}

/** The images Remotely builds (those a rebuild schedule can pick). */
export function builtImages(images: Image[]): Image[] {
  return images.filter((i) => i.build !== null);
}

/** The OS family of an ISO image's profile, when it is known. */
export function isoFamily(iso: Image | undefined, profiles: OsProfile[]): OsProfile["family"] | undefined {
  return profiles.find((p) => p.id === iso?.osProfile)?.family;
}

/** Own configs a build can install from: Ubuntu autoinstall, Debian preseed and Windows unattend, for the ISO's family. */
export function buildConfigs(configs: InstallConfig[], family?: OsProfile["family"]): InstallConfig[] {
  return configs.filter(
    (c) =>
      !c.builtIn &&
      BUILD_KINDS.includes(c.kind) &&
      (family === undefined || (c.kind === "unattend") === (family === "windows")),
  );
}

/** The hypervisors an ISO image deploys on, its OS profile allowing (Windows 11: VirtualBox only). */
export function buildHypervisors(iso: Image | undefined, profiles: OsProfile[]): Hypervisor[] {
  const profile = profiles.find((p) => p.id === iso?.osProfile);
  const listed: Hypervisor[] = iso?.hypervisors.length ? iso.hypervisors : ["vmware", "virtualbox"];
  return listed.filter((h) => profileHypervisors(profile).includes(h));
}

/** VirtualBox's host-only and bridged networks name an adapter of this PC. */
export function needsHostAdapter(hypervisor: Hypervisor, network: TemplateNetwork): boolean {
  return hypervisor === "virtualbox" && (network.kind === "hostOnly" || network.kind === "bridged");
}

const hasErrors = (c: InstallConfig) => c.problems.some((p) => p.severity === "error");

/** The first item that can be used, else the first. */
function firstOf<T>(items: T[], usable: (item: T) => boolean): T | undefined {
  return items.find(usable) ?? items[0];
}

/** A new build's defaults from what there is: the first ISO image and config that can be used, NAT, an hour. */
export function defaultForm(choices: BuildChoices): BuildForm {
  const blank: BuildForm = {
    name: "",
    isoImageId: "",
    installConfigId: "",
    sizeId: DEFAULT_SIZE,
    hypervisor: "vmware",
    network: { kind: "nat" },
    hostAdapter: null,
    vmFolder: null,
    values: {},
    addressPoolId: null,
    minutes: String(DEFAULT_INSTALL_MINUTES),
    keepOn: false,
    keep: String(DEFAULT_KEEP),
  };
  const iso = firstOf(isoImages(choices.images), (i) => i.problem === null);
  return iso ? withIso(blank, iso.id, choices) : blank;
}

/** The form for an image's saved build settings. */
export function formOfRecipe(name: string, recipe: BuildRecipe): BuildForm {
  return {
    name,
    isoImageId: recipe.isoImageId,
    installConfigId: recipe.installConfigId,
    sizeId: recipe.sizeId,
    hypervisor: recipe.hypervisor,
    network: recipe.network,
    hostAdapter: recipe.hostAdapter ?? null,
    vmFolder: recipe.vmFolder ?? null,
    values: { ...recipe.values },
    addressPoolId: recipe.addressPoolId ?? null,
    minutes: String(recipe.installMinutes),
    keepOn: recipe.keep !== null,
    keep: String(recipe.keep ?? DEFAULT_KEEP),
  };
}

/**
 * Another ISO image: the config stays when it fits its system (else the first that does), and so does the hypervisor
 * when the ISO deploys on it.
 */
export function withIso(form: BuildForm, isoImageId: string, choices: BuildChoices): BuildForm {
  const iso = choices.images.find((i) => i.id === isoImageId);
  const configs = buildConfigs(choices.configs, isoFamily(iso, choices.profiles));
  const config = configs.find((c) => c.id === form.installConfigId) ?? firstOf(configs, (c) => !hasErrors(c));
  const hypervisors = buildHypervisors(iso, choices.profiles);
  const hypervisor = hypervisors.includes(form.hypervisor) ? form.hypervisor : (hypervisors[0] ?? form.hypervisor);
  const next = config ? withConfig({ ...form, isoImageId }, config) : { ...form, isoImageId, installConfigId: "" };
  return withHypervisor(next, hypervisor);
}

/** Another install config: the values of the variables it has too are kept, the rest dropped. */
export function withConfig(form: BuildForm, config: InstallConfig): BuildForm {
  const names = new Set(config.variables.map((v) => v.name));
  const values = Object.fromEntries(Object.entries(form.values).filter(([name]) => names.has(name)));
  return { ...form, installConfigId: config.id, values };
}

/** Another hypervisor: a network it has (else NAT); the adapter and the pool were the other hypervisor's. */
export function withHypervisor(form: BuildForm, hypervisor: Hypervisor): BuildForm {
  if (hypervisor === form.hypervisor && networkKinds(hypervisor).includes(form.network.kind)) return form;
  const network = networkKinds(hypervisor).includes(form.network.kind) ? form.network : { kind: "nat" as const };
  return { ...form, hypervisor, network, hostAdapter: null, addressPoolId: null };
}

/** How many versions to keep, as typed: 1 to the most, or null. */
export function parseKeep(text: string): number | null {
  if (!/^\s*\d{1,2}\s*$/.test(text)) return null;
  const n = Number(text.trim());
  return n >= 1 && n <= MAX_KEEP_VERSIONS ? n : null;
}

/** QL-08: what the form still needs before the core is asked, or null. */
export function formProblem(form: BuildForm, mode: BuildMode, choices: Pick<BuildChoices, "images">): string | null {
  if (mode === "new") {
    const name = form.name.trim();
    if (!name) return "Give the image a name";
    if (name.length > MAX_IMAGE_NAME) return `An image's name can be at most ${MAX_IMAGE_NAME} characters`;
  }
  if (!form.isoImageId) {
    return isoImages(choices.images).length === 0
      ? "Add an ISO image first: a build installs from one"
      : "Pick an ISO image";
  }
  if (!form.installConfigId) {
    return "Make an install config first: Ubuntu autoinstall, Debian preseed or Windows unattend";
  }
  if (parseMinutes(form.minutes) === null) {
    return `Give the install's time limit in whole minutes, 1 to ${MAX_INSTALL_MINUTES}`;
  }
  if (form.keepOn && parseKeep(form.keep) === null) return `Keep 1 to ${MAX_KEEP_VERSIONS} versions`;
  return null;
}

/** What the core gets, once `formProblem` has nothing to say; null before. */
export function recipeOf(form: BuildForm): BuildRecipe | null {
  const installMinutes = parseMinutes(form.minutes);
  const keep = form.keepOn ? parseKeep(form.keep) : null;
  if (installMinutes === null || (form.keepOn && keep === null)) return null;
  if (!form.isoImageId || !form.installConfigId) return null;
  const values: Record<string, string> = {};
  for (const [name, value] of Object.entries(form.values)) {
    if (value.trim()) values[name] = value.trim();
  }
  return {
    isoImageId: form.isoImageId,
    installConfigId: form.installConfigId,
    sizeId: form.sizeId,
    hypervisor: form.hypervisor,
    network: form.network,
    hostAdapter: needsHostAdapter(form.hypervisor, form.network) ? form.hostAdapter : null,
    vmFolder: form.vmFolder,
    values,
    // A2 of PR 100's review: never a pool; the build VM takes its address by DHCP (a saved one is dropped).
    addressPoolId: null,
    installMinutes,
    keep,
  };
}

/** The dialog's request: a new image by its name, or the next version of the image whose settings these are. */
export function requestOf(form: BuildForm, mode: BuildMode, imageId?: string): BuildRequest | null {
  const recipe = recipeOf(form);
  if (!recipe) return null;
  let target: BuildTarget;
  if (mode === "new") {
    const name = form.name.trim();
    if (!name) return null;
    target = { kind: "new", name };
  } else {
    if (!imageId) return null;
    target = { kind: "image", id: imageId };
  }
  return { target, recipe };
}

/**
 * QL-08: why Build (a new image) or Save (build settings) can't be pressed yet, or null when it can. Save goes on
 * while the build itself couldn't run now (a full drive, say): the settings are what is saved, and the core checks
 * them as a build would be planned.
 */
export function buildReason(state: {
  mode: BuildMode;
  readOnly: string | null;
  busy: boolean;
  problem: string | null;
  checking: boolean;
  check: BuildCheck | null;
  error: string | null;
}): string | null {
  if (state.readOnly) return state.readOnly;
  if (state.busy) return state.mode === "new" ? "Submitting…" : "Saving…";
  if (state.problem) return state.problem;
  if (state.error) return state.error;
  if (state.checking || !state.check) return "Checking…";
  const first = state.check.problems[0];
  if (state.mode === "settings") return state.check.preview ? null : (first ?? "Checking…");
  return first ?? (state.check.preview ? null : "Checking…");
}

/** "Version 3", or that it has none yet. */
export function versionText(version: number | null): string {
  return version === null ? "No version yet" : `Version ${version}`;
}

/** A version's state in words: "Newest", "Kept: 2 linked clones use it", "Deleted". */
export function versionStateText(version: Pick<ImageVersion, "state" | "linkedClones">): string {
  switch (version.state) {
    case "newest":
      return "Newest";
    case "deleted":
      return "Deleted";
    case "kept": {
      const n = version.linkedClones.length;
      return n === 0 ? "Kept" : `Kept: ${plural(n, "linked clone")} use${n === 1 ? "s" : ""} it`;
    }
  }
}

/** What making it generic found missing, in words ("no cloud-init"); nothing when all was there or wasn't said. */
export function factsText(facts: ImageVersion["facts"]): string[] {
  const out: string[] = [];
  if (facts.cloudInit === false) out.push("no cloud-init");
  if (facts.vmTools === false) out.push("no open-vm-tools");
  return out;
}

/** The retention line: "Keeps the newest 3 versions". */
export function keepText(keep: number | null): string {
  if (keep === null) return "Keeps every version";
  return keep === 1 ? "Keeps only the newest version" : `Keeps the newest ${keep} versions`;
}
