// VM-19 to VM-21: what the Templates page shows of sizes, images and launch templates, and the size editor's form, as
// pure functions (tested in catalog.test.ts). The core checks everything again when it saves.

import type {
  DiskController,
  DiskSpec,
  Hypervisor,
  Image,
  ImageKind,
  LaunchTemplate,
  OsProfile,
  Provisioning,
  Size,
  SizeInput,
  TemplateNetwork,
} from "./api.ts";

/** QL-08: why the VMs page's Deploy button is off until the deploy package (R2) wires it up. */
export const DEPLOY_REASON = "Deploy arrives with the deploy package";

/** The core's limits, for the forms' hints (it checks them again). */
export const MAX_VCPUS = 32;
export const MAX_SIZE_NAME = 40;
export const MAX_DISKS = 8;
export const MAX_DEPLOY_COUNT = 50;

export const HYPERVISOR_LABEL: Record<Hypervisor, string> = {
  vmware: "Workstation",
  virtualbox: "VirtualBox",
};

export const IMAGE_KIND_LABEL: Record<ImageKind, string> = {
  goldenVm: "Golden VM",
  cloudImage: "Cloud image",
  iso: "ISO",
  appliance: "OVA/OVF",
};

export const CONTROLLER_LABEL: Record<DiskController, string> = {
  scsi: "SCSI",
  sata: "SATA",
  nvme: "NVMe",
  ide: "IDE",
};

/** `512 MB`, `4 GB`, `1.5 GB`. */
export function memoryText(mb: number): string {
  if (mb < 1024) return `${mb} MB`;
  const gb = mb / 1024;
  return Number.isInteger(gb) ? `${gb} GB` : `${gb.toFixed(1)} GB`;
}

/** `2 vCPU`, or `4 vCPU (2 × 2)` with more than one socket. */
export function cpuText(sockets: number, coresPerSocket: number): string {
  const vcpus = sockets * coresPerSocket;
  return sockets > 1 ? `${vcpus} vCPU (${sockets} × ${coresPerSocket})` : `${vcpus} vCPU`;
}

/** `40 GB`, `500 GB thick`, `100 GB on NVMe`: thin is the default and goes unsaid. */
export function diskText(disk: DiskSpec): string {
  const parts = [`${disk.sizeGb} GB`];
  if (disk.provisioning === "thick") parts.push("thick");
  if (disk.controller) parts.push(`on ${CONTROLLER_LABEL[disk.controller]}`);
  return parts.join(" ");
}

/** `2 vCPU · 4 GB RAM · 40 GB + 500 GB`. */
export function sizeSummary(size: Pick<Size, "sockets" | "coresPerSocket" | "memoryMb" | "disks">): string {
  return [
    cpuText(size.sockets, size.coresPerSocket),
    `${memoryText(size.memoryMb)} RAM`,
    size.disks.map(diskText).join(" + "),
  ].join(" · ");
}

/** Every disk at its full size, in GB: what thin disks may grow to. */
export function totalDiskGb(disks: DiskSpec[]): number {
  return disks.reduce((sum, d) => sum + d.sizeGb, 0);
}

/** The name Duplicate suggests for a size: `gp.medium-copy`, then `gp.medium-copy-2`, within the name's limit. */
export function copyName(name: string, taken: string[]): string {
  const used = new Set(taken.map((t) => t.toLowerCase()));
  for (let n = 1; n < 1000; n++) {
    const suffix = n === 1 ? "-copy" : `-copy-${n}`;
    const candidate = name.slice(0, MAX_SIZE_NAME - suffix.length) + suffix;
    if (!used.has(candidate.toLowerCase())) return candidate;
  }
  return `${name.slice(0, 30)}-${Date.now()}`;
}

/** The name Duplicate suggests for a launch template: `web (copy)`, then `web (copy 2)`. */
export function templateCopyName(name: string, taken: string[]): string {
  const used = new Set(taken.map((t) => t.toLowerCase()));
  for (let n = 1; n < 1000; n++) {
    const candidate = n === 1 ? `${name} (copy)` : `${name} (copy ${n})`;
    if (!used.has(candidate.toLowerCase())) return candidate;
  }
  return `${name} (copy)`;
}

/** `Workstation and VirtualBox`. */
export function hypervisorsText(list: Hypervisor[]): string {
  return list.map((h) => HYPERVISOR_LABEL[h]).join(" and ");
}

/** Where an image's OS comes from: its file, or its golden VM and snapshot. */
export function imageWhere(image: Image): string {
  const source = image.source;
  if (source.kind === "goldenVm") return `${image.vmName ?? source.vmKey}, snapshot '${source.snapshotName}'`;
  return source.path;
}

/** `VMDK`, `qcow2 (converted before deploy)`, `ISO`; a golden VM has no file format. */
export function imageFormatText(image: Image): string | null {
  const source = image.source;
  switch (source.kind) {
    case "goldenVm":
      return null;
    case "iso":
      return "ISO";
    default:
      return source.format === "qcow2" ? "qcow2 (converted before deploy)" : source.format.toUpperCase();
  }
}

/** The hypervisors a profile deploys on: Windows 11 on VirtualBox only. */
export function profileHypervisors(profile: OsProfile | undefined): Hypervisor[] {
  if (!profile) return ["vmware", "virtualbox"];
  return profile.workstation ? ["vmware", "virtualbox"] : ["virtualbox"];
}

export function networkLabel(network: TemplateNetwork): string {
  switch (network.kind) {
    case "nat":
      return "NAT";
    case "hostOnly":
      return "Host-only";
    case "bridged":
      return "Bridged";
    case "vmnet":
      return `vmnet${network.number}`;
    case "natNetwork":
      return `NAT network '${network.name}'`;
    case "internal":
      return `Internal network '${network.name}'`;
  }
}

/** The kinds of network the editor offers for a hypervisor. */
export function networkKinds(hypervisor: Hypervisor): TemplateNetwork["kind"][] {
  return hypervisor === "vmware"
    ? ["nat", "hostOnly", "bridged", "vmnet"]
    : ["nat", "hostOnly", "bridged", "natNetwork", "internal"];
}

/** A network of `kind` with what it needs filled in from `previous` when that fits. */
export function networkOfKind(kind: TemplateNetwork["kind"], previous: TemplateNetwork): TemplateNetwork {
  switch (kind) {
    case "vmnet":
      return { kind, number: previous.kind === "vmnet" ? previous.number : 2 };
    case "natNetwork":
    case "internal":
      return { kind, name: "name" in previous ? previous.name : "" };
    default:
      return { kind };
  }
}

/** QL-08: why a template can't deploy, or null when it can. */
export function templateReason(template: LaunchTemplate): string | null {
  return template.problems[0]?.message ?? null;
}

// ---- The size editor's form ----

export interface DiskForm {
  sizeGb: string;
  provisioning: Provisioning;
  /** "profile": the OS profile's controller. */
  controller: DiskController | "profile";
}

export interface SizeForm {
  name: string;
  sockets: string;
  coresPerSocket: string;
  /** In GB: 0.5 is 512 MB. */
  memoryGb: string;
  disks: DiskForm[];
  description: string;
}

export function sizeForm(size: SizeInput | Size): SizeForm {
  return {
    name: size.name,
    sockets: String(size.sockets),
    coresPerSocket: String(size.coresPerSocket),
    memoryGb: String(size.memoryMb / 1024),
    disks: size.disks.map((d) => ({
      sizeGb: String(d.sizeGb),
      provisioning: d.provisioning,
      controller: d.controller ?? "profile",
    })),
    description: size.description ?? "",
  };
}

export const EMPTY_SIZE: SizeInput = {
  name: "",
  sockets: 1,
  coresPerSocket: 2,
  memoryMb: 4096,
  disks: [{ sizeGb: 40, provisioning: "thin", controller: null }],
  description: null,
};

function whole(text: string): number | null {
  const t = text.trim();
  return /^\d+$/.test(t) ? Number(t) : null;
}

/** The form as the core takes it, or what is wrong with it. */
export function parseSizeForm(form: SizeForm): { input: SizeInput } | { error: string } {
  const sockets = whole(form.sockets);
  const cores = whole(form.coresPerSocket);
  if (!sockets || !cores) return { error: "Sockets and cores per socket are whole numbers, 1 or more." };
  if (sockets * cores > MAX_VCPUS)
    return { error: `${sockets * cores} vCPUs is more than a VM can have (${MAX_VCPUS}).` };
  const gb = Number(form.memoryGb.trim().replace(",", "."));
  if (!form.memoryGb.trim() || !Number.isFinite(gb) || gb <= 0)
    return { error: "RAM is a number of GB, such as 4 or 0.5." };
  const memoryMb = Math.round(gb * 1024);
  if (form.disks.length === 0) return { error: "A size needs a boot disk." };
  if (form.disks.length > MAX_DISKS) return { error: `A size can have at most ${MAX_DISKS} disks.` };
  const disks: DiskSpec[] = [];
  for (const [i, d] of form.disks.entries()) {
    const sizeGb = whole(d.sizeGb);
    if (!sizeGb) return { error: `Disk ${i + 1}'s size is a whole number of GB, 1 or more.` };
    disks.push({ sizeGb, provisioning: d.provisioning, controller: d.controller === "profile" ? null : d.controller });
  }
  return {
    input: {
      name: form.name.trim(),
      sockets,
      coresPerSocket: cores,
      memoryMb,
      disks,
      description: form.description.trim() || null,
    },
  };
}

/** `4.2 GB`, for an image file. */
export function fileSize(bytes: number | null): string {
  if (bytes === null) return "";
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${bytes} bytes` : `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

/** How far hashing has got, 0 to 100. */
export function hashPercent(done: number, total: number): number {
  if (total <= 0) return 0;
  return Math.min(100, Math.floor((done / total) * 100));
}
