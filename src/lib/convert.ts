// CV-01 to CV-03, VM-17: Image tools', Export's and Import's texts and reasons, as pure functions (convert.test.ts).

import type {
  ConvertOptions,
  ConvertTool,
  DiskFormat,
  ExportOption,
  ExportTarget,
  ImageInfo,
  ImportAnalysis,
  OutputKind,
  OutputOption,
  ToolsReport,
  VerifyReport,
} from "./convert-api.ts";

export const FORMAT_LABEL: Record<DiskFormat, string> = {
  vmdk: "VMDK",
  vdi: "VDI",
  vhd: "VHD",
  vhdx: "VHDX",
  qcow2: "qcow2",
  raw: "raw",
};

export const TOOL_LABEL: Record<ConvertTool, string> = {
  qemuImg: "qemu-img",
  vdiskManager: "vmware-vdiskmanager",
  vBoxManage: "VBoxManage",
  ovftool: "ovftool",
};

/** Convert's outputs, grouped by format in the order the menu shows them. */
export const OUTPUT_GROUPS: { label: string; kinds: OutputKind[] }[] = [
  { label: "VMware (Workstation, ESXi)", kinds: ["vmdkSparse", "vmdkFlat", "vmdkStream", "vmdkEsx"] },
  { label: "VirtualBox", kinds: ["vdiDynamic", "vdiFixed"] },
  { label: "Hyper-V and Azure", kinds: ["vhdDynamic", "vhdFixed", "vhdxDynamic", "vhdxFixed"] },
  { label: "KVM, Proxmox, OpenStack", kinds: ["qcow2", "qcow2Thick", "raw"] },
];

/** "1.5 GB", in powers of 1024 as hypervisors size disks. */
export function sizeText(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "unknown";
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  if (unit === 0) return `${bytes} bytes`;
  return Math.abs(value - Math.round(value)) < 0.05
    ? `${Math.round(value)} ${units[unit]}`
    : `${value.toFixed(1)} ${units[unit]}`;
}

/** One line for an image: "qcow2 v3, 20 GB (2.1 GB on disk)". */
export function describeImage(info: ImageInfo): string {
  const kind = info.subformat ?? FORMAT_LABEL[info.format];
  const name = kind.startsWith(FORMAT_LABEL[info.format]) ? kind : `${FORMAT_LABEL[info.format]} ${kind}`;
  const size = info.virtualBytes !== null ? `, ${sizeText(info.virtualBytes)}` : "";
  const onDisk = info.onDiskBytes !== null ? ` (${sizeText(info.onDiskBytes)} on disk)` : "";
  return `${name}${size}${onDisk}`;
}

/** What Inspect lists, label and value. */
export function inspectRows(info: ImageInfo): [string, string][] {
  const rows: [string, string][] = [
    ["Format", FORMAT_LABEL[info.format]],
    ["Layout", info.subformat ?? "—"],
    ["Allocation", info.thin === null ? "—" : info.thin ? "Thin (grows as the guest writes)" : "Thick (its full size)"],
    ["Virtual size", sizeText(info.virtualBytes)],
    ["Size on disk", sizeText(info.onDiskBytes)],
  ];
  if (info.extents.length > 0) rows.push(["Extents", info.extents.join(", ")]);
  if (info.parent) rows.push(["Parent", info.parent]);
  if (info.chain.length > 1) rows.push(["Chain", info.chain.join(" → ")]);
  if (info.partitionTable) rows.push(["Partition table", info.partitionTable]);
  if (info.encrypted) rows.push(["Encrypted", "Yes"]);
  return rows;
}

/** QL-08: why Convert can't start with this output, or null. */
export function convertReason(state: {
  readOnly: string | null;
  busy: boolean;
  options: ConvertOptions | null;
  option: OutputOption | null;
}): string | null {
  if (state.readOnly) return state.readOnly;
  if (state.busy) return "Starting…";
  if (!state.options) return "Choose a disk image first";
  if (!state.option) return "Choose what to convert it into";
  return state.option.reason;
}

/** The outputs qemu-img would make possible, for the "install it" note. */
export function qemuOnly(options: ConvertOptions | null): OutputKind[] {
  return options?.outputs.filter((o) => o.needsQemuImg).map((o) => o.kind) ?? [];
}

/** Which conversions need qemu-img, in words, when it isn't installed; null when it is. */
export function qemuNote(tools: ToolsReport | null): string | null {
  if (!tools || tools.paths.qemuImg) return null;
  const formats = tools.qemuImgFormats.map((f) => FORMAT_LABEL[f]).join(" and ");
  return `qemu-img isn't installed: converting to or from ${formats} needs it. Remotely never ships it (it is GPL-licensed); install QEMU for Windows from its own download page, and Remotely finds it.`;
}

/** A key for an export target (React keys, the picked one). */
export function targetKey(target: ExportTarget): string {
  switch (target.kind) {
    case "appliance":
      return `${target.ova ? "ova" : "ovf"}-${target.version}`;
    case "esxi":
      return target.thick ? "esxi-thick" : "esxi-stream";
    default:
      return target.kind;
  }
}

/** Export's targets grouped for the list: appliances, then each hypervisor or cloud. */
export function exportGroups(options: ExportOption[]): { label: string; options: ExportOption[] }[] {
  const appliances = options.filter((o) => o.target.kind === "appliance");
  const disks = options.filter((o) => o.target.kind !== "appliance");
  return [
    { label: "Appliance (any hypervisor)", options: appliances },
    { label: "Disks for another hypervisor or a cloud", options: disks },
  ].filter((g) => g.options.length > 0);
}

/** An export target's label with its OVF version. */
export function exportLabel(option: ExportOption): string {
  if (option.target.kind === "appliance")
    return `${option.label}, OVF ${option.target.version === "v1" ? "1.0" : "2.0"}`;
  return option.label;
}

/** QL-08: why Export can't start, or null. */
export function exportReason(state: {
  readOnly: string | null;
  busy: boolean;
  refusal: string | null;
  option: ExportOption | null;
}): string | null {
  if (state.readOnly) return state.readOnly;
  if (state.busy) return "Starting…";
  if (state.refusal) return state.refusal;
  if (!state.option) return "Choose where it goes";
  return state.option.reason;
}

/** Verify's verdict in a line. */
export function verifySummary(report: VerifyReport): { ok: boolean; text: string } {
  if (!report.second) {
    const files = report.firstHashes.length;
    return { ok: true, text: `SHA-256 taken of its ${files === 1 ? "file" : `${files} files`}.` };
  }
  if (report.sameSize === false) return { ok: false, text: "Their virtual sizes differ: they aren't the same disk." };
  if (report.comparison) {
    return report.comparison.identical
      ? { ok: true, text: "qemu-img compared them: the guest sees the same disk in both." }
      : { ok: false, text: `qemu-img found a difference: ${report.comparison.said}` };
  }
  const same =
    report.firstHashes.length > 0 &&
    report.firstHashes.length === report.secondHashes.length &&
    report.firstHashes.every((h, i) => h.sha256 === report.secondHashes[i]?.sha256);
  if (same) return { ok: true, text: "Same size and the same checksums: the files are identical." };
  return {
    ok: report.sameSize === true,
    text:
      report.sameSize === true
        ? "Same virtual size; their checksums differ, as images of different formats always do. " +
          (report.noComparison ?? "")
        : (report.noComparison ?? "The sizes couldn't be compared."),
  };
}

/** Import: the hypervisors it can go to here, and why not. */
export function importReasons(analysis: ImportAnalysis | null): { vmware: string | null; virtualbox: string | null } {
  if (!analysis) return { vmware: "Choose a file first", virtualbox: "Choose a file first" };
  const problem = analysis.problems[0] ?? null;
  return {
    vmware: problem ?? analysis.onWorkstation,
    virtualbox: problem ?? analysis.onVirtualbox,
  };
}

/** What the picked file is, in words. */
export function importKindText(analysis: ImportAnalysis): string {
  switch (analysis.kind) {
    case "appliance":
      return `An ${analysis.appliance === "ovf" ? "OVF" : "OVA"} appliance: the hypervisor imports it itself.`;
    case "libvirt":
      return "A KVM (libvirt) VM: its disks are converted, its CPU, memory and firmware come from the XML.";
    case "proxmox":
      return "A Proxmox VE VM: its disks are converted, its CPU, memory and firmware come from the .conf.";
    default:
      return "A disk image: it is converted into the new VM's boot disk.";
  }
}

/** The specs a description gives, in words (or null). */
export function describedText(analysis: ImportAnalysis): string | null {
  const d = analysis.described;
  const parts: string[] = [];
  if (d.vcpus) parts.push(`${d.vcpus} vCPU`);
  if (d.memoryMb) parts.push(`${d.memoryMb} MB`);
  if (d.efi !== null) parts.push(d.efi ? "UEFI" : "BIOS");
  if (d.os) parts.push(d.os);
  return parts.length > 0 ? parts.join(", ") : null;
}
