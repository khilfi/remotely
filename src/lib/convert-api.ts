// Typed wrappers over the conversion IPC commands in src-tauri/src/convert.rs (CV-01 to CV-03, VM-17): Image tools'
// Inspect, Convert and Verify, a VM's Export, and Import. Types mirror the serde shapes in crates/core/src/convert
// and deploy/service/import.rs. Like api.ts, every answer and event goes past the presentation masker (FD-03), since
// they go through api.ts's `invoke` and `listen`.

import {
  invoke,
  listen,
  type AfterDeploy,
  type DeployCheck,
  type Environment,
  type Firmware,
  type Hypervisor,
  type TemplateNetwork,
  type Settings,
  type SubmitOutcome,
} from "@/lib/api";

export type DiskFormat = "vmdk" | "vdi" | "vhd" | "vhdx" | "qcow2" | "raw";

export type OutputKind =
  | "vmdkSparse"
  | "vmdkFlat"
  | "vmdkStream"
  | "vmdkEsx"
  | "vdiDynamic"
  | "vdiFixed"
  | "vhdDynamic"
  | "vhdFixed"
  | "vhdxDynamic"
  | "vhdxFixed"
  | "qcow2"
  | "qcow2Thick"
  | "raw";

export type ConvertTool = "qemuImg" | "vdiskManager" | "vBoxManage" | "ovftool";

/** CV-03 Inspect. */
export interface ImageInfo {
  path: string;
  format: DiskFormat;
  subformat: string | null;
  thin: boolean | null;
  virtualBytes: number | null;
  onDiskBytes: number | null;
  extents: string[];
  parent: string | null;
  chain: string[];
  encrypted: boolean;
  partitionTable: string | null;
  /** Why it can't be converted as it is. */
  problems: string[];
  notes: string[];
}

export interface ToolPaths {
  qemuImg: string | null;
  vdiskmanager: string | null;
  vboxmanage: string | null;
  ovftool: string | null;
}

export interface ToolsReport {
  paths: ToolPaths;
  qemuImgSaved: string | null;
  /** The formats only qemu-img reads and writes. */
  qemuImgFormats: DiskFormat[];
  /** QEMU's download page, the one link Remotely opens for it. */
  downloadPage: string;
}

export interface ConvertStep {
  tool: ConvertTool;
  from: DiskFormat;
  to: OutputKind;
  growTo: number | null;
}

export interface OutputOption {
  kind: OutputKind;
  label: string;
  extension: string;
  steps: ConvertStep[];
  plan: string;
  reason: string | null;
  needsQemuImg: boolean;
  estimateBytes: number;
}

export interface ConvertOptions {
  info: ImageInfo;
  outputs: OutputOption[];
  freeBytes: number | null;
  roundsToMegabytes: boolean;
}

export type OvfVersion = "v1" | "v2";

export type ExportTarget =
  | { kind: "appliance"; ova: boolean; version: OvfVersion }
  | { kind: "esxi"; thick: boolean }
  | { kind: "hyperV" }
  | { kind: "azure" }
  | { kind: "kvm" }
  | { kind: "proxmox" }
  | { kind: "raw" };

export interface ExportDiskView {
  source: string;
  file: string;
  sourceFormat: DiskFormat;
  virtualBytes: number;
  plan: string;
}

export interface ExportOption {
  target: ExportTarget;
  label: string;
  disks: ExportDiskView[];
  tool: ConvertTool | null;
  reason: string | null;
  needsQemuImg: boolean;
  estimateBytes: number;
  folderName: string;
}

export interface ExportOptions {
  vmKey: string;
  vmName: string;
  hypervisor: Hypervisor;
  /** Why the VM can't be exported now; null when it can. */
  refusal: string | null;
  targets: ExportOption[];
}

export interface FileHash {
  path: string;
  bytes: number;
  sha256: string;
}

export interface VerifyReport {
  first: ImageInfo;
  second: ImageInfo | null;
  firstHashes: FileHash[];
  secondHashes: FileHash[];
  sameSize: boolean | null;
  comparison: { identical: boolean; said: string } | null;
  noComparison: string | null;
}

export type ImportKind = "appliance" | "disk" | "libvirt" | "proxmox";

export interface Described {
  name: string | null;
  vcpus: number | null;
  coresPerSocket: number | null;
  memoryMb: number | null;
  efi: boolean | null;
  family: "linux" | "windows" | null;
  os: string | null;
  disks: { file: string; format: string | null; capacityBytes: number | null }[];
}

export interface ImportDiskView {
  name: string;
  path: string | null;
  info: ImageInfo | null;
  virtualBytes: number | null;
  problem: string | null;
}

/** CV-01: what a picked file is and brings. */
export interface ImportAnalysis {
  path: string;
  kind: ImportKind;
  appliance: "ova" | "ovf" | null;
  described: Described;
  disks: ImportDiskView[];
  suggestedName: string;
  profile: string | null;
  problems: string[];
  onWorkstation: string | null;
  onVirtualbox: string | null;
  needsQemuImg: boolean;
  notes: string[];
}

export interface ImportRequest {
  source: string;
  hypervisor: Hypervisor;
  name: string;
  folder: string | null;
  profileId: string;
  firmware: Firmware | null;
  /** A catalogue size; null: the source's own CPU and memory and disks. */
  sizeId: string | null;
  vcpus: number | null;
  coresPerSocket: number | null;
  memoryMb: number | null;
  thick: boolean;
  network: TemplateNetwork;
  hostAdapter: string | null;
  environment: Environment;
  tags: string[];
  afterDeploy: AfterDeploy;
  cloudInit: { guestUser: string | null; sshKeyId: string | null; packages: string[] } | null;
}

export type PickFor = "image" | "import";

export const convertApi = {
  tools: () => invoke<ToolsReport>("convert_tools"),
  pick: (purpose: PickFor) => invoke<string | null>("convert_pick", { purpose }),
  inspect: (path: string) => invoke<ImageInfo>("convert_inspect", { path }),
  options: (path: string) => invoke<ConvertOptions>("convert_options", { path }),
  /** Opens a save dialog for the new image, then submits it (Low). null: the dialog was closed. */
  submit: (source: string, kind: OutputKind, wholeMegabytes: boolean) =>
    invoke<SubmitOutcome | null>("convert_submit", { source, kind, wholeMegabytes }),
  verify: (request: string, first: string, second: string | null) =>
    invoke<VerifyReport>("convert_verify", { request, first, second }),
  cancelVerify: (request: string) => invoke<boolean>("convert_verify_cancel", { request }),
  onVerify: (handler: (event: { request: string; done: number; total: number }) => void) =>
    listen<{ request: string; done: number; total: number }>("convert://verify", (e) => handler(e.payload)),
  exportOptions: (vmKey: string) => invoke<ExportOptions>("export_options", { vmKey }),
  /** Opens a folder dialog, then submits the export (Low; a Prod VM's asks). null: the dialog was closed. */
  exportSubmit: (vmKey: string, target: ExportTarget) =>
    invoke<SubmitOutcome | null>("export_submit", { vmKey, target }),
  importAnalyze: (path: string) => invoke<ImportAnalysis>("import_analyze", { path }),
  importCheck: (request: ImportRequest) => invoke<DeployCheck>("import_check", { request }),
  importSubmit: (request: ImportRequest) => invoke<SubmitOutcome>("import_submit", { request }),
  openQemuSite: (url: string) => invoke<void>("convert_open_qemu_site", { url }),
  setQemuImgPath: (path: string | null) => invoke<Settings>("settings_set_qemu_img_path", { path }),
};
