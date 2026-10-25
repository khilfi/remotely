// VM-23 and on: what the Settings tab, its edit dialogs and the VM menus decide, as pure functions (tested in
// vm-settings.test.ts). QL-08: every reason says why an action is off; `null` means it is available. The core checks
// all of it again when the command runs (crates/core/src/vm_settings), and the approval preview names a VM it would
// refuse.

import type { Hypervisor, NicNetwork, PowerState, VirtualNic, VmHardware, VmRecord } from "./api.ts";
import { PROTECTED_REASON } from "./vm-snapshots.ts";

/** What an action needs of the VM's power state. */
export type Needs = "off" | "running" | "any";

const BUSY_REASON = "Sending the last action…";

/** Settings and disks change only while the VM is off; Tools and screenshots need it running. */
export function powerReason(state: PowerState, needs: Needs, hypervisor: Hypervisor): string | null {
  const name = hypervisor === "virtualbox" ? "VirtualBox" : "Workstation";
  if (needs === "any") {
    return state === "suspended" ? "Suspended: resume it or shut it down first" : null;
  }
  if (needs === "running") {
    if (state === "running") return null;
    if (state === "paused") return "Paused: unpause it first";
    return "Not running: start the VM first";
  }
  switch (state) {
    case "not_running":
      return null;
    case "running":
    case "paused":
      return `Running: ${name} changes this only while the VM is off. Shut it down first`;
    case "suspended":
      return "Suspended: its saved state would not fit changed hardware. Start it and shut it down first";
    default:
      return `${name} could not say whether the VM is running`;
  }
}

/** Why an action on one VM is off. */
export function vmActionReason(input: {
  vm: Pick<VmRecord, "powerState" | "protected" | "hypervisor">;
  needs: Needs;
  /** FD-03: the read-only lock's reason, or null. */
  readOnly: string | null;
  busy?: boolean;
}): string | null {
  if (input.readOnly) return input.readOnly;
  if (input.vm.protected) return PROTECTED_REASON;
  if (input.busy) return BUSY_REASON;
  return powerReason(input.vm.powerState, input.needs, input.vm.hypervisor);
}

/** VM-16: why expanding, compacting, defragmenting or removing a disk is off, beyond the VM's own reason. */
export function diskActionReason(input: {
  action: "expand" | "compact" | "defragment" | "remove";
  hypervisor: Hypervisor;
  /** The VM's snapshot count, once read. */
  snapshots: number | null;
  /** The disk's file, and the VM's folder: Remotely removes only disks in it. */
  diskPath: string;
  vmFolder: string | null;
}): string | null {
  if (input.action === "defragment" && input.hypervisor === "virtualbox") {
    return "VirtualBox has no defragment for its disks: compact the disk instead";
  }
  if (input.snapshots === null) return "Reading the VM's snapshots…";
  if (input.snapshots > 0) {
    const what = {
      expand: "expanded",
      compact: "compacted",
      defragment: "defragmented",
      remove: "removed",
    }[input.action];
    const n = input.snapshots === 1 ? "1 snapshot" : `${input.snapshots} snapshots`;
    return `The VM has ${n}: a disk can't be ${what} while snapshots depend on it. Delete the snapshots first`;
  }
  if (input.action === "remove" && input.vmFolder && !sameFolder(parentOf(input.diskPath), input.vmFolder)) {
    return "The disk is outside the VM's folder, where another VM may use it: Remotely doesn't delete it";
  }
  return null;
}

function parentOf(path: string): string {
  const cut = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  return cut > 0 ? path.slice(0, cut) : "";
}

function sameFolder(a: string, b: string) {
  const norm = (p: string) =>
    p
      .replace(/\//g, "\\")
      .replace(/\\+$/, "")
      .toLowerCase();
  return norm(a) === norm(b);
}

/** VM-23: why the firmware dialog can't offer a TPM. */
export function tpmReason(hypervisor: Hypervisor): string | null {
  return hypervisor === "vmware"
    ? "Workstation's virtual TPM needs the VM encrypted with a password of its own, which Remotely doesn't do: add it in Workstation"
    : null;
}

/** VM-15: why Install Tools is off on one VM. */
export function toolsReason(
  vm: Pick<VmRecord, "powerState" | "protected" | "hypervisor">,
  readOnly: string | null,
  hardware: VmHardware | null,
): string | null {
  const off = vmActionReason({ vm, needs: "running", readOnly });
  if (off) return off;
  if (vm.hypervisor === "virtualbox" && hardware && hardware.cdroms.length === 0) {
    return "The VM has no DVD drive for the Guest Additions ISO: attach an ISO while it is off to add one";
  }
  return null;
}

/** VM-23: why attaching an ISO is off. A running VM needs a CD/DVD drive already; one that is off gets one. */
export function isoReason(
  vm: Pick<VmRecord, "powerState" | "protected" | "hypervisor">,
  readOnly: string | null,
  hardware: VmHardware | null,
): string | null {
  const off = vmActionReason({ vm, needs: "any", readOnly });
  if (off) return off;
  const on = vm.powerState === "running" || vm.powerState === "paused";
  if (on && hardware && hardware.cdroms.length === 0) {
    return "The VM has no CD/DVD drive, and one is added only while the VM is off: shut it down first";
  }
  return null;
}

/** VM-12: the selected VMs a bulk resize goes to (off and not protected), and why the others are left out. */
export function resizeTargets(vms: VmRecord[]): { targets: VmRecord[]; left: { name: string; why: string }[] } {
  const targets: VmRecord[] = [];
  const left: { name: string; why: string }[] = [];
  for (const vm of vms) {
    const why = vm.protected ? PROTECTED_REASON : powerReason(vm.powerState, "off", vm.hypervisor);
    if (why) left.push({ name: vm.displayName, why });
    else targets.push(vm);
  }
  return { targets, left };
}

/** The menus' reason for a bulk resize. */
export function bulkResizeReason(vms: VmRecord[], readOnly: string | null): string | null {
  if (readOnly) return readOnly;
  if (vms.length === 0) return "Select VMs first";
  return resizeTargets(vms).targets.length === 0 ? "None of the selected VMs is off and unprotected" : null;
}

/** "4 GB", "1.5 GB", "512 MB" (binary, as the hypervisors count). */
export function formatMb(mb: number | null | undefined): string {
  if (mb === null || mb === undefined) return "—";
  if (mb >= 1024 * 1024 && mb % (1024 * 1024) === 0) return `${mb / (1024 * 1024)} TB`;
  if (mb >= 1024) return mb % 1024 === 0 ? `${mb / 1024} GB` : `${(mb / 1024).toFixed(1)} GB`;
  return `${mb} MB`;
}

/** A size typed as GB (whole or with decimals) into MB; null when it is not a positive number. */
export function gbToMb(text: string): number | null {
  const value = Number(text.trim().replace(",", "."));
  if (!Number.isFinite(value) || value <= 0) return null;
  return Math.round(value * 1024);
}

/** VM-12: what the CPU and memory dialog can send, or why it can't. Workstation takes memory in steps of 4 MB. */
export function resourcesProblem(input: {
  vcpus: number | null;
  coresPerSocket: number | null;
  memoryMb: number | null;
  hypervisors: Hypervisor[];
}): string | null {
  const { vcpus, coresPerSocket, memoryMb } = input;
  if (vcpus === null && memoryMb === null && coresPerSocket === null) return "Change the vCPUs or the memory";
  if (vcpus !== null && (!Number.isInteger(vcpus) || vcpus < 1 || vcpus > 64)) return "vCPUs: 1 to 64";
  if (coresPerSocket !== null) {
    if (input.hypervisors.includes("virtualbox")) {
      return "VirtualBox gives a VM vCPUs, not sockets and cores";
    }
    if (!Number.isInteger(coresPerSocket) || coresPerSocket < 1) return "Cores per socket: a whole number";
    if (vcpus !== null && vcpus % coresPerSocket !== 0) return "The cores per socket must divide the vCPUs";
  }
  if (memoryMb !== null) {
    if (!Number.isInteger(memoryMb) || memoryMb < 4 || memoryMb > 1024 * 1024) return "Memory: 4 MB to 1 TB";
    if (input.hypervisors.includes("vmware") && memoryMb % 4 !== 0) return "Workstation takes memory in steps of 4 MB";
  }
  return null;
}

/** VM-11: the networks a hypervisor's adapters can use, for the adapter dialog. */
export function networkKinds(hypervisor: Hypervisor): { kind: NicNetwork["kind"]; label: string; named?: string }[] {
  return hypervisor === "vmware"
    ? [
        { kind: "nat", label: "NAT" },
        { kind: "bridged", label: "Bridged (this PC's network)" },
        { kind: "hostOnly", label: "Host-only" },
        { kind: "custom", label: "Custom (a VMnet)", named: "VMnet" },
      ]
    : [
        { kind: "nat", label: "NAT" },
        { kind: "bridged", label: "Bridged", named: "Host adapter (empty: VirtualBox picks)" },
        { kind: "hostOnly", label: "Host-only", named: "Host-only adapter (empty: VirtualBox picks)" },
        { kind: "natNetwork", label: "NAT network", named: "NAT network name" },
        { kind: "internal", label: "Internal network", named: "Internal network name" },
      ];
}

/** VM-11: the emulated cards a hypervisor offers. */
export function cardModels(hypervisor: Hypervisor): string[] {
  return hypervisor === "vmware"
    ? ["vmxnet3", "e1000e", "e1000"]
    : ["virtio", "82540EM", "82543GC", "82545EM", "Am79C973"];
}

/** A network from the dialog's choice and the name typed for it; null when a needed name is missing. */
export function networkOf(kind: NicNetwork["kind"], name: string): NicNetwork | null {
  const text = name.trim();
  switch (kind) {
    case "nat":
      return { kind: "nat" };
    case "bridged":
      return { kind: "bridged", adapter: text || null };
    case "hostOnly":
      return { kind: "hostOnly", adapter: text || null };
    case "custom": {
      const n = text.replace(/^vmnet/i, "");
      return /^\d{1,2}$/.test(n) && Number(n) <= 19 ? { kind: "custom", vnet: `VMnet${n}` } : null;
    }
    case "natNetwork":
      return text ? { kind: "natNetwork", name: text } : null;
    case "internal":
      return text ? { kind: "internal", name: text } : null;
  }
}

/** A network adapter's network in words: "NAT", "custom (VMnet2)", "bridged to Ethernet". */
export function nicText(nic: VirtualNic): string {
  const connection = nic.connection ?? "—";
  if (!nic.networkName) return connection;
  return connection.startsWith("custom") ? connection : `${connection} (${nic.networkName})`;
}

/** A MAC typed as hex with or without separators, as aa:bb:cc:dd:ee:ff; null when it is not one. */
export function normalMac(text: string): string | null {
  const hex = text.replace(/[:\-\s]/g, "");
  if (!/^[0-9a-fA-F]{12}$/.test(hex)) return null;
  return hex
    .toLowerCase()
    .match(/.{2}/g)!
    .join(":");
}

/** VM-11: Workstation takes a hand-picked MAC only from 00:50:56:00:00:00 to 00:50:56:3F:FF:FF. */
export function macProblem(text: string, hypervisor: Hypervisor): string | null {
  const mac = normalMac(text);
  if (!mac) return "Not a MAC address";
  if (parseInt(mac.slice(0, 2), 16) & 1) return "A multicast address: an adapter needs a unicast one";
  if (hypervisor === "vmware" && (!mac.startsWith("00:50:56:") || parseInt(mac.slice(9, 11), 16) > 0x3f)) {
    return "Workstation takes hand-picked MACs from 00:50:56:00:00:00 to 00:50:56:3F:FF:FF only";
  }
  return null;
}

/** VM-24: a name for a VM: what VirtualBox can make a folder of, and both take. */
export function vmNameProblem(name: string): string | null {
  if (!name.trim()) return "Give the VM a name";
  if (name.trim() !== name) return "No space at the start or end";
  if (name.length > 80) return "At most 80 characters";
  if (/[\\/:*?"<>|\u0000-\u001f]/.test(name)) return 'Not \\ / : * ? " < > |';
  return null;
}

/** VM-23: a shared folder's name the guest sees. */
export function shareNameProblem(name: string): string | null {
  if (!name.trim()) return "Give the folder the name the guest sees";
  if (!/^[\p{L}\p{N} _.()-]{1,128}$/u.test(name)) return "Letters, digits, spaces and _ . - ( ) only";
  return null;
}

/** The folder of a VM's files, from its key and its .vbox. */
export function vmFolder(vm: Pick<VmRecord, "hypervisor" | "vmxPath" | "configPath">): string | null {
  const file = vm.hypervisor === "virtualbox" ? vm.configPath : vm.vmxPath;
  if (!file) return null;
  const folder = parentOf(file);
  return folder || null;
}
