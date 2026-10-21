// VM-18: what the UI says about a VM's hypervisor (VMware Workstation or Oracle VirtualBox), as pure functions
// (tested in hypervisors.test.ts). A VMware VM's key is its .vmx path; a VirtualBox VM's is its UUID, so where the
// UI shows "where the VM lives", a VirtualBox VM shows its .vbox settings file instead.

import type { Hypervisor } from "./api.ts";

export const HYPERVISORS: { value: Hypervisor; label: string; short: string }[] = [
  { value: "vmware", label: "VMware Workstation", short: "VMware" },
  { value: "virtualbox", label: "Oracle VirtualBox", short: "VirtualBox" },
];

/** "VMware" or "VirtualBox", for a column or badge. */
export function hypervisorName(hypervisor: Hypervisor) {
  return HYPERVISORS.find((h) => h.value === hypervisor)?.short ?? hypervisor;
}

/** The guest tools that report the guest's IP and shut it down gracefully. */
export function toolsName(hypervisor: Hypervisor) {
  return hypervisor === "virtualbox" ? "Guest Additions" : "VMware Tools";
}

/** Where the VM lives, for the line under its name: the .vmx, or the .vbox file (else the UUID). */
export function vmLocation(vm: { vmxPath: string; hypervisor: Hypervisor; configPath: string | null }) {
  return vm.hypervisor === "virtualbox" ? (vm.configPath ?? vm.vmxPath) : vm.vmxPath;
}

/** The hypervisor behind a VM key, as the core decides it: a UUID is a VirtualBox VM, anything else a .vmx path. */
export function hypervisorOfKey(key: string): Hypervisor {
  return /^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$/i.test(key.trim())
    ? "virtualbox"
    : "vmware";
}

/** A VM target's key as the approval dialog shows it under the name. */
export function targetLocation(key: string) {
  return hypervisorOfKey(key) === "virtualbox" ? `VirtualBox VM ${key}` : key;
}

/** vmrun reads '/' in a snapshot name as a path to a child snapshot; VBoxManage takes the name as it is. */
export function slashIsPath(hypervisor: Hypervisor) {
  return hypervisor === "vmware";
}
