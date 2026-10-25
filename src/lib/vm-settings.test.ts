/// <reference types="node" />
// VM-23 and on (QL-08): the Settings tab's reasons, the edit dialogs' checks and choices. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { VmHardware, VmRecord } from "./api.ts";
import { READ_ONLY_REASON } from "./disabled-reasons.ts";
import {
  bulkResizeReason,
  diskActionReason,
  formatMb,
  gbToMb,
  isoReason,
  macProblem,
  networkOf,
  normalMac,
  powerReason,
  resizeTargets,
  resourcesProblem,
  shareNameProblem,
  toolsReason,
  tpmReason,
  vmActionReason,
  vmFolder,
  vmNameProblem,
} from "./vm-settings.ts";
import { PROTECTED_REASON } from "./vm-snapshots.ts";

function vm(name: string, extra: Partial<VmRecord> = {}): VmRecord {
  return {
    id: name,
    vmxPath: `C:\\VMs\\${name}\\${name}.vmx`,
    hypervisor: "vmware",
    configPath: null,
    displayName: name,
    guestOs: null,
    guestOsName: null,
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
  } as VmRecord;
}

const noDrives = { cdroms: [] } as unknown as VmHardware;

test("settings change only while the VM is off, and tools need it running", () => {
  assert.equal(powerReason("not_running", "off", "vmware"), null);
  assert.match(powerReason("running", "off", "vmware")!, /^Running: Workstation changes this only while the VM is off/);
  assert.match(powerReason("paused", "off", "virtualbox")!, /VirtualBox/);
  assert.match(powerReason("suspended", "off", "vmware")!, /^Suspended/);
  assert.match(powerReason("unknown", "off", "vmware")!, /could not say/);
  assert.equal(powerReason("running", "running", "vmware"), null);
  assert.equal(powerReason("not_running", "running", "vmware"), "Not running: start the VM first");
  assert.equal(powerReason("running", "any", "vmware"), null);
  assert.match(powerReason("suspended", "any", "vmware")!, /^Suspended/);
});

test("the read-only lock and protection come before the power state", () => {
  const running = vm("web", { powerState: "running" });
  assert.equal(vmActionReason({ vm: running, needs: "off", readOnly: READ_ONLY_REASON }), READ_ONLY_REASON);
  assert.equal(
    vmActionReason({ vm: { ...running, protected: true }, needs: "off", readOnly: null }),
    PROTECTED_REASON,
  );
  assert.equal(vmActionReason({ vm: vm("web"), needs: "off", readOnly: null, busy: true }), "Sending the last action…");
  assert.equal(vmActionReason({ vm: vm("web"), needs: "off", readOnly: null }), null);
});

test("disk actions wait for the snapshots and refuse what can't be done", () => {
  const disk = { hypervisor: "vmware" as const, diskPath: "C:\\VMs\\web\\web.vmdk", vmFolder: "C:\\VMs\\web" };
  assert.equal(diskActionReason({ ...disk, action: "expand", snapshots: 0 }), null);
  assert.equal(diskActionReason({ ...disk, action: "expand", snapshots: null }), "Reading the VM's snapshots…");
  assert.equal(
    diskActionReason({ ...disk, action: "expand", snapshots: 2 }),
    "The VM has 2 snapshots: a disk can't be expanded while snapshots depend on it. Delete the snapshots first",
  );
  assert.match(diskActionReason({ ...disk, action: "compact", snapshots: 1 })!, /^The VM has 1 snapshot:/);
  assert.match(
    diskActionReason({ ...disk, action: "defragment", hypervisor: "virtualbox", snapshots: 0 })!,
    /no defragment/,
  );
  assert.match(
    diskActionReason({ ...disk, action: "remove", snapshots: 0, diskPath: "D:\\shared\\common.vmdk" })!,
    /outside the VM's folder/,
  );
  assert.equal(diskActionReason({ ...disk, action: "remove", snapshots: 0, diskPath: "c:/vms/WEB/web-1.vmdk" }), null);
});

test("tools, ISOs and the TPM say why they are off", () => {
  assert.match(toolsReason(vm("web"), null, null)!, /^Not running/);
  const running = vm("db", { powerState: "running", hypervisor: "virtualbox" });
  assert.match(toolsReason(running, null, noDrives)!, /no DVD drive/);
  assert.equal(toolsReason({ ...running, hypervisor: "vmware" }, null, noDrives), null, "vmrun brings its own");
  assert.equal(isoReason(vm("web"), null, noDrives), null, "off: a drive is added");
  assert.match(isoReason(running, null, noDrives)!, /no CD\/DVD drive/);
  assert.match(tpmReason("vmware")!, /encrypted/);
  assert.equal(tpmReason("virtualbox"), null);
});

test("a bulk resize goes to the VMs that are off and unprotected", () => {
  const vms = [vm("a"), vm("b", { powerState: "running" }), vm("c", { protected: true }), vm("d")];
  const { targets, left } = resizeTargets(vms);
  assert.deepEqual(
    targets.map((v) => v.displayName),
    ["a", "d"],
  );
  assert.deepEqual(
    left.map((l) => l.name),
    ["b", "c"],
  );
  assert.equal(bulkResizeReason(vms, null), null);
  assert.equal(bulkResizeReason([], null), "Select VMs first");
  assert.equal(bulkResizeReason([vms[1]], null), "None of the selected VMs is off and unprotected");
  assert.equal(bulkResizeReason(vms, READ_ONLY_REASON), READ_ONLY_REASON);
});

test("the CPU and memory dialog checks what each hypervisor takes", () => {
  const ws = { hypervisors: ["vmware" as const] };
  assert.equal(resourcesProblem({ vcpus: 4, coresPerSocket: 2, memoryMb: 8192, ...ws }), null);
  assert.equal(resourcesProblem({ vcpus: null, coresPerSocket: null, memoryMb: null, ...ws }), "Change the vCPUs or the memory");
  assert.equal(resourcesProblem({ vcpus: 6, coresPerSocket: 4, memoryMb: null, ...ws }), "The cores per socket must divide the vCPUs");
  assert.equal(resourcesProblem({ vcpus: null, coresPerSocket: null, memoryMb: 1026, ...ws }), "Workstation takes memory in steps of 4 MB");
  assert.equal(
    resourcesProblem({ vcpus: null, coresPerSocket: null, memoryMb: 1026, hypervisors: ["virtualbox"] }),
    null,
  );
  assert.match(resourcesProblem({ vcpus: 2, coresPerSocket: 1, memoryMb: null, hypervisors: ["virtualbox"] })!, /sockets/);
  assert.equal(resourcesProblem({ vcpus: 65, coresPerSocket: null, memoryMb: null, ...ws }), "vCPUs: 1 to 64");
});

test("sizes, MACs and names", () => {
  assert.equal(formatMb(4096), "4 GB");
  assert.equal(formatMb(1536), "1.5 GB");
  assert.equal(formatMb(512), "512 MB");
  assert.equal(formatMb(null), "—");
  assert.equal(gbToMb("20"), 20480);
  assert.equal(gbToMb("1,5"), 1536);
  assert.equal(gbToMb("0"), null);
  assert.equal(gbToMb("lots"), null);
  assert.equal(normalMac("00-50-56-3F-00-01"), "00:50:56:3f:00:01");
  assert.equal(macProblem("00:50:56:3f:00:01", "vmware"), null);
  assert.match(macProblem("00:50:56:40:00:01", "vmware")!, /00:50:56:3F:FF:FF/);
  assert.equal(macProblem("08:00:27:00:00:01", "virtualbox"), null);
  assert.match(macProblem("01:00:5e:00:00:01", "virtualbox")!, /multicast/);
  assert.equal(vmNameProblem("web 02"), null);
  assert.equal(vmNameProblem("web/02"), 'Not \\ / : * ? " < > |');
  assert.equal(shareNameProblem("data share"), null);
  assert.match(shareNameProblem("a;b")!, /only/);
  assert.deepEqual(networkOf("custom", "vmnet2"), { kind: "custom", vnet: "VMnet2" });
  assert.equal(networkOf("custom", "VMnet25"), null);
  assert.equal(networkOf("internal", " "), null);
  assert.deepEqual(networkOf("bridged", ""), { kind: "bridged", adapter: null });
  assert.equal(vmFolder(vm("web")), "C:\\VMs\\web");
  assert.equal(
    vmFolder(vm("db", { hypervisor: "virtualbox", vmxPath: "uuid", configPath: "C:\\VBox\\db\\db.vbox" })),
    "C:\\VBox\\db",
  );
});
