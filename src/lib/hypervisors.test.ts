/// <reference types="node" />
// VM-18: what the UI says about each VM's hypervisor. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  HYPERVISORS,
  hypervisorName,
  hypervisorOfKey,
  slashIsPath,
  targetLocation,
  toolsName,
  vmLocation,
} from "./hypervisors.ts";

test("each hypervisor has a name and its guest tools", () => {
  assert.deepEqual(
    HYPERVISORS.map((h) => h.value),
    ["vmware", "virtualbox"],
  );
  assert.equal(hypervisorName("vmware"), "VMware");
  assert.equal(hypervisorName("virtualbox"), "VirtualBox");
  assert.equal(toolsName("vmware"), "VMware Tools");
  assert.equal(toolsName("virtualbox"), "Guest Additions");
});

test("a VirtualBox VM lives in its .vbox file, a VMware VM in its .vmx", () => {
  const uuid = "3f0c1a2b-1111-4222-8333-444455556666";
  const vbox = String.raw`C:\Users\alice\VirtualBox VMs\web01\web01.vbox`;
  assert.equal(vmLocation({ vmxPath: uuid, hypervisor: "virtualbox", configPath: vbox }), vbox);
  assert.equal(vmLocation({ vmxPath: uuid, hypervisor: "virtualbox", configPath: null }), uuid);
  const vmx = String.raw`D:\VMs\db01\db01.vmx`;
  assert.equal(vmLocation({ vmxPath: vmx, hypervisor: "vmware", configPath: null }), vmx);
});

test("only vmrun reads '/' in a snapshot name as a path", () => {
  assert.equal(slashIsPath("vmware"), true);
  assert.equal(slashIsPath("virtualbox"), false);
});

test("a UUID key is a VirtualBox VM, as the core decides", () => {
  const uuid = "3F0C1A2B-1111-4222-8333-444455556666";
  assert.equal(hypervisorOfKey(uuid), "virtualbox");
  assert.equal(hypervisorOfKey(`{${uuid}}`), "virtualbox");
  assert.equal(hypervisorOfKey(String.raw`C:\VMs\3f0c1a2b-1111-4222-8333-444455556666.vmx`), "vmware");
  assert.equal(targetLocation(uuid), `VirtualBox VM ${uuid}`);
  assert.equal(targetLocation(String.raw`D:\VMs\a\a.vmx`), String.raw`D:\VMs\a\a.vmx`);
});
