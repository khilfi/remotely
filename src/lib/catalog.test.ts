/// <reference types="node" />
// VM-19 to VM-21: the Templates page's texts and the size editor's form. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { Image, LaunchTemplate, OsProfile, Size } from "./api.ts";
import {
  copyName,
  cpuText,
  diskText,
  fileSize,
  hashPercent,
  imageFormatText,
  imageWhere,
  memoryText,
  networkKinds,
  networkLabel,
  networkOfKind,
  parseSizeForm,
  profileHypervisors,
  sizeForm,
  sizeSummary,
  templateCopyName,
  templateReason,
  totalDiskGb,
} from "./catalog.ts";

const diskLarge: Size = {
  id: "disk.large",
  name: "disk.large",
  builtIn: true,
  sockets: 1,
  coresPerSocket: 2,
  memoryMb: 4096,
  disks: [
    { sizeGb: 40, provisioning: "thin", controller: null },
    { sizeGb: 500, provisioning: "thin", controller: null },
  ],
  description: "File server, backups, logs",
  createdAt: null,
  updatedAt: null,
};

test("sizes read like a cloud provider's instance types", () => {
  assert.equal(sizeSummary(diskLarge), "2 vCPU · 4 GB RAM · 40 GB + 500 GB");
  assert.equal(memoryText(512), "512 MB");
  assert.equal(memoryText(1536), "1.5 GB");
  assert.equal(cpuText(2, 4), "8 vCPU (2 × 4)");
  assert.equal(diskText({ sizeGb: 100, provisioning: "thick", controller: "nvme" }), "100 GB thick on NVMe");
  assert.equal(totalDiskGb(diskLarge.disks), 540);
});

test("Duplicate suggests a free name within the limit", () => {
  assert.equal(copyName("gp.medium", []), "gp.medium-copy");
  assert.equal(copyName("gp.medium", ["GP.MEDIUM-COPY"]), "gp.medium-copy-2");
  const long = "x".repeat(40);
  assert.equal(copyName(long, []).length, 40);
  assert.ok(copyName(long, []).endsWith("-copy"));
  assert.equal(templateCopyName("web", ["web (copy)"]), "web (copy 2)");
});

test("the size form goes to the core in its units", () => {
  const parsed = parseSizeForm({ ...sizeForm(diskLarge), name: " files.large ", memoryGb: "0,5" });
  assert.deepEqual(parsed, {
    input: {
      name: "files.large",
      sockets: 1,
      coresPerSocket: 2,
      memoryMb: 512,
      disks: diskLarge.disks,
      description: "File server, backups, logs",
    },
  });
  const form = sizeForm(diskLarge);
  assert.equal(form.memoryGb, "4");
  assert.equal(form.disks[0]?.controller, "profile");
  const errors: [Partial<ReturnType<typeof sizeForm>>, string][] = [
    [{ sockets: "0" }, "whole numbers"],
    [{ coresPerSocket: "1.5" }, "whole numbers"],
    [{ sockets: "4", coresPerSocket: "16" }, "64 vCPUs"],
    [{ memoryGb: "" }, "RAM is a number"],
    [{ memoryGb: "-1" }, "RAM is a number"],
    [{ disks: [] }, "boot disk"],
    [{ disks: [{ sizeGb: "x", provisioning: "thin", controller: "profile" }] }, "Disk 1's size"],
  ];
  for (const [change, why] of errors) {
    const result = parseSizeForm({ ...form, ...change });
    assert.ok("error" in result && result.error.includes(why), `${why}: ${JSON.stringify(result)}`);
  }
  const nvme = parseSizeForm({ ...form, disks: [{ sizeGb: "80", provisioning: "thick", controller: "nvme" }] });
  assert.ok("input" in nvme);
  assert.deepEqual(nvme.input.disks, [{ sizeGb: 80, provisioning: "thick", controller: "nvme" }]);
});

const image = (over: Partial<Image>): Image => ({
  id: "1",
  name: "Noble",
  source: { kind: "cloudImage", path: "C:\\Images\\noble.vmdk", format: "vmdk" },
  hypervisors: ["vmware", "virtualbox"],
  osProfile: "ubuntu",
  sha256: null,
  sizeBytes: null,
  notes: null,
  createdAt: "",
  updatedAt: "",
  problem: null,
  vmName: null,
  ...over,
});

test("images say where their OS comes from", () => {
  assert.equal(imageWhere(image({})), "C:\\Images\\noble.vmdk");
  assert.equal(imageFormatText(image({})), "VMDK");
  const golden = image({
    source: { kind: "goldenVm", vmKey: "C:\\VMs\\golden\\golden.vmx", snapshotId: "2", snapshotName: "base" },
    vmName: "golden",
  });
  assert.equal(imageWhere(golden), "golden, snapshot 'base'");
  assert.equal(imageFormatText(golden), null);
  const rocky = image({ source: { kind: "cloudImage", path: "C:\\Images\\rocky.qcow2", format: "qcow2" } });
  assert.equal(imageFormatText(rocky), "qcow2 (converted before deploy)");
  assert.equal(
    imageFormatText(image({ source: { kind: "iso", path: "C:\\i.iso" } })),
    null,
    "the kind says ISO already",
  );
  assert.equal(fileSize(null), "");
  assert.equal(fileSize(512), "512 bytes");
  assert.equal(fileSize(650 * 1024 * 1024), "650 MB");
  assert.equal(fileSize(4.2 * 1024 ** 3), "4.2 GB");
  assert.equal(hashPercent(0, 0), 0);
  assert.equal(hashPercent(50, 200), 25);
  assert.equal(hashPercent(300, 200), 100);
});

test("Windows 11 profiles deploy on VirtualBox only", () => {
  const profile = (workstation: OsProfile["workstation"]): OsProfile => ({
    id: "x",
    name: "x",
    family: "windows",
    firmware: "efiSecureBoot",
    workstation,
    virtualbox: {
      osType: "Windows11_64",
      controller: "sata",
      controllerModel: "IntelAhci",
      nic: "82540EM",
      tpm: "2.0",
    },
    workstationNote: null,
  });
  assert.deepEqual(profileHypervisors(profile(null)), ["virtualbox"]);
  assert.deepEqual(
    profileHypervisors(
      profile({ guestOs: "windows9-64", hardwareVersion: 20, controller: "nvme", scsiAdapter: null, nic: "e1000e" }),
    ),
    ["vmware", "virtualbox"],
  );
  assert.deepEqual(profileHypervisors(undefined), ["vmware", "virtualbox"]);
});

test("networks follow the hypervisor", () => {
  assert.deepEqual(networkKinds("vmware"), ["nat", "hostOnly", "bridged", "vmnet"]);
  assert.ok(networkKinds("virtualbox").includes("internal"));
  assert.ok(!networkKinds("virtualbox").includes("vmnet"));
  assert.equal(networkLabel({ kind: "vmnet", number: 3 }), "vmnet3");
  assert.equal(networkLabel({ kind: "internal", name: "lab" }), "Internal network 'lab'");
  assert.deepEqual(networkOfKind("vmnet", { kind: "nat" }), { kind: "vmnet", number: 2 });
  assert.deepEqual(networkOfKind("internal", { kind: "natNetwork", name: "lab" }), { kind: "internal", name: "lab" });
  assert.deepEqual(networkOfKind("nat", { kind: "vmnet", number: 5 }), { kind: "nat" });
});

test("a template that can't deploy says why", () => {
  const template = { problems: [] } as unknown as LaunchTemplate;
  assert.equal(templateReason(template), null);
  const broken = {
    problems: [
      { code: "imageGone", message: "Its image was deleted. Pick another image." },
      { code: "sizeGone", message: "Its size was deleted." },
    ],
  } as unknown as LaunchTemplate;
  assert.equal(templateReason(broken), "Its image was deleted. Pick another image.");
});
