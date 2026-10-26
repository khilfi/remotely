import assert from "node:assert/strict";
import { test } from "node:test";
import {
  convertReason,
  describeImage,
  exportGroups,
  exportLabel,
  exportReason,
  importKindText,
  importReasons,
  inspectRows,
  qemuNote,
  sizeText,
  targetKey,
  verifySummary,
} from "./convert.ts";
import type { ExportOption, ImageInfo, ImportAnalysis, OutputOption, VerifyReport } from "./convert-api.ts";

const info: ImageInfo = {
  path: "C:\\Images\\rocky.qcow2",
  format: "qcow2",
  subformat: "qcow2 v3",
  thin: true,
  virtualBytes: 20 * 2 ** 30,
  onDiskBytes: 1.5 * 2 ** 30,
  extents: [],
  parent: null,
  chain: [],
  encrypted: false,
  partitionTable: null,
  problems: [],
  notes: [],
};

test("sizes read in powers of 1024, as hypervisors size disks", () => {
  assert.equal(sizeText(512), "512 bytes");
  assert.equal(sizeText(20 * 2 ** 30), "20 GB");
  assert.equal(sizeText(1.5 * 2 ** 30), "1.5 GB");
  assert.equal(sizeText(null), "unknown");
});

test("an image is described in one line and in Inspect's rows", () => {
  assert.equal(describeImage(info), "qcow2 v3, 20 GB (1.5 GB on disk)");
  assert.equal(
    describeImage({ ...info, format: "vmdk", subformat: "streamOptimized" }),
    "VMDK streamOptimized, 20 GB (1.5 GB on disk)",
  );
  const rows = inspectRows({ ...info, parent: "base.qcow2", encrypted: true });
  assert.deepEqual(rows[0], ["Format", "qcow2"]);
  assert.ok(rows.some(([k, v]) => k === "Parent" && v === "base.qcow2"));
  assert.ok(rows.some(([k]) => k === "Encrypted"));
});

const option = (reason: string | null): OutputOption => ({
  kind: "vmdkSparse",
  label: "VMDK, growable (monolithicSparse)",
  extension: "vmdk",
  steps: [],
  plan: "",
  reason,
  needsQemuImg: reason !== null,
  estimateBytes: 0,
});

test("Convert says why it can't start", () => {
  const options = { info, outputs: [option(null)], freeBytes: null, roundsToMegabytes: false };
  assert.equal(convertReason({ readOnly: "Presenting", busy: false, options, option: option(null) }), "Presenting");
  assert.equal(
    convertReason({ readOnly: null, busy: false, options: null, option: null }),
    "Choose a disk image first",
  );
  assert.equal(convertReason({ readOnly: null, busy: false, options, option: null }), "Choose what to convert it into");
  assert.equal(
    convertReason({ readOnly: null, busy: false, options, option: option("needs qemu-img") }),
    "needs qemu-img",
  );
  assert.equal(convertReason({ readOnly: null, busy: false, options, option: option(null) }), null);
});

test("without qemu-img the page says which formats need it", () => {
  const tools = {
    paths: { qemuImg: null, vdiskmanager: "x", vboxmanage: null, ovftool: null },
    qemuImgSaved: null,
    qemuImgFormats: ["qcow2", "vhdx"] as ("qcow2" | "vhdx")[],
    downloadPage: "https://www.qemu.org/download/#windows",
  };
  assert.match(qemuNote(tools) ?? "", /qcow2 and VHDX needs it/);
  assert.equal(qemuNote({ ...tools, paths: { ...tools.paths, qemuImg: "q" } }), null);
});

const exportOption = (target: ExportOption["target"], reason: string | null = null): ExportOption => ({
  target,
  label: target.kind === "appliance" ? (target.ova ? "OVA" : "OVF") : target.kind,
  disks: [],
  tool: null,
  reason,
  needsQemuImg: false,
  estimateBytes: 0,
  folderName: "web01-x",
});

test("export targets are keyed, grouped and labelled with their OVF version", () => {
  const ova2 = exportOption({ kind: "appliance", ova: true, version: "v2" });
  const kvm = exportOption({ kind: "kvm" });
  assert.equal(targetKey(ova2.target), "ova-v2");
  assert.equal(targetKey({ kind: "esxi", thick: true }), "esxi-thick");
  assert.equal(targetKey(kvm.target), "kvm");
  assert.equal(exportLabel(ova2), "OVA, OVF 2.0");
  const groups = exportGroups([ova2, kvm]);
  assert.deepEqual(
    groups.map((g) => g.options.length),
    [1, 1],
  );
  assert.equal(
    exportReason({ readOnly: null, busy: false, refusal: "The VM is running", option: kvm }),
    "The VM is running",
  );
  assert.equal(exportReason({ readOnly: null, busy: false, refusal: null, option: null }), "Choose where it goes");
  assert.equal(exportReason({ readOnly: null, busy: false, refusal: null, option: kvm }), null);
});

test("Verify's verdict", () => {
  const hash = (sha256: string) => ({ path: "a", bytes: 1, sha256 });
  const base: VerifyReport = {
    first: info,
    second: info,
    firstHashes: [hash("aa")],
    secondHashes: [hash("bb")],
    sameSize: true,
    comparison: { identical: true, said: "Images are identical." },
    noComparison: null,
  };
  assert.equal(verifySummary(base).ok, true);
  assert.equal(
    verifySummary({ ...base, comparison: { identical: false, said: "Content mismatch at offset 0!" } }).ok,
    false,
  );
  assert.equal(verifySummary({ ...base, sameSize: false }).ok, false);
  const noQemu = { ...base, comparison: null, noComparison: "qemu-img isn't installed" };
  assert.match(verifySummary(noQemu).text, /checksums differ/);
  assert.equal(
    verifySummary({ ...noQemu, secondHashes: [hash("aa")] }).text,
    "Same size and the same checksums: the files are identical.",
  );
  assert.match(verifySummary({ ...base, second: null }).text, /SHA-256 taken of its file/);
});

test("Import says where it can go and what the file is", () => {
  const analysis: ImportAnalysis = {
    path: "C:\\Imports\\db01.xml",
    kind: "libvirt",
    appliance: null,
    described: {
      name: "db01",
      vcpus: 2,
      coresPerSocket: 2,
      memoryMb: 2048,
      efi: true,
      family: "linux",
      os: null,
      disks: [],
    },
    disks: [],
    suggestedName: "db01",
    profile: "ubuntu",
    problems: [],
    onWorkstation: null,
    onVirtualbox: "qcow2 to VDI, dynamic needs qemu-img",
    needsQemuImg: true,
    notes: [],
  };
  assert.deepEqual(importReasons(analysis), { vmware: null, virtualbox: "qcow2 to VDI, dynamic needs qemu-img" });
  assert.deepEqual(importReasons({ ...analysis, problems: ["Disk 1 is missing."] }), {
    vmware: "Disk 1 is missing.",
    virtualbox: "Disk 1 is missing.",
  });
  assert.match(importKindText(analysis), /KVM \(libvirt\)/);
  assert.equal(importReasons(null).vmware, "Choose a file first");
});
