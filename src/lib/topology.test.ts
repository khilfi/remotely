/// <reference types="node" />
// QL-21 topology map: networks from R3's adapter settings, which sessions show, jump host columns, tunnels, the
// layered layout, and FD-03 masking of everything the map says. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { SessionRecord, TunnelInfo, VirtualNic, VmRecord } from "./api.ts";
import type { OpenTunnel } from "./open-tunnels.ts";
import { learnFields, Masker } from "./presentation.ts";
import { buildTopology, networkKey, PC_ID, type TopologyInput } from "./topology.ts";
import { DEFAULT_LAYOUT, edgePath, layoutTopology, orderColumns } from "./topology-layout.ts";

function nic(connection: string | null, networkName: string | null = null): VirtualNic {
  return {
    slot: "ethernet0",
    connection,
    model: null,
    mac: null,
    connected: true,
    networkName,
    connectedNow: null,
    staticMac: false,
  };
}

function vm(name: string, extra: Partial<VmRecord> = {}): VmRecord {
  return {
    id: `vm-${name}`,
    vmxPath: `C:\\VMs\\${name}\\${name}.vmx`,
    hypervisor: "vmware",
    configPath: null,
    displayName: name,
    guestOs: null,
    guestOsName: null,
    numVcpus: 2,
    memsizeMb: 2048,
    powerState: "running",
    ipAddress: null,
    toolsState: null,
    environment: "none",
    protected: false,
    tags: [],
    lastSeenAt: null,
    ...extra,
  };
}

function session(id: string, extra: Partial<SessionRecord> = {}): SessionRecord {
  return {
    id,
    name: id,
    host: `${id}.example.com`,
    username: "alice",
    vmId: null,
    jumpSessionId: null,
    tags: [],
    environment: "none",
    ...extra,
  } as unknown as SessionRecord;
}

function open(sessionId: string, terminalId: string): OpenTunnel {
  const tunnel = {
    forward: {
      id: `f-${terminalId}`,
      sessionId,
      label: "Postgres",
      kind: "local",
      bindAddress: "127.0.0.1",
      bindPort: 5432,
      destHost: "db01.example.com",
      destPort: 5432,
      autoStart: false,
    },
    state: { state: "listening", at: "127.0.0.1:5432" },
    connections: 0,
    open: 0,
    lastError: null,
    saved: true,
    changed: false,
  } as TunnelInfo;
  return { terminalId, sessionId, tunnel };
}

function input(extra: Partial<TopologyInput> = {}): TopologyInput {
  return { vms: [], networks: [], sessions: [], tunnels: [], ...extra };
}

test("Workstation's NAT, host-only and bridged are VMnet8, VMnet1 and VMnet0; a custom vnet is its own", () => {
  assert.equal(networkKey("vmware", nic("nat"))?.key, "vmware:vmnet8");
  assert.equal(networkKey("vmware", nic("hostonly"))?.label, "Host-only (VMnet1)");
  assert.equal(networkKey("vmware", nic("bridged"))?.key, "vmware:vmnet0");
  assert.equal(networkKey("vmware", nic("custom (VMnet2)", "VMnet2"))?.key, "vmware:vmnet2");
  assert.equal(networkKey("vmware", nic("custom (VMnet8)", "VMnet8"))?.key, "vmware:vmnet8", "the same NAT");
  assert.equal(networkKey("vmware", nic("custom (VMnet3)"))?.key, "vmware:vmnet3", "from the connection alone");
  assert.equal(networkKey("vmware", nic(null)), null);
});

test("VirtualBox's networks go by their kind and name; its NAT is each VM's own", () => {
  assert.equal(networkKey("virtualbox", nic("nat"))?.key, "virtualbox:nat");
  assert.match(networkKey("virtualbox", nic("nat"))?.sub ?? "", /each VM its own/);
  assert.equal(
    networkKey("virtualbox", nic("hostonly", "VirtualBox Host-Only Ethernet Adapter"))?.label,
    "Host-only: VirtualBox Host-Only Ethernet Adapter",
  );
  assert.equal(networkKey("virtualbox", nic("natnetwork", "lab"))?.key, "virtualbox:natnetwork:lab");
  assert.equal(networkKey("virtualbox", nic("intnet", "backend"))?.label, "Internal: backend");
  assert.equal(networkKey("virtualbox", nic("none")), null);
});

test("VMs sit on their networks; two VMs on one network share its node", () => {
  const vms = [
    vm("web"),
    vm("db"),
    vm("box", { hypervisor: "virtualbox", vmxPath: "0f8fad5b-d9cb-469f-a165-70867728950e" }),
  ];
  const graph = buildTopology(
    input({
      vms,
      networks: [
        { vmxPath: vms[0].vmxPath, hypervisor: "vmware", nics: [nic("nat"), nic("custom (VMnet2)", "VMnet2")] },
        { vmxPath: vms[1].vmxPath, hypervisor: "vmware", nics: [nic("custom (VMnet2)", "VMnet2")] },
        { vmxPath: vms[2].vmxPath, hypervisor: "virtualbox", nics: [nic("nat")] },
      ],
    }),
  );
  const networks = graph.nodes.filter((n) => n.kind === "network").map((n) => n.id);
  assert.deepEqual(networks.sort(), ["net:virtualbox:nat", "net:vmware:vmnet2", "net:vmware:vmnet8"]);
  const onVmnet2 = graph.edges.filter((e) => e.from === "net:vmware:vmnet2").map((e) => e.to);
  assert.deepEqual(onVmnet2.sort(), ["vm-db", "vm-web"].map((id) => `vm:${id}`).sort());
  assert.ok(graph.edges.some((e) => e.from === PC_ID && e.to === "net:vmware:vmnet8"));
  const web = graph.nodes.find((n) => n.id === "vm:vm-web");
  assert.deepEqual(web?.link, { kind: "vm", vmxPath: vms[0].vmxPath, view: "details" });
});

test("R4's host networks name a network by the same key, and add those no VM is on", () => {
  const vms = [vm("web")];
  const graph = buildTopology(
    input({
      vms,
      networks: [{ vmxPath: vms[0].vmxPath, hypervisor: "vmware", nics: [nic("nat")] }],
      hostNetworks: [
        { key: "vmware:vmnet8", label: "NAT 192.0.2.0/24", detail: "DHCP on" },
        { key: "vmware:vmnet5", label: "VMnet5", detail: "host-only, no VM" },
      ],
    }),
  );
  assert.equal(graph.nodes.find((n) => n.id === "net:vmware:vmnet8")?.label, "NAT 192.0.2.0/24");
  assert.ok(graph.nodes.some((n) => n.id === "net:vmware:vmnet5"));
});

test("a host network the hypervisor listed links to the host networks view; one only an adapter names doesn't", () => {
  const vms = [vm("web"), vm("db")];
  const graph = buildTopology(
    input({
      vms,
      networks: [
        { vmxPath: vms[0].vmxPath, hypervisor: "vmware", nics: [nic("nat")] },
        { vmxPath: vms[1].vmxPath, hypervisor: "vmware", nics: [nic("bridged")] },
      ],
      hostNetworks: [{ key: "vmware:vmnet8", label: "NAT (VMnet8)", link: { kind: "hostNetworks" } }],
    }),
  );
  const nat = graph.nodes.find((n) => n.id === "net:vmware:vmnet8");
  assert.deepEqual(nat?.link, { kind: "hostNetworks" });
  assert.ok(graph.edges.some((e) => e.from === "net:vmware:vmnet8" && e.to === "vm:" + vms[0].id));
  assert.equal(graph.nodes.find((n) => n.id === "net:vmware:vmnet0")?.link, undefined);
});

test("only sessions on the way to something show, unless every session is asked for", () => {
  const vms = [vm("web")];
  const sessions = [
    session("web", { vmId: "vm-web" }),
    session("bastion"),
    session("inner", { jumpSessionId: "bastion" }),
    session("db", { jumpSessionId: "inner" }),
    session("lonely"),
    session("tunnelled"),
  ];
  const graph = buildTopology(input({ vms, sessions, tunnels: [open("tunnelled", "t-1")] }));
  const shown = graph.nodes
    .filter((n) => n.kind === "session")
    .map((n) => n.label)
    .sort();
  assert.deepEqual(shown, ["bastion", "db", "inner", "tunnelled", "web"]);
  const all = buildTopology(input({ vms, sessions, allSessions: true }));
  assert.ok(all.nodes.some((n) => n.label === "lonely"));
});

test("each jump host puts the sessions behind it one column further, after their VM", () => {
  const vms = [vm("db")];
  const sessions = [
    session("bastion"),
    session("inner", { jumpSessionId: "bastion" }),
    session("db", { jumpSessionId: "inner", vmId: "vm-db" }),
  ];
  const graph = buildTopology(input({ vms, sessions }));
  const layer = (id: string) => graph.nodes.find((n) => n.id === `session:${id}`)?.layer;
  assert.deepEqual([layer("bastion"), layer("inner"), layer("db")], [3, 4, 5]);
  assert.ok(graph.edges.some((e) => e.from === "session:bastion" && e.to === "session:inner" && e.kind === "jump"));
  assert.ok(graph.edges.some((e) => e.from === "vm:vm-db" && e.to === "session:db" && e.kind === "reaches"));
});

test("a jump host loop (the core refuses it) still makes a map", () => {
  const sessions = [session("a", { jumpSessionId: "b" }), session("b", { jumpSessionId: "a" })];
  const graph = buildTopology(input({ sessions }));
  assert.equal(graph.nodes.filter((n) => n.kind === "session").length, 2);
  assert.ok(layoutTopology(graph.nodes, graph.edges).nodes.length > 0);
});

test("open tunnels follow the session whose terminal opened them, and link to its tunnels panel", () => {
  const sessions = [session("web", { vmId: "vm-web" })];
  const graph = buildTopology(
    input({ vms: [vm("web")], sessions, tunnels: [open("web", "t-9"), open("gone", "t-8")] }),
  );
  const tunnels = graph.nodes.filter((n) => n.kind === "tunnel");
  assert.equal(tunnels.length, 1, "a tunnel of a session not on the map is left out");
  assert.equal(tunnels[0].layer, 4);
  assert.deepEqual(tunnels[0].link, { kind: "terminal", terminalId: "t-9", tunnels: true });
  assert.match(tunnels[0].sub ?? "", /db01\.example\.com:5432/);
});

test("VMs that are off can be left out", () => {
  const vms = [vm("on"), vm("off", { powerState: "not_running" })];
  assert.equal(buildTopology(input({ vms })).nodes.filter((n) => n.kind === "vm").length, 2);
  assert.equal(buildTopology(input({ vms, offVms: false })).nodes.filter((n) => n.kind === "vm").length, 1);
});

test("the layout puts layers in columns, nobody closer than a row, and every edge from right to left side", () => {
  const vms = [vm("a"), vm("b"), vm("c")];
  const networks = vms.map((v, i) => ({
    vmxPath: v.vmxPath,
    hypervisor: "vmware" as const,
    nics: [nic(i === 2 ? "hostonly" : "nat")],
  }));
  const sessions = [session("a", { vmId: "vm-a" }), session("c", { vmId: "vm-c" })];
  const graph = buildTopology(input({ vms, networks, sessions }));
  const layout = layoutTopology(graph.nodes, graph.edges);
  const step = DEFAULT_LAYOUT.nodeWidth + DEFAULT_LAYOUT.gapX;
  for (const placed of layout.nodes) {
    assert.equal(placed.x, placed.column * step);
    assert.ok(placed.y >= 0);
  }
  const columns = new Map<number, number[]>();
  for (const p of layout.nodes) columns.set(p.column, [...(columns.get(p.column) ?? []), p.y]);
  for (const ys of columns.values()) {
    const sorted = [...ys].sort((a, b) => a - b);
    for (let i = 1; i < sorted.length; i++)
      assert.ok(sorted[i] - sorted[i - 1] >= DEFAULT_LAYOUT.nodeHeight + DEFAULT_LAYOUT.gapY, "no overlap");
  }
  assert.equal(layout.edges.length, graph.edges.length);
  assert.ok(layout.width > 0 && layout.height > 0);
  // A session sits level with its VM.
  const y = (id: string) => layout.nodes.find((p) => p.node.id === id)?.y;
  assert.equal(y("session:a"), y("vm:vm-a"));
});

test("ordering by neighbours uncrosses lines", () => {
  const nodes = [
    { id: "n1", kind: "network" as const, label: "A", layer: 1 },
    { id: "n2", kind: "network" as const, label: "B", layer: 1 },
    { id: "v1", kind: "vm" as const, label: "on B", layer: 2 },
    { id: "v2", kind: "vm" as const, label: "on A", layer: 2 },
  ];
  const edges = [
    { from: "n2", to: "v1", kind: "nic" as const },
    { from: "n1", to: "v2", kind: "nic" as const },
  ];
  assert.deepEqual(orderColumns(nodes, edges), [
    ["n1", "n2"],
    ["v2", "v1"],
  ]);
});

test("an edge across several columns runs in a lane of its own, never behind a node", () => {
  const nodes = [
    { id: "a", kind: "vm" as const, label: "a", layer: 2 },
    { id: "b", kind: "session" as const, label: "b", layer: 3 },
    { id: "t", kind: "tunnel" as const, label: "t", layer: 4 },
    { id: "c", kind: "session" as const, label: "c", layer: 5 },
  ];
  const edges = [
    { from: "a", to: "b", kind: "reaches" as const },
    { from: "b", to: "t", kind: "tunnel" as const },
    { from: "a", to: "c", kind: "reaches" as const },
  ];
  const o = DEFAULT_LAYOUT;
  const layout = layoutTopology(nodes, edges);
  const long = layout.edges.find((e) => e.edge.to === "c");
  assert.ok(long);
  const lanes = [...long.path.matchAll(/L (\S+) (\S+)/g)].map((m) => Number(m[2]));
  assert.equal(lanes.length, 2, "one lane in each column it crosses");
  for (const id of ["b", "t"]) {
    const box = layout.nodes.find((p) => p.node.id === id);
    assert.ok(box);
    for (const y of lanes)
      assert.ok(y < box.y - o.gapY / 2 || y > box.y + o.nodeHeight + o.gapY / 2, `the lane at ${y} misses ${id}`);
  }
  assert.ok(long.path.startsWith(`M ${o.nodeWidth} `));
});

test("a listening tunnel says where it listens and where it leads", () => {
  const tunnel = open("web", "t-1");
  const graph = buildTopology(
    input({ vms: [vm("web")], sessions: [session("web", { vmId: "vm-web" })], tunnels: [tunnel] }),
  );
  assert.equal(graph.nodes.find((n) => n.kind === "tunnel")?.sub, "127.0.0.1:5432 → db01.example.com:5432");
});

test("an edge is a curve from the right middle of one box to the left middle of the next", () => {
  const o = DEFAULT_LAYOUT;
  assert.equal(edgePath({ x: 0, y: 0 }, { x: 272, y: 66 }, o), `M 200 26 C 236 26, 236 92, 272 92`);
});

test("FD-03: everything the map says masks while presenting, and addresses are marked as one value", () => {
  const vms = [vm("web01", { ipAddress: "192.0.2.10" })];
  const sessions = [
    session("prod-web", { host: "web01.example.com", username: "alice", vmId: "vm-web01" }),
    session("jump", { host: "bastion.example.org", username: "bob" }),
    session("db", { host: "db01.example.com", jumpSessionId: "jump" }),
  ];
  const tunnels = [open("prod-web", "t-1")];
  // What the app learns from its answers (api.ts runs learnFields on every one).
  const masker = new Masker();
  learnFields(masker, vms);
  learnFields(masker, sessions);
  learnFields(
    masker,
    tunnels.map((t) => t.tunnel),
  );
  const graph = buildTopology(input({ vms, sessions, tunnels }));
  const secrets = ["192.0.2.10", "web01.example.com", "bastion.example.org", "db01.example.com", "alice", "bob"];
  for (const node of graph.nodes) {
    for (const text of [node.label, node.sub ?? ""]) {
      const shown = masker.text(text);
      for (const value of secrets) assert.ok(!shown.includes(value), `${node.id}: "${shown}" shows ${value}`);
    }
  }
  const web = graph.nodes.find((n) => n.id === "session:prod-web");
  assert.equal(web?.subMask, "address", "user@host is one value");
  assert.equal(graph.nodes.find((n) => n.id === "vm:vm-web01")?.subMask, "ip");
});
