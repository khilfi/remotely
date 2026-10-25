// QL-21 topology map, the graph (tested in topology.test.ts): this PC, the networks its VMs are on (from R3's adapter
// settings: Workstation's VMnets, VirtualBox's NAT, bridged, host-only, NAT and internal networks), the VMs, the saved
// sessions that reach them (QL-01 links), the jump hosts on the way (SS-07) and the tunnels open on each session's
// terminals. Read only: every node links to the item's own page, and nothing here changes anything. The layout is
// topology-layout.ts.
//
// R4 adds host networks: `hostNetworks` gives a network its name and details by the same key (`networkKey`), and adds
// those no VM is on yet.

import type { Hypervisor, SessionRecord, VirtualNic, VmRecord } from "./api.ts";
import type { AppLink } from "./links.ts";
import type { OpenTunnel } from "./open-tunnels.ts";
import type { DetailMask } from "./search.ts";
import { forwardText } from "./tunnels.ts";

export type TopoKind = "pc" | "network" | "vm" | "session" | "tunnel";
export type TopoState = "on" | "off" | "warning" | "unknown";

export interface TopoNode {
  id: string;
  kind: TopoKind;
  label: string;
  /** A second line: an address, a route, a network's kind. */
  sub?: string;
  /** FD-03: the second line holds one host, IP, user or address, masked as one while presenting. */
  subMask?: DetailMask;
  state?: TopoState;
  /** Where a click goes; a network has none until R4's host networks. */
  link?: AppLink;
  /** The column: this PC 0, networks 1, VMs 2, sessions 3 and on (one more per jump host), tunnels after them. */
  layer: number;
}

export type TopoEdgeKind = "network" | "nic" | "reaches" | "jump" | "tunnel";

export interface TopoEdge {
  from: string;
  to: string;
  kind: TopoEdgeKind;
}

export interface Topology {
  nodes: TopoNode[];
  edges: TopoEdge[];
}

/** A VM's adapters as the core read them (navigation-api.ts VmNetworks). */
export interface VmNics {
  vmxPath: string;
  hypervisor: Hypervisor;
  nics: VirtualNic[];
}

/** R4: a host network by its key, with its name and what it is. */
export interface HostNetwork {
  key: string;
  label: string;
  detail?: string;
}

export interface TopologyInput {
  vms: readonly VmRecord[];
  networks: readonly VmNics[];
  sessions: readonly SessionRecord[];
  tunnels: readonly OpenTunnel[];
  hostNetworks?: readonly HostNetwork[];
  /** Sessions with no VM, jump host or tunnel too (off: only those on the way to something). */
  allSessions?: boolean;
  /** VMs that are off too (on by default). */
  offVms?: boolean;
}

export const PC_ID = "pc";

const VMNET_LABELS: Record<string, string> = {
  vmnet0: "Bridged (VMnet0)",
  vmnet1: "Host-only (VMnet1)",
  vmnet8: "NAT (VMnet8)",
};

/** The network an adapter is on, as a key and a name; null for an adapter on none. */
export function networkKey(
  hypervisor: Hypervisor,
  nic: VirtualNic,
): { key: string; label: string; sub: string } | null {
  const connection = (nic.connection ?? "").toLowerCase();
  const name = nic.networkName?.trim() || null;
  if (hypervisor === "vmware") {
    const vnet =
      connection === "nat"
        ? "vmnet8"
        : connection === "hostonly"
          ? "vmnet1"
          : connection === "bridged"
            ? "vmnet0"
            : name?.toLowerCase().startsWith("vmnet")
              ? name.toLowerCase()
              : (/\((vmnet\d+)\)/i.exec(connection)?.[1]?.toLowerCase() ?? null);
    if (vnet) {
      const label = VMNET_LABELS[vnet] ?? `VMnet${vnet.slice(5)}`;
      return { key: `vmware:${vnet}`, label, sub: "Workstation" };
    }
    if (!connection) return null;
    return { key: `vmware:${connection}`, label: connection, sub: "Workstation" };
  }
  switch (connection) {
    case "":
    case "none":
    case "null":
      return null;
    case "nat":
      return { key: "virtualbox:nat", label: "NAT", sub: "VirtualBox: each VM its own" };
    case "bridged":
      return {
        key: `virtualbox:bridged:${name ?? ""}`,
        label: name ? `Bridged: ${name}` : "Bridged",
        sub: "VirtualBox",
      };
    case "hostonly":
      return {
        key: `virtualbox:hostonly:${name ?? ""}`,
        label: name ? `Host-only: ${name}` : "Host-only",
        sub: "VirtualBox",
      };
    case "natnetwork":
      return { key: `virtualbox:natnetwork:${name ?? ""}`, label: `NAT network: ${name ?? "?"}`, sub: "VirtualBox" };
    case "intnet":
      return { key: `virtualbox:intnet:${name ?? ""}`, label: `Internal: ${name ?? "?"}`, sub: "VirtualBox" };
    default:
      return { key: `virtualbox:${connection}:${name ?? ""}`, label: name ?? connection, sub: "VirtualBox" };
  }
}

function vmState(vm: VmRecord): TopoState {
  if (vm.powerState === "running") return "on";
  if (vm.powerState === "paused" || vm.powerState === "suspended") return "warning";
  if (vm.powerState === "not_running") return "off";
  return "unknown";
}

/** The map's nodes and edges from what the app read. */
export function buildTopology(input: TopologyInput): Topology {
  const nodes = new Map<string, TopoNode>();
  const edges: TopoEdge[] = [];
  const add = (node: TopoNode) => {
    if (!nodes.has(node.id)) nodes.set(node.id, node);
  };
  const edge = (from: string, to: string, kind: TopoEdgeKind) => {
    if (nodes.has(from) && nodes.has(to) && !edges.some((e) => e.from === from && e.to === to))
      edges.push({ from, to, kind });
  };

  add({
    id: PC_ID,
    kind: "pc",
    label: "This PC",
    sub: "Workstation and VirtualBox host",
    link: { kind: "page", page: "dashboard" },
    layer: 0,
  });

  const named = new Map((input.hostNetworks ?? []).map((n) => [n.key, n]));
  for (const n of input.hostNetworks ?? []) {
    add({ id: `net:${n.key}`, kind: "network", label: n.label, sub: n.detail, layer: 1 });
  }

  // VMs and their networks.
  const nicsByVm = new Map(input.networks.map((n) => [n.vmxPath, n]));
  const shownVms = input.vms.filter((vm) => input.offVms !== false || vm.powerState !== "not_running");
  for (const vm of shownVms) {
    add({
      id: `vm:${vm.id}`,
      kind: "vm",
      label: vm.displayName,
      sub: vm.ipAddress ?? (vm.hypervisor === "virtualbox" ? "VirtualBox" : "Workstation"),
      subMask: vm.ipAddress ? "ip" : undefined,
      state: vmState(vm),
      link: { kind: "vm", vmxPath: vm.vmxPath, view: "details" },
      layer: 2,
    });
    const read = nicsByVm.get(vm.vmxPath);
    for (const nic of read?.nics ?? []) {
      const net = networkKey(vm.hypervisor, nic);
      if (!net) continue;
      const known = named.get(net.key);
      add({
        id: `net:${net.key}`,
        kind: "network",
        label: known?.label ?? net.label,
        sub: known?.detail ?? net.sub,
        layer: 1,
      });
      edge(`net:${net.key}`, `vm:${vm.id}`, "nic");
    }
  }
  for (const node of nodes.values()) if (node.kind === "network") edge(PC_ID, node.id, "network");

  // Sessions: those that reach a shown VM, the jump hosts on their way and the sessions behind them, those with an
  // open tunnel; every one when asked.
  const byId = new Map(input.sessions.map((s) => [s.id, s]));
  const vmIds = new Set(shownVms.map((vm) => vm.id));
  const jumpHosts = new Set(
    input.sessions.flatMap((s) => (s.jumpSessionId && byId.has(s.jumpSessionId) ? [s.jumpSessionId] : [])),
  );
  const tunnelled = new Set(input.tunnels.map((t) => t.sessionId));
  const wanted = new Set<string>();
  const want = (id: string) => {
    let next: string | null = id;
    const seen = new Set<string>();
    while (next && byId.has(next) && !seen.has(next)) {
      seen.add(next);
      wanted.add(next);
      next = byId.get(next)?.jumpSessionId ?? null;
    }
  };
  for (const s of input.sessions) {
    const linked = s.vmId !== null && vmIds.has(s.vmId);
    if (input.allSessions || linked || jumpHosts.has(s.id) || s.jumpSessionId || tunnelled.has(s.id)) want(s.id);
  }
  // A session's column: after its VM, after its jump host, and never before the sessions' first column.
  const layerOf = new Map<string, number>();
  const sessionLayer = (id: string, seen = new Set<string>()): number => {
    const cached = layerOf.get(id);
    if (cached !== undefined) return cached;
    const s = byId.get(id);
    if (!s || seen.has(id)) return 3;
    seen.add(id);
    let layer = 3;
    if (s.jumpSessionId && wanted.has(s.jumpSessionId))
      layer = Math.max(layer, sessionLayer(s.jumpSessionId, seen) + 1);
    layerOf.set(id, layer);
    return layer;
  };
  for (const id of wanted) {
    const s = byId.get(id);
    if (!s) continue;
    add({
      id: `session:${s.id}`,
      kind: "session",
      label: s.name,
      sub: s.username ? `${s.username}@${s.host}` : s.host,
      subMask: s.username ? "address" : "host",
      link: { kind: "session", sessionId: s.id },
      layer: sessionLayer(s.id),
    });
  }
  for (const id of wanted) {
    const s = byId.get(id);
    if (!s) continue;
    if (s.vmId && vmIds.has(s.vmId)) edge(`vm:${s.vmId}`, `session:${s.id}`, "reaches");
    if (s.jumpSessionId && wanted.has(s.jumpSessionId)) edge(`session:${s.jumpSessionId}`, `session:${s.id}`, "jump");
  }

  // Open tunnels, after the session whose terminal opened them.
  for (const t of input.tunnels) {
    const from = nodes.get(`session:${t.sessionId}`);
    if (!from) continue;
    const id = `tunnel:${t.terminalId}:${t.tunnel.forward.id}`;
    add({
      id,
      kind: "tunnel",
      label: t.tunnel.forward.label ?? (t.tunnel.forward.kind === "dynamic" ? "SOCKS proxy" : "Tunnel"),
      sub: forwardText(t.tunnel.forward),
      state: t.tunnel.state.state === "listening" ? "on" : "warning",
      link: { kind: "terminal", terminalId: t.terminalId, tunnels: true },
      layer: from.layer + 1,
    });
    edge(from.id, id, "tunnel");
  }

  return { nodes: [...nodes.values()], edges };
}
