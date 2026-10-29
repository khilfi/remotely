// QL-21 topology map (Ctrl+0): this PC, its VMs' networks, the VMs, the saved sessions that reach them (QL-01), the
// jump hosts on the way (SS-07) and the tunnels open on their terminals, in one read-only diagram. Every node opens its
// item's page; pointing at one (or focusing it) lights up what it connects to. The graph is lib/topology.ts and the
// layout lib/topology-layout.ts, both pure and tested.
//
// FD-03: every word on the map is HTML (the nodes are buttons over an SVG that draws only the lines), so presentation
// mode's DOM masking covers it as anywhere else, and a node's address line carries `data-mask`.
//
// Reads only while shown (P6): the VM list, the sessions, each VM's adapters (what was read before, and a read of
// the VMs never read; Refresh reads every VM again) and R4's host networks alone (VM-11: vmrun listHostNetworks and
// VBoxManage's two lists, no VM read again), joined to the adapters by network name; what was listed is kept for the
// palette's search. Tunnels come from the panes' own events.

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { CableIcon, LaptopIcon, MonitorIcon, NetworkIcon, ServerIcon, type LucideIcon } from "lucide-react";
import { toast } from "sonner";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { RefreshButton } from "@/components/RefreshButton";
import { api, errorMessage, type SessionRecord, type VmRecord } from "@/lib/api";
import { rememberHostNetworks } from "@/lib/host-networks-cache";
import type { AppLink } from "@/lib/links";
import { navigationApi, type VmNetworks } from "@/lib/navigation-api";
import { openTunnels, subscribeTunnels } from "@/lib/open-tunnels";
import { buildTopology, type HostNetwork, type TopoKind, type TopoNode, type TopoState } from "@/lib/topology";
import { DEFAULT_LAYOUT, layoutTopology } from "@/lib/topology-layout";
import { cn } from "@/lib/utils";
import { topologyHostNetworks } from "@/lib/vm-insight";
import { insightApi } from "@/lib/vm-insight-api";

const ICON: Record<TopoKind, LucideIcon> = {
  pc: LaptopIcon,
  network: NetworkIcon,
  vm: MonitorIcon,
  session: ServerIcon,
  tunnel: CableIcon,
};

const STATE: Record<TopoState, { dot: string; label: string }> = {
  on: { dot: "bg-success", label: "Running" },
  off: { dot: "bg-muted-foreground/40", label: "Off" },
  warning: { dot: "bg-status-warning", label: "Paused, suspended or waiting" },
  unknown: { dot: "bg-muted-foreground/40", label: "Unknown" },
};

const EDGE_CLASS: Record<string, string> = {
  network: "stroke-border",
  nic: "stroke-muted-foreground/50",
  reaches: "stroke-series-1",
  jump: "stroke-series-2",
  tunnel: "stroke-status-warning",
};

const PAD = 16;

interface Props {
  active: boolean;
  onOpenLink: (link: AppLink) => void;
}

export function MapPage({ active, onOpenLink }: Props) {
  const [vms, setVms] = useState<VmRecord[] | null>(null);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [networks, setNetworks] = useState<VmNetworks[]>([]);
  const [hostNetworks, setHostNetworks] = useState<HostNetwork[]>([]);
  const [reading, setReading] = useState(false);
  const [allSessions, setAllSessions] = useState(false);
  const [offVms, setOffVms] = useState(true);
  const [lit, setLit] = useState<string | null>(null);
  const tunnels = useSyncExternalStore(subscribeTunnels, openTunnels);

  const load = useCallback((fresh: boolean) => {
    // VM-11: the host networks come on their own, as vmrun takes a moment; until then (or without them) the map names
    // its networks as the adapters do.
    insightApi.hostNetworkList().then(
      (report) => {
        const list = topologyHostNetworks(report);
        setHostNetworks(list);
        rememberHostNetworks(list);
      },
      (err) => console.warn("host networks not read", err),
    );
    return Promise.all([api.vmList(), api.sessions(), navigationApi.vmNetworks(fresh)]).then(
      ([v, s, n]) => {
        setVms(v);
        setSessions(s);
        setNetworks(n);
      },
      (err) => toast.error(errorMessage(err)),
    );
  }, []);

  useEffect(() => {
    if (active) void load(false);
  }, [active, load]);

  function readAgain() {
    setReading(true);
    void load(true).finally(() => setReading(false));
  }

  const graph = useMemo(
    () => buildTopology({ vms: vms ?? [], networks, sessions, tunnels, hostNetworks, allSessions, offVms }),
    [vms, networks, sessions, tunnels, hostNetworks, allSessions, offVms],
  );
  const layout = useMemo(() => layoutTopology(graph.nodes, graph.edges), [graph]);
  const near = useMemo(() => {
    if (!lit) return null;
    const ids = new Set([lit]);
    for (const e of graph.edges) {
      if (e.from === lit) ids.add(e.to);
      if (e.to === lit) ids.add(e.from);
    }
    return ids;
  }, [lit, graph.edges]);

  const unread = networks.filter((n) => n.problem !== null).length;
  const readAt = networks.reduce<string | null>(
    (latest, n) => (n.collectedAt && (!latest || n.collectedAt > latest) ? n.collectedAt : latest),
    null,
  );
  const nothing = vms !== null && graph.nodes.length <= 1;

  return (
    <div className="flex h-full flex-col gap-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <RefreshButton variant="outline" busy={reading} onClick={readAgain} />
        <div className="flex items-center gap-2">
          <Switch id="map-all-sessions" checked={allSessions} onCheckedChange={setAllSessions} />
          <Label htmlFor="map-all-sessions" className="font-normal">
            Sessions with no VM or jump host
          </Label>
        </div>
        <div className="flex items-center gap-2">
          <Switch id="map-off-vms" checked={offVms} onCheckedChange={setOffVms} />
          <Label htmlFor="map-off-vms" className="font-normal">
            VMs that are off
          </Label>
        </div>
        <Legend />
      </div>
      <p className="text-xs text-muted-foreground" role="status">
        Networks as each VM&apos;s settings say and Workstation and VirtualBox list them
        {readAt ? `, read ${new Date(readAt).toLocaleString()}` : ""}.
        {unread > 0 &&
          ` ${unread === 1 ? "One VM" : `${unread} VMs`} could not be read now: what was read before shows.`}{" "}
        Read only: click a node to open it.
      </p>
      {nothing ? (
        <Empty className="border">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <NetworkIcon />
            </EmptyMedia>
            <EmptyTitle>Nothing to map yet</EmptyTitle>
            <EmptyDescription>
              VMs show here with their networks once Remotely finds them; sessions once they reach a VM, go through a
              jump host or open a tunnel.
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <div
          className="relative min-h-0 flex-1 overflow-auto rounded-md border bg-muted/20"
          role="group"
          aria-label="Topology map"
        >
          <div className="relative" style={{ width: layout.width + PAD * 2, height: layout.height + PAD * 2 }}>
            <svg
              className="pointer-events-none absolute inset-0"
              width={layout.width + PAD * 2}
              height={layout.height + PAD * 2}
              aria-hidden
            >
              <g transform={`translate(${PAD} ${PAD})`} fill="none" strokeWidth={1.5}>
                {layout.edges.map(({ edge, path }) => (
                  <path
                    key={`${edge.from}>${edge.to}`}
                    d={path}
                    className={cn(
                      EDGE_CLASS[edge.kind],
                      edge.kind === "tunnel" && "[stroke-dasharray:4_3]",
                      near && !(near.has(edge.from) && near.has(edge.to)) && "opacity-15",
                    )}
                  />
                ))}
              </g>
            </svg>
            {layout.nodes.map(({ node, x, y }) => (
              <MapNode
                key={node.id}
                node={node}
                x={x + PAD}
                y={y + PAD}
                dimmed={near !== null && !near.has(node.id)}
                onLight={(on) => setLit(on ? node.id : null)}
                onOpen={() => {
                  if (node.link) onOpenLink(node.link);
                  else setLit((cur) => (cur === node.id ? null : node.id));
                }}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function MapNode({
  node,
  x,
  y,
  dimmed,
  onLight,
  onOpen,
}: {
  node: TopoNode;
  x: number;
  y: number;
  dimmed: boolean;
  onLight: (on: boolean) => void;
  onOpen: () => void;
}) {
  const Icon = ICON[node.kind];
  const state = node.state ? STATE[node.state] : null;
  return (
    <button
      type="button"
      className={cn(
        "absolute flex items-center gap-2 rounded-md border bg-card px-2.5 text-left shadow-xs transition-opacity hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring",
        node.kind === "network" && "border-dashed",
        dimmed && "opacity-30",
      )}
      style={{ left: x, top: y, width: DEFAULT_LAYOUT.nodeWidth, height: DEFAULT_LAYOUT.nodeHeight }}
      title={node.link ? undefined : "Shows what is on this network"}
      onPointerEnter={() => onLight(true)}
      onPointerLeave={() => onLight(false)}
      onFocus={() => onLight(true)}
      onBlur={() => onLight(false)}
      onClick={onOpen}
    >
      <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium">{node.label}</span>
        {node.sub && (
          <span className="block truncate text-xs text-muted-foreground" data-mask={node.subMask}>
            {node.sub}
          </span>
        )}
      </span>
      {state && <span className={cn("size-2 shrink-0 rounded-full", state.dot)} aria-label={state.label} />}
    </button>
  );
}

function Legend() {
  const line = (className: string, label: string, dashed = false) => (
    <span className="flex items-center gap-1.5">
      <svg width="22" height="8" aria-hidden>
        <path d="M 1 4 L 21 4" strokeWidth={2} className={cn(className, dashed && "[stroke-dasharray:4_3]")} />
      </svg>
      {label}
    </span>
  );
  return (
    <div className="ml-auto flex flex-wrap items-center gap-3 text-xs text-muted-foreground" aria-label="Legend">
      {line(EDGE_CLASS.nic, "on the network")}
      {line(EDGE_CLASS.reaches, "session reaches the VM")}
      {line(EDGE_CLASS.jump, "through a jump host")}
      {line(EDGE_CLASS.tunnel, "open tunnel", true)}
    </div>
  );
}
