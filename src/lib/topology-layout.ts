// QL-21: a layered layout for the topology map, written for it rather than taken from a library: columns by layer
// (this PC, networks, VMs, sessions, tunnels); an edge that spans several columns gets a thin slot of its own in each
// column it crosses, so it never runs behind a node there; the order in each column by the barycentre of each item's
// neighbours (a few sweeps right and left, so lines cross less); then each item placed level with its neighbours in the
// columns before it, never closer than its height to the item above. Edges are curves from the right side of one node
// to the left side of the next, straight through their slots. Pure: tested in topology.test.ts.

import type { TopoEdge, TopoNode } from "./topology.ts";

export interface LayoutOptions {
  nodeWidth: number;
  nodeHeight: number;
  /** Between columns. */
  gapX: number;
  /** Between nodes in a column. */
  gapY: number;
  /** The height a passing edge's slot takes in a column. */
  laneHeight: number;
  /** Sweeps of the ordering. */
  sweeps: number;
}

export const DEFAULT_LAYOUT: LayoutOptions = {
  nodeWidth: 200,
  nodeHeight: 52,
  gapX: 72,
  gapY: 14,
  laneHeight: 6,
  sweeps: 4,
};

export interface PlacedNode {
  node: TopoNode;
  x: number;
  y: number;
  /** Its column (empty layers left out) and its place in it. */
  column: number;
  row: number;
}

export interface PlacedEdge {
  edge: TopoEdge;
  /** An SVG path. */
  path: string;
}

export interface TopologyLayout {
  nodes: PlacedNode[];
  edges: PlacedEdge[];
  width: number;
  height: number;
}

/** A node, or the slot an edge passes through in a column between its ends. */
interface Item {
  id: string;
  column: number;
  label: string;
  network: boolean;
  lane: boolean;
}

interface Link {
  from: string;
  to: string;
}

/** Each node's column: its layer among the layers that have nodes. */
function columnsOf(nodes: readonly TopoNode[]): Map<string, number> {
  const layers = [...new Set(nodes.map((n) => n.layer))].sort((a, b) => a - b);
  const column = new Map(layers.map((layer, i) => [layer, i]));
  return new Map(nodes.map((n) => [n.id, column.get(n.layer) ?? 0]));
}

function mean(values: number[]): number | null {
  return values.length === 0 ? null : values.reduce((a, b) => a + b, 0) / values.length;
}

function itemsOf(nodes: readonly TopoNode[]): Item[] {
  const column = columnsOf(nodes);
  return nodes.map((n) => ({
    id: n.id,
    column: column.get(n.id) ?? 0,
    label: n.label,
    network: n.kind === "network",
    lane: false,
  }));
}

function orderItems(items: readonly Item[], links: readonly Link[], sweeps: number): string[][] {
  const column = new Map(items.map((i) => [i.id, i.column]));
  const count = Math.max(0, ...items.map((i) => i.column)) + 1;
  // Start: networks by name, the rest as given (which keeps a VM's sessions together).
  const columns: string[][] = Array.from({ length: count }, () => []);
  const sorted = [...items].sort((a, b) => (a.network && b.network ? a.label.localeCompare(b.label) : 0));
  for (const item of sorted) columns[item.column].push(item.id);
  const neighbours = new Map<string, string[]>(items.map((i) => [i.id, []]));
  for (const l of links) {
    neighbours.get(l.from)?.push(l.to);
    neighbours.get(l.to)?.push(l.from);
  }
  const position = () => {
    const at = new Map<string, number>();
    columns.forEach((ids) => ids.forEach((id, i) => at.set(id, i)));
    return at;
  };
  const reorder = (c: number, side: "left" | "right") => {
    const at = position();
    const keyed = columns[c].map((id, i) => {
      const near = (neighbours.get(id) ?? []).filter((other) => {
        const oc = column.get(other) ?? 0;
        return side === "left" ? oc < c : oc > c;
      });
      const centre = mean(near.map((other) => at.get(other) ?? 0));
      return { id, key: centre ?? i, i };
    });
    keyed.sort((a, b) => a.key - b.key || a.i - b.i);
    columns[c] = keyed.map((k) => k.id);
  };
  for (let sweep = 0; sweep < sweeps; sweep++) {
    for (let c = 1; c < count; c++) reorder(c, "left");
    for (let c = count - 2; c >= 0; c--) reorder(c, "right");
  }
  return columns;
}

/** The order of the nodes in each column (edges between neighbouring columns only). */
export function orderColumns(
  nodes: readonly TopoNode[],
  edges: readonly TopoEdge[],
  sweeps = DEFAULT_LAYOUT.sweeps,
): string[][] {
  return orderItems(itemsOf(nodes), edges, sweeps);
}

const r = (n: number) => Math.round(n * 10) / 10;

/** A curve between two points, leaving and arriving level. */
function curve(x1: number, y1: number, x2: number, y2: number, gapX: number): string {
  const bend = Math.max(gapX / 2, Math.abs(x2 - x1) / 2);
  return `C ${r(x1 + bend)} ${r(y1)}, ${r(x2 - bend)} ${r(y2)}, ${r(x2)} ${r(y2)}`;
}

/** A curve from the right middle of one box to the left middle of another. */
export function edgePath(from: { x: number; y: number }, to: { x: number; y: number }, o: LayoutOptions): string {
  const x1 = from.x + o.nodeWidth;
  const y1 = from.y + o.nodeHeight / 2;
  // An edge back to an earlier column (a jump host loop the core refuses anyway) bows out to the right.
  return `M ${r(x1)} ${r(y1)} ${curve(x1, y1, to.x, to.y + o.nodeHeight / 2, o.gapX)}`;
}

export function layoutTopology(
  nodes: readonly TopoNode[],
  edges: readonly TopoEdge[],
  options: Partial<LayoutOptions> = {},
): TopologyLayout {
  const o = { ...DEFAULT_LAYOUT, ...options };
  const items = itemsOf(nodes);
  const column = new Map(items.map((i) => [i.id, i.column]));
  // Long edges get a lane in each column they cross; `chains` keeps each edge's way through them.
  const links: Link[] = [];
  const chains: string[][] = [];
  edges.forEach((e, n) => {
    const a = column.get(e.from);
    const b = column.get(e.to);
    if (a === undefined || b === undefined) {
      chains.push([]);
      return;
    }
    const way = [e.from];
    for (let c = a + 1; c < b; c++) {
      const id = `~${n}:${c}`;
      items.push({ id, column: c, label: "", network: false, lane: true });
      way.push(id);
    }
    way.push(e.to);
    for (let k = 1; k < way.length; k++) links.push({ from: way[k - 1], to: way[k] });
    chains.push(way);
  });
  for (const item of items) column.set(item.id, item.column);
  const columns = orderItems(items, links, o.sweeps);
  const byId = new Map(items.map((i) => [i.id, i]));
  const height = (id: string) => (byId.get(id)?.lane ? o.laneHeight : o.nodeHeight);

  const before = new Map<string, string[]>(items.map((i) => [i.id, []]));
  const after = new Map<string, string[]>(items.map((i) => [i.id, []]));
  for (const l of links) {
    const cf = column.get(l.from) ?? 0;
    const ct = column.get(l.to) ?? 0;
    const [early, late] = cf < ct ? [l.from, l.to] : ct < cf ? [l.to, l.from] : [null, null];
    if (early && late) {
      before.get(late)?.push(early);
      after.get(early)?.push(late);
    }
  }
  // Centre lines, column by column.
  const centre = new Map<string, number>();
  const centreOf = (ids: string[]) =>
    mean(
      ids.flatMap((id) => {
        const y = centre.get(id);
        return y === undefined ? [] : [y];
      }),
    );
  const below = (prev: string | null, id: string) =>
    prev === null ? height(id) / 2 : (centre.get(prev) ?? 0) + (height(prev) + height(id)) / 2 + o.gapY;
  // Left to right: level with what comes before, below the item above at least.
  columns.forEach((ids) => {
    let prev: string | null = null;
    for (const id of ids) {
      const least = below(prev, id);
      centre.set(id, Math.max(centreOf(before.get(id) ?? []) ?? least, least));
      prev = id;
    }
  });
  // Right to left: a node with nothing before it (this PC, a jump host) moves level with what follows it.
  for (let c = columns.length - 1; c >= 0; c--) {
    let prev: string | null = null;
    for (const id of columns[c]) {
      const least = below(prev, id);
      const roots = (before.get(id) ?? []).length === 0;
      const level = roots ? centreOf(after.get(id) ?? []) : null;
      centre.set(id, Math.max(level ?? centre.get(id) ?? least, least));
      prev = id;
    }
  }

  const step = o.nodeWidth + o.gapX;
  const placed = new Map<string, PlacedNode>();
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  columns.forEach((ids, c) => {
    let row = 0;
    for (const id of ids) {
      const node = nodeById.get(id);
      if (!node) continue;
      placed.set(id, { node, x: c * step, y: (centre.get(id) ?? 0) - o.nodeHeight / 2, column: c, row });
      row += 1;
    }
  });
  const placedEdges = edges.flatMap((edge, n) => {
    const way = chains[n];
    const from = placed.get(edge.from);
    const to = placed.get(edge.to);
    if (!from || !to || way.length === 0) return [];
    if (way.length === 2) return [{ edge, path: edgePath(from, to, o) }];
    let x = from.x + o.nodeWidth;
    let y = from.y + o.nodeHeight / 2;
    let path = `M ${r(x)} ${r(y)}`;
    for (const lane of way.slice(1, -1)) {
      const lx = (column.get(lane) ?? 0) * step;
      const ly = centre.get(lane) ?? y;
      path += ` ${curve(x, y, lx, ly, o.gapX)} L ${r(lx + o.nodeWidth)} ${r(ly)}`;
      x = lx + o.nodeWidth;
      y = ly;
    }
    path += ` ${curve(x, y, to.x, to.y + o.nodeHeight / 2, o.gapX)}`;
    return [{ edge, path }];
  });
  const list = [...placed.values()];
  const width = list.length === 0 ? 0 : Math.max(...list.map((p) => p.x)) + o.nodeWidth;
  const bottom = Math.max(0, ...[...centre].map(([id, y]) => y + height(id) / 2));
  return { nodes: list, edges: placedEdges, width, height: bottom };
}
