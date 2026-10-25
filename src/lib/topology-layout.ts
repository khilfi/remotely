// QL-21: a layered layout for the topology map, written for it rather than taken from a library: columns by layer
// (this PC, networks, VMs, sessions, tunnels), the order in each column by the barycentre of each node's neighbours
// (a few sweeps right and left, so lines cross less), then each node placed level with its neighbours in the columns
// before it, never closer than a row to the node above. Edges are curves from the right side of one node to the left
// side of the next. Pure: tested in topology-layout.test.ts.

import type { TopoEdge, TopoNode } from "./topology.ts";

export interface LayoutOptions {
  nodeWidth: number;
  nodeHeight: number;
  /** Between columns. */
  gapX: number;
  /** Between nodes in a column. */
  gapY: number;
  /** Sweeps of the ordering. */
  sweeps: number;
}

export const DEFAULT_LAYOUT: LayoutOptions = { nodeWidth: 200, nodeHeight: 52, gapX: 72, gapY: 14, sweeps: 4 };

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

/** Each node's column: its layer among the layers that have nodes. */
function columnsOf(nodes: readonly TopoNode[]): Map<string, number> {
  const layers = [...new Set(nodes.map((n) => n.layer))].sort((a, b) => a - b);
  const column = new Map(layers.map((layer, i) => [layer, i]));
  return new Map(nodes.map((n) => [n.id, column.get(n.layer) ?? 0]));
}

function mean(values: number[]): number | null {
  return values.length === 0 ? null : values.reduce((a, b) => a + b, 0) / values.length;
}

/** The order of the nodes in each column. */
export function orderColumns(
  nodes: readonly TopoNode[],
  edges: readonly TopoEdge[],
  sweeps = DEFAULT_LAYOUT.sweeps,
): string[][] {
  const column = columnsOf(nodes);
  const count = Math.max(0, ...column.values()) + 1;
  // Start: by kind's own order (networks by name, the rest as given), which keeps a VM's sessions together.
  const columns: string[][] = Array.from({ length: count }, () => []);
  const sorted = [...nodes].sort((a, b) =>
    a.kind === "network" && b.kind === "network" ? a.label.localeCompare(b.label) : 0,
  );
  for (const n of sorted) columns[column.get(n.id) ?? 0].push(n.id);
  const neighbours = new Map<string, string[]>(nodes.map((n) => [n.id, []]));
  for (const e of edges) {
    neighbours.get(e.from)?.push(e.to);
    neighbours.get(e.to)?.push(e.from);
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

/** A curve from the right middle of one box to the left middle of another. */
export function edgePath(from: { x: number; y: number }, to: { x: number; y: number }, o: LayoutOptions): string {
  const x1 = from.x + o.nodeWidth;
  const y1 = from.y + o.nodeHeight / 2;
  const x2 = to.x;
  const y2 = to.y + o.nodeHeight / 2;
  // An edge back to an earlier column (a jump host loop the core refuses anyway) bows out to the right.
  const bend = Math.max(o.gapX / 2, Math.abs(x2 - x1) / 2);
  const r = (n: number) => Math.round(n * 10) / 10;
  return `M ${r(x1)} ${r(y1)} C ${r(x1 + bend)} ${r(y1)}, ${r(x2 - bend)} ${r(y2)}, ${r(x2)} ${r(y2)}`;
}

export function layoutTopology(
  nodes: readonly TopoNode[],
  edges: readonly TopoEdge[],
  options: Partial<LayoutOptions> = {},
): TopologyLayout {
  const o = { ...DEFAULT_LAYOUT, ...options };
  const columns = orderColumns(nodes, edges, o.sweeps);
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const placed = new Map<string, PlacedNode>();
  const rowStep = o.nodeHeight + o.gapY;
  const before = new Map<string, string[]>(nodes.map((n) => [n.id, []]));
  const column = columnsOf(nodes);
  for (const e of edges) {
    const cf = column.get(e.from) ?? 0;
    const ct = column.get(e.to) ?? 0;
    if (cf < ct) before.get(e.to)?.push(e.from);
    else if (ct < cf) before.get(e.from)?.push(e.to);
  }
  const after = new Map<string, string[]>(nodes.map((n) => [n.id, []]));
  for (const [id, earlier] of before) for (const p of earlier) after.get(p)?.push(id);
  const yOf = (ids: string[]) =>
    mean(
      ids.flatMap((p) => {
        const at = placed.get(p);
        return at ? [at.y] : [];
      }),
    );
  // Left to right: level with the neighbours before, a row below the node above at least.
  columns.forEach((ids, c) => {
    let last = -Infinity;
    ids.forEach((id, row) => {
      const node = byId.get(id);
      if (!node) return;
      const level = yOf(before.get(id) ?? []);
      const y = Math.max(level ?? (c === 0 ? row * rowStep : last + rowStep), last + rowStep, 0);
      last = y;
      placed.set(id, { node, x: c * (o.nodeWidth + o.gapX), y, column: c, row });
    });
  });
  // Right to left: a node with nothing before it (this PC, a jump host) moves level with what follows it.
  for (let c = columns.length - 1; c >= 0; c--) {
    let last = -Infinity;
    for (const id of columns[c]) {
      const at = placed.get(id);
      if (!at) continue;
      const roots = (before.get(id) ?? []).length === 0;
      const level = roots ? yOf(after.get(id) ?? []) : null;
      at.y = Math.max(level ?? at.y, last + rowStep, 0);
      last = at.y;
    }
  }
  const list = [...placed.values()];
  const placedEdges = edges.flatMap((edge) => {
    const from = placed.get(edge.from);
    const to = placed.get(edge.to);
    return from && to ? [{ edge, path: edgePath(from, to, o) }] : [];
  });
  const width = list.length === 0 ? 0 : Math.max(...list.map((p) => p.x)) + o.nodeWidth;
  const height = list.length === 0 ? 0 : Math.max(...list.map((p) => p.y)) + o.nodeHeight;
  return { nodes: list, edges: placedEdges, width, height };
}
