// VM-29, VM-32: the Deploy dialog's values per VM for an install config: which placeholders a VM's row fills, rows
// pasted from CSV, the address pools that fit the deploy's network, and the request's rows. Pure, so it is tested
// without a window.

import type { Hypervisor, TemplateNetwork, VmInstall } from "@/lib/api";
import type { AddressPool } from "@/lib/address-pools-api";
import type { InstallConfig } from "@/lib/install-configs-api";

/** The most rows a deploy takes (the core's MAX_DEPLOY_COUNT). */
export const MAX_ROWS = 50;
/** How long the install watcher waits by default, and at most (the core's). */
export const DEFAULT_INSTALL_MINUTES = 60;
export const MAX_INSTALL_MINUTES = 240;

/** Whether the file uses `{{name}}` (not escaped as `\{{`). */
export function usesPlaceholder(body: string, name: string): boolean {
  const pattern = new RegExp(`(^|[^\\\\])\\{\\{\\s*${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*\\}\\}`);
  return pattern.test(body);
}

/** The config's own variables a row may set, in its order, with their defaults. */
export function rowVariables(config: InstallConfig): { name: string; fallback: string | null }[] {
  return config.variables.map((v) => ({ name: v.name, fallback: v.default ?? null }));
}

/** The kinds Remotely delivers to an ISO install (S1 to S3); the rest say why not. */
export function deliveryProblem(config: InstallConfig): string | null {
  switch (config.kind) {
    case "autoinstall":
    case "preseed":
    case "unattend":
      return null;
    case "kickstart":
      return "Kickstart installs aren't delivered yet: only Ubuntu, Debian and Windows Server were tried by hand.";
    case "cloudInit":
      return "cloud-init user data is for cloud images, not ISO installs.";
  }
}

/** The pools that fit the deploy: its hypervisor and its network, as the template names it. */
export function poolsFor(
  pools: AddressPool[],
  hypervisor: Hypervisor | undefined,
  network: TemplateNetwork | undefined,
): AddressPool[] {
  if (!hypervisor || !network) return [];
  const key = JSON.stringify(network);
  return pools.filter((p) => p.hypervisor === hypervisor && JSON.stringify(p.network) === key);
}

/** One CSV line's cells: commas split, double quotes quote (`""` is a quote). */
export function csvCells(line: string): string[] {
  const out: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') {
        quoted = false;
      } else {
        cell += c;
      }
    } else if (c === '"') {
      quoted = true;
    } else if (c === "," || c === ";" || c === "\t") {
      out.push(cell.trim());
      cell = "";
    } else {
      cell += c;
    }
  }
  out.push(cell.trim());
  return out;
}

export interface ParsedRows {
  rows: VmInstall[];
  error: string | null;
}

/**
 * Rows pasted from a spreadsheet: a header line naming the columns (`ip` and the config's own variables; a `name` or
 * `hostname` column is read past, since the pattern names the VMs), then a line per VM in the order they're named.
 */
export function parseRows(text: string, variables: string[]): ParsedRows {
  const lines = text
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .filter((l) => l.trim() !== "");
  if (lines.length === 0) return { rows: [], error: "Paste a header line, then a line per VM." };
  const header = csvCells(lines[0]).map((h) => h.toLowerCase());
  for (const column of header) {
    if (column !== "ip" && column !== "name" && column !== "hostname" && !variables.includes(column)) {
      return {
        rows: [],
        error: `The column "${column}" isn't ip or one of the config's variables (${variables.join(", ") || "it has none"}).`,
      };
    }
  }
  if (lines.length - 1 > MAX_ROWS) return { rows: [], error: `A deploy makes at most ${MAX_ROWS} VMs.` };
  const rows = lines.slice(1).map((line) => {
    const cells = csvCells(line);
    const row: VmInstall = { ip: null, values: {} };
    header.forEach((column, i) => {
      const value = (cells[i] ?? "").trim();
      if (!value || column === "name" || column === "hostname") return;
      if (column === "ip") row.ip = value;
      else row.values[column] = value;
    });
    return row;
  });
  return { rows, error: null };
}

/** The request's rows: one per VM, empty values left out (they take the config's defaults). */
export function requestRows(rows: VmInstall[], count: number, pooled: boolean): VmInstall[] {
  return Array.from({ length: count }, (_, i) => {
    const row = rows[i] ?? { ip: null, values: {} };
    const values: Record<string, string> = {};
    for (const [name, value] of Object.entries(row.values)) {
      if (value.trim()) values[name] = value.trim();
    }
    return { ip: pooled ? null : row.ip?.trim() || null, values };
  });
}

/** The time limit as typed: whole minutes, 1 to the most; null when it isn't one. */
export function parseMinutes(text: string): number | null {
  if (!/^\d{1,3}$/.test(text.trim())) return null;
  const n = Number(text.trim());
  return n >= 1 && n <= MAX_INSTALL_MINUTES ? n : null;
}
