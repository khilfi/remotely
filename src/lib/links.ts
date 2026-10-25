// R10: where things in the app lead. QL-20's search results, QL-21's map nodes, QL-22's status bar items and QL-25's
// notifications each carry an AppLink, and App.tsx's `openLink` is the one place that opens one. A later package adds
// a kind here and a case there (deploy, schedules, stacks). Links the core keeps for the notification centre come back
// as plain JSON, so `isAppLink` checks them before they are opened. Tested in links.test.ts.

import type { ContainerHost, EngineKind } from "./api.ts";
import type { VmView } from "./vm-snapshots.ts";

/** The tabs of the Templates page (VM-19 to VM-21). */
export type CatalogTab = "sizes" | "images" | "templates";

export type AppLink =
  /** A page by its id (App.tsx's PAGES), or one that moved into another (lib/navigation.ts). */
  | { kind: "page"; page: string }
  /** QL-14: a VM on the Virtual machines page, on one of its tabs. */
  | { kind: "vm"; vmxPath: string; view?: VmView }
  /** A saved session, shown on the Sessions page. */
  | { kind: "session"; sessionId: string }
  /** An open terminal's tab (SS-07: with its tunnels panel). */
  | { kind: "terminal"; terminalId: string; tunnels?: boolean }
  /** A job's results in Activity. */
  | { kind: "job"; jobId: string }
  /** CT-01: a container's details on the Containers page. */
  | { kind: "container"; host: ContainerHost; engine: EngineKind; containerId: string }
  /** VM-19 to VM-21: a size, image or launch template on the Templates page. */
  | { kind: "catalog"; tab: CatalogTab; id?: string }
  /** A card of the Settings page (settings-index.ts). */
  | { kind: "setting"; section: string }
  /** BX-08: a command in the Terminal page's command panel. */
  | { kind: "snippet"; command: string }
  /** MO-07: the dashboard's alert list. */
  | { kind: "alerts" }
  /** FD-14: the update banner, or Settings' Updates card when nothing is offered. */
  | { kind: "update" }
  /** SS-04: the Vault page. */
  | { kind: "vault" }
  /** QL-21: the topology map. */
  | { kind: "map" };

export type AppLinkKind = AppLink["kind"];

const KINDS: Record<AppLinkKind, readonly string[]> = {
  page: ["page"],
  vm: ["vmxPath"],
  session: ["sessionId"],
  terminal: ["terminalId"],
  job: ["jobId"],
  container: ["engine", "containerId"],
  catalog: ["tab"],
  setting: ["section"],
  snippet: ["command"],
  alerts: [],
  update: [],
  vault: [],
  map: [],
};

/** A value (from the core, say) is a link this version can open: a known kind with its text fields. */
export function isAppLink(value: unknown): value is AppLink {
  if (typeof value !== "object" || value === null) return false;
  const link = value as Record<string, unknown>;
  const kind = link.kind;
  if (typeof kind !== "string" || !Object.prototype.hasOwnProperty.call(KINDS, kind)) return false;
  if (!KINDS[kind as AppLinkKind].every((field) => typeof link[field] === "string" && link[field] !== "")) return false;
  if (kind === "container") {
    const host = link.host as Record<string, unknown> | undefined;
    if (!host || (host.kind !== "thisPc" && !(host.kind === "session" && typeof host.sessionId === "string")))
      return false;
  }
  if (kind === "catalog" && !["sizes", "images", "templates"].includes(link.tab as string)) return false;
  return true;
}

/** What a button that opens the link says. */
export function linkLabel(link: AppLink): string {
  switch (link.kind) {
    case "page":
      return "Open the page";
    case "vm":
      return link.view === "snapshots"
        ? "Show its snapshots"
        : link.view === "settings"
          ? "Open its settings"
          : "Show the VM";
    case "session":
      return "Show the session";
    case "terminal":
      return link.tunnels ? "Show its tunnels" : "Go to the terminal";
    case "job":
      return "Show the job";
    case "container":
      return "Show the container";
    case "catalog":
      return link.tab === "sizes" ? "Show the size" : link.tab === "images" ? "Show the image" : "Show the template";
    case "setting":
      return "Open the setting";
    case "snippet":
      return "Show the command";
    case "alerts":
      return "Show the alerts";
    case "update":
      return "Show the update";
    case "vault":
      return "Open the vault";
    case "map":
      return "Open the map";
  }
}
