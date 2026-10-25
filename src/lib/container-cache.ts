// QL-20: the containers the Containers page read last, host by host, so the palette can find them without a read of
// its own: listing containers logs in to the host (CT-01), and search makes no logins. In memory only; a host's list
// is replaced each time the page reads it, and goes when the host is no longer marked. Tested in search.test.ts.

import type { ContainerHost, ContainerSummary, EngineKind } from "./api.ts";

export interface CachedContainers {
  host: ContainerHost;
  engine: EngineKind;
  /** The session's name, or "This PC". */
  hostName: string;
  containers: ContainerSummary[];
  /** When the page read it (RFC 3339). */
  readAt: string;
}

let lists = new Map<string, CachedContainers>();

export function hostKey(host: ContainerHost, engine: EngineKind): string {
  return `${host.kind === "session" ? host.sessionId : "thisPc"}:${engine}`;
}

/** The Containers page read a host's list. */
export function rememberContainers(entry: CachedContainers) {
  lists = new Map(lists).set(hostKey(entry.host, entry.engine), entry);
}

/** The hosts the page lists now: the rest are forgotten. */
export function keepContainerHosts(hosts: { host: ContainerHost; engines: { engine: EngineKind }[] }[]) {
  const keep = new Set(hosts.flatMap((h) => h.engines.map((e) => hostKey(h.host, e.engine))));
  lists = new Map([...lists].filter(([key]) => keep.has(key)));
}

export function cachedContainers(): CachedContainers[] {
  return [...lists.values()];
}

/** Tests only. */
export function resetContainerCache() {
  lists = new Map();
}
