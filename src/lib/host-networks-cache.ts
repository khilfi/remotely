// QL-20, VM-11: the host networks the topology map or the host networks view read last, so the palette finds them
// without a read of its own (listing them runs vmrun and VBoxManage, which search never does). In memory only; each
// read replaces the list. Tested in search.test.ts.

import type { HostNetwork } from "./topology.ts";

let networks: readonly HostNetwork[] = [];

/** The map or the host networks view read the networks (vm-insight.ts `topologyHostNetworks`). */
export function rememberHostNetworks(list: readonly HostNetwork[]) {
  networks = list;
}

export function cachedHostNetworks(): readonly HostNetwork[] {
  return networks;
}
