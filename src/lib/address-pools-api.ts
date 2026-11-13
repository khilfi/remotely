// VM-32 address pools: the types the core sends and the IPC wrappers. Edits are the app's own data (audited, no approval
// tier, refused by the read-only lock); a deploy's claims on a pool never come from the window. The address fields are
// named so the presentation masker learns them (`ip`, `firstIp`, `lastIp`, `gateway`, `dnsServers`).

import { invoke, type Hypervisor, type TemplateNetwork } from "@/lib/api";

export type LeaseState = "claimed" | "assigned";

/** What the editor sends; addresses as typed. */
export interface AddressPoolInput {
  name: string;
  hypervisor: Hypervisor;
  network: TemplateNetwork;
  firstIp: string;
  lastIp: string;
  prefix: number;
  gateway: string | null;
  dnsServers: string[];
  notes: string | null;
}

export interface AddressPool extends AddressPoolInput {
  id: string;
  /** Addresses in the range. */
  size: number;
  /** Addresses it can hand out: the range without the gateway and DNS servers. */
  usable: number;
  /** Assigned to a VM, or claimed by a deploy now. */
  used: number;
  free: number;
  createdAt: string;
  updatedAt: string;
}

/** A taken address of a pool. */
export interface AddressLease {
  poolId: string;
  ip: string;
  /** The VM's key once it was made. */
  vmKey: string | null;
  vmName: string;
  jobId: string | null;
  state: LeaseState;
  createdAt: string;
  /** Its VM is gone from the VMs page, or its deploy isn't running: it can be freed by hand. */
  canFree: boolean;
}

export const addressPoolsApi = {
  list: () => invoke<AddressPool[]>("address_pools_list"),
  leases: (id: string) => invoke<AddressLease[]>("address_pool_leases", { id }),
  add: (input: AddressPoolInput) => invoke<AddressPool>("address_pool_add", { input }),
  update: (id: string, input: AddressPoolInput) => invoke<AddressPool>("address_pool_update", { id, input }),
  remove: (id: string) => invoke<void>("address_pool_delete", { id }),
  free: (id: string, ip: string) => invoke<void>("address_pool_free", { id, ip }),
};
