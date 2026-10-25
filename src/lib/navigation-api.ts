// R10's IPC wrappers (src-tauri/src/navigation.rs): QL-25 the notification centre's history and QL-21 the map's read of
// each VM's networks. Kept apart from api.ts, as dashboard-api.ts is, so packages working at once touch fewer shared
// lines.

import { invoke, type Hypervisor, type VirtualNic } from "@/lib/api";
import type { AppNotification, NotificationInput, NotificationList } from "@/lib/notifications";

/** QL-21: one VM's network adapters (crates/core/src/host_details/networks.rs). */
export interface VmNetworks {
  vmId: string;
  vmxPath: string;
  hypervisor: Hypervisor;
  nics: VirtualNic[];
  /** VM-11: the guest's addresses the hypervisor reported with them. */
  guestIps: string[];
  collectedAt: string | null;
  /** What was read before (the files could not be read now, or nothing asked for a fresh read). */
  stored: boolean;
  problem: string | null;
}

export const navigationApi = {
  notifications: () => invoke<NotificationList>("notifications_list"),
  /** The core redacts the text before keeping it. */
  addNotification: (input: NotificationInput) => invoke<AppNotification>("notifications_add", { input }),
  /** All of them when `ids` is null. */
  markNotificationsRead: (ids: number[] | null) => invoke<NotificationList>("notifications_mark_read", { ids }),
  clearNotifications: (ids: number[] | null) => invoke<NotificationList>("notifications_clear", { ids }),
  /** QL-21: what was read before, and a read of VMs never read; `fresh` reads every VM again. */
  vmNetworks: (fresh: boolean) => invoke<VmNetworks[]>("topology_vm_networks", { fresh }),
  /** QL-23: a folder dialog for a folder that holds VMs (adding it is `setScanFolders`, as in Settings). */
  vmFolderPick: () => invoke<string | null>("vm_folder_pick"),
};
