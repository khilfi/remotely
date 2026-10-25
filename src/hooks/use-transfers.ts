// SS-08, P6: the transfers store (src/lib/transfers-store.ts) read by the components that show transfers, so a
// transfer's progress re-renders them and not the Terminal page around them.

import { useCallback, useSyncExternalStore } from "react";
import { transferStore, uploadsDone, type TransferSnapshot } from "@/lib/transfers-store";

/** Every transfer, and the ones the transfers panel lists. */
export function useTransfers(): TransferSnapshot {
  return useSyncExternalStore(transferStore.subscribe, transferStore.getSnapshot);
}

/** Uploads finished through this terminal: a number, so progress elsewhere renders nothing. */
export function useUploadsDone(terminalId: string | null): number {
  const read = useCallback(() => uploadsDone(transferStore.getSnapshot().all, terminalId), [terminalId]);
  return useSyncExternalStore(transferStore.subscribe, read);
}
