// QL-27: the toast after a delete, with an Undo that puts the item back from the trash (the newest trash entry of that
// item). A restored session that would send a vault password somewhere new asks for it first.

import { toast } from "sonner";
import { errorMessage } from "@/lib/api";
import { comfortApi, type TrashKind } from "@/lib/comfort-api";
import { isReauthCancelled } from "@/lib/reauth";
import { withVaultPassword } from "@/lib/reauth-prompt";
import { deletedMessage, restoredMessage } from "@/lib/trash";

/** Shows "Deleted 'x'" with Undo; `onRestored` runs after a restore (to read the list again). */
export function toastDeleted(kind: TrashKind, itemId: string, name: string, onRestored?: () => void) {
  const message = deletedMessage(name);
  toast.success(message.title, {
    description: message.description,
    action: {
      label: "Undo",
      onClick: () => {
        withVaultPassword((password) => comfortApi.undoDelete(kind, itemId, password)).then(
          (report) => {
            const restored = restoredMessage(report);
            toast.success(restored.title, restored.description ? { description: restored.description } : undefined);
            onRestored?.();
          },
          (err: unknown) => {
            if (!isReauthCancelled(err)) toast.error(errorMessage(err));
          },
        );
      },
    },
  });
}
