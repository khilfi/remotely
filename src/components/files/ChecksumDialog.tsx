// SS-14 (0.8.0 G3): a file's SHA-256, from either pane of the Files page, with Copy.

import { CopyIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { formatSize } from "@/lib/transfers";

export interface ChecksumShown {
  name: string;
  /** null while it is worked out. */
  sha256: string | null;
  size?: number;
  /** Where it was worked out, in words. */
  by?: string;
  error?: string;
}

export function ChecksumDialog({ shown, onClose }: { shown: ChecksumShown; onClose: () => void }) {
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>SHA-256 of {shown.name}</DialogTitle>
          <DialogDescription>
            {shown.error
              ? "The checksum couldn't be worked out."
              : shown.sha256
                ? `${shown.size !== undefined ? `${formatSize(shown.size)}, ` : ""}${shown.by ?? ""}`
                : "Reading the file…"}
          </DialogDescription>
        </DialogHeader>
        {shown.error ? (
          <p className="text-sm text-destructive">{shown.error}</p>
        ) : (
          <code className="rounded-md bg-muted px-2 py-1.5 font-mono text-xs break-all">{shown.sha256 ?? "…"}</code>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          <Button
            disabled={!shown.sha256}
            onClick={() => {
              if (!shown.sha256) return;
              void navigator.clipboard?.writeText(shown.sha256).then(
                () => toast.success("Copied the SHA-256"),
                () => toast.error("The clipboard couldn't be written"),
              );
            }}
          >
            <CopyIcon data-icon="inline-start" />
            Copy
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
