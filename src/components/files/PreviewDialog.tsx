// SS-14 (0.8.0 G3): a host file's first 256 KB as text: never rendered (React writes it as text), control characters
// shown as their pictures and invisible formatting characters as ⟨U+XXXX⟩ by the core, a binary file not shown.

import { DownloadIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { plural } from "@/lib/format";
import type { FilePreview } from "@/lib/files-page-api";
import { formatSize } from "@/lib/transfers";

export interface PreviewShown {
  name: string;
  preview: FilePreview | null;
  error?: string;
}

export function PreviewDialog({
  shown,
  onDownload,
  onClose,
}: {
  shown: PreviewShown;
  onDownload: () => void;
  onClose: () => void;
}) {
  const p = shown.preview;
  const notes: string[] = [];
  if (p?.truncated) notes.push(`only the first 256 KB of ${formatSize(p.size)} is shown`);
  if (p?.notUtf8) notes.push("it isn't UTF-8, so some characters may show wrong");
  if (p && p.marked > 0) notes.push(`${plural(p.marked, "control or invisible character")} shown as a symbol`);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="flex max-h-[85vh] flex-col sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="truncate">{shown.name}</DialogTitle>
          <DialogDescription>
            {shown.error
              ? "The file couldn't be read."
              : !p
                ? "Reading the file…"
                : p.text === null
                  ? "A binary file: there is no text to show."
                  : notes.length > 0
                    ? `${notes.join("; ")}.`.replace(/^./, (c) => c.toUpperCase())
                    : `${formatSize(p.size)}.`}
          </DialogDescription>
        </DialogHeader>
        {shown.error && <p className="text-sm text-destructive">{shown.error}</p>}
        {p?.text != null && (
          <pre className="min-h-0 flex-1 overflow-auto rounded-md border bg-muted/40 p-2 font-mono text-xs whitespace-pre">
            {p.text}
          </pre>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onDownload}>
            <DownloadIcon data-icon="inline-start" />
            Download
          </Button>
          <Button onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
