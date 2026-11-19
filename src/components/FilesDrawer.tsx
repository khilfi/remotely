// SS-08, UX-14 (0.9.0 H1): the Terminal page's "Files here" drawer. It is the Files page's host pane in compact mode
// (files/HostPane.tsx) on the current terminal: the same row menu, double-click, editing, find, preview, checksums,
// bookmarks and root browsing, following the shell's folder, with "Transfers as alice" and Expand (the Files page at the
// same folder). Below it, the files edited on this PC (EditingSessionsList) and the transfers. SFTP runs on the
// terminal's own connection; every upload and change goes through the approval flow. A drop from Explorer on it
// uploads into the folder it shows (lib/drop-target.ts); one on a terminal still goes into that terminal's folder.

import { EditingSessionsList } from "@/components/EditingSessionsList";
import { TransfersList } from "@/components/TransfersList";
import { HostPane } from "@/components/files/HostPane";
import type { FileDoubleClick, SubmitOutcome, TransferInfo } from "@/lib/api";
import type { DropHost } from "@/lib/drop-target";

/** The drawer's `data-files-tab`, for drops. */
export const DRAWER_KEY = "drawer";

interface Props {
  /** The current pane's core id, once it opened. */
  terminalId: string | null;
  /** SS-10: terminals Type in all tabs types into; uploads still go to this one only. */
  multiExecTerminals: number;
  /** SS-14: `asRoot` through root browsing; `folder`: pick a folder to upload with what is in it. */
  onUpload: (folder: string, asRoot: boolean, pick: "files" | "folder") => void;
  onDownload: (paths: string[], to: "downloads" | "choose", asRoot: boolean) => void;
  onRetry: (transfer: TransferInfo) => void;
  onSubmitted: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  /** SS-14 (G4): an editor job is queued: the page opens its tab. */
  onEditorJob: (jobId: string, title: string) => void;
  doubleClick: FileDoubleClick;
  /** UX-14: the folder the drawer shows, for drops on it (null while none is open). */
  onPlace: (place: DropHost | null) => void;
}

export function FilesDrawer({
  terminalId,
  multiExecTerminals,
  onUpload,
  onDownload,
  onRetry,
  onSubmitted,
  onEditorJob,
  doubleClick,
  onPlace,
}: Props) {
  return (
    <div className="flex h-full min-h-0 flex-col gap-2 rounded-lg border p-2">
      {terminalId ? (
        // A pane of its own per terminal, so a folder opened by hand doesn't carry over to another terminal.
        <HostPane
          key={terminalId}
          compact
          tab={{ key: DRAWER_KEY, terminalId }}
          local={null}
          doubleClick={doubleClick}
          multiExecTerminals={multiExecTerminals}
          onDownload={(paths, to, asRoot) => onDownload(paths, to === "default" ? "downloads" : "choose", asRoot)}
          onUpload={onUpload}
          onSubmitted={onSubmitted}
          onEditorJob={onEditorJob}
          onFolder={(key, folder, asRoot) => onPlace({ key, terminalId, folder, asRoot })}
        />
      ) : (
        <section className="flex min-h-0 flex-1 flex-col gap-2">
          <h2 className="text-sm font-medium">Files here</h2>
          <p className="text-sm text-muted-foreground">Open a terminal: its files show here.</p>
        </section>
      )}
      <div className="flex max-h-[35%] min-h-0 shrink-0 flex-col gap-2 overflow-hidden">
        <EditingSessionsList />
        <TransfersList onRetry={onRetry} />
      </div>
    </div>
  );
}
