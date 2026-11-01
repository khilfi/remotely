// FD-05: the inventory to Excel. One workbook of the shown workspace (VMs, hosts, networks, health checks, and on
// request each host's installed packages), from what Remotely has read before or, with "Read reachable hosts again
// first", read now (the button counts the hosts done; Cancel or closing the dialog stops the reads and writes nothing).
// Export opens the shell's save dialog; the core writes the file and audits it.

import { useEffect, useState } from "react";
import { FileSpreadsheetIcon, FolderOpenIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { HelpTip } from "@/components/HelpTip";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useExportRun } from "@/hooks/use-export-run";
import { errorMessage } from "@/lib/api";
import { plural } from "@/lib/format";
import { reportsApi, type InventoryExport, type ReportsOverview } from "@/lib/reports-api";
import { busyText, inventorySavedText, readText, utcOffsetMinutes } from "@/lib/reports";

interface Props {
  onClose: () => void;
}

export function InventoryExportDialog({ onClose }: Props) {
  const [overview, setOverview] = useState<ReportsOverview | null>(null);
  const [readAgain, setReadAgain] = useState(false);
  const [updates, setUpdates] = useState(false);
  const [packages, setPackages] = useState(false);
  const exporting = useExportRun();
  const busy = exporting.busy;
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<InventoryExport | null>(null);

  useEffect(() => {
    let stale = false;
    reportsApi.overview().then(
      (o) => {
        if (stale) return;
        setOverview(o);
        setError(null);
      },
      (err) => !stale && setError(errorMessage(err)),
    );
    return () => {
      stale = true;
    };
  }, []);

  async function save() {
    setError(null);
    try {
      const report = await exporting.run((run) =>
        reportsApi.exportInventory(
          run,
          { readAgain, updates: readAgain && updates, packages: readAgain && packages },
          utcOffsetMinutes(),
        ),
      );
      // Also after a late Cancel: the file was written by then, so it says so.
      if (report) {
        setDone(report);
        toast.success(inventorySavedText(report));
      }
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function showFile() {
    if (!done) return;
    try {
      await reportsApi.showFile(done.savedId);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  const noHosts = overview !== null && overview.sshSessions + overview.winrmSessions === 0;
  // Windows hosts are read again for their facts only: updates and packages are Linux reads.
  const linuxOnly = (overview?.winrmSessions ?? 0) > 0;
  const reason = busy ? busyText({ reading: readAgain, progress: exporting.progress, saving: "Saving…" }) : null;
  const problems = [...(done?.read?.problems ?? []), ...(done?.notes ?? [])];

  return (
    // Closing while the hosts are read stops them (useExportRun); nothing is written.
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileSpreadsheetIcon className="size-4" aria-hidden />
            Export the inventory to Excel
            <HelpTip topic="reports.inventory" />
          </DialogTitle>
          <DialogDescription>
            {overview ? (
              <>
                {plural(overview.vms, "VM")}, {plural(overview.sessions, "session")} and{" "}
                {plural(overview.checks, "health check")} of <span data-mask="workspace">{overview.workspace}</span>.
              </>
            ) : (
              "VMs, hosts, networks and health checks of this workspace."
            )}
          </DialogDescription>
        </DialogHeader>

        {done ? (
          <div className="grid gap-2 text-sm">
            <p>{inventorySavedText(done)}</p>
            {readText(done.read) && <p className="text-muted-foreground">{readText(done.read)}</p>}
            {problems.length > 0 && (
              <ul className="max-h-40 list-disc overflow-y-auto pl-5 text-xs break-words text-muted-foreground">
                {problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            )}
          </div>
        ) : (
          <div className="grid gap-3">
            <div className="flex items-start gap-3">
              <Checkbox
                id="inventory-read-again"
                className="mt-0.5"
                checked={readAgain}
                disabled={noHosts}
                onCheckedChange={(v) => setReadAgain(v === true)}
              />
              <div className="grid min-w-0 gap-0.5">
                <Label htmlFor="inventory-read-again" className="font-normal">
                  Read reachable hosts again first
                  <HelpTip topic="reports.readAgain" />
                </Label>
                <p className="text-xs break-words text-muted-foreground">
                  {noHosts
                    ? "No SSH or WinRM sessions to read."
                    : "With each session's saved login, a few hosts at a time."}
                </p>
              </div>
            </div>
            <div className="grid gap-2 pl-7">
              <div className="flex items-center gap-3">
                <Checkbox
                  id="inventory-updates"
                  checked={readAgain && updates}
                  disabled={!readAgain}
                  onCheckedChange={(v) => setUpdates(v === true)}
                />
                <Label htmlFor="inventory-updates" className="font-normal">
                  Add pending updates
                  {linuxOnly && <span className="text-muted-foreground">(Linux hosts)</span>}
                </Label>
              </div>
              <div className="flex items-center gap-3">
                <Checkbox
                  id="inventory-packages"
                  checked={readAgain && packages}
                  disabled={!readAgain}
                  onCheckedChange={(v) => setPackages(v === true)}
                />
                <Label htmlFor="inventory-packages" className="font-normal">
                  Add each host&apos;s installed packages
                  {linuxOnly && <span className="text-muted-foreground">(Linux hosts)</span>}
                </Label>
              </div>
            </div>
          </div>
        )}

        {error && (
          <p className="text-sm break-words text-destructive" role="alert">
            {error}
          </p>
        )}
        <DialogFooter>
          {done ? (
            <>
              <Button variant="outline" onClick={() => void showFile()}>
                <FolderOpenIcon data-icon="inline-start" />
                Show in folder
              </Button>
              <Button onClick={onClose}>Close</Button>
            </>
          ) : (
            <>
              <Button variant="outline" onClick={onClose}>
                Cancel
              </Button>
              <WhyDisabled reason={reason}>
                <Button onClick={() => void save()} disabled={reason !== null}>
                  {busy ? reason : "Export…"}
                </Button>
              </WhyDisabled>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
