// FD-08: the handover pack. The dates (from the Activity page's filter when opened there), who prepared it, and what
// to add: the outputs of what ran, a fresh read of the hosts, their installed packages. The count line says what the
// dates hold. Save opens the shell's save dialog; the core writes the zip (one page, the workbook, a CSV per table)
// and audits it.

import { useEffect, useState } from "react";
import { FolderOpenIcon, PackageCheckIcon } from "lucide-react";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { HelpTip } from "@/components/HelpTip";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage } from "@/lib/api";
import {
  reportsApi,
  type HandoverExport,
  type HandoverPreview,
  type HandoverRequest,
  type ReportsOverview,
} from "@/lib/reports-api";
import {
  dayRange,
  handoverCountText,
  handoverReason,
  handoverSavedText,
  MAX_PREPARED_BY,
  readText,
  utcOffsetMinutes,
} from "@/lib/reports";

interface Props {
  /** The first and last day, `YYYY-MM-DD`. */
  from: string;
  to: string;
  onClose: () => void;
}

export function HandoverPackDialog({ from: initialFrom, to: initialTo, onClose }: Props) {
  const [overview, setOverview] = useState<ReportsOverview | null>(null);
  const [from, setFrom] = useState(initialFrom);
  const [to, setTo] = useState(initialTo);
  const [preparedBy, setPreparedBy] = useState<string | null>(null);
  const [outputs, setOutputs] = useState(false);
  const [readAgain, setReadAgain] = useState(false);
  const [packages, setPackages] = useState(false);
  const [preview, setPreview] = useState<{ key: string; preview: HandoverPreview } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<HandoverExport | null>(null);

  useEffect(() => {
    let stale = false;
    reportsApi.overview().then(
      (o) => {
        if (stale) return;
        setOverview(o);
        setPreparedBy((p) => p ?? o.preparedBy ?? "");
      },
      (err) => !stale && setError(errorMessage(err)),
    );
    return () => {
      stale = true;
    };
  }, []);

  const range = dayRange(from, to);
  const request: HandoverRequest | null =
    "problem" in range
      ? null
      : {
          fromMs: range.fromMs,
          toMs: range.toMs,
          utcOffsetMinutes: utcOffsetMinutes(),
          preparedBy: (preparedBy ?? "").trim(),
          includeOutputs: outputs,
          inventory: { readAgain, updates: false, packages: readAgain && packages },
        };
  const rangeKey = "problem" in range ? null : `${range.fromMs}-${range.toMs}`;
  const shown = preview && preview.key === rangeKey ? preview.preview : null;

  // What the dates hold.
  useEffect(() => {
    if (!rangeKey) return;
    const [fromMs, toMs] = rangeKey.split("-").map(Number);
    let stale = false;
    const timer = window.setTimeout(() => {
      reportsApi
        .handoverPreview({
          fromMs,
          toMs,
          utcOffsetMinutes: utcOffsetMinutes(),
          preparedBy: "",
          includeOutputs: false,
          inventory: { readAgain: false, updates: false, packages: false },
        })
        .then(
          (p) => !stale && setPreview({ key: rangeKey, preview: p }),
          (err) => !stale && setError(errorMessage(err)),
        );
    }, 250);
    return () => {
      stale = true;
      window.clearTimeout(timer);
    };
  }, [rangeKey]);

  async function save() {
    if (!request) return;
    setBusy(true);
    setError(null);
    try {
      const report = await reportsApi.exportHandover(request);
      if (report) {
        setDone(report);
        toast.success(handoverSavedText(report));
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
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

  const reason = handoverReason({ range, preparedBy: preparedBy ?? "", busy });

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <PackageCheckIcon className="size-4" aria-hidden />
            Make a handover pack
            <HelpTip topic="reports.handover" />
          </DialogTitle>
          <DialogDescription>
            {overview ? (
              <>
                One printable page and the inventory of <span data-mask="workspace">{overview.workspace}</span>, in a
                zip.
              </>
            ) : (
              "One printable page and the inventory of this workspace, in a zip."
            )}
          </DialogDescription>
        </DialogHeader>

        {done ? (
          <div className="grid gap-2 text-sm">
            <p>{handoverSavedText(done)}</p>
            {readText(done.read) && <p className="text-muted-foreground">{readText(done.read)}</p>}
            {(done.read?.problems.length ?? 0) > 0 && (
              <ul className="max-h-40 list-disc overflow-y-auto pl-5 text-xs break-words text-muted-foreground">
                {done.read?.problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            )}
            <p className="text-xs text-muted-foreground">Read it through before you share it.</p>
          </div>
        ) : (
          <div className="grid gap-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="handover-from">First day</Label>
                <Input
                  id="handover-from"
                  type="date"
                  value={from}
                  onChange={(e) => setFrom(e.currentTarget.value)}
                  aria-invalid={"problem" in range || undefined}
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="handover-to">Last day</Label>
                <Input
                  id="handover-to"
                  type="date"
                  value={to}
                  onChange={(e) => setTo(e.currentTarget.value)}
                  aria-invalid={"problem" in range || undefined}
                />
              </div>
            </div>
            <p className="text-sm text-muted-foreground" aria-live="polite">
              {"problem" in range
                ? range.problem
                : shown
                  ? `${handoverCountText(shown.jobs, shown.otherChanges, shown.notes)} go in.`
                  : "Counting…"}
            </p>
            <div className="grid gap-1.5">
              <Label htmlFor="handover-by">Prepared by</Label>
              <Input
                id="handover-by"
                data-mask="user"
                maxLength={MAX_PREPARED_BY}
                value={preparedBy ?? ""}
                onChange={(e) => setPreparedBy(e.currentTarget.value)}
              />
            </div>
            <div className="grid gap-2">
              <div className="flex items-center gap-3">
                <Checkbox id="handover-outputs" checked={outputs} onCheckedChange={(v) => setOutputs(v === true)} />
                <Label htmlFor="handover-outputs" className="font-normal">
                  Add the outputs of what ran
                </Label>
              </div>
              <div className="flex items-center gap-3">
                <Checkbox
                  id="handover-read-again"
                  checked={readAgain}
                  disabled={overview?.sshSessions === 0}
                  onCheckedChange={(v) => setReadAgain(v === true)}
                />
                <Label htmlFor="handover-read-again" className="font-normal">
                  Read reachable hosts again first
                  <HelpTip topic="reports.readAgain" />
                </Label>
              </div>
              <div className="flex items-center gap-3 pl-7">
                <Checkbox
                  id="handover-packages"
                  checked={readAgain && packages}
                  disabled={!readAgain}
                  onCheckedChange={(v) => setPackages(v === true)}
                />
                <Label htmlFor="handover-packages" className="font-normal">
                  Add each host&apos;s installed packages
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
              <Button variant="outline" onClick={onClose} disabled={busy}>
                Cancel
              </Button>
              <WhyDisabled reason={reason}>
                <Button onClick={() => void save()} disabled={reason !== null}>
                  {busy ? "Making the pack…" : "Save…"}
                </Button>
              </WhyDisabled>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
