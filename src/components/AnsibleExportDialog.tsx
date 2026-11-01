// BX-12: an Ansible inventory. Hosts are picked like Compare hosts' (saved SSH and WinRM sessions; a VM through its linked
// session; tags and saved filters); none picked is every SSH and WinRM session of the workspace. The file is YAML or INI,
// grouped by folder, tag, environment and workspace, and the preview shows it exactly as it will be written. Save
// opens the shell's save dialog; the core writes the file and audits it. No secret ever goes in.

import { useEffect, useState } from "react";
import { FileCodeIcon, FolderOpenIcon } from "lucide-react";
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
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { BulkTargetPicker } from "@/components/BulkTargetPicker";
import { HelpTip } from "@/components/HelpTip";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type ResolvedTargets, type TargetPicks } from "@/lib/api";
import { plural } from "@/lib/format";
import {
  reportsApi,
  type AnsibleExport,
  type AnsibleFormat,
  type AnsiblePreview,
  type AnsibleRequest,
  type GroupBy,
} from "@/lib/reports-api";
import { ansibleReason, ansibleSavedText, utcOffsetMinutes } from "@/lib/reports";

interface Props {
  /** Sessions picked already (the Sessions page's selection). */
  sessionIds: string[];
  onOpenSessions: () => void;
  onClose: () => void;
}

const GROUPS: { key: keyof GroupBy; label: string }[] = [
  { key: "folder", label: "Folder" },
  { key: "tag", label: "Tag" },
  { key: "environment", label: "Environment" },
  { key: "workspace", label: "Workspace" },
];

function nothingPicked(picks: TargetPicks): boolean {
  return (
    !picks.sessionIds?.length &&
    !picks.terminalIds?.length &&
    !picks.vmPaths?.length &&
    !picks.tags?.length &&
    !picks.filterIds?.length
  );
}

export function AnsibleExportDialog({ sessionIds, onOpenSessions, onClose }: Props) {
  const [picks, setPicks] = useState<TargetPicks>({ sessionIds });
  const [resolved, setResolved] = useState<{ key: string; targets: ResolvedTargets } | null>(null);
  const [format, setFormat] = useState<AnsibleFormat>("yaml");
  const [groupBy, setGroupBy] = useState<GroupBy>({ folder: true, tag: true, environment: true, workspace: false });
  const [preview, setPreview] = useState<{ key: string; preview: AnsiblePreview } | null>(null);
  // A read's failure, for the picks or request it was for: one read for other picks since then clears it.
  const [readError, setReadError] = useState<{ key: string; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<AnsibleExport | null>(null);

  const request: AnsibleRequest = { picks, format, groupBy };
  const requestKey = JSON.stringify(request);
  const shown = preview?.key === requestKey ? preview.preview : null;
  const all = nothingPicked(picks);

  // BX-01: the hosts the picks reach, for the picker's list (none when nothing is picked).
  const picksKey = JSON.stringify(picks);
  const resolvedNow = !all && resolved?.key === picksKey ? resolved.targets : null;
  useEffect(() => {
    const parsed = JSON.parse(picksKey) as TargetPicks;
    if (nothingPicked(parsed)) return;
    let stale = false;
    reportsApi.ansibleTargets(parsed).then(
      (r) => !stale && setResolved({ key: picksKey, targets: r }),
      (err) => !stale && setReadError({ key: `picks:${picksKey}`, message: errorMessage(err) }),
    );
    return () => {
      stale = true;
    };
  }, [picksKey]);

  // The file as it would be written.
  useEffect(() => {
    const parsed = JSON.parse(requestKey) as AnsibleRequest;
    let stale = false;
    const timer = window.setTimeout(() => {
      reportsApi.ansiblePreview(parsed).then(
        (p) => !stale && setPreview({ key: requestKey, preview: p }),
        (err) => !stale && setReadError({ key: `preview:${requestKey}`, message: errorMessage(err) }),
      );
    }, 200);
    return () => {
      stale = true;
      window.clearTimeout(timer);
    };
  }, [requestKey]);

  const previewProblem = readError?.key === `preview:${requestKey}` ? readError.message : null;
  const picksProblem = readError?.key === `picks:${picksKey}` ? readError.message : null;

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const report = await reportsApi.exportAnsible(request, utcOffsetMinutes());
      if (report) {
        setDone(report);
        toast.success(ansibleSavedText(report));
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

  const reason = ansibleReason({ hosts: shown ? shown.hosts : null, busy, problem: previewProblem });

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileCodeIcon className="size-4" aria-hidden />
            Export an Ansible inventory
            <HelpTip topic="reports.ansible" />
          </DialogTitle>
          <DialogDescription>
            Each host with its address, port, user and jump hosts. No secret goes in.
          </DialogDescription>
        </DialogHeader>

        {done ? (
          <div className="grid gap-2 text-sm">
            <p>{ansibleSavedText(done)}</p>
            {done.notes.length > 0 && (
              <ul className="max-h-40 list-disc overflow-y-auto pl-5 text-xs break-words text-muted-foreground">
                {done.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            )}
          </div>
        ) : (
          <div className="grid max-h-[60vh] gap-4 overflow-y-auto pr-1">
            <BulkTargetPicker
              active
              purpose="export"
              picks={picks}
              onPicksChange={setPicks}
              resolved={resolvedNow}
              onOpenSessions={onOpenSessions}
            />
            {picksProblem && (
              <p className="text-sm break-words text-destructive" role="alert">
                {picksProblem}
              </p>
            )}
            <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
              <div className="flex items-center gap-3">
                <span className="text-sm font-medium">Format</span>
                <ToggleGroup
                  type="single"
                  variant="outline"
                  size="sm"
                  value={format}
                  onValueChange={(v) => v && setFormat(v as AnsibleFormat)}
                  aria-label="Format"
                >
                  <ToggleGroupItem value="yaml">YAML</ToggleGroupItem>
                  <ToggleGroupItem value="ini">INI</ToggleGroupItem>
                </ToggleGroup>
              </div>
              <fieldset className="flex flex-wrap items-center gap-3">
                <legend className="sr-only">Groups by</legend>
                <span className="text-sm font-medium" aria-hidden>
                  Groups by
                </span>
                {GROUPS.map((g) => (
                  <div key={g.key} className="flex items-center gap-2">
                    <Checkbox
                      id={`ansible-group-${g.key}`}
                      checked={groupBy[g.key]}
                      onCheckedChange={(v) => setGroupBy((b) => ({ ...b, [g.key]: v === true }))}
                    />
                    <Label htmlFor={`ansible-group-${g.key}`} className="font-normal">
                      {g.label}
                    </Label>
                  </div>
                ))}
              </fieldset>
            </div>
            <div className="grid gap-1.5">
              <span className="text-sm font-medium">
                {shown ? `Preview: ${plural(shown.hosts, "host")} in ${plural(shown.groups, "group")}` : "Preview"}
              </span>
              <pre className="max-h-64 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs whitespace-pre">
                {shown?.text ?? ""}
              </pre>
              {shown && shown.notes.length > 0 && (
                <ul className="list-disc pl-5 text-xs break-words text-muted-foreground">
                  {shown.notes.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              )}
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
                  Save…
                </Button>
              </WhyDisabled>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
