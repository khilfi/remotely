// SS-14 (0.8.0 G3): compare the local pane's folder with the host pane's, then sync one way. Comparing only reads.
// To the host is one job through the approval rules (new files need none, replacing asks once, deleting what only the
// host has, only when ticked, asks for the full approval); to this PC is downloads, and nothing here is deleted.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeftIcon, ArrowRightIcon, GitCompareIcon } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { HelpTip } from "@/components/HelpTip";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type DownloadStart, type SubmitOutcome } from "@/lib/api";
import { READ_ONLY_REASON } from "@/lib/disabled-reasons";
import { plural } from "@/lib/format";
import { defaultPicks, rowWords, syncSummary, syncTakes } from "@/lib/files-page";
import { filesPageApi, type Comparison, type SyncDirection } from "@/lib/files-page-api";
import { readOnlyLocked } from "@/lib/presentation-state";
import { usePresentation } from "@/components/Presentation";
import { formatSize } from "@/lib/transfers";
import { cn } from "@/lib/utils";

interface Props {
  terminalId: string;
  hostName: string;
  hostFolder: string;
  asRoot: boolean;
  /** The local pane's listing (its folder is compared). */
  listing: string;
  localFolder: string;
  onSubmitted: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onDownloads: (start: DownloadStart) => void;
  onClose: () => void;
}

export function CompareSheet(props: Props) {
  const { terminalId, hostName, hostFolder, asRoot, listing, localFolder, onSubmitted, onDownloads, onClose } = props;
  const presentation = usePresentation();
  const [contents, setContents] = useState(false);
  /** Comparisons asked for (counted, with their contents option) and the last one answered. */
  const [run, setRun] = useState({ n: 1, contents: false });
  const [answered, setAnswered] = useState(0);
  const [syncing, setSyncing] = useState(false);
  const busy = syncing || answered !== run.n;
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [direction, setDirection] = useState<SyncDirection>("toHost");
  const [deleting, setDeleting] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);
  /** Jobs of syncs started here; the folders are compared again once one ends. */
  const [watching, setWatching] = useState<string | null>(null);

  const compare = useCallback(() => setRun((r) => ({ n: r.n + 1, contents })), [contents]);

  // The latest picking options, for the answer.
  const options = useRef({ direction, deleting });
  useEffect(() => {
    options.current = { direction, deleting };
  });

  useEffect(() => {
    let gone = false;
    filesPageApi.compare({ terminalId, listing, hostFolder, contents: run.contents, asRoot }).then(
      (next) => {
        if (gone) return;
        setAnswered(run.n);
        setError(null);
        setComparison(next);
        const { direction: d, deleting: del } = options.current;
        setPicked(defaultPicks(next.rows, d, d === "toHost" && del));
      },
      (err) => {
        if (gone) return;
        setAnswered(run.n);
        setError(errorMessage(err));
      },
    );
    return () => {
      gone = true;
    };
  }, [run, terminalId, listing, hostFolder, asRoot]);

  function changeDirection(next: SyncDirection, nextDeleting = deleting) {
    setDirection(next);
    setDeleting(nextDeleting);
    if (comparison) setPicked(defaultPicks(comparison.rows, next, next === "toHost" && nextDeleting));
  }

  const rows = useMemo(() => comparison?.rows ?? [], [comparison]);
  const del = direction === "toHost" && deleting;
  const summary = syncSummary(rows, picked, direction, del);
  const nothing = summary.send + summary.replace + summary.remove === 0;
  const readOnly = readOnlyLocked(presentation);
  const why =
    readOnly && direction === "toHost"
      ? READ_ONLY_REASON
      : !comparison
        ? "Compare the folders first"
        : nothing
          ? "Nothing picked needs to go that way"
          : null;

  async function sync() {
    if (!comparison) return;
    setSyncing(true);
    try {
      const start = await filesPageApi.sync({ comparison: comparison.id, direction, paths: picked, delete: del });
      if (start.status === "nothing") toast.info("Nothing picked needed to go.");
      else if (start.status === "downloads") {
        onDownloads(start.start);
        onClose();
      } else {
        onSubmitted(start.outcome, (jobId) => setWatching(jobId));
        if (start.outcome.status === "queued") setWatching(start.outcome.jobId);
      }
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setSyncing(false);
    }
  }

  // A sync to the host ended: compare again, so what is left shows.
  useEffect(() => {
    if (!watching) return;
    const unlisten = api.onJobEvent((event) => {
      if (event.event === "finished" && event.jobId === watching) {
        setWatching(null);
        compare();
      }
    });
    return () => void unlisten.then((stop) => stop());
  }, [watching, compare]);

  const label =
    direction === "toHost"
      ? `Sync to ${hostName}${summary.remove > 0 ? `, deleting ${summary.remove}` : ""}…`
      : `Download ${plural(summary.send + summary.replace, "file")} to this PC`;

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-1">
            Compare and sync
            <HelpTip topic="files.compare" />
          </SheetTitle>
          <SheetDescription className="grid gap-0.5">
            <span className="truncate">
              This PC: <span className="font-mono">{localFolder}</span>
            </span>
            <span className="truncate">
              {hostName}: <span className="font-mono">{hostFolder}</span>
              {asRoot ? ", as root" : ""}
            </span>
          </SheetDescription>
        </SheetHeader>
        <div className="flex flex-wrap items-center gap-3 px-4">
          <div className="flex items-center gap-2">
            <Checkbox id="compare-contents" checked={contents} onCheckedChange={(v) => setContents(v === true)} />
            <Label htmlFor="compare-contents" className="font-normal">
              Compare contents (SHA-256)
            </Label>
          </div>
          <Button variant="outline" size="sm" disabled={busy} onClick={compare}>
            <GitCompareIcon data-icon="inline-start" />
            {busy ? "Comparing…" : "Compare again"}
          </Button>
        </div>
        {error && <p className="px-4 text-sm text-destructive">{error}</p>}
        {comparison && (
          <div className="grid min-h-0 flex-1 gap-2 overflow-hidden px-4">
            <p className="text-xs text-muted-foreground">
              {plural(comparison.counts.same, "file")} the same, {comparison.counts.onlyHere} only on this PC,{" "}
              {comparison.counts.onlyThere} only on the host, {comparison.counts.differs} different
              {comparison.counts.conflicts > 0 &&
                `, ${comparison.counts.conflicts} a file on one side and a folder on the other`}
              {comparison.leftOut > 0 && `; ${plural(comparison.leftOut, "link")}, Git's data and the like left out`}
              {comparison.contentsCapped &&
                `; contents compared for ${plural(comparison.contentsCompared, "file")} only, the rest by size and time`}
              {comparison.contentsUnread > 0 &&
                `; ${plural(comparison.contentsUnread, "host file")} too large or slow to hash, compared by size and time`}
              .
            </p>
            <RadioGroup
              value={direction}
              onValueChange={(v) => changeDirection(v as SyncDirection)}
              className="flex flex-wrap gap-4"
            >
              <div className="flex items-center gap-2">
                <RadioGroupItem id="sync-to-host" value="toHost" />
                <Label htmlFor="sync-to-host" className="font-normal">
                  <ArrowRightIcon className="size-3.5" aria-hidden /> To the host
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <RadioGroupItem id="sync-to-pc" value="toPc" />
                <Label htmlFor="sync-to-pc" className="font-normal">
                  <ArrowLeftIcon className="size-3.5" aria-hidden /> To this PC
                </Label>
              </div>
            </RadioGroup>
            {direction === "toHost" && (
              <div className="flex items-center gap-2">
                <Checkbox
                  id="sync-delete"
                  checked={deleting}
                  onCheckedChange={(v) => changeDirection("toHost", v === true)}
                />
                <Label htmlFor="sync-delete" className="font-normal">
                  Delete on the host what this PC's folder doesn't have
                </Label>
              </div>
            )}
            <ul className="min-h-0 divide-y overflow-auto rounded-md border text-xs">
              {rows.length === 0 && <li className="px-2 py-2 text-muted-foreground">Both folders hold the same.</li>}
              {rows.map((row) => {
                const takes = syncTakes(row, direction, del);
                const side = direction === "toHost" ? row.here : row.there;
                const removing = direction === "toHost" && row.state === "onlyThere";
                return (
                  <li key={row.path} className={cn("flex items-center gap-2 px-2 py-1", !takes.can && "opacity-60")}>
                    <Checkbox
                      aria-label={`Sync ${row.path}`}
                      checked={takes.can && picked.includes(row.path)}
                      disabled={!takes.can}
                      onCheckedChange={(v) =>
                        setPicked((p) => (v === true ? [...p, row.path] : p.filter((x) => x !== row.path)))
                      }
                    />
                    <span className="min-w-0 flex-1 truncate font-mono">{row.path}</span>
                    {removing && takes.can && (
                      <Badge variant="outline" className="border-tier-high/50 font-normal text-tier-high">
                        deleted there
                      </Badge>
                    )}
                    <span className="shrink-0 text-muted-foreground">{rowWords(row)}</span>
                    <span className="w-16 shrink-0 text-right text-muted-foreground tabular-nums">
                      {side && !side.folder ? formatSize(side.size) : ""}
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
        <SheetFooter className="flex-row justify-end gap-2">
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          <WhyDisabled reason={why}>
            <Button disabled={why !== null || busy} onClick={() => void sync()}>
              {label}
            </Button>
          </WhyDisabled>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
