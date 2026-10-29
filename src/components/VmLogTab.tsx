// VM-25: a VM's Log tab. Workstation's vmware.log and its older vmware-N.log, VirtualBox's VBox.log and VBox.log.N,
// read only. The first read is the log's last 256 KB (the core caps every read; a huge log is never read whole);
// following reads only what was added, every 2 seconds, while this tab shows and the window is visible (usePoll), and
// only for the current log of a running VM. Search shows the matching lines. Reads are not audited and the read-only
// lock doesn't stop them.

import { useEffect, useMemo, useRef, useState } from "react";
import { FileTextIcon, SearchIcon, TriangleAlertIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { WhyDisabled } from "@/components/WhyDisabled";
import { RefreshButton } from "@/components/RefreshButton";
import { errorMessage, type VmRecord } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { useVisibility, usePoll } from "@/hooks/use-poll";
import { formatBytes } from "@/lib/retention";
import { insightApi, type LogListing } from "@/lib/vm-insight-api";
import {
  LOG_FOLLOW_MS,
  followLog,
  followReason,
  logMatches,
  splitMatches,
  startLog,
  type LogView,
} from "@/lib/vm-insight";

export function VmLogTab({ vm }: { vm: VmRecord }) {
  const [picked, setPicked] = useState<string | null>(null);
  const [follow, setFollow] = useState(true);
  const [query, setQuery] = useState("");
  const [reloads, setReloads] = useState(0);
  const visibility = useVisibility();
  const box = useRef<HTMLPreElement>(null);
  const atBottom = useRef(true);
  const vmxPath = vm.vmxPath;

  // The listing, for what was asked (`key`): another VM or Refresh reads it again.
  const listKey = `${vmxPath}|${reloads}`;
  const [listed, setListed] = useState<{ key: string; listing?: LogListing; error?: string } | null>(null);
  const loading = listed?.key !== listKey;
  const listing = listed?.listing ?? null;
  // The log picked, while the listing has it; else the current log.
  const file = listing?.files.some((f) => f.name === picked) ? picked : (listing?.files[0]?.name ?? null);

  useEffect(() => {
    let stale = false;
    insightApi.vmLogs(vmxPath).then(
      (found) => !stale && setListed({ key: listKey, listing: found }),
      (err: unknown) => !stale && setListed({ key: listKey, error: errorMessage(err) }),
    );
    return () => {
      stale = true;
    };
  }, [vmxPath, listKey]);

  // The chosen log's tail, then what following adds, for the log it was read from (`key`).
  const viewKey = `${listKey}|${file ?? ""}`;
  const [shown, setShown] = useState<{ key: string; view?: LogView; error?: string } | null>(null);
  const view = shown?.key === viewKey ? (shown.view ?? null) : null;
  const error = listed?.error ?? (shown?.key === viewKey ? shown.error : undefined) ?? null;

  useEffect(() => {
    if (!file) return;
    let stale = false;
    insightApi.vmLogRead(vmxPath, file, null).then(
      (chunk) => {
        if (stale) return;
        atBottom.current = true;
        setShown({ key: viewKey, view: startLog(chunk) });
      },
      (err: unknown) => !stale && setShown({ key: viewKey, error: errorMessage(err) }),
    );
    return () => {
      stale = true;
    };
  }, [vmxPath, file, viewKey]);

  const chosen = listing?.files.find((f) => f.name === file);
  const followOff = followReason(vm.powerState, chosen);
  const following = follow && followOff === null && view !== null;

  usePoll(
    async (live) => {
      if (!view || !file) return;
      const chunk = await insightApi.vmLogRead(vmxPath, file, view.end);
      if (!live()) return;
      setShown((was) => (was?.key === viewKey && was.view ? { key: viewKey, view: followLog(was.view, chunk) } : was));
    },
    {
      enabled: following && visibility === "visible",
      resetKey: `${vmxPath}|${file}`,
      intervalMs: LOG_FOLLOW_MS,
      immediate: false,
    },
  );

  // While following, a log scrolled to its end stays there as lines arrive.
  useEffect(() => {
    const el = box.current;
    if (el && atBottom.current && !query) el.scrollTop = el.scrollHeight;
  }, [view?.text, query]);

  const matches = useMemo(() => (view && query.trim() ? logMatches(view.text, query) : null), [view, query]);

  if (error) {
    return (
      <Alert variant="destructive">
        <TriangleAlertIcon />
        <AlertTitle>Could not read the VM&apos;s logs</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  if (listing && listing.files.length === 0) {
    return (
      <Empty className="border py-8">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <FileTextIcon />
          </EmptyMedia>
          <EmptyTitle>No logs</EmptyTitle>
          <EmptyDescription>{listing.problem ?? "The hypervisor writes a log when the VM starts."}</EmptyDescription>
        </EmptyHeader>
      </Empty>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={file ?? ""} onValueChange={setPicked} disabled={!listing}>
          <SelectTrigger className="w-48" aria-label="Log file">
            <SelectValue placeholder="Log file" />
          </SelectTrigger>
          <SelectContent>
            {listing?.files.map((f) => (
              <SelectItem key={f.name} value={f.name}>
                {f.name}
                <span className="text-xs text-muted-foreground">
                  {f.current ? "current" : formatWhen(f.modified)} · {formatBytes(f.size)}
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <WhyDisabled reason={followOff}>
          <div className="flex items-center gap-1.5">
            <Switch id="log-follow" checked={following} disabled={followOff !== null} onCheckedChange={setFollow} />
            <Label htmlFor="log-follow" className="text-sm font-normal">
              Follow
            </Label>
          </div>
        </WhyDisabled>
        <InputGroup className="w-56">
          <InputGroupAddon>
            <SearchIcon />
          </InputGroupAddon>
          <InputGroupInput
            placeholder="Search this log"
            aria-label="Search this log"
            value={query}
            onChange={(e) => setQuery(e.currentTarget.value)}
          />
        </InputGroup>
        <RefreshButton className="ml-auto" busy={loading} onClick={() => setReloads((n) => n + 1)} />
      </div>

      <div className="text-xs text-muted-foreground">
        {view?.startsMidway && "The log's last part; older lines are left out. "}
        {view && view.skipped > 0 && `${formatBytes(view.skipped)} was skipped while following. `}
        {view?.restarted && "The VM started again, so its log began anew. "}
        {matches && `${matches.length} matching line${matches.length === 1 ? "" : "s"}.`}
        {listing?.folder && (
          <span className="block font-mono break-all" title="Where the logs are">
            {listing.folder}
          </span>
        )}
      </div>

      {!view ? (
        <div className="flex flex-col gap-1.5" aria-label="Reading the log">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-[92%]" />
          <Skeleton className="h-4 w-[85%]" />
        </div>
      ) : (
        <pre
          ref={box}
          tabIndex={0}
          aria-label={`${file ?? "log"} of ${vm.displayName}`}
          onScroll={(e) => {
            const el = e.currentTarget;
            atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
          }}
          className="min-h-48 flex-1 overflow-auto rounded-md border bg-muted/30 p-2 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all"
        >
          {matches
            ? matches.map((m) => (
                <div key={m.line}>
                  <span className="mr-2 text-muted-foreground select-none">{m.line}</span>
                  {splitMatches(m.text, query).map((part, i) =>
                    part.match ? (
                      <mark key={i} className="rounded-sm bg-tier-medium/30 text-foreground">
                        {part.text}
                      </mark>
                    ) : (
                      part.text
                    ),
                  )}
                </div>
              ))
            : view.text || <span className="text-muted-foreground">The log is empty.</span>}
        </pre>
      )}
    </div>
  );
}
