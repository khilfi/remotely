// BX-10 (0.8.0 G3): the Files page's Many hosts tab: push files of this PC into one folder on every picked host, or
// fetch the same file from each into a folder of this PC (each host's in a folder of its own). The hosts are BX-01's
// targets (sessions, VMs through their linked sessions, tags, filters). Each runs as one job through the approval
// rules (a push asks once, and for the full approval from 5 hosts; a fetch from a Prod host asks once), and its results
// show like Compare hosts': hosts that got or hold the same bytes grouped, and two groups diffed.
//
// UX-15 (0.9.0 H1): files dropped on this tab from Explorer fill the push's list (`data-files-drop="many"`,
// lib/drop-target.ts). Fetch leads to the support bundle (many files and commands from each host, in one zip), and the
// bundle dialog back here, each with the hosts picked.

import { useEffect, useRef, useState } from "react";
import { ArchiveIcon, DownloadIcon, FileUpIcon, UploadIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { BulkResultsView } from "@/components/BulkResultsView";
import { BulkTargetPicker } from "@/components/BulkTargetPicker";
import { HelpTip } from "@/components/HelpTip";
import { usePresentation } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type ResolvedTargets,
  type StagedFiles,
  type SubmitOutcome,
  type TargetPicks,
} from "@/lib/api";
import { READ_ONLY_REASON } from "@/lib/disabled-reasons";
import { plural } from "@/lib/format";
import { filesPageApi, type FetchTo, type LocalListing, type PushFrom } from "@/lib/files-page-api";
import { requestLink } from "@/lib/links";
import { readOnlyLocked } from "@/lib/presentation-state";

interface Props {
  active: boolean;
  /** The local pane's folder and what is picked there. */
  local: LocalListing | null;
  localPicked: string[];
  /** UX-15: files dropped on this tab from Explorer, for the push; `n` counts the drops. */
  dropped?: { staged: StagedFiles; n: number } | null;
  /** UX-15: opened from the support bundle dialog: fetch, on these picks. */
  request?: { mode: Mode; picks?: TargetPicks; n: number } | null;
  onSubmitted: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onOpenSessions: () => void;
}

export type Mode = "push" | "fetch";

export function ManyHostsView({
  active,
  local,
  localPicked,
  dropped = null,
  request = null,
  onSubmitted,
  onOpenSessions,
}: Props) {
  const presentation = usePresentation();
  const [picks, setPicks] = useState<TargetPicks>(request?.picks ?? {});
  const [resolved, setResolved] = useState<ResolvedTargets | null>(null);
  const [mode, setMode] = useState<Mode>(request?.mode ?? "push");
  // A request from elsewhere (the support bundle dialog), once per ask.
  const [handledRequest, setHandledRequest] = useState(request?.n ?? 0);
  if (request && request.n !== handledRequest) {
    setHandledRequest(request.n);
    setMode(request.mode);
    if (request.picks) setPicks(request.picks);
  }
  const [folder, setFolder] = useState("");
  const [replace, setReplace] = useState(false);
  const [path, setPath] = useState("");
  const [trust, setTrust] = useState(false);
  const [staged, setStaged] = useState<StagedFiles | null>(null);
  const [busy, setBusy] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);

  useEffect(() => {
    let stale = false;
    api.bulkTargets(picks).then(
      (r) => !stale && setResolved(r),
      () => !stale && setResolved(null),
    );
    return () => {
      stale = true;
    };
  }, [picks]);

  const hosts = resolved?.hosts.length ?? 0;
  const localFiles = local?.path
    ? localPicked.filter((n) => local.entries.some((e) => e.name === n && e.kind === "file" && !e.link))
    : [];
  const pushFrom: PushFrom | null = staged
    ? { kind: "staged", id: staged.id }
    : local && localFiles.length > 0
      ? { kind: "local", listing: local.id, names: localFiles }
      : null;
  const fileCount = staged ? staged.files.length : localFiles.length;
  const readOnly = readOnlyLocked(presentation);
  const why = readOnly
    ? READ_ONLY_REASON
    : hosts === 0
      ? "Pick the hosts first"
      : mode === "push"
        ? !pushFrom
          ? "Choose files, or pick files on this PC's side"
          : !folder.trim().startsWith("/")
            ? "Type the host folder, a full path such as /etc/app"
            : null
        : !path.trim().startsWith("/")
          ? "Type the file's full path on the hosts, such as /etc/hosts"
          : null;

  /** The push's files: chosen in the dialog or dropped here, in place of what was chosen before. */
  function take(next: StagedFiles, verb: "pick" | "drop") {
    if (staged && staged.id !== next.id) void api.filesUnstage(staged.id).catch(() => undefined);
    if (next.files.some((f) => f.folder)) {
      void api.filesUnstage(next.id).catch(() => undefined);
      setStaged(null);
      toast.error(`A push sends files: ${verb} files, not folders.`);
      return;
    }
    setMode("push");
    setStaged(next);
  }

  async function choose() {
    try {
      const next = await filesPageApi.pickPush();
      if (next) take(next, "pick");
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  // UX-15: files from Explorer dropped on this tab fill the push's list.
  const takeRef = useRef(take);
  useEffect(() => {
    takeRef.current = take;
  });
  const seenDrop = useRef(dropped?.n ?? 0);
  useEffect(() => {
    if (!dropped || dropped.n === seenDrop.current) return;
    seenDrop.current = dropped.n;
    takeRef.current(dropped.staged, "drop");
  }, [dropped]);

  async function go(to?: FetchTo) {
    setBusy(true);
    try {
      const started =
        mode === "push" && pushFrom
          ? await filesPageApi.push(picks, pushFrom, folder.trim(), replace, trust)
          : await filesPageApi.fetch(picks, path.trim(), to ?? { kind: "choose" }, trust);
      if (!started) return;
      if (mode === "push") setStaged(null);
      onSubmitted(started.outcome, setJobId);
      if (started.outcome.status === "queued") setJobId(started.outcome.jobId);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="@container min-h-0 flex-1 overflow-auto" data-files-drop="many">
      <div className="grid gap-4 @4xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <div className="grid content-start gap-4">
          <BulkTargetPicker
            active={active}
            picks={picks}
            onPicksChange={setPicks}
            resolved={resolved}
            onOpenSessions={onOpenSessions}
          />
        </div>
        <div className="grid content-start gap-4">
          <div className="flex items-center gap-1">
            <h2 className="text-sm font-medium">What to do on {plural(hosts, "host")}</h2>
            <HelpTip topic="files.manyHosts" />
          </div>
          <RadioGroup value={mode} onValueChange={(v) => setMode(v as Mode)} className="flex flex-wrap gap-4">
            <div className="flex items-center gap-2">
              <RadioGroupItem id="many-push" value="push" />
              <Label htmlFor="many-push" className="font-normal">
                Push files to each
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <RadioGroupItem id="many-fetch" value="fetch" />
              <Label htmlFor="many-fetch" className="font-normal">
                Fetch a file from each
              </Label>
            </div>
          </RadioGroup>
          {mode === "push" ? (
            <div className="grid gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <Button variant="outline" size="sm" onClick={() => void choose()}>
                  <FileUpIcon data-icon="inline-start" />
                  Choose files…
                </Button>
                <span className="text-xs text-muted-foreground">
                  {staged
                    ? `${plural(staged.files.length, "file")} chosen`
                    : localFiles.length > 0
                      ? `${plural(localFiles.length, "file")} picked on this PC's side`
                      : "or pick files on this PC's side, or drop them here from Explorer"}
                </span>
                {staged && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      void api.filesUnstage(staged.id).catch(() => undefined);
                      setStaged(null);
                    }}
                  >
                    Clear
                  </Button>
                )}
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="many-folder">Into this folder on each host</Label>
                <Input
                  id="many-folder"
                  className="font-mono"
                  placeholder="/etc/app"
                  value={folder}
                  onChange={(e) => setFolder(e.target.value)}
                  spellCheck={false}
                />
              </div>
              <div className="flex items-center gap-2">
                <Checkbox id="many-replace" checked={replace} onCheckedChange={(v) => setReplace(v === true)} />
                <Label htmlFor="many-replace" className="font-normal">
                  Replace files of the same name there
                </Label>
              </div>
            </div>
          ) : (
            <div className="grid gap-1.5">
              <Label htmlFor="many-path">The file on each host</Label>
              <Input
                id="many-path"
                className="font-mono"
                placeholder="/etc/ssh/sshd_config"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                spellCheck={false}
              />
            </div>
          )}
          <div className="flex items-center gap-2">
            <Checkbox id="many-trust" checked={trust} onCheckedChange={(v) => setTrust(v === true)} />
            <Label htmlFor="many-trust" className="font-normal">
              Trust host keys never seen before
            </Label>
          </div>
          <div className="flex flex-wrap gap-2">
            {mode === "push" ? (
              <WhyDisabled reason={why}>
                <Button disabled={why !== null || busy} onClick={() => void go()}>
                  <UploadIcon data-icon="inline-start" />
                  Push {fileCount > 0 ? plural(fileCount, "file") : "files"} to {plural(hosts, "host")}…
                </Button>
              </WhyDisabled>
            ) : (
              <>
                <WhyDisabled reason={why ?? (local?.path ? null : "Open a folder of this PC on the Files tab first")}>
                  <Button
                    disabled={why !== null || busy || !local?.path}
                    onClick={() => local && void go({ kind: "local", listing: local.id })}
                  >
                    <DownloadIcon data-icon="inline-start" />
                    Fetch into this PC's folder
                  </Button>
                </WhyDisabled>
                <WhyDisabled reason={why}>
                  <Button variant="outline" disabled={why !== null || busy} onClick={() => void go({ kind: "choose" })}>
                    Fetch into…
                  </Button>
                </WhyDisabled>
              </>
            )}
          </div>
          {mode === "fetch" && local?.path && (
            <p className="text-xs text-muted-foreground">
              Each host's file goes into a folder of its own under <span className="font-mono">{local.path}</span>.
            </p>
          )}
          {mode === "fetch" && (
            <div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => requestLink({ kind: "bundle", sessionIds: resolved?.hosts.map((h) => h.sessionId) })}
              >
                <ArchiveIcon data-icon="inline-start" />
                Collect a support bundle instead…
              </Button>
            </div>
          )}
          {jobId && (
            <div className="rounded-lg border p-3">
              <BulkResultsView jobId={jobId} onRetry={(outcome) => onSubmitted(outcome, setJobId)} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
