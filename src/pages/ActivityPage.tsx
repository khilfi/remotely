// Activity (AP-03, AP-05, VM-05; UX-02, UX-06 in 0.6.0): what happened, in two views. Timeline: one row per job, its
// audit entries (approval asked, approved, started, finished) folded under it, and one row per change of no job (a
// session edited, a host key trusted), with the events in plain words (lib/activity.ts) and filters by target or
// action, kind and date. Audit log: every entry one by one, with Verify and the CSV export.
//
// Open jobs can be cancelled here: a job in its countdown shows the time left and touches nothing if cancelled, and a
// running job stops targets that have not started and stops waiting for VM power actions in progress (Workstation or
// VirtualBox may still finish those). A job's results show each target's outcome and the safety snapshot taken on it.
// BX-02: a job older than the retention period (Settings, General) keeps its results but no longer its outputs or
// command text, which its results say.
//
// P6, AP-03: job events come in bursts (a MultiExec line on 50 terminals sends about 100), so they reach the lists
// through one path. App bumps `version` only when a job is queued or ends; while this page shows, a job's progress
// (its countdown, its start, each target's result) asks too. Asks within a second of the first are one reload, a
// second later (PROGRESS_READ_MS), so the lists are read at most once a second, and never per event. Nothing is read
// while the page is hidden; showing it reads once.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  CameraIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  DownloadIcon,
  EraserIcon,
  FilterXIcon,
  ListChecksIcon,
  ScrollTextIcon,
  SearchIcon,
  ShieldCheckIcon,
  ShieldXIcon,
} from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { StatusBadge, TierBadge } from "@/components/Badges";
import { EmptyState } from "@/components/EmptyState";
import { HelpTip } from "@/components/HelpTip";
import { PageHeader } from "@/components/PageHeader";
import { Term } from "@/components/Term";
import { api, errorMessage, type AuditEntry, type ChainCheck, type JobSummary, type JobTarget } from "@/lib/api";
import {
  ACTIVITY_KINDS,
  DATE_RANGES,
  eventLabel,
  filterEntries,
  filterGroups,
  groupActivity,
  isFiltered,
  isOpenJob,
  NO_FILTER,
  plainText,
  resultLabel,
  resultTone,
  stepsText,
  type ActivityFilter,
  type ActivityGroup,
  type ActivityKind,
  type DateRange,
} from "@/lib/activity";
import { formatWhen, plural } from "@/lib/format";
import { progressesJob, PROGRESS_READ_MS } from "@/lib/job-events";
import { cn } from "@/lib/utils";

type View = "timeline" | "audit";

/** How many jobs and audit entries a read asks for; "Show older" asks for more. */
const JOBS_STEP = 100;
const AUDIT_STEP = 500;

/** Seconds left in a job's countdown, or null when it has none. */
function secondsLeft(job: JobSummary, now: number) {
  if (job.status !== "countdown" || !job.countdownUntil) return null;
  return Math.max(0, Math.ceil((new Date(job.countdownUntil).getTime() - now) / 1000));
}

/** "01:58" today, "30 Oct, 01:58" before; the full date and time on hover. */
function shortWhen(ts: string, now: number) {
  const at = new Date(ts);
  const time = at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (at.toDateString() === new Date(now).toDateString()) return time;
  return `${at.toLocaleDateString([], { day: "numeric", month: "short" })}, ${time}`;
}

function When({ ts, now }: { ts: string; now: number }) {
  return (
    <time dateTime={ts} title={formatWhen(ts)} className="whitespace-nowrap text-muted-foreground tabular-nums">
      {shortWhen(ts, now)}
    </time>
  );
}

function Result({ result }: { result: string | null }) {
  const text = resultLabel(result);
  if (!text) return <span className="text-muted-foreground">—</span>;
  const tone = resultTone(result);
  return <span className={cn(tone === "ok" && "text-success", tone === "bad" && "text-destructive")}>{text}</span>;
}

/**
 * `version` changes when a job is queued or ends; `active` is true while the page is shown, so entries written
 * without a job (terminals, host keys, imports, settings) show up when the user comes back.
 */
export function ActivityPage({
  version,
  active,
  focusJob = null,
}: {
  version: number;
  active: boolean;
  /** R10: a job to open (a notification, the status bar). */
  focusJob?: { jobId: string; n: number } | null;
}) {
  const [jobs, setJobs] = useState<JobSummary[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [limits, setLimits] = useState({ jobs: JOBS_STEP, audit: AUDIT_STEP });
  const [view, setView] = useState<View>("timeline");
  const [filter, setFilter] = useState<ActivityFilter>(NO_FILTER);
  const [unfolded, setUnfolded] = useState<Set<string>>(new Set());
  const [check, setCheck] = useState<ChainCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloads, setReloads] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  // The job whose results are open; read from `jobs`, so its status stays current.
  const [openedId, setOpenedId] = useState<string | null>(null);
  const [focusHandled, setFocusHandled] = useState(focusJob?.n ?? 0);
  if (focusJob && focusJob.n !== focusHandled) {
    setFocusHandled(focusJob.n);
    setOpenedId(focusJob.jobId);
    setView("timeline");
  }
  const opened = jobs.find((j) => j.id === openedId);
  const [exporting, setExporting] = useState(false);
  const counting = jobs.some((j) => j.status === "countdown");

  // One reload path (see the top of the file): `asked` moves at most once a second, a second after the first ask.
  const [asked, setAsked] = useState(0);
  const askTimer = useRef<number | undefined>(undefined);
  const ask = useCallback(() => {
    if (askTimer.current !== undefined) return;
    askTimer.current = window.setTimeout(() => {
      askTimer.current = undefined;
      setAsked((n) => n + 1);
    }, PROGRESS_READ_MS);
  }, []);
  useEffect(() => () => window.clearTimeout(askTimer.current), []);

  // A job queued or ended. While hidden it asks nothing: showing the page reads anyway.
  const seenVersion = useRef(version);
  useEffect(() => {
    if (version === seenVersion.current) return;
    seenVersion.current = version;
    if (active) ask();
  }, [version, active, ask]);

  // A job's progress, while the page shows.
  useEffect(() => {
    if (!active) return;
    const unlisten = api.onJobEvent((event) => {
      if (progressesJob(event)) ask();
    });
    return () => void unlisten.then((stop) => stop());
  }, [active, ask]);

  useEffect(() => {
    if (!active) return;
    let stale = false;
    Promise.all([api.recentJobs(limits.jobs), api.recentAudit(limits.audit)]).then(
      ([j, a]) => {
        if (stale) return;
        setJobs(j);
        setAudit(a);
        setLoaded(true);
        setNow(Date.now());
        setError(null);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [asked, reloads, active, limits]);

  // AP-03: the time left ticks while a job is in its countdown.
  useEffect(() => {
    if (!counting) return;
    const timer = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(timer);
  }, [counting]);

  const groups = useMemo(() => groupActivity(jobs, audit), [jobs, audit]);
  const shownGroups = useMemo(() => filterGroups(groups, filter, now), [groups, filter, now]);
  const shownEntries = useMemo(() => filterEntries(audit, jobs, filter, now), [audit, jobs, filter, now]);
  const filtered = isFiltered(filter);
  const more = jobs.length >= limits.jobs || audit.length >= limits.audit;

  async function verify() {
    try {
      setCheck(await api.verifyAudit());
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function exportCsv() {
    setExporting(true);
    try {
      const report = await api.exportAudit();
      if (report) {
        const redacted = report.redacted
          ? ` ${plural(report.redacted, "row")} had something that looked like a secret, replaced by [redacted].`
          : "";
        toast.success(`Exported ${plural(report.entries, "entry")}`, {
          description: `${report.path}.${redacted}`,
          duration: 8000,
        });
        setReloads((n) => n + 1);
      }
    } catch (err) {
      toast.error(`Could not export the audit log: ${errorMessage(err)}`);
    } finally {
      setExporting(false);
    }
  }

  async function cancel(jobId: string) {
    try {
      await api.cancelJob(jobId);
    } finally {
      setReloads((n) => n + 1);
    }
  }

  function toggle(key: string) {
    setUnfolded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  const clearFilters = (
    <Button variant="ghost" size="sm" onClick={() => setFilter(NO_FILTER)}>
      <FilterXIcon data-icon="inline-start" />
      Clear filters
    </Button>
  );

  return (
    <Tabs value={view} onValueChange={(v) => setView(v as View)} className="flex flex-col gap-4">
      <PageHeader
        page="activity"
        tabs={
          <TabsList>
            <TabsTrigger value="timeline">
              <ListChecksIcon />
              Timeline
            </TabsTrigger>
            <TabsTrigger value="audit">
              <ScrollTextIcon />
              Audit log
            </TabsTrigger>
          </TabsList>
        }
      >
        <div className="relative w-64">
          <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={filter.text}
            onChange={(e) => setFilter((f) => ({ ...f, text: e.target.value }))}
            placeholder="Filter by target or action"
            aria-label="Filter by target or action"
            className="pl-8"
          />
        </div>
        <Select
          value={filter.kind}
          onValueChange={(v) => setFilter((f) => ({ ...f, kind: v as ActivityKind | "all" }))}
        >
          <SelectTrigger className="w-44" aria-label="Kind">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All kinds</SelectItem>
            {ACTIVITY_KINDS.map((k) => (
              <SelectItem key={k.value} value={k.value}>
                {k.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filter.range} onValueChange={(v) => setFilter((f) => ({ ...f, range: v as DateRange }))}>
          <SelectTrigger className="w-36" aria-label="When">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {DATE_RANGES.map((r) => (
              <SelectItem key={r.value} value={r.value}>
                {r.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {filtered && clearFilters}
      </PageHeader>

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Could not load activity</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <TabsContent value="timeline" className="flex flex-col gap-3">
        {loaded && groups.length === 0 ? (
          <EmptyState
            icon={ListChecksIcon}
            title="Nothing yet"
            description="Actions on VMs and hosts, and changes to sessions and settings, show here."
          />
        ) : loaded && shownGroups.length === 0 ? (
          <EmptyState icon={FilterXIcon} title="Nothing matches the filters" action={clearFilters} />
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-9">
                    <span className="sr-only">Steps</span>
                  </TableHead>
                  <TableHead>What</TableHead>
                  <TableHead className="w-24">Tier</TableHead>
                  <TableHead className="w-44">Result</TableHead>
                  <TableHead className="w-32">When</TableHead>
                  <TableHead className="w-20">
                    <span className="sr-only">Cancel</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {shownGroups.map((group) => (
                  <GroupRows
                    key={group.key}
                    group={group}
                    now={now}
                    unfolded={unfolded.has(group.key)}
                    onToggle={() => toggle(group.key)}
                    onOpen={(id) => setOpenedId(id)}
                    onCancel={(id) => void cancel(id)}
                  />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </TabsContent>

      <TabsContent value="audit" className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm text-muted-foreground">
            {filtered
              ? `${plural(shownEntries.length, "entry")} of ${audit.length} match`
              : `The newest ${plural(audit.length, "entry")}`}
          </span>
          <HelpTip topic="auditLog" />
          <div className="ml-auto flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              title="Check that no entry was changed or removed"
              onClick={() => void verify()}
            >
              <ShieldCheckIcon data-icon="inline-start" />
              Verify the chain
            </Button>
            <Button variant="outline" size="sm" onClick={() => void exportCsv()} disabled={exporting}>
              <DownloadIcon data-icon="inline-start" />
              {exporting ? "Exporting…" : "Export CSV…"}
            </Button>
          </div>
        </div>
        {check && (
          <Alert variant={check.ok ? "default" : "destructive"}>
            {check.ok ? <ShieldCheckIcon /> : <ShieldXIcon />}
            <AlertTitle>
              {check.ok
                ? `All ${check.entries} entries check out`
                : `The audit log was changed at entry ${check.firstBadSeq}`}
            </AlertTitle>
            {check.problem && <AlertDescription>{check.problem}</AlertDescription>}
          </Alert>
        )}
        {loaded && audit.length === 0 ? (
          <EmptyState
            icon={ScrollTextIcon}
            title="The audit log is empty"
            description="Every change is logged when it starts and when it ends."
            help="auditLog"
          />
        ) : loaded && shownEntries.length === 0 ? (
          <EmptyState icon={FilterXIcon} title="Nothing matches the filters" action={clearFilters} />
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-14 text-right">#</TableHead>
                  <TableHead className="w-32">When</TableHead>
                  <TableHead className="w-48">Event</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead className="w-24">Tier</TableHead>
                  <TableHead className="w-28">Result</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {shownEntries.map((e) => (
                  <TableRow key={e.id} title={e.detail ? plainText(e.detail) : undefined}>
                    <TableCell className="text-right text-muted-foreground tabular-nums">{e.seq}</TableCell>
                    <TableCell>
                      <When ts={e.ts} now={now} />
                    </TableCell>
                    <TableCell>
                      <span title={e.event}>{eventLabel(e.event)}</span>
                    </TableCell>
                    <TableCell className="whitespace-normal">{plainText(e.action)}</TableCell>
                    <TableCell>
                      {e.tier ? <TierBadge tier={e.tier} /> : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell>
                      <Result result={e.result} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </TabsContent>

      {more && (
        <div className="flex justify-center">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setLimits((l) => ({ jobs: l.jobs + JOBS_STEP, audit: l.audit + AUDIT_STEP }))}
          >
            Show older
          </Button>
        </div>
      )}

      {opened && <JobResults job={opened} version={asked + reloads} onClose={() => setOpenedId(null)} />}
    </Tabs>
  );
}

/** "db-01, web-01 and 3 more". */
function targetsText(names: string[]) {
  if (names.length <= 3) return names.join(", ");
  return `${names.slice(0, 2).join(", ")} and ${names.length - 2} more`;
}

/** One row of the timeline and, unfolded, its steps. */
function GroupRows({
  group,
  now,
  unfolded,
  onToggle,
  onOpen,
  onCancel,
}: {
  group: ActivityGroup;
  now: number;
  unfolded: boolean;
  onToggle: () => void;
  onOpen: (jobId: string) => void;
  onCancel: (jobId: string) => void;
}) {
  const job = group.job;
  const left = job ? secondsLeft(job, now) : null;
  const last = group.entries[group.entries.length - 1];
  const single = group.jobId === null && group.entries.length === 1 ? group.entries[0] : null;
  // A row with something to unfold: a job's steps, an approval's, or an entry's detail.
  const foldable =
    group.entries.length > 1 || (single?.detail ?? "") !== "" || (group.jobId !== null && group.entries.length > 0);
  const opens = job !== null;
  const subtitle = [single ? eventLabel(single.event) : null, targetsText(group.targets) || null]
    .filter(Boolean)
    .join(" · ");

  return (
    <>
      <TableRow
        className={cn((opens || foldable) && "cursor-pointer")}
        onClick={() => (opens && job ? onOpen(job.id) : foldable && onToggle())}
      >
        <TableCell className="align-top">
          {foldable && (
            <Button
              variant="ghost"
              size="icon-xs"
              aria-expanded={unfolded}
              aria-label={`${unfolded ? "Fold" : "Unfold"} ${group.title}: ${single ? "details" : stepsText(group.entries.length)}`}
              title={single ? "Details" : stepsText(group.entries.length)}
              onClick={(e) => {
                e.stopPropagation();
                onToggle();
              }}
            >
              {unfolded ? <ChevronDownIcon /> : <ChevronRightIcon />}
            </Button>
          )}
        </TableCell>
        <TableCell className="whitespace-normal">
          {opens && job ? (
            <button
              type="button"
              className="text-left font-medium hover:underline"
              onClick={(e) => {
                e.stopPropagation();
                onOpen(job.id);
              }}
            >
              {group.title}
            </button>
          ) : (
            <span className="font-medium">{group.title}</span>
          )}
          {subtitle && <div className="text-xs text-muted-foreground">{subtitle}</div>}
        </TableCell>
        <TableCell className="align-top">
          {group.tier ? <TierBadge tier={group.tier} /> : <span className="text-muted-foreground">—</span>}
        </TableCell>
        <TableCell className="align-top">
          {job ? (
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge status={job.status} />
              {left !== null && (
                <span className="text-sm text-tier-high tabular-nums" role="timer">
                  starts in {left} s
                </span>
              )}
              {job.targetsFailed > 0 && (
                <span className="text-xs text-destructive tabular-nums">
                  {job.targetsFailed} of {job.targetsTotal} failed
                </span>
              )}
            </div>
          ) : group.result ? (
            <Result result={group.result} />
          ) : last && !single ? (
            <span className="text-muted-foreground">{eventLabel(last.event)}</span>
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </TableCell>
        <TableCell className="align-top">
          <When ts={group.at} now={now} />
        </TableCell>
        <TableCell className="text-right align-top">
          {isOpenJob(job) && job && (
            <Button
              size="sm"
              variant="ghost"
              title={
                job.status === "running"
                  ? "Stops the targets that haven't started. A VM power action or snapshot under way may still finish."
                  : "Nothing has been done yet; no target is touched"
              }
              onClick={(e) => {
                e.stopPropagation();
                onCancel(job.id);
              }}
            >
              Cancel
            </Button>
          )}
        </TableCell>
      </TableRow>
      {unfolded && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell />
          <TableCell colSpan={5} className="py-2 whitespace-normal">
            <ol className="grid grid-cols-[auto_auto_1fr] gap-x-4 gap-y-1 text-sm">
              {group.entries.map((e) => (
                <li key={e.id} className="contents">
                  <When ts={e.ts} now={now} />
                  <span title={e.event}>
                    {eventLabel(e.event)}
                    {e.result && (
                      <>
                        {" · "}
                        <Result result={e.result} />
                      </>
                    )}
                  </span>
                  <span className="min-w-0 text-xs text-muted-foreground">{e.detail ? plainText(e.detail) : ""}</span>
                </li>
              ))}
            </ol>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

/** One job's targets and how each went, with the safety snapshot taken first (VM-05). */
function JobResults({ job, version, onClose }: { job: JobSummary; version: number; onClose: () => void }) {
  const [targets, setTargets] = useState<JobTarget[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stale = false;
    api.jobTargets(job.id).then(
      (t) => {
        if (!stale) setTargets(t);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [job.id, version]);

  const safety = [...new Set((targets ?? []).flatMap((t) => (t.safetySnapshot ? [t.safetySnapshot] : [])))];

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-2xl">
        <SheetHeader>
          <div className="flex items-center gap-2">
            <TierBadge tier={job.tier} />
            <StatusBadge status={job.status} />
          </div>
          <SheetTitle>{job.summary}</SheetTitle>
          <SheetDescription>
            Created {formatWhen(job.createdAt)}
            {job.finishedAt && ` · finished ${formatWhen(job.finishedAt)}`}
            {/* AP-08: the ticket or change number its approval was given with. */}
            {job.changeId && ` · change ID ${job.changeId}`}
          </SheetDescription>
        </SheetHeader>
        <div className="flex flex-col gap-4 overflow-auto px-4 pb-4">
          {job.bodiesRemoved && (
            <Alert>
              <EraserIcon />
              <AlertTitle>Outputs removed</AlertTitle>
              <AlertDescription className="flex items-center gap-1">
                Older than the retention period: its targets, results and audit entries are kept.
                <HelpTip topic="retention" />
              </AlertDescription>
            </Alert>
          )}
          {!job.bodiesRemoved && job.commandRedacted && (
            <Alert>
              <EraserIcon />
              <AlertTitle>Secret redacted</AlertTitle>
              <AlertDescription>The command held something like a password; it's kept as [redacted].</AlertDescription>
            </Alert>
          )}
          {safety.map((name) => (
            <Alert key={name}>
              <CameraIcon />
              <AlertTitle className="flex items-center gap-1">
                <Term id="safetySnapshot" /> taken first
              </AlertTitle>
              <AlertDescription>
                <p className="font-mono text-xs break-all">{name}</p>
                <p>Revert to it from the VM's snapshots to undo this job.</p>
              </AlertDescription>
            </Alert>
          ))}
          {error && <p className="text-sm text-destructive">{error}</p>}
          {targets && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Target</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead className="text-right">Took</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {targets.map((t) => (
                  <TableRow key={t.targetKey}>
                    <TableCell className="whitespace-normal">
                      <div className="font-medium">{t.targetName}</div>
                      {t.error && <div className="text-xs text-destructive">{t.error}</div>}
                      {t.safetySnapshot && (
                        <Badge variant="outline" className="mt-1 font-normal">
                          <CameraIcon />
                          Safety snapshot
                        </Badge>
                      )}
                      {t.output && (
                        <pre className="mt-1 max-h-32 overflow-auto rounded bg-muted p-2 font-mono text-xs whitespace-pre-wrap">
                          {t.output}
                        </pre>
                      )}
                      {t.stderr && (
                        <pre className="mt-1 max-h-32 overflow-auto rounded border border-destructive/30 bg-destructive/5 p-2 font-mono text-xs whitespace-pre-wrap">
                          {t.stderr}
                        </pre>
                      )}
                      {t.exitCode !== null && (
                        <div className="mt-1 text-xs text-muted-foreground">Exit code {t.exitCode}</div>
                      )}
                    </TableCell>
                    <TableCell>{TARGET_STATUS[t.status]}</TableCell>
                    <TableCell className="text-right text-muted-foreground tabular-nums">
                      {t.durationMs != null ? `${(t.durationMs / 1000).toFixed(1)} s` : "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

const TARGET_STATUS: Record<JobTarget["status"], string> = {
  pending: "Waiting",
  running: "Running",
  succeeded: "Succeeded",
  failed: "Failed",
  skipped: "Not started",
  cancelled: "Cancelled",
  unknown: "Outcome unknown",
};
