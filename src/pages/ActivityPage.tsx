// Jobs and audit log (AP-03, AP-05, VM-05). Open jobs can be cancelled here: a job in its countdown
// shows the time left and touches nothing if cancelled, and a running job stops targets that have
// not started and stops waiting for VM power actions in progress (Workstation or VirtualBox may still finish
// those). A job's results show each target's outcome and the safety snapshot taken on it. The audit
// log can be verified and exported to CSV. BX-02: a job older than the retention period (Settings, General) keeps its
// results but no longer its outputs or command text, which its results say.
//
// P6, AP-03: job events come in bursts (a MultiExec line on 50 terminals sends about 100), so they reach the lists
// through one path. App bumps `version` only when a job is queued or ends; while this page shows, a job's progress
// (its countdown, its start, each target's result) asks too. Asks within a second of the first are one reload, a
// second later (PROGRESS_READ_MS), so the lists are read at most once a second, and never per event. Nothing is read
// while the page is hidden; showing it reads once.

import { useCallback, useEffect, useRef, useState } from "react";
import {
  CameraIcon,
  DownloadIcon,
  EraserIcon,
  ListChecksIcon,
  ScrollTextIcon,
  ShieldCheckIcon,
  ShieldXIcon,
} from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { StatusBadge, TierBadge } from "@/components/Badges";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { api, errorMessage, type AuditEntry, type ChainCheck, type JobSummary, type JobTarget } from "@/lib/api";
import { formatWhen, plural } from "@/lib/format";
import { progressesJob, PROGRESS_READ_MS } from "@/lib/job-events";

const OPEN = new Set(["queued", "countdown", "running"]);

/** Seconds left in a job's countdown, or null when it has none. */
function secondsLeft(job: JobSummary, now: number) {
  if (job.status !== "countdown" || !job.countdownUntil) return null;
  return Math.max(0, Math.ceil((new Date(job.countdownUntil).getTime() - now) / 1000));
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
    Promise.all([api.recentJobs(50), api.recentAudit(100)]).then(
      ([j, a]) => {
        if (stale) return;
        setJobs(j);
        setAudit(a);
        setError(null);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [asked, reloads, active]);

  // AP-03: the time left ticks while a job is in its countdown.
  useEffect(() => {
    if (!counting) return;
    const timer = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(timer);
  }, [counting]);

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

  return (
    <div className="flex flex-col gap-6">
      <PageHeader page="activity" />
      {error && (
        <Alert variant="destructive">
          <AlertTitle>Could not load activity</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Jobs</CardTitle>
          <CardDescription>
            Every action on VMs and hosts, newest first. Open a job to see each target&apos;s result.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {jobs.length === 0 ? (
            <EmptyState
              bordered={false}
              icon={ListChecksIcon}
              title="No jobs yet"
              description="Actions you run on VMs and hosts show up here."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Action</TableHead>
                  <TableHead>Tier</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Targets</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {jobs.map((job) => {
                  const left = secondsLeft(job, now);
                  return (
                    <TableRow key={job.id} className="cursor-pointer" onClick={() => setOpenedId(job.id)}>
                      <TableCell className="font-medium whitespace-normal">{job.summary}</TableCell>
                      <TableCell>
                        <TierBadge tier={job.tier} />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <StatusBadge status={job.status} />
                          {left !== null && (
                            <span className="text-sm text-tier-high tabular-nums" role="timer">
                              starts in {left} s
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-right tabular-nums">
                        {job.targetsSucceeded}/{job.targetsTotal}
                        {job.targetsFailed > 0 && (
                          <span className="text-destructive"> · {job.targetsFailed} failed</span>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{formatWhen(job.createdAt)}</TableCell>
                      <TableCell className="text-right">
                        {OPEN.has(job.status) && (
                          <Button
                            size="sm"
                            variant="destructive"
                            title={
                              job.status === "running"
                                ? "Stops the targets that have not started and stops waiting for VM power actions in progress; Workstation or VirtualBox may still finish those. A snapshot in progress finishes."
                                : "Nothing has been done yet; no target is touched"
                            }
                            onClick={(e) => {
                              e.stopPropagation();
                              void cancel(job.id);
                            }}
                          >
                            Cancel
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Audit log</CardTitle>
          <CardDescription>
            Append-only and hash-chained, so any edit shows up when you verify it. The CSV export holds every entry with
            its hashes, and never a password or key.
          </CardDescription>
          <CardAction className="flex gap-2">
            <Button variant="outline" onClick={() => void verify()}>
              Verify the hash chain
            </Button>
            <Button variant="outline" onClick={() => void exportCsv()} disabled={exporting}>
              <DownloadIcon data-icon="inline-start" />
              {exporting ? "Exporting…" : "Export CSV…"}
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
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
          {audit.length === 0 ? (
            <EmptyState
              bordered={false}
              icon={ScrollTextIcon}
              title="The audit log is empty"
              description="Every change is logged when it starts and when it ends."
              help="auditLog"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12 text-right">#</TableHead>
                  <TableHead>Time</TableHead>
                  <TableHead>Event</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Tier</TableHead>
                  <TableHead>Result</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {audit.map((e) => (
                  <TableRow key={e.id} title={e.detail ?? undefined}>
                    <TableCell className="text-right text-muted-foreground tabular-nums">{e.seq}</TableCell>
                    <TableCell className="text-muted-foreground">{formatWhen(e.ts)}</TableCell>
                    <TableCell className="font-mono text-xs">{e.event}</TableCell>
                    <TableCell className="whitespace-normal">{e.action}</TableCell>
                    <TableCell>
                      {e.tier ? <TierBadge tier={e.tier} /> : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell>{e.result ?? <span className="text-muted-foreground">—</span>}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {opened && <JobResults job={opened} version={asked + reloads} onClose={() => setOpenedId(null)} />}
    </div>
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
              <AlertDescription>
                This job is older than the retention period set in Settings, General, so its outputs and its script or
                line text were removed. Its targets, results and audit entries are kept.
              </AlertDescription>
            </Alert>
          )}
          {!job.bodiesRemoved && job.commandRedacted && (
            <Alert>
              <EraserIcon />
              <AlertTitle>Secret redacted</AlertTitle>
              <AlertDescription>
                The command had something that looked like a password or token. The journal keeps it as [redacted].
              </AlertDescription>
            </Alert>
          )}
          {safety.map((name) => (
            <Alert key={name}>
              <CameraIcon />
              <AlertTitle>Safety snapshot taken first</AlertTitle>
              <AlertDescription>
                <p className="font-mono text-xs break-all">{name}</p>
                <p>Revert to it on the Snapshots page to undo this job.</p>
              </AlertDescription>
            </Alert>
          ))}
          {error && <p className="text-sm text-destructive">{error}</p>}
          {targets && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Target</TableHead>
                  <TableHead>Status</TableHead>
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
                        <div className="mt-1 text-xs text-muted-foreground">exit code {t.exitCode}</div>
                      )}
                    </TableCell>
                    <TableCell className="capitalize">
                      {t.status === "unknown" ? "Outcome unknown" : t.status}
                    </TableCell>
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
