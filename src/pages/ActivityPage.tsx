// Jobs and audit log (AP-03, AP-05). Open jobs can be cancelled here: a job in its countdown
// touches nothing, and a running job stops targets that have not started.

import { useEffect, useState } from "react";
import { ListChecksIcon, ScrollTextIcon, ShieldCheckIcon, ShieldXIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { StatusBadge, TierBadge } from "@/components/Badges";
import { api, errorMessage, type AuditEntry, type ChainCheck, type JobSummary } from "@/lib/api";

const OPEN = new Set(["queued", "countdown", "running"]);

function when(ts: string | null) {
  return ts ? new Date(ts).toLocaleString() : "—";
}

export function ActivityPage({ version }: { version: number }) {
  const [jobs, setJobs] = useState<JobSummary[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [check, setCheck] = useState<ChainCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloads, setReloads] = useState(0);

  // `version` changes on every job event, so the lists stay current.
  useEffect(() => {
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
  }, [version, reloads]);

  async function verify() {
    try {
      setCheck(await api.verifyAudit());
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function cancel(jobId: string) {
    await api.cancelJob(jobId);
    setReloads((n) => n + 1);
  }

  return (
    <div className="flex flex-col gap-6">
      {error && (
        <Alert variant="destructive">
          <AlertTitle>Could not load activity</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Jobs</CardTitle>
          <CardDescription>Every action on VMs and hosts, newest first.</CardDescription>
        </CardHeader>
        <CardContent>
          {jobs.length === 0 ? (
            <Empty>
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <ListChecksIcon />
                </EmptyMedia>
                <EmptyTitle>No jobs yet</EmptyTitle>
                <EmptyDescription>Actions you run on VMs and hosts show up here.</EmptyDescription>
              </EmptyHeader>
            </Empty>
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
                {jobs.map((job) => (
                  <TableRow key={job.id}>
                    <TableCell className="font-medium">{job.summary}</TableCell>
                    <TableCell>
                      <TierBadge tier={job.tier} />
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={job.status} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {job.targetsSucceeded}/{job.targetsTotal}
                      {job.targetsFailed > 0 && <span className="text-destructive"> · {job.targetsFailed} failed</span>}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{when(job.createdAt)}</TableCell>
                    <TableCell className="text-right">
                      {OPEN.has(job.status) && (
                        <Button size="sm" variant="destructive" onClick={() => void cancel(job.id)}>
                          Cancel
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Audit log</CardTitle>
          <CardDescription>Append-only and hash-chained, so any edit shows up when you verify it.</CardDescription>
          <CardAction>
            <Button variant="outline" onClick={() => void verify()}>
              Verify the hash chain
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
            <Empty>
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <ScrollTextIcon />
                </EmptyMedia>
                <EmptyTitle>The audit log is empty</EmptyTitle>
                <EmptyDescription>
                  Every state-changing action is logged when it starts and when it ends.
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
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
                    <TableCell className="text-muted-foreground">{when(e.ts)}</TableCell>
                    <TableCell className="font-mono text-xs">{e.event}</TableCell>
                    <TableCell>{e.action}</TableCell>
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
    </div>
  );
}
