// FD-09: the Toolbox's Ping, Trace route, DNS lookup and Check ports tabs. Each reads only: nothing here goes through
// the approval rules, and each works while presenting with the read-only lock. One filled button per tab: its run.

import { useState } from "react";
import { ActivityIcon, NetworkIcon, RouteIcon, SearchIcon, SquareIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { HelpTip } from "@/components/HelpTip";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useProbeRun } from "@/hooks/use-probe-run";
import {
  dnsFailureText,
  dnsServerText,
  echoText,
  hasTarget,
  hopTimes,
  pingSummaryText,
  portStateText,
  probeTarget,
  rttText,
  type ToolTarget,
} from "@/lib/toolbox";
import {
  RECORD_TYPES,
  toolboxApi,
  type DnsResult,
  type PingReply,
  type PingSummary,
  type PortResult,
  type PortSummary,
  type RecordType,
  type TraceHop,
  type TraceSummary,
} from "@/lib/toolbox-api";
import { Field, RunError, TargetField, useRecent } from "./TargetField";

/** A session, VM or host handed over from a row, counted so the same one again still arrives. */
export interface Incoming {
  target: ToolTarget;
  n: number;
}

const EMPTY: ToolTarget = { kind: "address", host: "" };

/** The target, taking each new one a row hands over. */
function useTarget(incoming: Incoming | null): [ToolTarget, (t: ToolTarget) => void] {
  const [target, setTarget] = useState<ToolTarget>(incoming?.target ?? EMPTY);
  const [handled, setHandled] = useState(incoming?.n ?? 0);
  if (incoming && incoming.n !== handled) {
    setHandled(incoming.n);
    setTarget(incoming.target);
  }
  return [target, setTarget];
}

function numberOr(text: string, fallback: number): number {
  const n = Number(text);
  return Number.isFinite(n) && text.trim() !== "" ? n : fallback;
}

function RunButtons({
  label,
  icon: Icon,
  running,
  reason,
  onRun,
  onStop,
}: {
  label: string;
  icon: typeof ActivityIcon;
  running: boolean;
  reason: string | null;
  onRun: () => void;
  onStop?: () => void;
}) {
  return (
    <div className="flex items-end gap-2">
      <WhyDisabled reason={running ? null : reason}>
        <Button onClick={onRun} disabled={running || reason !== null}>
          <Icon data-icon="inline-start" />
          {label}
        </Button>
      </WhyDisabled>
      {running && onStop && (
        <Button variant="outline" onClick={onStop}>
          <SquareIcon data-icon="inline-start" />
          Stop
        </Button>
      )}
    </div>
  );
}

// ---- Ping ----

export function PingTool({ incoming }: { incoming: Incoming | null }) {
  const [target, setTarget] = useTarget(incoming);
  const [recent, remember] = useRecent("ping");
  const [count, setCount] = useState("4");
  const [size, setSize] = useState("32");
  const run = useProbeRun<PingSummary>();
  const replies: PingReply[] = run.result
    ? run.result.replies
    : run.progress.flatMap((p) => (p.kind === "ping" ? [p.reply] : []));
  const ping = () => {
    if (!hasTarget(target)) return;
    if (target.kind === "address") remember(target.host);
    void run.start((id) =>
      toolboxApi.ping(id, {
        target: probeTarget(target),
        count: Math.min(Math.max(numberOr(count, 4), 1), 1000),
        intervalMs: 1000,
        size: Math.min(Math.max(numberOr(size, 32), 0), 65500),
        timeoutMs: 2000,
      }),
    );
  };
  return (
    <div className="flex max-w-4xl flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_7rem_7rem_auto] sm:items-end">
        <Field label="Host" htmlFor="ping-target">
          <TargetField id="ping-target" target={target} onChange={setTarget} onSubmit={ping} recent={recent} />
        </Field>
        <Field label="Requests" htmlFor="ping-count">
          <Input id="ping-count" inputMode="numeric" value={count} onChange={(e) => setCount(e.target.value)} />
        </Field>
        <Field label="Bytes" htmlFor="ping-size">
          <Input id="ping-size" inputMode="numeric" value={size} onChange={(e) => setSize(e.target.value)} />
        </Field>
        <RunButtons
          label="Ping"
          icon={ActivityIcon}
          running={run.running}
          reason={hasTarget(target) ? null : "Choose a host first"}
          onRun={ping}
          onStop={run.stop}
        />
      </div>
      <RunError error={run.error} />
      {replies.length > 0 && (
        <div className="rounded-lg border">
          <Table>
            <TableBody>
              {replies.map((r) => (
                <TableRow key={r.seq}>
                  <TableCell className="w-12 text-muted-foreground">{r.seq}</TableCell>
                  <TableCell className="font-mono text-xs">{echoText(r.echo)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {run.result && (
        <p className="text-sm" role="status">
          {run.result.label !== run.result.address ? `${run.result.label} (${run.result.address}): ` : ""}
          {pingSummaryText(run.result)}
          {run.result.cancelled ? " · stopped" : ""}
        </p>
      )}
    </div>
  );
}

// ---- Trace route ----

export function TraceTool({ incoming }: { incoming: Incoming | null }) {
  const [target, setTarget] = useTarget(incoming);
  const [recent, remember] = useRecent("trace");
  const [names, setNames] = useState(false);
  const run = useProbeRun<TraceSummary>();
  const hops: TraceHop[] = run.result
    ? run.result.hops
    : run.progress.flatMap((p) => (p.kind === "hop" ? [p.hop] : []));
  const trace = () => {
    if (!hasTarget(target)) return;
    if (target.kind === "address") remember(target.host);
    void run.start((id) =>
      toolboxApi.trace(id, { target: probeTarget(target), maxHops: 30, timeoutMs: 2000, resolveNames: names }),
    );
  };
  return (
    <div className="flex max-w-4xl flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:items-end">
        <Field label="Host" htmlFor="trace-target">
          <TargetField id="trace-target" target={target} onChange={setTarget} onSubmit={trace} recent={recent} />
        </Field>
        <label className="flex h-9 items-center gap-2 text-sm">
          <Checkbox checked={names} onCheckedChange={(v) => setNames(v === true)} />
          Look up names
        </label>
        <RunButtons
          label="Trace"
          icon={RouteIcon}
          running={run.running}
          reason={hasTarget(target) ? null : "Choose a host first"}
          onRun={trace}
          onStop={run.stop}
        />
      </div>
      <RunError error={run.error} />
      {hops.length > 0 && (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12">Hop</TableHead>
                <TableHead>Address</TableHead>
                <TableHead>Times</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {hops.map((h) => (
                <TableRow key={h.hop}>
                  <TableCell className="text-muted-foreground">{h.hop}</TableCell>
                  <TableCell className="font-mono text-xs whitespace-normal">
                    {h.address ?? "No answer"}
                    {h.name && <span className="text-muted-foreground"> ({h.name})</span>}
                    {h.note && <span className="text-destructive"> · {h.note}</span>}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{hopTimes(h)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {run.result && (
        <p className="text-sm" role="status">
          {run.result.reached
            ? `Reached ${run.result.address} in ${run.result.hops.length} hops.`
            : run.result.cancelled
              ? "Stopped."
              : `${run.result.address} didn't answer within ${run.result.hops.length} hops.`}
        </p>
      )}
    </div>
  );
}

// ---- DNS lookup ----

export function DnsTool() {
  const [name, setName] = useState("");
  const [type, setType] = useState<RecordType>("A");
  const [server, setServer] = useState("");
  const [recent, remember] = useRecent("dns");
  const run = useProbeRun<DnsResult>();
  const lookUp = () => {
    if (!name.trim()) return;
    remember(name);
    void run.start(() =>
      toolboxApi.dns({ name: name.trim(), recordType: type, server: server.trim() ? server.trim() : null }),
    );
  };
  const result = run.result;
  return (
    <div className="flex max-w-4xl flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_7rem_12rem_auto] sm:items-end">
        <Field label={type === "PTR" ? "IP address or name" : "Name"} htmlFor="dns-name">
          <Input
            id="dns-name"
            data-mask="host"
            list="dns-name-recent"
            autoComplete="off"
            spellCheck={false}
            placeholder="web01.example.com"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") lookUp();
            }}
          />
          <datalist id="dns-name-recent">
            {recent.map((v) => (
              <option key={v} value={v} />
            ))}
          </datalist>
        </Field>
        <Field label="Type" htmlFor="dns-type">
          <Select value={type} onValueChange={(v) => setType(v as RecordType)}>
            <SelectTrigger id="dns-type" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {RECORD_TYPES.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <Field label="Server" htmlFor="dns-server">
          <Input
            id="dns-server"
            data-mask="ip"
            autoComplete="off"
            spellCheck={false}
            placeholder="Windows' resolver"
            value={server}
            onChange={(e) => setServer(e.target.value)}
          />
        </Field>
        <RunButtons
          label="Look up"
          icon={SearchIcon}
          running={run.running}
          reason={name.trim() ? null : "Type a name first"}
          onRun={lookUp}
        />
      </div>
      <RunError error={run.error} />
      {result && (
        <>
          {result.failure ? (
            <p className="text-sm text-destructive" role="status">
              {dnsFailureText(result.failure)}
            </p>
          ) : (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead className="w-20">Type</TableHead>
                    <TableHead className="w-20">TTL</TableHead>
                    <TableHead>Data</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.records.map((r, i) => (
                    <TableRow key={`${r.name}-${r.recordType}-${i}`}>
                      <TableCell className="font-mono text-xs whitespace-normal">{r.name}</TableCell>
                      <TableCell>{r.recordType}</TableCell>
                      <TableCell>{r.ttl} s</TableCell>
                      <TableCell className="font-mono text-xs break-all whitespace-normal">{r.data}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          <p className="text-sm text-muted-foreground">
            {dnsServerText(result.server)} · {rttText(result.tookMs)}
          </p>
        </>
      )}
    </div>
  );
}

// ---- Check ports ----

function stateClass(state: PortResult["state"]): string {
  return state === "open" ? "text-tier-low" : state === "closed" ? "" : "text-muted-foreground";
}

export function PortsTool({ incoming }: { incoming: Incoming | null }) {
  const [target, setTarget] = useTarget(incoming);
  const [recent, remember] = useRecent("ports");
  const [ports, setPorts] = useState("22, 80, 443");
  const [banner, setBanner] = useState(false);
  const run = useProbeRun<PortSummary>();
  const results: PortResult[] = run.result
    ? run.result.results
    : run.progress.flatMap((p) => (p.kind === "port" ? [p.result] : []));
  const check = () => {
    if (!hasTarget(target)) return;
    if (target.kind === "address") remember(target.host);
    void run.start((id) => toolboxApi.ports(id, { target: probeTarget(target), ports, timeoutMs: 3000, banner }));
  };
  const summary = run.result;
  return (
    <div className="flex max-w-4xl flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto_auto] sm:items-end">
        <Field label="Host" htmlFor="ports-target">
          <TargetField id="ports-target" target={target} onChange={setTarget} onSubmit={check} recent={recent} />
        </Field>
        <Field label="Ports" htmlFor="ports-list">
          <Input
            id="ports-list"
            autoComplete="off"
            spellCheck={false}
            placeholder={target.kind === "session" ? "Empty: the session's port" : "22, 443, 8000-8010"}
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") check();
            }}
          />
        </Field>
        <label className="flex h-9 items-center gap-2 text-sm">
          <Checkbox checked={banner} onCheckedChange={(v) => setBanner(v === true)} />
          Read banners
          <HelpTip topic="toolbox.ports" />
        </label>
        <RunButtons
          label="Check"
          icon={NetworkIcon}
          running={run.running}
          reason={hasTarget(target) ? null : "Choose a host first"}
          onRun={check}
          onStop={run.stop}
        />
      </div>
      <RunError error={run.error} />
      {results.length > 0 && (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-20">Port</TableHead>
                <TableHead className="w-28">State</TableHead>
                <TableHead className="w-24">Time</TableHead>
                <TableHead>Banner</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {results.map((r) => (
                <TableRow key={r.port}>
                  <TableCell>{r.port}</TableCell>
                  <TableCell className={stateClass(r.state)}>{portStateText(r.state)}</TableCell>
                  <TableCell>{r.ms !== null ? rttText(r.ms) : ""}</TableCell>
                  <TableCell className="font-mono text-xs break-all whitespace-normal">
                    {r.banner ?? (r.detail && <span className="font-sans text-muted-foreground">{r.detail}</span>)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {summary && (
        <p className="text-sm" role="status">
          {summary.open} of {summary.results.length} open
          {summary.via
            ? ` · checked from the jump host '${summary.via}'`
            : summary.address
              ? ` · ${summary.address}`
              : ""}
          {summary.cancelled ? " · stopped" : ""}
        </p>
      )}
    </div>
  );
}
