// FD-09: the Toolbox's Certificate tab: the certificate a TLS server sends (any chain, so a bad one can be read too),
// checked against Windows' trust store and the server name, or a certificate file. A read.

import { useState } from "react";
import { FileBadgeIcon, ShieldCheckIcon, ShieldXIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table";
import { HelpTip } from "@/components/HelpTip";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useProbeRun } from "@/hooks/use-probe-run";
import { certificateVerdict, daysLeftText, hasTarget, probeTarget, type ToolTarget } from "@/lib/toolbox";
import { toolboxApi, type CertificateInfo, type CertificateReport } from "@/lib/toolbox-api";
import type { Incoming } from "./ProbeTools";
import { Field, RunError, TargetField, useRecent } from "./TargetField";

function dateText(rfc3339: string): string {
  const at = new Date(rfc3339);
  return Number.isNaN(at.getTime()) ? rfc3339 : at.toLocaleString();
}

function Details({ cert }: { cert: CertificateInfo }) {
  const rows: [string, string][] = [
    ["Subject", cert.subject],
    ["Alternative names", cert.alternativeNames.join(", ") || "None"],
    ["Issuer", cert.selfIssued ? `${cert.issuer} (itself)` : cert.issuer],
    ["Valid", `${dateText(cert.notBefore)} to ${dateText(cert.notAfter)}`],
    ["Key", cert.key],
    ["Signature", cert.signatureAlgorithm],
    ["Serial number", cert.serial],
    ["SHA-256", cert.sha256],
    ["SHA-1", cert.sha1],
  ];
  if (cert.isCa) rows.push(["Can issue certificates", "Yes"]);
  return (
    <div className="rounded-lg border">
      <Table>
        <TableBody>
          {rows.map(([label, value]) => (
            <TableRow key={label}>
              <TableCell className="w-44 align-top text-muted-foreground">{label}</TableCell>
              <TableCell className="font-mono text-xs break-all whitespace-normal">{value}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function Report({ report }: { report: CertificateReport }) {
  const verdict = certificateVerdict(report);
  const leaf = report.chain[0];
  const Icon = verdict.ok ? ShieldCheckIcon : ShieldXIcon;
  return (
    <div className="flex flex-col gap-3">
      <div className="grid gap-1">
        <p
          className={
            verdict.ok ? "flex items-center gap-2 text-sm" : "flex items-center gap-2 text-sm text-destructive"
          }
          role="status"
        >
          <Icon className="size-4 shrink-0" aria-hidden />
          {verdict.text}
        </p>
        <p className="text-sm text-muted-foreground">
          {report.source}
          {report.via ? ` · read from the jump host '${report.via}'` : ""}
          {report.protocol ? ` · ${report.protocol}` : ""}
          {verdict.ok ? "" : report.daysLeft !== null ? ` · ${daysLeftText(report.daysLeft)}` : ""}
        </p>
        {report.trustProblems.map((p) => (
          <p key={p} className="text-sm text-muted-foreground">
            {p.charAt(0).toUpperCase() + p.slice(1)}
            {/[.!?]$/.test(p) ? "" : "."}
          </p>
        ))}
        {report.handshakeError && (
          <p className="text-sm text-muted-foreground">
            The handshake failed after the certificate: {report.handshakeError}
          </p>
        )}
        {report.unreadable.map((note) => (
          <p key={note} className="text-sm text-muted-foreground">
            Couldn&apos;t read {note}
          </p>
        ))}
      </div>
      {leaf && <Details cert={leaf} />}
      {report.chain.length > 1 && (
        <div className="grid gap-1 text-sm">
          <p className="font-medium">Sent with it</p>
          {report.chain.slice(1).map((c, i) => (
            <p key={`${c.sha256}-${i}`} className="font-mono text-xs break-all text-muted-foreground">
              {c.subject}
            </p>
          ))}
        </div>
      )}
      {report.built.length > 0 && (
        <div className="grid gap-1 text-sm">
          <p className="font-medium">The chain Windows built</p>
          {report.built.map((subject, i) => (
            <p key={`${subject}-${i}`} className="font-mono text-xs break-all text-muted-foreground">
              {"  ".repeat(i)}
              {subject}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

export function CertificateTool({ incoming }: { incoming: Incoming | null }) {
  const [target, setTarget] = useState<ToolTarget>(incoming?.target ?? { kind: "address", host: "" });
  const [handled, setHandled] = useState(incoming?.n ?? 0);
  if (incoming && incoming.n !== handled) {
    setHandled(incoming.n);
    setTarget(incoming.target);
  }
  const [recent, remember] = useRecent("certificate");
  const [port, setPort] = useState("443");
  const [serverName, setServerName] = useState("");
  const run = useProbeRun<CertificateReport>();
  const portNumber = Number(port);
  const portOk = Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= 65535;
  const reason = !hasTarget(target) ? "Choose a host first" : !portOk ? "Type a port from 1 to 65535" : null;
  const read = () => {
    if (reason) return;
    if (target.kind === "address") remember(target.host);
    void run.start((id) =>
      toolboxApi.certificate(id, {
        target: probeTarget(target),
        port: portNumber,
        serverName: serverName.trim() || null,
        timeoutMs: 10000,
      }),
    );
  };
  const openFile = () =>
    void run.start(async () => {
      const report = await toolboxApi.certificateFile();
      if (!report) throw new Error("No file was chosen.");
      return report;
    });
  return (
    <div className="flex max-w-4xl flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_6rem_minmax(0,1fr)_auto] sm:items-end">
        <Field label="Host" htmlFor="cert-target">
          <TargetField id="cert-target" target={target} onChange={setTarget} onSubmit={read} recent={recent} />
        </Field>
        <Field label="Port" htmlFor="cert-port">
          <Input id="cert-port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} />
        </Field>
        <div className="grid gap-1.5">
          <span className="flex items-center gap-1 text-sm font-medium">
            <label htmlFor="cert-name">Server name</label>
            <HelpTip topic="toolbox.certificate" />
          </span>
          <Input
            id="cert-name"
            data-mask="host"
            autoComplete="off"
            spellCheck={false}
            placeholder="The host"
            value={serverName}
            onChange={(e) => setServerName(e.target.value)}
          />
        </div>
        <div className="flex items-end gap-2">
          <WhyDisabled reason={run.running ? null : reason}>
            <Button onClick={read} disabled={run.running || reason !== null}>
              <ShieldCheckIcon data-icon="inline-start" />
              {run.running ? "Reading…" : "Read"}
            </Button>
          </WhyDisabled>
          <Button variant="outline" onClick={openFile} disabled={run.running}>
            <FileBadgeIcon data-icon="inline-start" />
            Open a file…
          </Button>
        </div>
      </div>
      <RunError error={run.error === "No file was chosen." ? null : run.error} />
      {run.result && <Report report={run.result} />}
    </div>
  );
}
