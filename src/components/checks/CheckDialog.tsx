// MO-08: a health check's editor: a name, a target (a typed host, a session or a VM), a kind with its own fields,
// and its timing. The core checks everything again and audits the save; while presenting with the read-only lock it
// refuses it.

import { useEffect, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { HelpTip } from "@/components/HelpTip";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type SessionRecord, type VmRecord } from "@/lib/api";
import { checksApi, type CheckInput, type CheckKind, type CheckSpec, type HealthCheck } from "@/lib/checks-api";
import { checkProblem, cleanCheckInput, defaultSpec, everyText, INTERVALS, KINDS, kindTakes } from "@/lib/checks";
import type { ProbeTarget } from "@/lib/toolbox-api";

interface Props {
  /** A new check, prefilled (from a row's "Add a check"), or the check edited. */
  start: { kind: "new"; input: CheckInput } | { kind: "edit"; check: HealthCheck };
  onClose: () => void;
  onSaved: (check: HealthCheck) => void;
}

/** A whole number from a field, or NaN. */
function whole(text: string): number {
  return /^\d+$/.test(text.trim()) ? Number(text.trim()) : Number.NaN;
}

function Field({ id, label, children }: { id: string; label: string; children: ReactNode }) {
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
    </div>
  );
}

function SwitchRow({
  id,
  label,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (on: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-2">
      <Label htmlFor={id} className="font-normal">
        {label}
      </Label>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  );
}

export function CheckDialog({ start, onClose, onSaved }: Props) {
  const editing = start.kind === "edit" ? start.check : null;
  const [input, setInput] = useState<CheckInput>(() => (start.kind === "edit" ? { ...start.check } : start.input));
  // Number fields keep what is typed; they are read when checked.
  const [timeout, setTimeoutText] = useState(String(input.timeoutSecs));
  const [failures, setFailures] = useState(String(input.failuresBeforeDown));
  const [port, setPort] = useState(() => portOf(input.spec));
  const [statusMin, setStatusMin] = useState(() => (input.spec.kind === "http" ? String(input.spec.statusMin) : "200"));
  const [statusMax, setStatusMax] = useState(() => (input.spec.kind === "http" ? String(input.spec.statusMax) : "399"));
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [vms, setVms] = useState<VmRecord[]>([]);
  const [busy, setBusy] = useState(false);
  const readOnly = useReadOnlyReason();

  useEffect(() => {
    Promise.all([api.sessions(), api.vmList()]).then(
      ([s, v]) => {
        setSessions(s);
        setVms(v);
      },
      () => undefined,
    );
  }, []);

  const spec = withNumbers(input.spec, port, statusMin, statusMax);
  const candidate: CheckInput = {
    ...input,
    spec,
    timeoutSecs: whole(timeout),
    failuresBeforeDown: whole(failures),
  };
  // SS-12, F4: a service check reads a systemd unit over SSH or a Windows service over WinRM, so only those sessions are
  // offered for it.
  const serviceOnly = input.spec.kind === "service";
  const servesChecks = (s: SessionRecord) => s.kind.protocol === "ssh" || s.kind.protocol === "winrm";
  const offered = serviceOnly ? sessions.filter(servesChecks) : sessions;
  const chosen = input.target.kind === "session" ? input.target.sessionId : null;
  const chosenSession = chosen === null ? undefined : sessions.find((s) => s.id === chosen);
  const windowsService = chosenSession?.kind.protocol === "winrm";
  const notServed = serviceOnly && chosenSession !== undefined && !servesChecks(chosenSession);
  const problem =
    checkProblem(candidate, windowsService) ??
    (notServed
      ? "A service check reads a systemd unit over SSH or a Windows service over WinRM: choose such a session."
      : null);
  const set = (change: Partial<CheckInput>) => setInput((old) => ({ ...old, ...change }));
  const setSpec = (next: CheckSpec) => setInput((old) => ({ ...old, spec: next }));

  function changeKind(kind: CheckKind) {
    const next = defaultSpec(kind);
    setSpec(next);
    setPort(portOf(next));
  }

  function changeTarget(kind: ProbeTarget["kind"]) {
    const target: ProbeTarget =
      kind === "address"
        ? { kind, host: "" }
        : kind === "session"
          ? { kind, sessionId: (input.spec.kind === "service" ? offered : sessions)[0]?.id ?? "" }
          : { kind, vmKey: vms[0]?.vmxPath ?? "" };
    const usable = kindTakes(input.spec.kind, kind) ? input.spec : defaultSpec("tcp");
    if (usable !== input.spec) setPort(portOf(usable));
    setInput({ ...input, target, spec: usable });
  }

  async function save() {
    setBusy(true);
    try {
      const clean = cleanCheckInput(candidate);
      const saved = editing ? await checksApi.update(editing.id, clean) : await checksApi.create(clean);
      toast.success(editing ? "Check saved" : "Check added");
      onSaved(saved);
      onClose();
    } catch (err) {
      toast.error(errorMessage(err));
      setBusy(false);
    }
  }

  const target = input.target;
  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{editing ? "Edit check" : "Add a check"}</DialogTitle>
          <DialogDescription className="flex items-center gap-1">
            Runs from this PC on a schedule, and alerts you when it goes down.
            <HelpTip topic="checks" />
          </DialogDescription>
        </DialogHeader>
        <div className="grid max-h-[65vh] gap-3 overflow-y-auto px-0.5">
          <Field id="check-name" label="Name">
            <Input
              id="check-name"
              value={input.name}
              maxLength={80}
              placeholder="Web site"
              onChange={(e) => set({ name: e.target.value })}
            />
          </Field>
          <div className="grid grid-cols-[10rem_1fr] gap-3">
            <Field id="check-target-kind" label="On">
              <Select value={target.kind} onValueChange={(v) => changeTarget(v as ProbeTarget["kind"])}>
                <SelectTrigger id="check-target-kind" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="address">A host</SelectItem>
                  <SelectItem value="session">A session</SelectItem>
                  <SelectItem value="vm">A VM</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            {target.kind === "address" && (
              <Field id="check-host" label="Host name or IP address">
                <Input
                  id="check-host"
                  data-mask="host"
                  autoComplete="off"
                  spellCheck={false}
                  value={target.host}
                  placeholder="web01.example.com"
                  onChange={(e) => set({ target: { kind: "address", host: e.target.value } })}
                />
              </Field>
            )}
            {target.kind === "session" && (
              <Field id="check-session" label="Session">
                <Select
                  value={target.sessionId || undefined}
                  onValueChange={(sessionId) => set({ target: { kind: "session", sessionId } })}
                >
                  <SelectTrigger id="check-session" className="w-full">
                    <SelectValue placeholder="Choose a session" />
                  </SelectTrigger>
                  <SelectContent>
                    {offered.map((s) => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
            )}
            {target.kind === "vm" && (
              <Field id="check-vm" label="VM (its guest IP address)">
                <Select
                  value={target.vmKey || undefined}
                  onValueChange={(vmKey) => set({ target: { kind: "vm", vmKey } })}
                >
                  <SelectTrigger id="check-vm" className="w-full">
                    <SelectValue placeholder="Choose a VM" />
                  </SelectTrigger>
                  <SelectContent>
                    {vms.map((vm) => (
                      <SelectItem key={vm.vmxPath} value={vm.vmxPath}>
                        {vm.displayName}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
            )}
          </div>
          <Field id="check-kind" label="Check">
            <Select value={input.spec.kind} onValueChange={(v) => changeKind(v as CheckKind)}>
              <SelectTrigger id="check-kind" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {KINDS.filter((k) => kindTakes(k.value, target.kind)).map((k) => (
                  <SelectItem key={k.value} value={k.value}>
                    {k.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">{KINDS.find((k) => k.value === input.spec.kind)?.hint}</p>
          </Field>
          <KindFields spec={input.spec} port={port} setPort={setPort} setSpec={setSpec} windowsService={windowsService}>
            {input.spec.kind === "http" && (
              <div className="grid grid-cols-2 gap-3">
                <Field id="check-status-min" label="Status from">
                  <Input
                    id="check-status-min"
                    inputMode="numeric"
                    value={statusMin}
                    onChange={(e) => setStatusMin(e.target.value)}
                  />
                </Field>
                <Field id="check-status-max" label="Status to">
                  <Input
                    id="check-status-max"
                    inputMode="numeric"
                    value={statusMax}
                    onChange={(e) => setStatusMax(e.target.value)}
                  />
                </Field>
              </div>
            )}
          </KindFields>
          <div className="grid grid-cols-3 gap-3">
            <Field id="check-every" label="Runs">
              <Select value={String(input.intervalSecs)} onValueChange={(v) => set({ intervalSecs: Number(v) })}>
                <SelectTrigger id="check-every" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {[...new Set([...INTERVALS, input.intervalSecs])]
                    .sort((a, b) => a - b)
                    .map((secs) => (
                      <SelectItem key={secs} value={String(secs)}>
                        {everyText(secs)}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </Field>
            <Field id="check-timeout" label="Timeout (s)">
              <Input
                id="check-timeout"
                inputMode="numeric"
                value={timeout}
                onChange={(e) => setTimeoutText(e.target.value)}
              />
            </Field>
            <div className="grid gap-1.5">
              <Label htmlFor="check-failures" className="flex items-center gap-1">
                Down after
                <HelpTip topic="checkTiming" />
              </Label>
              <Input
                id="check-failures"
                inputMode="numeric"
                value={failures}
                aria-describedby="check-failures-unit"
                onChange={(e) => setFailures(e.target.value)}
              />
              <span id="check-failures-unit" className="text-xs text-muted-foreground">
                failed runs in a row
              </span>
            </div>
          </div>
          {problem && (
            <p className="text-xs text-muted-foreground" role="status">
              {problem}
            </p>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={onClose}>
            Cancel
          </Button>
          <WhyDisabled reason={readOnly}>
            <Button disabled={busy || problem !== null || readOnly !== null} onClick={() => void save()}>
              {editing ? "Save" : "Add check"}
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** The port field's text for a kind that has one. */
function portOf(spec: CheckSpec): string {
  switch (spec.kind) {
    case "tcp":
    case "certificate":
      return String(spec.port);
    case "http":
      return spec.port === null ? "" : String(spec.port);
    default:
      return "";
  }
}

/** The spec with the typed numbers in it (NaN where they aren't numbers, so the check refuses them). */
function withNumbers(spec: CheckSpec, port: string, statusMin: string, statusMax: string): CheckSpec {
  switch (spec.kind) {
    case "tcp":
    case "certificate":
      return { ...spec, port: whole(port) };
    case "http":
      return {
        ...spec,
        port: port.trim() === "" ? null : whole(port),
        statusMin: whole(statusMin),
        statusMax: whole(statusMax),
      };
    default:
      return spec;
  }
}

function KindFields({
  spec,
  port,
  setPort,
  setSpec,
  windowsService,
  children,
}: {
  spec: CheckSpec;
  port: string;
  setPort: (port: string) => void;
  setSpec: (spec: CheckSpec) => void;
  /** F4: the session is a WinRM one: the service is a Windows service. */
  windowsService: boolean;
  children?: ReactNode;
}) {
  const portField = (placeholder?: string) => (
    <Field id="check-port" label="Port">
      <Input
        id="check-port"
        inputMode="numeric"
        value={port}
        placeholder={placeholder}
        onChange={(e) => setPort(e.target.value)}
      />
    </Field>
  );
  switch (spec.kind) {
    case "ping":
      return null;
    case "tcp":
      return portField();
    case "http":
      return (
        <div className="grid gap-3">
          <div className="grid grid-cols-[1fr_7rem] gap-3">
            <Field id="check-path" label="Path">
              <Input
                id="check-path"
                spellCheck={false}
                value={spec.path}
                placeholder="/health"
                onChange={(e) => setSpec({ ...spec, path: e.target.value })}
              />
            </Field>
            {portField(spec.https ? "443" : "80")}
          </div>
          <SwitchRow
            id="check-https"
            label="HTTPS"
            checked={spec.https}
            onChange={(https) => setSpec({ ...spec, https, allowInvalidCert: https && spec.allowInvalidCert })}
          />
          {children}
          <Field id="check-body" label="Text the page must hold (optional)">
            <Input
              id="check-body"
              maxLength={200}
              value={spec.bodyContains ?? ""}
              onChange={(e) => setSpec({ ...spec, bodyContains: e.target.value })}
            />
          </Field>
          <SwitchRow
            id="check-redirects"
            label="Follow redirects"
            checked={spec.followRedirects}
            onChange={(followRedirects) => setSpec({ ...spec, followRedirects })}
          />
          {spec.https && (
            <SwitchRow
              id="check-cert-errors"
              label="Allow certificate errors"
              checked={spec.allowInvalidCert}
              onChange={(allowInvalidCert) => setSpec({ ...spec, allowInvalidCert })}
            />
          )}
        </div>
      );
    case "certificate":
      return (
        <div className="grid gap-3">
          <div className="grid grid-cols-[1fr_7rem] gap-3">
            <Field id="check-server-name" label="Name to check (optional)">
              <Input
                id="check-server-name"
                data-mask="host"
                spellCheck={false}
                value={spec.serverName ?? ""}
                placeholder="The host's name"
                onChange={(e) => setSpec({ ...spec, serverName: e.target.value })}
              />
            </Field>
            {portField()}
          </div>
          <SwitchRow
            id="check-untrusted"
            label="Allow a certificate Windows doesn't trust"
            checked={spec.allowUntrusted}
            onChange={(allowUntrusted) => setSpec({ ...spec, allowUntrusted })}
          />
        </div>
      );
    case "dns":
      return (
        <div className="grid grid-cols-3 gap-3">
          <Field id="check-record" label="Record">
            <Select
              value={spec.recordType}
              onValueChange={(v) => setSpec({ ...spec, recordType: v === "AAAA" ? "AAAA" : "A" })}
            >
              <SelectTrigger id="check-record" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="A">A</SelectItem>
                <SelectItem value="AAAA">AAAA</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field id="check-expect" label="Expected address">
            <Input
              id="check-expect"
              data-mask="ip"
              spellCheck={false}
              value={spec.expect ?? ""}
              placeholder="Any"
              onChange={(e) => setSpec({ ...spec, expect: e.target.value })}
            />
          </Field>
          <Field id="check-dns-server" label="DNS server">
            <Input
              id="check-dns-server"
              data-mask="ip"
              spellCheck={false}
              value={spec.server ?? ""}
              placeholder="Windows'"
              onChange={(e) => setSpec({ ...spec, server: e.target.value })}
            />
          </Field>
        </div>
      );
    case "service":
      return (
        <Field id="check-unit" label={windowsService ? "Windows service" : "systemd unit"}>
          <Input
            id="check-unit"
            spellCheck={false}
            value={spec.unit}
            placeholder={windowsService ? "Spooler" : "nginx.service"}
            onChange={(e) => setSpec({ ...spec, unit: e.target.value })}
          />
        </Field>
      );
  }
}
