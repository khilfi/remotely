// FD-09: the Toolbox's File server tab: TFTP and HTTP from one file or folder of this PC, on one of its addresses, for a
// time limit; with "Accept uploads" on, other computers can also send files into one empty folder. Starting is a
// command on the bus (Medium serving, High with uploads), refused by the read-only lock; the server stops at its time
// limit, on Stop, when another workspace opens, the vault locks, the window reloads or Remotely closes. While it runs
// (and after it stopped) the tab lists the requests, newest first.

import { useCallback, useEffect, useState } from "react";
import { CopyIcon, FileIcon, FolderIcon, PlayIcon, SquareIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { HelpTip } from "@/components/HelpTip";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type SubmitOutcome } from "@/lib/api";
import {
  countsText,
  endText,
  initialForm,
  listeningText,
  minutesText,
  outcomeText,
  requestText,
  requestTime,
  sizeText,
  specOf,
  startReason,
  TIME_LIMITS,
  type FileServerForm,
} from "@/lib/file-server";
import { fileServerApi, type PickFor, type ServeAddress, type ServerStatus } from "@/lib/file-server-api";
import { cn } from "@/lib/utils";
import { Field, RunError } from "./TargetField";

export function FileServerTool({
  shown,
  onSubmitted,
}: {
  /** The tab shows: the addresses and the status are read then. */
  shown: boolean;
  onSubmitted: (outcome: SubmitOutcome) => void;
}) {
  const [addresses, setAddresses] = useState<ServeAddress[] | null>(null);
  const [form, setForm] = useState<FileServerForm | null>(null);
  const [status, setStatus] = useState<ServerStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const readOnly = useReadOnlyReason();

  const refresh = useCallback(() => {
    fileServerApi.status().then(setStatus, (err) => setError(errorMessage(err)));
  }, []);

  // The addresses and last choices, read each time the tab shows (an adapter may have come or gone).
  useEffect(() => {
    if (!shown) return;
    let gone = false;
    fileServerApi.options().then(
      (options) => {
        if (gone) return;
        setAddresses(options.addresses);
        setStatus(options.status);
        setForm((current) => {
          if (!current) return initialForm(options.last, options.addresses);
          // The chosen address may be gone now.
          return options.addresses.some((a) => a.address === current.address)
            ? current
            : { ...current, address: options.addresses.find((a) => !a.loopback)?.address ?? "" };
        });
      },
      (err) => {
        if (!gone) setError(errorMessage(err));
      },
    );
    return () => {
      gone = true;
    };
  }, [shown]);

  // Started, requests came in, stopped: read the status again (the core sends these a few times a second at most).
  useEffect(() => {
    const unlisten = fileServerApi.onEvent(() => refresh());
    return () => {
      void unlisten.then((stop) => stop());
    };
  }, [refresh]);

  // "Stops at 14:30 (in 12 minutes)" keeps up while it runs.
  const [, setTick] = useState(0);
  const running = status?.running ?? false;
  useEffect(() => {
    if (!running || !shown) return;
    const timer = window.setInterval(() => setTick((n) => n + 1), 30_000);
    return () => window.clearInterval(timer);
  }, [running, shown]);

  const update = (change: Partial<FileServerForm>) =>
    setForm((current) => (current ? { ...current, ...change } : current));

  const pick = async (purpose: PickFor) => {
    if (!form) return;
    setError(null);
    try {
      const current = purpose === "uploads" ? form.uploadFolder : form.root;
      const chosen = await fileServerApi.pick(purpose, current || null);
      if (!chosen) return;
      if (purpose === "uploads") update({ uploadFolder: chosen });
      else update({ root: chosen, folder: purpose === "folder" });
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  const start = async () => {
    if (!form || startReason(form) || readOnly) return;
    setBusy(true);
    setError(null);
    try {
      onSubmitted(await fileServerApi.start(specOf(form)));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    if (!status) return;
    setBusy(true);
    try {
      await fileServerApi.stop(status.jobId);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (!form || !addresses) {
    return (
      <div className="flex max-w-4xl flex-col gap-4">
        <p className="text-sm text-muted-foreground">Reading this PC's addresses…</p>
        <RunError error={error} />
      </div>
    );
  }

  return (
    <div className="flex max-w-4xl flex-col gap-4">
      {running && status ? (
        <RunningView status={status} busy={busy} onStop={() => void stop()} />
      ) : (
        <ServerForm
          form={form}
          addresses={addresses}
          busy={busy}
          readOnly={readOnly}
          onChange={update}
          onPick={(purpose) => void pick(purpose)}
          onStart={() => void start()}
        />
      )}
      <RunError error={error} />
      {status && <RequestList status={status} />}
    </div>
  );
}

function ServerForm({
  form,
  addresses,
  busy,
  readOnly,
  onChange,
  onPick,
  onStart,
}: {
  form: FileServerForm;
  addresses: ServeAddress[];
  busy: boolean;
  readOnly: string | null;
  onChange: (change: Partial<FileServerForm>) => void;
  onPick: (purpose: PickFor) => void;
  onStart: () => void;
}) {
  const reason = readOnly ?? startReason(form);
  return (
    <>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Serve" htmlFor="fs-root" className="grid gap-1.5 sm:col-span-2">
          <div className="flex flex-wrap items-center gap-2">
            <PathBox id="fs-root" path={form.root} folder={form.folder} empty="Nothing chosen yet" />
            <Button variant="outline" size="sm" onClick={() => onPick("folder")}>
              <FolderIcon data-icon="inline-start" />
              Choose a folder…
            </Button>
            <Button variant="outline" size="sm" onClick={() => onPick("file")}>
              <FileIcon data-icon="inline-start" />
              Choose a file…
            </Button>
          </div>
        </Field>
        <Field label="Address" htmlFor="fs-address">
          <Select value={form.address} onValueChange={(address) => onChange({ address })}>
            <SelectTrigger id="fs-address" className="w-full">
              <SelectValue placeholder="Choose an address of this PC" />
            </SelectTrigger>
            <SelectContent>
              {addresses.map((a) => (
                <SelectItem key={a.address} value={a.address}>
                  {a.name} · {a.address}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <Field label="Time limit" htmlFor="fs-minutes">
          <Select value={String(form.minutes)} onValueChange={(v) => onChange({ minutes: Number(v) })}>
            <SelectTrigger id="fs-minutes" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TIME_LIMITS.map((m) => (
                <SelectItem key={m} value={String(m)}>
                  {minutesText(m)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
        <ProtocolField
          id="fs-tftp"
          label="TFTP"
          on={form.tftp}
          port={form.tftpPort}
          onToggle={(tftp) => onChange({ tftp })}
          onPort={(tftpPort) => onChange({ tftpPort })}
        />
        <ProtocolField
          id="fs-http"
          label="HTTP"
          on={form.http}
          port={form.httpPort}
          onToggle={(http) => onChange({ http })}
          onPort={(httpPort) => onChange({ httpPort })}
        />
      </div>
      <div className="grid gap-3 rounded-lg border p-3">
        <div className="flex items-center gap-2">
          <Switch id="fs-uploads" checked={form.uploads} onCheckedChange={(uploads) => onChange({ uploads })} />
          <label htmlFor="fs-uploads" className="text-sm font-medium">
            Accept uploads
          </label>
          <HelpTip topic="toolbox.fileServer.uploads" />
        </div>
        {form.uploads && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Upload folder" htmlFor="fs-upload-folder" className="grid gap-1.5 sm:col-span-2">
              <div className="flex flex-wrap items-center gap-2">
                <PathBox id="fs-upload-folder" path={form.uploadFolder} folder empty="An empty folder" />
                <Button variant="outline" size="sm" onClick={() => onPick("uploads")}>
                  <FolderIcon data-icon="inline-start" />
                  Choose a folder…
                </Button>
              </div>
            </Field>
            <Field label="Largest file (MB)" htmlFor="fs-max-file">
              <Input
                id="fs-max-file"
                inputMode="numeric"
                value={form.maxFileMb}
                onChange={(e) => onChange({ maxFileMb: e.target.value })}
              />
            </Field>
            <Field label="All uploads (MB)" htmlFor="fs-max-total">
              <Input
                id="fs-max-total"
                inputMode="numeric"
                value={form.maxTotalMb}
                onChange={(e) => onChange({ maxTotalMb: e.target.value })}
              />
            </Field>
          </div>
        )}
      </div>
      <p className="text-sm text-muted-foreground">
        Windows Firewall may ask the first time. Remotely changes no firewall rule.
      </p>
      <div className="flex items-center gap-2">
        <WhyDisabled reason={busy ? null : reason}>
          <Button onClick={onStart} disabled={busy || reason !== null}>
            <PlayIcon data-icon="inline-start" />
            Start the file server
          </Button>
        </WhyDisabled>
        <HelpTip topic="toolbox.fileServer" />
      </div>
    </>
  );
}

function PathBox({ id, path, folder, empty }: { id: string; path: string; folder: boolean; empty: string }) {
  const Icon = folder ? FolderIcon : FileIcon;
  return (
    <div
      id={id}
      className="flex h-9 min-w-0 flex-1 basis-64 items-center gap-2 rounded-md border px-3 text-sm"
      title={path || undefined}
    >
      <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
      <span className={cn("min-w-0 truncate", !path && "text-muted-foreground")}>{path || empty}</span>
    </div>
  );
}

function ProtocolField({
  id,
  label,
  on,
  port,
  onToggle,
  onPort,
}: {
  id: string;
  label: string;
  on: boolean;
  port: string;
  onToggle: (on: boolean) => void;
  onPort: (port: string) => void;
}) {
  return (
    <div className="grid gap-1.5">
      <div className="flex items-center gap-2">
        <Switch id={id} checked={on} onCheckedChange={onToggle} />
        <label htmlFor={id} className="text-sm font-medium">
          {label}
        </label>
      </div>
      <Input
        aria-label={`${label} port`}
        inputMode="numeric"
        disabled={!on}
        value={port}
        onChange={(e) => onPort(e.target.value)}
      />
    </div>
  );
}

function RunningView({ status, busy, onStop }: { status: ServerStatus; busy: boolean; onStop: () => void }) {
  const Icon = status.folder ? FolderIcon : FileIcon;
  const copy = (url: string) =>
    void navigator.clipboard?.writeText(url).then(
      () => toast.success("Copied the address"),
      () => undefined,
    );
  return (
    <div className="grid gap-3 rounded-lg border p-4">
      <div className="flex flex-wrap items-start gap-3">
        <div className="grid min-w-0 flex-1 gap-1">
          <p className="flex min-w-0 items-center gap-2 font-medium">
            <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            <span className="min-w-0 truncate" title={status.served}>
              Serving {status.served}
            </span>
          </p>
          <p className="text-sm text-muted-foreground">
            On <span data-mask="ip">{status.address}</span> · {listeningText(status)} · {endText(status)}
          </p>
        </div>
        <Button onClick={onStop} disabled={busy}>
          <SquareIcon data-icon="inline-start" />
          Stop
        </Button>
      </div>
      <ul className="grid gap-1">
        {status.urls.map((url) => (
          <li key={url} className="flex items-center gap-1">
            <code className="min-w-0 truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{url}</code>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon-sm" aria-label="Copy the address" onClick={() => copy(url)}>
                  <CopyIcon />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Copy the address</TooltipContent>
            </Tooltip>
          </li>
        ))}
      </ul>
      {status.uploads && (
        <p className="text-sm text-muted-foreground">
          Uploads go into {status.uploads.folder} · {sizeText(status.uploads.used)} of{" "}
          {sizeText(status.uploads.maxTotalMb * 1024 * 1024)} taken · {status.uploads.files}{" "}
          {status.uploads.files === 1 ? "file" : "files"}
        </p>
      )}
    </div>
  );
}

function RequestList({ status }: { status: ServerStatus }) {
  return (
    <div className="grid gap-2">
      <p className="text-sm">
        <span className="font-medium">{countsText(status)}</span>
        {!status.running && status.stopped && <span className="text-muted-foreground"> · {endText(status)}</span>}
      </p>
      {status.requests.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-20">Time</TableHead>
              <TableHead>Client</TableHead>
              <TableHead>Request</TableHead>
              <TableHead className="text-right">Bytes</TableHead>
              <TableHead>Result</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {status.requests.map((r, i) => {
              const { what, path } = requestText(r);
              return (
                <TableRow key={`${r.at}-${r.port}-${i}`}>
                  <TableCell className="text-muted-foreground tabular-nums">{requestTime(r)}</TableCell>
                  <TableCell className="font-mono text-xs">
                    <span data-mask="ip">{r.ip}</span>
                  </TableCell>
                  <TableCell className="max-w-80 whitespace-normal">
                    <span className="text-muted-foreground">{what} </span>
                    <span className="font-mono text-xs break-all">{path}</span>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{r.bytes > 0 ? sizeText(r.bytes) : ""}</TableCell>
                  <TableCell className="max-w-72 whitespace-normal">
                    <span className={cn(r.outcome === "refused" || r.outcome === "failed" ? "text-destructive" : "")}>
                      {outcomeText(r.outcome)}
                    </span>
                    {r.detail && <span className="text-muted-foreground">: {r.detail}</span>}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}
      {status.counts.requests > status.requests.length && (
        <p className="text-xs text-muted-foreground">
          Only the last {status.requests.length} are shown; the job in Activity keeps the last 500.
        </p>
      )}
    </div>
  );
}
