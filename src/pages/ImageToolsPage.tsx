// CV-03: Image tools, which make no VM. Inspect (format, virtual size, size on disk, parent), Convert between VMDK
// (growable, preallocated, stream-optimized, ESXi's layout), VDI, VHD, VHDX, qcow2 and raw, thin or thick, and Verify
// (sizes, SHA-256 of every file, and qemu-img's comparison when it is installed). The hypervisors' own tools convert
// first; qemu-img only what they can't (qcow2, VHDX), and only when the owner installed it: the page says which
// conversions need it and links to QEMU's own download page. Import as a VM (CV-01) opens the Import dialog.
//
// Inspect and Verify are reads. Convert asks where the new image goes (a save dialog in the shell; nothing is ever
// replaced) and goes to the bus as a Low job, its progress in the job's toast and Activity. The source is only read.

import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
  ArrowRightLeftIcon,
  CheckCircle2Icon,
  ExternalLinkIcon,
  FileSearchIcon,
  ImportIcon,
  ScanSearchIcon,
  ShieldCheckIcon,
  XCircleIcon,
} from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type SubmitOutcome } from "@/lib/api";
import {
  convertApi,
  type ConvertOptions,
  type ImageInfo,
  type OutputKind,
  type PickFor,
  type ToolsReport,
  type VerifyReport,
} from "@/lib/convert-api";
import {
  convertReason,
  describeImage,
  inspectRows,
  OUTPUT_GROUPS,
  qemuNote,
  sizeText,
  verifySummary,
} from "@/lib/convert";

type Tab = "inspect" | "convert" | "verify";

interface Props {
  /** True while the page is shown: it reads the tools only then. */
  active: boolean;
  onSubmitted: (outcome: SubmitOutcome) => void;
  /** CV-01: the Import dialog, on this file when one is given. */
  onImport: (path?: string) => void;
  onOpenSettings: () => void;
}

async function pickFile(purpose: PickFor, onError: (message: string) => void): Promise<string | null> {
  try {
    return await convertApi.pick(purpose);
  } catch (err) {
    onError(errorMessage(err));
    return null;
  }
}

function Problems({ info }: { info: ImageInfo }) {
  if (info.problems.length === 0 && info.notes.length === 0) return null;
  return (
    <div className="grid gap-1 text-sm">
      {info.problems.map((p) => (
        <p key={p} className="text-destructive" role="alert">
          It can&apos;t be converted as it is: {p}.
        </p>
      ))}
      {info.notes.map((n) => (
        <p key={n} className="text-muted-foreground">
          {n}
        </p>
      ))}
    </div>
  );
}

function InfoTable({ info }: { info: ImageInfo }) {
  return (
    <div className="rounded-lg border">
      <Table>
        <TableBody>
          {inspectRows(info).map(([label, value]) => (
            <TableRow key={label}>
              <TableCell className="w-40 text-muted-foreground">{label}</TableCell>
              <TableCell className="font-mono text-xs break-all whitespace-normal">{value}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function ToolsCard({ tools, onOpenSettings }: { tools: ToolsReport | null; onOpenSettings: () => void }) {
  if (!tools) return null;
  const rows: [string, string | null][] = [
    ["vmware-vdiskmanager (Workstation)", tools.paths.vdiskmanager],
    ["ovftool (Workstation)", tools.paths.ovftool],
    ["VBoxManage (VirtualBox)", tools.paths.vboxmanage],
    ["qemu-img (QEMU, if installed)", tools.paths.qemuImg],
  ];
  const note = qemuNote(tools);
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
        {rows.map(([label, path]) => (
          <span key={label} className="flex items-center gap-1.5" title={path ?? "Not found"}>
            {path ? (
              <CheckCircle2Icon className="size-4 text-tier-low" aria-label="Found" />
            ) : (
              <XCircleIcon className="size-4 text-muted-foreground" aria-label="Not found" />
            )}
            {label}
          </span>
        ))}
      </div>
      {note && (
        <Alert>
          <AlertTitle>qemu-img isn&apos;t installed</AlertTitle>
          <AlertDescription className="grid gap-2">
            <span>{note}</span>
            <span className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={() => void convertApi.openQemuSite(tools.downloadPage)}>
                <ExternalLinkIcon data-icon="inline-start" />
                QEMU&apos;s download page
              </Button>
              <Button variant="ghost" size="sm" onClick={onOpenSettings}>
                Set its path in Settings
              </Button>
            </span>
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}

export function ImageToolsPage({ active, onSubmitted, onImport, onOpenSettings }: Props) {
  const readOnly = useReadOnlyReason();
  const [tab, setTab] = useState<Tab>("inspect");
  const [tools, setTools] = useState<ToolsReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Inspect.
  const [inspected, setInspected] = useState<ImageInfo | null>(null);
  // Convert.
  const [options, setOptions] = useState<ConvertOptions | null>(null);
  const [kind, setKind] = useState<OutputKind | null>(null);
  const [wholeMb, setWholeMb] = useState(true);
  const [converting, setConverting] = useState(false);
  // Verify.
  const [first, setFirst] = useState<string | null>(null);
  const [second, setSecond] = useState<string | null>(null);
  const [verifying, setVerifying] = useState<{ request: string; done: number; total: number } | null>(null);
  const [report, setReport] = useState<VerifyReport | null>(null);
  const verifyRequest = useRef<string | null>(null);

  const loadTools = useCallback(() => {
    convertApi.tools().then(setTools, (err) => setError(errorMessage(err)));
  }, []);

  useEffect(() => {
    if (active) loadTools();
  }, [active, loadTools]);

  useEffect(() => {
    const unlisten = convertApi.onVerify((event) => {
      if (event.request === verifyRequest.current) setVerifying(event);
    });
    return () => {
      void unlisten.then((stop) => stop());
    };
  }, []);

  async function inspect() {
    const path = await pickFile("image", setError);
    if (!path) return;
    setError(null);
    try {
      setInspected(await convertApi.inspect(path));
    } catch (err) {
      setInspected(null);
      setError(errorMessage(err));
    }
  }

  async function chooseSource() {
    const path = await pickFile("image", setError);
    if (path) await loadOptions(path);
  }

  /** The Convert tab's options for one image: picked there, or the one Inspect shows ("Convert it…"). */
  async function loadOptions(path: string) {
    setError(null);
    try {
      const o = await convertApi.options(path);
      setOptions(o);
      setKind((k) => (k && o.outputs.some((x) => x.kind === k && !x.reason) ? k : null));
    } catch (err) {
      setOptions(null);
      setError(errorMessage(err));
    }
  }

  const option = options?.outputs.find((o) => o.kind === kind) ?? null;
  const reason = convertReason({ readOnly, busy: converting, options, option });

  async function convert() {
    if (!options || !kind) return;
    setConverting(true);
    setError(null);
    try {
      const outcome = await convertApi.submit(options.info.path, kind, kind === "vhdFixed" && wholeMb);
      if (outcome) {
        onSubmitted(outcome);
        toast.info("Converting: its progress is in the job's notice and in Activity.");
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setConverting(false);
    }
  }

  async function verify() {
    if (!first) return;
    const request = crypto.randomUUID();
    verifyRequest.current = request;
    setVerifying({ request, done: 0, total: 0 });
    setReport(null);
    setError(null);
    try {
      setReport(await convertApi.verify(request, first, second));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      verifyRequest.current = null;
      setVerifying(null);
    }
  }

  const summary = report ? verifySummary(report) : null;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start gap-3">
        <p className="max-w-3xl flex-1 text-sm text-muted-foreground">
          Read and convert other hypervisors&apos; disk images: VMDK, VDI, VHD, VHDX, qcow2 and raw. Nothing here makes
          a VM, and a source is never changed: a conversion writes a new file beside it (or where you say). To make a VM
          from a foreign disk or appliance, import it.
        </p>
        <WhyDisabled reason={readOnly}>
          <Button variant="outline" disabled={readOnly !== null} onClick={() => onImport()}>
            <ImportIcon data-icon="inline-start" />
            Import as a VM…
          </Button>
        </WhyDisabled>
      </div>
      <ToolsCard tools={tools} onOpenSettings={onOpenSettings} />
      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}

      <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)}>
        <TabsList>
          <TabsTrigger value="inspect">
            <ScanSearchIcon />
            Inspect
          </TabsTrigger>
          <TabsTrigger value="convert">
            <ArrowRightLeftIcon />
            Convert
          </TabsTrigger>
          <TabsTrigger value="verify">
            <ShieldCheckIcon />
            Verify
          </TabsTrigger>
        </TabsList>

        <TabsContent value="inspect" className="flex max-w-3xl flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" onClick={() => void inspect()}>
              <FileSearchIcon data-icon="inline-start" />
              Choose a disk image…
            </Button>
            {inspected && <code className="min-w-0 truncate font-mono text-xs">{inspected.path}</code>}
          </div>
          {inspected && (
            <>
              <InfoTable info={inspected} />
              <Problems info={inspected} />
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setTab("convert");
                    void loadOptions(inspected.path);
                  }}
                >
                  <ArrowRightLeftIcon data-icon="inline-start" />
                  Convert it…
                </Button>
                <WhyDisabled reason={readOnly}>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={readOnly !== null}
                    onClick={() => onImport(inspected.path)}
                  >
                    <ImportIcon data-icon="inline-start" />
                    Import it as a VM…
                  </Button>
                </WhyDisabled>
              </div>
            </>
          )}
        </TabsContent>

        <TabsContent value="convert" className="flex max-w-3xl flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" onClick={() => void chooseSource()}>
              <FileSearchIcon data-icon="inline-start" />
              {options ? "Choose another image…" : "Choose the image to convert…"}
            </Button>
            {options && <span className="text-sm">{describeImage(options.info)}</span>}
          </div>
          {options && (
            <>
              <code className="truncate font-mono text-xs text-muted-foreground">{options.info.path}</code>
              <Problems info={options.info} />
              <div className="grid max-w-md gap-2">
                <Label htmlFor="convert-kind">Into</Label>
                <Select value={kind ?? ""} onValueChange={(v) => setKind(v as OutputKind)}>
                  <SelectTrigger id="convert-kind" className="w-full">
                    <SelectValue placeholder="Choose a format" />
                  </SelectTrigger>
                  <SelectContent>
                    {OUTPUT_GROUPS.map((group) => (
                      <SelectGroup key={group.label}>
                        <SelectLabel>{group.label}</SelectLabel>
                        {group.kinds.map((k) => {
                          const o = options.outputs.find((x) => x.kind === k);
                          if (!o) return null;
                          return (
                            <SelectItem key={k} value={k} disabled={o.reason !== null}>
                              {o.label}
                              {o.needsQemuImg ? " (needs qemu-img)" : o.reason ? " (can't here)" : ""}
                            </SelectItem>
                          );
                        })}
                      </SelectGroup>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {option && (
                <div className="grid gap-1 text-sm">
                  {option.reason ? (
                    <p className="text-destructive">{option.reason}</p>
                  ) : (
                    <>
                      <p>With {option.plan}.</p>
                      <p className="text-muted-foreground">
                        It may take up to {sizeText(option.estimateBytes)}
                        {options.freeBytes !== null
                          ? ` (${sizeText(options.freeBytes)} free on the source's drive)`
                          : ""}
                        .
                      </p>
                    </>
                  )}
                </div>
              )}
              {kind === "vhdFixed" && options.roundsToMegabytes && (
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox checked={wholeMb} onCheckedChange={(v) => setWholeMb(v === true)} />
                  Round its size up to a whole megabyte (Azure takes only those)
                </label>
              )}
              <div>
                <WhyDisabled reason={reason}>
                  <Button onClick={() => void convert()} disabled={reason !== null}>
                    <ArrowRightLeftIcon data-icon="inline-start" />
                    {converting ? "Starting…" : "Convert…"}
                  </Button>
                </WhyDisabled>
              </div>
            </>
          )}
        </TabsContent>

        <TabsContent value="verify" className="flex max-w-3xl flex-col gap-3">
          <p className="text-sm text-muted-foreground">
            One image&apos;s checksums, or two compared: a conversion&apos;s source and the new image, or a copy and its
            original. With qemu-img, the disks&apos; contents are compared too.
          </p>
          <div className="grid gap-2">
            {[
              { label: "Image", value: first, set: setFirst },
              { label: "Compare with (optional)", value: second, set: setSecond },
            ].map((row) => (
              <div key={row.label} className="flex flex-wrap items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={verifying !== null}
                  onClick={() =>
                    void pickFile("image", setError).then((path) => {
                      if (path) row.set(path);
                    })
                  }
                >
                  {row.label}…
                </Button>
                {row.value && <code className="min-w-0 truncate font-mono text-xs">{row.value}</code>}
              </div>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <WhyDisabled reason={!first ? "Choose an image first" : verifying ? "Verifying…" : null}>
              <Button onClick={() => void verify()} disabled={!first || verifying !== null}>
                <ShieldCheckIcon data-icon="inline-start" />
                Verify
              </Button>
            </WhyDisabled>
            {verifying && (
              <Button variant="outline" onClick={() => void convertApi.cancelVerify(verifying.request)}>
                Stop
              </Button>
            )}
          </div>
          {verifying && verifying.total > 0 && (
            <Progress value={(verifying.done / verifying.total) * 100} aria-label="Checksums" />
          )}
          {report && summary && (
            <div className="grid gap-3">
              <p className={summary.ok ? "text-sm" : "text-sm text-destructive"} role="status">
                {summary.text}
              </p>
              <div className="rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>File</TableHead>
                      <TableHead>Size</TableHead>
                      <TableHead>SHA-256</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {[...report.firstHashes, ...report.secondHashes].map((h) => (
                      <TableRow key={h.path}>
                        <TableCell className="font-mono text-xs break-all whitespace-normal">{h.path}</TableCell>
                        <TableCell className="whitespace-nowrap">{sizeText(h.bytes)}</TableCell>
                        <TableCell className="font-mono text-xs break-all whitespace-normal">{h.sha256}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="text-sm text-muted-foreground">
                {describeImage(report.first)}
                {report.second && <> · {describeImage(report.second)}</>}
              </div>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
