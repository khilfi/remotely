// MO-13: a VM's System tab in its details panel: what the hypervisor's files say (vCPUs and their layout, memory,
// firmware, each virtual disk's provisioned size and size on this PC, each network adapter and its MAC), read when the
// tab opens and on Refresh, and what was read before when the files can't be read now. "From the guest" shows a linked
// session's own facts (OS, kernel, filesystems), with a way into that session's host details. MACs carry
// data-mask="mac" (FD-03); disk paths go through the DOM masker like any text (C:\Users\<name> is masked).

import { useEffect, useState } from "react";
import { CircleAlertIcon, HardDriveIcon, RefreshCwIcon, ServerIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { FactList, SystemFacts } from "@/components/HostDetailsSheet";
import { api, errorMessage, type VmRecord, type VmSpecs } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { collectedByText } from "@/lib/host-details";
import { formatBytes, type Thresholds } from "@/lib/metrics";

interface Props {
  vm: VmRecord;
  thresholds: Thresholds;
  /** Opens a linked session's host details (MO-14 there). */
  onHostDetails: (session: { id: string; name: string }) => void;
}

function vcpuText(specs: VmSpecs): string | null {
  const h = specs.hardware;
  if (!h.vcpus) return null;
  const layout =
    h.coresPerSocket && h.vcpus % h.coresPerSocket === 0
      ? ` (${h.vcpus / h.coresPerSocket} × ${h.coresPerSocket} cores)`
      : "";
  return `${h.vcpus}${layout}`;
}

export function VmSystemTab({ vm, thresholds, onHostDetails }: Props) {
  const [read, setRead] = useState<{ for: string; specs: VmSpecs } | null>(null);
  const [error, setError] = useState<{ for: string; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const key = vm.vmxPath;

  const load = (vmxPath: string) =>
    api.vmSpecs(vmxPath).then(
      (specs) => {
        setRead({ for: vmxPath, specs });
        setError(null);
      },
      (err) => setError({ for: vmxPath, message: errorMessage(err) }),
    );

  useEffect(() => {
    let stale = false;
    api.vmSpecs(key).then(
      (specs) => !stale && setRead({ for: key, specs }),
      (err) => !stale && setError({ for: key, message: errorMessage(err) }),
    );
    return () => {
      stale = true;
    };
  }, [key]);

  const specs = read?.for === key ? read.specs : null;
  const failed = error?.for === key ? error.message : null;
  const h = specs?.hardware;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        {specs && <span>Read from the VM&apos;s files {formatWhen(specs.collectedAt)}</span>}
        <Button
          className="ml-auto"
          variant="outline"
          size="sm"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            void load(key).finally(() => setBusy(false));
          }}
        >
          <RefreshCwIcon data-icon="inline-start" className={busy ? "animate-spin" : undefined} />
          Refresh
        </Button>
      </div>

      {failed && (
        <Alert variant="destructive">
          <CircleAlertIcon />
          <AlertTitle>Could not read the VM&apos;s files</AlertTitle>
          <AlertDescription>{failed}</AlertDescription>
        </Alert>
      )}
      {specs?.stored && (
        <Alert>
          <CircleAlertIcon />
          <AlertTitle>Showing what was read {formatWhen(specs.collectedAt)}</AlertTitle>
          <AlertDescription>{specs.problem ?? "The VM's files can't be read now."}</AlertDescription>
        </Alert>
      )}
      {!specs && !failed && (
        <div className="flex flex-col gap-2" aria-label="Reading the VM's files">
          <Skeleton className="h-5 w-2/3" />
          <Skeleton className="h-5 w-1/2" />
          <Skeleton className="h-20 w-full" />
        </div>
      )}

      {specs && h && (
        <>
          <FactList
            rows={[
              {
                label: "Guest OS",
                value: h.guestOsName ?? h.guestOs,
                hint: "What the guest tools report, else what the VM was set up for",
              },
              ...(h.guestOsName && h.guestOs ? [{ label: "Set up as", value: h.guestOs }] : []),
              {
                label: "Guest kernel",
                value: h.guestKernel ? <span className="font-mono text-xs">{h.guestKernel}</span> : null,
              },
              { label: "vCPUs", value: vcpuText(specs) },
              { label: "Memory", value: h.memoryMb ? formatBytes(h.memoryMb * 1024 * 1024) : null },
              { label: "Firmware", value: h.firmware },
              ...(h.hardwareVersion ? [{ label: "Hardware version", value: h.hardwareVersion }] : []),
            ]}
          />

          <section className="flex flex-col gap-2">
            <h3 className="flex items-center gap-1.5 text-sm font-medium">
              <HardDriveIcon className="size-4 text-muted-foreground" /> Virtual disks ({h.disks.length})
            </h3>
            {h.disks.length === 0 ? (
              <p className="text-xs text-muted-foreground">No virtual disk is attached.</p>
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Slot</TableHead>
                      <TableHead>File</TableHead>
                      <TableHead className="text-right" title="The size the guest sees">
                        Provisioned
                      </TableHead>
                      <TableHead className="text-right" title="What its files take on this PC">
                        On disk
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {h.disks.map((d) => (
                      <TableRow key={`${d.slot}|${d.path}`}>
                        <TableCell className="font-mono text-xs">{d.slot}</TableCell>
                        <TableCell className="text-xs whitespace-normal">
                          <div className="font-mono break-all">{d.path}</div>
                          <div className="text-muted-foreground">
                            {[d.format, d.delta ? "snapshot delta" : null, d.files > 1 ? `${d.files} files` : null]
                              .filter(Boolean)
                              .join(" · ")}
                          </div>
                          {d.problem && <div className="text-tier-medium">{d.problem}</div>}
                        </TableCell>
                        <TableCell className="text-right text-xs tabular-nums">
                          {formatBytes(d.provisionedBytes)}
                        </TableCell>
                        <TableCell className="text-right text-xs tabular-nums">{formatBytes(d.onDiskBytes)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </section>

          <section className="flex flex-col gap-2">
            <h3 className="text-sm font-medium">Network adapters ({h.nics.length})</h3>
            {h.nics.length === 0 ? (
              <p className="text-xs text-muted-foreground">No network adapter.</p>
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableBody>
                    {h.nics.map((n) => (
                      <TableRow key={n.slot}>
                        <TableCell className="text-xs">
                          <div className="font-mono">{n.slot}</div>
                          {n.model && <div className="text-muted-foreground">{n.model}</div>}
                        </TableCell>
                        <TableCell className="text-xs whitespace-normal">
                          {n.connection ?? "—"}
                          {n.connected === false && <div className="text-muted-foreground">not connected</div>}
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs">
                          {n.mac ? <span data-mask="mac">{n.mac}</span> : "—"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </section>

          <section className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <h3 className="flex items-center gap-1.5 text-sm font-medium">
                <ServerIcon className="size-4 text-muted-foreground" /> From the guest
              </h3>
              {specs.guest && specs.guestSessionName && (
                <Button
                  className="ml-auto"
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    specs.guest && onHostDetails({ id: specs.guest.sessionId, name: specs.guestSessionName ?? "" })
                  }
                >
                  Host details…
                </Button>
              )}
            </div>
            {specs.guest ? (
              <>
                <p className="text-xs text-muted-foreground">
                  Read over <Badge variant="secondary">{specs.guestSessionName}</Badge>{" "}
                  {formatWhen(specs.guest.collectedAt)}, {collectedByText(specs.guest.collectedBy)}.
                </p>
                <SystemFacts read={specs.guest} thresholds={thresholds} compact />
              </>
            ) : (
              <p className="text-xs text-muted-foreground">
                {vm.ipAddress
                  ? "Open a terminal to a session linked to this VM (or watch it on the dashboard) to read the guest's own OS, disks and filesystems."
                  : "Link a session to this VM on the Sessions page, then open a terminal to it, to read the guest's own OS, disks and filesystems."}
              </p>
            )}
          </section>
        </>
      )}
    </div>
  );
}
