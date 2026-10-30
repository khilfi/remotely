// MO-13: the system part of a VM's Overview tab (UX-03: Details and System are one tab since 0.6.0): what the
// hypervisor's files add to the inventory's rows (the guest type it was set up as, the guest kernel, the CPU layout),
// read when the tab opens and on Refresh, and what was read before when the files can't be read now. "From the guest"
// shows a linked session's own facts (OS, kernel, filesystems), with a way into that session's host details. VM-23: the
// VM's virtual hardware in full (disks, adapters, firmware, devices) and its edits are on the Settings tab.

import { useEffect, useState } from "react";
import { CircleAlertIcon, ServerIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { FactList, SystemFacts } from "@/components/HostDetailsSheet";
import { RefreshButton } from "@/components/RefreshButton";
import { api, errorMessage, type VmRecord, type VmSpecs } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { collectedByText } from "@/lib/host-details";
import { type Thresholds } from "@/lib/metrics";

interface Props {
  vm: VmRecord;
  thresholds: Thresholds;
  /** Opens a linked session's host details (MO-14 there). */
  onHostDetails: (session: { id: string; name: string }) => void;
}

function layoutText(specs: VmSpecs): string | null {
  const h = specs.hardware;
  if (!h.vcpus || !h.coresPerSocket || h.vcpus % h.coresPerSocket !== 0) return null;
  const sockets = h.vcpus / h.coresPerSocket;
  return `${sockets} socket${sockets === 1 ? "" : "s"} × ${h.coresPerSocket} cores`;
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
  // Only what the rows above don't say already.
  const rows = h
    ? [
        ...(h.guestOsName && h.guestOs ? [{ label: "Set up as", value: h.guestOs }] : []),
        ...(h.guestKernel
          ? [{ label: "Guest kernel", value: <span className="font-mono text-xs">{h.guestKernel}</span> }]
          : []),
        ...(specs && layoutText(specs) ? [{ label: "CPU layout", value: layoutText(specs) }] : []),
      ]
    : [];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <h3 className="flex items-center gap-1.5 text-sm font-medium">
          <ServerIcon className="size-4 text-muted-foreground" aria-hidden /> System
        </h3>
        {specs && <span className="truncate text-xs text-muted-foreground">read {formatWhen(specs.collectedAt)}</span>}
        <RefreshButton
          className="ml-auto"
          busy={busy}
          onClick={() => {
            setBusy(true);
            void load(key).finally(() => setBusy(false));
          }}
        />
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
        </div>
      )}

      {specs && h && (
        <>
          {rows.length > 0 && <FactList rows={rows} />}
          <section className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <h4 className="text-sm text-muted-foreground">From the guest</h4>
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
                  ? "Open a terminal to a linked session to read the guest's own OS and filesystems."
                  : "Link a session to this VM, then open a terminal to it, to read the guest's own OS and filesystems."}
              </p>
            )}
          </section>
        </>
      )}
    </div>
  );
}
