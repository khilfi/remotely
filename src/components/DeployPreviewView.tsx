// VM-21, AP-02: what a deploy makes, for the Deploy and Clone dialogs and the approval dialog: each VM's name,
// hostname and folder, the hypervisor and where the OS comes from, the size, the disk space each VM may take and all
// of them together (thin disks at their full size), the drive's free space, the network, cloud-init's setup and the
// after-deploy steps, then what to know, what may go wrong and why it can't run.

import { AlertTriangleIcon, BanIcon, InfoIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EnvBadge } from "@/components/Badges";
import type { DeployPreview } from "@/lib/api";
import { cpuText, memoryText } from "@/lib/catalog";
import { bytesText } from "@/lib/deploy";

const STEP_LABEL: { key: keyof DeployPreview["afterDeploy"]; label: string }[] = [
  { key: "createSession", label: "create the SSH session" },
  { key: "linkSession", label: "link it to the VM" },
  { key: "cleanSnapshot", label: "take a “clean” snapshot" },
  { key: "openConsole", label: "open the console" },
];

interface Props {
  preview: DeployPreview;
  /** The approval dialog lists the warnings itself. */
  showWarnings?: boolean;
}

export function DeployPreviewView({ preview, showWarnings = true }: Props) {
  const steps = STEP_LABEL.filter((s) => preview.afterDeploy[s.key]).map((s) => s.label);
  const size = preview.size;
  return (
    <div className="grid gap-3 text-sm">
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 rounded-md border p-3">
        <dt className="text-muted-foreground">Makes</dt>
        <dd className="break-words">{preview.source}</dd>
        <dt className="text-muted-foreground">In</dt>
        <dd className="font-mono text-xs break-all">{preview.folder}</dd>
        {size && (
          <>
            <dt className="text-muted-foreground">Size</dt>
            <dd>
              {size.name}: {cpuText(size.sockets, size.coresPerSocket)}, {memoryText(size.memoryMb)} RAM,{" "}
              {size.disks.map((d) => `${d.sizeGb} GB ${d.provisioning}`).join(" + ")}
            </dd>
          </>
        )}
        {preview.network && (
          <>
            <dt className="text-muted-foreground">Network</dt>
            <dd>
              {preview.network}
              {preview.hostAdapter ? ` (${preview.hostAdapter})` : ""}
            </dd>
          </>
        )}
        <dt className="text-muted-foreground">Label</dt>
        <dd className="flex flex-wrap items-center gap-2">
          <EnvBadge env={preview.environment} />
          {preview.tags.length > 0 && <span className="text-muted-foreground">tags {preview.tags.join(", ")}</span>}
        </dd>
        {preview.firstBoot && (
          <>
            <dt className="text-muted-foreground">First boot</dt>
            <dd>
              {preview.firstBoot.user ? (
                <>
                  user <span className="font-mono">{preview.firstBoot.user}</span> with sudo
                </>
              ) : (
                "the image's default user"
              )}
              {preview.firstBoot.keyFingerprint ? (
                <>
                  , key <span className="font-mono text-xs">{preview.firstBoot.keyFingerprint}</span>
                </>
              ) : (
                ", no SSH key"
              )}
              {preview.firstBoot.packages.length > 0 && <>, installs {preview.firstBoot.packages.join(", ")}</>}
            </dd>
          </>
        )}
        <dt className="text-muted-foreground">Then</dt>
        <dd>{steps.length ? steps.join(", ") : "nothing more"}</dd>
        <dt className="text-muted-foreground">Disk</dt>
        <dd>
          up to {bytesText(preview.diskBytes)} in all
          {preview.thickBytes > 0 && <>, {bytesText(preview.thickBytes)} of it thick (taken at once)</>}
          {preview.freeBytes !== null && <>; the drive has {bytesText(preview.freeBytes)} free</>}
        </dd>
      </dl>

      <div className="max-h-56 overflow-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>VM</TableHead>
              <TableHead>Folder</TableHead>
              <TableHead className="text-right">Disk, at most</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {preview.vms.map((vm) => (
              <TableRow key={vm.name}>
                <TableCell className="whitespace-normal">
                  <div className="font-medium">{vm.name}</div>
                  <div className="text-xs text-muted-foreground">
                    {vm.cloneOf ? `clone of ${vm.cloneOf}` : `hostname ${vm.hostname}`}
                  </div>
                  {vm.problem && <div className="text-xs text-destructive">{vm.problem}</div>}
                </TableCell>
                <TableCell className="font-mono text-xs break-all whitespace-normal text-muted-foreground">
                  {vm.folder}
                </TableCell>
                <TableCell className="text-right tabular-nums">{bytesText(vm.diskBytes)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {preview.refusals.length > 0 && (
        <Alert variant="destructive">
          <BanIcon />
          <AlertTitle>It can't run as it is</AlertTitle>
          <AlertDescription>
            <ul className="list-disc pl-5">
              {preview.refusals.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
      {showWarnings && preview.warnings.length > 0 && (
        <Alert className="border-tier-medium/40">
          <AlertTriangleIcon className="text-tier-medium" />
          <AlertTitle>Read this before you go on</AlertTitle>
          <AlertDescription>
            <ul className="list-disc pl-5">
              {preview.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
      {preview.notes.length > 0 && (
        <div className="flex items-start gap-1.5 text-xs text-muted-foreground">
          <InfoIcon className="mt-px size-3.5 shrink-0" aria-hidden />
          <ul className="grid gap-1">
            {preview.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
