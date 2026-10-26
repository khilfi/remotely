// VM-17, CV-02: Export a powered-off VM for another hypervisor or a cloud: an OVA or OVF (1.0, or 2.0 from
// VirtualBox), VMDK for ESXi, VHDX for Hyper-V, a fixed VHD for Azure, qcow2 with a libvirt XML for KVM, a Proxmox
// script, or raw disks. Each target says how each disk is converted (the hypervisors' own tools first, qemu-img for
// qcow2 and VHDX) or why it can't be. Export asks for the folder (a dialog in the shell), then goes to the bus: a Low
// job (a Prod VM's asks), with progress in its toast and Activity. The VM is only read.

import { useEffect, useState } from "react";
import { ExternalLinkIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { useReadOnlyReason } from "@/components/Presentation";
import { ReasonLine, WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type SubmitOutcome } from "@/lib/api";
import { HYPERVISOR_LABEL } from "@/lib/catalog";
import { convertApi, type ExportOptions, type ToolsReport } from "@/lib/convert-api";
import { exportGroups, exportLabel, exportReason, FORMAT_LABEL, qemuNote, sizeText, targetKey } from "@/lib/convert";

interface Props {
  vmKey: string;
  /** Goes through the app, which opens the approval dialog for a Prod VM, or shows the job's toast. */
  onSubmitted: (outcome: SubmitOutcome) => void;
  onClose: () => void;
}

export function VmExportDialog({ vmKey, onSubmitted, onClose }: Props) {
  const readOnly = useReadOnlyReason();
  const [options, setOptions] = useState<ExportOptions | null>(null);
  const [tools, setTools] = useState<ToolsReport | null>(null);
  const [picked, setPicked] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let stopped = false;
    Promise.all([convertApi.exportOptions(vmKey), convertApi.tools()]).then(
      ([o, t]) => {
        if (stopped) return;
        setOptions(o);
        setTools(t);
        const first = o.targets.find((x) => x.reason === null);
        setPicked(first ? targetKey(first.target) : null);
      },
      (err) => !stopped && setError(errorMessage(err)),
    );
    return () => {
      stopped = true;
    };
  }, [vmKey]);

  const option = options?.targets.find((t) => targetKey(t.target) === picked) ?? null;
  const reason = exportReason({ readOnly, busy, refusal: options?.refusal ?? null, option });
  const anyNeedsQemu = options?.targets.some((t) => t.needsQemuImg) ?? false;
  const note = anyNeedsQemu ? qemuNote(tools) : null;

  async function exportIt() {
    if (!option) return;
    setBusy(true);
    setError(null);
    try {
      const outcome = await convertApi.exportSubmit(vmKey, option.target);
      if (outcome) {
        onSubmitted(outcome);
        onClose();
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Export {options?.vmName ?? "the VM"}</DialogTitle>
          <DialogDescription>
            For another hypervisor or a cloud, as it is now (shut down, its snapshots merged into its disks). The VM
            isn&apos;t changed: Remotely only reads it and writes new files, with a README that says how to import them.
          </DialogDescription>
        </DialogHeader>

        <div className="-mx-1 grid max-h-[65vh] gap-4 overflow-y-auto px-1">
          {options?.refusal && (
            <Alert variant="destructive">
              <AlertTitle>It can&apos;t be exported now</AlertTitle>
              <AlertDescription>{options.refusal}</AlertDescription>
            </Alert>
          )}
          {options && (
            <RadioGroup value={picked ?? ""} onValueChange={setPicked} className="grid gap-4">
              {exportGroups(options.targets).map((group) => (
                <div key={group.label} className="grid gap-2">
                  <div className="text-xs font-medium text-muted-foreground uppercase">{group.label}</div>
                  {group.options.map((o) => {
                    const key = targetKey(o.target);
                    return (
                      <div key={key} className="flex items-start gap-2">
                        <RadioGroupItem id={`export-${key}`} value={key} disabled={o.reason !== null} />
                        <Label htmlFor={`export-${key}`} className="grid gap-0.5 font-normal">
                          <span className={o.reason ? "text-muted-foreground" : "font-medium"}>{exportLabel(o)}</span>
                          <ReasonLine reason={o.reason} />
                        </Label>
                      </div>
                    );
                  })}
                </div>
              ))}
            </RadioGroup>
          )}

          {option && option.reason === null && (
            <div className="grid gap-2 rounded-md border p-3 text-sm">
              <div>
                Into a new folder <code className="font-mono text-xs">{option.folderName}</code> in the folder you
                choose, with a README.md.{" "}
                {option.estimateBytes > 0 && <>It may take up to {sizeText(option.estimateBytes)}.</>}
              </div>
              {option.tool && (
                <div className="text-muted-foreground">
                  {HYPERVISOR_LABEL[options?.hypervisor ?? "vmware"]}&apos;s own export of the whole VM.
                </div>
              )}
              {option.disks.length > 0 && (
                <ul className="grid gap-1">
                  {option.disks.map((d) => (
                    <li key={d.file}>
                      <code className="font-mono text-xs">{d.file}</code>: {FORMAT_LABEL[d.sourceFormat]},{" "}
                      {sizeText(d.virtualBytes)}
                      <div className="text-xs text-muted-foreground">{d.plan}</div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {note && (
            <Alert>
              <AlertTitle>Some targets need qemu-img</AlertTitle>
              <AlertDescription className="grid gap-2">
                <span>{note}</span>
                <Button
                  variant="outline"
                  size="sm"
                  className="w-fit"
                  onClick={() => tools && void convertApi.openQemuSite(tools.downloadPage)}
                >
                  <ExternalLinkIcon data-icon="inline-start" />
                  QEMU&apos;s download page
                </Button>
              </AlertDescription>
            </Alert>
          )}
        </div>

        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <WhyDisabled reason={reason}>
            <Button onClick={() => void exportIt()} disabled={reason !== null}>
              {busy ? "Starting…" : "Export…"}
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
