// VM-10: clones the VMs picked on the VMs page, one full clone each of the VM as it is now (shut down), named by a
// pattern in which {template} is each VM's own name, into the hypervisor's default folder or one chosen here. The
// core checks it as it is filled in and shows the AP-02 preview; Clone goes through the bus (the approval dialog),
// then the dialog follows the job with a step per clone, cancellable.

import { useEffect, useState } from "react";
import { FolderOpenIcon, XIcon } from "lucide-react";
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
import { DeployProgressView, useDeployProgress } from "@/components/DeployDialog";
import { CapacityPlanView } from "@/components/CapacityPlanView";
import { DeployPreviewView } from "@/components/DeployPreviewView";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useDebounced } from "@/hooks/use-debounced";
import { api, errorMessage, type CloneRequest, type DeployCheck, type SubmitOutcome, type VmRecord } from "@/lib/api";
import { cloneReason, DEFAULT_CLONE_PATTERN, deployReason, newVmKey, startProgress } from "@/lib/deploy";

interface Props {
  vms: VmRecord[];
  onSubmitted: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onClose: () => void;
}

export function CloneDialog({ vms, onSubmitted, onClose }: Props) {
  const readOnly = useReadOnlyReason();
  const [pattern, setPattern] = useState(DEFAULT_CLONE_PATTERN);
  const [folder, setFolder] = useState<string | null>(null);
  const [check, setCheck] = useState<{ key: string; check: DeployCheck } | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setStarted] = useDeployProgress();
  const following = progress !== null;

  const picked = cloneReason(
    vms.map((v) => ({ name: v.displayName, powerState: v.powerState, hypervisor: v.hypervisor })),
  );
  const request: CloneRequest = { vmKeys: vms.map((v) => v.vmxPath), namingPattern: pattern, folder };
  const requestKey = JSON.stringify(request);
  const checkedKey = useDebounced(requestKey, 300);

  useEffect(() => {
    if (picked || following) return;
    const asked = JSON.parse(checkedKey) as CloneRequest;
    let stopped = false;
    api.deployCloneCheck(asked).then(
      (c) => {
        if (stopped) return;
        setCheck({ key: checkedKey, check: c });
        setCheckError(null);
      },
      (err) => {
        if (stopped) return;
        setCheck(null);
        setCheckError(errorMessage(err));
      },
    );
    return () => {
      stopped = true;
    };
  }, [checkedKey, picked, following]);

  const current = check?.key === requestKey ? check.check : null;
  const reason =
    readOnly ??
    picked ??
    deployReason({
      busy,
      count: vms.length,
      checking: requestKey !== checkedKey || (!current && !checkError),
      check: current,
      error: checkError,
    });

  async function pickFolder() {
    try {
      const chosen = await api.catalogFolderPick();
      if (chosen) setFolder(chosen);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function submit() {
    const preview = current?.preview;
    if (!preview) return;
    const steps = preview.vms.map((vm) => ({ name: vm.name, target: newVmKey(preview.hypervisor, vm.name) }));
    setBusy(true);
    setError(null);
    try {
      onSubmitted(await api.deployCloneSubmit(request), (jobId) => setStarted(startProgress(jobId, steps)));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const running = progress !== null && progress.finished === null;

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{vms.length === 1 ? `Clone ${vms[0].displayName}` : `Clone ${vms.length} VMs`}</DialogTitle>
          <DialogDescription>
            {progress
              ? "One step per clone. Cancel stops the job: the clone being made is removed, and clones already made stay."
              : "A full clone of each VM as it is now, with its own CPU, memory, disks and network. Each VM must be shut down."}
          </DialogDescription>
        </DialogHeader>

        {progress ? (
          <DeployProgressView progress={progress} />
        ) : (
          <div className="-mx-1 grid max-h-[65vh] gap-4 overflow-x-hidden overflow-y-auto px-1">
            <div className="grid gap-2">
              <Label htmlFor="clone-pattern">Names</Label>
              <Input
                id="clone-pattern"
                className="font-mono"
                value={pattern}
                maxLength={80}
                onChange={(e) => setPattern(e.currentTarget.value)}
              />
              <p className="text-xs text-muted-foreground">
                <code>{"{template}"}</code> is each VM&apos;s name, <code>{"{n}"}</code> a number that skips names
                already taken, <code>{"{date}"}</code> today.
              </p>
            </div>
            <div className="grid gap-2">
              <Label>Folder</Label>
              <div className="flex min-w-0 items-center gap-2">
                <Button type="button" variant="outline" size="sm" onClick={() => void pickFolder()}>
                  <FolderOpenIcon data-icon="inline-start" />
                  Choose…
                </Button>
                <span className="min-w-0 truncate text-sm text-muted-foreground" title={folder ?? undefined}>
                  {folder ?? "The hypervisor's default folder"}
                </span>
                {folder && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    aria-label="Use the hypervisor's default folder"
                    onClick={() => setFolder(null)}
                  >
                    <XIcon />
                  </Button>
                )}
              </div>
            </div>
            {current?.problems.length ? (
              <ul className="grid gap-1 text-sm text-destructive" role="alert">
                {current.problems.map((p) => (
                  <li key={p.message}>{p.message}</li>
                ))}
              </ul>
            ) : null}
            {checkError && (
              <p className="text-sm text-destructive" role="alert">
                {checkError}
              </p>
            )}
            {current?.preview && <DeployPreviewView preview={current.preview} />}
            {/* VM-26: this PC after it, and what to suspend when it won't fit. */}
            {current?.capacity && (
              <CapacityPlanView
                capacity={current.capacity}
                readOnly={readOnly}
                onSubmitted={(outcome) => onSubmitted(outcome, () => {})}
              />
            )}
          </div>
        )}

        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <DialogFooter>
          {progress ? (
            <>
              {running && (
                <Button variant="outline" onClick={() => void api.cancelJob(progress.jobId)}>
                  Cancel the job
                </Button>
              )}
              <Button onClick={onClose}>{running ? "Hide" : "Close"}</Button>
            </>
          ) : (
            <>
              <Button variant="outline" onClick={onClose} disabled={busy}>
                Cancel
              </Button>
              <WhyDisabled reason={reason}>
                <Button onClick={() => void submit()} disabled={reason !== null}>
                  {busy ? "Submitting…" : vms.length > 1 ? `Clone ${vms.length} VMs` : "Clone"}
                </Button>
              </WhyDisabled>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
