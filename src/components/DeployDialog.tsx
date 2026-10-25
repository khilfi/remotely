// VM-21, VM-22: the Deploy dialog. Pick a launch template, or Custom (every value by hand, checked by the core like a
// template), then the count and names (the template's naming pattern unless another is typed) and, for VirtualBox's
// host-only or bridged networks, the adapter. The core checks it as it is filled in and shows the AP-02 preview:
// names, hypervisor, folder, size, disk space each and in all, network. Deploy goes through the bus (the approval
// dialog for Medium and above), then the dialog follows the job with a step per VM; Cancel stops it, and a VM that
// was being made is removed with everything it made.

import { useEffect, useMemo, useState } from "react";
import { CheckCircle2Icon, CircleDashedIcon, Loader2Icon, XCircleIcon } from "lucide-react";
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
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DeployPreviewView } from "@/components/DeployPreviewView";
import { useReadOnlyReason } from "@/components/Presentation";
import { blankTemplate, effectiveInput, formOf, TemplateFields, type TemplateForm } from "@/components/TemplateFields";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useDebounced } from "@/hooks/use-debounced";
import {
  api,
  errorMessage,
  type DeployCheck,
  type DeployRequest,
  type Image,
  type LaunchTemplate,
  type OsProfile,
  type SecretMeta,
  type Size,
  type SshKey,
  type SubmitOutcome,
} from "@/lib/api";
import { HYPERVISOR_LABEL, templateReason } from "@/lib/catalog";
import {
  applyJobEvent,
  applyJobTargets,
  deployReason,
  newVmKey,
  parseCount,
  progressSummary,
  startProgress,
  stepText,
  type DeployProgress,
  type DeployStep,
} from "@/lib/deploy";

interface Props {
  /** The template to start with (its row's Deploy); none: the first that can deploy. */
  templateId?: string | null;
  /** Goes through the app, which opens the approval dialog; `onJob` gets the job id once queued. */
  onSubmitted: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onClose: () => void;
}

type Mode = "template" | "custom";

function StepIcon({ step }: { step: DeployStep }) {
  switch (step.status) {
    case "running":
      return <Loader2Icon className="size-4 animate-spin text-muted-foreground" aria-label="Making it" />;
    case "succeeded":
      return <CheckCircle2Icon className="size-4 text-tier-low" aria-label="Made" />;
    case "failed":
    case "unknown":
      return <XCircleIcon className="size-4 text-destructive" aria-label="Failed" />;
    default:
      return <CircleDashedIcon className="size-4 text-muted-foreground" aria-label="Waiting" />;
  }
}

/** The job's steps, one per VM, with Cancel while it runs. */
export function DeployProgressView({ progress }: { progress: DeployProgress }) {
  return (
    <div className="grid gap-2 text-sm">
      <p className="font-medium">{progressSummary(progress)}</p>
      <ul className="grid max-h-72 gap-2 overflow-auto rounded-md border p-3">
        {progress.steps.map((step) => (
          <li key={step.target} className="flex items-start gap-2">
            <StepIcon step={step} />
            <div className="min-w-0">
              <div className="font-medium">{step.name}</div>
              <div className="text-xs break-words whitespace-pre-wrap text-muted-foreground">{stepText(step)}</div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * Follows a deploy's job: its events as they come, and the journal when it is first followed (events sent before the
 * approval dialog handed the job over) and when it ends.
 */
export function useDeployProgress(): [DeployProgress | null, (start: DeployProgress) => void] {
  const [progress, setProgress] = useState<DeployProgress | null>(null);
  const jobId = progress?.jobId ?? null;
  useEffect(() => {
    if (!jobId) return;
    let stopped = false;
    const reconcile = () =>
      api.jobTargets(jobId).then(
        (targets) => !stopped && setProgress((p) => (p ? applyJobTargets(p, targets) : p)),
        () => {},
      );
    const unlisten = api.onJobEvent((event) => {
      setProgress((p) => (p ? applyJobEvent(p, event) : p));
      if (event.jobId === jobId && event.event === "finished") void reconcile();
    });
    void reconcile();
    return () => {
      stopped = true;
      void unlisten.then((stop) => stop());
    };
  }, [jobId]);
  return [progress, setProgress];
}

export function DeployDialog({ templateId, onSubmitted, onClose }: Props) {
  // FD-03: the core refuses a deploy while the read-only lock is on; the button says so first.
  const readOnly = useReadOnlyReason();
  const [mode, setMode] = useState<Mode>("template");
  const [templates, setTemplates] = useState<LaunchTemplate[] | null>(null);
  const [chosen, setChosen] = useState<string | null>(templateId ?? null);
  const [images, setImages] = useState<Image[]>([]);
  const [sizes, setSizes] = useState<Size[]>([]);
  const [profiles, setProfiles] = useState<OsProfile[]>([]);
  const [keys, setKeys] = useState<SshKey[]>([]);
  const [custom, setCustom] = useState<TemplateForm | null>(null);
  const [countText, setCountText] = useState("1");
  const [pattern, setPattern] = useState("");
  const [adapters, setAdapters] = useState<string[]>([]);
  const [adapter, setAdapter] = useState<string | null>(null);
  const [passwords, setPasswords] = useState<SecretMeta[]>([]);
  const [guestPassword, setGuestPassword] = useState<string | null>(null);
  const [check, setCheck] = useState<{ key: string; check: DeployCheck } | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setStarted] = useDeployProgress();
  const following = progress !== null;

  useEffect(() => {
    let stopped = false;
    Promise.all([api.catalogTemplates(), api.catalogImages(), api.catalogSizes(), api.catalogProfiles()]).then(
      ([t, i, s, p]) => {
        if (stopped) return;
        setTemplates(t);
        setImages(i);
        setSizes(s);
        setProfiles(p);
        setCustom((c) => c ?? formOf({ ...blankTemplate(i), name: "custom" }));
        const first = t.find((x) => x.id === templateId) ?? t.find((x) => x.problems.length === 0) ?? t[0];
        if (first) choose(first);
        if (t.length === 0) setMode("custom");
      },
      (err) => !stopped && setError(errorMessage(err)),
    );
    api.sshKeys().then(
      (k) => !stopped && setKeys(k),
      () => {},
    );
    api.secrets().then(
      (list) => !stopped && setPasswords(list.filter((x) => x.kind === "password")),
      () => {},
    );
    return () => {
      stopped = true;
    };
    // Once, when the dialog opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /** A template, with its count and naming pattern to start from. */
  function choose(t: LaunchTemplate) {
    setChosen(t.id);
    setCountText(String(t.defaultCount));
    setPattern(t.namingPattern);
  }

  const template = templates?.find((t) => t.id === chosen) ?? null;

  const count = parseCount(countText);
  const customInput = useMemo(
    () => (custom ? effectiveInput(custom, images, profiles, count ?? 1) : null),
    [custom, images, profiles, count],
  );
  const hypervisor = mode === "template" ? template?.hypervisor : customInput?.hypervisor;
  const network = mode === "template" ? template?.network : customInput?.network;
  const needsAdapter = hypervisor === "virtualbox" && (network?.kind === "hostOnly" || network?.kind === "bridged");
  // VM-21: VirtualBox installs some ISOs by itself, with a vault password for the guest user.
  const imageId = mode === "template" ? template?.imageId : customInput?.imageId;
  const isoOnVirtualBox = hypervisor === "virtualbox" && images.find((i) => i.id === imageId)?.source.kind === "iso";
  const bridged = network?.kind === "bridged";

  // VirtualBox's host-only or bridged adapters, when the network needs one.
  useEffect(() => {
    if (!needsAdapter) return;
    let stopped = false;
    api.deployHostAdapters(bridged).then(
      (list) => {
        if (stopped) return;
        setAdapters(list);
        setAdapter((a) => (a && list.includes(a) ? a : (list[0] ?? null)));
      },
      () => !stopped && setAdapters([]),
    );
    return () => {
      stopped = true;
    };
  }, [needsAdapter, bridged]);

  const request: DeployRequest | null =
    count === null
      ? null
      : mode === "template"
        ? template
          ? {
              from: { kind: "template", id: template.id },
              count,
              namingPattern: pattern.trim() && pattern.trim() !== template.namingPattern ? pattern.trim() : null,
              hostAdapter: needsAdapter ? adapter : null,
              guestPasswordId: isoOnVirtualBox ? guestPassword : null,
            }
          : null
        : customInput && customInput.imageId
          ? {
              from: { kind: "custom", input: customInput },
              count,
              hostAdapter: needsAdapter ? adapter : null,
              guestPasswordId: isoOnVirtualBox ? guestPassword : null,
            }
          : null;
  const requestKey = JSON.stringify(request);
  const checkedKey = useDebounced(requestKey, 300);

  // The core's check as the dialog is filled in.
  useEffect(() => {
    if (checkedKey === "null" || following) return;
    const asked = JSON.parse(checkedKey) as DeployRequest;
    let stopped = false;
    api.deployCheck(asked).then(
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
  }, [checkedKey, following]);

  const current = check?.key === requestKey ? check.check : null;
  const reason =
    readOnly ??
    (mode === "template" && !template
      ? templates?.length === 0
        ? "Add a launch template on the Templates page, or use Custom"
        : "Pick a launch template"
      : deployReason({
          busy,
          count,
          checking: requestKey !== checkedKey || (!current && !checkError),
          check: current,
          error: checkError,
        }));

  async function deploy() {
    if (!request || !current?.preview) return;
    const vms = current.preview.vms.map((vm) => ({
      name: vm.name,
      target: newVmKey(current.preview?.hypervisor ?? "vmware", vm.name),
    }));
    setBusy(true);
    setError(null);
    try {
      onSubmitted(await api.deploySubmit(request), (jobId) => setStarted(startProgress(jobId, vms)));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const running = progress !== null && progress.finished === null;

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>{progress ? (current?.preview?.summary ?? "Deploy") : "Deploy VMs"}</DialogTitle>
          <DialogDescription>
            {progress
              ? "One step per VM. Cancel stops the job: the VM being made is removed with everything it made, and VMs already made stay."
              : "From a launch template, or Custom with every value chosen here. You see what it makes, and approve it, before anything is made."}
          </DialogDescription>
        </DialogHeader>

        {progress ? (
          <DeployProgressView progress={progress} />
        ) : (
          <div className="-mx-1 grid max-h-[65vh] gap-4 overflow-x-hidden overflow-y-auto px-1">
            <Tabs value={mode} onValueChange={(v) => setMode(v as Mode)}>
              <TabsList>
                <TabsTrigger value="template">Launch template</TabsTrigger>
                <TabsTrigger value="custom">Custom</TabsTrigger>
              </TabsList>
            </Tabs>

            {mode === "template" ? (
              <div className="grid grid-cols-[1fr_1fr_8rem] gap-3">
                <div className="grid gap-2">
                  <Label htmlFor="deploy-template">Launch template</Label>
                  <Select
                    value={chosen ?? ""}
                    onValueChange={(id) => {
                      const t = templates?.find((x) => x.id === id);
                      if (t) choose(t);
                    }}
                  >
                    <SelectTrigger id="deploy-template" className="w-full">
                      <SelectValue placeholder={templates?.length === 0 ? "No templates yet" : "Pick a template"} />
                    </SelectTrigger>
                    <SelectContent>
                      {(templates ?? []).map((t) => (
                        <SelectItem key={t.id} value={t.id} disabled={t.problems.length > 0}>
                          {t.name} ({HYPERVISOR_LABEL[t.hypervisor]}){t.problems.length > 0 ? ": can't deploy" : ""}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {template && templateReason(template) && (
                    <p className="text-xs text-destructive">{templateReason(template)}</p>
                  )}
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="deploy-pattern">Names</Label>
                  <Input
                    id="deploy-pattern"
                    className="font-mono"
                    value={pattern}
                    maxLength={80}
                    onChange={(e) => setPattern(e.currentTarget.value)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="deploy-count">Count</Label>
                  <Input
                    id="deploy-count"
                    inputMode="numeric"
                    value={countText}
                    onChange={(e) => setCountText(e.currentTarget.value)}
                  />
                </div>
              </div>
            ) : (
              custom && (
                <TemplateFields
                  form={custom}
                  onChange={setCustom}
                  images={images}
                  sizes={sizes}
                  profiles={profiles}
                  keys={keys}
                  idPrefix="deploy-custom"
                  onError={setError}
                  count={
                    <div className="grid gap-2">
                      <Label htmlFor="deploy-custom-count">Count</Label>
                      <Input
                        id="deploy-custom-count"
                        inputMode="numeric"
                        value={countText}
                        onChange={(e) => setCountText(e.currentTarget.value)}
                      />
                    </div>
                  }
                />
              )
            )}

            {isoOnVirtualBox && (
              <div className="grid max-w-md gap-2">
                <Label htmlFor="deploy-guest-password">Install by itself</Label>
                <Select
                  value={guestPassword ?? "none"}
                  onValueChange={(v) => setGuestPassword(v === "none" ? null : v)}
                >
                  <SelectTrigger id="deploy-guest-password" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">No: install it from the console</SelectItem>
                    {passwords.map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        Yes, with the vault password {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  VirtualBox installs the ISOs it knows unattended, as the template&apos;s guest user with this
                  password. It reads it from a file only you can read, which Remotely deletes at once; approving asks
                  for the vault password.
                </p>
              </div>
            )}
            {needsAdapter && (
              <div className="grid max-w-md gap-2">
                <Label htmlFor="deploy-adapter">{bridged ? "Bridge to" : "Host-only network"}</Label>
                <Select value={adapter ?? ""} onValueChange={setAdapter}>
                  <SelectTrigger id="deploy-adapter" className="w-full">
                    <SelectValue placeholder="VirtualBox lists none" />
                  </SelectTrigger>
                  <SelectContent>
                    {adapters.map((a) => (
                      <SelectItem key={a} value={a}>
                        {a}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {current?.problems.length ? (
              <ul className="grid gap-1 text-sm text-destructive" role="alert">
                {current.problems.map((p) => (
                  <li key={p.code + p.message}>{p.message}</li>
                ))}
              </ul>
            ) : null}
            {checkError && (
              <p className="text-sm text-destructive" role="alert">
                {checkError}
              </p>
            )}
            {current?.preview && <DeployPreviewView preview={current.preview} />}
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
                <Button onClick={() => void deploy()} disabled={reason !== null}>
                  {busy ? "Submitting…" : count && count > 1 ? `Deploy ${count} VMs` : "Deploy"}
                </Button>
              </WhyDisabled>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
