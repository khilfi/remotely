// VM-30 (0.8.0 G7): builds a golden image, or edits an image's build settings. A build makes one VM from an ISO image,
// installs it unattended from an own install config (Ubuntu autoinstall, Debian preseed or Windows unattend: G6's
// install), makes the system generic, shuts it down and keeps it with a snapshot: the image's next version, which its
// launch templates deploy from then on. The fields are the recipe the image keeps: the ISO, the config with its own
// variables, the size, the hypervisor, the network (and VirtualBox's adapter), the VM folder, an address pool for
// `{{ip}}`, the install's time limit, and how many versions to keep (deleting older versions' VMs that no linked clone
// uses, which makes the build Critical). The core checks it as it is filled in and shows what the build makes, the
// build VM's deploy preview and this PC after it. Build goes through the bus (the approval dialog, from the page's
// onSubmitted), then the dialog closes; Save keeps the settings for the next rebuild (audited, refused by the read-only
// lock) without building.

import { useEffect, useState } from "react";
import { FolderOpenIcon, TriangleAlertIcon, XIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Skeleton } from "@/components/ui/skeleton";
import { BuildDetailsView } from "@/components/BuildDetailsView";
import { CapacityPlanView } from "@/components/CapacityPlanView";
import { DeployPreviewView } from "@/components/DeployPreviewView";
import { HelpTip } from "@/components/HelpTip";
import { useReadOnlyReason } from "@/components/Presentation";
import { Term } from "@/components/Term";
import { NetworkField, SizeField } from "@/components/TemplateFields";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useDebounced } from "@/hooks/use-debounced";
import { api, errorMessage, type Hypervisor, type Image, type Size, type SubmitOutcome } from "@/lib/api";
import { addressPoolsApi, type AddressPool } from "@/lib/address-pools-api";
import { HYPERVISOR_LABEL } from "@/lib/catalog";
import { goldenApi, type BuildCheck, type BuildRequest } from "@/lib/golden-api";
import {
  buildConfigs,
  buildHypervisors,
  buildReason,
  defaultForm,
  formOfRecipe,
  formProblem,
  isoFamily,
  isoImages,
  MAX_IMAGE_NAME,
  MAX_KEEP_VERSIONS,
  needsHostAdapter,
  requestOf,
  withConfig,
  withHypervisor,
  withIso,
  type BuildChoices,
  type BuildForm,
  type BuildMode,
} from "@/lib/golden";
import { KIND_LABEL } from "@/lib/install-configs";
import { installConfigsApi } from "@/lib/install-configs-api";
import { poolsFor, rowVariables, usesPlaceholder } from "@/lib/unattended";

const NO_POOL = "none";

interface Props {
  /** An image Remotely builds, whose build settings are edited; without it, a new image is built. */
  image?: Image;
  /** A build goes through the app, which opens the approval dialog. */
  onSubmitted: (outcome: SubmitOutcome) => void;
  /** The build settings were saved. */
  onSaved?: (image: Image) => void;
  /** UX-07: with no ISO image yet, where to add one (the dialog closes). */
  onAddImage?: () => void;
  /** UX-07: with no install config for the ISO's system yet, where to make one (the dialog closes). */
  onNewConfig?: () => void;
  onClose: () => void;
}

export function BuildImageDialog({ image, onSubmitted, onSaved, onAddImage, onNewConfig, onClose }: Props) {
  // FD-03: the core refuses a build and a save while the read-only lock is on; the button says so first.
  const readOnly = useReadOnlyReason();
  const mode: BuildMode = image ? "settings" : "new";
  const [choices, setChoices] = useState<BuildChoices>({ images: [], configs: [], profiles: [] });
  const [sizes, setSizes] = useState<Size[]>([]);
  // Null until read (or when they can't be): a saved pool is then kept as it is.
  const [pools, setPools] = useState<AddressPool[] | null>(null);
  const [form, setForm] = useState<BuildForm | null>(null);
  const [adapters, setAdapters] = useState<string[]>([]);
  const [check, setCheck] = useState<{ key: string; check: BuildCheck } | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let stopped = false;
    Promise.all([
      api.catalogImages(),
      api.catalogSizes(),
      api.catalogProfiles(),
      installConfigsApi.list(),
      image ? goldenApi.rebuildRequest(image.id) : Promise.resolve(null),
    ]).then(
      ([images, s, profiles, configs, saved]) => {
        if (stopped) return;
        const picks = { images, configs, profiles };
        setChoices(picks);
        setSizes(s);
        setForm(saved && image ? formOfRecipe(image.name, saved.recipe) : defaultForm(picks));
      },
      (err) => !stopped && setError(errorMessage(err)),
    );
    addressPoolsApi.list().then(
      (list) => !stopped && setPools(list),
      () => {},
    );
    return () => {
      stopped = true;
    };
    // Once, when the dialog opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const set = (change: Partial<BuildForm>) => setForm((f) => (f ? { ...f, ...change } : f));
  const isos = isoImages(choices.images);
  const iso = choices.images.find((i) => i.id === form?.isoImageId);
  const configChoices = buildConfigs(choices.configs, isoFamily(iso, choices.profiles));
  const config = choices.configs.find((c) => c.id === form?.installConfigId) ?? null;
  const hypervisors = buildHypervisors(iso, choices.profiles);
  const hypervisor = form?.hypervisor ?? "vmware";
  const network = form?.network ?? { kind: "nat" as const };
  const needsAdapter = needsHostAdapter(hypervisor, network);
  const bridged = network.kind === "bridged";
  const variables = config ? rowVariables(config) : [];
  const usesIp = config ? usesPlaceholder(config.body, "ip") : false;
  const fittingPools = usesIp
    ? poolsFor(pools ?? [], hypervisor, network, needsAdapter ? form?.hostAdapter : null)
    : [];

  // VirtualBox's host-only or bridged adapters, when the network needs one.
  useEffect(() => {
    if (!needsAdapter) return;
    let stopped = false;
    api.deployHostAdapters(bridged).then(
      (list) => {
        if (stopped) return;
        setAdapters(list);
        setForm((f) =>
          f && !(f.hostAdapter && list.includes(f.hostAdapter)) ? { ...f, hostAdapter: list[0] ?? null } : f,
        );
      },
      () => !stopped && setAdapters([]),
    );
    return () => {
      stopped = true;
    };
  }, [needsAdapter, bridged]);

  // What is sent: a pool only where the config takes `{{ip}}` and the pool is on the build's network (kept as saved
  // while the pools can't be read).
  const keptPool =
    form && usesIp && (pools === null || fittingPools.some((p) => p.id === form.addressPoolId))
      ? form.addressPoolId
      : null;
  const sent: BuildForm | null = form ? { ...form, addressPoolId: keptPool } : null;
  const problem = form ? formProblem(form, mode, choices) : "Reading the catalogue…";
  const request: BuildRequest | null = sent && problem === null ? requestOf(sent, mode, image?.id) : null;
  const requestKey = JSON.stringify(request);
  const checkedKey = useDebounced(requestKey, 300);

  // The core's check as the dialog is filled in.
  useEffect(() => {
    if (checkedKey === "null") return;
    const asked = JSON.parse(checkedKey) as BuildRequest;
    let stopped = false;
    goldenApi.check(asked).then(
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
  }, [checkedKey]);

  const current = check?.key === requestKey ? check.check : null;
  const preview = current?.preview ?? null;
  const reason = buildReason({
    mode,
    readOnly,
    busy,
    problem,
    checking: requestKey !== checkedKey || (!current && !checkError),
    check: current,
    error: checkError,
  });

  async function go() {
    if (!request) return;
    setBusy(true);
    setError(null);
    try {
      if (image) {
        const saved = await goldenApi.setRecipe(image.id, request.recipe);
        onSaved?.(saved);
      } else {
        onSubmitted(await goldenApi.submit(request));
      }
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function pickFolder() {
    try {
      const folder = await api.catalogFolderPick();
      if (folder) set({ vmFolder: folder });
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-1">
            {image ? `Build settings of '${image.name}'` : "Build an image"}
            <HelpTip topic="golden.build" />
          </DialogTitle>
          <DialogDescription>
            {image ? (
              "What each rebuild builds its next version from. Saving builds nothing."
            ) : (
              <>
                A <Term id="goldenImage">golden image</Term> installed from an ISO by an install config, then made
                generic.
              </>
            )}
          </DialogDescription>
        </DialogHeader>

        {!form ? (
          !error && <Skeleton className="h-64 w-full" />
        ) : (
          <div className="-mx-1 grid max-h-[65vh] gap-4 overflow-x-hidden overflow-y-auto px-1">
            <div className="grid grid-cols-2 gap-3">
              {!image && (
                <div className="col-span-2 grid gap-2">
                  <Label htmlFor="build-name">Name</Label>
                  <Input
                    id="build-name"
                    value={form.name}
                    maxLength={MAX_IMAGE_NAME}
                    placeholder="Ubuntu 24.04 golden"
                    autoFocus
                    onChange={(e) => set({ name: e.currentTarget.value })}
                  />
                </div>
              )}
              <div className="grid gap-2">
                <Label htmlFor="build-iso">ISO image</Label>
                {isos.length === 0 ? (
                  // UX-07: no dead end; the Images tab adds one.
                  <div className="flex min-h-9 items-center gap-2 text-sm text-muted-foreground">
                    No ISO image yet.
                    {onAddImage && (
                      <Button
                        type="button"
                        variant="link"
                        size="sm"
                        className="h-auto p-0"
                        onClick={() => {
                          onClose();
                          onAddImage();
                        }}
                      >
                        Add an image
                      </Button>
                    )}
                  </div>
                ) : (
                  <Select value={form.isoImageId} onValueChange={(id) => setForm((f) => f && withIso(f, id, choices))}>
                    <SelectTrigger id="build-iso" className="w-full">
                      <SelectValue placeholder="Pick an ISO image" />
                    </SelectTrigger>
                    <SelectContent>
                      {isos.map((i) => (
                        <SelectItem key={i.id} value={i.id}>
                          {i.name}
                          {i.problem ? " (can't be used now)" : ""}
                        </SelectItem>
                      ))}
                      {form.isoImageId && !iso && (
                        <SelectItem value={form.isoImageId} disabled>
                          (deleted image)
                        </SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                )}
                {iso?.problem && <p className="text-xs text-destructive">{iso.problem}</p>}
              </div>
              <div className="grid gap-2">
                <Label htmlFor="build-config">
                  <Term id="installConfig">Install config</Term>
                </Label>
                {configChoices.length === 0 && !config ? (
                  <div className="flex min-h-9 items-center gap-2 text-sm text-muted-foreground">
                    None for this system yet.
                    {onNewConfig && (
                      <Button
                        type="button"
                        variant="link"
                        size="sm"
                        className="h-auto p-0"
                        onClick={() => {
                          onClose();
                          onNewConfig();
                        }}
                      >
                        New install config
                      </Button>
                    )}
                  </div>
                ) : (
                  <Select
                    value={form.installConfigId}
                    onValueChange={(id) => {
                      const picked = choices.configs.find((c) => c.id === id);
                      if (picked) setForm((f) => f && withConfig(f, picked));
                    }}
                  >
                    <SelectTrigger id="build-config" className="w-full">
                      <SelectValue placeholder="Pick an install config" />
                    </SelectTrigger>
                    <SelectContent>
                      {configChoices.map((c) => (
                        <SelectItem key={c.id} value={c.id}>
                          {c.name} ({KIND_LABEL[c.kind]})
                        </SelectItem>
                      ))}
                      {config && !configChoices.includes(config) && (
                        <SelectItem value={config.id}>
                          {config.name} ({KIND_LABEL[config.kind]})
                        </SelectItem>
                      )}
                      {form.installConfigId && !config && (
                        <SelectItem value={form.installConfigId} disabled>
                          (deleted install config)
                        </SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                )}
              </div>
              <SizeField id="build-size" sizes={sizes} value={form.sizeId} onChange={(sizeId) => set({ sizeId })} />
              <div className="grid gap-2">
                <Label htmlFor="build-hypervisor">Hypervisor</Label>
                <Select
                  value={hypervisor}
                  onValueChange={(v) => setForm((f) => f && withHypervisor(f, v as Hypervisor))}
                >
                  <SelectTrigger id="build-hypervisor" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(["vmware", "virtualbox"] as Hypervisor[]).map((h) => (
                      <SelectItem key={h} value={h} disabled={!hypervisors.includes(h)}>
                        {HYPERVISOR_LABEL[h]}
                        {!hypervisors.includes(h) ? " (not for this ISO)" : ""}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <NetworkField
                id="build-network"
                hypervisor={hypervisor}
                value={network}
                onChange={(next) => set({ network: next })}
              />
              {needsAdapter && (
                <div className="grid gap-2">
                  <Label htmlFor="build-adapter">{bridged ? "Bridge to" : "Host-only network"}</Label>
                  <Select value={form.hostAdapter ?? ""} onValueChange={(hostAdapter) => set({ hostAdapter })}>
                    <SelectTrigger id="build-adapter" className="w-full">
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
            </div>

            <div className="grid gap-2">
              <Label>VM folder</Label>
              <div className="flex min-w-0 items-center gap-2">
                <Button type="button" variant="outline" size="sm" onClick={() => void pickFolder()}>
                  <FolderOpenIcon data-icon="inline-start" />
                  Choose…
                </Button>
                <span className="min-w-0 truncate text-sm text-muted-foreground" title={form.vmFolder ?? undefined}>
                  {form.vmFolder ?? `${HYPERVISOR_LABEL[hypervisor]}'s default folder`}
                </span>
                {form.vmFolder && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    aria-label="Use the hypervisor's default folder"
                    title="Use the hypervisor's default folder"
                    onClick={() => set({ vmFolder: null })}
                  >
                    <XIcon />
                  </Button>
                )}
              </div>
              <p className="text-xs text-muted-foreground">Each version&apos;s VM gets its own folder in it.</p>
            </div>

            {config && (
              <section className="grid gap-3 rounded-md border p-3" aria-label="Unattended install">
                <div className="flex items-center gap-1 text-sm font-medium">
                  Unattended install from &apos;{config.name}&apos;
                  <HelpTip topic="deploy.unattended" />
                </div>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                  {variables.map((v) => (
                    <div key={v.name} className="grid gap-2">
                      <Label htmlFor={`build-var-${v.name}`} className="font-mono">
                        {v.name}
                      </Label>
                      <Input
                        id={`build-var-${v.name}`}
                        className="font-mono"
                        placeholder={v.fallback ?? ""}
                        value={form.values[v.name] ?? ""}
                        onChange={(e) => set({ values: { ...form.values, [v.name]: e.currentTarget.value } })}
                      />
                    </div>
                  ))}
                  {usesIp && (
                    <div className="grid gap-2">
                      <Label htmlFor="build-pool">Address from</Label>
                      <Select
                        value={sent?.addressPoolId ?? NO_POOL}
                        onValueChange={(v) => set({ addressPoolId: v === NO_POOL ? null : v })}
                      >
                        <SelectTrigger id="build-pool" className="w-full">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={NO_POOL}>No pool</SelectItem>
                          {fittingPools.map((p) => (
                            <SelectItem key={p.id} value={p.id}>
                              The pool {p.name} ({p.free} free)
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      {pools !== null && fittingPools.length === 0 && (
                        <p className="text-xs text-muted-foreground">No address pool is on this network.</p>
                      )}
                    </div>
                  )}
                  <div className="grid gap-2">
                    <Label htmlFor="build-minutes">Time limit (minutes)</Label>
                    <Input
                      id="build-minutes"
                      inputMode="numeric"
                      value={form.minutes}
                      onChange={(e) => set({ minutes: e.currentTarget.value })}
                    />
                  </div>
                </div>
              </section>
            )}

            <div className="grid gap-1">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <Checkbox
                  id="build-keep"
                  checked={form.keepOn}
                  onCheckedChange={(on) => set({ keepOn: on === true })}
                />
                <Label htmlFor="build-keep" className="font-normal">
                  Keep only the newest
                </Label>
                <Input
                  aria-label="Versions to keep"
                  className="w-16"
                  inputMode="numeric"
                  disabled={!form.keepOn}
                  value={form.keep}
                  onChange={(e) => set({ keep: e.currentTarget.value })}
                />
                <span>versions (1 to {MAX_KEEP_VERSIONS})</span>
                <HelpTip topic="golden.retention" />
              </div>
              {form.keepOn && (
                <p className="text-xs text-tier-high">
                  Older versions&apos; VMs are deleted after each build unless a linked clone uses them, so a build
                  needs the full approval.
                </p>
              )}
            </div>

            {current && !preview && current.problems.length > 0 && (
              <ul className="grid gap-1 text-sm text-destructive" role="alert">
                {current.problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            )}
            {checkError && (
              <p className="text-sm text-destructive" role="alert">
                {checkError}
              </p>
            )}
            {preview && (
              <>
                <BuildDetailsView details={preview.details} />
                {preview.warnings.length > 0 && (
                  <Alert className="border-tier-medium/40">
                    <TriangleAlertIcon className="text-tier-medium" />
                    <AlertTitle>Read this before you build</AlertTitle>
                    <AlertDescription>
                      <ul className="list-disc pl-5">
                        {preview.warnings.map((w) => (
                          <li key={w}>{w}</li>
                        ))}
                      </ul>
                    </AlertDescription>
                  </Alert>
                )}
                {/* Its warnings are the build's, listed above. */}
                <DeployPreviewView preview={preview.deploy} showWarnings={false} />
                <CapacityPlanView capacity={preview.capacity} readOnly={readOnly} onSubmitted={onSubmitted} />
              </>
            )}
          </div>
        )}

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
            <Button onClick={() => void go()} disabled={reason !== null || !request}>
              {busy ? (image ? "Saving…" : "Submitting…") : image ? "Save" : "Build"}
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
