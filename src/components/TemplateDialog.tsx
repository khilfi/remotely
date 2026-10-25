// VM-21: adds or edits a launch template: an image and a size, with the hypervisor, VM folder (picked in a dialog the
// core opens; the hypervisor's own folder when none), network, SSH key (its public half goes to the VMs), naming
// pattern, default count, environment label, tags and after-deploy steps. As it is filled in the core says why it
// couldn't deploy and which names its default count would get (VMs already here are skipped). Saved in the core and
// audited; deploying it arrives with the deploy package (R2).

import { useEffect, useMemo, useState } from "react";
import { AlertTriangleIcon, FolderOpenIcon, XIcon } from "lucide-react";
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
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useDebounced } from "@/hooks/use-debounced";
import {
  api,
  errorMessage,
  type AfterDeploy,
  type Environment,
  type Hypervisor,
  type Image,
  type LaunchTemplate,
  type OsProfile,
  type Size,
  type SshKey,
  type TemplateInput,
  type TemplateNetwork,
  type TemplatePreview,
} from "@/lib/api";
import {
  HYPERVISOR_LABEL,
  MAX_DEPLOY_COUNT,
  networkKinds,
  networkOfKind,
  profileHypervisors,
  sizeSummary,
} from "@/lib/catalog";

interface Props {
  /** The template to edit; without it, a new one from `initial` (Duplicate). */
  existing?: LaunchTemplate;
  initial?: TemplateInput;
  images: Image[];
  sizes: Size[];
  profiles: OsProfile[];
  onSaved: (template: LaunchTemplate) => void;
  onClose: () => void;
}

const NONE = "none";

const ENVIRONMENTS: { value: Environment; label: string; className?: string }[] = [
  { value: "none", label: "None" },
  { value: "lab", label: "Lab", className: "data-[state=on]:text-env-lab" },
  { value: "staging", label: "Staging", className: "data-[state=on]:text-env-staging" },
  { value: "prod", label: "Prod", className: "data-[state=on]:text-env-prod" },
];

const NETWORK_KIND_LABEL: Record<TemplateNetwork["kind"], string> = {
  nat: "NAT",
  hostOnly: "Host-only",
  bridged: "Bridged",
  vmnet: "Custom vmnet",
  natNetwork: "NAT network",
  internal: "Internal network",
};

const STEPS: { key: keyof AfterDeploy; label: string; hint: string }[] = [
  { key: "createSession", label: "Create the SSH session", hint: "Saved to the guest's IP once it shows." },
  { key: "linkSession", label: "Link it to the VM", hint: "So the dashboard and Compare know which VM it is." },
  { key: "cleanSnapshot", label: "Take a “clean” snapshot", hint: "Something to go back to." },
  { key: "openConsole", label: "Open the console", hint: "The hypervisor's own window." },
];

function blank(images: Image[]): TemplateInput {
  const image = images.find((i) => !i.problem) ?? images[0];
  return {
    name: "",
    imageId: image?.id ?? "",
    sizeId: "gp.medium",
    hypervisor: image?.hypervisors[0] ?? "vmware",
    vmFolder: null,
    network: { kind: "nat" },
    sshKeyId: null,
    namingPattern: "{template}-{n}",
    defaultCount: 1,
    environment: "none",
    tags: [],
    afterDeploy: { createSession: true, linkSession: true, cleanSnapshot: false, openConsole: false },
  };
}

function inputOf(t: LaunchTemplate): TemplateInput {
  return {
    name: t.name,
    imageId: t.imageId,
    sizeId: t.sizeId,
    hypervisor: t.hypervisor,
    vmFolder: t.vmFolder,
    network: t.network,
    sshKeyId: t.sshKeyId,
    namingPattern: t.namingPattern,
    defaultCount: t.defaultCount,
    environment: t.environment,
    tags: t.tags,
    afterDeploy: t.afterDeploy,
  };
}

export function TemplateDialog({ existing, initial, images, sizes, profiles, onSaved, onClose }: Props) {
  const [form, setForm] = useState<TemplateInput>(() => (existing ? inputOf(existing) : (initial ?? blank(images))));
  const [count, setCount] = useState(String(form.defaultCount));
  const [tags, setTags] = useState(form.tags.join(", "));
  const [keys, setKeys] = useState<SshKey[]>([]);
  const [preview, setPreview] = useState<TemplatePreview | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const set = (change: Partial<TemplateInput>) => setForm((f) => ({ ...f, ...change }));
  const image = images.find((i) => i.id === form.imageId);
  const profile = profiles.find((p) => p.id === image?.osProfile);
  const hypervisors = useMemo(
    () =>
      (image?.hypervisors ?? (["vmware", "virtualbox"] as Hypervisor[])).filter((h) =>
        profileHypervisors(profile).includes(h),
      ),
    [image, profile],
  );
  const builtIns = sizes.filter((s) => s.builtIn);
  const own = sizes.filter((s) => !s.builtIn);
  const size = sizes.find((s) => s.id === form.sizeId);

  // An image that deploys on one hypervisor only takes the template there, with a network that hypervisor has.
  const hypervisor = hypervisors.includes(form.hypervisor) ? form.hypervisor : (hypervisors[0] ?? form.hypervisor);
  const network: TemplateNetwork = useMemo(
    () => (networkKinds(hypervisor).includes(form.network.kind) ? form.network : { kind: "nat" }),
    [hypervisor, form.network],
  );

  const parsedCount = /^\d+$/.test(count.trim()) ? Number(count.trim()) : NaN;
  const input: TemplateInput = useMemo(
    () => ({
      ...form,
      hypervisor,
      network,
      defaultCount: parsedCount,
      tags: tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    }),
    [form, hypervisor, network, parsedCount, tags],
  );
  const checked = useDebounced(input, 250);

  useEffect(() => {
    api.sshKeys().then(setKeys, () => setKeys([]));
  }, []);

  // The core's check while it is filled in: problems, and the names its default count would get.
  useEffect(() => {
    if (!checked.imageId || !Number.isInteger(checked.defaultCount)) return;
    let stopped = false;
    api.catalogTemplatePreview(checked).then(
      (p) => {
        if (stopped) return;
        setPreview(p);
        setCheckError(null);
      },
      (err) => {
        if (stopped) return;
        setPreview(null);
        setCheckError(errorMessage(err));
      },
    );
    return () => {
      stopped = true;
    };
  }, [checked]);

  async function pickFolder() {
    try {
      const folder = await api.catalogFolderPick();
      if (folder) set({ vmFolder: folder });
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const saved = existing
        ? await api.catalogTemplateUpdate(existing.id, input)
        : await api.catalogTemplateAdd(input);
      onSaved(saved);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const reason = busy
    ? "Saving…"
    : !form.name.trim()
      ? "Give the template a name"
      : !image
        ? "Pick an image"
        : !Number.isInteger(parsedCount) || parsedCount < 1 || parsedCount > MAX_DEPLOY_COUNT
          ? `The default count is a whole number, 1 to ${MAX_DEPLOY_COUNT}`
          : null;
  const keyChoices = keys.filter((k) => k.public !== null || k.id === form.sshKeyId);

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{existing ? `Edit ${existing.name}` : "New launch template"}</DialogTitle>
          <DialogDescription>
            An image and a size with everything a deploy needs. Deploying arrives with the deploy package; templates you
            save now are ready for it.
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (!reason) void save();
          }}
        >
          <div className="-mx-1 grid max-h-[60vh] gap-4 overflow-x-hidden overflow-y-auto px-1">
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-2">
                <Label htmlFor="template-name">Name</Label>
                <Input
                  id="template-name"
                  value={form.name}
                  maxLength={60}
                  placeholder="web"
                  onChange={(e) => set({ name: e.currentTarget.value })}
                  autoFocus
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="template-image">Image</Label>
                <Select value={form.imageId} onValueChange={(v) => set({ imageId: v })}>
                  <SelectTrigger id="template-image" className="w-full">
                    <SelectValue placeholder={images.length ? "Pick an image" : "Add an image first"} />
                  </SelectTrigger>
                  <SelectContent>
                    {images.map((i) => (
                      <SelectItem key={i.id} value={i.id}>
                        {i.name}
                        {i.problem ? " (can't deploy now)" : ""}
                      </SelectItem>
                    ))}
                    {existing && !image && (
                      <SelectItem value={existing.imageId} disabled>
                        (deleted image)
                      </SelectItem>
                    )}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="template-size">Size</Label>
                <Select value={form.sizeId} onValueChange={(v) => set({ sizeId: v })}>
                  <SelectTrigger id="template-size" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectLabel>Built-in</SelectLabel>
                      {builtIns.map((s) => (
                        <SelectItem key={s.id} value={s.id}>
                          {s.name}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                    {own.length > 0 && (
                      <SelectGroup>
                        <SelectLabel>Yours</SelectLabel>
                        {own.map((s) => (
                          <SelectItem key={s.id} value={s.id}>
                            {s.name}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    )}
                    {!size && (
                      <SelectItem value={form.sizeId} disabled>
                        (deleted size)
                      </SelectItem>
                    )}
                  </SelectContent>
                </Select>
                {size && <p className="text-xs text-muted-foreground">{sizeSummary(size)}</p>}
              </div>
              <div className="grid gap-2">
                <Label htmlFor="template-hypervisor">Hypervisor</Label>
                <Select
                  value={hypervisor}
                  onValueChange={(v) => {
                    const h = v as Hypervisor;
                    set({
                      hypervisor: h,
                      network: networkKinds(h).includes(network.kind) ? network : { kind: "nat" },
                    });
                  }}
                >
                  <SelectTrigger id="template-hypervisor" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(["vmware", "virtualbox"] as Hypervisor[]).map((h) => (
                      <SelectItem key={h} value={h} disabled={!hypervisors.includes(h)}>
                        {HYPERVISOR_LABEL[h]}
                        {!hypervisors.includes(h) ? " (not for this image)" : ""}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
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
                    onClick={() => set({ vmFolder: null })}
                  >
                    <XIcon />
                  </Button>
                )}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-2">
                <Label htmlFor="template-network">Network</Label>
                <div className="flex gap-2">
                  <Select
                    value={network.kind}
                    onValueChange={(v) => set({ network: networkOfKind(v as TemplateNetwork["kind"], network) })}
                  >
                    <SelectTrigger id="template-network" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {networkKinds(hypervisor).map((k) => (
                        <SelectItem key={k} value={k}>
                          {NETWORK_KIND_LABEL[k]}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {network.kind === "vmnet" && (
                    <Input
                      aria-label="vmnet number"
                      className="w-20"
                      inputMode="numeric"
                      value={String(network.number)}
                      onChange={(e) => {
                        const n = Number(e.currentTarget.value.replace(/\D/g, "") || "0");
                        set({ network: { kind: "vmnet", number: Math.min(n, 99) } });
                      }}
                    />
                  )}
                  {(network.kind === "natNetwork" || network.kind === "internal") && (
                    <Input
                      aria-label="Network name"
                      placeholder="Name"
                      value={network.name}
                      maxLength={64}
                      onChange={(e) => {
                        const kind = network.kind as "natNetwork" | "internal";
                        set({ network: { kind, name: e.currentTarget.value } });
                      }}
                    />
                  )}
                </div>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="template-key">SSH key</Label>
                <Select value={form.sshKeyId ?? NONE} onValueChange={(v) => set({ sshKeyId: v === NONE ? null : v })}>
                  <SelectTrigger id="template-key" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NONE}>None</SelectItem>
                    {keyChoices.map((k) => (
                      <SelectItem key={k.id} value={k.id}>
                        {k.label}
                        {k.public ? ` (${k.public.algorithm})` : " (public half not read yet)"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">Only its public half goes to the VMs (SS-09).</p>
              </div>
            </div>

            <div className="grid grid-cols-[1fr_8rem] gap-3">
              <div className="grid gap-2">
                <Label htmlFor="template-pattern">Naming pattern</Label>
                <Input
                  id="template-pattern"
                  className="font-mono"
                  value={form.namingPattern}
                  maxLength={80}
                  onChange={(e) => set({ namingPattern: e.currentTarget.value })}
                />
                <p className="text-xs text-muted-foreground">
                  <code>{"{n}"}</code> the VM&apos;s number, <code>{"{template}"}</code> the template&apos;s name,{" "}
                  <code>{"{date}"}</code> today (YYYYMMDD).
                </p>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="template-count">Default count</Label>
                <Input
                  id="template-count"
                  inputMode="numeric"
                  value={count}
                  onChange={(e) => setCount(e.currentTarget.value)}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-2">
                <Label>Environment label</Label>
                <ToggleGroup
                  type="single"
                  variant="outline"
                  size="sm"
                  value={form.environment}
                  onValueChange={(v) => v && set({ environment: v as Environment })}
                >
                  {ENVIRONMENTS.map((e) => (
                    <ToggleGroupItem key={e.value} value={e.value} className={e.className}>
                      {e.label}
                    </ToggleGroupItem>
                  ))}
                </ToggleGroup>
                {form.environment === "prod" && (
                  <p className="text-xs text-muted-foreground">Deploying VMs labelled Prod needs a High approval.</p>
                )}
              </div>
              <div className="grid gap-2">
                <Label htmlFor="template-tags">Tags</Label>
                <Input
                  id="template-tags"
                  value={tags}
                  placeholder="web, frontend"
                  onChange={(e) => setTags(e.currentTarget.value)}
                />
                <p className="text-xs text-muted-foreground">Separated by commas; the VMs get them.</p>
              </div>
            </div>

            <fieldset className="grid gap-2">
              <legend className="mb-2 text-sm font-medium">After each VM is deployed</legend>
              <div className="grid grid-cols-2 gap-2">
                {STEPS.map((step) => (
                  <Label key={step.key} className="flex items-start gap-2 font-normal">
                    <Checkbox
                      className="mt-0.5"
                      checked={form.afterDeploy[step.key]}
                      disabled={step.key === "linkSession" && !form.afterDeploy.createSession}
                      onCheckedChange={(v) => {
                        const on = v === true;
                        const next = { ...form.afterDeploy, [step.key]: on };
                        if (step.key === "createSession" && !on) next.linkSession = false;
                        set({ afterDeploy: next });
                      }}
                    />
                    <span className="grid gap-0.5">
                      {step.label}
                      <span className="text-xs text-muted-foreground">{step.hint}</span>
                    </span>
                  </Label>
                ))}
              </div>
            </fieldset>

            {checkError && (
              <p className="text-sm text-destructive" role="alert">
                {checkError}
              </p>
            )}
            {preview && preview.problems.length > 0 && (
              <Alert>
                <AlertTriangleIcon />
                <AlertTitle>It can't deploy yet</AlertTitle>
                <AlertDescription>
                  <ul className="grid gap-1">
                    {preview.problems.map((p) => (
                      <li key={p.code + p.message}>{p.message}</li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}
            {preview && preview.vms.length > 0 && (
              <p className="text-sm text-muted-foreground">
                A deploy of {preview.vms.length} would make:{" "}
                <span className="font-mono text-foreground">{preview.vms.map((v) => v.name).join(", ")}</span>
              </p>
            )}
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <WhyDisabled reason={reason}>
              <Button type="submit" disabled={reason !== null}>
                {busy ? "Saving…" : existing ? "Save" : "Add template"}
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
