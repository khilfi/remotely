// VM-21, VM-22: a launch template's fields, shared by the template editor and the Deploy dialog's Custom tab: an
// image and a size, with the hypervisor, VM folder (picked in a dialog the core opens; the hypervisor's own folder
// when none), network, SSH key (its public half goes to the VMs), naming pattern, environment label, tags,
// after-deploy steps, cloud-init's guest user and packages, and how a golden VM is cloned. The parent keeps the
// form; `effectiveInput` gives what the core gets.

import { useMemo } from "react";
import { FolderOpenIcon, XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import {
  api,
  errorMessage,
  type AfterDeploy,
  type CloneMode,
  type Environment,
  type Hypervisor,
  type Image,
  type OsProfile,
  type Size,
  type SshKey,
  type TemplateInput,
  type TemplateNetwork,
} from "@/lib/api";
import { HYPERVISOR_LABEL, networkKinds, networkOfKind, profileHypervisors, sizeSummary } from "@/lib/catalog";
import { parsePackages } from "@/lib/deploy";

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
  {
    key: "cleanSnapshot",
    label: "Take a “clean” snapshot",
    hint: "Before the first boot: going back to it boots the VM as deployed.",
  },
  { key: "openConsole", label: "Open the console", hint: "The hypervisor's own window." },
];

/** The form as the parent keeps it: text fields as typed. */
export interface TemplateForm {
  input: TemplateInput;
  tags: string;
  packages: string;
}

export function blankTemplate(images: Image[]): TemplateInput {
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
    guestUser: null,
    packages: [],
    cloneMode: "full",
  };
}

export function formOf(input: TemplateInput): TemplateForm {
  return { input, tags: input.tags.join(", "), packages: input.packages.join(", ") };
}

/** The hypervisors the form's image deploys on. */
function hypervisorsFor(image: Image | undefined, profile: OsProfile | undefined): Hypervisor[] {
  return (image?.hypervisors ?? (["vmware", "virtualbox"] as Hypervisor[])).filter((h) =>
    profileHypervisors(profile).includes(h),
  );
}

/**
 * What the core gets: an image that deploys on one hypervisor only takes the template there, with a network that
 * hypervisor has; tags and packages from their text.
 */
export function effectiveInput(
  form: TemplateForm,
  images: Image[],
  profiles: OsProfile[],
  count: number,
): TemplateInput {
  const image = images.find((i) => i.id === form.input.imageId);
  const profile = profiles.find((p) => p.id === image?.osProfile);
  const hypervisors = hypervisorsFor(image, profile);
  const hypervisor = hypervisors.includes(form.input.hypervisor)
    ? form.input.hypervisor
    : (hypervisors[0] ?? form.input.hypervisor);
  const network = networkKinds(hypervisor).includes(form.input.network.kind)
    ? form.input.network
    : { kind: "nat" as const };
  return {
    ...form.input,
    hypervisor,
    network,
    defaultCount: count,
    tags: form.tags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean),
    guestUser: form.input.guestUser?.trim() ? form.input.guestUser.trim() : null,
    packages: parsePackages(form.packages),
  };
}

interface Props {
  form: TemplateForm;
  onChange: (form: TemplateForm) => void;
  images: Image[];
  sizes: Size[];
  profiles: OsProfile[];
  keys: SshKey[];
  /** For the template editor: an image or size that was deleted is still named. */
  deletedImageId?: string;
  /** Shown beside the naming pattern: the template editor's default count, the Deploy dialog's count. */
  count: React.ReactNode;
  idPrefix: string;
  onError: (message: string) => void;
}

export function TemplateFields({
  form,
  onChange,
  images,
  sizes,
  profiles,
  keys,
  deletedImageId,
  count,
  idPrefix,
  onError,
}: Props) {
  const value = form.input;
  const set = (change: Partial<TemplateInput>) => onChange({ ...form, input: { ...value, ...change } });
  const image = images.find((i) => i.id === value.imageId);
  const profile = profiles.find((p) => p.id === image?.osProfile);
  const hypervisors = useMemo(() => hypervisorsFor(image, profile), [image, profile]);
  const builtIns = sizes.filter((s) => s.builtIn);
  const own = sizes.filter((s) => !s.builtIn);
  const size = sizes.find((s) => s.id === value.sizeId);
  const hypervisor = hypervisors.includes(value.hypervisor) ? value.hypervisor : (hypervisors[0] ?? value.hypervisor);
  const network: TemplateNetwork = networkKinds(hypervisor).includes(value.network.kind)
    ? value.network
    : { kind: "nat" };
  const keyChoices = keys.filter((k) => k.public !== null || k.id === value.sshKeyId);
  const golden = image?.source.kind === "goldenVm";
  const cloudInit = profile?.family !== "windows" && image?.source.kind !== "iso";
  const id = (name: string) => `${idPrefix}-${name}`;

  async function pickFolder() {
    try {
      const folder = await api.catalogFolderPick();
      if (folder) set({ vmFolder: folder });
    } catch (err) {
      onError(errorMessage(err));
    }
  }

  return (
    <>
      <div className="grid grid-cols-2 gap-3">
        <div className="grid gap-2">
          <Label htmlFor={id("name")}>Name</Label>
          <Input
            id={id("name")}
            value={value.name}
            maxLength={60}
            placeholder="web"
            onChange={(e) => set({ name: e.currentTarget.value })}
            autoFocus
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={id("image")}>Image</Label>
          <Select value={value.imageId} onValueChange={(v) => set({ imageId: v })}>
            <SelectTrigger id={id("image")} className="w-full">
              <SelectValue placeholder={images.length ? "Pick an image" : "Add an image first"} />
            </SelectTrigger>
            <SelectContent>
              {images.map((i) => (
                <SelectItem key={i.id} value={i.id}>
                  {i.name}
                  {i.problem ? " (can't deploy now)" : ""}
                </SelectItem>
              ))}
              {deletedImageId && !image && (
                <SelectItem value={deletedImageId} disabled>
                  (deleted image)
                </SelectItem>
              )}
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor={id("size")}>Size</Label>
          <Select value={value.sizeId} onValueChange={(v) => set({ sizeId: v })}>
            <SelectTrigger id={id("size")} className="w-full">
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
                <SelectItem value={value.sizeId} disabled>
                  (deleted size)
                </SelectItem>
              )}
            </SelectContent>
          </Select>
          {size && <p className="text-xs text-muted-foreground">{sizeSummary(size)}</p>}
        </div>
        <div className="grid gap-2">
          <Label htmlFor={id("hypervisor")}>Hypervisor</Label>
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
            <SelectTrigger id={id("hypervisor")} className="w-full">
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
          <span className="min-w-0 truncate text-sm text-muted-foreground" title={value.vmFolder ?? undefined}>
            {value.vmFolder ?? `${HYPERVISOR_LABEL[hypervisor]}'s default folder`}
          </span>
          {value.vmFolder && (
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
        <p className="text-xs text-muted-foreground">Each VM gets its own folder in it, named like the VM.</p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="grid gap-2">
          <Label htmlFor={id("network")}>Network</Label>
          <div className="flex gap-2">
            <Select
              value={network.kind}
              onValueChange={(v) => set({ network: networkOfKind(v as TemplateNetwork["kind"], network) })}
            >
              <SelectTrigger id={id("network")} className="w-full">
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
          <Label htmlFor={id("key")}>SSH key</Label>
          <Select value={value.sshKeyId ?? NONE} onValueChange={(v) => set({ sshKeyId: v === NONE ? null : v })}>
            <SelectTrigger id={id("key")} className="w-full">
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
          <p className="text-xs text-muted-foreground">Only its public half goes to the VMs.</p>
        </div>
      </div>

      <div className="grid grid-cols-[1fr_8rem] gap-3">
        <div className="grid gap-2">
          <Label htmlFor={id("pattern")}>Naming pattern</Label>
          <Input
            id={id("pattern")}
            className="font-mono"
            value={value.namingPattern}
            maxLength={80}
            onChange={(e) => set({ namingPattern: e.currentTarget.value })}
          />
          <p className="text-xs text-muted-foreground">
            <code>{"{n}"}</code> the VM&apos;s number, <code>{"{template}"}</code> the template&apos;s name,{" "}
            <code>{"{date}"}</code> today (YYYYMMDD).
          </p>
        </div>
        {count}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="grid gap-2">
          <Label>Environment</Label>
          <ToggleGroup
            type="single"
            variant="outline"
            size="sm"
            value={value.environment}
            onValueChange={(v) => v && set({ environment: v as Environment })}
          >
            {ENVIRONMENTS.map((e) => (
              <ToggleGroupItem key={e.value} value={e.value} className={e.className}>
                {e.label}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
          {value.environment === "prod" && (
            <p className="text-xs text-muted-foreground">Deploying Prod VMs needs a High approval.</p>
          )}
        </div>
        <div className="grid gap-2">
          <Label htmlFor={id("tags")}>Tags</Label>
          <Input
            id={id("tags")}
            value={form.tags}
            placeholder="web, frontend"
            onChange={(e) => onChange({ ...form, tags: e.currentTarget.value })}
          />
          <p className="text-xs text-muted-foreground">Separated by commas; the VMs get them.</p>
        </div>
      </div>

      <fieldset className="grid gap-2">
        <legend className="mb-2 text-sm font-medium">First boot (cloud-init)</legend>
        <div className="grid grid-cols-2 gap-3">
          <div className="grid gap-2">
            <Label htmlFor={id("user")}>Guest user</Label>
            <Input
              id={id("user")}
              className="font-mono"
              value={value.guestUser ?? ""}
              maxLength={32}
              placeholder="the image's default user"
              disabled={!cloudInit}
              onChange={(e) => set({ guestUser: e.currentTarget.value })}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor={id("packages")}>Packages</Label>
            <Input
              id={id("packages")}
              className="font-mono"
              value={form.packages}
              placeholder="nginx, htop"
              disabled={!cloudInit}
              onChange={(e) => onChange({ ...form, packages: e.currentTarget.value })}
            />
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          {cloudInit
            ? "cloud-init sets the hostname, makes the user with sudo and the SSH key, and installs the packages on first boot. No password is set or stored."
            : profile?.family === "windows"
              ? "Windows guests get no cloud-init setup."
              : "An ISO install has no OS yet, so nothing is set up on first boot."}
        </p>
      </fieldset>

      {golden && (
        <div className="grid gap-2">
          <Label>Golden VM clones</Label>
          <ToggleGroup
            type="single"
            variant="outline"
            size="sm"
            value={value.cloneMode}
            onValueChange={(v) => v && set({ cloneMode: v as CloneMode })}
          >
            <ToggleGroupItem value="full">Full clone</ToggleGroupItem>
            <ToggleGroupItem value="linked">Linked clone</ToggleGroupItem>
          </ToggleGroup>
          <p className="text-xs text-muted-foreground">
            {value.cloneMode === "linked"
              ? "Quick and small, but each clone needs the golden VM and its snapshot, and its disk can't grow to the size's."
              : "A copy that stands alone; its boot disk grows to the size's."}
          </p>
        </div>
      )}

      <fieldset className="grid gap-2">
        <legend className="mb-2 text-sm font-medium">After each VM is deployed</legend>
        <div className="grid grid-cols-2 gap-2">
          {STEPS.map((step) => (
            <Label key={step.key} className="flex items-start gap-2 font-normal">
              <Checkbox
                className="mt-0.5"
                checked={value.afterDeploy[step.key]}
                disabled={step.key === "linkSession" && !value.afterDeploy.createSession}
                onCheckedChange={(v) => {
                  const on = v === true;
                  const next = { ...value.afterDeploy, [step.key]: on };
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
    </>
  );
}
