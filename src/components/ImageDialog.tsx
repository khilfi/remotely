// VM-20: adds an image (a cloud image, an ISO, an OVA/OVF appliance, or a golden VM's snapshot) or edits one. A file
// is picked in a dialog the core opens; adding it checks its format and takes its SHA-256 in the core, with progress
// and Cancel, since images can be many GB. Files on network shares are refused by the core. A golden VM is picked from
// the VM list with one of its snapshots, and deploys on its own hypervisor only. Editing changes the name, hypervisors,
// OS profile and notes; its file or VM stays (another file is another image). Saved in the core and audited.

import { useEffect, useMemo, useRef, useState } from "react";
import { FolderOpenIcon } from "lucide-react";
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
import { Progress } from "@/components/ui/progress";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorCode,
  errorMessage,
  type Hypervisor,
  type Image,
  type ImageInput,
  type ImageKind,
  type OsProfile,
  type SnapshotNode,
  type VmRecord,
} from "@/lib/api";
import {
  fileSize,
  hashPercent,
  HYPERVISOR_LABEL,
  IMAGE_KIND_LABEL,
  imageWhere,
  profileHypervisors,
} from "@/lib/catalog";

interface Props {
  /** The image to edit; without it, a new one. */
  existing?: Image;
  profiles: OsProfile[];
  onSaved: (image: Image) => void;
  onClose: () => void;
}

const KINDS: { kind: ImageKind; hint: string }[] = [
  { kind: "cloudImage", hint: "A VMDK, OVA, .img or raw disk that boots with cloud-init; qcow2 is converted first." },
  { kind: "iso", hint: "An installer to boot a blank VM from." },
  { kind: "appliance", hint: "An OVA or OVF exported from any hypervisor, imported as it is." },
  { kind: "goldenVm", hint: "One of your VMs and one of its snapshots, cloned (full or linked)." },
];

const ALL: Hypervisor[] = ["vmware", "virtualbox"];

/** "noble-server-cloudimg-amd64" from its path. */
function baseName(path: string): string {
  const file = path.split(/[\\/]/).pop() ?? path;
  return file.replace(/\.[^.]+$/, "");
}

export function ImageDialog({ existing, profiles, onSaved, onClose }: Props) {
  const [kind, setKind] = useState<ImageKind>(existing?.source.kind ?? "cloudImage");
  const [path, setPath] = useState<string | null>(null);
  const [vms, setVms] = useState<VmRecord[]>([]);
  const [vmKey, setVmKey] = useState<string>("");
  const [snapshots, setSnapshots] = useState<SnapshotNode[] | null>(null);
  const [snapshot, setSnapshot] = useState<string>("");
  const [name, setName] = useState(existing?.name ?? "");
  const [osProfile, setOsProfile] = useState(existing?.osProfile ?? "ubuntu");
  const [hypervisors, setHypervisors] = useState<Hypervisor[]>(existing?.hypervisors ?? ALL);
  const [notes, setNotes] = useState(existing?.notes ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const request = useRef<string | null>(null);

  const profile = profiles.find((p) => p.id === osProfile);
  const vm = vms.find((v) => v.vmxPath === vmKey);
  const golden = kind === "goldenVm";
  /** What the image can deploy on: a golden VM's own hypervisor, and where its OS profile runs. */
  const allowed = useMemo(() => {
    const own = existing?.source.kind === "goldenVm" ? existing.hypervisors : golden && vm ? [vm.hypervisor] : ALL;
    return own.filter((h) => profileHypervisors(profile).includes(h));
  }, [existing, golden, vm, profile]);
  const picked = hypervisors.filter((h) => allowed.includes(h));

  // A golden VM is picked from the VM list.
  useEffect(() => {
    if (!golden || existing) return;
    api.vmList().then(setVms, (err) => setError(errorMessage(err)));
  }, [golden, existing]);

  useEffect(() => {
    if (!vmKey) return;
    let stopped = false;
    api.snapshots([vmKey]).then(
      (list) => {
        if (stopped) return;
        setSnapshots(list[0]?.snapshots ?? []);
        setSnapshot("");
      },
      (err) => !stopped && setError(errorMessage(err)),
    );
    return () => {
      stopped = true;
    };
  }, [vmKey]);

  // Hashing progress for this dialog's request.
  useEffect(() => {
    const unlisten = api.onCatalogHash((p) => {
      if (p.request === request.current) setProgress({ done: p.done, total: p.total });
    });
    return () => void unlisten.then((stop) => stop());
  }, []);

  async function pick() {
    setError(null);
    try {
      const chosen = await api.catalogImagePick(kind);
      if (!chosen) return;
      setPath(chosen);
      if (!name.trim()) setName(baseName(chosen));
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      if (existing) {
        const saved = await api.catalogImageUpdate(existing.id, {
          name,
          hypervisors: picked,
          osProfile,
          notes: notes.trim() || null,
        });
        onSaved(saved);
        onClose();
        return;
      }
      const source: ImageInput["source"] = golden
        ? { kind: "goldenVm", vmKey, snapshot }
        : kind === "iso"
          ? { kind: "iso", path: path ?? "" }
          : kind === "appliance"
            ? { kind: "appliance", path: path ?? "" }
            : { kind: "cloudImage", path: path ?? "" };
      const id = crypto.randomUUID();
      request.current = id;
      setProgress(golden ? null : { done: 0, total: 0 });
      const saved = await api.catalogImageAdd(id, {
        name,
        source,
        hypervisors: picked,
        osProfile,
        notes: notes.trim() || null,
      });
      onSaved(saved);
      onClose();
    } catch (err) {
      if (errorCode(err) !== "cancelled") setError(errorMessage(err));
    } finally {
      request.current = null;
      setProgress(null);
      setBusy(false);
    }
  }

  function cancel() {
    if (busy && request.current) {
      void api.catalogImageCancel(request.current);
      return;
    }
    onClose();
  }

  const reason = busy
    ? progress
      ? "Reading the file…"
      : "Saving…"
    : !name.trim()
      ? "Give the image a name"
      : existing
        ? picked.length === 0
          ? "Pick the hypervisors it deploys on"
          : null
        : golden
          ? !vmKey
            ? "Pick a VM"
            : !snapshot
              ? "Pick one of its snapshots: a golden VM image starts from one"
              : null
          : !path
            ? "Choose the file"
            : picked.length === 0
              ? "Pick the hypervisors it deploys on"
              : null;

  return (
    <Dialog open onOpenChange={(open) => !open && cancel()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{existing ? `Edit ${existing.name}` : "Add an image"}</DialogTitle>
          <DialogDescription>
            {existing
              ? `${IMAGE_KIND_LABEL[existing.source.kind]}: ${imageWhere(existing)}. To use another file or VM, add another image.`
              : "Where a new VM's OS comes from. Remotely reads the file once to take its checksum; it downloads nothing."}
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (!reason) void save();
          }}
        >
          {!existing && (
            <RadioGroup
              value={kind}
              onValueChange={(v) => {
                setKind(v as ImageKind);
                setPath(null);
                setError(null);
              }}
              className="grid grid-cols-2 gap-2"
              disabled={busy}
            >
              {KINDS.map((k) => (
                <Label
                  key={k.kind}
                  htmlFor={`image-kind-${k.kind}`}
                  className="flex cursor-pointer items-start gap-3 rounded-md border p-3 font-normal has-data-[state=checked]:border-primary"
                >
                  <RadioGroupItem id={`image-kind-${k.kind}`} value={k.kind} className="mt-0.5" />
                  <span className="grid gap-1">
                    <span className="font-medium">{IMAGE_KIND_LABEL[k.kind]}</span>
                    <span className="text-xs text-muted-foreground">{k.hint}</span>
                  </span>
                </Label>
              ))}
            </RadioGroup>
          )}

          {!existing && !golden && (
            <div className="grid gap-2">
              <Label>File</Label>
              <div className="flex min-w-0 items-center gap-3">
                <Button type="button" variant="outline" onClick={() => void pick()} disabled={busy}>
                  <FolderOpenIcon data-icon="inline-start" />
                  {path ? "Choose another…" : "Choose a file…"}
                </Button>
                <span className="min-w-0 truncate text-sm text-muted-foreground" title={path ?? undefined}>
                  {path ?? "No file chosen"}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">
                On this PC: files on network shares are refused. Copy them here first.
              </p>
            </div>
          )}

          {!existing && golden && (
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-2">
                <Label htmlFor="image-vm">VM</Label>
                <Select value={vmKey} onValueChange={setVmKey} disabled={busy}>
                  <SelectTrigger id="image-vm" className="w-full">
                    <SelectValue placeholder={vms.length ? "Pick a VM" : "No VMs in the list"} />
                  </SelectTrigger>
                  <SelectContent>
                    {vms.map((v) => (
                      <SelectItem key={v.vmxPath} value={v.vmxPath}>
                        {v.displayName} ({HYPERVISOR_LABEL[v.hypervisor]})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="image-snapshot">Snapshot</Label>
                <Select value={snapshot} onValueChange={setSnapshot} disabled={busy || !snapshots?.length}>
                  <SelectTrigger id="image-snapshot" className="w-full">
                    <SelectValue
                      placeholder={
                        !vmKey ? "Pick a VM first" : snapshots?.length ? "Pick a snapshot" : "It has no snapshots"
                      }
                    />
                  </SelectTrigger>
                  <SelectContent>
                    {(snapshots ?? []).map((s) => (
                      <SelectItem key={s.path} value={s.path}>
                        {"   ".repeat(s.depth)}
                        {s.name || "(no name)"}
                        {s.current ? " (you are here)" : ""}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-2">
              <Label htmlFor="image-name">Name</Label>
              <Input
                id="image-name"
                value={name}
                maxLength={80}
                placeholder="Ubuntu 24.04 cloud"
                onChange={(e) => setName(e.currentTarget.value)}
                disabled={busy}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="image-profile">OS profile</Label>
              <Select value={osProfile} onValueChange={setOsProfile} disabled={busy}>
                <SelectTrigger id="image-profile" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {profiles.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          {profile && (
            <p className="-mt-2 text-xs text-muted-foreground">
              {profile.workstation
                ? `Workstation: ${profile.workstation.guestOs}, ${profile.workstation.nic}. `
                : `${profile.workstationNote ?? ""} `}
              VirtualBox: {profile.virtualbox.osType}, {profile.virtualbox.nic}
              {profile.virtualbox.tpm ? `, TPM ${profile.virtualbox.tpm}` : ""}.
            </p>
          )}

          <fieldset className="grid gap-2">
            <legend className="mb-2 text-sm font-medium">Deploys on</legend>
            <div className="flex gap-6">
              {ALL.map((h) => {
                const why = allowed.includes(h)
                  ? null
                  : golden || existing?.source.kind === "goldenVm"
                    ? "A golden VM deploys on its own hypervisor only"
                    : (profile?.workstationNote ?? "Not for this OS profile");
                return (
                  <WhyDisabled key={h} reason={why}>
                    <Label className="flex items-center gap-2 font-normal">
                      <Checkbox
                        checked={picked.includes(h)}
                        disabled={why !== null || busy}
                        onCheckedChange={(v) =>
                          setHypervisors((list) => (v === true ? [...list, h] : list.filter((x) => x !== h)))
                        }
                      />
                      {HYPERVISOR_LABEL[h]}
                    </Label>
                  </WhyDisabled>
                );
              })}
            </div>
          </fieldset>

          <div className="grid gap-2">
            <Label htmlFor="image-notes">Notes (optional)</Label>
            <Textarea
              id="image-notes"
              rows={3}
              value={notes}
              maxLength={2000}
              placeholder="Where it came from, what is installed, its default user"
              onChange={(e) => setNotes(e.currentTarget.value)}
              disabled={busy}
            />
          </div>

          {progress && (
            <div className="grid gap-1.5">
              <Progress value={hashPercent(progress.done, progress.total)} />
              <p className="text-xs text-muted-foreground">
                Reading the file for its SHA-256: {fileSize(progress.done)} of {fileSize(progress.total)}
              </p>
            </div>
          )}
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={cancel} disabled={busy && !progress}>
              {busy && progress ? "Stop" : "Cancel"}
            </Button>
            <WhyDisabled reason={reason}>
              <Button type="submit" disabled={reason !== null}>
                {busy ? (progress ? "Reading…" : "Saving…") : existing ? "Save" : "Add image"}
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
