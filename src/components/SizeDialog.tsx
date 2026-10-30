// VM-19: adds or edits one of the owner's sizes: its name, vCPU as sockets × cores per socket, RAM and disks (the first
// boots; each thin or thick, on the OS profile's controller or another), and a description. Duplicate opens this filled
// in from any size, built-ins included, under a free name. Saved in the core and audited.

import { useMemo, useState } from "react";
import { PlusIcon, Trash2Icon } from "lucide-react";
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
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type DiskController, type Provisioning, type Size, type SizeInput } from "@/lib/api";
import {
  CONTROLLER_LABEL,
  EMPTY_SIZE,
  MAX_DISKS,
  MAX_SIZE_NAME,
  MAX_VCPUS,
  parseSizeForm,
  sizeForm,
  sizeSummary,
  type DiskForm,
  type SizeForm,
} from "@/lib/catalog";

interface Props {
  /** An own size to edit; without it, a new size from `initial` (Duplicate). */
  existing?: Size;
  initial?: SizeInput;
  onSaved: (size: Size) => void;
  onClose: () => void;
}

const CONTROLLERS: (DiskController | "profile")[] = ["profile", "scsi", "sata", "nvme", "ide"];

export function SizeDialog({ existing, initial, onSaved, onClose }: Props) {
  const [form, setForm] = useState<SizeForm>(() => sizeForm(existing ?? initial ?? EMPTY_SIZE));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const parsed = useMemo(() => parseSizeForm(form), [form]);
  const formError = "error" in parsed ? parsed.error : null;

  const set = (change: Partial<SizeForm>) => setForm((f) => ({ ...f, ...change }));
  const setDisk = (index: number, change: Partial<DiskForm>) =>
    setForm((f) => ({ ...f, disks: f.disks.map((d, i) => (i === index ? { ...d, ...change } : d)) }));

  async function save() {
    if (!("input" in parsed)) return;
    setBusy(true);
    setError(null);
    try {
      const saved = existing
        ? await api.catalogSizeUpdate(existing.id, parsed.input)
        : await api.catalogSizeAdd(parsed.input);
      onSaved(saved);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const reason = busy ? "Saving…" : !form.name.trim() ? "Give the size a name" : formError;

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{existing ? `Edit ${existing.name}` : "New size"}</DialogTitle>
          <DialogDescription>
            What a VM gets, like a cloud instance type. Disks are thin unless you make them thick.
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (!reason) void save();
          }}
        >
          <div className="grid gap-2">
            <Label htmlFor="size-name">Name</Label>
            <Input
              id="size-name"
              value={form.name}
              maxLength={MAX_SIZE_NAME}
              placeholder="web.small"
              onChange={(e) => set({ name: e.currentTarget.value })}
              autoFocus
            />
            <p className="text-xs text-muted-foreground">
              Letters, digits, dots, hyphens and underscores, like gp.medium.
            </p>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="grid gap-2">
              <Label htmlFor="size-sockets">Sockets</Label>
              <Input
                id="size-sockets"
                inputMode="numeric"
                value={form.sockets}
                onChange={(e) => set({ sockets: e.currentTarget.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="size-cores">Cores per socket</Label>
              <Input
                id="size-cores"
                inputMode="numeric"
                value={form.coresPerSocket}
                onChange={(e) => set({ coresPerSocket: e.currentTarget.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="size-memory">RAM (GB)</Label>
              <Input
                id="size-memory"
                inputMode="decimal"
                value={form.memoryGb}
                onChange={(e) => set({ memoryGb: e.currentTarget.value })}
              />
            </div>
          </div>
          <p className="-mt-2 text-xs text-muted-foreground">
            At most {MAX_VCPUS} vCPUs and 128 GB of RAM (in steps of 4 MB).
          </p>
          <fieldset className="grid gap-2">
            <legend className="mb-2 text-sm font-medium">Disks</legend>
            {form.disks.map((disk, i) => (
              <div key={i} className="flex items-center gap-2">
                <span className="w-16 shrink-0 text-xs text-muted-foreground">{i === 0 ? "Boot" : `Data ${i}`}</span>
                <Input
                  aria-label={`Disk ${i + 1} size in GB`}
                  className="w-24"
                  inputMode="numeric"
                  value={disk.sizeGb}
                  onChange={(e) => setDisk(i, { sizeGb: e.currentTarget.value })}
                />
                <span className="text-sm text-muted-foreground">GB</span>
                <Select
                  value={disk.provisioning}
                  onValueChange={(v) => setDisk(i, { provisioning: v as Provisioning })}
                >
                  <SelectTrigger size="sm" className="w-24" aria-label={`Disk ${i + 1} provisioning`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="thin">Thin</SelectItem>
                    <SelectItem value="thick">Thick</SelectItem>
                  </SelectContent>
                </Select>
                <Select
                  value={disk.controller}
                  onValueChange={(v) => setDisk(i, { controller: v as DiskForm["controller"] })}
                >
                  <SelectTrigger size="sm" className="w-40" aria-label={`Disk ${i + 1} controller`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CONTROLLERS.map((c) => (
                      <SelectItem key={c} value={c}>
                        {c === "profile" ? "OS profile's controller" : CONTROLLER_LABEL[c]}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`Remove disk ${i + 1}`}
                  disabled={form.disks.length === 1}
                  onClick={() => set({ disks: form.disks.filter((_, j) => j !== i) })}
                >
                  <Trash2Icon />
                </Button>
              </div>
            ))}
            <div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={form.disks.length >= MAX_DISKS}
                onClick={() =>
                  set({ disks: [...form.disks, { sizeGb: "100", provisioning: "thin", controller: "profile" }] })
                }
              >
                <PlusIcon data-icon="inline-start" />
                Add a data disk
              </Button>
            </div>
          </fieldset>
          <div className="grid gap-2">
            <Label htmlFor="size-description">Description (optional)</Label>
            <Input
              id="size-description"
              value={form.description}
              maxLength={200}
              placeholder="What it is good for"
              onChange={(e) => set({ description: e.currentTarget.value })}
            />
          </div>
          {"input" in parsed && <p className="text-sm text-muted-foreground">{sizeSummary(parsed.input)}</p>}
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
                {busy ? "Saving…" : existing ? "Save" : "Add size"}
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
