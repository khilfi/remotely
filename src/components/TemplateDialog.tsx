// VM-21: adds or edits a launch template: an image and a size, with the hypervisor, VM folder, network, SSH key (its
// public half goes to the VMs), naming pattern, default count, environment label, tags, after-deploy steps, and
// (VM-22) cloud-init's guest user and packages and how a golden VM is cloned (TemplateFields). As it is filled in the
// core says why it couldn't deploy and which names its default count would get (VMs already here are skipped). Saved
// in the core and audited; Deploy on the template's row deploys it.

import { useEffect, useMemo, useState } from "react";
import { AlertTriangleIcon } from "lucide-react";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { WhyDisabled } from "@/components/WhyDisabled";
import { blankTemplate, effectiveInput, formOf, TemplateFields, type TemplateForm } from "@/components/TemplateFields";
import { useDebounced } from "@/hooks/use-debounced";
import {
  api,
  errorMessage,
  type Image,
  type LaunchTemplate,
  type OsProfile,
  type Size,
  type SshKey,
  type TemplateInput,
  type TemplatePreview,
} from "@/lib/api";
import { MAX_DEPLOY_COUNT } from "@/lib/catalog";

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
    guestUser: t.guestUser,
    packages: t.packages,
    cloneMode: t.cloneMode,
  };
}

export function TemplateDialog({ existing, initial, images, sizes, profiles, onSaved, onClose }: Props) {
  const [form, setForm] = useState<TemplateForm>(() =>
    formOf(existing ? inputOf(existing) : (initial ?? blankTemplate(images))),
  );
  const [count, setCount] = useState(String(form.input.defaultCount));
  const [keys, setKeys] = useState<SshKey[]>([]);
  const [preview, setPreview] = useState<TemplatePreview | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const parsedCount = /^\d+$/.test(count.trim()) ? Number(count.trim()) : NaN;
  const input = useMemo(
    () => effectiveInput(form, images, profiles, parsedCount),
    [form, images, profiles, parsedCount],
  );
  const checked = useDebounced(input, 250);
  const image = images.find((i) => i.id === form.input.imageId);

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
    : !form.input.name.trim()
      ? "Give the template a name"
      : !image
        ? "Pick an image"
        : !Number.isInteger(parsedCount) || parsedCount < 1 || parsedCount > MAX_DEPLOY_COUNT
          ? `The default count is a whole number, 1 to ${MAX_DEPLOY_COUNT}`
          : null;

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{existing ? `Edit ${existing.name}` : "New launch template"}</DialogTitle>
          <DialogDescription>
            An image and a size with everything a deploy needs. Deploy it from its row here, or from the VMs page.
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
            <TemplateFields
              form={form}
              onChange={setForm}
              images={images}
              sizes={sizes}
              profiles={profiles}
              keys={keys}
              deletedImageId={existing?.imageId}
              idPrefix="template"
              onError={setError}
              count={
                <div className="grid gap-2">
                  <Label htmlFor="template-count">Default count</Label>
                  <Input
                    id="template-count"
                    inputMode="numeric"
                    value={count}
                    onChange={(e) => setCount(e.currentTarget.value)}
                  />
                </div>
              }
            />

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
