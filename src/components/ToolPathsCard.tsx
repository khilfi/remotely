// UX-10: Settings › Tools and VMs: every outside program Remotely runs, in one table ("vmrun · Found · Change"):
// vmrun (VMware Workstation), vdiskmanager beside it, ovftool, VBoxManage (VM-18), qemu-img (CV-03) and docker
// (CT-02). Change opens a small dialog with the path; an empty path finds the tool again by itself. How each is found
// (the path set here, its REMOTELY_ variable, the registry, the default folder) is the "?"'s. Each change saves at
// once, audited by the core, with Undo; the read-only lock refuses them.

import { useEffect, useState } from "react";
import { CheckIcon, CircleSlashIcon, ExternalLinkIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { HelpTip } from "@/components/HelpTip";
import { useReadOnlyReason } from "@/components/Presentation";
import { SaveStatus, useSaveStatus } from "@/components/SaveStatus";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type Settings } from "@/lib/api";
import { convertApi } from "@/lib/convert-api";
import type { SettingsChange } from "@/lib/job-events";
import { settingsCardId } from "@/lib/settings-index";
import { toolRows, toolStatus, type ToolId, type ToolRow } from "@/lib/settings-summary";
import { cn } from "@/lib/utils";

/** QEMU's download page (the core opens only this one). */
const QEMU_DOWNLOAD = "https://www.qemu.org/download/#windows";

const SAVE: Record<Exclude<ToolId, "vdiskmanager">, (path: string | null) => Promise<Settings>> = {
  vmrun: api.setVmrunPath,
  ovftool: api.setOvftoolPath,
  vboxmanage: api.setVboxmanagePath,
  qemuImg: convertApi.setQemuImgPath,
  docker: api.setDockerPath,
};

/** What else reads a tool's path again once it changes (the VM list, the sidebar, Containers). */
const CHANGE: Partial<Record<ToolId, SettingsChange>> = { vmrun: "vmrun", vboxmanage: "vboxmanage", docker: "docker" };

interface Props {
  settings: Settings | null;
  onSettings: (settings: Settings) => void;
  onChanged: (change: SettingsChange) => void;
  /** The row a link lights. */
  lit: string | null;
}

export function ToolPathsCard({ settings, onSettings, onChanged, lit }: Props) {
  const status = useSaveStatus();
  const readOnly = useReadOnlyReason();
  const [vdiskmanager, setVdiskmanager] = useState<string | null>(null);
  const [editing, setEditing] = useState<ToolRow | null>(null);

  // vdiskmanager is found beside vmrun: read again when vmrun's path changes.
  const vmrun = settings?.vmrunPathInUse ?? null;
  useEffect(() => {
    let live = true;
    convertApi.tools().then(
      (report) => live && setVdiskmanager(report.paths.vdiskmanager),
      () => live && setVdiskmanager(null),
    );
    return () => {
      live = false;
    };
  }, [vmrun]);

  async function save(id: Exclude<ToolId, "vdiskmanager">, path: string | null) {
    const saved = await SAVE[id](path);
    onSettings(saved);
    const change = CHANGE[id];
    if (change) onChanged(change);
    return saved;
  }

  const rows = settings ? toolRows(settings, vdiskmanager) : [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Tools
          <HelpTip topic="toolPaths" />
        </CardTitle>
        <CardDescription>The programs Remotely runs. Either hypervisor is enough.</CardDescription>
        <CardAction>
          <SaveStatus status={status} />
        </CardAction>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[40%]">Tool</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-24">
                  <span className="sr-only">Change</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => (
                <TableRow
                  key={row.id}
                  id={row.section ? settingsCardId(row.section) : undefined}
                  className={cn(
                    "scroll-mt-4",
                    row.section && lit === row.section && "bg-accent ring-2 ring-ring ring-inset",
                  )}
                >
                  <TableCell className="whitespace-normal">
                    <div className="font-medium">{row.exe}</div>
                    <div className="text-xs text-muted-foreground">{row.purpose}</div>
                  </TableCell>
                  <TableCell className="max-w-0 whitespace-normal">
                    <div className="flex items-center gap-1.5 text-sm">
                      {row.inUse ? (
                        <CheckIcon className="size-4 shrink-0 text-success" aria-hidden />
                      ) : (
                        <CircleSlashIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                      )}
                      <span className={row.inUse ? undefined : "text-muted-foreground"}>{toolStatus(row)}</span>
                      {row.id === "qemuImg" && !row.inUse && (
                        <Button
                          variant="link"
                          size="sm"
                          className="h-auto p-0"
                          onClick={() => void convertApi.openQemuSite(QEMU_DOWNLOAD)}
                        >
                          Get QEMU
                          <ExternalLinkIcon data-icon="inline-end" />
                        </Button>
                      )}
                    </div>
                    {(row.inUse ?? row.saved) && (
                      <div
                        className="truncate font-mono text-xs text-muted-foreground"
                        title={row.inUse ?? row.saved ?? ""}
                      >
                        {row.inUse ?? row.saved}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    {row.editable ? (
                      <WhyDisabled reason={readOnly}>
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={readOnly !== null}
                          aria-label={`Change the path of ${row.exe}`}
                          onClick={() => {
                            status.clear();
                            setEditing(row);
                          }}
                        >
                          Change
                        </Button>
                      </WhyDisabled>
                    ) : (
                      <span className="pr-3 text-xs text-muted-foreground">With vmrun</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
      {editing && editing.id !== "vdiskmanager" && (
        <ToolPathDialog
          row={editing}
          onSave={async (path) => {
            const id = editing.id as Exclude<ToolId, "vdiskmanager">;
            const before = editing.saved;
            let used: string | null = null;
            const ok = await status.run(
              async () => {
                used = rowOf(id, await save(id, path));
              },
              () => save(id, before),
            );
            return ok ? used : undefined;
          }}
          onClose={() => setEditing(null)}
        />
      )}
    </Card>
  );
}

/** The path in use for a tool, from settings read again. */
function rowOf(id: Exclude<ToolId, "vdiskmanager">, s: Settings): string | null {
  switch (id) {
    case "vmrun":
      return s.vmrunPathInUse;
    case "ovftool":
      return s.ovftoolPathInUse;
    case "vboxmanage":
      return s.vboxmanagePathInUse;
    case "qemuImg":
      return s.qemuImgPathInUse;
    case "docker":
      return s.dockerPathInUse;
  }
}

/** A tool's path: the one set here, or empty to find it again. */
function ToolPathDialog({
  row,
  onSave,
  onClose,
}: {
  row: ToolRow;
  /** Saves; resolves with the path now in use (null: not found), or undefined when the core refused it. */
  onSave: (path: string | null) => Promise<string | null | undefined>;
  onClose: () => void;
}) {
  const [path, setPath] = useState(row.saved ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(next: string | null) {
    setBusy(true);
    setError(null);
    try {
      const used = await onSave(next);
      if (used === undefined) setError("The path wasn't saved: the card says why.");
      else if (used === null && next !== null)
        setError(`${row.exe} isn't there. Check the path, or find it automatically.`);
      else onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (path.trim() && !busy) void submit(path.trim());
          }}
        >
          <DialogHeader>
            <DialogTitle>{row.exe}</DialogTitle>
            <DialogDescription>
              {row.inUse ? (
                <>
                  In use: <span className="font-mono break-all">{row.inUse}</span>
                </>
              ) : (
                `Not found. Give its full path, or install it and find it automatically.`
              )}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="tool-path">Path</Label>
            <Input
              id="tool-path"
              className="font-mono"
              placeholder={`C:\\…\\${row.exe}`}
              spellCheck={false}
              autoFocus
              value={path}
              onChange={(e) => setPath(e.currentTarget.value)}
            />
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter className="sm:justify-between">
            <Button
              type="button"
              variant="ghost"
              disabled={busy || row.saved === null}
              onClick={() => void submit(null)}
            >
              Find automatically
            </Button>
            <div className="flex gap-2">
              <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={busy || !path.trim()}>
                Use this path
              </Button>
            </div>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
