// FD-02: the top bar's workspace switcher. One workspace per customer engagement: the menu lists the active ones, makes
// a new one, edits the shown one's name and colour, and manages them all (archive, restore). Switching asks first,
// says what closes (terminals, MultiExec, waiting approvals) and is refused while jobs started in this workspace run;
// once the core has switched, the window loads again, so nothing the old workspace showed stays in memory.
//
// Workspace names may be customer names: every element that shows one is `data-mask="workspace"`, so presentation
// mode (FD-03) shows `workspace-1` instead, and the masker learns them for any other text.

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  ArchiveIcon,
  ArchiveRestoreIcon,
  CheckIcon,
  ChevronsUpDownIcon,
  PencilIcon,
  PlusIcon,
  SettingsIcon,
} from "lucide-react";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { errorMessage } from "@/lib/api";
import { cn } from "@/lib/utils";
import { workspacesApi, type SwitchPreview, type Workspace } from "@/lib/workspaces-api";
import {
  COLOR_LABEL,
  colorClass,
  MAX_WORKSPACE_NAME,
  nameProblem,
  SWITCH_NOTE,
  switchable,
  switchCloses,
  switchRefusal,
  WORKSPACE_COLORS,
  type WorkspaceColor,
} from "@/lib/workspaces";

/** The coloured dot before a workspace's name. */
export function WorkspaceDot({ color, className }: { color: string; className?: string }) {
  return (
    <span aria-hidden className={cn("inline-block size-2.5 shrink-0 rounded-full", colorClass(color), className)} />
  );
}

/** The switch itself: the core closes what the old workspace had open, then the window loads the new one. */
export async function switchWorkspace(id: string) {
  await workspacesApi.switchTo(id);
  window.location.reload();
}

interface Props {
  /** Opens Activity (the switch's refusal offers it while jobs run). */
  onOpenActivity: () => void;
}

export function WorkspaceSwitcher({ onOpenActivity }: Props) {
  const [all, setAll] = useState<Workspace[]>([]);
  const [editing, setEditing] = useState<Workspace | "new" | null>(null);
  const [managing, setManaging] = useState(false);
  const [switching, setSwitching] = useState<Workspace | null>(null);
  const readOnly = useReadOnlyReason();

  const load = useCallback(async () => {
    try {
      setAll(await workspacesApi.list());
    } catch (err) {
      toast.error(`Could not read the workspaces: ${errorMessage(err)}`);
    }
  }, []);

  useEffect(() => {
    let live = true;
    workspacesApi.list().then(
      (list) => {
        if (live) setAll(list);
      },
      (err) => toast.error(`Could not read the workspaces: ${errorMessage(err)}`),
    );
    return () => {
      live = false;
    };
  }, []);

  const shown = all.find((w) => w.current);
  const list = switchable(all);

  return (
    <>
      <DropdownMenu onOpenChange={(open) => open && void load()}>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" className="max-w-56 gap-2 px-2" aria-label="Workspace: switch or manage">
            {shown && <WorkspaceDot color={shown.color} />}
            <span className="truncate font-medium" data-mask="workspace">
              {shown?.name ?? "Workspace"}
            </span>
            <ChevronsUpDownIcon className="opacity-60" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-72">
          <DropdownMenuLabel className="font-normal text-muted-foreground">
            One workspace per engagement: its own sessions, VMs, vault items, jobs and audit log.
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          {list.map((w) => (
            <DropdownMenuItem
              key={w.id}
              onSelect={() => {
                if (!w.current) setSwitching(w);
              }}
            >
              <WorkspaceDot color={w.color} />
              <span className="truncate" data-mask="workspace">
                {w.name}
              </span>
              {w.current && <CheckIcon className="ml-auto" aria-label="shown now" />}
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          <DropdownMenuItem disabled={!!readOnly} onSelect={() => setEditing("new")}>
            <PlusIcon />
            New workspace…
          </DropdownMenuItem>
          {shown && (
            <DropdownMenuItem disabled={!!readOnly} onSelect={() => setEditing(shown)}>
              <PencilIcon />
              Rename or recolour this one…
            </DropdownMenuItem>
          )}
          <DropdownMenuItem onSelect={() => setManaging(true)}>
            <SettingsIcon />
            Manage workspaces…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      {editing && (
        <WorkspaceEditDialog
          workspace={editing === "new" ? null : editing}
          others={all}
          onSaved={(saved, isNew) => {
            setEditing(null);
            void load();
            if (isNew) setSwitching(saved);
          }}
          onClose={() => setEditing(null)}
        />
      )}
      {managing && (
        <ManageWorkspacesDialog
          workspaces={all}
          readOnly={readOnly}
          onChanged={() => void load()}
          onSwitch={(w) => {
            setManaging(false);
            setSwitching(w);
          }}
          onEdit={(w) => {
            setManaging(false);
            setEditing(w);
          }}
          onClose={() => setManaging(false)}
        />
      )}
      {switching && (
        <SwitchDialog
          to={switching}
          readOnly={readOnly}
          onOpenActivity={() => {
            setSwitching(null);
            onOpenActivity();
          }}
          onClose={() => setSwitching(null)}
        />
      )}
    </>
  );
}

/** Asks before a switch: what closes, or why it can't happen now. */
function SwitchDialog({
  to,
  readOnly,
  onOpenActivity,
  onClose,
}: {
  to: Workspace;
  readOnly: string | null;
  onOpenActivity: () => void;
  onClose: () => void;
}) {
  const [preview, setPreview] = useState<SwitchPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    workspacesApi
      .switchPreview(to.id)
      .then(setPreview)
      .catch((err) => setError(errorMessage(err)));
  }, [to.id]);

  const refusal = readOnly ?? (preview ? switchRefusal(preview) : null);
  const closes = preview ? switchCloses(preview) : [];

  async function go() {
    setBusy(true);
    setError(null);
    try {
      await switchWorkspace(to.id);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <WorkspaceDot color={to.color} />
            <span>
              Open <span data-mask="workspace">{to.name}</span>?
            </span>
          </DialogTitle>
          <DialogDescription>{SWITCH_NOTE}</DialogDescription>
        </DialogHeader>
        {closes.length > 0 && (
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {closes.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        )}
        {refusal && (
          <p className="text-sm text-destructive" role="alert">
            {refusal}
          </p>
        )}
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <DialogFooter>
          {preview && preview.openJobs > 0 && (
            <Button variant="outline" onClick={onOpenActivity}>
              Open Activity
            </Button>
          )}
          <Button variant="outline" disabled={busy} onClick={onClose}>
            Cancel
          </Button>
          <WhyDisabled reason={refusal ?? (preview ? null : "Reading what is open…")}>
            <Button disabled={busy || !!refusal || !preview} onClick={() => void go()}>
              Switch
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** A new workspace, or the name and colour of one. */
export function WorkspaceEditDialog({
  workspace,
  others,
  onSaved,
  onClose,
}: {
  workspace: Workspace | null;
  others: Workspace[];
  onSaved: (saved: Workspace, isNew: boolean) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(workspace?.name ?? "");
  const [color, setColor] = useState<WorkspaceColor>(
    (WORKSPACE_COLORS as readonly string[]).includes(workspace?.color ?? "")
      ? (workspace?.color as WorkspaceColor)
      : "blue",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const problem = nameProblem(name, others, workspace?.id);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      if (!workspace) {
        onSaved(await workspacesApi.create({ name: name.trim(), color }), true);
        return;
      }
      let saved = workspace;
      if (name.trim() !== workspace.name) saved = await workspacesApi.rename(workspace.id, name.trim());
      if (color !== workspace.color) saved = await workspacesApi.setColor(workspace.id, color);
      onSaved(saved, false);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{workspace ? "Rename or recolour" : "New workspace"}</DialogTitle>
          <DialogDescription>
            {workspace
              ? "The audit log of this workspace keeps the change."
              : "An empty workspace for another engagement: its own sessions, vault items, VMs, templates, schedules, jobs and audit log. VMs join it from the VMs page's Unassigned list, or when it deploys them."}
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (!problem) void save();
          }}
        >
          <div className="grid gap-2">
            <Label htmlFor="workspace-name">Name</Label>
            <Input
              id="workspace-name"
              data-mask="workspace"
              value={name}
              maxLength={MAX_WORKSPACE_NAME}
              autoFocus
              onChange={(e) => setName(e.target.value)}
            />
            {name !== "" && problem && <p className="text-sm text-destructive">{problem}</p>}
          </div>
          <div className="grid gap-2">
            <Label>Colour</Label>
            <RadioGroup
              className="flex flex-wrap gap-3"
              value={color}
              onValueChange={(v) => setColor(v as WorkspaceColor)}
            >
              {WORKSPACE_COLORS.map((c) => (
                <label key={c} className="flex items-center gap-1.5 text-sm">
                  <RadioGroupItem value={c} aria-label={COLOR_LABEL[c]} />
                  <WorkspaceDot color={c} />
                  {COLOR_LABEL[c]}
                </label>
              ))}
            </RadioGroup>
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              Cancel
            </Button>
            <WhyDisabled reason={problem}>
              <Button type="submit" disabled={busy || !!problem}>
                {workspace ? "Save" : "Create"}
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Every workspace, archived ones too: open, edit, archive, restore. */
function ManageWorkspacesDialog({
  workspaces,
  readOnly,
  onChanged,
  onSwitch,
  onEdit,
  onClose,
}: {
  workspaces: Workspace[];
  readOnly: string | null;
  onChanged: () => void;
  onSwitch: (w: Workspace) => void;
  onEdit: (w: Workspace) => void;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const active = workspaces.filter((w) => !w.archived);
  const archived = workspaces.filter((w) => w.archived);

  // Toasts don't name the workspace: a short name isn't masked outside its own field while presenting.
  async function run(id: string, action: () => Promise<Workspace>, done: string) {
    setBusy(id);
    try {
      await action();
      toast.success(done);
      onChanged();
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  const archiveReason = (w: Workspace) =>
    readOnly ??
    (w.current
      ? "This workspace is open: open another one first."
      : active.length < 2
        ? "At least one workspace stays active."
        : null);

  const row = (w: Workspace) => (
    <li key={w.id} className="flex items-center gap-2 py-1.5">
      <WorkspaceDot color={w.color} />
      <span className="min-w-0 flex-1 truncate" data-mask="workspace">
        {w.name}
      </span>
      {w.current && <span className="text-xs text-muted-foreground">open now</span>}
      {!w.archived && !w.current && (
        <Button size="sm" variant="ghost" onClick={() => onSwitch(w)}>
          Open
        </Button>
      )}
      {!w.archived && (
        <WhyDisabled reason={readOnly}>
          <Button
            size="sm"
            variant="ghost"
            aria-label="Rename or recolour"
            disabled={!!readOnly}
            onClick={() => onEdit(w)}
          >
            <PencilIcon />
          </Button>
        </WhyDisabled>
      )}
      {w.archived ? (
        <WhyDisabled reason={readOnly}>
          <Button
            size="sm"
            variant="ghost"
            disabled={!!readOnly || busy === w.id}
            onClick={() => void run(w.id, () => workspacesApi.restore(w.id), "Restored the workspace")}
          >
            <ArchiveRestoreIcon />
            Restore
          </Button>
        </WhyDisabled>
      ) : (
        <WhyDisabled reason={archiveReason(w)}>
          <Button
            size="sm"
            variant="ghost"
            disabled={!!archiveReason(w) || busy === w.id}
            onClick={() => void run(w.id, () => workspacesApi.archive(w.id), "Archived the workspace")}
          >
            <ArchiveIcon />
            Archive
          </Button>
        </WhyDisabled>
      )}
    </li>
  );

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Workspaces</DialogTitle>
          <DialogDescription>
            An archived workspace keeps its data and audit log, can't be opened and runs no schedules until it is
            restored. Workspaces are never deleted: their audit logs are kept for good.
          </DialogDescription>
        </DialogHeader>
        <ul className="divide-y">{active.map(row)}</ul>
        {archived.length > 0 && (
          <>
            <p className="pt-2 text-sm font-medium text-muted-foreground">Archived</p>
            <ul className="divide-y">{archived.map(row)}</ul>
          </>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
