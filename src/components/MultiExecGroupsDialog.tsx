// QL-19: saved MultiExec groups, managed from the Terminal page's Groups menu: the groups on the left; on the right
// the one picked (or a new one), with its name and its sessions in order (moved up and down, removed), and the other
// saved sessions to add. "Save picked tabs as a group" opens it on a new group holding the picked tabs' sessions.
// Every save and delete goes to the core, which checks it, audits it and refuses it under the read-only lock (FD-03);
// QL-08: disabled buttons say why.

import { useMemo, useState } from "react";
import { toast } from "sonner";
import { ArrowDownIcon, ArrowUpIcon, LayersIcon, PlusIcon, Trash2Icon, XIcon } from "lucide-react";
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
import { ScrollArea } from "@/components/ui/scroll-area";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type MultiExecGroup, type SessionRecord } from "@/lib/api";
import { plural } from "@/lib/format";
import {
  draftChanged,
  GROUP_MEMBERS_MAX,
  GROUP_NAME_MAX,
  moveMember,
  saveDraftReason,
  toggleMember,
} from "@/lib/multiexec-groups";
import { sessionAddress } from "@/lib/terminal-session";
import { cn } from "@/lib/utils";

/** How the dialog opens: on the list (a group picked, or the first), or on a new group of these sessions. */
export type GroupsDialogStart =
  { kind: "manage"; groupId?: string } | { kind: "new"; sessionIds: string[]; note: string | null };

interface Draft {
  /** null: a new group. */
  id: string | null;
  name: string;
  sessionIds: string[];
  note: string | null;
}

function draftOf(group: MultiExecGroup | undefined): Draft {
  return group
    ? { id: group.id, name: group.name, sessionIds: group.members.map((m) => m.sessionId), note: null }
    : { id: null, name: "", sessionIds: [], note: null };
}

interface Props {
  groups: MultiExecGroup[];
  sessions: SessionRecord[];
  start: GroupsDialogStart;
  /** A group was saved or deleted: read them again. */
  onChanged: () => void;
  onClose: () => void;
}

export function MultiExecGroupsDialog({ groups, sessions, start, onChanged, onClose }: Props) {
  const readOnly = useReadOnlyReason();
  const [draft, setDraft] = useState<Draft>(() =>
    start.kind === "new"
      ? { id: null, name: "", sessionIds: start.sessionIds, note: start.note }
      : draftOf(groups.find((g) => g.id === start.groupId) ?? groups[0]),
  );
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<MultiExecGroup | null>(null);

  const byId = useMemo(() => new Map(sessions.map((s) => [s.id, s])), [sessions]);
  const saved = draft.id ? (groups.find((g) => g.id === draft.id) ?? null) : null;
  const memberName = (id: string) =>
    byId.get(id)?.name ?? saved?.members.find((m) => m.sessionId === id)?.name ?? "A session";
  const changed = draftChanged(draft, saved);
  const saveReason = busy
    ? "Saving…"
    : saveDraftReason({
        name: draft.name,
        sessionIds: draft.sessionIds,
        groups,
        self: draft.id,
        readOnly,
        changed,
      });
  const needle = filter.trim().toLowerCase();
  const addable = sessions.filter(
    (s) =>
      !draft.sessionIds.includes(s.id) &&
      (!needle ||
        s.name.toLowerCase().includes(needle) ||
        s.host.toLowerCase().includes(needle) ||
        s.tags.some((t) => t.toLowerCase().includes(needle))),
  );
  const full = draft.sessionIds.length >= GROUP_MEMBERS_MAX;

  function pick(group: MultiExecGroup | undefined) {
    setDraft(draftOf(group));
    setError(null);
    setFilter("");
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const input = { name: draft.name.trim(), sessionIds: draft.sessionIds };
      const group = draft.id ? await api.updateMultiExecGroup(draft.id, input) : await api.createMultiExecGroup(input);
      toast.success(`Saved the MultiExec group '${group.name}'`);
      setDraft(draftOf(group));
      onChanged();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
        <DialogContent className="sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <LayersIcon className="size-4" aria-hidden />
              MultiExec groups
            </DialogTitle>
            <DialogDescription>
              A group names saved sessions, like &ldquo;all web servers&rdquo;. Open group opens a tab for each and
              turns MultiExec on for them; Select group picks the ones already open. Each line still asks as usual.
            </DialogDescription>
          </DialogHeader>
          <div className="grid min-h-0 gap-4 sm:grid-cols-[13rem_minmax(0,1fr)]">
            <div className="grid content-start gap-1">
              <WhyDisabled reason={readOnly}>
                <Button
                  variant="outline"
                  size="sm"
                  className="justify-start"
                  disabled={readOnly !== null}
                  onClick={() => pick(undefined)}
                >
                  <PlusIcon data-icon="inline-start" />
                  New group
                </Button>
              </WhyDisabled>
              <ScrollArea className="max-h-80">
                <ul className="grid gap-0.5 pr-2" aria-label="Saved groups">
                  {groups.map((g) => (
                    <li key={g.id}>
                      <button
                        type="button"
                        className={cn(
                          "grid w-full rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted",
                          draft.id === g.id && "bg-accent font-medium",
                        )}
                        onClick={() => pick(g)}
                      >
                        <span className="truncate">{g.name}</span>
                        <span className="text-xs font-normal text-muted-foreground">
                          {plural(g.members.length, "session")}
                        </span>
                      </button>
                    </li>
                  ))}
                  {groups.length === 0 && (
                    <li className="px-2 py-1.5 text-sm text-muted-foreground">No groups saved yet.</li>
                  )}
                </ul>
              </ScrollArea>
            </div>

            <form
              className="grid min-w-0 content-start gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                if (!saveReason) void save();
              }}
            >
              <div className="grid gap-1.5">
                <Label htmlFor="multiexec-group-name">{draft.id ? "Name" : "New group's name"}</Label>
                <Input
                  id="multiexec-group-name"
                  value={draft.name}
                  maxLength={GROUP_NAME_MAX}
                  placeholder="all web servers"
                  disabled={readOnly !== null}
                  onChange={(e) => {
                    const name = e.currentTarget.value;
                    setDraft((d) => ({ ...d, name }));
                  }}
                />
              </div>
              {draft.note && <p className="text-xs text-muted-foreground">{draft.note}</p>}
              <div className="grid gap-1.5">
                <span className="text-sm font-medium">
                  Sessions in the group ({draft.sessionIds.length}
                  {full ? `, at most ${GROUP_MEMBERS_MAX}` : ""})
                </span>
                {draft.sessionIds.length === 0 ? (
                  <p className="rounded-md border border-dashed px-3 py-2 text-sm text-muted-foreground">
                    No sessions yet: add them below.
                  </p>
                ) : (
                  <ScrollArea className="max-h-48 rounded-md border">
                    <ol className="grid">
                      {draft.sessionIds.map((id, i) => {
                        const session = byId.get(id);
                        return (
                          <li key={id} className="flex items-center gap-1 border-b px-2 py-1 text-sm last:border-b-0">
                            <span className="w-5 shrink-0 text-xs text-muted-foreground tabular-nums">{i + 1}</span>
                            <span className="min-w-0 flex-1 truncate">{memberName(id)}</span>
                            {session && (
                              <span
                                className="hidden truncate font-mono text-xs text-muted-foreground sm:inline"
                                data-mask="address"
                              >
                                {sessionAddress(session)}
                              </span>
                            )}
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon-xs"
                              aria-label={`Move ${memberName(id)} up`}
                              disabled={readOnly !== null || i === 0}
                              onClick={() => setDraft((d) => ({ ...d, sessionIds: moveMember(d.sessionIds, i, -1) }))}
                            >
                              <ArrowUpIcon />
                            </Button>
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon-xs"
                              aria-label={`Move ${memberName(id)} down`}
                              disabled={readOnly !== null || i === draft.sessionIds.length - 1}
                              onClick={() => setDraft((d) => ({ ...d, sessionIds: moveMember(d.sessionIds, i, 1) }))}
                            >
                              <ArrowDownIcon />
                            </Button>
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon-xs"
                              aria-label={`Take ${memberName(id)} out of the group`}
                              disabled={readOnly !== null}
                              onClick={() => setDraft((d) => ({ ...d, sessionIds: toggleMember(d.sessionIds, id) }))}
                            >
                              <XIcon />
                            </Button>
                          </li>
                        );
                      })}
                    </ol>
                  </ScrollArea>
                )}
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="multiexec-group-filter">Add saved sessions</Label>
                <Input
                  id="multiexec-group-filter"
                  placeholder="Filter by name, host or tag"
                  value={filter}
                  onChange={(e) => setFilter(e.currentTarget.value)}
                  disabled={readOnly !== null}
                />
                <ScrollArea className="h-40 rounded-md border">
                  <ul className="grid">
                    {addable.map((s) => (
                      <li key={s.id}>
                        <button
                          type="button"
                          className="flex w-full items-center gap-2 px-2 py-1 text-left text-sm hover:bg-muted disabled:opacity-50"
                          disabled={readOnly !== null || full}
                          onClick={() => setDraft((d) => ({ ...d, sessionIds: toggleMember(d.sessionIds, s.id) }))}
                        >
                          <PlusIcon className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                          <span className="min-w-0 flex-1 truncate">{s.name}</span>
                          <span className="truncate font-mono text-xs text-muted-foreground" data-mask="address">
                            {sessionAddress(s)}
                          </span>
                        </button>
                      </li>
                    ))}
                    {addable.length === 0 && (
                      <li className="px-2 py-1.5 text-sm text-muted-foreground">
                        {sessions.length === 0 ? "No saved sessions." : "No other session matches."}
                      </li>
                    )}
                  </ul>
                </ScrollArea>
              </div>
              {error && (
                <p className="text-sm text-destructive" role="alert">
                  {error}
                </p>
              )}
              <DialogFooter className="items-center sm:justify-between">
                {saved ? (
                  <WhyDisabled reason={readOnly}>
                    <Button
                      type="button"
                      variant="ghost"
                      className="text-destructive"
                      disabled={readOnly !== null || busy}
                      onClick={() => setDeleting(saved)}
                    >
                      <Trash2Icon data-icon="inline-start" />
                      Delete group
                    </Button>
                  </WhyDisabled>
                ) : (
                  <span />
                )}
                <div className="flex items-center gap-2">
                  <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
                    Close
                  </Button>
                  <WhyDisabled reason={saveReason}>
                    <Button type="submit" disabled={saveReason !== null}>
                      {busy ? "Saving…" : draft.id ? "Save changes" : "Save group"}
                    </Button>
                  </WhyDisabled>
                </div>
              </DialogFooter>
            </form>
          </div>
        </DialogContent>
      </Dialog>
      {deleting && (
        <ConfirmDialog
          title={`Delete the group '${deleting.name}'?`}
          description="Its sessions stay; only the group goes. Open tabs and MultiExec are not changed."
          confirmLabel="Delete group"
          onConfirm={async () => {
            await api.deleteMultiExecGroup(deleting.id);
            toast.success(`Deleted the MultiExec group '${deleting.name}'`);
            onChanged();
            pick(groups.find((g) => g.id !== deleting.id));
          }}
          onClose={() => setDeleting(null)}
        />
      )}
    </>
  );
}
