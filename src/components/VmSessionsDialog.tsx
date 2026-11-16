// QL-29: SSH sessions made from VMs that have none linked. One VM opens the session editor filled in from the VM
// (NewVmSessionDialog: its name, guest address, labels, and the user and key of the deploy that made it); several show
// a preview of each VM's session and what it lacks, saved together (VmSessionsDialog). The core works every draft out
// again from the VM ids when it saves; each session is audited and linked to its VM by hand.

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  api,
  errorMessage,
  type SecretMeta,
  type SessionFolder,
  type SessionRecord,
  type VaultInfo,
  type VmSessionDraft,
} from "@/lib/api";
import { plural } from "@/lib/format";
import { draftMissing, loginText, saveReason, savedSummary, sentence, splitDrafts } from "@/lib/vm-sessions";
import { SessionDialog } from "./SessionDialog";
import { useReadOnlyReason } from "./Presentation";
import { WhyDisabled } from "./WhyDisabled";

/** One VM's draft in the session editor; the folders, sessions and tags it offers are read when it opens. */
export function NewVmSessionDialog({
  vault,
  onVaultChanged,
  draft,
  onSaved,
  onClose,
}: {
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  draft: VmSessionDraft;
  onSaved: (session: SessionRecord) => void;
  onClose: () => void;
}) {
  const [lists, setLists] = useState<{ folders: SessionFolder[]; sessions: SessionRecord[]; tags: string[] } | null>(
    null,
  );
  useEffect(() => {
    let stale = false;
    Promise.all([api.sessionFolders(), api.sessions(), api.tags()]).then(
      ([folders, sessions, tags]) => {
        if (!stale) setLists({ folders, sessions, tags: tags.map((t) => t.name) });
      },
      (err) => {
        if (stale) return;
        toast.error("The session editor didn't open", { description: errorMessage(err) });
        onClose();
      },
    );
    return () => {
      stale = true;
    };
  }, [onClose]);
  if (!lists || !draft.session) return null;
  return (
    <SessionDialog
      vault={vault}
      folderId={null}
      draft={draft.session}
      draftNotes={draft.notes}
      folders={lists.folders}
      sessions={lists.sessions}
      tagSuggestions={lists.tags}
      onVaultChanged={onVaultChanged}
      onSaved={onSaved}
      onClose={onClose}
    />
  );
}

/** Several VMs' sessions: what each would be, why some get none, then saved together. */
export function VmSessionsDialog({
  vmIds,
  onSaved,
  onClose,
}: {
  vmIds: string[];
  onSaved: () => void;
  onClose: () => void;
}) {
  const readOnly = useReadOnlyReason();
  const [drafts, setDrafts] = useState<VmSessionDraft[] | null>(null);
  const [keys, setKeys] = useState<SecretMeta[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let stale = false;
    Promise.all([api.vmSessionDrafts(vmIds), api.secrets()]).then(
      ([list, secrets]) => {
        if (stale) return;
        setDrafts(list);
        setKeys(secrets);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [vmIds]);

  const { saving, refused } = splitDrafts(drafts ?? []);
  const keyLabel = (id: string) => keys.find((k) => k.id === id)?.label;
  // A failed read leaves `drafts` null with the error shown.
  const reason = saveReason({ readOnly, drafts, failed: error !== null });

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const made = await api.createVmSessions(saving.map((d) => d.vmId));
      const { title, failed } = savedSummary(made);
      const description = failed.map((m) => `${m.vmName}: ${sentence(m.error ?? "no session")}`).join(" ");
      if (failed.length === made.length) toast.error(title, { description });
      else if (failed.length > 0) toast.warning(title, { description });
      else toast.success(title);
      onSaved();
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Create SSH sessions</DialogTitle>
          <DialogDescription>
            Each session goes to the address the VM reports, on port 22, with the VM&apos;s environment and tags, and is
            linked to its VM. A VM Remotely deployed gets its deploy&apos;s user and key.
          </DialogDescription>
        </DialogHeader>

        {drafts === null && !error && <p className="text-sm text-muted-foreground">Working out the sessions…</p>}
        {drafts !== null && (
          <div className="max-h-96 overflow-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>VM</TableHead>
                  <TableHead>Address</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Login</TableHead>
                  <TableHead>Notes</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {saving.map((d) => {
                  const s = d.session;
                  if (!s) return null;
                  const missing = draftMissing(s);
                  return (
                    <TableRow key={d.vmId}>
                      <TableCell className="font-medium">{d.vmName}</TableCell>
                      <TableCell className="font-mono text-xs" data-mask="ip">
                        {s.host}
                      </TableCell>
                      <TableCell>
                        {/* FD-03: only a real user is masked; the dash stays a dash. */}
                        {s.username ? (
                          <span data-mask="user">{s.username}</span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>{loginText(s.auth, keyLabel)}</TableCell>
                      <TableCell className="whitespace-normal text-xs text-muted-foreground">
                        {missing.length > 0 && <span className="block">Fill in later: {missing.join(", ")}.</span>}
                        {d.notes.map((n) => (
                          <span key={n} className="block">
                            {sentence(n)}
                          </span>
                        ))}
                      </TableCell>
                    </TableRow>
                  );
                })}
                {refused.map((d) => (
                  <TableRow key={d.vmId} className="text-muted-foreground">
                    <TableCell className="font-medium">{d.vmName}</TableCell>
                    <TableCell colSpan={4} className="whitespace-normal text-xs">
                      No session: {d.refused ? d.refused : "none can be made now"}.
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}

        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}

        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={onClose}>
            Cancel
          </Button>
          <WhyDisabled reason={busy ? null : reason}>
            <Button disabled={busy || reason !== null} onClick={() => void save()}>
              {busy ? "Saving…" : `Save ${plural(saving.length, "session")}`}
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
