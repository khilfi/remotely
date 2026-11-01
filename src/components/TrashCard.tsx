// QL-27: the trash, in Settings › Privacy and data. What was deleted (a session, favourite command, size, image, launch
// template or stack), when and from where, with Restore and Delete now on each row and Empty trash for all (a
// destructive confirm). Items go after 30 days, at start and daily. Restoring, deleting and emptying are audited and
// refused while presenting; a restored session that would send a vault password somewhere new asks for it first.

import { useCallback, useEffect, useState } from "react";
import { ArchiveRestoreIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { DropdownMenuItem } from "@/components/ui/dropdown-menu";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { HelpTip } from "@/components/HelpTip";
import { useReadOnlyReason } from "@/components/Presentation";
import { RefreshButton } from "@/components/RefreshButton";
import { RowMenu } from "@/components/RowMenu";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage } from "@/lib/api";
import { comfortApi, type TrashEntry } from "@/lib/comfort-api";
import { formatWhen, plural } from "@/lib/format";
import { isReauthCancelled } from "@/lib/reauth";
import { withVaultPassword } from "@/lib/reauth-prompt";
import { restoredMessage, trashKindLabel } from "@/lib/trash";

export function TrashCard() {
  const [items, setItems] = useState<TrashEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ kind: "empty" } | { kind: "delete"; item: TrashEntry } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const readOnly = useReadOnlyReason();

  const load = useCallback(() => {
    comfortApi.trash().then(
      (list) => {
        setItems(list);
        setError(null);
      },
      (err) => setError(errorMessage(err)),
    );
  }, []);
  useEffect(load, [load]);

  async function restore(item: TrashEntry) {
    setBusy(item.id);
    try {
      const report = await withVaultPassword((password) => comfortApi.restoreTrash(item.id, password));
      const message = restoredMessage(report);
      toast.success(message.title, message.description ? { description: message.description } : undefined);
      load();
    } catch (err) {
      if (!isReauthCancelled(err)) toast.error(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Trash
          <HelpTip topic="trash" />
        </CardTitle>
        <CardDescription>What you delete waits here for 30 days, then it is deleted for good.</CardDescription>
        <CardAction className="flex items-center gap-1">
          <RefreshButton onClick={load} />
          <WhyDisabled reason={readOnly ?? (items && items.length === 0 ? "The trash is empty" : null)}>
            <Button
              variant="outline"
              size="sm"
              disabled={!items || items.length === 0 || readOnly !== null}
              onClick={() => setConfirm({ kind: "empty" })}
            >
              <Trash2Icon data-icon="inline-start" />
              Empty trash
            </Button>
          </WhyDisabled>
        </CardAction>
      </CardHeader>
      <CardContent>
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        {items && items.length === 0 && (
          <EmptyState
            icon={Trash2Icon}
            title="The trash is empty"
            description="Deleted sessions, commands, sizes, images, templates and stacks show here."
            bordered={false}
          />
        )}
        {items && items.length > 0 && (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>From</TableHead>
                  <TableHead>Deleted</TableHead>
                  <TableHead className="w-24">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="whitespace-normal">
                      <div className="flex flex-wrap items-center gap-1.5 font-medium">
                        {item.name}
                        <Badge variant="secondary" className="font-normal">
                          {trashKindLabel(item.kind)}
                        </Badge>
                      </div>
                      {item.detail && <div className="text-xs text-muted-foreground">With {item.detail}</div>}
                    </TableCell>
                    <TableCell className="text-sm whitespace-normal">{item.place}</TableCell>
                    <TableCell className="text-sm" title={`Deleted for good ${formatWhen(item.expiresAt)}`}>
                      {formatWhen(item.deletedAt)}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-0.5">
                        <WhyDisabled reason={readOnly}>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={readOnly !== null || busy !== null}
                            onClick={() => void restore(item)}
                          >
                            <ArchiveRestoreIcon data-icon="inline-start" />
                            Restore
                          </Button>
                        </WhyDisabled>
                        <RowMenu label={item.name}>
                          <DropdownMenuItem
                            variant="destructive"
                            disabled={readOnly !== null}
                            onSelect={() => setConfirm({ kind: "delete", item })}
                          >
                            Delete now…
                          </DropdownMenuItem>
                        </RowMenu>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
      {confirm?.kind === "empty" && items && (
        <ConfirmDialog
          title="Empty the trash?"
          description={`${plural(items.length, "item")} will be deleted for good. This can't be undone.`}
          confirmLabel="Empty trash"
          onConfirm={async () => {
            await comfortApi.emptyTrash();
            load();
          }}
          onClose={() => setConfirm(null)}
        />
      )}
      {confirm?.kind === "delete" && (
        <ConfirmDialog
          title={`Delete '${confirm.item.name}' for good?`}
          description="It can't be restored after this."
          confirmLabel="Delete now"
          onConfirm={async () => {
            await comfortApi.deleteTrash(confirm.item.id);
            load();
          }}
          onClose={() => setConfirm(null)}
        />
      )}
    </Card>
  );
}
