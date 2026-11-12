// VM-28: the Templates page's Install configs tab: the workspace's own configs, then the starters (read only, with
// Make a copy), each with what its check found and the launch templates that use it. Edits are audited in the core with
// no approval tier and refused by the read-only lock; a delete goes to the trash.

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { CopyIcon, EyeIcon, LockIcon, PencilIcon, Trash2Icon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { InstallConfigDialog } from "@/components/InstallConfigDialog";
import { RowMenu } from "@/components/RowMenu";
import { Term } from "@/components/Term";
import { errorMessage, type LaunchTemplate, type Size } from "@/lib/api";
import { installConfigsApi, type InstallConfig, type InstallConfigInput } from "@/lib/install-configs-api";
import { configReason, copyOf, diskText, KIND_LABEL, problemSummary } from "@/lib/install-configs";
import { plural } from "@/lib/format";
import { toastDeleted } from "@/lib/undo-delete";
import { cn } from "@/lib/utils";

interface Props {
  /** True while the tab shows: it reads the configs again when it comes back. */
  active: boolean;
  readOnly: string | null;
  sizes: Size[];
  templates: LaunchTemplate[];
  /** Changes when the header's New install config is pressed. */
  createRequest: number;
  /** A search result to light. */
  lit: string | null;
  /** A config was saved or deleted: templates' problems may have changed. */
  onChanged: () => void;
}

type Dialog =
  { kind: "edit"; existing?: InstallConfig; initial?: InstallConfigInput } | { kind: "delete"; config: InstallConfig };

export function InstallConfigsTab({ active, readOnly, sizes, templates, createRequest, lit, onChanged }: Props) {
  const [configs, setConfigs] = useState<InstallConfig[]>([]);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [handled, setHandled] = useState(createRequest);

  const load = useCallback(() => {
    installConfigsApi.list().then(setConfigs, (err) => toast.error(errorMessage(err)));
  }, []);

  useEffect(() => {
    if (active) load();
  }, [active, load]);

  if (createRequest !== handled) {
    setHandled(createRequest);
    if (!readOnly) setDialog({ kind: "edit" });
  }

  const own = configs.filter((c) => !c.builtIn);
  const starters = configs.filter((c) => c.builtIn);
  const names = configs.map((c) => c.name);
  const usedBy = (id: string) => templates.filter((t) => t.installConfigId === id).map((t) => t.name);

  function changed() {
    load();
    onChanged();
  }

  return (
    <>
      <p className="text-sm text-muted-foreground">
        An <Term id="installConfig">install config</Term> lets an ISO install by itself, with each VM&apos;s own
        hostname and values. Starters are read only: make a copy to pick its password and key from the vault.
      </p>
      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Install config</TableHead>
              <TableHead>Kind</TableHead>
              <TableHead>Check</TableHead>
              <TableHead>Used by</TableHead>
              <TableHead className="w-12">
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {[...own, ...starters].map((c) => {
              const why = configReason(c);
              const used = usedBy(c.id);
              return (
                <TableRow key={c.id} data-catalog-id={c.id} className={cn("align-top", lit === c.id && "bg-accent")}>
                  <TableCell className="font-medium whitespace-normal">
                    <span className="flex flex-wrap items-center gap-2">
                      {c.name}
                      {c.builtIn && (
                        <Badge variant="outline" className="font-normal text-muted-foreground">
                          <LockIcon />
                          Starter
                        </Badge>
                      )}
                    </span>
                    {c.notes && <div className="line-clamp-2 text-xs font-normal text-muted-foreground">{c.notes}</div>}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    {KIND_LABEL[c.kind]}
                    {c.diskNeedMb !== null && (
                      <div className="text-xs text-muted-foreground">Disk at least {diskText(c.diskNeedMb)}</div>
                    )}
                  </TableCell>
                  <TableCell className="whitespace-nowrap">
                    {why ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Badge
                            variant="outline"
                            tabIndex={0}
                            className="cursor-help border-destructive/40 text-destructive"
                          >
                            Can&apos;t deploy
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent className="max-w-sm">{why}</TooltipContent>
                      </Tooltip>
                    ) : (
                      <span className="text-xs text-muted-foreground">{problemSummary(c.problems)}</span>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {c.builtIn ? "—" : used.length ? used.join(", ") : "No template"}
                  </TableCell>
                  <TableCell>
                    <RowMenu label={c.name}>
                      <DropdownMenuItem onSelect={() => setDialog({ kind: "edit", existing: c })}>
                        {c.builtIn || readOnly ? <EyeIcon /> : <PencilIcon />}
                        {c.builtIn || readOnly ? "View…" : "Edit…"}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        disabled={readOnly !== null}
                        onSelect={() => setDialog({ kind: "edit", initial: copyOf(c, names) })}
                      >
                        <CopyIcon />
                        Make a copy…
                      </DropdownMenuItem>
                      {!c.builtIn && (
                        <>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            variant="destructive"
                            disabled={readOnly !== null}
                            onSelect={() => setDialog({ kind: "delete", config: c })}
                          >
                            <Trash2Icon />
                            Delete…
                          </DropdownMenuItem>
                        </>
                      )}
                    </RowMenu>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>

      {dialog?.kind === "edit" && (
        <InstallConfigDialog
          existing={dialog.existing}
          initial={dialog.initial}
          starters={starters}
          sizes={sizes}
          taken={names}
          readOnly={readOnly}
          onSaved={(c) => {
            toast.success(dialog.existing ? `Saved ${c.name}` : `Added the install config ${c.name}`);
            changed();
          }}
          onCopy={(copy) => setDialog({ kind: "edit", initial: copy })}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "delete" && (
        <ConfirmDialog
          title={`Delete the install config ${dialog.config.name}?`}
          description={
            <>
              <span className="block">It goes to the trash for 30 days.</span>
              {usedBy(dialog.config.id).length > 0 ? (
                <span className="block">
                  {plural(usedBy(dialog.config.id).length, "launch template")} use it (
                  {usedBy(dialog.config.id).join(", ")}) and can&apos;t deploy until they get another.
                </span>
              ) : (
                <span className="block">No launch template uses it.</span>
              )}
            </>
          }
          confirmLabel="Delete"
          onConfirm={async () => {
            const { id, name } = dialog.config;
            await installConfigsApi.remove(id);
            changed();
            toastDeleted("installConfig", id, name, changed);
          }}
          onClose={() => setDialog(null)}
        />
      )}
    </>
  );
}
