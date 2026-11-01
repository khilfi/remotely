// QL-28: the Sessions page's bulk edit. Tick what to change (folder, port, user, login, jump host, environment; tags
// added or taken off), see each selected session before and after, then save them all at once. The core checks each
// as an edit of it, saves them in one go with one audit entry naming every session, and asks for the vault password
// once when a login would send one somewhere new.

import { useState } from "react";
import { toast } from "sonner";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { HelpTip } from "@/components/HelpTip";
import { errorMessage, type Environment, type SecretMeta, type SessionFolder, type SessionRecord } from "@/lib/api";
import { bulkEditFrom, emptyBulkForm, type BulkForm, type Field } from "@/lib/bulk-edit";
import { comfortApi, type BulkEdit, type BulkEditPreview } from "@/lib/comfort-api";
import { flattenFolders, folderPath } from "@/lib/folders";
import { plural } from "@/lib/format";
import { isReauthCancelled } from "@/lib/reauth";
import { withVaultPassword } from "@/lib/reauth-prompt";
import { kindOf } from "@/lib/session-kinds";

const TOP = "__top";

interface Props {
  sessions: SessionRecord[];
  all: SessionRecord[];
  folders: SessionFolder[];
  secrets: SecretMeta[];
  onSaved: () => void;
  onClose: () => void;
}

function Row<T>({
  id,
  label,
  field,
  onToggle,
  children,
}: {
  id: string;
  label: string;
  field: Field<T>;
  onToggle: (on: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[8.5rem_1fr] items-center gap-3">
      <div className="flex items-center gap-2">
        <Checkbox id={`bulk-${id}`} checked={field.on} onCheckedChange={(on) => onToggle(on === true)} />
        <Label htmlFor={`bulk-${id}`} className="font-normal">
          {label}
        </Label>
      </div>
      <div className={field.on ? undefined : "pointer-events-none opacity-50"}>{children}</div>
    </div>
  );
}

export function BulkEditDialog({ sessions, all, folders, secrets, onSaved, onClose }: Props) {
  const [form, setForm] = useState<BulkForm>(emptyBulkForm);
  const [preview, setPreview] = useState<{ edit: BulkEdit; result: BulkEditPreview } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ids = sessions.map((s) => s.id);

  function set<K extends keyof BulkForm>(key: K, value: BulkForm[K]) {
    setForm((f) => ({ ...f, [key]: value }));
    setError(null);
  }
  function on<K extends "folder" | "port" | "user" | "login" | "jump" | "environment">(key: K, value: boolean) {
    setForm((f) => ({ ...f, [key]: { ...f[key], on: value } }));
    setError(null);
  }
  function value<K extends "folder" | "port" | "user" | "login" | "jump" | "environment">(
    key: K,
    v: BulkForm[K]["value"],
  ) {
    setForm((f) => ({ ...f, [key]: { on: true, value: v } }));
    setError(null);
  }

  async function showPreview() {
    const made = bulkEditFrom(form);
    if ("error" in made) {
      setError(made.error);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setPreview({ edit: made.edit, result: await comfortApi.bulkPreview(ids, made.edit) });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    if (!preview) return;
    setBusy(true);
    setError(null);
    try {
      const done = await withVaultPassword((password) => comfortApi.bulkEdit(ids, preview.edit, password));
      toast.success(`Changed ${plural(done.changed, "session")}`);
      onSaved();
      onClose();
    } catch (err) {
      if (!isReauthCancelled(err)) setError(errorMessage(err));
      setBusy(false);
    }
  }

  const passwords = secrets.filter((s) => s.kind === "password");
  const keys = secrets.filter((s) => s.kind === "privateKey");
  // A jump host is an SSH session.
  const jumpHosts = all.filter((s) => !ids.includes(s.id) && kindOf(s).protocol === "ssh");
  const changedRows = preview?.result.rows.filter((r) => r.changes.length > 0) ?? [];
  // Also the sessions whose kind doesn't take a ticked field, which keep it.
  const shownRows = preview?.result.rows.filter((r) => r.changes.length > 0 || r.skipped.length > 0) ?? [];

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-1">
            Edit {plural(sessions.length, "session")}
            <HelpTip topic="bulkEdit" />
          </DialogTitle>
          <DialogDescription>
            {preview ? "Check each session before and after, then save." : "Tick what to change on all of them."}
          </DialogDescription>
        </DialogHeader>

        {!preview && (
          <div className="grid gap-3">
            <Row id="folder" label="Folder" field={form.folder} onToggle={(v) => on("folder", v)}>
              <Select value={form.folder.value ?? TOP} onValueChange={(v) => value("folder", v === TOP ? null : v)}>
                <SelectTrigger className="w-full" aria-label="Folder">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={TOP}>Top level</SelectItem>
                  {flattenFolders(folders).map(({ folder }) => (
                    <SelectItem key={folder.id} value={folder.id}>
                      {folderPath(folders, folder.id)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Row>
            <Row id="port" label="Port" field={form.port} onToggle={(v) => on("port", v)}>
              <Input
                aria-label="Port"
                inputMode="numeric"
                className="w-28"
                value={form.port.value}
                onChange={(e) => value("port", e.currentTarget.value)}
              />
            </Row>
            <Row id="user" label="User" field={form.user} onToggle={(v) => on("user", v)}>
              <Input
                aria-label="User"
                data-mask="user"
                placeholder="As their folders say"
                value={form.user.value}
                onChange={(e) => value("user", e.currentTarget.value)}
              />
            </Row>
            <Row id="login" label="Login" field={form.login} onToggle={(v) => on("login", v)}>
              <Select value={form.login.value} onValueChange={(v) => value("login", v)}>
                <SelectTrigger className="w-full" aria-label="Login">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="folder">As their folders say</SelectItem>
                  <SelectItem value="asked">Password, asked when connecting</SelectItem>
                  <SelectItem value="agent">SSH agent</SelectItem>
                  {passwords.map((p) => (
                    <SelectItem key={p.id} value={`password:${p.id}`}>
                      Password · {p.label}
                    </SelectItem>
                  ))}
                  {keys.map((k) => (
                    <SelectItem key={k.id} value={`key:${k.id}`}>
                      Key · {k.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Row>
            <Row id="jump" label="Jump host" field={form.jump} onToggle={(v) => on("jump", v)}>
              <Select value={form.jump.value} onValueChange={(v) => value("jump", v)}>
                <SelectTrigger className="w-full" aria-label="Jump host">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="folder">As their folders say</SelectItem>
                  <SelectItem value="direct">None: connect directly</SelectItem>
                  {jumpHosts.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Row>
            <Row id="environment" label="Environment" field={form.environment} onToggle={(v) => on("environment", v)}>
              <Select value={form.environment.value} onValueChange={(v) => value("environment", v as Environment)}>
                <SelectTrigger className="w-full" aria-label="Environment">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None of their own</SelectItem>
                  <SelectItem value="lab">Lab</SelectItem>
                  <SelectItem value="staging">Staging</SelectItem>
                  <SelectItem value="prod">Prod</SelectItem>
                </SelectContent>
              </Select>
            </Row>
            <div className="grid grid-cols-[8.5rem_1fr] items-center gap-3">
              <Label htmlFor="bulk-tags-add" className="font-normal">
                Add tags
              </Label>
              <Input
                id="bulk-tags-add"
                placeholder="web, edge"
                value={form.tagsAdd}
                onChange={(e) => set("tagsAdd", e.currentTarget.value)}
              />
              <Label htmlFor="bulk-tags-remove" className="font-normal">
                Remove tags
              </Label>
              <Input
                id="bulk-tags-remove"
                placeholder="old"
                value={form.tagsRemove}
                onChange={(e) => set("tagsRemove", e.currentTarget.value)}
              />
            </div>
          </div>
        )}

        {preview && (
          <div className="max-h-96 overflow-auto rounded-lg border">
            {shownRows.length === 0 ? (
              <p className="p-3 text-sm text-muted-foreground">Nothing changes: they already are like that.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Session</TableHead>
                    <TableHead>Field</TableHead>
                    <TableHead>Before</TableHead>
                    <TableHead>After</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {shownRows.flatMap((row) => [
                    ...row.changes.map((c, i) => (
                      <TableRow key={`${row.id}-${c.field}`}>
                        <TableCell className="font-medium">{i === 0 ? row.name : ""}</TableCell>
                        <TableCell>{c.field}</TableCell>
                        <TableCell className="whitespace-normal text-muted-foreground">{c.before}</TableCell>
                        <TableCell className="whitespace-normal">{c.after}</TableCell>
                      </TableRow>
                    )),
                    ...(row.skipped.length > 0
                      ? [
                          <TableRow key={`${row.id}-skipped`}>
                            <TableCell className="font-medium">{row.changes.length === 0 ? row.name : ""}</TableCell>
                            <TableCell colSpan={3} className="whitespace-normal text-muted-foreground">
                              {row.skipped.map((s) => (
                                <span key={s} className="block">
                                  {s}.
                                </span>
                              ))}
                            </TableCell>
                          </TableRow>,
                        ]
                      : []),
                  ])}
                </TableBody>
              </Table>
            )}
          </div>
        )}

        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <DialogFooter>
          {preview ? (
            <>
              <Button variant="outline" disabled={busy} onClick={() => setPreview(null)}>
                Back
              </Button>
              <Button disabled={busy || changedRows.length === 0} onClick={() => void save()}>
                {busy ? "Saving…" : `Save ${plural(changedRows.length, "session")}`}
              </Button>
            </>
          ) : (
            <>
              <Button variant="outline" disabled={busy} onClick={onClose}>
                Cancel
              </Button>
              <Button disabled={busy} onClick={() => void showPreview()}>
                {busy ? "Checking…" : "Preview changes"}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
