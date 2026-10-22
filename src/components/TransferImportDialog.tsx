// FD-07: import a Remotely export from another laptop. The core opens the file (chosen in a dialog it
// opens) with the passphrase typed here and compares it with this library; this shows each session,
// trusted host key, vault secret and favourite command (BX-08) as new, already here or in conflict, and lets the
// user choose per item: import, skip, replace or keep both. The opened file stays in the core; only choices go back.
// Startup commands (SS-01) and saved port forwards (SS-07) are shown with a warning and left out unless ticked.

import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { AlertTriangleIcon, ArrowLeftIcon, FileLockIcon, FolderOpenIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { StartupRatingBadges } from "@/components/Badges";
import { VaultUnlock } from "@/components/VaultUnlock";
import {
  api,
  errorCode,
  errorMessage,
  type TransferAction,
  type TransferItem,
  type TransferPreview,
  type TransferReport,
  type TransferStatus,
  type VaultInfo,
} from "@/lib/api";
import { formatWhen, plural } from "@/lib/format";
import { cn } from "@/lib/utils";

interface Props {
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  onImported: () => void;
  onClose: () => void;
}

type Section = "sessions" | "knownHosts" | "secrets" | "favourites";
type Choices = Record<Section, Record<number, TransferAction>>;

const ACTION_LABEL: Record<TransferAction, string> = {
  import: "Import",
  skip: "Skip",
  replace: "Replace",
  keepBoth: "Keep both",
};

const STATUS: Record<TransferStatus, { label: string; className: string }> = {
  new: { label: "New", className: "border-success/40 text-success" },
  same: { label: "Already here", className: "text-muted-foreground" },
  conflict: { label: "Conflict", className: "border-tier-medium/40 text-tier-medium" },
};

const SECTIONS: { key: Section; title: string; empty: string }[] = [
  { key: "sessions", title: "Sessions", empty: "No sessions in the file." },
  { key: "knownHosts", title: "Trusted host keys", empty: "No host keys in the file." },
  { key: "secrets", title: "Vault secrets", empty: "" },
  { key: "favourites", title: "Favourite commands", empty: "No favourite commands in the file." },
];

function defaults(preview: TransferPreview): Choices {
  const of = (items: TransferItem[]) => Object.fromEntries(items.map((i) => [i.index, i.defaultAction]));
  return {
    sessions: of(preview.sessions),
    knownHosts: of(preview.knownHosts),
    secrets: of(preview.secrets),
    // Files from before BX-08 have none.
    favourites: of(preview.favourites ?? []),
  };
}

function counts(report: TransferReport) {
  const part = (what: string, c: TransferReport["sessions"]) => {
    const done = [
      c.added && `${c.added} added`,
      c.replaced && `${c.replaced} replaced`,
      c.keptBoth && `${c.keptBoth} kept as a second copy`,
    ].filter(Boolean);
    return done.length ? `${what}: ${done.join(", ")}` : null;
  };
  return [
    part("Sessions", report.sessions),
    part("Host keys", report.knownHosts),
    part("Secrets", report.secrets),
    part("Favourite commands", report.favourites),
    report.forwards ? `Port forwards: ${report.forwards} saved with their sessions` : null,
    report.startupLeftOut ? `Startup commands: ${report.startupLeftOut} left out` : null,
    report.forwardsLeftOut ? `Port forwards: ${report.forwardsLeftOut} left out` : null,
    report.foldersAdded ? `Folders: ${report.foldersAdded} added` : null,
  ].filter(Boolean) as string[];
}

export function TransferImportDialog({ vault, onVaultChanged, onImported, onClose }: Props) {
  const [file, setFile] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [preview, setPreview] = useState<TransferPreview | null>(null);
  const [choices, setChoices] = useState<Choices>({ sessions: {}, knownHosts: {}, secrets: {}, favourites: {} });
  /** SS-01, SS-07: sessions whose startup command, and whose port forwards, come along; none by default. */
  const [keepStartup, setKeepStartup] = useState<Set<number>>(new Set());
  const [keepForwards, setKeepForwards] = useState<Set<number>>(new Set());
  const [report, setReport] = useState<TransferReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const unlocked = vault?.status === "unlocked";

  // The opened file (and any secrets in it) is dropped in the core when the dialog goes.
  useEffect(() => {
    const id = preview?.id;
    return () => {
      if (id) void api.transferClose(id);
    };
  }, [preview?.id]);

  async function choose() {
    setError(null);
    try {
      const name = await api.transferChoose();
      if (name) setFile(name);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function open() {
    setBusy(true);
    setError(null);
    try {
      const opened = await api.transferOpen(passphrase);
      setPassphrase("");
      setPreview(opened);
      setChoices(defaults(opened));
      setKeepStartup(new Set());
      setKeepForwards(new Set());
    } catch (err) {
      setError(
        errorCode(err) === "wrong_passphrase"
          ? "The passphrase is wrong, or the file was changed or damaged after it was exported."
          : errorMessage(err),
      );
    } finally {
      setBusy(false);
    }
  }

  /** After the vault is unlocked, secrets can be compared and imported: ask the core again. */
  async function refresh(info: VaultInfo) {
    onVaultChanged(info);
    if (!preview) return;
    try {
      const again = await api.transferRefresh(preview.id);
      setPreview(again);
      setChoices(defaults(again));
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function commit() {
    if (!preview) return;
    setBusy(true);
    setError(null);
    const list = (section: Section) =>
      Object.entries(choices[section]).map(([index, action]) => ({ index: Number(index), action }));
    try {
      const done = await api.transferCommit({
        previewId: preview.id,
        sessions: list("sessions"),
        knownHosts: list("knownHosts"),
        secrets: list("secrets"),
        favourites: list("favourites"),
        keepStartup: [...keepStartup].sort((a, b) => a - b),
        keepForwards: [...keepForwards].sort((a, b) => a - b),
      });
      setReport(done);
      onImported();
      toast.success(`Imported from ${preview.file}`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  function setAll(section: Section, status: TransferStatus, action: TransferAction) {
    if (!preview) return;
    setChoices((c) => {
      const next = { ...c[section] };
      for (const item of preview[section]) {
        if (item.status === status && item.choices.includes(action)) next[item.index] = action;
      }
      return { ...c, [section]: next };
    });
  }

  const totals = useMemo(() => {
    const t: Record<TransferAction, number> = { import: 0, skip: 0, replace: 0, keepBoth: 0 };
    for (const section of Object.values(choices)) {
      for (const action of Object.values(section)) t[action] += 1;
    }
    return t;
  }, [choices]);
  const changes = totals.import + totals.replace + totals.keepBoth;
  /** SS-01, SS-07: sessions to import that bring a startup command or port forwards. */
  const extras = (preview?.sessions ?? []).filter(
    (s) =>
      (choices.sessions[s.index] ?? s.defaultAction) !== "skip" && (s.startupCommand || (s.forwards?.length ?? 0) > 0),
  );
  const toggle = (set: (f: (prev: Set<number>) => Set<number>) => void, index: number, on: boolean) =>
    set((prev) => {
      const next = new Set(prev);
      if (on) next.add(index);
      else next.delete(index);
      return next;
    });
  const secretsChosen = Object.values(choices.secrets).some((a) => a !== "skip");

  function close() {
    setPassphrase("");
    onClose();
  }

  return (
    <Dialog open onOpenChange={(o) => !o && !busy && close()}>
      <DialogContent className="sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileLockIcon className="size-4" aria-hidden />
            Import from another laptop
          </DialogTitle>
          <DialogDescription>
            {preview
              ? `${preview.file}, exported ${formatWhen(preview.exportedAt)}${preview.exportedBy ? ` by ${preview.exportedBy}` : ""}.`
              : "Choose a Remotely export file and type its passphrase. Nothing changes until you import."}
          </DialogDescription>
        </DialogHeader>

        {report ? (
          <div className="grid gap-3">
            <ul className="grid gap-1 text-sm">
              {counts(report).map((line) => (
                <li key={line}>{line}</li>
              ))}
              {counts(report).length === 0 && <li>Nothing was imported.</li>}
            </ul>
            {report.withoutCredentials > 0 && (
              <Alert>
                <AlertTriangleIcon />
                <AlertTitle>
                  {plural(report.withoutCredentials, "session")} came without the password or key they used
                </AlertTitle>
                <AlertDescription>
                  Their secrets were not in the file or were skipped. They ask for a password when connecting; edit them
                  to choose a key from the vault.
                </AlertDescription>
              </Alert>
            )}
            {report.problems.length > 0 && (
              <Alert variant="destructive">
                <AlertTriangleIcon />
                <AlertTitle>{plural(report.problems.length, "item")} not imported</AlertTitle>
                <AlertDescription>
                  <ul className="grid gap-1">
                    {report.problems.map((p, i) => (
                      <li key={i}>
                        <span className="font-medium">{p.name}</span>: {p.reason}
                      </li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}
          </div>
        ) : !preview ? (
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (file && passphrase && !busy) void open();
            }}
          >
            <div className="grid gap-2">
              <Label>Export file</Label>
              <div className="flex items-center gap-3">
                <Button type="button" variant="outline" onClick={() => void choose()}>
                  <FolderOpenIcon data-icon="inline-start" />
                  {file ? "Choose another…" : "Choose a file…"}
                </Button>
                <span className="truncate text-sm text-muted-foreground">{file ?? "No file chosen"}</span>
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="transfer-passphrase">Passphrase</Label>
              <Input
                id="transfer-passphrase"
                type="password"
                autoComplete="off"
                className="max-w-sm"
                value={passphrase}
                onChange={(e) => setPassphrase(e.currentTarget.value)}
                disabled={!file}
              />
              <p className="text-sm text-muted-foreground">The one chosen when the file was exported.</p>
            </div>
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={close} disabled={busy}>
                Cancel
              </Button>
              <Button type="submit" disabled={!file || !passphrase || busy}>
                {busy ? "Opening…" : "Open"}
              </Button>
            </DialogFooter>
          </form>
        ) : (
          <div className="grid max-h-[60vh] gap-5 overflow-y-auto pr-1">
            <p className="text-sm text-muted-foreground">
              {plural(preview.folders, "folder")} in the file
              {preview.newFolders > 0
                ? `, ${preview.newFolders} new here (made as the sessions in them need them)`
                : ""}
              .
            </p>
            {preview.warnings.map((w) => (
              <Alert key={w}>
                <AlertTriangleIcon />
                <AlertDescription>{w}</AlertDescription>
              </Alert>
            ))}
            {preview.secretValues && !unlocked && vault && vault.status !== "notSetUp" && (
              <div className="grid gap-2 rounded-lg border p-3">
                <p className="text-sm font-medium">Unlock the vault to import the secrets</p>
                <VaultUnlock info={vault} onUnlocked={(info) => void refresh(info)} idPrefix="transfer-unlock" />
              </div>
            )}
            {SECTIONS.filter((s) => s.key !== "secrets" || preview.secretValues).map((section) => (
              <ItemTable
                key={section.key}
                title={section.title}
                empty={section.empty}
                items={preview[section.key]}
                choices={choices[section.key]}
                onChoose={(index, action) =>
                  setChoices((c) => ({ ...c, [section.key]: { ...c[section.key], [index]: action } }))
                }
                onAll={(status, action) => setAll(section.key, status, action)}
              />
            ))}
            {extras.length > 0 && (
              <Alert>
                <AlertTriangleIcon />
                <AlertTitle>Startup commands and port forwards</AlertTitle>
                <AlertDescription className="grid gap-3">
                  <p>
                    A startup command is typed into the shell at every connection without asking, and a port forward
                    opens a way into a network. They are left out unless you tick them; a replaced session keeps its
                    own.
                  </p>
                  <ul className="grid gap-3">
                    {extras.map((s) => (
                      <li key={s.index} className="grid min-w-0 gap-1.5">
                        <span className="font-medium text-foreground">{s.name}</span>
                        {s.startupCommand && (
                          <div className="flex min-w-0 items-start gap-2">
                            <Checkbox
                              id={`transfer-startup-${s.index}`}
                              className="mt-0.5"
                              checked={keepStartup.has(s.index)}
                              onCheckedChange={(v) => toggle(setKeepStartup, s.index, v === true)}
                            />
                            <Label htmlFor={`transfer-startup-${s.index}`} className="grid min-w-0 gap-1 font-normal">
                              <span className="flex flex-wrap items-center gap-2">
                                Startup command
                                {s.startupRating && <StartupRatingBadges rating={s.startupRating} />}
                              </span>
                              <code className="font-mono text-xs break-all whitespace-pre-wrap">
                                {s.startupCommand}
                              </code>
                            </Label>
                          </div>
                        )}
                        {(s.forwards?.length ?? 0) > 0 && (
                          <div className="flex min-w-0 items-start gap-2">
                            <Checkbox
                              id={`transfer-forwards-${s.index}`}
                              className="mt-0.5"
                              checked={keepForwards.has(s.index)}
                              onCheckedChange={(v) => toggle(setKeepForwards, s.index, v === true)}
                            />
                            <Label htmlFor={`transfer-forwards-${s.index}`} className="grid min-w-0 gap-1 font-normal">
                              {plural(s.forwards?.length ?? 0, "port forward")}
                              <ul className="font-mono text-xs">
                                {s.forwards?.map((f) => (
                                  <li key={f} className="break-all">
                                    {f}
                                  </li>
                                ))}
                              </ul>
                            </Label>
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}
          </div>
        )}

        {preview && !report && (
          <>
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
            <DialogFooter className="items-center sm:justify-between">
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  void api.transferClose(preview.id);
                  setPreview(null);
                  setError(null);
                }}
                disabled={busy}
              >
                <ArrowLeftIcon data-icon="inline-start" />
                Another file
              </Button>
              <div className="flex items-center gap-3">
                <span className="text-sm text-muted-foreground">
                  {changes === 0
                    ? "Nothing to import"
                    : [
                        totals.import && `${totals.import} to import`,
                        totals.replace && `${totals.replace} to replace`,
                        totals.keepBoth && `${totals.keepBoth} to keep both`,
                      ]
                        .filter(Boolean)
                        .join(", ")}
                </span>
                <Button type="button" variant="outline" onClick={close} disabled={busy}>
                  Cancel
                </Button>
                <Button
                  type="button"
                  onClick={() => void commit()}
                  disabled={busy || changes === 0 || (secretsChosen && !unlocked)}
                >
                  {busy ? "Importing…" : "Import"}
                </Button>
              </div>
            </DialogFooter>
          </>
        )}
        {report && (
          <DialogFooter>
            <Button type="button" onClick={close}>
              Done
            </Button>
          </DialogFooter>
        )}
      </DialogContent>
    </Dialog>
  );
}

function ItemTable({
  title,
  empty,
  items,
  choices,
  onChoose,
  onAll,
}: {
  title: string;
  empty: string;
  items: TransferItem[];
  choices: Record<number, TransferAction>;
  onChoose: (index: number, action: TransferAction) => void;
  onAll: (status: TransferStatus, action: TransferAction) => void;
}) {
  const conflicts = items.filter((i) => i.status === "conflict").length;
  const fresh = items.filter((i) => i.status === "new").length;
  return (
    <section className="grid gap-2">
      <div className="flex items-center gap-2">
        <h3 className="text-sm font-medium">{title}</h3>
        <span className="text-sm text-muted-foreground">
          {items.length === 0
            ? empty
            : [fresh && `${fresh} new`, conflicts && `${conflicts} in conflict`].filter(Boolean).join(", ") ||
              "all already here"}
        </span>
        {(conflicts > 0 || fresh > 0) && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="ml-auto">
                Set all…
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {fresh > 0 && (
                <>
                  <DropdownMenuLabel>New items</DropdownMenuLabel>
                  <DropdownMenuItem onSelect={() => onAll("new", "import")}>Import</DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => onAll("new", "skip")}>Skip</DropdownMenuItem>
                </>
              )}
              {conflicts > 0 && (
                <>
                  <DropdownMenuLabel>Conflicts</DropdownMenuLabel>
                  {(["skip", "replace", "keepBoth"] as TransferAction[]).map((a) => (
                    <DropdownMenuItem key={a} onSelect={() => onAll("conflict", a)}>
                      {ACTION_LABEL[a]}
                    </DropdownMenuItem>
                  ))}
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
      {items.length > 0 && (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Here</TableHead>
                <TableHead className="w-36">Do</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((item) => (
                <TableRow key={item.index} className="align-top">
                  <TableCell className="max-w-sm whitespace-normal">
                    <div className="font-medium">{item.name}</div>
                    <div className="text-xs break-all text-muted-foreground">{item.detail}</div>
                    {item.notes.map((n) => (
                      <div key={n} className="text-xs text-muted-foreground">
                        {n}
                      </div>
                    ))}
                  </TableCell>
                  <TableCell className="max-w-xs whitespace-normal">
                    <Badge variant="outline" className={cn("mb-1", STATUS[item.status].className)}>
                      {STATUS[item.status].label}
                    </Badge>
                    {item.conflict && item.status !== "new" && (
                      <div className="text-xs text-muted-foreground">{item.conflict}</div>
                    )}
                  </TableCell>
                  <TableCell>
                    <Select
                      value={choices[item.index] ?? item.defaultAction}
                      onValueChange={(v) => onChoose(item.index, v as TransferAction)}
                      disabled={item.choices.length < 2}
                    >
                      <SelectTrigger size="sm" className="w-32" aria-label={`What to do with ${item.name}`}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {item.choices.map((a) => (
                          <SelectItem key={a} value={a}>
                            {ACTION_LABEL[a]}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </section>
  );
}
