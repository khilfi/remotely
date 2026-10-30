// SS-02: import a session list from PuTTY, MobaXterm, an OpenSSH config or CSV. The core reads the source
// (the file is chosen in a dialog it opens), then this shows a preview with duplicates and name conflicts
// before anything is saved. Stored passwords are never imported; key files can go into the vault.
// QL-10: each file format has a short guide (made in the core from its parser's tables) and a sample file, saved
// through a Rust save dialog; samples hold made-up example sessions only.

import { useMemo, useState } from "react";
import { toast } from "sonner";
import {
  AlertTriangleIcon,
  ArrowLeftIcon,
  BookOpenIcon,
  DownloadIcon,
  FileSpreadsheetIcon,
  FileTextIcon,
  InfoIcon,
  LoaderCircleIcon,
  MonitorIcon,
  TerminalSquareIcon,
} from "lucide-react";
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
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EnvBadge, StartupRatingBadges } from "@/components/Badges";
import { VaultUnlock } from "@/components/VaultUnlock";
import {
  api,
  errorMessage,
  type FormatGuide,
  type ImportPreview,
  type ImportReport,
  type ImportRow,
  type ImportSource,
  type SessionFolder,
  type VaultInfo,
} from "@/lib/api";
import { flattenFolders, folderPath } from "@/lib/folders";
import { plural } from "@/lib/format";
import { cn } from "@/lib/utils";

interface Props {
  folders: SessionFolder[];
  /** The folder open on the Sessions page: the default place to import into. */
  folderId: string | null;
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  onOpenVault: () => void;
  onImported: () => void;
  onClose: () => void;
}

const SOURCES: {
  source: ImportSource;
  title: string;
  detail: string;
  icon: typeof MonitorIcon;
  chooseFile?: boolean;
  /** QL-10: a file format, with a guide and a sample file. */
  format?: boolean;
}[] = [
  {
    source: "putty",
    title: "PuTTY on this computer",
    detail: "The sessions PuTTY saved for your Windows user (registry).",
    icon: MonitorIcon,
  },
  {
    source: "mobaxterm",
    title: "MobaXterm export",
    detail: "A .mxtsessions file (MobaXterm: Settings, Export all sessions). Folders are kept.",
    icon: TerminalSquareIcon,
    format: true,
  },
  {
    source: "openssh",
    title: "OpenSSH config",
    detail: "~/.ssh/config: each Host becomes a session, with its user, port, key file and wildcard settings.",
    icon: FileTextIcon,
    format: true,
  },
  {
    source: "puttyFile",
    title: "PuTTY export from another computer",
    detail: "A .reg file of PuTTY's sessions (regedit, export HKCU\\Software\\SimonTatham\\PuTTY\\Sessions).",
    icon: FileTextIcon,
    format: true,
  },
  {
    source: "csv",
    title: "CSV file",
    detail:
      "A header row with host (required) and any of name, port, user, folder, tags, environment, key_file; the guide lists every column.",
    icon: FileSpreadsheetIcon,
    format: true,
  },
];

const SOURCE_NAME: Record<ImportSource, string> = {
  putty: "PuTTY",
  puttyFile: "the PuTTY export",
  mobaxterm: "the MobaXterm export",
  openssh: "the OpenSSH config",
  csv: "the CSV file",
};

const TOP = "top";

function address(row: ImportRow) {
  const c = row.candidate;
  const host = c.host.includes(":") ? `[${c.host}]` : c.host;
  return `${c.username ? `${c.username}@` : ""}${host}${c.port === 22 ? "" : `:${c.port}`}`;
}

function fileName(path: string) {
  return path.split(/[\\/]/).pop() ?? path;
}

function StatusBadge({ row, preview }: { row: ImportRow; preview: ImportPreview }) {
  const status = row.status;
  switch (status.kind) {
    case "new":
      return (
        <Badge variant="outline" className="border-success/40 text-success">
          New
        </Badge>
      );
    case "duplicate":
      return (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" className="text-muted-foreground">
              Already saved
            </Badge>
          </TooltipTrigger>
          <TooltipContent>Same user, host and port as the saved session {status.sessionName}</TooltipContent>
        </Tooltip>
      );
    case "duplicateInImport": {
      const first = preview.rows.find((r) => r.index === status.row);
      return (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" className="text-muted-foreground">
              Duplicate
            </Badge>
          </TooltipTrigger>
          <TooltipContent>Same user, host and port as {first?.candidate.name ?? "an earlier row"}</TooltipContent>
        </Tooltip>
      );
    }
    case "nameConflict":
      return (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge variant="outline" className="border-tier-medium/40 text-tier-medium">
              Name taken
            </Badge>
          </TooltipTrigger>
          <TooltipContent>A saved session has this name; this one is imported as {status.renameTo}</TooltipContent>
        </Tooltip>
      );
  }
}

export function ImportDialog({ folders, folderId, vault, onVaultChanged, onOpenVault, onImported, onClose }: Props) {
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [picked, setPicked] = useState<Set<number>>(new Set());
  /** SS-01: rows whose startup command is imported too; none by default. */
  const [keepStartup, setKeepStartup] = useState<Set<number>>(new Set());
  const [target, setTarget] = useState<string>(folderId ?? TOP);
  const [addKeys, setAddKeys] = useState(true);
  const [busy, setBusy] = useState<ImportSource | "import" | null>(null);
  const [report, setReport] = useState<ImportReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** QL-10: the format guide open in the dialog. */
  const [guide, setGuide] = useState<FormatGuide | null>(null);

  async function openGuide(source: ImportSource) {
    setError(null);
    try {
      setGuide(await api.importGuide(source));
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function saveSample(source: ImportSource) {
    setError(null);
    try {
      const saved = await api.importSaveSample(source);
      if (saved) toast.success(`Sample saved to ${saved}`);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function read(source: ImportSource, chooseFile = false) {
    setBusy(source);
    setError(null);
    try {
      const found = await api.importPreview(source, chooseFile);
      if (found) {
        setGuide(null);
        setPreview(found);
        setPicked(new Set(found.rows.filter((r) => r.selected).map((r) => r.index)));
        setKeepStartup(new Set());
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  const keyFiles = useMemo(() => {
    const files = new Set<string>();
    for (const row of preview?.rows ?? []) if (row.keyFile && picked.has(row.index)) files.add(row.keyFile.path);
    return files;
  }, [preview, picked]);
  const vaultReady = vault?.status === "unlocked";
  const keysWanted = addKeys && keyFiles.size > 0 && vault?.status !== "notSetUp";
  /** SS-01: picked rows with a startup command. */
  const withStartup = (preview?.rows ?? []).filter((r) => picked.has(r.index) && r.candidate.startupCommand);

  async function commit() {
    if (!preview) return;
    setBusy("import");
    setError(null);
    try {
      const done = await api.importCommit({
        previewId: preview.id,
        rows: [...picked].sort((a, b) => a - b),
        folderId: target === TOP ? null : target,
        addKeys: keysWanted,
        keepStartup: [...keepStartup].filter((i) => picked.has(i)).sort((a, b) => a - b),
      });
      setReport(done);
      onImported();
      toast.success(`Imported ${plural(done.created, "session")}`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  const counts = useMemo(() => {
    const rows = preview?.rows ?? [];
    return {
      fresh: rows.filter((r) => r.status.kind === "new").length,
      duplicates: rows.filter((r) => r.status.kind === "duplicate" || r.status.kind === "duplicateInImport").length,
      conflicts: rows.filter((r) => r.status.kind === "nameConflict").length,
    };
  }, [preview]);

  const allPicked = preview !== null && preview.rows.length > 0 && picked.size === preview.rows.length;

  return (
    <Dialog open onOpenChange={(open) => !open && busy === null && onClose()}>
      <DialogContent className={cn(preview && !report ? "sm:max-w-5xl" : guide ? "sm:max-w-3xl" : "sm:max-w-xl")}>
        <DialogHeader>
          <DialogTitle>Import sessions</DialogTitle>
          <DialogDescription>
            {report
              ? "Done."
              : guide && !preview
                ? "What Remotely reads from this format, and a sample file to start from. The sample holds made-up example sessions only."
                : preview
                  ? `${plural(preview.rows.length, "session")} found in ${preview.file ?? SOURCE_NAME[preview.source]}: ${counts.fresh} new, ${plural(counts.duplicates, "duplicate")}, ${plural(counts.conflicts, "name")} already taken. Nothing is saved until you import.`
                  : "Pick where your sessions are. You'll see what was found, with duplicates and name conflicts, before anything is saved. Saved passwords are never imported."}
          </DialogDescription>
        </DialogHeader>

        {!preview && !report && guide && <GuideView guide={guide} />}

        {!preview && !report && !guide && (
          <div className="grid gap-2">
            {SOURCES.map((s) => (
              <div key={s.source} className="flex items-stretch rounded-lg border">
                <button
                  type="button"
                  disabled={busy !== null}
                  onClick={() => void read(s.source)}
                  className="flex min-w-0 flex-1 items-start gap-3 rounded-l-lg p-3 text-left hover:bg-muted/60 disabled:opacity-60"
                >
                  {busy === s.source ? (
                    <LoaderCircleIcon className="mt-0.5 size-5 shrink-0 animate-spin text-muted-foreground" />
                  ) : (
                    <s.icon className="mt-0.5 size-5 shrink-0 text-muted-foreground" />
                  )}
                  <span className="grid gap-0.5">
                    <span className="font-medium">{s.title}</span>
                    <span className="text-sm text-muted-foreground">{s.detail}</span>
                  </span>
                </button>
                {s.format && (
                  <div className="flex shrink-0 flex-col justify-center gap-1 border-l px-1.5">
                    <Button
                      variant="ghost"
                      size="xs"
                      className="justify-start"
                      disabled={busy !== null}
                      onClick={() => void openGuide(s.source)}
                    >
                      <BookOpenIcon />
                      Guide
                    </Button>
                    <Button
                      variant="ghost"
                      size="xs"
                      className="justify-start"
                      disabled={busy !== null}
                      title="Save a sample file with made-up example sessions"
                      onClick={() => void saveSample(s.source)}
                    >
                      <DownloadIcon />
                      Sample…
                    </Button>
                  </div>
                )}
              </div>
            ))}
            <Button
              variant="link"
              className="h-auto justify-self-start p-0 text-sm"
              disabled={busy !== null}
              onClick={() => void read("openssh", true)}
            >
              Choose another OpenSSH config file…
            </Button>
          </div>
        )}

        {preview && !report && (
          <div className="grid min-w-0 gap-3">
            {preview.warnings.map((w) => (
              <Alert key={w}>
                <InfoIcon />
                <AlertDescription>{w}</AlertDescription>
              </Alert>
            ))}
            {preview.rows.length > 0 && (
              <div className="max-h-[45vh] overflow-auto rounded-lg border">
                <Table>
                  <TableHeader className="sticky top-0 bg-background">
                    <TableRow>
                      <TableHead className="w-8">
                        <Checkbox
                          aria-label="Import all"
                          checked={allPicked ? true : picked.size > 0 ? "indeterminate" : false}
                          onCheckedChange={(v) =>
                            setPicked(v === true ? new Set(preview.rows.map((r) => r.index)) : new Set())
                          }
                        />
                      </TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Address</TableHead>
                      <TableHead>Folder</TableHead>
                      <TableHead>Login</TableHead>
                      <TableHead>Environment</TableHead>
                      <TableHead>Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {preview.rows.map((row) => {
                      const c = row.candidate;
                      const on = picked.has(row.index);
                      return (
                        <TableRow key={row.index} className={cn(!on && "text-muted-foreground")}>
                          <TableCell>
                            <Checkbox
                              aria-label={`Import ${c.name}`}
                              checked={on}
                              onCheckedChange={(v) =>
                                setPicked((prev) => {
                                  const next = new Set(prev);
                                  if (v === true) next.add(row.index);
                                  else next.delete(row.index);
                                  return next;
                                })
                              }
                            />
                          </TableCell>
                          <TableCell className="whitespace-normal">
                            <div className="flex items-center gap-1.5 font-medium">
                              {row.status.kind === "nameConflict" ? row.status.renameTo : c.name}
                              {(c.notes.length > 0 || c.jump) && (
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <InfoIcon className="size-3.5 text-muted-foreground" aria-label="Notes" />
                                  </TooltipTrigger>
                                  <TooltipContent className="max-w-xs">
                                    {[
                                      ...c.notes,
                                      ...(c.jump
                                        ? [
                                            `Connects through ${c.jump}. The link is kept if that session is imported too (or is here already); otherwise it connects directly until you choose a jump host.`,
                                          ]
                                        : []),
                                    ].map((n) => (
                                      <p key={n}>{n}</p>
                                    ))}
                                  </TooltipContent>
                                </Tooltip>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="font-mono text-xs" data-mask="address">
                            {address(row)}
                          </TableCell>
                          <TableCell className="text-sm">{c.folder.length > 0 ? c.folder.join(" / ") : "—"}</TableCell>
                          <TableCell className="text-sm">
                            {c.auth.method === "keyFile" ? (
                              <span className="inline-flex items-center gap-1">
                                Key {fileName(c.auth.path)}
                                {row.keyFile && !row.keyFile.exists && (
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <AlertTriangleIcon className="size-3.5 text-tier-high" aria-label="Missing" />
                                    </TooltipTrigger>
                                    <TooltipContent>{c.auth.path} is not on this computer</TooltipContent>
                                  </Tooltip>
                                )}
                                {/* A3: a key on a network share or a device path is not read; the notes say why. */}
                                {!row.keyFile && (
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <AlertTriangleIcon className="size-3.5 text-tier-high" aria-label="Not read" />
                                    </TooltipTrigger>
                                    <TooltipContent className="max-w-xs">
                                      Remotely didn&apos;t read {c.auth.path}: it is on a network share or a device
                                      path. Copy the key to this PC, then choose it in the session editor.
                                    </TooltipContent>
                                  </Tooltip>
                                )}
                              </span>
                            ) : c.auth.method === "agent" ? (
                              "SSH agent"
                            ) : (
                              "Password, asked"
                            )}
                          </TableCell>
                          <TableCell>
                            <EnvBadge env={c.environment} />
                          </TableCell>
                          <TableCell>
                            <StatusBadge row={row} preview={preview} />
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            )}
            {withStartup.length > 0 && (
              <Alert>
                <AlertTriangleIcon />
                <AlertTitle>
                  {plural(withStartup.length, "session")} {withStartup.length === 1 ? "has" : "have"} a startup command
                </AlertTitle>
                <AlertDescription className="grid gap-2">
                  <p>
                    A startup command is typed into the shell at every connection, without asking. They are left out
                    unless you tick them; tick only the ones you know.
                  </p>
                  <ul className="grid gap-1.5">
                    {withStartup.map((row) => (
                      <li key={row.index} className="flex min-w-0 items-start gap-2">
                        <Checkbox
                          id={`import-startup-${row.index}`}
                          className="mt-0.5"
                          checked={keepStartup.has(row.index)}
                          onCheckedChange={(v) =>
                            setKeepStartup((prev) => {
                              const next = new Set(prev);
                              if (v === true) next.add(row.index);
                              else next.delete(row.index);
                              return next;
                            })
                          }
                        />
                        <Label htmlFor={`import-startup-${row.index}`} className="grid min-w-0 gap-1 font-normal">
                          <span className="flex flex-wrap items-center gap-2">
                            <span className="font-medium text-foreground">{row.candidate.name}</span>
                            {row.startupRating && <StartupRatingBadges rating={row.startupRating} />}
                          </span>
                          <code className="font-mono text-xs break-all whitespace-pre-wrap">
                            {row.candidate.startupCommand}
                          </code>
                        </Label>
                      </li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}
            {preview.skipped.length > 0 && (
              <details className="text-sm">
                <summary className="cursor-pointer text-muted-foreground">
                  {plural(preview.skipped.length, "entry")} can't be imported
                </summary>
                <ul className="mt-1 grid gap-0.5 pl-4">
                  {preview.skipped.map((s, i) => (
                    <li key={`${s.name}-${i}`}>
                      <span className="font-medium">{s.name}</span>: {s.reason}
                    </li>
                  ))}
                </ul>
              </details>
            )}
            <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
              <div className="flex items-center gap-2">
                <Label htmlFor="import-folder">Import into</Label>
                <Select value={target} onValueChange={setTarget}>
                  <SelectTrigger id="import-folder" className="w-56">
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
              </div>
              {keyFiles.size > 0 && (
                <div className="flex items-center gap-2">
                  <Checkbox
                    id="import-keys"
                    checked={addKeys && vault?.status !== "notSetUp"}
                    disabled={vault?.status === "notSetUp"}
                    onCheckedChange={(v) => setAddKeys(v === true)}
                  />
                  <Label htmlFor="import-keys" className="font-normal">
                    Add {plural(keyFiles.size, "key file")} to the vault and log in with them
                  </Label>
                  {vault?.status === "notSetUp" && (
                    <Button variant="link" className="h-auto p-0" onClick={onOpenVault}>
                      Set up the vault first
                    </Button>
                  )}
                </div>
              )}
            </div>
            {keysWanted && !vaultReady && vault && (
              <Alert>
                <AlertTriangleIcon />
                <AlertTitle>Unlock the vault to add the key files</AlertTitle>
                <AlertDescription>
                  <VaultUnlock info={vault} onUnlocked={onVaultChanged} idPrefix="import-unlock" />
                </AlertDescription>
              </Alert>
            )}
          </div>
        )}

        {report && (
          <div className="grid gap-3 text-sm">
            <p>
              Imported {plural(report.created, "session")}
              {report.keysAdded > 0 && `, added ${plural(report.keysAdded, "key")} to the vault`}
              {report.foldersCreated > 0 && `, created ${plural(report.foldersCreated, "folder")}`}. Each one is in the
              audit log.
              {report.startupLeftOut > 0 &&
                ` ${plural(report.startupLeftOut, "startup command")} left out; add one in the session editor if it is wanted.`}
            </p>
            {report.problems.length > 0 && (
              <Alert>
                <AlertTriangleIcon />
                <AlertTitle>{plural(report.problems.length, "thing")} to check</AlertTitle>
                <AlertDescription>
                  <ul className="grid gap-0.5">
                    {report.problems.map((p, i) => (
                      <li key={`${p.name}-${i}`}>
                        <span className="font-medium">{p.name}</span>: {p.reason}
                      </li>
                    ))}
                  </ul>
                </AlertDescription>
              </Alert>
            )}
          </div>
        )}

        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}

        <DialogFooter>
          {report ? (
            <Button onClick={onClose}>Close</Button>
          ) : preview ? (
            <>
              <Button variant="outline" disabled={busy !== null} onClick={() => setPreview(null)}>
                <ArrowLeftIcon data-icon="inline-start" />
                Back
              </Button>
              <Button
                disabled={busy !== null || picked.size === 0 || (keysWanted && !vaultReady)}
                onClick={() => void commit()}
              >
                {busy === "import" && <LoaderCircleIcon className="animate-spin" data-icon="inline-start" />}
                Import {plural(picked.size, "session")}
              </Button>
            </>
          ) : guide ? (
            <>
              <Button variant="outline" disabled={busy !== null} onClick={() => setGuide(null)}>
                <ArrowLeftIcon data-icon="inline-start" />
                Back
              </Button>
              <Button variant="outline" disabled={busy !== null} onClick={() => void saveSample(guide.source)}>
                <DownloadIcon data-icon="inline-start" />
                Save a sample file…
              </Button>
              <Button disabled={busy !== null} onClick={() => void read(guide.source, guide.source === "openssh")}>
                {busy === guide.source && <LoaderCircleIcon className="animate-spin" data-icon="inline-start" />}
                Choose a file to import…
              </Button>
            </>
          ) : (
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** QL-10: a format guide: what the import reads, and how. */
function GuideView({ guide }: { guide: FormatGuide }) {
  return (
    <div className="grid max-h-[60vh] min-w-0 gap-4 overflow-auto pr-1 text-sm">
      <div className="grid gap-1.5">
        <h3 className="font-medium">{guide.title}</h3>
        {guide.intro.map((p) => (
          <p key={p} className="text-muted-foreground">
            {p}
          </p>
        ))}
      </div>
      {guide.sections.map((section) => (
        <section key={section.heading} className="grid gap-1.5">
          <h4 className="font-medium">{section.heading}</h4>
          {section.text.map((p) => (
            <p key={p} className="text-muted-foreground">
              {p}
            </p>
          ))}
          {section.table && (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    {section.table.headings.map((h) => (
                      <TableHead key={h}>{h}</TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {section.table.rows.map((row) => (
                    <TableRow key={row.join("|")}>
                      {row.map((cell, i) => (
                        <TableCell
                          key={i}
                          className={cn("align-top whitespace-normal", i === 0 && "font-mono text-xs")}
                        >
                          {cell}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </section>
      ))}
      <p className="text-xs text-muted-foreground">
        The sample, {guide.sampleName}, uses made-up example names and addresses only. Import it to see what each line
        becomes before you import your own sessions.
      </p>
    </div>
  );
}
