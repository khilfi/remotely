// SS-08: the "Files here" drawer of the Terminal page. It follows the current terminal's shell folder (bash and zsh
// report it through Remotely's prompt hook), or starts in the home folder for other shells, where folders are opened
// by hand: double-click a folder, the breadcrumb, Up, or a path typed in. Files can be ticked and downloaded to
// Downloads or a folder picked in a dialog, and uploaded into the folder shown. SFTP runs on the terminal's own
// connection; uploads go through the approval flow. The transfers panel sits at the bottom. QL-08: disabled buttons
// say why.

import { useEffect, useState, type FormEvent } from "react";
import {
  ArrowUpIcon,
  CrosshairIcon,
  FileIcon,
  FolderIcon,
  FolderOpenIcon,
  LinkIcon,
  RefreshCwIcon,
  UploadIcon,
  XIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { SortableHead } from "@/components/SortableHead";
import { usePresentation } from "@/components/Presentation";
import { TransfersList } from "@/components/TransfersList";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type FolderListing, type FolderTracking, type TransferInfo } from "@/lib/api";
import { downloadReason, uploadReason } from "@/lib/disabled-reasons";
import { plural } from "@/lib/format";
import { readOnlyLocked } from "@/lib/presentation-state";
import { crumbs, formatSize, joinPath, sortEntries, type SortKey } from "@/lib/transfers";
import type { PaneSnapshot } from "@/lib/terminal-session";
import { cn } from "@/lib/utils";

interface Props {
  /** The current pane's core id, once it opened. */
  terminalId: string | null;
  snapshot: PaneSnapshot;
  /** How the current terminal is named. */
  name: string;
  /** SS-10: terminals MultiExec types into; uploads still go to this one only. */
  multiExecTerminals: number;
  transfers: TransferInfo[];
  /** Bumped when a transfer into this terminal finished, so the list shows it. */
  refresh: number;
  onUpload: (folder: string) => void;
  onDownload: (paths: string[], to: "downloads" | "choose") => void;
  onRetry: (transfer: TransferInfo) => void;
  onClearTransfers: () => void;
  onClose: () => void;
}

/** What the drawer says about following the shell. */
function trackingNote(tracking: FolderTracking | undefined, following: boolean) {
  switch (tracking) {
    case "following":
      return following ? "Follows the shell's folder." : null;
    case "unsupported":
      return "This shell doesn't report its folder (Remotely follows bash and zsh), so this starts in your home folder.";
    case "missed":
      return "Folder tracking wasn't set up because something was typed first. Reconnect to follow the shell's folder.";
    default:
      return null;
  }
}

export function FilesDrawer({
  terminalId,
  snapshot,
  name,
  multiExecTerminals,
  transfers,
  refresh,
  onUpload,
  onDownload,
  onRetry,
  onClearTransfers,
  onClose,
}: Props) {
  // FD-03: uploads say why they are off while the read-only lock applies.
  const presentation = usePresentation();
  const connected = terminalId !== null && snapshot.status.state === "connected";
  const shellFolder = snapshot.folder?.path ?? null;
  /** A folder opened by hand, per terminal; none: the shell's folder (or home). */
  const [browsing, setBrowsing] = useState<{ terminal: string | null; path: string } | null>(null);
  const browse = browsing && browsing.terminal === terminalId ? browsing.path : null;
  const [tick, setTick] = useState(0);
  const want = `${terminalId ?? ""}|${browse ?? `shell:${shellFolder ?? ""}`}|${tick}|${refresh}|${connected}`;
  const [loaded, setLoaded] = useState<{ key: string; listing: FolderListing | null; error: string | null } | null>(
    null,
  );
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "name", dir: 1 });
  const [picked, setPicked] = useState<{ path: string; names: string[] }>({ path: "", names: [] });
  const [typed, setTyped] = useState<{ for: string; text: string } | null>(null);

  useEffect(() => {
    if (!terminalId || !connected) return;
    let gone = false;
    api.filesList(terminalId, browse).then(
      (listing) => {
        if (!gone) setLoaded({ key: want, listing, error: null });
      },
      (err) => {
        if (!gone) setLoaded({ key: want, listing: null, error: errorMessage(err) });
      },
    );
    return () => {
      gone = true;
    };
  }, [want, terminalId, connected, browse]);

  const fresh = loaded?.key === want;
  // While the next folder loads, the last one stays (dimmed).
  const listing = loaded?.listing ?? null;
  const error = fresh ? loaded?.error : null;
  const loading = connected && !fresh;
  const names = listing && picked.path === listing.path ? picked.names : [];
  const entries = listing ? sortEntries(listing.entries, sort.key, sort.dir) : [];
  const pickedEntries = entries.filter((e) => names.includes(e.name));
  const pathText = typed && typed.for === listing?.path ? typed.text : (listing?.path ?? "");

  function open(path: string) {
    setBrowsing({ terminal: terminalId, path });
    setTyped(null);
  }

  function follow() {
    setBrowsing(null);
    setTyped(null);
  }

  function toggle(entryName: string, on: boolean) {
    if (!listing) return;
    const now = new Set(names);
    if (on) now.add(entryName);
    else now.delete(entryName);
    setPicked({ path: listing.path, names: [...now] });
  }

  function sortBy(key: SortKey) {
    setSort((s) => ({ key, dir: s.key === key ? (s.dir === 1 ? -1 : 1) : 1 }));
  }

  function submitPath(ev: FormEvent) {
    ev.preventDefault();
    const text = pathText.trim();
    if (text) open(text);
  }

  const followingShell = snapshot.folder?.tracking === "following";
  const note = trackingNote(snapshot.folder?.tracking, browse === null);
  const files = pickedEntries.filter((e) => e.kind === "file");
  const download = downloadReason({ connected, picked: pickedEntries });
  const upload =
    uploadReason({ open: terminalId !== null, connected, readOnly: readOnlyLocked(presentation) }) ??
    (listing ? null : "Open a folder first");
  const allFiles = entries.filter((e) => e.kind === "file");

  return (
    <div className="@container flex h-full min-h-0 flex-col gap-2 rounded-lg border p-2">
      <div className="flex items-center gap-1.5">
        <FolderOpenIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
        <h2 className="shrink-0 text-sm font-medium whitespace-nowrap">Files here</h2>
        <span className="truncate text-xs text-muted-foreground" title={name}>
          {name}
        </span>
        <Button variant="ghost" size="icon-sm" className="ml-auto" aria-label="Close the files" onClick={onClose}>
          <XIcon />
        </Button>
      </div>

      {!terminalId ? (
        <p className="text-sm text-muted-foreground">Open a terminal: its files show here.</p>
      ) : !connected ? (
        <p className="text-sm text-muted-foreground">This terminal is not connected, so its files can't be reached.</p>
      ) : (
        <>
          {note && <p className="text-xs text-muted-foreground">{note}</p>}
          {multiExecTerminals > 1 && (
            <p className="rounded-md bg-muted/60 px-2 py-1 text-xs">
              MultiExec is on: uploads and downloads go through this terminal only, not all{" "}
              {plural(multiExecTerminals, "terminal")}.
            </p>
          )}
          <div className="flex items-center gap-1">
            <DrawerButton
              label="Up one folder"
              disabledReason={listing?.parent ? null : "This is the top folder"}
              onClick={() => listing?.parent && open(listing.parent)}
            >
              <ArrowUpIcon />
            </DrawerButton>
            <form className="min-w-0 flex-1" onSubmit={submitPath}>
              <Input
                aria-label="Folder on the host"
                className="h-7 font-mono text-xs"
                value={pathText}
                onChange={(e) => setTyped({ for: listing?.path ?? "", text: e.target.value })}
                spellCheck={false}
              />
            </form>
            <DrawerButton label="Refresh" onClick={() => setTick((n) => n + 1)}>
              <RefreshCwIcon className={cn(loading && "animate-spin")} />
            </DrawerButton>
            {browse !== null && (
              <DrawerButton
                label={followingShell ? "Follow the terminal's folder again" : "Back to the starting folder (home)"}
                onClick={follow}
              >
                <CrosshairIcon />
              </DrawerButton>
            )}
          </div>
          {listing && (
            <nav aria-label="Folder path" className="flex flex-wrap items-center gap-0.5 text-xs">
              {crumbs(listing.path).map((c, i) => (
                <span key={c.path} className="flex items-center">
                  {i > 1 && <span className="px-0.5 text-muted-foreground">/</span>}
                  <button
                    type="button"
                    className="rounded px-1 hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                    onClick={() => open(c.path)}
                  >
                    {c.label}
                  </button>
                </span>
              ))}
            </nav>
          )}
          {error && <p className="text-xs text-destructive">{error}</p>}
          <div
            className={cn(
              // One scroll area: the table's own container would add a second, inner one.
              "min-h-28 flex-1 overflow-auto rounded-md border [&>[data-slot=table-container]]:overflow-visible",
              loading && "opacity-60",
            )}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-7">
                    <Checkbox
                      aria-label="Tick every file"
                      checked={allFiles.length > 0 && allFiles.every((e) => names.includes(e.name))}
                      disabled={allFiles.length === 0}
                      onCheckedChange={(on) =>
                        listing && setPicked({ path: listing.path, names: on ? allFiles.map((e) => e.name) : [] })
                      }
                    />
                  </TableHead>
                  <SortableHead
                    label="Name"
                    active={sort.key === "name"}
                    dir={sort.dir}
                    onSort={() => sortBy("name")}
                  />
                  <SortableHead
                    label="Size"
                    active={sort.key === "size"}
                    dir={sort.dir}
                    onSort={() => sortBy("size")}
                    className="text-right"
                  />
                  <SortableHead
                    label="Modified"
                    active={sort.key === "modified"}
                    dir={sort.dir}
                    onSort={() => sortBy("modified")}
                    className="hidden @sm:table-cell"
                  />
                </TableRow>
              </TableHeader>
              <TableBody>
                {listing && entries.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} className="text-center text-xs text-muted-foreground">
                      This folder is empty.
                    </TableCell>
                  </TableRow>
                )}
                {entries.map((e) => (
                  <TableRow
                    key={e.name}
                    data-state={names.includes(e.name) ? "selected" : undefined}
                    onDoubleClick={() => {
                      if (!listing) return;
                      if (e.kind === "folder") open(joinPath(listing.path, e.name));
                      else if (e.kind === "file") onDownload([joinPath(listing.path, e.name)], "downloads");
                    }}
                    className="cursor-default text-xs"
                    title={
                      e.kind === "folder"
                        ? "Double-click to open"
                        : e.kind === "file"
                          ? "Double-click to download to Downloads"
                          : "Not a regular file"
                    }
                  >
                    <TableCell className="py-1">
                      <Checkbox
                        aria-label={`Tick ${e.name}`}
                        checked={names.includes(e.name)}
                        onCheckedChange={(on) => toggle(e.name, on === true)}
                      />
                    </TableCell>
                    <TableCell className="max-w-0 py-1">
                      <span className="flex min-w-0 items-center gap-1.5">
                        {e.kind === "folder" ? (
                          <FolderIcon className="size-3.5 shrink-0 text-primary" aria-label="Folder" />
                        ) : (
                          <FileIcon className="size-3.5 shrink-0 text-muted-foreground" aria-label="File" />
                        )}
                        <span className={cn("truncate", e.kind === "other" && "text-muted-foreground")}>{e.name}</span>
                        {e.link && <LinkIcon className="size-3 shrink-0 text-muted-foreground" aria-label="Link" />}
                      </span>
                    </TableCell>
                    <TableCell className="py-1 text-right whitespace-nowrap tabular-nums">
                      {e.kind === "file" ? formatSize(e.size) : ""}
                    </TableCell>
                    <TableCell className="hidden py-1 whitespace-nowrap text-muted-foreground @sm:table-cell">
                      {e.modified
                        ? new Date(e.modified * 1000).toLocaleString(undefined, {
                            dateStyle: "short",
                            timeStyle: "short",
                          })
                        : ""}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <WhyDisabled reason={download}>
              <Button
                size="xs"
                disabled={download !== null}
                onClick={() =>
                  listing &&
                  onDownload(
                    files.map((e) => joinPath(listing.path, e.name)),
                    "downloads",
                  )
                }
              >
                Download{files.length > 1 ? ` ${files.length}` : ""}
              </Button>
            </WhyDisabled>
            <WhyDisabled reason={download}>
              <Button
                size="xs"
                variant="outline"
                disabled={download !== null}
                onClick={() =>
                  listing &&
                  onDownload(
                    files.map((e) => joinPath(listing.path, e.name)),
                    "choose",
                  )
                }
              >
                Download to…
              </Button>
            </WhyDisabled>
            <WhyDisabled reason={upload}>
              <Button
                size="xs"
                variant="outline"
                className="ml-auto"
                disabled={upload !== null}
                onClick={() => listing && onUpload(listing.path)}
              >
                <UploadIcon />
                Upload here…
              </Button>
            </WhyDisabled>
          </div>
          <p className="text-[11px] text-muted-foreground">
            Drop files on the terminal to upload them; right-click a file name in it to download. As the logged-in user,
            never with sudo.
          </p>
        </>
      )}
      <div className="flex max-h-[35%] min-h-0 shrink-0 flex-col overflow-hidden">
        <TransfersList transfers={transfers} onRetry={onRetry} onClear={onClearTransfers} />
      </div>
    </div>
  );
}

function DrawerButton({
  label,
  onClick,
  disabledReason,
  children,
}: {
  label: string;
  onClick: () => void;
  disabledReason?: string | null;
  children: React.ReactNode;
}) {
  if (disabledReason) {
    return (
      <WhyDisabled reason={`${label}: ${disabledReason}`}>
        <Button variant="ghost" size="icon-sm" aria-label={label} disabled>
          {children}
        </Button>
      </WhyDisabled>
    );
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label={label} onClick={onClick}>
          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}
