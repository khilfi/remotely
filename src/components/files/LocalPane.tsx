// SS-14 (0.8.0 G3): the Files page's left pane, this PC. It only browses and is a transfer's source or destination:
// nothing here changes a file of this PC. The core lists each folder and keeps the listing; this pane names files by
// that listing and their names, never by a path it made up (a typed folder goes through the core's checks). Links and
// junctions are listed but not opened, and Remotely's own data folder isn't opened at all.

import { useCallback, useEffect, useState, type FormEvent, type PointerEvent as ReactPointerEvent } from "react";
import {
  ArrowLeftIcon,
  ArrowRightIcon,
  ArrowUpIcon,
  DownloadIcon,
  FingerprintIcon,
  FolderOpenIcon,
  HardDriveIcon,
  HouseIcon,
  MonitorIcon,
  UploadIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { DropdownMenuItem } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { RefreshButton } from "@/components/RefreshButton";
import { SelectionBar } from "@/components/SelectionBar";
import { WhyDisabled } from "@/components/WhyDisabled";
import { ChecksumDialog, type ChecksumShown } from "@/components/files/ChecksumDialog";
import { FileTable } from "@/components/files/FileTable";
import { PaneButton } from "@/components/files/PaneButton";
import { errorMessage } from "@/lib/api";
import {
  canGo,
  DEFAULT_VIEW,
  emptyHistory,
  go,
  localCrumbs,
  localPaneEntry,
  viewEntries,
  visit,
  type DragItems,
  type History,
  type PaneView,
} from "@/lib/files-page";
import { filesPageApi, type LocalAsk, type LocalEntry, type LocalListing } from "@/lib/files-page-api";
import { cn } from "@/lib/utils";

interface Props {
  /** Where an upload from here goes: the host tab's folder, and the host's name. */
  hostFolder: string | null;
  hostName: string | null;
  /** Why an upload can't go now (no host tab, not connected, the read-only lock). */
  uploadReason: string | null;
  onUpload: (listing: string, names: string[]) => void;
  /** The listing shown, for downloads into it and comparisons. */
  onListing: (listing: LocalListing | null) => void;
  onDragStart: (items: DragItems, event: ReactPointerEvent) => void;
  /** Bumped when something landed here (a download), to list the folder again. */
  refresh: number;
  /** What is picked (a push to many hosts takes picked files). */
  onPicked?: (names: string[]) => void;
}

type Place = string | null;

export function LocalPane({
  hostFolder,
  hostName,
  uploadReason,
  onUpload,
  onListing,
  onDragStart,
  refresh,
  onPicked,
}: Props) {
  const [listing, setListing] = useState<LocalListing | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** What to show next (each ask counted), and the last one answered. */
  const [want, setWant] = useState<{ ask: LocalAsk; n: number; remember: boolean }>({
    ask: { kind: "home" },
    n: 1,
    remember: true,
  });
  const [answered, setAnswered] = useState(0);
  const loading = answered !== want.n;
  const [view, setView] = useState<PaneView>(DEFAULT_VIEW);
  const [picked, setPicked] = useState<{ names: string[]; anchor: string | null }>({ names: [], anchor: null });
  const [history, setHistory] = useState<History<Place>>(emptyHistory());
  const [typed, setTyped] = useState<string | null>(null);
  const [checksum, setChecksum] = useState<ChecksumShown | null>(null);

  const open = useCallback((ask: LocalAsk, remember = true) => {
    setWant((w) => ({ ask, n: w.n + 1, remember }));
  }, []);

  useEffect(() => {
    let gone = false;
    filesPageApi.localList(want.ask).then(
      (next) => {
        if (gone) return;
        setAnswered(want.n);
        setListing(next);
        onListing(next);
        setError(null);
        setTyped(null);
        setPicked({ names: [], anchor: null });
        if (want.remember) setHistory((h) => visit(h, next.path, (a, b) => a === b));
      },
      (err) => {
        if (gone) return;
        setAnswered(want.n);
        setError(errorMessage(err));
      },
    );
    return () => {
      gone = true;
    };
  }, [want, onListing]);

  // A download landed here: the same folder again, without a new step in the history.
  const [seenRefresh, setSeenRefresh] = useState(refresh);
  if (refresh !== seenRefresh) {
    setSeenRefresh(refresh);
    if (listing) open({ kind: "again", listing: listing.id }, false);
  }

  function place(path: Place, remember = true) {
    open(path ? { kind: "typed", path } : { kind: "drives" }, remember);
  }

  function step(dir: -1 | 1) {
    const moved = go(history, dir);
    if (!moved) return;
    setHistory(moved.history);
    place(moved.item, false);
  }

  function submit(ev: FormEvent) {
    ev.preventDefault();
    const text = (typed ?? listing?.path ?? "").trim();
    if (text) place(text);
  }

  async function sum(entry: LocalEntry) {
    if (!listing) return;
    setChecksum({ name: entry.name, sha256: null });
    try {
      const sha256 = await filesPageApi.localChecksum(listing.id, entry.name);
      setChecksum({ name: entry.name, sha256, size: entry.size, by: "worked out on this PC" });
    } catch (err) {
      setChecksum({ name: entry.name, sha256: null, error: errorMessage(err) });
    }
  }

  useEffect(() => onPicked?.(picked.names), [picked.names, onPicked]);

  const drives = listing !== null && listing.path === null;
  const entries = listing
    ? viewEntries(
        listing.entries.map((e) => ({ ...localPaneEntry(e), raw: e })),
        view,
      )
    : [];
  const picks = picked.names.filter((n) => entries.some((e) => e.name === n));
  const pickedEntries = entries.filter((e) => picks.includes(e.name));
  const uploadable = pickedEntries.length > 0 && pickedEntries.every((e) => !e.link && e.kind !== "other");
  const why =
    uploadReason ??
    (drives ? "A drive can't be uploaded whole: open it first" : null) ??
    (pickedEntries.some((e) => e.link)
      ? "Links and junctions aren't uploaded from here: pick what they lead to"
      : null);

  function openEntry(e: (typeof entries)[number]) {
    if (!listing) return;
    if (e.kind === "folder" && !e.link) open({ kind: "child", listing: listing.id, name: e.name });
  }

  return (
    <section
      aria-label="This PC"
      data-files-drop="local"
      className="@container flex min-h-0 min-w-0 flex-1 flex-col gap-2 rounded-lg border p-2"
    >
      <div className="flex items-center gap-1.5">
        <MonitorIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
        <h2 className="shrink-0 text-sm font-medium">This PC</h2>
        <div className="ml-auto flex items-center gap-1">
          <Label htmlFor="files-local-hidden" className="text-xs font-normal text-muted-foreground">
            Hidden files
          </Label>
          <Switch
            id="files-local-hidden"
            checked={view.hidden}
            onCheckedChange={(hidden) => setView((v) => ({ ...v, hidden }))}
          />
        </div>
      </div>
      <div className="flex items-center gap-1">
        <PaneButton
          label="Back"
          disabledReason={canGo(history, -1) ? null : "Nothing before this"}
          onClick={() => step(-1)}
        >
          <ArrowLeftIcon />
        </PaneButton>
        <PaneButton
          label="Forward"
          disabledReason={canGo(history, 1) ? null : "Nothing after this"}
          onClick={() => step(1)}
        >
          <ArrowRightIcon />
        </PaneButton>
        <PaneButton
          label="Up one folder"
          disabledReason={listing?.hasParent ? null : "This is the top"}
          onClick={() => listing && open({ kind: "parent", listing: listing.id })}
        >
          <ArrowUpIcon />
        </PaneButton>
        <PaneButton label="Home folder" onClick={() => open({ kind: "home" })}>
          <HouseIcon />
        </PaneButton>
        <PaneButton label="Downloads" onClick={() => open({ kind: "downloads" })}>
          <DownloadIcon />
        </PaneButton>
        <PaneButton label="This PC's drives" onClick={() => open({ kind: "drives" })}>
          <HardDriveIcon />
        </PaneButton>
        <form className="min-w-0 flex-1" onSubmit={submit}>
          <Input
            aria-label="Folder on this PC"
            aria-invalid={listing?.error ? true : undefined}
            className="h-7 font-mono text-xs"
            value={typed ?? listing?.path ?? ""}
            placeholder={drives ? "This PC" : "Type a folder and press Enter"}
            onChange={(e) => setTyped(e.target.value)}
            spellCheck={false}
          />
        </form>
        <RefreshButton busy={loading} onClick={() => listing && open({ kind: "again", listing: listing.id }, false)} />
      </div>
      <nav aria-label="Folder path on this PC" className="flex flex-wrap items-center gap-0.5 text-xs">
        {localCrumbs(listing?.path ?? null).map((c, i) => (
          <span key={`${c.path ?? "pc"}-${i}`} className="flex items-center">
            {i > 1 && <span className="px-0.5 text-muted-foreground">\</span>}
            <button
              type="button"
              className="rounded px-1 hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              onClick={() => place(c.path)}
            >
              {c.label}
            </button>
          </span>
        ))}
      </nav>
      <Input
        aria-label="Filter this PC's folder"
        className="h-7 text-xs"
        placeholder="Filter: words or a pattern such as *.log"
        value={view.filter}
        onChange={(e) => setView((v) => ({ ...v, filter: e.target.value }))}
      />
      {(error ?? listing?.error) && <p className="text-xs text-destructive">{error ?? listing?.error}</p>}
      {picks.length > 0 && (
        <SelectionBar count={picks.length} onClear={() => setPicked({ names: [], anchor: null })} className="flex-none">
          <WhyDisabled reason={why ?? (uploadable ? null : "Only files and folders can be uploaded")}>
            <Button
              variant="ghost"
              size="sm"
              disabled={why !== null || !uploadable}
              onClick={() => listing && onUpload(listing.id, picks)}
            >
              <UploadIcon />
              {hostName ? `Upload to ${hostName}` : "Upload"}
            </Button>
          </WhyDisabled>
        </SelectionBar>
      )}
      <FileTable
        label="this PC"
        entries={entries}
        view={view}
        onView={setView}
        picked={picks}
        anchor={picked.anchor}
        onPick={(names, anchor) => setPicked({ names, anchor })}
        onOpen={openEntry}
        isDrive={(e) => drives && e.raw.drive !== undefined}
        rowTitle={(e) =>
          e.link
            ? "A link or junction: not opened from here"
            : e.kind === "folder"
              ? "Double-click to open"
              : hostFolder
                ? `Drag to the host to upload into ${hostFolder}`
                : "A file of this PC"
        }
        onDragStart={(names, ev) => {
          if (!listing || drives) return;
          onDragStart({ from: "local", listing: listing.id, names }, ev);
        }}
        empty={drives ? "No drives found." : "This folder is empty."}
        loading={loading}
        menu={(e) => (
          <>
            {e.kind === "folder" && !e.link && (
              <DropdownMenuItem onSelect={() => openEntry(e)}>
                <FolderOpenIcon />
                Open
              </DropdownMenuItem>
            )}
            {!drives && !e.link && e.kind !== "other" && (
              <DropdownMenuItem
                disabled={uploadReason !== null}
                onSelect={() => listing && onUpload(listing.id, [e.name])}
              >
                <UploadIcon />
                {hostFolder ? `Upload to ${hostFolder}` : "Upload"}
              </DropdownMenuItem>
            )}
            {e.kind === "file" && !e.link && (
              <DropdownMenuItem onSelect={() => void sum(e.raw)}>
                <FingerprintIcon />
                SHA-256 checksum
              </DropdownMenuItem>
            )}
          </>
        )}
      />
      {listing?.more && (
        <p className={cn("text-xs text-muted-foreground")}>More is in this folder than is listed here.</p>
      )}
      {checksum && <ChecksumDialog shown={checksum} onClose={() => setChecksum(null)} />}
    </section>
  );
}
