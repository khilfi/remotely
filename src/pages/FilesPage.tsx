// SS-14, BX-10 (0.8.0 G3): the Files page. This PC on the left (it only browses, and is a transfer's source or
// destination), a host on the right with a tab per host, and a Many hosts tab for BX-10. A host tab rides on an open SSH
// terminal's connection, as the Terminal's "Files here" drawer does: opening a saved session here opens its terminal
// tab in the background on the Terminal page, where its login, host key and password questions show.
//
// Drag and drop: picked rows dragged from one pane to the other upload or download, and host rows dropped on a host
// folder move into it (pointer events: the window's drop handler, which catches Explorer's files in Rust, turns HTML
// drag and drop off on Windows). Files from Explorer dropped on the host pane upload there (`files://dropped`, staged in
// the core; no path comes from the window). Every change goes through the approval rules; reads don't.

import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { FolderTreeIcon, PlusIcon, ServerIcon, UsersIcon, XIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { usePresentation } from "@/components/Presentation";
import { Tip } from "@/components/Tip";
import { TransfersList } from "@/components/TransfersList";
import { UploadConflictDialog } from "@/components/UploadConflictDialog";
import { HostPane, type HostTab } from "@/components/files/HostPane";
import { LocalPane } from "@/components/files/LocalPane";
import { ManyHostsView } from "@/components/files/ManyHostsView";
import {
  api,
  errorMessage,
  type DownloadStart,
  type Existing,
  type SessionRecord,
  type StagedFiles,
  type SubmitOutcome,
  type TransferInfo,
  type UploadStart,
} from "@/lib/api";
import { uploadReason } from "@/lib/disabled-reasons";
import { dropAction, type DragItems } from "@/lib/files-page";
import { filesPageApi, type LocalListing } from "@/lib/files-page-api";
import { plural } from "@/lib/format";
import { filePanes, openPanes, paneOf, subscribePanes } from "@/lib/open-panes";
import { readOnlyLocked } from "@/lib/presentation-state";
import { kindOf } from "@/lib/session-kinds";
import { transferStore } from "@/lib/transfers-store";

export interface FilesRequest {
  terminalId?: string;
  path?: string;
  n: number;
}

interface Props {
  active: boolean;
  request: FilesRequest | null;
  onSubmitted: (outcome: SubmitOutcome, onJob?: (jobId: string) => void) => void;
  /** Opens a saved session's terminal tab without leaving this page. */
  onOpenTerminal: (sessionId: string) => void;
  onShowTerminal: (terminalId: string) => void;
  onOpenSessions: () => void;
}

const MANY = "many";

/** An upload or download waiting for the answer about files already there. */
type Conflict =
  | {
      kind: "upload";
      terminalId: string;
      staged: StagedFiles;
      folder: string;
      existing: string[];
      asRoot: boolean;
      name: string;
    }
  | {
      kind: "download";
      terminalId: string;
      paths: string[];
      /** Into the local pane's listing, or (`null`) the folder a choice was about. */
      listing: string | null;
      choice: string | null;
      folder: string;
      existing: string[];
      asRoot: boolean;
      name: string;
    };

/** Downloads finished, so the local pane lists its folder again when the count grows. */
function downloadsDone(all: TransferInfo[]) {
  return all.filter((t) => t.direction === "download" && t.state === "done").length;
}

export function FilesPage({ active, request, onSubmitted, onOpenTerminal, onShowTerminal, onOpenSessions }: Props) {
  const presentation = usePresentation();
  const panes = useSyncExternalStore(subscribePanes, openPanes);
  const [allTabs, setTabs] = useState<HostTab[]>([]);
  const [activeTab, setActiveTab] = useState<string>(MANY);
  // A tab whose terminal closed goes once another tab shows (the one shown says so first).
  const tabs = allTabs.filter((t) => paneOf(t.terminalId) || t.key === activeTab);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [local, setLocal] = useState<LocalListing | null>(null);
  const [localPicked, setLocalPicked] = useState<string[]>([]);
  const [folders, setFolders] = useState<Record<string, { folder: string | null; asRoot: boolean }>>({});
  const [conflict, setConflict] = useState<Conflict | null>(null);
  const [drag, setDrag] = useState<{ items: DragItems; x: number; y: number } | null>(null);
  /** Saved sessions opened from here, waiting for their terminal to open. */
  const waiting = useRef(new Set<string>());
  const downloads = useSyncExternalStore(transferStore.subscribe, () => downloadsDone(transferStore.getSnapshot().all));

  const current = tabs.find((t) => t.key === activeTab) ?? null;
  const currentPane = paneOf(current?.terminalId);
  const currentFolder = current ? folders[current.key] : undefined;
  const connected = currentPane?.getSnapshot().status.state === "connected";

  // The saved SSH sessions to open from here.
  useEffect(() => {
    if (!active) return;
    api.sessions().then(
      (list) => setSessions(list.filter((s) => kindOf(s).protocol === "ssh")),
      () => setSessions([]),
    );
  }, [active]);

  /** Shows a terminal's tab (made when it has none), at `path` when given. */
  const addTab = useCallback((terminalId: string, path?: string) => {
    const key = `tab-${terminalId}`;
    setTabs((prev) => {
      const there = prev.find((t) => t.key === key);
      if (!there)
        return [
          ...prev.filter((t) => paneOf(t.terminalId)),
          { key, terminalId, pathRequest: path ? { path, n: 1 } : undefined },
        ];
      if (!path) return prev;
      return prev.map((t) => (t.key === key ? { ...t, pathRequest: { path, n: (t.pathRequest?.n ?? 0) + 1 } } : t));
    });
    setActiveTab(key);
  }, []);

  // A session opened from here: its tab once its terminal opened (heard from the Terminal page's panes).
  useEffect(
    () =>
      subscribePanes(() => {
        for (const pane of filePanes(openPanes())) {
          if (pane.sessionId && pane.terminalId && waiting.current.delete(pane.sessionId)) addTab(pane.terminalId);
        }
      }),
    [addTab],
  );

  // "Open in Files" from the Terminal's drawer, or a link.
  const [handled, setHandled] = useState(0);
  if (request && request.n !== handled) {
    setHandled(request.n);
    if (request.terminalId) addTab(request.terminalId, request.path);
  }

  function closeTab(key: string) {
    setTabs((prev) => prev.filter((t) => t.key !== key));
    if (activeTab === key) setActiveTab(MANY);
  }

  function openSession(session: SessionRecord) {
    const open = filePanes(panes).find((p) => p.sessionId === session.id);
    if (open?.terminalId) {
      addTab(open.terminalId);
      return;
    }
    waiting.current.add(session.id);
    onOpenTerminal(session.id);
    toast.info(`Opening '${session.name}' in a terminal…`, {
      description: "Its files show here once it connects; anything it asks shows in its terminal.",
    });
  }

  const onFolder = useCallback(
    (key: string, folder: string | null, asRoot: boolean) => {
      setFolders((prev) =>
        prev[key]?.folder === folder && prev[key]?.asRoot === asRoot ? prev : { ...prev, [key]: { folder, asRoot } },
      );
    },
    [setFolders],
  );

  // ---- Uploads and downloads ----------------------------------------------------------------------------------

  function nameOfTerminal(terminalId: string) {
    return paneOf(terminalId)?.title ?? "the host";
  }

  function handleUpload(terminalId: string, staged: StagedFiles, start: UploadStart, folder: string, asRoot: boolean) {
    if ((staged.leftOut ?? 0) > 0) {
      toast.info(`${plural(staged.leftOut ?? 0, "link")} in the folder left out: links and junctions aren't followed`);
    }
    if (start.status === "conflicts") {
      setConflict({
        kind: "upload",
        terminalId,
        staged,
        folder: start.folder || folder,
        existing: start.existing,
        asRoot,
        name: nameOfTerminal(terminalId),
      });
    } else if (start.status === "submitted") onSubmitted(start.outcome);
    else toast.info("Every file is in the folder already, so nothing was uploaded.");
  }

  async function uploadStaged(terminalId: string, staged: StagedFiles, folder: string, asRoot: boolean) {
    try {
      handleUpload(
        terminalId,
        staged,
        await api.filesUpload(terminalId, staged.id, folder, "ask", asRoot),
        folder,
        asRoot,
      );
    } catch (err) {
      void api.filesUnstage(staged.id).catch(() => undefined);
      toast.error(`Upload failed: ${errorMessage(err)}`);
    }
  }

  async function uploadLocal(terminalId: string, listing: string, names: string[], folder: string, asRoot: boolean) {
    try {
      const { staged, start } = await filesPageApi.localUpload(terminalId, listing, names, folder, asRoot);
      handleUpload(terminalId, staged, start, folder, asRoot);
    } catch (err) {
      toast.error(`Upload failed: ${errorMessage(err)}`);
    }
  }

  async function pickAndUpload(terminalId: string, folder: string, asRoot: boolean, pick: "files" | "folder") {
    try {
      const staged = pick === "folder" ? await api.filesPickUploadFolder() : await api.filesPickUpload();
      if (staged) await uploadStaged(terminalId, staged, folder, asRoot);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  function queued(start: DownloadStart) {
    if (start.status !== "queued") return;
    if (start.leftOut > 0) {
      toast.info(
        `${plural(start.leftOut, "item")} left out: Git's data, links to folders and what isn't a file stay on the host.`,
      );
    }
    if (start.transfers.length === 0) {
      toast.info(start.skipped > 0 ? "Every file is here already, so nothing was downloaded." : "Nothing to download.");
      return;
    }
    toast.info(
      `Downloading ${start.transfers.length === 1 ? start.transfers[0].name : plural(start.transfers.length, "file")}…`,
    );
  }

  async function download(terminalId: string, paths: string[], to: "here" | "downloads" | "choose", asRoot: boolean) {
    try {
      if (to === "here") {
        if (!local?.path) {
          toast.info("Open a folder of this PC on the left first.");
          return;
        }
        const start = await filesPageApi.downloadHere(terminalId, paths, local.id, "ask", asRoot);
        if (start.status === "conflicts") {
          setConflict({
            kind: "download",
            terminalId,
            paths,
            listing: local.id,
            choice: start.choice,
            folder: start.dest,
            existing: start.existing,
            asRoot,
            name: nameOfTerminal(terminalId),
          });
          return;
        }
        queued(start);
        return;
      }
      const start = await api.filesDownload(terminalId, paths, to, "ask", asRoot);
      if (!start) return;
      if (start.status === "conflicts") {
        setConflict({
          kind: "download",
          terminalId,
          paths,
          listing: null,
          choice: start.choice,
          folder: start.dest,
          existing: start.existing,
          asRoot,
          name: nameOfTerminal(terminalId),
        });
        return;
      }
      queued(start);
    } catch (err) {
      toast.error(`Download failed: ${errorMessage(err)}`);
    }
  }

  async function answer(next: Exclude<Existing, "ask">) {
    if (!conflict) return;
    if (conflict.kind === "upload") {
      const { terminalId, staged, folder, asRoot } = conflict;
      const start = await api.filesUpload(terminalId, staged.id, folder, next, asRoot);
      setConflict(null);
      handleUpload(terminalId, staged, start, folder, asRoot);
      return;
    }
    const { terminalId, paths, listing, choice, asRoot } = conflict;
    const start =
      listing !== null
        ? await filesPageApi.downloadHere(terminalId, paths, listing, next, asRoot, choice)
        : await api.filesDownload(terminalId, paths, "downloads", next, asRoot, choice);
    setConflict(null);
    if (start) queued(start);
  }

  async function retry(t: TransferInfo) {
    try {
      const retried = await api.filesRetry(t.id);
      if (retried.kind === "upload" && retried.start.status === "submitted") onSubmitted(retried.start.outcome);
    } catch (err) {
      toast.error(`Retry failed: ${errorMessage(err)}`);
    }
  }

  // ---- Drag and drop -------------------------------------------------------------------------------------------

  /** What is under a point: the host pane's tab (and the folder row there), or the local pane. */
  function targetAt(x: number, y: number) {
    const under = document.elementFromPoint(x, y);
    const pane = under?.closest<HTMLElement>("[data-files-drop]");
    if (!pane) return null;
    if (pane.dataset.filesDrop === "local") return { pane: "local" as const, listing: local?.path ? local.id : null };
    const tab = tabs.find((t) => t.key === pane.dataset.filesTab);
    const folder = tab ? folders[tab.key] : undefined;
    if (!tab || !folder?.folder) return null;
    const row = under?.closest<HTMLElement>("[data-files-folder]");
    return {
      pane: "host" as const,
      terminalId: tab.terminalId,
      folder: folder.folder,
      asRoot: folder.asRoot,
      intoFolder: row?.dataset.filesFolder,
    };
  }

  const dropRef = useRef<(x: number, y: number) => void>(() => undefined);
  useEffect(() => {
    dropRef.current = (x, y) => {
      if (!drag) return;
      const target = targetAt(x, y);
      if (!target) return;
      const action = dropAction(drag.items, target);
      if (!action) return;
      const items = drag.items;
      if (action.kind === "upload" && items.from === "local" && target.pane === "host") {
        void uploadLocal(target.terminalId, items.listing, items.names, action.folder, target.asRoot);
      } else if (action.kind === "download" && items.from === "host") {
        void download(items.terminalId, items.paths, "here", items.asRoot);
      } else if (action.kind === "move" && items.from === "host") {
        api.filesChange(items.terminalId, { kind: "move", paths: items.paths, into: action.into }, items.asRoot).then(
          (outcome) => onSubmitted(outcome),
          (err) => toast.error(errorMessage(err)),
        );
      }
    };
  });

  useEffect(() => {
    if (!drag) return;
    const move = (e: PointerEvent) => setDrag((d) => (d ? { ...d, x: e.clientX, y: e.clientY } : d));
    const up = (e: PointerEvent) => {
      dropRef.current(e.clientX, e.clientY);
      setDrag(null);
    };
    const key = (e: KeyboardEvent) => e.key === "Escape" && setDrag(null);
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up, { once: true });
    window.addEventListener("keydown", key);
    return () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("keydown", key);
    };
    // Only a drag starting or ending adds or takes the listeners away.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drag !== null]);

  const startDrag = useCallback(
    (items: DragItems, event: React.PointerEvent) => {
      setDrag({ items, x: event.clientX, y: event.clientY });
    },
    [setDrag],
  );

  // Files from Explorer: staged by the shell, uploaded into the host pane they fell on.
  const osDropRef = useRef<
    (dropped: { staged: StagedFiles | null; error: string | null; x: number; y: number }) => void
  >(() => undefined);
  useEffect(() => {
    osDropRef.current = (dropped) => {
      if (!active) return;
      if (dropped.error) {
        toast.error(`Not uploaded: ${dropped.error}`);
        return;
      }
      if (!dropped.staged) return;
      const target = targetAt(dropped.x, dropped.y);
      if (!target || target.pane !== "host") {
        void api.filesUnstage(dropped.staged.id).catch(() => undefined);
        toast.info("Drop files on the host's side to upload them; nothing on this PC is changed here.");
        return;
      }
      void uploadStaged(target.terminalId, dropped.staged, target.intoFolder ?? target.folder, target.asRoot);
    };
  });
  useEffect(() => {
    const unlisten = api.onFilesDropped((dropped) => osDropRef.current(dropped));
    return () => void unlisten.then((stop) => stop());
  }, []);

  // ---- Page --------------------------------------------------------------------------------------------------

  const openable = useMemo(
    () => filePanes(panes).filter((p) => !tabs.some((t) => t.terminalId === p.terminalId)),
    [panes, tabs],
  );
  const readOnly = readOnlyLocked(presentation);
  const localUploadReason = !current
    ? "Open a host tab first: files upload into its folder"
    : (uploadReason({ open: true, connected, readOnly }) ??
      (currentFolder?.folder ? null : "The host's folder couldn't be opened"));

  const openMenu = (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button>
          <PlusIcon data-icon="inline-start" />
          Open a host
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="max-h-96 min-w-64 overflow-y-auto">
        <DropdownMenuLabel>Open terminals</DropdownMenuLabel>
        {openable.length === 0 && <p className="px-2 py-1 text-xs text-muted-foreground">None not shown here.</p>}
        {openable.map((p) => (
          <DropdownMenuItem key={p.key} onSelect={() => p.terminalId && addTab(p.terminalId)}>
            <ServerIcon />
            {p.title}
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuLabel>Saved sessions</DropdownMenuLabel>
        {sessions.length === 0 && <p className="px-2 py-1 text-xs text-muted-foreground">No SSH sessions saved.</p>}
        {sessions.map((s) => (
          <DropdownMenuItem key={s.id} onSelect={() => openSession(s)}>
            <FolderTreeIcon />
            {s.name}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );

  return (
    <Tabs value={activeTab} onValueChange={setActiveTab} className="flex h-full min-h-0 flex-col gap-3">
      <PageHeader
        page="files"
        primary={openMenu}
        tabs={
          <TabsList className="flex-wrap">
            {tabs.map((t) => (
              <TabsTrigger key={t.key} value={t.key} className="group">
                <ServerIcon />
                <span className="max-w-48 truncate">{paneOf(t.terminalId)?.title ?? "Closed terminal"}</span>
                <span
                  role="button"
                  tabIndex={0}
                  aria-label={`Close the tab of ${paneOf(t.terminalId)?.title ?? "a closed terminal"}`}
                  className="ml-1 rounded p-0.5 opacity-60 hover:bg-accent hover:opacity-100"
                  onPointerDown={(e) => e.stopPropagation()}
                  onClick={(e) => {
                    e.stopPropagation();
                    closeTab(t.key);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      closeTab(t.key);
                    }
                  }}
                >
                  <XIcon className="size-3" />
                </span>
              </TabsTrigger>
            ))}
            <TabsTrigger value={MANY}>
              <UsersIcon />
              Many hosts
            </TabsTrigger>
          </TabsList>
        }
      />
      <Tip id="files.panes">
        Drag picked files from one side to the other to upload or download them, or drop files from Explorer on the
        host's side.
      </Tip>
      <div className="flex min-h-0 flex-1 gap-3">
        <LocalPane
          hostFolder={currentFolder?.folder ?? null}
          hostName={currentPane?.title ?? null}
          uploadReason={localUploadReason}
          onUpload={(listing, names) => {
            if (current && currentFolder?.folder)
              void uploadLocal(current.terminalId, listing, names, currentFolder.folder, currentFolder.asRoot);
          }}
          onListing={setLocal}
          onPicked={setLocalPicked}
          onDragStart={startDrag}
          refresh={downloads}
        />
        <div className="flex min-h-0 min-w-0 flex-1 flex-col">
          {tabs.map((t) => (
            <div key={t.key} className={t.key === activeTab ? "flex min-h-0 flex-1 flex-col" : "hidden"}>
              <HostPane
                tab={t}
                local={local}
                onDownload={(paths, to, asRoot) => void download(t.terminalId, paths, to, asRoot)}
                onUpload={(folder, asRoot, pick) => void pickAndUpload(t.terminalId, folder, asRoot, pick)}
                onSubmitted={(outcome, onJob) => onSubmitted(outcome, onJob)}
                onDownloads={(start) => queued(start)}
                onFolder={onFolder}
                onDragStart={startDrag}
                onShowTerminal={onShowTerminal}
                onCloseTab={closeTab}
              />
            </div>
          ))}
          {activeTab === MANY && (
            <ManyHostsView
              active={active && activeTab === MANY}
              local={local}
              localPicked={localPicked}
              onSubmitted={(outcome, onJob) => onSubmitted(outcome, onJob)}
              onOpenSessions={onOpenSessions}
            />
          )}
          {tabs.length === 0 && activeTab !== MANY && (
            <EmptyState
              icon={ServerIcon}
              title="No host open"
              description="Open a host: a terminal open now, or a saved session."
              help="page.files"
            />
          )}
        </div>
      </div>
      <div className="flex max-h-[30%] min-h-0 shrink-0 flex-col overflow-hidden">
        <TransfersList onRetry={(t) => void retry(t)} />
      </div>
      {conflict && (
        <UploadConflictDialog
          direction={conflict.kind}
          folder={conflict.folder}
          existing={conflict.existing}
          total={
            conflict.kind === "upload" ? (conflict.staged.count ?? conflict.staged.files.length) : conflict.paths.length
          }
          terminal={conflict.name}
          onAnswer={answer}
          onCancel={() => {
            if (conflict.kind === "upload") void api.filesUnstage(conflict.staged.id).catch(() => undefined);
            setConflict(null);
          }}
        />
      )}
      {drag && (
        <div
          className="pointer-events-none fixed z-50 rounded-md border bg-popover px-2 py-1 text-xs shadow-md"
          style={{ left: drag.x + 12, top: drag.y + 12 }}
          aria-hidden
        >
          {drag.items.from === "local"
            ? `Upload ${plural(drag.items.names.length, "item")}`
            : `${plural(drag.items.paths.length, "item")}: drop on this PC to download, or on a folder to move`}
        </div>
      )}
    </Tabs>
  );
}
