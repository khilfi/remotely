// SS-14 (0.8.0 G3): the Files page's right pane, one host tab. It rides on an open SSH terminal's connection, as the
// Terminal's "Files here" drawer does, and reuses G2's work as it is: every change is a FileChange the core turns into
// a command on the bus at its tier, transfers go through the terminal's queue, "Browse as root" runs the host's
// sftp-server under sudo (the header says "as root", and every change asks one tier more), and a file that is there
// is asked about. Reads (listing, find, preview, checksums) need no approval. Bookmarks are per session.

import {
  Fragment,
  useCallback,
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  ArrowLeftIcon,
  ArrowRightIcon,
  ArrowUpIcon,
  BookmarkIcon,
  BookmarkPlusIcon,
  CopyIcon,
  DownloadIcon,
  FileSearchIcon,
  FilePlusIcon,
  FileTextIcon,
  FingerprintIcon,
  FolderInputIcon,
  FolderOpenIcon,
  FolderPlusIcon,
  FolderUpIcon,
  GitCompareIcon,
  HouseIcon,
  KeyRoundIcon,
  MoreHorizontalIcon,
  PencilIcon,
  SearchIcon,
  ServerIcon,
  ShieldIcon,
  ShieldOffIcon,
  SquareTerminalIcon,
  Trash2Icon,
  UploadIcon,
  UserRoundCogIcon,
} from "lucide-react";
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { FileChangeDialog, type FileAsk } from "@/components/FileChangeDialog";
import { HelpTip } from "@/components/HelpTip";
import { usePresentation } from "@/components/Presentation";
import { RefreshButton } from "@/components/RefreshButton";
import { SelectionBar } from "@/components/SelectionBar";
import { SudoPasswordDialog } from "@/components/SudoPasswordDialog";
import { WhyDisabled } from "@/components/WhyDisabled";
import { ChecksumDialog, type ChecksumShown } from "@/components/files/ChecksumDialog";
import { CompareSheet } from "@/components/files/CompareSheet";
import { FileTable } from "@/components/files/FileTable";
import { FindSheet } from "@/components/files/FindSheet";
import { PaneButton } from "@/components/files/PaneButton";
import { PreviewDialog, type PreviewShown } from "@/components/files/PreviewDialog";
import { NameDialog } from "@/components/files/NameDialog";
import { useUploadsDone } from "@/hooks/use-transfers";
import {
  api,
  errorMessage,
  type DownloadStart,
  type FileChange,
  type FolderListing,
  type RemoteEntry,
  type SubmitOutcome,
} from "@/lib/api";
import { downloadReason, fileChangeReason, uploadReason } from "@/lib/disabled-reasons";
import { changeLabel } from "@/lib/file-ops";
import {
  canGo,
  DEFAULT_VIEW,
  emptyHistory,
  go,
  viewEntries,
  visit,
  type DragItems,
  type History,
  type PaneView,
} from "@/lib/files-page";
import { filesPageApi, type Bookmark, type LocalListing } from "@/lib/files-page-api";
import { plural } from "@/lib/format";
import { paneOf, subscribePanes, openPanes } from "@/lib/open-panes";
import { readOnlyLocked } from "@/lib/presentation-state";
import { isReauthCancelled } from "@/lib/reauth";
import { withVaultPassword } from "@/lib/reauth-prompt";
import type { PaneSnapshot } from "@/lib/terminal-session";
import { crumbs, joinPath } from "@/lib/transfers";
import { cn } from "@/lib/utils";

export interface HostTab {
  key: string;
  terminalId: string;
  /** A folder to open, asked from outside (the Terminal's "Open in Files"), with a counter so the same one opens again. */
  pathRequest?: { path: string; n: number };
}

interface Props {
  tab: HostTab;
  /** The local pane's listing, for "Download here" and Compare. */
  local: LocalListing | null;
  onDownload: (paths: string[], to: "here" | "downloads" | "choose", asRoot: boolean) => void;
  onUpload: (folder: string, asRoot: boolean, pick: "files" | "folder") => void;
  onSubmitted: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onDownloads: (start: DownloadStart, asRoot: boolean) => void;
  /** The folder shown and whether it is root's, for uploads from the local pane and drops. */
  onFolder: (key: string, folder: string | null, asRoot: boolean) => void;
  onDragStart: (items: DragItems, at: { clientX: number; clientY: number }) => void;
  onDragEnd: (x: number, y: number) => void;
  onShowTerminal: (terminalId: string) => void;
  onCloseTab: (key: string) => void;
}

const NO_SNAPSHOT = { status: { state: "closed" } };

/** A rename or move that would replace a file: asked before it goes again with `replace`. */
interface ReplaceAsk {
  change: Extract<FileChange, { kind: "rename" } | { kind: "move" }>;
  message: string;
}

export function HostPane({
  tab,
  local,
  onDownload,
  onUpload,
  onSubmitted,
  onDownloads,
  onFolder,
  onDragStart,
  onDragEnd,
  onShowTerminal,
  onCloseTab,
}: Props) {
  const terminalId = tab.terminalId;
  const presentation = usePresentation();
  const readOnly = readOnlyLocked(presentation);
  // The pane this tab rides on: its status, its folder's user, its name (read again when the Terminal page's panes change).
  useSyncExternalStore(subscribePanes, openPanes);
  const pane = paneOf(terminalId);
  const subscribe = useCallback((listener: () => void) => pane?.subscribe(listener) ?? (() => undefined), [pane]);
  const snapshot = useSyncExternalStore(subscribe, () => pane?.getSnapshot() ?? NO_SNAPSHOT) as PaneSnapshot;
  const connected = pane !== undefined && snapshot.status.state === "connected";
  const name = pane?.title ?? "Closed terminal";
  const sessionId = pane?.sessionId ?? null;

  const refresh = useUploadsDone(terminalId);
  const [asRoot, setAsRoot] = useState(false);
  const [path, setPath] = useState<string | null>(tab.pathRequest?.path ?? null);
  const [tick, setTick] = useState(0);
  const [listing, setListing] = useState<FolderListing | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** The listing asked for, and the last one answered. */
  const want = `${path ?? ""}|${asRoot}|${tick}|${refresh}`;
  const [answered, setAnswered] = useState<string | null>(null);
  const loading = connected && answered !== want;
  const [history, setHistory] = useState<History<string>>(emptyHistory());
  const [view, setView] = useState<PaneView>(DEFAULT_VIEW);
  const [picked, setPicked] = useState<{ names: string[]; anchor: string | null }>({ names: [], anchor: null });
  const [typed, setTyped] = useState<string | null>(null);
  const [ask, setAsk] = useState<FileAsk | null>(null);
  const [replaceAsk, setReplaceAsk] = useState<ReplaceAsk | null>(null);
  const [askSudo, setAskSudo] = useState(false);
  const [preview, setPreview] = useState<PreviewShown | null>(null);
  const [checksum, setChecksum] = useState<ChecksumShown | null>(null);
  const [finding, setFinding] = useState(false);
  const [comparing, setComparing] = useState(false);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  const [naming, setNaming] = useState<{ bookmark: Bookmark | null; path: string } | null>(null);
  const watched = useRef(new Set<string>());
  /** Back and Forward set the path without a new step. */
  const stepping = useRef(false);

  // Root browsing may be on already (started in the Terminal's drawer).
  useEffect(() => {
    if (!connected) return;
    api.filesRootStatus(terminalId).then(
      (status) => setAsRoot(status !== null),
      () => undefined,
    );
  }, [terminalId, connected]);

  // A folder asked from outside opens, once per request.
  const [handledRequest, setHandledRequest] = useState(tab.pathRequest?.n ?? 0);
  if (tab.pathRequest && tab.pathRequest.n !== handledRequest) {
    setHandledRequest(tab.pathRequest.n);
    setPath(tab.pathRequest.path);
  }

  useEffect(() => {
    const unlisten = api.onJobEvent((event) => {
      if (event.event === "finished" && watched.current.delete(event.jobId)) setTick((n) => n + 1);
    });
    return () => void unlisten.then((stop) => stop());
  }, []);

  useEffect(() => {
    if (!connected) return;
    let gone = false;
    api.filesList(terminalId, path, null, asRoot).then(
      (next) => {
        if (gone) return;
        setAnswered(want);
        setListing(next);
        setError(null);
        if (!stepping.current && !next.error) setHistory((h) => visit(h, next.path, (a, b) => a === b));
        stepping.current = false;
      },
      (err) => {
        if (gone) return;
        setAnswered(want);
        if (asRoot && errorMessage(err).includes("not browsing as root")) {
          setAsRoot(false);
          toast.info("Root browsing ended; the folder shows what the login user can open");
          return;
        }
        setError(errorMessage(err));
      },
    );
    return () => {
      gone = true;
    };
  }, [terminalId, path, asRoot, want, connected]);

  useEffect(() => {
    onFolder(tab.key, listing && !listing.error ? listing.path : null, asRoot);
  }, [tab.key, listing, asRoot, onFolder]);

  const [bookmarksRead, setBookmarksRead] = useState(0);
  const loadBookmarks = useCallback(() => setBookmarksRead((n) => n + 1), []);
  useEffect(() => {
    if (!sessionId) return;
    let gone = false;
    filesPageApi.bookmarks(sessionId).then(
      (list) => !gone && setBookmarks(list),
      () => !gone && setBookmarks([]),
    );
    return () => {
      gone = true;
    };
  }, [sessionId, bookmarksRead]);

  const here = listing?.path ?? "/";
  const failed = listing?.error ?? null;
  const entries = listing ? viewEntries(listing.entries, view) : [];
  const picks = picked.names.filter((n) => entries.some((e) => e.name === n));
  const pickedEntries = entries.filter((e) => picks.includes(e.name));
  const paths = (list: RemoteEntry[]) => list.map((e) => joinPath(here, e.name));
  const changes = fileChangeReason({ connected, readOnly, folderOpen: listing !== null && !failed });
  const upload =
    uploadReason({ open: true, connected, readOnly }) ??
    (!listing ? "Open a folder first" : failed ? "This folder couldn't be opened" : null);
  const download = downloadReason({ connected, picked: pickedEntries });
  const downloadHere = local?.path ? null : "Open a folder of this PC on the left first";

  function open(next: string) {
    setPath(next);
    setTyped(null);
    setPicked({ names: [], anchor: null });
  }

  function step(dir: -1 | 1) {
    const moved = go(history, dir);
    if (!moved) return;
    stepping.current = true;
    setHistory(moved.history);
    open(moved.item);
  }

  function submit(ev: FormEvent) {
    ev.preventDefault();
    const text = (typed ?? here).trim();
    if (text) open(text.startsWith("/") || text.startsWith("~") ? text : joinPath(here, text));
  }

  async function change(next: FileChange) {
    try {
      const outcome = await api.filesChange(terminalId, next, asRoot);
      setAsk(null);
      setPicked({ names: [], anchor: null });
      onSubmitted(outcome, (jobId) => watched.current.add(jobId));
      if (outcome.status === "queued") {
        toast.success(changeLabel(next));
        window.setTimeout(() => setTick((n) => n + 1), 1500);
      }
    } catch (err) {
      const code = err && typeof err === "object" && "code" in err ? String(err.code) : "";
      if (code === "path_taken" && (next.kind === "rename" || next.kind === "move")) {
        setAsk(null);
        setReplaceAsk({ change: next, message: errorMessage(err) });
        return;
      }
      throw err;
    }
  }

  function run(next: FileChange) {
    change(next).catch((err) => toast.error(errorMessage(err)));
  }

  async function startRoot(retry = false, sudoPasswordId: string | null = null) {
    try {
      const started = await withVaultPassword((vaultPassword) =>
        api.filesRootStart(terminalId, { vaultPassword, retry, sudoPasswordId }),
      );
      setAsRoot(true);
      setPicked({ names: [], anchor: null });
      toast.success(started.withPassword ? "Browsing as root" : "Browsing as root (sudo asked for no password)");
    } catch (err) {
      if (isReauthCancelled(err)) return;
      const code = err && typeof err === "object" && "code" in err ? String(err.code) : "";
      if (code === "login_parked") {
        toast.error(errorMessage(err), {
          action: { label: "Try again", onClick: () => void startRoot(true, sudoPasswordId) },
        });
      } else if (code === "no_sudo_password") {
        setAskSudo(true);
      } else {
        toast.error(`Can't browse as root: ${errorMessage(err)}`);
      }
    }
  }

  async function stopRoot() {
    setAsRoot(false);
    setPicked({ names: [], anchor: null });
    try {
      await api.filesRootStop(terminalId);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function showPreview(path: string, label: string) {
    setPreview({ name: label, preview: null });
    try {
      setPreview({ name: label, preview: await filesPageApi.preview(terminalId, path, asRoot) });
    } catch (err) {
      setPreview({ name: label, preview: null, error: errorMessage(err) });
    }
  }

  async function showChecksum(path: string, label: string) {
    setChecksum({ name: label, sha256: null });
    try {
      const sum = await filesPageApi.checksum(terminalId, path, asRoot);
      setChecksum({
        name: label,
        sha256: sum.sha256,
        size: sum.size,
        by: sum.by === "host" ? "worked out on the host" : "read over SFTP and worked out on this PC",
      });
    } catch (err) {
      setChecksum({ name: label, sha256: null, error: errorMessage(err) });
    }
  }

  async function saveBookmark(name: string) {
    if (!naming || !sessionId) return;
    if (naming.bookmark) await filesPageApi.renameBookmark(naming.bookmark.id, name);
    else await filesPageApi.addBookmark(sessionId, name, naming.path);
    setNaming(null);
    loadBookmarks();
  }

  async function removeBookmark(bookmark: Bookmark) {
    try {
      await filesPageApi.removeBookmark(bookmark.id);
      loadBookmarks();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  /** A row's actions, or the picked rows' (the selection bar's). */
  function actions(
    list: RemoteEntry[],
    item: (key: string, label: string, icon: ReactNode, run: () => void) => ReactNode,
  ) {
    const p = paths(list);
    const one = list.length === 1 ? list[0] : null;
    const transferable = list.every((e) => e.kind !== "other");
    return [
      one?.kind === "folder" && item("open", "Open", <FolderOpenIcon />, () => open(p[0])),
      transferable &&
        item("downloadHere", "Download to this PC's folder", <DownloadIcon />, () => onDownload(p, "here", asRoot)),
      transferable && item("downloadTo", "Download to…", <FolderInputIcon />, () => onDownload(p, "choose", asRoot)),
      one?.kind === "file" && item("preview", "Preview", <FileTextIcon />, () => void showPreview(p[0], one.name)),
      one?.kind === "file" &&
        item("checksum", "SHA-256 checksum", <FingerprintIcon />, () => void showChecksum(p[0], one.name)),
      one && item("rename", "Rename…", <PencilIcon />, () => setAsk({ kind: "rename", path: p[0] })),
      item("move", "Move to…", <FolderUpIcon />, () => setAsk({ kind: "move", paths: p, folder: here })),
      item("copy", "Copy to…", <CopyIcon />, () => setAsk({ kind: "copy", paths: p, folder: here })),
      list.every((e) => !e.link) &&
        item("mode", "Permissions…", <KeyRoundIcon />, () =>
          setAsk({ kind: "mode", paths: p, mode: one?.mode ?? null }),
        ),
      list.every((e) => !e.link) &&
        item("owner", "Owner…", <UserRoundCogIcon />, () =>
          setAsk({ kind: "owner", paths: p, uid: one?.uid ?? null, gid: one?.gid ?? null }),
        ),
      item("delete", list.length === 1 ? "Delete" : `Delete ${list.length}`, <Trash2Icon />, () =>
        run({ kind: "delete", paths: p }),
      ),
    ];
  }

  const reads = ["open", "downloadHere", "downloadTo", "preview", "checksum"];
  const menuItem = (key: string, label: string, icon: ReactNode, onSelect: () => void) => {
    const why = reads.includes(key) ? (key === "downloadHere" ? downloadHere : null) : changes;
    return (
      <Fragment key={key}>
        {key === "delete" && <DropdownMenuSeparator />}
        <DropdownMenuItem
          variant={key === "delete" ? "destructive" : "default"}
          disabled={why !== null}
          onSelect={onSelect}
        >
          {icon}
          {label}
        </DropdownMenuItem>
      </Fragment>
    );
  };
  const barButton = (key: string, label: string, icon: ReactNode, onSelect: () => void) => {
    if (!["downloadHere", "move", "copy", "delete"].includes(key)) return null;
    const why = reads.includes(key) ? (download ?? downloadHere) : changes;
    return (
      <WhyDisabled key={key} reason={why}>
        <Button variant="ghost" size="sm" disabled={why !== null} onClick={onSelect}>
          {icon}
          {key === "downloadHere" ? "Download here" : label}
        </Button>
      </WhyDisabled>
    );
  };

  if (!pane) {
    return (
      <section className="flex min-h-0 min-w-0 flex-1 flex-col items-center justify-center gap-2 rounded-lg border p-4 text-center">
        <p className="text-sm">This tab's terminal has closed.</p>
        <Button variant="outline" size="sm" onClick={() => onCloseTab(tab.key)}>
          Close the tab
        </Button>
      </section>
    );
  }

  const user = snapshot.folder?.user?.username;

  return (
    <section
      aria-label={`Files on ${name}`}
      data-files-drop="host"
      data-files-tab={tab.key}
      className="@container flex min-h-0 min-w-0 flex-1 flex-col gap-2 rounded-lg border p-2"
    >
      <div className="flex items-center gap-1.5">
        <ServerIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
        <h2 className="truncate text-sm font-medium" title={name}>
          {name}
        </h2>
        {asRoot && (
          <Badge variant="outline" className="shrink-0 border-tier-high/50 font-normal text-tier-high">
            as root
          </Badge>
        )}
        {user && !asRoot && (
          <span className="truncate text-xs text-muted-foreground">
            as <span data-mask="user">{user}</span>
          </span>
        )}
        <div className="ml-auto flex items-center gap-1">
          <Label htmlFor={`files-host-hidden-${tab.key}`} className="text-xs font-normal text-muted-foreground">
            Hidden files
          </Label>
          <Switch
            id={`files-host-hidden-${tab.key}`}
            checked={view.hidden}
            onCheckedChange={(hidden) => setView((v) => ({ ...v, hidden }))}
          />
          <PaneButton label="Show its terminal" onClick={() => onShowTerminal(terminalId)}>
            <SquareTerminalIcon />
          </PaneButton>
          <DropdownMenu>
            <Tooltip>
              <TooltipTrigger asChild>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon-sm" aria-label="More file actions">
                    <MoreHorizontalIcon />
                  </Button>
                </DropdownMenuTrigger>
              </TooltipTrigger>
              <TooltipContent>More file actions</TooltipContent>
            </Tooltip>
            <DropdownMenuContent align="end" className="min-w-56">
              <DropdownMenuItem
                disabled={changes !== null}
                onSelect={() => setAsk({ kind: "newFolder", folder: here })}
              >
                <FolderPlusIcon />
                New folder…
              </DropdownMenuItem>
              <DropdownMenuItem disabled={changes !== null} onSelect={() => setAsk({ kind: "newFile", folder: here })}>
                <FilePlusIcon />
                New empty file…
              </DropdownMenuItem>
              <DropdownMenuItem disabled={upload !== null} onSelect={() => onUpload(here, asRoot, "files")}>
                <UploadIcon />
                Upload files here…
              </DropdownMenuItem>
              <DropdownMenuItem disabled={upload !== null} onSelect={() => onUpload(here, asRoot, "folder")}>
                <FolderUpIcon />
                Upload a folder here…
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem disabled={!connected || !listing || failed !== null} onSelect={() => setFinding(true)}>
                <FileSearchIcon />
                Find files…
              </DropdownMenuItem>
              <DropdownMenuItem
                disabled={!connected || !listing || failed !== null || !local?.path}
                onSelect={() => setComparing(true)}
              >
                <GitCompareIcon />
                Compare with this PC's folder…
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              {asRoot ? (
                <DropdownMenuItem onSelect={() => void stopRoot()}>
                  <ShieldOffIcon />
                  Stop browsing as root
                </DropdownMenuItem>
              ) : (
                <DropdownMenuItem disabled={readOnly || !connected} onSelect={() => void startRoot()}>
                  <ShieldIcon />
                  Browse as root…
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
      {!connected ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-2 text-center text-sm text-muted-foreground">
          <p>
            {snapshot.status.state === "connecting" || snapshot.status.state === "opening"
              ? "Connecting… If the host asks for anything, answer in its terminal."
              : "This terminal is not connected, so its files can't be reached."}
          </p>
          <Button variant="outline" size="sm" onClick={() => onShowTerminal(terminalId)}>
            Show the terminal
          </Button>
        </div>
      ) : (
        <>
          {asRoot && (
            <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <ShieldIcon className="size-3.5 shrink-0 text-tier-high" aria-hidden />
              Changes here run as <span className="font-medium text-tier-high">root</span>, one approval tier higher.
              <HelpTip topic="filesRoot" />
            </p>
          )}
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
              disabledReason={listing?.parent ? null : "This is the top folder"}
              onClick={() => listing?.parent && open(listing.parent)}
            >
              <ArrowUpIcon />
            </PaneButton>
            <PaneButton label="Home folder" onClick={() => open("~")}>
              <HouseIcon />
            </PaneButton>
            <DropdownMenu>
              <Tooltip>
                <TooltipTrigger asChild>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon-sm" aria-label="Bookmarks">
                      <BookmarkIcon />
                    </Button>
                  </DropdownMenuTrigger>
                </TooltipTrigger>
                <TooltipContent>Bookmarks</TooltipContent>
              </Tooltip>
              <DropdownMenuContent align="start" className="min-w-56">
                <DropdownMenuLabel>Bookmarks of this session</DropdownMenuLabel>
                {!sessionId && (
                  <p className="px-2 py-1 text-xs text-muted-foreground">
                    A quick connection has none: save it as a session to keep bookmarks.
                  </p>
                )}
                {sessionId && bookmarks.length === 0 && (
                  <p className="px-2 py-1 text-xs text-muted-foreground">None yet.</p>
                )}
                {bookmarks.map((b) => (
                  <DropdownMenuSub key={b.id}>
                    <DropdownMenuSubTrigger>
                      <span className="truncate">{b.name}</span>
                      <span className="ml-2 truncate font-mono text-xs text-muted-foreground">{b.path}</span>
                    </DropdownMenuSubTrigger>
                    <DropdownMenuSubContent>
                      <DropdownMenuItem onSelect={() => open(b.path)}>
                        <FolderOpenIcon />
                        Open
                      </DropdownMenuItem>
                      <DropdownMenuItem disabled={readOnly} onSelect={() => setNaming({ bookmark: b, path: b.path })}>
                        <PencilIcon />
                        Rename…
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        variant="destructive"
                        disabled={readOnly}
                        onSelect={() => void removeBookmark(b)}
                      >
                        <Trash2Icon />
                        Remove
                      </DropdownMenuItem>
                    </DropdownMenuSubContent>
                  </DropdownMenuSub>
                ))}
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  disabled={!sessionId || readOnly || !listing || failed !== null}
                  onSelect={() => setNaming({ bookmark: null, path: here })}
                >
                  <BookmarkPlusIcon />
                  Bookmark this folder…
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <form className="min-w-0 flex-1" onSubmit={submit}>
              <Input
                aria-label="Folder on the host"
                aria-invalid={failed ? true : undefined}
                className="h-7 font-mono text-xs"
                value={typed ?? here}
                onChange={(e) => setTyped(e.target.value)}
                placeholder="Type a folder and press Enter"
                spellCheck={false}
              />
            </form>
            <PaneButton
              label="Find files"
              disabledReason={listing && !failed ? null : "Open a folder first"}
              onClick={() => setFinding(true)}
            >
              <SearchIcon />
            </PaneButton>
            <RefreshButton busy={loading} onClick={() => setTick((n) => n + 1)} />
          </div>
          {listing && (
            <nav aria-label="Folder path on the host" className="flex flex-wrap items-center gap-0.5 text-xs">
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
          <Input
            aria-label="Filter the host's folder"
            className="h-7 text-xs"
            placeholder="Filter: words or a pattern such as *.log"
            value={view.filter}
            onChange={(e) => setView((v) => ({ ...v, filter: e.target.value }))}
          />
          {error && <p className="text-xs text-destructive">{error}</p>}
          {picks.length > 0 && (
            <SelectionBar
              count={picks.length}
              onClear={() => setPicked({ names: [], anchor: null })}
              className="flex-none"
            >
              {actions(pickedEntries, barButton)}
            </SelectionBar>
          )}
          {failed ? (
            <div
              role="alert"
              className="flex min-h-28 flex-1 flex-col gap-1.5 rounded-md border border-destructive/40 p-2 text-xs"
            >
              <p className="text-destructive">{failed.message}</p>
              <p className="text-muted-foreground">
                {failed.code === "permission_denied" && !asRoot && "Browse as root (the ⋯ above) to open it as root. "}
                Go Back, Up or Home, pick a bookmark, or type another folder.
              </p>
            </div>
          ) : (
            <FileTable
              label={name}
              entries={entries}
              view={view}
              onView={setView}
              picked={picks}
              anchor={picked.anchor}
              onPick={(names, anchor) => setPicked({ names, anchor })}
              onOpen={(e) => {
                if (e.kind === "folder") open(joinPath(here, e.name));
                else if (e.kind === "file") void showPreview(joinPath(here, e.name), e.name);
              }}
              folderPath={(e) => (e.kind === "folder" ? joinPath(here, e.name) : null)}
              rowTitle={(e) =>
                e.kind === "folder"
                  ? "Double-click to open; drop files on it to upload or move them into it"
                  : e.kind === "file"
                    ? "Double-click to preview; drag to this PC to download"
                    : "Not a regular file"
              }
              onDragStart={(names, ev) =>
                onDragStart(
                  { from: "host", terminalId, folder: here, paths: names.map((n) => joinPath(here, n)), asRoot },
                  ev,
                )
              }
              onDragEnd={onDragEnd}
              empty="This folder is empty."
              loading={loading}
              menu={(e) => actions([e], menuItem)}
            />
          )}
          {listing?.more && (
            <p className="text-xs text-muted-foreground">More is in this folder than is listed here.</p>
          )}
          {picks.length > 0 && (
            <p className={cn("text-xs text-muted-foreground")}>
              {plural(picks.length, "item")} picked: drag them to this PC to download.
            </p>
          )}
        </>
      )}
      {ask && <FileChangeDialog ask={ask} asRoot={asRoot} onSubmit={change} onClose={() => setAsk(null)} />}
      {askSudo && (
        <SudoPasswordDialog
          terminal={name}
          onCancel={() => setAskSudo(false)}
          onPick={(id) => {
            setAskSudo(false);
            void startRoot(false, id);
          }}
        />
      )}
      {replaceAsk && (
        <AlertDialog open onOpenChange={(o) => !o && setReplaceAsk(null)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Replace what is there?</AlertDialogTitle>
              <AlertDialogDescription>
                {replaceAsk.message}. Replacing loses what is there, so it asks for your approval next.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction
                onClick={() => {
                  const again = { ...replaceAsk.change, replace: true };
                  setReplaceAsk(null);
                  run(again);
                }}
              >
                Replace…
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      )}
      {preview && (
        <PreviewDialog
          shown={preview}
          onClose={() => setPreview(null)}
          onDownload={() => {
            const p = preview.preview?.path;
            setPreview(null);
            if (p) onDownload([p], local?.path ? "here" : "downloads", asRoot);
          }}
        />
      )}
      {checksum && <ChecksumDialog shown={checksum} onClose={() => setChecksum(null)} />}
      {finding && listing && (
        <FindSheet
          terminalId={terminalId}
          folder={here}
          asRoot={asRoot}
          onOpenFolder={(folder) => {
            setFinding(false);
            open(folder);
          }}
          onPreview={(hit) => void showPreview(hit.path, hit.shown)}
          onChecksum={(hit) => void showChecksum(hit.path, hit.shown)}
          onClose={() => setFinding(false)}
        />
      )}
      {comparing && local?.path && listing && (
        <CompareSheet
          terminalId={terminalId}
          hostName={name}
          hostFolder={here}
          asRoot={asRoot}
          listing={local.id}
          localFolder={local.path}
          onSubmitted={(outcome, onJob) =>
            onSubmitted(outcome, (jobId) => {
              watched.current.add(jobId);
              onJob(jobId);
            })
          }
          onDownloads={(start) => onDownloads(start, asRoot)}
          onClose={() => setComparing(false)}
        />
      )}
      {naming && (
        <NameDialog
          title={naming.bookmark ? "Rename the bookmark" : "Bookmark this folder"}
          description={naming.path}
          label="Name"
          initial={naming.bookmark?.name ?? (naming.path.split("/").filter(Boolean).pop() || "/")}
          submit={naming.bookmark ? "Rename" : "Bookmark"}
          onSubmit={saveBookmark}
          onClose={() => setNaming(null)}
        />
      )}
    </section>
  );
}
