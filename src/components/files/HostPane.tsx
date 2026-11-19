// SS-14 (0.8.0 G3), UX-14 (0.9.0 H1): one host's files, on an open SSH terminal's connection: the Files page's host tab,
// and in compact mode the Terminal's "Files here" drawer. Both are this one component, so a file has the same row menu,
// the same double-click (Settings › Terminal › Files) and the same editing, find, preview, checksums and bookmarks in
// either place.
//
// It reuses G2's work as it is: every change is a FileChange the core turns into a command on the bus at its tier,
// transfers go through the terminal's queue, "Browse as root" runs the host's sftp-server under sudo (the header says
// "as root", and every change asks one tier more; a session that saves no password for sudo picks one from the vault),
// and a file that is there is asked about. Reads (listing, find, preview, checksums) need no approval. Bookmarks are per
// session. Whether a terminal browses as root is the core's answer (`files_root_status`), shared by both places through
// lib/root-browsing.ts, so root browsing started in one shows in the other.
//
// SS-14, SS-08 (0.8.0 G4): a file's "⋯" edits it in the terminal (a new tab on the host running its editor; as root,
// sudoedit) or on this PC (a private copy in the editor chosen in Settings, each save uploaded). A double-click does
// what Settings says, or previews the file when that can't be done (lib/editing.ts doubleClickAction). The header's
// "⋯" picks the session's terminal editor.
//
// QL-09: a folder that can't be opened (permission denied, gone) still shows its path, breadcrumbs and the reason, and
// Back, Up, Home, a typed path (from the folder shown) and Refresh all go on from there. Who transfers run as (the SSH
// login) is said, and when the shell may run as someone else (su, sudo -i), that transfers still run as the login user.
// User names carry data-mask="user" (FD-03).
//
// Compact mode (the drawer): it follows the terminal's shell folder (bash and zsh report it through Remotely's prompt
// hook; other shells start in the home folder) until a folder is opened by hand, says "Transfers as alice", and Expand
// opens the Files page at the same folder. Files from Explorer dropped on it upload into the folder it shows, or the
// folder row they fall on (lib/drop-target.ts).

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
  CircleAlertIcon,
  CopyIcon,
  CrosshairIcon,
  DownloadIcon,
  EyeIcon,
  FileSearchIcon,
  FilePenLineIcon,
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
  LaptopIcon,
  Maximize2Icon,
  MoreHorizontalIcon,
  PencilIcon,
  SearchIcon,
  ServerIcon,
  ShieldIcon,
  ShieldOffIcon,
  SquareTerminalIcon,
  Trash2Icon,
  UploadIcon,
  UserIcon,
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
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
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
import { RowMenu } from "@/components/RowMenu";
import { SelectionBar } from "@/components/SelectionBar";
import { SudoPasswordDialog } from "@/components/SudoPasswordDialog";
import { Tip } from "@/components/Tip";
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
  type FileDoubleClick,
  type FolderListing,
  type FolderTracking,
  type RemoteEntry,
  type ShellUsers,
  type SubmitOutcome,
} from "@/lib/api";
import { downloadReason, fileChangeReason, uploadReason } from "@/lib/disabled-reasons";
import { doubleClickAction, doubleClickTitle, editInTerminalLabel, editInTerminalReason } from "@/lib/editing";
import { editingApi, type HostEditors } from "@/lib/editing-api";
import { changeLabel } from "@/lib/file-ops";
import {
  back,
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
import { requestLink } from "@/lib/links";
import { paneOf, subscribePanes, openPanes } from "@/lib/open-panes";
import { readOnlyLocked } from "@/lib/presentation-state";
import { isReauthCancelled } from "@/lib/reauth";
import { withVaultPassword } from "@/lib/reauth-prompt";
import { rootStore } from "@/lib/root-browsing";
import type { PaneSnapshot } from "@/lib/terminal-session";
import { crumbs, joinPath, userNote } from "@/lib/transfers";
import { cn } from "@/lib/utils";

export interface HostTab {
  key: string;
  terminalId: string;
  /** A folder to open, asked from outside (the drawer's Expand, a link), with a counter so the same one opens again. */
  pathRequest?: { path: string; n: number };
}

interface Props {
  tab: HostTab;
  /** UX-14: the Terminal's drawer: narrow, follows the shell's folder, says who transfers run as; Expand. */
  compact?: boolean;
  /** The Files page's local pane, for "Download" into its folder and Compare; null in the drawer. */
  local: LocalListing | null;
  /** What a double-click on a file does (Settings). */
  doubleClick: FileDoubleClick;
  /** SS-10: terminals Type in all tabs types into; transfers still go through this one only. */
  multiExecTerminals?: number;
  /** "default": the local pane's folder on the Files page (Downloads when it shows none), Downloads in the drawer. */
  onDownload: (paths: string[], to: "default" | "choose", asRoot: boolean) => void;
  onUpload: (folder: string, asRoot: boolean, pick: "files" | "folder") => void;
  /** A change, an edit or a sync went to the bus: queued, or the approval dialog; `onJob` once its job runs. */
  onSubmitted: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  /** SS-14 (G4): an editor job is queued: its tab opens on the Terminal page. */
  onEditorJob: (jobId: string, title: string) => void;
  /** A sync to this PC's folder (Compare). */
  onDownloads?: (start: DownloadStart, asRoot: boolean) => void;
  /**
   * The folder shown (null while none is open or the terminal isn't connected), whether it is root's, and why uploads
   * can't go there now (null: they can), for uploads from the local pane and drops.
   */
  onFolder?: (key: string, folder: string | null, asRoot: boolean, why: string | null) => void;
  /** UX-14: what the drawer showed of this terminal last (folder, history, view), so a tab switch keeps it. */
  remembered?: PaneMemory;
  onRemember?: (memory: PaneMemory) => void;
  onDragStart?: (items: DragItems, at: { clientX: number; clientY: number }) => void;
  onDragEnd?: (x: number, y: number) => void;
  onShowTerminal?: (terminalId: string) => void;
  onCloseTab?: (key: string) => void;
}

const NO_SNAPSHOT = { status: { state: "closed" } };

/** UX-14: what a pane remembers of a terminal across tab switches: a folder opened by hand, Back and Forward, the view. */
export interface PaneMemory {
  path: string | null;
  history: History<string>;
  view: PaneView;
}

/** The drawer shows hidden files, as Files here always did; the Files page's tab starts without them. */
const COMPACT_VIEW: PaneView = { ...DEFAULT_VIEW, hidden: true };

/** Picked rows belong to the folder they were picked in: another folder shows none of them picked. */
interface Picks {
  path: string;
  names: string[];
  anchor: string | null;
}
const NO_PICKS: Picks = { path: "", names: [], anchor: null };

const samePath = (a: string, b: string) => a === b;

/** The core's answer: does the terminal browse as root now. */
const readRoot = (terminalId: string) => api.filesRootStatus(terminalId).then((status) => status !== null);

/** A rename or move that would replace a file: asked before it goes again with `replace`. */
interface ReplaceAsk {
  change: Extract<FileChange, { kind: "rename" } | { kind: "move" }>;
  message: string;
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
    case "off":
      return "The prompt hook is off for this session (Settings, the session, or a Prod session), so this starts in your home folder.";
    default:
      return null;
  }
}

/** A user name, masked while presenting (FD-03). */
function Who({ children }: { children: string }) {
  return (
    <span className="font-medium text-foreground" data-mask="user">
      {children}
    </span>
  );
}

/** QL-09: what is known about the shell's own user, when it may not be the login user transfers run as. */
function ShellUserNote({ user }: { user: ShellUsers | undefined }) {
  const login = user?.username;
  if (!login) return null;
  const note = userNote(user);
  let more: ReactNode = null;
  switch (note.kind) {
    case "reported":
      more = (
        <>
          The shell runs as <Who>{note.shell}</Who>, but transfers still run as <Who>{login}</Who>, the SSH login user,
          so a folder <Who>{note.shell}</Who> can open may be refused here.
        </>
      );
      break;
    case "switched":
      more = (
        <>
          The shell may have switched to <Who>{note.shell}</Who>: its prompt names <Who>{note.shell}</Who>, and it
          stopped reporting its folder after the last command (su, sudo -i, or a login elsewhere). This can't follow it:
          it shows what <Who>{login}</Who> can open, and transfers still run as <Who>{login}</Who>.
        </>
      );
      break;
    case "stopped":
      more = (
        <>
          The shell stopped reporting its folder after the last command: it may have switched user or started another
          shell or program, so this can't follow it. It shows what <Who>{login}</Who> can open, and transfers still run
          as <Who>{login}</Who>.
        </>
      );
      break;
    case "prompt":
      more = (
        <>
          The shell's prompt names <Who>{note.shell}</Who>. If it switched user, transfers still run as{" "}
          <Who>{login}</Who>, the SSH login user, so some folders may be refused here.
        </>
      );
      break;
  }
  return more ? <p className="rounded-md bg-muted/60 px-2 py-1 text-xs text-foreground/90">{more}</p> : null;
}

export function HostPane({
  tab,
  compact = false,
  local,
  doubleClick,
  multiExecTerminals = 0,
  onDownload,
  onUpload,
  onSubmitted,
  onEditorJob,
  onDownloads,
  onFolder,
  onDragStart,
  onDragEnd,
  onShowTerminal,
  onCloseTab,
  remembered,
  onRemember,
}: Props) {
  const terminalId = tab.terminalId;
  const presentation = usePresentation();
  const readOnly = readOnlyLocked(presentation);
  // The pane this rides on: its status, its folder's user, its name (read again when the Terminal page's panes change).
  useSyncExternalStore(subscribePanes, openPanes);
  const pane = paneOf(terminalId);
  const subscribe = useCallback((listener: () => void) => pane?.subscribe(listener) ?? (() => undefined), [pane]);
  const snapshot = useSyncExternalStore(subscribe, () => pane?.getSnapshot() ?? NO_SNAPSHOT) as PaneSnapshot;
  // Only an SSH terminal has files here (SFTP on its connection); nothing is asked of any other kind of tab.
  const connected = pane !== undefined && pane.ssh && snapshot.status.state === "connected";
  const name = pane?.title ?? "Closed terminal";
  const sessionId = pane?.sessionId ?? null;
  // UX-14: one answer for the drawer and the Files page.
  const asRoot = useSyncExternalStore(rootStore.subscribe, () => rootStore.isRoot(terminalId));

  const refresh = useUploadsDone(terminalId);
  /** A folder opened by hand; null: the start folder (in compact mode, the shell's folder, followed). */
  const [path, setPath] = useState<string | null>(tab.pathRequest?.path ?? remembered?.path ?? null);
  const shellFolder = compact ? (snapshot.folder?.path ?? null) : null;
  const following = compact && path === null;
  const [tick, setTick] = useState(0);
  const [listing, setListing] = useState<FolderListing | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** The listing asked for, and the last one answered. */
  const want = `${path ?? `start:${shellFolder ?? ""}`}|${asRoot}|${tick}|${refresh}|${connected}`;
  const [answered, setAnswered] = useState<string | null>(null);
  const loading = connected && answered !== want;
  const [history, setHistory] = useState<History<string>>(remembered?.history ?? emptyHistory());
  const [view, setView] = useState<PaneView>(remembered?.view ?? (compact ? COMPACT_VIEW : DEFAULT_VIEW));
  const [picked, setPicked] = useState<Picks>(NO_PICKS);
  const [typed, setTyped] = useState<{ for: string; text: string } | null>(null);
  const [ask, setAsk] = useState<FileAsk | null>(null);
  const [replaceAsk, setReplaceAsk] = useState<ReplaceAsk | null>(null);
  const [askSudo, setAskSudo] = useState(false);
  const [preview, setPreview] = useState<PreviewShown | null>(null);
  const [checksum, setChecksum] = useState<ChecksumShown | null>(null);
  const [finding, setFinding] = useState(false);
  const [comparing, setComparing] = useState(false);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  const [naming, setNaming] = useState<{ bookmark: Bookmark | null; path: string } | null>(null);
  /** SS-14 (G4): the host's terminal editors and the session's choice; asked again after a choice. */
  const [editors, setEditors] = useState<HostEditors | null>(null);
  const [editorsTick, setEditorsTick] = useState(0);
  const watched = useRef(new Set<string>());
  /** Back and Forward set the path without a new step. */
  const stepping = useRef(false);

  // Root browsing may be on already, started in the other place: the core says.
  useEffect(() => {
    if (connected) void rootStore.load(terminalId, readRoot);
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
    // Without a path: the shell's folder, or the home folder (the core knows which).
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
        // SS-14: root browsing ended (a reconnect, the vault locked): back to the login user, in both places.
        if (asRoot && errorMessage(err).includes("not browsing as root")) {
          if (rootStore.set(terminalId, false)) {
            toast.info("Root browsing ended; the folder shows what the login user can open");
          }
          return;
        }
        // The terminal can't reach its files at all: the last folder stays, so this still goes somewhere.
        setError(errorMessage(err));
      },
    );
    return () => {
      gone = true;
    };
  }, [terminalId, path, asRoot, want, connected]);

  const opened = connected && listing !== null && !listing.error ? listing.path : null;
  const uploadWhy =
    uploadReason({ open: true, connected, readOnly }) ??
    (!listing ? "Open a folder first" : listing.error ? "This folder couldn't be opened" : null);
  useEffect(() => {
    onFolder?.(tab.key, opened, asRoot, uploadWhy);
  }, [tab.key, opened, asRoot, uploadWhy, onFolder]);

  useEffect(() => {
    onRemember?.({ path, history, view });
  }, [path, history, view, onRemember]);

  useEffect(() => {
    if (!connected) return;
    let gone = false;
    editingApi.hostEditors(terminalId).then(
      (found) => !gone && setEditors(found),
      () => undefined,
    );
    return () => {
      gone = true;
    };
  }, [terminalId, connected, editorsTick]);

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
  // Picks only count in the folder they were picked in: a folder change (opened, followed, Back) shows none picked.
  const pickedHere = listing !== null && picked.path === listing.path;
  const picks = pickedHere ? picked.names.filter((n) => entries.some((e) => e.name === n)) : [];
  const pickedEntries = entries.filter((e) => picks.includes(e.name));
  const paths = (list: RemoteEntry[]) => list.map((e) => joinPath(here, e.name));
  const changes = fileChangeReason({ connected, readOnly, folderOpen: listing !== null && !failed });
  const upload = uploadWhy;
  const download = downloadReason({ connected, picked: pickedEntries });
  const downloadInto = !compact && local?.path ? `Into ${local.path}` : "Into your Downloads folder";
  const pathText = typed && typed.for === here ? typed.text : here;
  const user = snapshot.folder?.user?.username;

  function open(next: string) {
    setPath(next);
    setTyped(null);
    setPicked(NO_PICKS);
  }

  /** Compact mode: back to the shell's folder, followed again. */
  function follow() {
    setPath(null);
    setTyped(null);
    setPicked(NO_PICKS);
  }

  /** QL-09: Back from a folder that wouldn't open goes to the last one that did (lib/files-page.ts back). */
  const backTo = back(history, listing ? { item: listing.path, failed: failed !== null } : null, samePath);

  function step(dir: -1 | 1) {
    const moved = dir === -1 ? backTo : go(history, dir);
    if (!moved) return;
    stepping.current = true;
    setHistory(moved.history);
    open(moved.item);
  }

  function submit(ev: FormEvent) {
    ev.preventDefault();
    const text = pathText.trim();
    // A relative path goes on from the folder shown, even one that could not be opened.
    if (text) open(text.startsWith("/") || text.startsWith("~") ? text : joinPath(here, text));
  }

  function reload() {
    setTick((n) => n + 1);
    if (connected) void rootStore.load(terminalId, readRoot);
  }

  async function change(next: FileChange) {
    try {
      const outcome = await api.filesChange(terminalId, next, asRoot);
      setAsk(null);
      setPicked(NO_PICKS);
      onSubmitted(outcome, (jobId) => watched.current.add(jobId));
      if (outcome.status === "queued") {
        toast.success(changeLabel(next));
        // A quick job may end before its id is watched: list the folder again a moment later anyway.
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
      rootStore.set(terminalId, true);
      setPicked(NO_PICKS);
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
    rootStore.set(terminalId, false);
    setPicked(NO_PICKS);
    try {
      await api.filesRootStop(terminalId);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  /** SS-14 (G4): opens a file in a terminal editor on the host (a new tab once its job runs). */
  async function editInTerminal(filePath: string) {
    try {
      const outcome = await editingApi.openInEditor(terminalId, filePath, asRoot);
      const title = filePath.split("/").pop() || filePath;
      // Queued at once (Low) or after the approval: the Terminal page opens the tab that job opens.
      onSubmitted(outcome, (jobId) => onEditorJob(jobId, title));
    } catch (err) {
      toast.error(`Can't edit it in the terminal: ${errorMessage(err)}`);
    }
  }

  /** SS-08 (G4): edits a file on this PC (one approval for the editing session). */
  async function editOnPc(filePath: string) {
    try {
      onSubmitted(await editingApi.editOnPc(terminalId, filePath, asRoot), () => undefined);
    } catch (err) {
      toast.error(`Can't edit it on this PC: ${errorMessage(err)}`);
    }
  }

  /** SS-14 (G4): the session's terminal editor. */
  async function chooseEditor(editor: string | null) {
    if (!editors?.sessionId) return;
    try {
      await editingApi.setHostEditor(editors.sessionId, editor);
      setEditorsTick((n) => n + 1);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function showPreview(filePath: string, label: string) {
    setPreview({ name: label, preview: null });
    try {
      setPreview({ name: label, preview: await filesPageApi.preview(terminalId, filePath, asRoot) });
    } catch (err) {
      setPreview({ name: label, preview: null, error: errorMessage(err) });
    }
  }

  async function showChecksum(filePath: string, label: string) {
    setChecksum({ name: label, sha256: null });
    try {
      const sum = await filesPageApi.checksum(terminalId, filePath, asRoot);
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

  async function saveBookmark(bookmarkName: string) {
    if (!naming || !sessionId) return;
    if (naming.bookmark) await filesPageApi.renameBookmark(naming.bookmark.id, bookmarkName);
    else await filesPageApi.addBookmark(sessionId, bookmarkName, naming.path);
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

  /** What a double-click on this file does now. */
  const doubleClickOn = (e: RemoteEntry) =>
    doubleClickAction(doubleClick, editors, e, { asRoot, canChange: changes === null });

  /** UX-14: one row menu, the same in the drawer and on the Files page; or the picked rows' (the selection bar's). */
  function actions(
    list: RemoteEntry[],
    item: (key: string, label: string, icon: ReactNode, onSelect: () => void) => ReactNode,
  ) {
    const p = paths(list);
    const one = list.length === 1 ? list[0] : null;
    const transferable = list.every((e) => e.kind !== "other");
    // SS-14 (G4): a file is edited in the terminal or on this PC; never a link as root (sudoedit edits none).
    const editable = one?.kind === "file" && !(asRoot && one.link);
    return [
      one?.kind === "folder" && item("open", "Open", <FolderOpenIcon />, () => open(p[0])),
      editable &&
        editInTerminalReason(editors) === null &&
        item("editTerminal", editInTerminalLabel(editors), <SquareTerminalIcon />, () => void editInTerminal(p[0])),
      // Never a link on this PC either: a save never goes through one.
      editable && !one.link && item("editPc", "Edit on this PC", <LaptopIcon />, () => void editOnPc(p[0])),
      one?.kind === "file" && item("preview", "Preview", <FileTextIcon />, () => void showPreview(p[0], one.name)),
      one?.kind === "file" &&
        item("checksum", "SHA-256 checksum", <FingerprintIcon />, () => void showChecksum(p[0], one.name)),
      transferable && item("download", "Download", <DownloadIcon />, () => onDownload(p, "default", asRoot)),
      transferable && item("downloadTo", "Download to…", <FolderInputIcon />, () => onDownload(p, "choose", asRoot)),
      one && item("rename", "Rename…", <PencilIcon />, () => setAsk({ kind: "rename", path: p[0] })),
      item("move", "Move to…", <FolderUpIcon />, () => setAsk({ kind: "move", paths: p, folder: here })),
      item("copy", "Copy to…", <CopyIcon />, () => setAsk({ kind: "copy", paths: p, folder: here })),
      // Never through a link: the file it points to is changed where it is.
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

  const reads = ["open", "preview", "checksum", "download", "downloadTo"];
  const menuItem = (key: string, label: string, icon: ReactNode, onSelect: () => void) => (
    <Fragment key={key}>
      {key === "delete" && <DropdownMenuSeparator />}
      <DropdownMenuItem
        variant={key === "delete" ? "destructive" : "default"}
        disabled={!reads.includes(key) && changes !== null}
        title={key === "download" ? downloadInto : undefined}
        onSelect={onSelect}
      >
        {icon}
        {label}
      </DropdownMenuItem>
    </Fragment>
  );
  /** The selection bar's buttons: its main actions; the rest are in its "⋯". */
  const barButton = (key: string, label: string, icon: ReactNode, onSelect: () => void) => {
    if (!["download", "move", "copy", "delete"].includes(key)) return null;
    const why = reads.includes(key) ? download : changes;
    return (
      <WhyDisabled key={key} reason={why}>
        <Button variant="ghost" size="sm" disabled={why !== null} onClick={onSelect}>
          {icon}
          {label}
        </Button>
      </WhyDisabled>
    );
  };

  if (!pane) {
    return (
      <section
        className={cn(
          "flex min-h-0 min-w-0 flex-1 flex-col items-center justify-center gap-2 text-center",
          !compact && "rounded-lg border p-4",
        )}
      >
        <p className="text-sm text-muted-foreground">
          {compact ? "Open a terminal: its files show here." : "This tab's terminal has closed."}
        </p>
        {!compact && onCloseTab && (
          <Button variant="outline" size="sm" onClick={() => onCloseTab(tab.key)}>
            Close the tab
          </Button>
        )}
      </section>
    );
  }
  // An editor tab, Telnet, serial, a tunnel or PowerShell: no SFTP (the Files page only opens SSH terminals).
  if (!pane.ssh) {
    return (
      <section className="flex min-h-0 min-w-0 flex-1 flex-col gap-2">
        {compact && <h2 className="text-sm font-medium">Files here</h2>}
        <p className="text-sm text-muted-foreground">
          This tab has no files to show: Files here is for SSH terminals. Pick one of those tabs.
        </p>
      </section>
    );
  }

  const note = compact ? trackingNote(snapshot.folder?.tracking, following) : null;
  const followingShell = snapshot.folder?.tracking === "following";

  return (
    <section
      aria-label={`Files on ${name}`}
      data-files-drop="host"
      data-files-tab={tab.key}
      className={cn(
        // `pane-drop`: while Explorer files are dragged over it, it says where they would go (the Terminal page), over
        // what shows of it: the content scrolls inside.
        "pane-drop @container relative flex min-h-0 min-w-0 flex-1 flex-col",
        !compact && "rounded-lg border p-2",
      )}
    >
      {/* The drawer scrolls as a whole when its notes and table don't fit, rather than spill over the lists below. */}
      <div className={cn("flex min-h-0 flex-1 flex-col gap-2", compact && "overflow-y-auto")}>
        <div className="flex items-center gap-1.5">
          {compact ? (
            <>
              <FolderOpenIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
              <h2 className="shrink-0 text-sm font-medium whitespace-nowrap">Files here</h2>
            </>
          ) : (
            <ServerIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
          )}
          {!compact && (
            <h2 className="truncate text-sm font-medium" title={name}>
              {name}
            </h2>
          )}
          {asRoot && (
            <Badge variant="outline" className="shrink-0 border-tier-high/50 font-normal text-tier-high">
              as root
            </Badge>
          )}
          {compact && (
            <span className="truncate text-xs text-muted-foreground" title={name}>
              {name}
            </span>
          )}
          {!compact && user && !asRoot && (
            <span className="truncate text-xs text-muted-foreground">
              as <span data-mask="user">{user}</span>
            </span>
          )}
          <div className="ml-auto flex items-center gap-1">
            {!compact && (
              <>
                <Label htmlFor={`files-host-hidden-${tab.key}`} className="text-xs font-normal text-muted-foreground">
                  Hidden files
                </Label>
                <Switch
                  id={`files-host-hidden-${tab.key}`}
                  checked={view.hidden}
                  onCheckedChange={(hidden) => setView((v) => ({ ...v, hidden }))}
                />
                {onShowTerminal && (
                  <PaneButton label="Show its terminal" onClick={() => onShowTerminal(terminalId)}>
                    <SquareTerminalIcon />
                  </PaneButton>
                )}
              </>
            )}
            {connected && (
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
                  <DropdownMenuItem
                    disabled={changes !== null}
                    onSelect={() => setAsk({ kind: "newFile", folder: here })}
                  >
                    <FilePlusIcon />
                    New empty file…
                  </DropdownMenuItem>
                  {/* The drawer's "Upload here…" button is below its list. */}
                  {!compact && (
                    <DropdownMenuItem disabled={upload !== null} onSelect={() => onUpload(here, asRoot, "files")}>
                      <UploadIcon />
                      Upload files here…
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuItem disabled={upload !== null} onSelect={() => onUpload(here, asRoot, "folder")}>
                    <FolderUpIcon />
                    Upload a folder here…
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem disabled={!listing || failed !== null} onSelect={() => setFinding(true)}>
                    <FileSearchIcon />
                    Find files…
                  </DropdownMenuItem>
                  {!compact && (
                    <DropdownMenuItem
                      disabled={!listing || failed !== null || !local?.path}
                      onSelect={() => setComparing(true)}
                    >
                      <GitCompareIcon />
                      Compare with this PC's folder…
                    </DropdownMenuItem>
                  )}
                  {compact && (
                    <DropdownMenuCheckboxItem
                      checked={view.hidden}
                      onCheckedChange={(hidden) => setView((v) => ({ ...v, hidden: hidden === true }))}
                    >
                      <EyeIcon />
                      Hidden files
                    </DropdownMenuCheckboxItem>
                  )}
                  {editors?.sessionId && editors.found.length > 0 && (
                    <DropdownMenuSub>
                      <DropdownMenuSubTrigger disabled={readOnly}>
                        <FilePenLineIcon />
                        Terminal editor
                      </DropdownMenuSubTrigger>
                      <DropdownMenuSubContent>
                        <DropdownMenuRadioGroup
                          value={editors.chosen ?? ""}
                          onValueChange={(value) => void chooseEditor(value === "" ? null : value)}
                        >
                          <DropdownMenuRadioItem value="">First found (nano, micro, vim, vi)</DropdownMenuRadioItem>
                          {editors.found.map((editor) => (
                            <DropdownMenuRadioItem key={editor} value={editor}>
                              {editor}
                            </DropdownMenuRadioItem>
                          ))}
                        </DropdownMenuRadioGroup>
                      </DropdownMenuSubContent>
                    </DropdownMenuSub>
                  )}
                  {compact && (
                    <DropdownMenuItem
                      disabled={!listing || failed !== null}
                      onSelect={() => requestLink({ kind: "files", terminalId, path: here })}
                    >
                      <Maximize2Icon />
                      Expand
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuSeparator />
                  {asRoot ? (
                    <DropdownMenuItem onSelect={() => void stopRoot()}>
                      <ShieldOffIcon />
                      Stop browsing as root
                    </DropdownMenuItem>
                  ) : (
                    <DropdownMenuItem disabled={readOnly} onSelect={() => void startRoot()}>
                      <ShieldIcon />
                      Browse as root…
                    </DropdownMenuItem>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </div>
        </div>
        {!connected ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 text-center text-sm text-muted-foreground">
            <p>
              {snapshot.status.state === "connecting" || snapshot.status.state === "opening"
                ? `Connecting…${compact ? "" : " If the host asks for anything, answer in its terminal."}`
                : "This terminal is not connected, so its files can't be reached."}
            </p>
            {!compact && onShowTerminal && (
              <Button variant="outline" size="sm" onClick={() => onShowTerminal(terminalId)}>
                Show the terminal
              </Button>
            )}
          </div>
        ) : (
          <>
            {asRoot ? (
              <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <ShieldIcon className="size-3.5 shrink-0 text-tier-high" aria-hidden />
                <span>
                  Transfers and changes here run as <span className="font-medium text-tier-high">root</span> (sudo), one
                  approval tier higher.
                </span>
                <HelpTip topic="filesRoot" />
              </p>
            ) : (
              compact &&
              user && (
                <p
                  className="flex items-center gap-1.5 text-xs text-muted-foreground"
                  title="Uploads, downloads and changes run over SFTP as the SSH login user, unless you browse as root."
                >
                  <UserIcon className="size-3.5 shrink-0" aria-hidden />
                  <span>
                    Transfers as <Who>{user}</Who>
                  </span>
                  <HelpTip topic="filesChanges" />
                </p>
              )
            )}
            {!asRoot && <ShellUserNote user={snapshot.folder?.user} />}
            {note && <p className="text-xs text-muted-foreground">{note}</p>}
            {compact && multiExecTerminals > 1 && (
              <p className="rounded-md bg-muted/60 px-2 py-1 text-xs">
                Type in all tabs is on: uploads and downloads go through this terminal only, not all{" "}
                {plural(multiExecTerminals, "terminal")}.
              </p>
            )}
            <div className="flex items-center gap-1">
              <PaneButton
                label={backTo ? `Back to ${backTo.item}` : "Back"}
                disabledReason={backTo ? null : "Nothing before this"}
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
                disabledReason={listing?.parent ? null : listing ? "This is the top folder" : "Open a folder first"}
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
                  value={pathText}
                  onChange={(e) => setTyped({ for: here, text: e.target.value })}
                  placeholder="Type a folder and press Enter"
                  spellCheck={false}
                />
              </form>
              {!compact && (
                <PaneButton
                  label="Find files"
                  disabledReason={listing && !failed ? null : "Open a folder first"}
                  onClick={() => setFinding(true)}
                >
                  <SearchIcon />
                </PaneButton>
              )}
              <RefreshButton busy={loading} onClick={reload} />
              {compact && !following && (
                <PaneButton
                  label={followingShell ? "Follow the terminal's folder again" : "Back to the starting folder (home)"}
                  onClick={follow}
                >
                  <CrosshairIcon />
                </PaneButton>
              )}
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
              <SelectionBar count={picks.length} onClear={() => setPicked(NO_PICKS)} className="flex-none">
                {actions(pickedEntries, barButton)}
                <RowMenu label={plural(picks.length, "picked item")}>
                  {actions(pickedEntries, (key, label, icon, onSelect) =>
                    ["downloadTo", "mode", "owner"].includes(key) ? menuItem(key, label, icon, onSelect) : null,
                  )}
                </RowMenu>
              </SelectionBar>
            )}
            {failed ? (
              <div
                role="alert"
                className={cn(
                  "flex min-h-28 flex-1 flex-col gap-1.5 overflow-auto rounded-md border border-destructive/40 p-2 text-xs",
                  loading && "opacity-60",
                )}
              >
                <p className="flex items-start gap-1.5 text-destructive">
                  <CircleAlertIcon className="mt-0.5 size-3.5 shrink-0" aria-hidden />
                  <span className="break-words">{failed.message}</span>
                </p>
                <p className="text-muted-foreground">
                  {failed.code === "permission_denied" && !asRoot && (
                    <>
                      {user ? (
                        <>
                          Transfers run as <Who>{user}</Who>, the SSH login user, unless you browse as root (the "⋯"
                          above).{" "}
                        </>
                      ) : (
                        "Browse as root (the ⋯ above) to open it as root. "
                      )}
                    </>
                  )}
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
                anchor={pickedHere ? picked.anchor : null}
                onPick={(names, anchor) => setPicked({ path: here, names, anchor })}
                onOpen={(e) => {
                  const at = joinPath(here, e.name);
                  if (e.kind === "folder") open(at);
                  else if (e.kind === "file") {
                    const action = doubleClickOn(e);
                    if (action === "editTerminal") void editInTerminal(at);
                    else if (action === "editPc") void editOnPc(at);
                    else void showPreview(at, e.name);
                  }
                }}
                folderPath={(e) => (e.kind === "folder" ? joinPath(here, e.name) : null)}
                rowTitle={(e) =>
                  e.kind === "folder"
                    ? compact
                      ? "Double-click to open; drop files from Explorer on it to upload them into it"
                      : "Double-click to open; drop files on it to upload or move them into it"
                    : e.kind === "file"
                      ? `${doubleClickTitle(doubleClickOn(e), doubleClick, editors)}${compact ? "" : "; drag to this PC to download"}`
                      : "Not a regular file"
                }
                onDragStart={
                  onDragStart &&
                  ((names, ev) =>
                    onDragStart(
                      { from: "host", terminalId, folder: here, paths: names.map((n) => joinPath(here, n)), asRoot },
                      ev,
                    ))
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
            {!compact && picks.length > 0 && (
              <p className="text-xs text-muted-foreground">
                {plural(picks.length, "item")} picked: drag them to this PC to download.
              </p>
            )}
            {compact && (
              <>
                <div className="flex flex-wrap items-center gap-1.5">
                  <WhyDisabled reason={upload}>
                    <Button
                      size="xs"
                      variant="outline"
                      className="ml-auto"
                      disabled={upload !== null}
                      onClick={() => onUpload(here, asRoot, "files")}
                    >
                      <UploadIcon />
                      Upload here…
                    </Button>
                  </WhyDisabled>
                </div>
                <Tip id="terminal.filesDrop">
                  Drop files on a terminal or here to upload them; right-click a file name in a terminal to download it.
                </Tip>
              </>
            )}
          </>
        )}
      </div>
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
            if (p) onDownload([p], "default", asRoot);
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
          onDownloads={(start) => onDownloads?.(start, asRoot)}
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
