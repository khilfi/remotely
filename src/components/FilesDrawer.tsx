// SS-08: the "Files here" drawer of the Terminal page. It follows the current terminal's shell folder (bash and zsh
// report it through Remotely's prompt hook), or starts in the home folder for other shells, where folders are opened
// by hand: double-click a folder, the breadcrumb, Up, Home, Back, or a path typed in. Files and folders can be ticked
// and downloaded to Downloads or a folder picked in a dialog, and uploaded into the folder shown. SFTP runs on the
// terminal's own connection; uploads go through the approval flow. The transfers panel sits at the bottom. QL-08:
// disabled buttons say why.
//
// QL-09: a folder that can't be opened (permission denied, gone) still shows its path, breadcrumbs and the reason,
// and Up, Home, Back (to the last folder that opened), a typed path (from the folder shown) and Refresh all go on from
// there. The top line says which user transfers run as (the SSH login), and, when the shell may run as someone else
// (su, sudo -i), says so and that transfers still run as the login user. User names carry data-mask="user" (FD-03).
// P6: transfers come from the transfers store, not from the page: the drawer re-renders when an upload into its
// terminal finished (to list the folder again), and only the transfers panel follows each transfer's progress.
//
// SS-14: each row's "⋯" renames, moves, copies, deletes and sets permissions or the owner; ticked rows get the same in
// the selection bar; the header's "⋯" makes a folder or an empty file, uploads a folder, and browses as root (the
// host's sftp-server under sudo: the header says "as root", and every change asks one tier more; a session that saves
// no password for sudo picks one from the vault). Permissions and owners are never offered on a link (the core refuses
// them too). Each change goes through the command bus, which asks at its tier; the folder lists again once its job
// ends. The full two-pane Files page is 0.8.0's G3.

import { Fragment, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  ArrowLeftIcon,
  ArrowUpIcon,
  CircleAlertIcon,
  CopyIcon,
  CrosshairIcon,
  DownloadIcon,
  FileIcon,
  FilePlusIcon,
  FolderIcon,
  FolderInputIcon,
  FolderOpenIcon,
  FolderPlusIcon,
  FolderUpIcon,
  HouseIcon,
  KeyRoundIcon,
  LinkIcon,
  MoreHorizontalIcon,
  PencilIcon,
  RefreshCwIcon,
  ShieldIcon,
  ShieldOffIcon,
  Trash2Icon,
  UploadIcon,
  UserIcon,
  UserRoundCogIcon,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
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
import { FileChangeDialog, type FileAsk } from "@/components/FileChangeDialog";
import { HelpTip } from "@/components/HelpTip";
import { RowMenu } from "@/components/RowMenu";
import { SelectionBar } from "@/components/SelectionBar";
import { SortableHead } from "@/components/SortableHead";
import { SudoPasswordDialog } from "@/components/SudoPasswordDialog";
import { usePresentation } from "@/components/Presentation";
import { Tip } from "@/components/Tip";
import { TransfersList } from "@/components/TransfersList";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useUploadsDone } from "@/hooks/use-transfers";
import {
  api,
  errorMessage,
  type FileChange,
  type FolderListing,
  type FolderTracking,
  type RemoteEntry,
  type ShellUsers,
  type SubmitOutcome,
  type TransferInfo,
} from "@/lib/api";
import { downloadReason, fileChangeReason, uploadReason } from "@/lib/disabled-reasons";
import { changeLabel } from "@/lib/file-ops";
import { plural } from "@/lib/format";
import { readOnlyLocked } from "@/lib/presentation-state";
import { isReauthCancelled } from "@/lib/reauth";
import { withVaultPassword } from "@/lib/reauth-prompt";
import { crumbs, formatSize, joinPath, sortEntries, userNote, type SortKey } from "@/lib/transfers";
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
  /** SS-14: `asRoot` through root browsing; `folder`: pick a folder to upload with what is in it. */
  onUpload: (folder: string, asRoot: boolean, pick: "files" | "folder") => void;
  onDownload: (paths: string[], to: "downloads" | "choose", asRoot: boolean) => void;
  onRetry: (transfer: TransferInfo) => void;
  /** SS-14: a file change went to the bus: queued, or the approval dialog; `onJob` once its job runs. */
  onSubmitted: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
}

/** A folder opened by hand: a path (absolute, `~`, or relative to `from`, the folder shown when it was typed). */
interface Browse {
  terminal: string | null;
  path: string;
  from: string | null;
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

/** QL-09: "Transfers as alice", and what is known about the shell's own user. SS-14: or "as root". */
function TransfersAs({ user, asRoot }: { user: ShellUsers | undefined; asRoot: boolean }) {
  const login = user?.username;
  if (asRoot) {
    return (
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <ShieldIcon className="size-3.5 shrink-0 text-tier-high" aria-hidden />
        <span>
          Transfers and changes here run as <span className="font-medium text-tier-high">root</span> (sudo), one
          approval tier higher.
        </span>
        <HelpTip topic="filesRoot" />
      </p>
    );
  }
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
          stopped reporting its folder after the last command (su, sudo -i, or a login elsewhere). The drawer can't
          follow it: it shows what <Who>{login}</Who> can open, and transfers still run as <Who>{login}</Who>.
        </>
      );
      break;
    case "stopped":
      more = (
        <>
          The shell stopped reporting its folder after the last command: it may have switched user or started another
          shell or program, so the drawer can't follow it. It shows what <Who>{login}</Who> can open, and transfers
          still run as <Who>{login}</Who>.
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
  return (
    <div className="grid gap-1 text-xs text-muted-foreground">
      <p
        className="flex items-center gap-1.5"
        title="Uploads, downloads and changes run over SFTP as the SSH login user, unless you browse as root."
      >
        <UserIcon className="size-3.5 shrink-0" aria-hidden />
        <span>
          Transfers as <Who>{login}</Who>
        </span>
        <HelpTip topic="filesChanges" />
      </p>
      {more && <p className="rounded-md bg-muted/60 px-2 py-1 text-foreground/90">{more}</p>}
    </div>
  );
}

/** A rename or move that would replace a file: asked before it goes again with `replace`. */
interface ReplaceAsk {
  change: Extract<FileChange, { kind: "rename" } | { kind: "move" }>;
  /** The core's words: what is there. */
  message: string;
}

export function FilesDrawer({
  terminalId,
  snapshot,
  name,
  multiExecTerminals,
  onUpload,
  onDownload,
  onRetry,
  onSubmitted,
}: Props) {
  // Grows when an upload into this terminal finished, so the listing shows the new file.
  const refresh = useUploadsDone(terminalId);
  // FD-03: uploads and changes say why they are off while the read-only lock applies.
  const presentation = usePresentation();
  const connected = terminalId !== null && snapshot.status.state === "connected";
  const shellFolder = snapshot.folder?.path ?? null;
  /** A folder opened by hand, per terminal; none: the shell's folder (or home). */
  const [browsing, setBrowsing] = useState<Browse | null>(null);
  const browse = browsing && browsing.terminal === terminalId ? browsing : null;
  /** SS-14: root browsing, per terminal. */
  const [rootFor, setRootFor] = useState<string | null>(null);
  const asRoot = terminalId !== null && rootFor === terminalId;
  const [tick, setTick] = useState(0);
  const keyOf = (b: Browse | null) =>
    `${terminalId ?? ""}|${b ? `${b.path}|${b.from ?? ""}` : `shell:${shellFolder ?? ""}`}|${tick}|${refresh}|${connected}|${asRoot}`;
  const want = keyOf(browse);
  const [loaded, setLoaded] = useState<{ key: string; listing: FolderListing | null; error: string | null } | null>(
    null,
  );
  /** The key whose listing is in hand already (Back loads its folder itself). */
  const have = useRef<string | null>(null);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "name", dir: 1 });
  const [picked, setPicked] = useState<{ path: string; names: string[] }>({ path: "", names: [] });
  const [typed, setTyped] = useState<{ for: string; text: string } | null>(null);
  const [ask, setAsk] = useState<FileAsk | null>(null);
  const [replaceAsk, setReplaceAsk] = useState<ReplaceAsk | null>(null);
  /** SS-14: sudo asked for a password the session doesn't save. */
  const [askSudo, setAskSudo] = useState(false);
  /** SS-14: jobs of changes made here; the folder lists again when one ends. */
  const watched = useRef(new Set<string>());

  useEffect(() => {
    const unlisten = api.onJobEvent((event) => {
      if (event.event === "finished" && watched.current.delete(event.jobId)) setTick((n) => n + 1);
    });
    return () => void unlisten.then((stop) => stop());
  }, []);

  useEffect(() => {
    if (!terminalId || !connected || have.current === want) return;
    let gone = false;
    api.filesList(terminalId, browse?.path ?? null, browse?.from ?? null, asRoot).then(
      (listing) => {
        if (gone) return;
        have.current = want;
        setLoaded({ key: want, listing, error: null });
      },
      (err) => {
        if (gone) return;
        // SS-14: root browsing ended (a reconnect, the vault locked): back to the login user.
        if (asRoot && errorMessage(err).includes("not browsing as root")) {
          setRootFor(null);
          toast.info("Root browsing ended; the folder shows what the login user can open");
          return;
        }
        // The terminal can't reach its files at all: the last folder stays, so the drawer still goes somewhere.
        setLoaded((prev) => ({ key: want, listing: prev?.listing ?? null, error: errorMessage(err) }));
      },
    );
    return () => {
      gone = true;
    };
  }, [want, terminalId, connected, browse, asRoot]);

  const fresh = loaded?.key === want;
  // While the next folder loads, the last one stays (dimmed).
  const listing = loaded?.listing ?? null;
  const failed = listing?.error ?? null;
  const error = fresh ? loaded?.error : null;
  const loading = connected && !fresh;
  const names = listing && picked.path === listing.path ? picked.names : [];
  const entries = listing ? sortEntries(listing.entries, sort.key, sort.dir) : [];
  const pickedEntries = entries.filter((e) => names.includes(e.name));
  const shownPath = listing?.path ?? "";
  const pathText = typed && typed.for === shownPath ? typed.text : shownPath;
  const readOnly = readOnlyLocked(presentation);

  function open(path: string, from: string | null = null) {
    setBrowsing({ terminal: terminalId, path, from });
    setTyped(null);
  }

  function follow() {
    setBrowsing(null);
    setTyped(null);
  }

  async function back() {
    if (!terminalId || !listing) return;
    try {
      const result = await api.filesBack(terminalId, listing.path, asRoot);
      const next: Browse = { terminal: terminalId, path: result.path, from: null };
      const key = keyOf(next);
      have.current = key;
      setBrowsing(next);
      setTyped(null);
      setLoaded({ key, listing: result, error: null });
    } catch (err) {
      setLoaded((prev) => prev && { ...prev, error: errorMessage(err) });
    }
  }

  function toggle(entryName: string, on: boolean) {
    if (!listing) return;
    const now = new Set(names);
    if (on) now.add(entryName);
    else now.delete(entryName);
    setPicked({ path: listing.path, names: [...now] });
  }

  function clearPicked() {
    setPicked({ path: "", names: [] });
  }

  function sortBy(key: SortKey) {
    setSort((s) => ({ key, dir: s.key === key ? (s.dir === 1 ? -1 : 1) : 1 }));
  }

  function submitPath(ev: FormEvent) {
    ev.preventDefault();
    const text = pathText.trim();
    // A relative path goes on from the folder shown, even one that could not be opened.
    if (text) open(text, listing?.path ?? null);
  }

  /** SS-14: sends a change to the bus; the folder lists again once its job ends. Throws for the dialog to show. */
  async function change(next: FileChange) {
    if (!terminalId) return;
    try {
      const outcome = await api.filesChange(terminalId, next, asRoot);
      setAsk(null);
      clearPicked();
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

  /** A change from a menu (no dialog of its own): its error is a toast. */
  function run(next: FileChange) {
    change(next).catch((err) => toast.error(errorMessage(err)));
  }

  async function startRoot(retry = false, sudoPasswordId: string | null = null) {
    if (!terminalId) return;
    try {
      const started = await withVaultPassword((vaultPassword) =>
        api.filesRootStart(terminalId, { vaultPassword, retry, sudoPasswordId }),
      );
      setRootFor(terminalId);
      clearPicked();
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
    if (!terminalId) return;
    setRootFor(null);
    clearPicked();
    try {
      await api.filesRootStop(terminalId);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  const followingShell = snapshot.folder?.tracking === "following";
  const note = trackingNote(snapshot.folder?.tracking, browse === null);
  const download = downloadReason({ connected, picked: pickedEntries });
  const upload =
    uploadReason({ open: terminalId !== null, connected, readOnly }) ??
    (!listing ? "Open a folder first" : failed ? "This folder couldn't be opened" : null);
  const changes = fileChangeReason({ connected, readOnly, folderOpen: listing !== null && !failed });
  const paths = (list: RemoteEntry[]) => (listing ? list.map((e) => joinPath(listing.path, e.name)) : []);
  const here = listing?.path ?? "/";

  /** The actions on one row, or on the ticked rows (the selection bar's). */
  function actions(
    list: RemoteEntry[],
    item: (key: string, label: string, icon: ReactNode, onSelect: () => void, danger?: boolean) => ReactNode,
  ) {
    const p = paths(list);
    const one = list.length === 1 ? list[0] : null;
    return [
      one?.kind === "folder" &&
        item("open", "Open", <FolderOpenIcon />, () => listing && open(joinPath(listing.path, one.name))),
      list.every((e) => e.kind !== "other") &&
        item("download", "Download", <DownloadIcon />, () => onDownload(p, "downloads", asRoot)),
      list.every((e) => e.kind !== "other") &&
        item("downloadTo", "Download to…", <FolderInputIcon />, () => onDownload(p, "choose", asRoot)),
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
      item(
        "delete",
        list.length === 1 ? "Delete" : `Delete ${list.length}`,
        <Trash2Icon />,
        () => run({ kind: "delete", paths: p }),
        true,
      ),
    ];
  }

  const menuItem = (key: string, label: string, icon: ReactNode, onSelect: () => void, danger = false) => {
    const changing = !["open", "download", "downloadTo"].includes(key);
    return (
      <Fragment key={key}>
        {key === "delete" && <DropdownMenuSeparator />}
        <DropdownMenuItem
          variant={danger ? "destructive" : "default"}
          disabled={changing && changes !== null}
          onSelect={onSelect}
        >
          {icon}
          {label}
        </DropdownMenuItem>
      </Fragment>
    );
  };

  /** The selection bar's buttons: its main actions; the rest are in its "⋯". */
  const barButton = (key: string, label: string, icon: ReactNode, onSelect: () => void) => {
    const changing = !["open", "download", "downloadTo"].includes(key);
    const why = changing ? changes : download;
    if (!["download", "move", "copy", "delete"].includes(key)) return null;
    return (
      <WhyDisabled key={key} reason={why}>
        <Button variant="ghost" size="sm" disabled={why !== null} onClick={onSelect}>
          {icon}
          {label}
        </Button>
      </WhyDisabled>
    );
  };

  return (
    <div className="@container flex h-full min-h-0 flex-col gap-2 rounded-lg border p-2">
      <div className="flex items-center gap-1.5">
        <FolderOpenIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
        <h2 className="shrink-0 text-sm font-medium whitespace-nowrap">Files here</h2>
        {asRoot && (
          <Badge variant="outline" className="shrink-0 border-tier-high/50 font-normal text-tier-high">
            as root
          </Badge>
        )}
        <span className="truncate text-xs text-muted-foreground" title={name}>
          {name}
        </span>
        {connected && (
          <DropdownMenu>
            <Tooltip>
              <TooltipTrigger asChild>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon-sm" className="ml-auto" aria-label="More file actions">
                    <MoreHorizontalIcon />
                  </Button>
                </DropdownMenuTrigger>
              </TooltipTrigger>
              <TooltipContent>More file actions</TooltipContent>
            </Tooltip>
            <DropdownMenuContent align="end" className="min-w-52">
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
              <DropdownMenuItem
                disabled={upload !== null}
                onSelect={() => listing && onUpload(listing.path, asRoot, "folder")}
              >
                <FolderUpIcon />
                Upload a folder here…
              </DropdownMenuItem>
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

      {!terminalId ? (
        <p className="text-sm text-muted-foreground">Open a terminal: its files show here.</p>
      ) : !connected ? (
        <p className="text-sm text-muted-foreground">This terminal is not connected, so its files can't be reached.</p>
      ) : (
        <>
          <TransfersAs user={snapshot.folder?.user} asRoot={asRoot} />
          {note && <p className="text-xs text-muted-foreground">{note}</p>}
          {multiExecTerminals > 1 && (
            <p className="rounded-md bg-muted/60 px-2 py-1 text-xs">
              Type in all tabs is on: uploads and downloads go through this terminal only, not all{" "}
              {plural(multiExecTerminals, "terminal")}.
            </p>
          )}
          <div className="flex items-center gap-1">
            <DrawerButton
              label={listing?.back ? `Back to ${listing.back}` : "Back"}
              disabledReason={listing?.back ? null : "No folder opened before this one"}
              onClick={() => void back()}
            >
              <ArrowLeftIcon />
            </DrawerButton>
            <DrawerButton
              label="Up one folder"
              disabledReason={listing?.parent ? null : listing ? "This is the top folder" : "Open a folder first"}
              onClick={() => listing?.parent && open(listing.parent)}
            >
              <ArrowUpIcon />
            </DrawerButton>
            <DrawerButton label="Home folder" onClick={() => open("~")}>
              <HouseIcon />
            </DrawerButton>
            <form className="min-w-0 flex-1" onSubmit={submitPath}>
              <Input
                aria-label="Folder on the host"
                aria-invalid={failed ? true : undefined}
                className="h-7 font-mono text-xs"
                value={pathText}
                onChange={(e) => setTyped({ for: shownPath, text: e.target.value })}
                placeholder="Type a folder and press Enter"
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
          {pickedEntries.length > 0 && (
            <SelectionBar count={pickedEntries.length} onClear={clearPicked} className="flex-none">
              {actions(pickedEntries, barButton)}
              <RowMenu label={plural(pickedEntries.length, "selected item")}>
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
                {failed.code === "permission_denied" && snapshot.folder?.user?.username && !asRoot && (
                  <>
                    Transfers run as <Who>{snapshot.folder.user.username}</Who>, the SSH login user, unless you browse
                    as root (the "⋯" above).{" "}
                  </>
                )}
                Go Back, Up or Home, pick a folder above, or type another one.
              </p>
            </div>
          ) : (
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
                        aria-label="Tick everything"
                        checked={entries.length > 0 && entries.every((e) => names.includes(e.name))}
                        disabled={entries.length === 0}
                        onCheckedChange={(on) =>
                          listing && setPicked({ path: listing.path, names: on ? entries.map((e) => e.name) : [] })
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
                    <TableHead className="w-8">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {listing && entries.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-xs text-muted-foreground">
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
                        else if (e.kind === "file") onDownload([joinPath(listing.path, e.name)], "downloads", asRoot);
                      }}
                      className="group cursor-default text-xs"
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
                          <span className={cn("truncate", e.kind === "other" && "text-muted-foreground")}>
                            {e.name}
                          </span>
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
                      <TableCell className="py-0.5">
                        <RowMenu label={e.name} className="opacity-0 group-hover:opacity-100 focus-visible:opacity-100">
                          {actions([e], menuItem)}
                        </RowMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-1.5">
            {listing?.more && (
              <p className="text-xs text-muted-foreground">More is in this folder than is listed here.</p>
            )}
            <WhyDisabled reason={upload}>
              <Button
                size="xs"
                variant="outline"
                className="ml-auto"
                disabled={upload !== null}
                onClick={() => listing && onUpload(listing.path, asRoot, "files")}
              >
                <UploadIcon />
                Upload here…
              </Button>
            </WhyDisabled>
          </div>
          <Tip id="terminal.filesDrop">
            Drop files on a terminal to upload them; right-click a file name in it to download.
          </Tip>
        </>
      )}
      <div className="flex max-h-[35%] min-h-0 shrink-0 flex-col overflow-hidden">
        <TransfersList onRetry={onRetry} />
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
        <AlertDialog open onOpenChange={(open) => !open && setReplaceAsk(null)}>
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
