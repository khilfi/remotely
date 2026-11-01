// Session library (SS-01, SS-06): folders on the left; search, label and tag filters and the session list
// on the right. Each session shows its colour, environment label, address, how it logs in and its jump
// host (SS-07: the whole chain on hover). Creating, editing and organising sessions is the app's own data (audited, no approval). Connect
// (or a double-click) opens the session in a terminal tab (SS-03); Import reads PuTTY, MobaXterm,
// OpenSSH and CSV session lists (SS-02). The VM column shows the VM each session reaches (QL-01),
// linked automatically by IP address or by hand, and lets the user keep, change or remove the link.
// Export and "Import from another laptop" move the library between the owner's laptops in one encrypted
// file (FD-07).
// Under the address: the host name and IP the last connection saw (QL-03).
// UX-01, UX-02, UX-12: the page header holds the search and filters, New session (its one primary) and "⋯" (import and
// export); rows and folders have one "⋯" menu each; the Environment column shows the environment that applies (a Prod
// VM the session reaches makes it Prod) and where it comes from when it is not the session's own.
// 0.7.0: QL-28 rows can be selected (the selection bar's Edit changes them all at once, and FD-04 its Support bundle
// collects from the SSH ones), QL-26 a star on each row, FD-06 a session's and a folder's note in their menus, and
// QL-27 a delete's toast offers Undo (the item is in the trash).

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { jumpChain, routeText } from "@/lib/tunnels";
import {
  FileCodeIcon,
  FileLockIcon,
  FileSpreadsheetIcon,
  FolderIcon,
  FolderOpenIcon,
  FolderPlusIcon,
  ImportIcon,
  KeyRoundIcon,
  LaptopIcon,
  LibraryIcon,
  ListTreeIcon,
  NotebookPenIcon,
  PackageIcon,
  PencilIcon,
  PlusIcon,
  SearchIcon,
  ShieldIcon,
  TagIcon,
  TerminalIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ColorDot, EnvBadge } from "@/components/Badges";
import { BulkEditDialog } from "@/components/BulkEditDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { ExportDialog } from "@/components/ExportDialog";
import { PageHeader } from "@/components/PageHeader";
import { FolderDefaultsDialog } from "@/components/FolderDefaultsDialog";
import { HostDetailsSheet } from "@/components/HostDetailsSheet";
import { ImportDialog } from "@/components/ImportDialog";
import { NameDialog } from "@/components/NameDialog";
import { RowMenu } from "@/components/RowMenu";
import { SelectionBar } from "@/components/SelectionBar";
import { StarButton } from "@/components/StarButton";
import { SessionDialog } from "@/components/SessionDialog";
import { TransferImportDialog } from "@/components/TransferImportDialog";
import { SessionVmLink } from "@/components/VmLinkControls";
import { ToolboxMenu } from "@/components/toolbox/ToolboxMenu";
import { ReasonLine, WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type Environment,
  type SecretMeta,
  type SessionAuth,
  type SessionFolder,
  type SessionRecord,
  type Tag,
  type VaultInfo,
  type VmRecord,
} from "@/lib/api";
import { flattenFolders, folderPath, subtree } from "@/lib/folders";
import { formatWhen, plural } from "@/lib/format";
import { requestLink } from "@/lib/links";
import { useThresholds } from "@/lib/metrics";
import { noteLink } from "@/lib/notes";
import { toastDeleted } from "@/lib/undo-delete";
import { withVaultPassword } from "@/lib/reauth-prompt";
import { reveal } from "@/lib/reveal";
import { appliedEnvironment, environmentText, sourceText, vmsById } from "@/lib/session-environment";
import { cn } from "@/lib/utils";
import { openSessionWindow } from "@/lib/console-open";
import { kindAddress, kindLabel, kindOf, opensWindow } from "@/lib/session-kinds";
import { usePresentation } from "@/components/Presentation";

interface Props {
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  onOpenVault: () => void;
  /** SS-03: opens the session in a new terminal tab. */
  onConnect: (sessionId: string) => void;
  /** FD-04: the support bundle dialog, with these sessions picked (a selection's; none from the "⋯" menu). */
  onSupportBundle: (sessionIds: string[]) => void;
  /** BX-12: the Ansible inventory dialog, with these sessions picked (none: every SSH session). */
  onExportAnsible: (sessionIds: string[]) => void;
  /** FD-05: the inventory to Excel. */
  onExportInventory: () => void;
  /** True while the page is shown, so the lists are read again when the user comes back. */
  active: boolean;
  /** R10: a session to show (a search result, a map node): the filters cleared, its row scrolled to and lit. */
  focus?: { sessionId: string; n: number } | null;
}

type DialogState =
  | { kind: "editSession"; session?: SessionRecord }
  | { kind: "deleteSession"; session: SessionRecord }
  | { kind: "newFolder"; parentId: string | null }
  | { kind: "renameFolder"; folder: SessionFolder }
  | { kind: "deleteFolder"; folder: SessionFolder }
  | { kind: "folderDefaults"; folder: SessionFolder }
  | { kind: "import" }
  | { kind: "export" }
  | { kind: "importExport" }
  | { kind: "bulkEdit" }
  | null;

const LABELS: { value: Environment; label: string; className: string }[] = [
  { value: "lab", label: "Lab", className: "data-[state=on]:text-env-lab" },
  { value: "staging", label: "Staging", className: "data-[state=on]:text-env-staging" },
  { value: "prod", label: "Prod", className: "data-[state=on]:text-env-prod" },
];

/** Where it connects; SS-12: another kind's own port, or a serial session's COM port and line. */
function address(s: SessionRecord) {
  if (kindOf(s).protocol !== "ssh") return kindAddress(s);
  return `${s.username ? `${s.username}@` : ""}${s.host}${s.port === 22 ? "" : `:${s.port}`}`;
}

/** QL-16, UX-12: where a value comes from when it is not the session's own ("from folder Production"). */
function FromNote({ text }: { text: string }) {
  return <div className="text-xs text-muted-foreground">{text}</div>;
}

export function SessionsPage({
  vault,
  onVaultChanged,
  onOpenVault,
  onConnect,
  onSupportBundle,
  onExportAnsible,
  onExportInventory,
  active,
  focus = null,
}: Props) {
  const presentation = usePresentation();
  const [all, setAll] = useState<SessionRecord[]>([]);
  const [shown, setShown] = useState<SessionRecord[]>([]);
  const [folders, setFolders] = useState<SessionFolder[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [folderId, setFolderId] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [version, setVersion] = useState(0);
  const [loaded, setLoaded] = useState(false);
  const [dialog, setDialog] = useState<DialogState>(null);
  /** QL-28: the sessions picked for the selection bar's Edit. */
  const [selected, setSelected] = useState<Set<string>>(new Set());
  /** MO-13, MO-14: a session's host details. */
  const [hostDetails, setHostDetails] = useState<{ id: string; name: string } | null>(null);
  const [thresholds] = useThresholds();
  // R10: the session a link asked for, lit until it has been seen.
  const [lit, setLit] = useState<string | null>(null);
  const [focusHandled, setFocusHandled] = useState(focus?.n ?? 0);
  if (focus && focus.n !== focusHandled) {
    setFocusHandled(focus.n);
    setFolderId(null);
    setText("");
    setEnvironments([]);
    setTagFilter([]);
    setLit(focus.sessionId);
  }
  const litShown = lit !== null && shown.some((s) => s.id === lit);
  useEffect(() => {
    if (!litShown || !lit) return;
    reveal(document.getElementById(`session-row-${lit}`));
    const timer = window.setTimeout(() => setLit(null), 2500);
    return () => window.clearTimeout(timer);
  }, [litShown, lit]);

  const reload = useCallback(() => setVersion((v) => v + 1), []);
  /** SS-07: the whole way in, for the Via column's tooltip. */
  const chainTitle = (id: string) => {
    const chain = jumpChain(id, new Map(all.map((x) => [x.id, x])));
    if (chain.loop) return "Its jump hosts go round in a loop, so it can't connect. Edit one of them.";
    return chain.names.length > 0 ? `Connects through ${routeText(chain.names)}` : undefined;
  };

  // Everything but the filtered list: folders, every session (jump hosts, counts), tags, vault labels.
  useEffect(() => {
    if (!active) return;
    Promise.all([api.sessionFolders(), api.sessions(), api.tags(), api.secrets()]).then(
      ([f, s, t, v]) => {
        setFolders(f);
        setAll(s);
        setSelected((prev) => (prev.size === 0 ? prev : new Set([...prev].filter((id) => s.some((x) => x.id === id)))));
        setTags(t.filter((tag) => tag.sessionCount > 0));
        setSecrets(v);
        setLoaded(true);
        // A folder deleted elsewhere: fall back to all sessions.
        setFolderId((current) => (current && !f.some((x) => x.id === current) ? null : current));
      },
      (err) => toast.error(errorMessage(err)),
    );
  }, [active, version]);

  useEffect(() => {
    if (!active) return;
    const timer = window.setTimeout(() => {
      api.sessions({ text, environments, tags: tagFilter, folderId }).then(setShown, (err) => {
        toast.error(errorMessage(err));
      });
    }, 120);
    return () => window.clearTimeout(timer);
  }, [active, version, text, environments, tagFilter, folderId]);

  // QL-01: the VMs a session can be linked to, and the sessions several VMs match.
  const [vms, setVms] = useState<VmRecord[]>([]);
  const [ambiguous, setAmbiguous] = useState<Map<string, string[]>>(new Map());
  useEffect(() => {
    if (!active) return;
    Promise.all([api.vmList(), api.ambiguousVmLinks()]).then(
      ([v, a]) => {
        setVms(v);
        setAmbiguous(new Map(a.map((x) => [x.sessionId, x.vmIds])));
      },
      () => {
        setVms([]);
        setAmbiguous(new Map());
      },
    );
  }, [active, version]);

  const vmById = useMemo(() => vmsById(vms), [vms]);
  const secretLabel = useMemo(() => new Map(secrets.map((s) => [s.id, s.label])), [secrets]);
  const sessionName = useMemo(() => new Map(all.map((s) => [s.id, s.name])), [all]);
  const rows = flattenFolders(folders);
  const counts = useMemo(() => {
    const map = new Map<string, number>();
    for (const f of folders) {
      const scope = subtree(folders, f.id);
      map.set(f.id, all.filter((s) => s.folderId && scope.has(s.folderId)).length);
    }
    return map;
  }, [folders, all]);
  const filtered = text.trim() !== "" || environments.length > 0 || tagFilter.length > 0;
  const current = folders.find((f) => f.id === folderId) ?? null;

  function login(auth: SessionAuth) {
    const name = (id: string | null) => (id ? (secretLabel.get(id) ?? "missing from the vault") : null);
    switch (auth.method) {
      case "password":
        return auth.passwordId ? `Password · ${name(auth.passwordId)}` : "Password, asked";
      case "key":
        return auth.keyId ? `Key · ${name(auth.keyId)}` : "Key, none chosen";
      case "agent":
        return "SSH agent";
      // QL-16: what applies to a session is never "as its folders say"; shown only for completeness.
      case "folder":
        return "From folder";
    }
  }

  async function move(session: SessionRecord, target: string | null) {
    try {
      // QL-16, SS-04: a folder whose login sends a vault password to new hosts asks for the vault password.
      await withVaultPassword((password) => api.moveSessions([session.id], target, password));
      reload();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function moveFolder(folder: SessionFolder, parentId: string | null) {
    try {
      await withVaultPassword((password) => api.moveFolder(folder.id, parentId, password));
      reload();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  /**
   * SS-07: a session behind jump hosts connects through them; the terminal says how. SS-12: an RDP or VNC session with
   * no jump host opens its window from here; behind one, a tunnel tab on the Terminal page opens it.
   */
  function connect(session: SessionRecord) {
    const kind = kindOf(session);
    if (opensWindow(kind) && !session.jumpSessionId) {
      openSessionWindow({ id: session.id, name: session.name, kind }, presentation.presenting);
      return;
    }
    onConnect(session.id);
  }

  async function duplicate(session: SessionRecord) {
    try {
      const copy = await api.duplicateSession(session.id);
      toast.success(`Created '${copy.name}'`);
      reload();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  const newSession = () => setDialog({ kind: "editSession" });
  const selectedSessions = all.filter((s) => selected.has(s.id));
  // BX-13: support bundles and the Ansible inventory take SSH and WinRM sessions (a WinRM host runs PowerShell).
  const selectedHosts = selectedSessions.filter((s) => ["ssh", "winrm"].includes(kindOf(s).protocol));
  const allShownSelected = shown.length > 0 && shown.every((s) => selected.has(s.id));
  function toggleSelected(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="flex min-h-0 flex-col gap-4">
      <PageHeader
        page="sessions"
        primary={
          <Button onClick={newSession}>
            <PlusIcon data-icon="inline-start" />
            New session
          </Button>
        }
        toolsClassName="w-72"
        tools={
          <>
            <DropdownMenuItem onSelect={() => setDialog({ kind: "import" })}>
              <ImportIcon />
              <span className="grid">
                Import from another app…
                <span className="text-xs text-muted-foreground">PuTTY, MobaXterm, OpenSSH or CSV</span>
              </span>
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={() => setDialog({ kind: "importExport" })}>
              <LaptopIcon />
              <span className="grid">
                Import from another laptop…
                <span className="text-xs text-muted-foreground">A file exported from Remotely</span>
              </span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem disabled={all.length === 0} onSelect={() => setDialog({ kind: "export" })}>
              <FileLockIcon />
              <span>
                Export to another laptop…
                <ReasonLine reason={all.length === 0 ? "No sessions to export yet" : null} />
              </span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem disabled={all.length === 0} onSelect={() => onSupportBundle([])}>
              <PackageIcon />
              <span className="grid">
                Collect a support bundle…
                <span className="text-xs text-muted-foreground">Logs and settings from hosts, in one zip</span>
                <ReasonLine reason={all.length === 0 ? "No sessions to collect from yet" : null} />
              </span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem disabled={all.length === 0} onSelect={() => onExportAnsible([])}>
              <FileCodeIcon />
              <span className="grid">
                Export an Ansible inventory…
                <span className="text-xs text-muted-foreground">Hosts and groups for playbooks, no secrets</span>
                <ReasonLine reason={all.length === 0 ? "No sessions to export yet" : null} />
              </span>
            </DropdownMenuItem>
            <DropdownMenuItem onSelect={onExportInventory}>
              <FileSpreadsheetIcon />
              <span className="grid">
                Export the inventory to Excel…
                <span className="text-xs text-muted-foreground">VMs, hosts, networks and checks</span>
              </span>
            </DropdownMenuItem>
          </>
        }
      >
        {selectedSessions.length > 0 ? (
          <SelectionBar count={selectedSessions.length} onClear={() => setSelected(new Set())}>
            <Button variant="ghost" size="sm" onClick={() => setDialog({ kind: "bulkEdit" })}>
              <PencilIcon data-icon="inline-start" />
              Edit…
            </Button>
            {/* BX-13: bundles collect over SSH and WinRM; the dialog leaves other kinds out with a note. */}
            <WhyDisabled
              reason={selectedHosts.length === 0 ? "Support bundles collect from SSH and WinRM sessions only" : null}
            >
              <Button
                variant="ghost"
                size="sm"
                disabled={selectedHosts.length === 0}
                onClick={() => onSupportBundle(selectedHosts.map((s) => s.id))}
              >
                <PackageIcon data-icon="inline-start" />
                Make a support bundle…
              </Button>
            </WhyDisabled>
            <WhyDisabled
              reason={selectedHosts.length === 0 ? "An Ansible inventory takes SSH and WinRM sessions only" : null}
            >
              <Button
                variant="ghost"
                size="sm"
                disabled={selectedHosts.length === 0}
                onClick={() => onExportAnsible(selectedHosts.map((s) => s.id))}
              >
                <FileCodeIcon data-icon="inline-start" />
                Export Ansible inventory…
              </Button>
            </WhyDisabled>
          </SelectionBar>
        ) : (
          <>
            <div className="relative w-full max-w-xs">
              <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                aria-label="Search sessions"
                placeholder="Search name, host, user, tag"
                className="pl-8"
                value={text}
                onChange={(e) => setText(e.currentTarget.value)}
              />
            </div>
            <ToggleGroup
              type="multiple"
              variant="outline"
              aria-label="Environment"
              value={environments}
              onValueChange={(v) => setEnvironments(v as Environment[])}
            >
              {LABELS.map((l) => (
                <ToggleGroupItem key={l.value} value={l.value} className={cn("font-medium", l.className)}>
                  {l.label}
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline">
                  <TagIcon data-icon="inline-start" />
                  Tags{tagFilter.length > 0 ? ` (${tagFilter.length})` : ""}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="w-56">
                <DropdownMenuLabel>Sessions with any of</DropdownMenuLabel>
                {tags.length === 0 && <DropdownMenuItem disabled>No tags yet</DropdownMenuItem>}
                {tags.map((t) => (
                  <DropdownMenuCheckboxItem
                    key={t.id}
                    checked={tagFilter.some((x) => x.toLowerCase() === t.name.toLowerCase())}
                    onSelect={(e) => e.preventDefault()}
                    onCheckedChange={(checked) =>
                      setTagFilter((list) =>
                        checked ? [...list, t.name] : list.filter((x) => x.toLowerCase() !== t.name.toLowerCase()),
                      )
                    }
                  >
                    {t.name}
                    <DropdownMenuShortcut>{t.sessionCount}</DropdownMenuShortcut>
                  </DropdownMenuCheckboxItem>
                ))}
                {tagFilter.length > 0 && (
                  <>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onSelect={() => setTagFilter([])}>Clear</DropdownMenuItem>
                  </>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
            <span className="text-sm text-muted-foreground">
              {filtered || folderId
                ? `${shown.length} of ${plural(all.length, "session")}`
                : plural(all.length, "session")}
            </span>
          </>
        )}
      </PageHeader>
      <div className="flex min-h-0 flex-col gap-4 md:flex-row">
        <aside className="flex shrink-0 flex-col gap-1 md:w-60">
          <div className="mb-1 flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">Folders</span>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label="New folder"
                  onClick={() => setDialog({ kind: "newFolder", parentId: null })}
                >
                  <FolderPlusIcon />
                </Button>
              </TooltipTrigger>
              <TooltipContent>New folder</TooltipContent>
            </Tooltip>
          </div>
          <div className="flex items-center pr-8">
            <FolderButton active={folderId === null} onClick={() => setFolderId(null)} count={all.length} depth={0}>
              <LibraryIcon />
              All sessions
            </FolderButton>
          </div>
          {rows.map(({ folder, depth }) => (
            <div key={folder.id} className="group/folder flex items-center">
              <FolderButton
                active={folderId === folder.id}
                onClick={() => setFolderId(folder.id)}
                count={counts.get(folder.id) ?? 0}
                depth={depth}
              >
                {folderId === folder.id ? <FolderOpenIcon /> : <FolderIcon />}
                <span className="truncate">{folder.name}</span>
              </FolderButton>
              <RowMenu
                label={`folder ${folder.name}`}
                align="start"
                className="opacity-0 group-hover/folder:opacity-100 focus-visible:opacity-100 data-[state=open]:opacity-100"
              >
                <DropdownMenuItem onSelect={() => setDialog({ kind: "folderDefaults", folder })}>
                  Defaults…
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => requestLink(noteLink("folder", folder.id, folder.name))}>
                  <NotebookPenIcon />
                  Note…
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setDialog({ kind: "newFolder", parentId: folder.id })}>
                  New folder inside…
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setDialog({ kind: "renameFolder", folder })}>
                  Rename…
                </DropdownMenuItem>
                <DropdownMenuSub>
                  <DropdownMenuSubTrigger>Move to</DropdownMenuSubTrigger>
                  <DropdownMenuSubContent>
                    <DropdownMenuItem
                      disabled={folder.parentId === null}
                      onSelect={() => void moveFolder(folder, null)}
                    >
                      Top level
                    </DropdownMenuItem>
                    {rows
                      .filter(({ folder: f }) => !subtree(folders, folder.id).has(f.id) && f.id !== folder.parentId)
                      .map(({ folder: f }) => (
                        <DropdownMenuItem key={f.id} onSelect={() => void moveFolder(folder, f.id)}>
                          {folderPath(folders, f.id)}
                        </DropdownMenuItem>
                      ))}
                  </DropdownMenuSubContent>
                </DropdownMenuSub>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onSelect={() => setDialog({ kind: "deleteFolder", folder })}>
                  Delete…
                </DropdownMenuItem>
              </RowMenu>
            </div>
          ))}
        </aside>

        <div className="flex min-w-0 flex-1 flex-col gap-4">
          {vault?.status === "notSetUp" && (
            <p className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
              <KeyRoundIcon className="size-4" aria-hidden />
              Sessions log in with passwords and keys from the vault.
              <Button variant="link" className="h-auto p-0" onClick={onOpenVault}>
                Set up the vault
              </Button>
            </p>
          )}

          {loaded && all.length === 0 && (
            <EmptyState
              icon={ListTreeIcon}
              title="No sessions yet"
              description="Save the SSH hosts you work with, then connect with one click."
              help="page.sessions"
              action={
                <>
                  <Button onClick={newSession}>
                    <PlusIcon data-icon="inline-start" />
                    New session
                  </Button>
                  <Button variant="outline" onClick={() => setDialog({ kind: "import" })}>
                    <ImportIcon data-icon="inline-start" />
                    Import from another app…
                  </Button>
                </>
              }
            />
          )}

          {all.length > 0 && shown.length === 0 && (
            <p className="text-sm text-muted-foreground">
              {current && !filtered ? `No sessions in ${current.name}.` : "No sessions match."}
            </p>
          )}

          {shown.length > 0 && (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        aria-label="Select all shown sessions"
                        checked={
                          allShownSelected ? true : shown.some((s) => selected.has(s.id)) ? "indeterminate" : false
                        }
                        onCheckedChange={() =>
                          setSelected((prev) => {
                            const next = new Set(prev);
                            for (const s of shown) {
                              if (allShownSelected) next.delete(s.id);
                              else next.add(s.id);
                            }
                            return next;
                          })
                        }
                      />
                    </TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Address</TableHead>
                    <TableHead>Login</TableHead>
                    <TableHead>Via</TableHead>
                    <TableHead>VM</TableHead>
                    <TableHead className="w-32">Environment</TableHead>
                    <TableHead className="w-20">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {shown.map((s) => {
                    // UX-12: the environment that applies, and where it comes from.
                    const applied = appliedEnvironment(s, vmById);
                    const vm = s.vmId ? vmById.get(s.vmId) : undefined;
                    const isProtected = s.protected || Boolean(vm?.protected);
                    return (
                      <TableRow
                        key={s.id}
                        id={`session-row-${s.id}`}
                        data-state={selected.has(s.id) ? "selected" : undefined}
                        className={cn(
                          "group select-none",
                          applied.environment === "prod" && "bg-env-prod/5",
                          lit === s.id && "bg-accent ring-2 ring-ring ring-inset",
                        )}
                        onDoubleClick={() => connect(s)}
                      >
                        <TableCell onDoubleClick={(e) => e.stopPropagation()}>
                          <Checkbox
                            aria-label={`Select ${s.name}`}
                            checked={selected.has(s.id)}
                            onCheckedChange={() => toggleSelected(s.id)}
                          />
                        </TableCell>
                        <TableCell className="whitespace-normal">
                          <div className="flex flex-wrap items-center gap-1.5 font-medium">
                            <span className="inline-flex items-center gap-1.5">
                              <StarButton kind="session" itemKey={s.id} name={s.name} className="-ml-1" />
                              <ColorDot color={s.color} />
                              {s.name}
                            </span>
                            {isProtected && (
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <ShieldIcon className="size-3.5 text-tier-high" aria-label="Protected" />
                                </TooltipTrigger>
                                <TooltipContent>
                                  {s.protected
                                    ? "Protected: bulk actions skip this session"
                                    : `Protected, from VM ${vm?.displayName ?? ""}: bulk actions skip this session`}
                                </TooltipContent>
                              </Tooltip>
                            )}
                            {s.tags.map((t) => (
                              <Badge key={t} variant="secondary" className="font-normal">
                                {t}
                              </Badge>
                            ))}
                          </div>
                          {folderId === null && s.folderId && (
                            <div className="text-xs text-muted-foreground">{folderPath(folders, s.folderId)}</div>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {kindOf(s).protocol === "serial" ? (
                            <span>{address(s)}</span>
                          ) : (
                            <span data-mask="address">{address(s)}</span>
                          )}
                          {kindOf(s).protocol !== "ssh" && (
                            <div className="font-sans text-muted-foreground">{kindLabel(kindOf(s).protocol)}</div>
                          )}
                          {(s.lastHostname || s.lastIp) && (
                            <div
                              className="font-sans text-muted-foreground"
                              title={`What the last connection saw, ${formatWhen(s.lastSeenAt)}`}
                            >
                              {[s.lastHostname, s.lastIp].filter(Boolean).join(" · ")}
                            </div>
                          )}
                        </TableCell>
                        <TableCell className="text-sm">
                          {login(s.auth)}
                          {s.inherited.auth && <FromNote text={`from folder ${s.inherited.auth.name}`} />}
                        </TableCell>
                        <TableCell className="text-sm" title={chainTitle(s.id)}>
                          {s.jumpSessionId ? (
                            (sessionName.get(s.jumpSessionId) ?? "—")
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                          {s.inherited.jump && <FromNote text={`from folder ${s.inherited.jump.name}`} />}
                        </TableCell>
                        {/* Its own menu: a double-click there doesn't connect. */}
                        <TableCell onDoubleClick={(e) => e.stopPropagation()}>
                          <SessionVmLink
                            session={s}
                            vms={vms}
                            candidates={ambiguous.get(s.id) ?? []}
                            onChanged={reload}
                          />
                        </TableCell>
                        <TableCell className="whitespace-normal" title={environmentText(applied)}>
                          <EnvBadge env={applied.environment} />
                          {applied.from && <FromNote text={sourceText(applied.from)} />}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center justify-end gap-0.5">
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="icon-sm"
                                  aria-label={`Connect to ${s.name}`}
                                  onClick={() => connect(s)}
                                >
                                  <TerminalIcon />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>Connect (or double-click the row)</TooltipContent>
                            </Tooltip>
                            <RowMenu label={s.name}>
                              <DropdownMenuItem onSelect={() => setDialog({ kind: "editSession", session: s })}>
                                Edit…
                              </DropdownMenuItem>
                              <DropdownMenuItem onSelect={() => setHostDetails({ id: s.id, name: s.name })}>
                                Host details…
                              </DropdownMenuItem>
                              <DropdownMenuItem onSelect={() => requestLink(noteLink("session", s.id, s.name))}>
                                Note…
                              </DropdownMenuItem>
                              <DropdownMenuItem onSelect={() => void duplicate(s)}>Duplicate</DropdownMenuItem>
                              {kindOf(s).protocol !== "serial" && (
                                <ToolboxMenu target={{ kind: "session", sessionId: s.id, label: s.name }} />
                              )}
                              <DropdownMenuSub>
                                <DropdownMenuSubTrigger>Move to</DropdownMenuSubTrigger>
                                <DropdownMenuSubContent>
                                  <DropdownMenuItem disabled={s.folderId === null} onSelect={() => void move(s, null)}>
                                    Top level
                                  </DropdownMenuItem>
                                  {rows.map(({ folder: f }) => (
                                    <DropdownMenuItem
                                      key={f.id}
                                      disabled={s.folderId === f.id}
                                      onSelect={() => void move(s, f.id)}
                                    >
                                      {folderPath(folders, f.id)}
                                    </DropdownMenuItem>
                                  ))}
                                </DropdownMenuSubContent>
                              </DropdownMenuSub>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                variant="destructive"
                                onSelect={() => setDialog({ kind: "deleteSession", session: s })}
                              >
                                Delete…
                              </DropdownMenuItem>
                            </RowMenu>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </div>

        <HostDetailsSheet session={hostDetails} thresholds={thresholds} onClose={() => setHostDetails(null)} />
        {dialog?.kind === "editSession" && (
          <SessionDialog
            vault={vault}
            session={dialog.session}
            folderId={folderId}
            folders={folders}
            sessions={all}
            tagSuggestions={tags.map((t) => t.name)}
            onVaultChanged={onVaultChanged}
            onSaved={(saved) => {
              toast.success(dialog.session ? `Saved '${saved.name}'` : `Created '${saved.name}'`);
              reload();
            }}
            onClose={() => setDialog(null)}
          />
        )}
        {dialog?.kind === "deleteSession" && (
          <ConfirmDialog
            title={`Delete '${dialog.session.name}'?`}
            description={
              all.some((s) => s.jumpSessionId === dialog.session.id)
                ? "Sessions that use it as their jump host will connect directly afterwards. It goes to the trash for 30 days; its passwords and keys stay in the vault."
                : "It goes to the trash for 30 days, with its port forwards and note. Its passwords and keys stay in the vault."
            }
            confirmLabel="Delete"
            onConfirm={async () => {
              const { id, name } = dialog.session;
              await api.deleteSession(id);
              reload();
              toastDeleted("session", id, name, reload);
            }}
            onClose={() => setDialog(null)}
          />
        )}
        {dialog?.kind === "newFolder" && (
          <NameDialog
            title={dialog.parentId ? `New folder in ${folderPath(folders, dialog.parentId)}` : "New folder"}
            description="Folders are Remotely's own way to sort sessions, e.g. by customer or site."
            label="Name"
            submitLabel="Create"
            onSubmit={async (name) => {
              const created = await api.createFolder(name, dialog.parentId);
              setFolderId(created.id);
              reload();
            }}
            onClose={() => setDialog(null)}
          />
        )}
        {dialog?.kind === "renameFolder" && (
          <NameDialog
            title={`Rename ${dialog.folder.name}`}
            description="Its sessions and folders stay in it."
            label="Name"
            submitLabel="Rename"
            initial={dialog.folder.name}
            onSubmit={async (name) => {
              await api.renameFolder(dialog.folder.id, name);
              reload();
            }}
            onClose={() => setDialog(null)}
          />
        )}
        {dialog?.kind === "folderDefaults" && (
          <FolderDefaultsDialog
            folder={dialog.folder}
            folders={folders}
            sessions={all}
            onSaved={() => reload()}
            onClose={() => setDialog(null)}
          />
        )}
        {dialog?.kind === "deleteFolder" && (
          <ConfirmDialog
            title={`Delete the folder ${dialog.folder.name}?`}
            description={`Only the folder goes: its ${plural(
              all.filter((s) => s.folderId === dialog.folder.id).length,
              "session",
            )} and ${plural(
              folders.filter((f) => f.parentId === dialog.folder.id).length,
              "folder",
            )} move to ${dialog.folder.parentId ? folderPath(folders, dialog.folder.parentId) : "the top level"}.`}
            confirmLabel="Delete folder"
            onConfirm={async () => {
              await withVaultPassword((password) => api.deleteFolder(dialog.folder.id, password));
              if (folderId === dialog.folder.id) setFolderId(dialog.folder.parentId);
              reload();
            }}
            onClose={() => setDialog(null)}
          />
        )}
        {dialog?.kind === "import" && (
          <ImportDialog
            folders={folders}
            folderId={folderId}
            vault={vault}
            onVaultChanged={onVaultChanged}
            onOpenVault={onOpenVault}
            onImported={reload}
            onClose={() => setDialog(null)}
          />
        )}
        {dialog?.kind === "export" && (
          <ExportDialog
            sessions={all.length}
            folders={folders.length}
            vault={vault}
            onVaultChanged={onVaultChanged}
            onExported={(report) =>
              toast.success(
                `Exported ${plural(report.sessions, "session")}${report.favourites ? ` and ${plural(report.favourites, "favourite command")}` : ""}`,
                { description: report.path },
              )
            }
            onClose={() => setDialog(null)}
          />
        )}
        {dialog?.kind === "bulkEdit" && (
          <BulkEditDialog
            sessions={selectedSessions}
            all={all}
            folders={folders}
            secrets={secrets}
            onSaved={() => {
              setSelected(new Set());
              reload();
            }}
            onClose={() => setDialog(null)}
          />
        )}
        {dialog?.kind === "importExport" && (
          <TransferImportDialog
            vault={vault}
            onVaultChanged={onVaultChanged}
            onImported={reload}
            onClose={() => setDialog(null)}
          />
        )}
      </div>
    </div>
  );
}

function FolderButton({
  active,
  onClick,
  count,
  depth,
  children,
}: {
  active: boolean;
  onClick: () => void;
  count: number;
  depth: number;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex h-8 min-w-0 flex-1 items-center gap-2 self-stretch rounded-md px-2 text-left text-sm hover:bg-accent [&_svg]:size-4 [&_svg]:shrink-0",
        active && "bg-accent font-medium",
      )}
      style={{ paddingLeft: `${0.5 + depth * 0.875}rem` }}
      aria-current={active || undefined}
    >
      {children}
      <span className="ml-auto text-xs text-muted-foreground tabular-nums">{count}</span>
    </button>
  );
}
