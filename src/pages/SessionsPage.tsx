// Session library (SS-01, SS-06): folders on the left; search, label and tag filters and the session list
// on the right. Each session shows its colour, environment label, address, how it logs in and its jump
// host (SS-07: the whole chain on hover). Creating, editing and organising sessions is the app's own data (audited, no approval). Connect
// (or a double-click) opens the session in a terminal tab (SS-03); Import reads PuTTY, MobaXterm,
// OpenSSH and CSV session lists (SS-02). The VM column shows the VM each session reaches (QL-01),
// linked automatically by IP address or by hand, and lets the user keep, change or remove the link.
// Export and "Import from another laptop" move the library between the owner's laptops in one encrypted
// file (FD-07).
// Under the address: the host name and IP the last connection saw (QL-03).

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { jumpChain, routeText } from "@/lib/tunnels";
import {
  EllipsisIcon,
  FileLockIcon,
  FolderIcon,
  FolderOpenIcon,
  FolderPlusIcon,
  ImportIcon,
  KeyRoundIcon,
  LaptopIcon,
  LibraryIcon,
  ListTreeIcon,
  PlusIcon,
  SearchIcon,
  ShieldIcon,
  TagIcon,
  TerminalIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ColorDot, EnvBadge } from "@/components/Badges";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ExportDialog } from "@/components/ExportDialog";
import { FolderDefaultsDialog } from "@/components/FolderDefaultsDialog";
import { HostDetailsSheet } from "@/components/HostDetailsSheet";
import { ImportDialog } from "@/components/ImportDialog";
import { NameDialog } from "@/components/NameDialog";
import { SessionDialog } from "@/components/SessionDialog";
import { TransferImportDialog } from "@/components/TransferImportDialog";
import { SessionVmLink } from "@/components/VmLinkControls";
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
import { useThresholds } from "@/lib/metrics";
import { withVaultPassword } from "@/lib/reauth-prompt";
import { cn } from "@/lib/utils";

interface Props {
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  onOpenVault: () => void;
  /** SS-03: opens the session in a new terminal tab. */
  onConnect: (sessionId: string) => void;
  /** True while the page is shown, so the lists are read again when the user comes back. */
  active: boolean;
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
  | null;

const LABELS: { value: Environment; label: string; className: string }[] = [
  { value: "lab", label: "Lab", className: "data-[state=on]:text-env-lab" },
  { value: "staging", label: "Staging", className: "data-[state=on]:text-env-staging" },
  { value: "prod", label: "Prod", className: "data-[state=on]:text-env-prod" },
];

function address(s: SessionRecord) {
  return `${s.username ? `${s.username}@` : ""}${s.host}${s.port === 22 ? "" : `:${s.port}`}`;
}

/** QL-16: a value the session has from a folder rather than its own. */
function FromFolderNote({ name }: { name: string }) {
  return <div className="text-xs text-muted-foreground">from folder &apos;{name}&apos;</div>;
}

export function SessionsPage({ vault, onVaultChanged, onOpenVault, onConnect, active }: Props) {
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
  /** MO-13, MO-14: a session's host details. */
  const [hostDetails, setHostDetails] = useState<{ id: string; name: string } | null>(null);
  const [thresholds] = useThresholds();

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

  /** SS-07: a session behind jump hosts connects through them; the terminal says how. */
  function connect(session: SessionRecord) {
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

  return (
    <div className="flex min-h-0 flex-col gap-4 md:flex-row">
      <aside className="flex shrink-0 flex-col gap-1 md:w-60">
        <div className="mb-1 flex items-center justify-between">
          <span className="text-sm font-medium text-muted-foreground">Folders</span>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="New folder"
            title="New folder"
            onClick={() => setDialog({ kind: "newFolder", parentId: null })}
          >
            <FolderPlusIcon />
          </Button>
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
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  className="opacity-0 group-hover/folder:opacity-100 focus-visible:opacity-100 data-[state=open]:opacity-100"
                  aria-label={`Actions for folder ${folder.name}`}
                >
                  <EllipsisIcon />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start">
                <DropdownMenuItem onSelect={() => setDialog({ kind: "newFolder", parentId: folder.id })}>
                  New folder inside…
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setDialog({ kind: "renameFolder", folder })}>
                  Rename…
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setDialog({ kind: "folderDefaults", folder })}>
                  Defaults…
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
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        ))}
      </aside>

      <div className="flex min-w-0 flex-1 flex-col gap-4">
        <div className="flex flex-wrap items-center gap-2">
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
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="ml-auto">
                <ImportIcon data-icon="inline-start" />
                Import
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={() => setDialog({ kind: "import" })}>
                <ImportIcon />
                From PuTTY, MobaXterm, OpenSSH or CSV…
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setDialog({ kind: "importExport" })}>
                <LaptopIcon />
                From another laptop (Remotely export)…
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button variant="outline" disabled={all.length === 0} onClick={() => setDialog({ kind: "export" })}>
            <FileLockIcon data-icon="inline-start" />
            Export
          </Button>
          <Button onClick={() => setDialog({ kind: "editSession" })}>
            <PlusIcon data-icon="inline-start" />
            New session
          </Button>
        </div>

        {vault?.status === "notSetUp" && (
          <p className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <KeyRoundIcon className="size-4" aria-hidden />
            Sessions can log in with passwords and keys from the vault once it is set up.
            <Button variant="link" className="h-auto p-0" onClick={onOpenVault}>
              Set up the vault
            </Button>
          </p>
        )}

        {loaded && all.length === 0 && (
          <Empty className="border">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <ListTreeIcon />
              </EmptyMedia>
              <EmptyTitle>No sessions yet</EmptyTitle>
              <EmptyDescription>
                Save the SSH hosts you work with: host, user, how to log in, a jump host and a startup command. Sort
                them into folders, tag them and label Prod hosts so actions on them need more approval.
              </EmptyDescription>
            </EmptyHeader>
            <EmptyContent className="flex-row justify-center">
              <Button onClick={() => setDialog({ kind: "editSession" })}>
                <PlusIcon data-icon="inline-start" />
                New session
              </Button>
              <Button variant="outline" onClick={() => setDialog({ kind: "import" })}>
                <ImportIcon data-icon="inline-start" />
                Import from PuTTY, MobaXterm…
              </Button>
              <Button variant="outline" onClick={() => setDialog({ kind: "importExport" })}>
                <LaptopIcon data-icon="inline-start" />
                Import from another laptop…
              </Button>
            </EmptyContent>
          </Empty>
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
                  <TableHead>Name</TableHead>
                  <TableHead>Address</TableHead>
                  <TableHead>Login</TableHead>
                  <TableHead>Via</TableHead>
                  <TableHead>VM</TableHead>
                  <TableHead className="w-20">Label</TableHead>
                  <TableHead className="w-20">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {shown.map((s) => (
                  <TableRow
                    key={s.id}
                    className={cn("select-none", s.environment === "prod" && "bg-env-prod/5")}
                    onDoubleClick={() => connect(s)}
                  >
                    <TableCell className="whitespace-normal">
                      <div className="flex flex-wrap items-center gap-1.5 font-medium">
                        <span className="inline-flex items-center gap-1.5">
                          <ColorDot color={s.color} />
                          {s.name}
                        </span>
                        {s.protected && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <ShieldIcon className="size-3.5 text-tier-high" aria-label="Protected" />
                            </TooltipTrigger>
                            <TooltipContent>Protected: bulk actions skip this session</TooltipContent>
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
                      <span data-mask="address">{address(s)}</span>
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
                      {s.inherited.auth && <FromFolderNote name={s.inherited.auth.name} />}
                    </TableCell>
                    <TableCell className="text-sm" title={chainTitle(s.id)}>
                      {s.jumpSessionId ? (
                        (sessionName.get(s.jumpSessionId) ?? "—")
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                      {s.inherited.jump && <FromFolderNote name={s.inherited.jump.name} />}
                    </TableCell>
                    {/* Its own menu: a double-click there doesn't connect. */}
                    <TableCell onDoubleClick={(e) => e.stopPropagation()}>
                      <SessionVmLink session={s} vms={vms} candidates={ambiguous.get(s.id) ?? []} onChanged={reload} />
                    </TableCell>
                    <TableCell>
                      <EnvBadge env={s.environment} />
                      {s.inherited.environment && <FromFolderNote name={s.inherited.environment.name} />}
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
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${s.name}`}>
                              <EllipsisIcon />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" className="w-52">
                            <DropdownMenuItem onSelect={() => connect(s)}>Connect</DropdownMenuItem>
                            <DropdownMenuItem onSelect={() => setHostDetails({ id: s.id, name: s.name })}>
                              Host details…
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem onSelect={() => setDialog({ kind: "editSession", session: s })}>
                              Edit…
                            </DropdownMenuItem>
                            <DropdownMenuItem onSelect={() => void duplicate(s)}>Duplicate</DropdownMenuItem>
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
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
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
              ? "Sessions that use it as their jump host will connect directly afterwards. Its passwords and keys stay in the vault."
              : "Its passwords and keys stay in the vault."
          }
          confirmLabel="Delete"
          onConfirm={async () => {
            await api.deleteSession(dialog.session.id);
            reload();
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
      {dialog?.kind === "importExport" && (
        <TransferImportDialog
          vault={vault}
          onVaultChanged={onVaultChanged}
          onImported={reload}
          onClose={() => setDialog(null)}
        />
      )}
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
