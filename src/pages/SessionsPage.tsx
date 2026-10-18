// Session library (SS-01, SS-06): folders on the left; search, label and tag filters and the session list
// on the right. Each session shows its colour, environment label, address, how it logs in and its jump
// host. Creating, editing and organising sessions is the app's own data (audited, no approval);
// connecting comes with the terminal (SS-03).

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import {
  EllipsisIcon,
  FolderIcon,
  FolderOpenIcon,
  FolderPlusIcon,
  KeyRoundIcon,
  LibraryIcon,
  ListTreeIcon,
  PlusIcon,
  SearchIcon,
  ShieldIcon,
  TagIcon,
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
import { NameDialog } from "@/components/NameDialog";
import { SessionDialog } from "@/components/SessionDialog";
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
} from "@/lib/api";
import { flattenFolders, folderPath, subtree } from "@/lib/folders";
import { plural } from "@/lib/format";
import { cn } from "@/lib/utils";

interface Props {
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  onOpenVault: () => void;
  /** True while the page is shown, so the lists are read again when the user comes back. */
  active: boolean;
}

type DialogState =
  | { kind: "editSession"; session?: SessionRecord }
  | { kind: "deleteSession"; session: SessionRecord }
  | { kind: "newFolder"; parentId: string | null }
  | { kind: "renameFolder"; folder: SessionFolder }
  | { kind: "deleteFolder"; folder: SessionFolder }
  | null;

const LABELS: { value: Environment; label: string; className: string }[] = [
  { value: "lab", label: "Lab", className: "data-[state=on]:text-env-lab" },
  { value: "staging", label: "Staging", className: "data-[state=on]:text-env-staging" },
  { value: "prod", label: "Prod", className: "data-[state=on]:text-env-prod" },
];

function address(s: SessionRecord) {
  return `${s.username ? `${s.username}@` : ""}${s.host}${s.port === 22 ? "" : `:${s.port}`}`;
}

export function SessionsPage({ vault, onVaultChanged, onOpenVault, active }: Props) {
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

  const reload = useCallback(() => setVersion((v) => v + 1), []);

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
    }
  }

  async function move(session: SessionRecord, target: string | null) {
    try {
      await api.moveSessions([session.id], target);
      reload();
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function moveFolder(folder: SessionFolder, parentId: string | null) {
    try {
      await api.moveFolder(folder.id, parentId);
      reload();
    } catch (err) {
      toast.error(errorMessage(err));
    }
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
          <Button className="ml-auto" onClick={() => setDialog({ kind: "editSession" })}>
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
            <EmptyContent>
              <Button onClick={() => setDialog({ kind: "editSession" })}>
                <PlusIcon data-icon="inline-start" />
                New session
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
                  <TableHead className="w-20">Label</TableHead>
                  <TableHead className="w-10">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {shown.map((s) => (
                  <TableRow
                    key={s.id}
                    className={cn("select-none", s.environment === "prod" && "bg-env-prod/5")}
                    onDoubleClick={() => setDialog({ kind: "editSession", session: s })}
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
                    <TableCell className="font-mono text-xs">{address(s)}</TableCell>
                    <TableCell className="text-sm">{login(s.auth)}</TableCell>
                    <TableCell className="text-sm">
                      {s.jumpSessionId ? (
                        (sessionName.get(s.jumpSessionId) ?? "—")
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <EnvBadge env={s.environment} />
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${s.name}`}>
                            <EllipsisIcon />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-52">
                          <DropdownMenuItem disabled>
                            Connect
                            <DropdownMenuShortcut>SS-03</DropdownMenuShortcut>
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
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

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
            await api.deleteFolder(dialog.folder.id);
            if (folderId === dialog.folder.id) setFolderId(dialog.folder.parentId);
            reload();
          }}
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
