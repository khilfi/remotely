// BX-08: the command panel on the right of the Terminal page. Favourites are the user's saved commands in folders
// (add, edit, reorder, delete); the Library holds common Linux commands, grouped, each with a short description. Every
// command shows what the policy engine makes of it with the current rules (read-only, changes, dangerous). Click
// pastes into the current terminal without pressing Enter; Shift+click also presses Enter. A command with
// {{variables}} asks for them first. Any library entry can be copied into the favourites.

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import {
  ArrowDownIcon,
  ArrowUpIcon,
  BookOpenIcon,
  ChevronRightIcon,
  EllipsisIcon,
  FolderIcon,
  FolderOpenIcon,
  PencilIcon,
  PlusIcon,
  SearchIcon,
  StarIcon,
  Trash2Icon,
  XIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { RiskBadge } from "@/components/Badges";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { FavouriteDialog } from "@/components/FavouriteDialog";
import { FillCommandDialog } from "@/components/FillCommandDialog";
import { ReasonLine } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type CommandRisk,
  type CommandVariable,
  type Favourite,
  type FavouriteInput,
  type LibraryEntry,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const SECTION_KEY = "remotely.terminal.commandsSection";
const OPEN_KEY = "remotely.terminal.commandsOpen";

type Section = "favourites" | "library";

/** QL-08: why a favourite can't move while the list is searched. */
const MOVE_SEARCHING = "Clear the search to reorder";

/** One command as the panel lists it. */
interface Item {
  key: string;
  name: string;
  command: string;
  description: string | null;
  variables: CommandVariable[];
  risk: CommandRisk;
  favourite?: Favourite;
  library?: LibraryEntry;
}

interface Group {
  key: string;
  label: string;
  /** Favourites: the folder name, or null for the top level. */
  folder?: string | null;
  items: Item[];
}

function readJson<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function matches(item: Item, group: string, words: string[]) {
  const text = `${item.name} ${item.command} ${item.description ?? ""} ${group}`.toLowerCase();
  return words.every((w) => text.includes(w));
}

interface Props {
  /** The page is shown: lists reload when it comes back (rules may have changed in Settings). */
  active: boolean;
  /** Where a click pastes, e.g. "web01"; null when no terminal is open. */
  targetName: string | null;
  /** Pastes into the current terminal (and presses Enter when `enter`). False when it is not connected. */
  onSend: (command: string, enter: boolean) => boolean;
  onClose: () => void;
}

export function CommandPanel({ active, targetName, onSend, onClose }: Props) {
  const [section, setSection] = useState<Section>(() => readJson(SECTION_KEY, "favourites"));
  const [favourites, setFavourites] = useState<Favourite[]>([]);
  const [library, setLibrary] = useState<LibraryEntry[]>([]);
  const [text, setText] = useState("");
  const [open, setOpen] = useState<Record<string, boolean>>(() => readJson(OPEN_KEY, {}));
  const [editing, setEditing] = useState<{ existing?: Favourite; initial?: Partial<FavouriteInput> } | null>(null);
  const [deleting, setDeleting] = useState<Favourite | null>(null);
  const [filling, setFilling] = useState<{ item: Item; run: boolean } | null>(null);

  const load = useCallback(() => {
    Promise.all([api.favourites(), api.commandLibrary()]).then(
      ([f, l]) => {
        setFavourites(f);
        setLibrary(l);
      },
      (err) => toast.error(errorMessage(err)),
    );
  }, []);

  useEffect(() => {
    if (active) load();
  }, [active, load]);

  useEffect(() => {
    try {
      localStorage.setItem(SECTION_KEY, JSON.stringify(section));
      localStorage.setItem(OPEN_KEY, JSON.stringify(open));
    } catch {
      // Private storage off: the panel just forgets.
    }
  }, [section, open]);

  const words = text.toLowerCase().split(/\s+/).filter(Boolean);
  const searching = words.length > 0;

  const favouriteGroups = useMemo<Group[]>(() => {
    const groups = new Map<string, Group>();
    for (const f of favourites) {
      const key = `fav:${(f.folder ?? "").toLowerCase()}`;
      const group = groups.get(key) ?? { key, label: f.folder ?? "", folder: f.folder, items: [] };
      group.items.push({
        key: f.id,
        name: f.name,
        command: f.command,
        description: f.description,
        variables: f.variables,
        risk: f.risk,
        favourite: f,
      });
      groups.set(key, group);
    }
    return [...groups.values()];
  }, [favourites]);

  const libraryGroups = useMemo<Group[]>(() => {
    const groups = new Map<string, Group>();
    for (const e of library) {
      const key = `lib:${e.group}`;
      const group = groups.get(key) ?? { key, label: e.groupLabel, items: [] };
      group.items.push({
        key: e.id,
        name: e.name,
        command: e.command,
        description: e.description,
        variables: e.variables,
        risk: e.risk,
        library: e,
      });
      groups.set(key, group);
    }
    return [...groups.values()];
  }, [library]);

  const folders = useMemo(
    () => favouriteGroups.map((g) => g.folder).filter((f): f is string => Boolean(f)),
    [favouriteGroups],
  );

  function filter(groups: Group[]) {
    if (!searching) return groups;
    return groups
      .map((g) => ({ ...g, items: g.items.filter((i) => matches(i, g.label, words)) }))
      .filter((g) => g.items.length > 0);
  }

  function pick(item: Item, run: boolean) {
    if (!targetName) {
      toast.info("Open a terminal first: a command goes into the current terminal.");
      return;
    }
    if (item.variables.length > 0) {
      setFilling({ item, run });
      return;
    }
    send(item.command, run);
  }

  function send(command: string, enter: boolean) {
    if (!onSend(command, enter)) toast.info(`${targetName ?? "The terminal"} is not connected, so nothing was pasted.`);
  }

  async function move(group: Group, item: Favourite, by: -1 | 1) {
    const ids = group.items.map((i) => i.key);
    const at = ids.indexOf(item.id);
    const to = at + by;
    if (at < 0 || to < 0 || to >= ids.length) return;
    [ids[at], ids[to]] = [ids[to], ids[at]];
    try {
      setFavourites(await api.reorderFavourites(group.folder ?? null, ids));
    } catch (err) {
      toast.error(errorMessage(err));
      load();
    }
  }

  const isOpen = (key: string, byDefault: boolean) => searching || (open[key] ?? byDefault);

  const groupView = (group: Group, byDefault: boolean) => {
    const expanded = isOpen(group.key, byDefault);
    const topLevel = group.folder === null;
    return (
      <div key={group.key} role="group" aria-label={group.label || "Favourites"}>
        {!topLevel && (
          <button
            type="button"
            className="flex h-7 w-full min-w-0 items-center gap-1.5 rounded-md px-1 text-left text-sm hover:bg-accent [&_svg]:size-3.5 [&_svg]:shrink-0"
            aria-expanded={expanded}
            onClick={() => setOpen((prev) => ({ ...prev, [group.key]: !expanded }))}
          >
            <ChevronRightIcon className={cn("text-muted-foreground transition-transform", expanded && "rotate-90")} />
            {group.folder !== undefined ? (
              expanded ? (
                <FolderOpenIcon className="text-muted-foreground" />
              ) : (
                <FolderIcon className="text-muted-foreground" />
              )
            ) : (
              <BookOpenIcon className="text-muted-foreground" />
            )}
            <span className="min-w-0 flex-1 truncate font-medium">{group.label}</span>
            <span className="text-xs text-muted-foreground tabular-nums">{group.items.length}</span>
          </button>
        )}
        {(expanded || topLevel) && (
          <ul className={cn("grid gap-0.5", !topLevel && "pl-3")}>
            {group.items.map((item, i) => (
              <CommandRow
                key={item.key}
                item={item}
                first={i === 0}
                last={i === group.items.length - 1}
                canMove={!searching}
                onPick={(run) => pick(item, run)}
                onEdit={() => item.favourite && setEditing({ existing: item.favourite })}
                onDelete={() => item.favourite && setDeleting(item.favourite)}
                onMove={(by) => item.favourite && void move(group, item.favourite, by)}
                onCopy={() =>
                  item.library &&
                  setEditing({
                    initial: {
                      folder: item.library.groupLabel,
                      name: item.library.name,
                      command: item.library.command,
                      description: item.library.description,
                    },
                  })
                }
              />
            ))}
          </ul>
        )}
      </div>
    );
  };

  const shownFavourites = filter(favouriteGroups);
  const shownLibrary = filter(libraryGroups);

  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="flex items-center gap-1">
        <span className="min-w-0 flex-1 truncate text-sm font-medium">Commands</span>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label="New favourite command"
          title="New favourite command"
          onClick={() => setEditing({ initial: {} })}
        >
          <PlusIcon />
        </Button>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label="Hide the commands"
          title="Hide the commands"
          onClick={onClose}
        >
          <XIcon />
        </Button>
      </div>
      <div className="relative">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input
          aria-label="Search commands"
          placeholder="Search commands"
          className="h-8 pl-7 text-sm"
          value={text}
          onChange={(e) => setText(e.currentTarget.value)}
        />
      </div>
      <Tabs value={section} onValueChange={(v) => setSection(v as Section)} className="min-h-0 flex-1">
        <TabsList className="w-full">
          <TabsTrigger value="favourites">
            <StarIcon />
            Favourites
          </TabsTrigger>
          <TabsTrigger value="library">
            <BookOpenIcon />
            Library
          </TabsTrigger>
        </TabsList>
        <TabsContent value="favourites" className="min-h-0">
          <ScrollArea className="h-full pr-2">
            {favourites.length === 0 ? (
              <Empty className="border">
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <StarIcon />
                  </EmptyMedia>
                  <EmptyTitle>No favourites yet</EmptyTitle>
                  <EmptyDescription>
                    Add your own commands with +, or copy one from the Library (its ⋯ menu).
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>
            ) : shownFavourites.length === 0 ? (
              <p className="px-1 py-2 text-sm text-muted-foreground">No favourite matches.</p>
            ) : (
              <div className="grid gap-1">{shownFavourites.map((g) => groupView(g, true))}</div>
            )}
          </ScrollArea>
        </TabsContent>
        <TabsContent value="library" className="min-h-0">
          <ScrollArea className="h-full pr-2">
            {shownLibrary.length === 0 ? (
              <p className="px-1 py-2 text-sm text-muted-foreground">No command in the library matches.</p>
            ) : (
              <div className="grid gap-1">{shownLibrary.map((g) => groupView(g, false))}</div>
            )}
          </ScrollArea>
        </TabsContent>
      </Tabs>
      <p className="text-xs text-muted-foreground">
        {targetName ? (
          <>
            Click pastes into <span className="font-medium text-foreground">{targetName}</span>; Shift+click also
            presses Enter.
          </>
        ) : (
          "Open a terminal: a click pastes the command into it, Shift+click also presses Enter."
        )}
      </p>
      {editing && (
        <FavouriteDialog
          existing={editing.existing}
          initial={editing.initial}
          folders={folders}
          onSaved={(saved) => {
            load();
            if (!editing.existing) {
              setSection("favourites");
              toast.success(`Added '${saved.name}' to the favourites`);
            }
          }}
          onClose={() => setEditing(null)}
        />
      )}
      {deleting && (
        <ConfirmDialog
          title={`Delete '${deleting.name}'?`}
          description="It goes from your favourite commands. The Library's commands stay."
          confirmLabel="Delete"
          onConfirm={async () => {
            await api.deleteFavourite(deleting.id);
            load();
          }}
          onClose={() => setDeleting(null)}
        />
      )}
      {filling && (
        <FillCommandDialog
          name={filling.item.name}
          command={filling.item.command}
          variables={filling.item.variables}
          risk={filling.item.risk}
          target={targetName ?? "the terminal"}
          run={filling.run}
          onSend={send}
          onClose={() => setFilling(null)}
        />
      )}
    </div>
  );
}

function CommandRow({
  item,
  first,
  last,
  canMove,
  onPick,
  onEdit,
  onDelete,
  onMove,
  onCopy,
}: {
  item: Item;
  first: boolean;
  last: boolean;
  canMove: boolean;
  onPick: (run: boolean) => void;
  onEdit: () => void;
  onDelete: () => void;
  onMove: (by: -1 | 1) => void;
  onCopy: () => void;
}) {
  const tooltip = [item.description, item.command, "Click pastes; Shift+click also presses Enter."]
    .filter(Boolean)
    .join("\n\n");
  return (
    <li className="group/row flex min-w-0 items-start gap-1 rounded-md hover:bg-accent">
      <button
        type="button"
        className="grid min-w-0 flex-1 gap-0.5 px-1.5 py-1 text-left"
        title={tooltip}
        onClick={(e) => onPick(e.shiftKey)}
      >
        <span className="flex min-w-0 items-center gap-1.5">
          <span className="min-w-0 flex-1 truncate text-sm">{item.name}</span>
          {item.risk.action !== "execReadOnly" && <RiskBadge risk={item.risk} className="h-4 px-1.5 text-[10px]" />}
        </span>
        <span className="truncate font-mono text-[11px] text-muted-foreground">{item.command}</span>
      </button>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon-xs"
            className="mt-1 opacity-0 group-hover/row:opacity-100 focus-visible:opacity-100 data-[state=open]:opacity-100"
            aria-label={`More for ${item.name}`}
          >
            <EllipsisIcon />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onSelect={() => onPick(false)}>Paste</DropdownMenuItem>
          <DropdownMenuItem onSelect={() => onPick(true)}>Paste and run</DropdownMenuItem>
          <DropdownMenuSeparator />
          {item.favourite ? (
            <>
              <DropdownMenuItem onSelect={onEdit}>
                <PencilIcon />
                Edit…
              </DropdownMenuItem>
              <DropdownMenuItem disabled={!canMove || first} onSelect={() => onMove(-1)}>
                <ArrowUpIcon />
                <span>
                  Move up
                  <ReasonLine reason={!canMove ? MOVE_SEARCHING : first ? "Already the first in its folder" : null} />
                </span>
              </DropdownMenuItem>
              <DropdownMenuItem disabled={!canMove || last} onSelect={() => onMove(1)}>
                <ArrowDownIcon />
                <span>
                  Move down
                  <ReasonLine reason={!canMove ? MOVE_SEARCHING : last ? "Already the last in its folder" : null} />
                </span>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem variant="destructive" onSelect={onDelete}>
                <Trash2Icon />
                Delete…
              </DropdownMenuItem>
            </>
          ) : (
            <DropdownMenuItem onSelect={onCopy}>
              <StarIcon />
              Copy to favourites…
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    </li>
  );
}
