// SS-14 (0.8.0 G3): the table both panes of the Files page show: folders first, a sortable header, a click picks a
// row (Ctrl adds, Shift picks a range), double-click opens, each row has its "⋯" menu, and dragging picked rows starts
// a drag the page carries to the other pane (pointer events: the window's own drop handler for Explorer files turns
// HTML drag and drop off on Windows). Host folder rows are drop targets (`data-files-folder`).

import { useRef, type PointerEvent as ReactPointerEvent, type ReactNode } from "react";
import { FileIcon, FolderIcon, HardDriveIcon, LinkIcon } from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { RowMenu } from "@/components/RowMenu";
import { SortableHead } from "@/components/SortableHead";
import { clickPick, type PaneEntry, type PaneSort, type PaneView } from "@/lib/files-page";
import { formatSize } from "@/lib/transfers";
import { cn } from "@/lib/utils";

interface Props<T extends PaneEntry> {
  /** For the checkboxes' labels: "this PC" or the host's name. */
  label: string;
  entries: T[];
  view: PaneView;
  onView: (view: PaneView) => void;
  picked: string[];
  anchor: string | null;
  onPick: (picked: string[], anchor: string | null) => void;
  /** Double-click or Enter. */
  onOpen: (entry: T) => void;
  /** The "⋯" menu's items for a row. */
  menu: (entry: T) => ReactNode;
  /** A drag of these names began (the pointer moved with the button down). */
  onDragStart?: (names: string[], at: { clientX: number; clientY: number }) => void;
  /** The drag ended there (the row keeps the pointer while it drags, so this comes wherever it is let go). */
  onDragEnd?: (x: number, y: number) => void;
  /** Folder rows carry `data-files-folder` with this path, so a drop can go into them. */
  folderPath?: (entry: T) => string | null;
  /** A row's title (what double-click does). */
  rowTitle?: (entry: T) => string;
  /** A drive in the drives view. */
  isDrive?: (entry: T) => boolean;
  empty: string;
  loading?: boolean;
}

const DRAG_START_PX = 6;

export function FileTable<T extends PaneEntry>({
  label,
  entries,
  view,
  onView,
  picked,
  anchor,
  onPick,
  onOpen,
  menu,
  onDragStart,
  onDragEnd,
  folderPath,
  rowTitle,
  isDrive,
  empty,
  loading = false,
}: Props<T>) {
  const names = entries.map((e) => e.name);
  const press = useRef<{ x: number; y: number; name: string; started: boolean } | null>(null);

  function sortBy(sort: PaneSort) {
    onView({ ...view, sort, dir: view.sort === sort ? (view.dir === 1 ? -1 : 1) : 1 });
  }

  function down(e: ReactPointerEvent, entry: T) {
    if (e.button !== 0) return;
    press.current = { x: e.clientX, y: e.clientY, name: entry.name, started: false };
    if (!onDragStart) return;
    // The window follows the pointer until it is let go, wherever it goes: a quick drag leaves the row at once.
    const startDrag = onDragStart;
    const move = (ev: PointerEvent) => {
      const p = press.current;
      if (!p || p.started) return;
      if (Math.hypot(ev.clientX - p.x, ev.clientY - p.y) < DRAG_START_PX) return;
      p.started = true;
      // While it drags, the pointer selects no text on the page.
      document.body.classList.add("select-none");
      window.getSelection()?.removeAllRanges();
      // Dragging a row that isn't picked drags that row alone.
      const dragged = picked.includes(p.name) ? picked : [p.name];
      if (!picked.includes(p.name)) onPick([p.name], p.name);
      startDrag(dragged, ev);
    };
    const up = (ev: PointerEvent) => {
      window.removeEventListener("pointermove", move);
      const p = press.current;
      if (!p?.started) return;
      press.current = null;
      document.body.classList.remove("select-none");
      onDragEnd?.(ev.clientX, ev.clientY);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up, { once: true });
  }

  function up(e: ReactPointerEvent, entry: T) {
    const p = press.current;
    // A drag ends in the window's own listener, wherever it is let go.
    if (p?.started) return;
    press.current = null;
    if (e.button !== 0) return;
    const next = clickPick(names, picked, anchor, entry.name, { ctrl: e.ctrlKey || e.metaKey, shift: e.shiftKey });
    onPick(next.picked, next.anchor);
  }

  const allPicked = entries.length > 0 && entries.every((e) => picked.includes(e.name));

  return (
    <div
      className={cn(
        "min-h-28 flex-1 overflow-auto rounded-md border [&>[data-slot=table-container]]:overflow-visible",
        loading && "opacity-60",
      )}
    >
      <Table>
        <TableHeader className="sticky top-0 z-10 bg-background">
          <TableRow>
            <TableHead className="w-7">
              <Checkbox
                aria-label={`Pick everything on ${label}`}
                checked={allPicked}
                disabled={entries.length === 0}
                onCheckedChange={(on) => onPick(on ? names : [], null)}
              />
            </TableHead>
            <SortableHead label="Name" active={view.sort === "name"} dir={view.dir} onSort={() => sortBy("name")} />
            <SortableHead
              label="Size"
              active={view.sort === "size"}
              dir={view.dir}
              onSort={() => sortBy("size")}
              className="text-right"
            />
            <SortableHead
              label="Modified"
              active={view.sort === "modified"}
              dir={view.dir}
              onSort={() => sortBy("modified")}
              className="hidden @md:table-cell"
            />
            <TableHead className="w-8">
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {entries.length === 0 && (
            <TableRow>
              <TableCell colSpan={5} className="text-center text-xs text-muted-foreground">
                {empty}
              </TableCell>
            </TableRow>
          )}
          {entries.map((e) => {
            const on = picked.includes(e.name);
            const folder = folderPath?.(e) ?? null;
            const drive = isDrive?.(e) ?? false;
            return (
              <TableRow
                key={e.name}
                data-state={on ? "selected" : undefined}
                data-files-folder={folder ?? undefined}
                tabIndex={0}
                onPointerDown={(ev) => down(ev, e)}
                onPointerUp={(ev) => up(ev, e)}
                onDoubleClick={() => onOpen(e)}
                onKeyDown={(ev) => {
                  if (ev.key === "Enter") onOpen(e);
                  if (ev.key === " ") {
                    ev.preventDefault();
                    const next = clickPick(names, picked, anchor, e.name, { ctrl: true, shift: ev.shiftKey });
                    onPick(next.picked, next.anchor);
                  }
                }}
                className="group cursor-default text-xs select-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                title={rowTitle?.(e)}
              >
                <TableCell
                  className="py-1"
                  onPointerDown={(ev) => ev.stopPropagation()}
                  onPointerUp={(ev) => ev.stopPropagation()}
                >
                  <Checkbox
                    aria-label={`Pick ${e.name}`}
                    checked={on}
                    onCheckedChange={(v) =>
                      onPick(v === true ? [...picked, e.name] : picked.filter((p) => p !== e.name), e.name)
                    }
                  />
                </TableCell>
                <TableCell className="max-w-0 py-1">
                  <span className="flex min-w-0 items-center gap-1.5">
                    {drive ? (
                      <HardDriveIcon className="size-3.5 shrink-0 text-muted-foreground" aria-label="Drive" />
                    ) : e.kind === "folder" ? (
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
                <TableCell className="hidden py-1 whitespace-nowrap text-muted-foreground @md:table-cell">
                  {e.modified
                    ? new Date(e.modified * 1000).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" })
                    : ""}
                </TableCell>
                <TableCell
                  className="py-0.5"
                  onPointerDown={(ev) => ev.stopPropagation()}
                  onPointerUp={(ev) => ev.stopPropagation()}
                >
                  <RowMenu label={e.name} className="opacity-0 group-hover:opacity-100 focus-visible:opacity-100">
                    {menu(e)}
                  </RowMenu>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
