// MO-16: the dashboard's widgets on a grid of four columns and 120-pixel rows, in the layout's order, each its own
// width and height. While customizing, each widget gets a bar: drag its handle (or press the arrow keys on it) to move
// it, Move up and Move down, its size (or drag the corner, or the arrow keys on the corner), its settings (a chart's VM
// or host, metric and range; a services widget's host) and Remove. The widgets underneath are inert then. Dragging is
// done with pointer events, not HTML5 drag and drop: the window's own file drop (SS-08) takes those over on Windows, and
// it needs no library.

import {
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type PointerEvent,
  type ReactNode,
} from "react";
import { ArrowDownIcon, ArrowUpIcon, GripVerticalIcon, MoveDiagonal2Icon, Settings2Icon, XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { WidgetSettings } from "@/components/WidgetSettings";
import type { DashboardLayout, Widget } from "@/lib/dashboard-api";
import {
  dropIndex,
  GAP_PX,
  GRID_COLUMNS,
  heightPx,
  MAX_ROWS,
  moveWidget,
  moveWidgetTo,
  removeWidget,
  resizeWidget,
  sizeFromDrag,
  updateWidget,
} from "@/lib/dashboard-layout";
import { cn } from "@/lib/utils";

interface Props {
  layout: DashboardLayout;
  editing: boolean;
  onChange: (layout: DashboardLayout) => void;
  /** A widget's content, `height` pixels tall. */
  renderWidget: (widget: Widget, height: number) => ReactNode;
  titleOf: (widget: Widget) => string;
}

const WIDTHS: { w: number; label: string }[] = [
  { w: 1, label: "A quarter" },
  { w: 2, label: "Half" },
  { w: 3, label: "Three quarters" },
  { w: 4, label: "Full width" },
];

/** The bar a widget gets while customizing, and its height. */
const BAR_PX = 36;

export function DashboardGrid({ layout, editing, onChange, renderWidget, titleOf }: Props) {
  const grid = useRef<HTMLDivElement>(null);
  const grips = useRef(new Map<string, HTMLButtonElement>());
  const [drag, setDrag] = useState<{ id: string; over: string | null; before: boolean } | null>(null);
  const [resizing, setResizing] = useState<{
    id: string;
    x: number;
    y: number;
    start: { w: number; h: number };
  } | null>(null);
  /** Keeps the focus on a widget's handle after the keyboard moved it. */
  const refocus = useRef<string | null>(null);
  useEffect(() => {
    if (!refocus.current) return;
    grips.current.get(refocus.current)?.focus();
    refocus.current = null;
  }, [layout]);

  const columnPx = () => {
    const width = grid.current?.clientWidth ?? 0;
    return (width - GAP_PX * (GRID_COLUMNS - 1)) / GRID_COLUMNS;
  };

  function dragMove(e: PointerEvent<HTMLElement>) {
    if (!drag) return;
    const el = document.elementFromPoint(e.clientX, e.clientY)?.closest<HTMLElement>("[data-widget-id]");
    const over = el?.dataset.widgetId ?? null;
    if (!el || !over || over === drag.id) {
      if (drag.over !== null) setDrag({ ...drag, over: null });
      return;
    }
    const rect = el.getBoundingClientRect();
    // Before when the pointer is in the target's top-left half.
    const before = (e.clientX - rect.left) / rect.width + (e.clientY - rect.top) / rect.height < 1;
    if (drag.over !== over || drag.before !== before) setDrag({ ...drag, over, before });
  }

  function dragEnd() {
    if (drag?.over) onChange(moveWidgetTo(layout, drag.id, dropIndex(layout, drag.id, drag.over, drag.before)));
    setDrag(null);
  }

  function gripKeys(e: KeyboardEvent<HTMLButtonElement>, id: string) {
    const delta =
      e.key === "ArrowUp" || e.key === "ArrowLeft" ? -1 : e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : 0;
    if (delta === 0) return;
    e.preventDefault();
    refocus.current = id;
    onChange(moveWidget(layout, id, delta));
  }

  function cornerKeys(e: KeyboardEvent<HTMLButtonElement>, widget: Widget) {
    const change: Record<string, [number, number]> = {
      ArrowLeft: [-1, 0],
      ArrowRight: [1, 0],
      ArrowUp: [0, -1],
      ArrowDown: [0, 1],
    };
    const step = change[e.key];
    if (!step) return;
    e.preventDefault();
    onChange(resizeWidget(layout, widget.id, widget.w + step[0], widget.h + step[1]));
  }

  return (
    <div
      ref={grid}
      className="grid auto-rows-[120px] grid-cols-1 gap-4 md:grid-cols-4"
      onPointerMove={(e) => {
        dragMove(e);
        if (resizing) {
          const size = sizeFromDrag(resizing.start, e.clientX - resizing.x, e.clientY - resizing.y, columnPx());
          const widget = layout.widgets.find((w) => w.id === resizing.id);
          if (widget && (widget.w !== size.w || widget.h !== size.h)) {
            onChange(resizeWidget(layout, resizing.id, size.w, size.h));
          }
        }
      }}
      onPointerUp={() => {
        if (drag) dragEnd();
        setResizing(null);
      }}
      onPointerCancel={() => {
        setDrag(null);
        setResizing(null);
      }}
    >
      {layout.widgets.map((widget, index) => {
        const title = titleOf(widget);
        const contentHeight = heightPx(widget.h) - (editing ? BAR_PX : 0);
        const target = drag && drag.over === widget.id;
        return (
          <section
            key={widget.id}
            data-widget-id={widget.id}
            aria-label={editing ? `${title}, widget ${index + 1} of ${layout.widgets.length}` : undefined}
            className={cn(
              "relative flex min-h-0 min-w-0 flex-col md:col-span-(--w) row-span-(--h)",
              editing && "rounded-lg outline-2 outline-dashed outline-border",
              drag?.id === widget.id && "opacity-50",
              target && (drag.before ? "shadow-[-4px_0_0_0_var(--primary)]" : "shadow-[4px_0_0_0_var(--primary)]"),
            )}
            style={{ "--w": widget.w, "--h": widget.h } as CSSProperties}
          >
            {editing && (
              <div className="flex h-9 shrink-0 items-center gap-1 px-1" style={{ height: BAR_PX }}>
                <button
                  type="button"
                  ref={(el) => {
                    if (el) grips.current.set(widget.id, el);
                    else grips.current.delete(widget.id);
                  }}
                  className="flex size-7 cursor-grab touch-none items-center justify-center rounded-md text-muted-foreground hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none active:cursor-grabbing"
                  aria-label={`Move ${title}: drag, or press the arrow keys`}
                  title="Drag to move, or press the arrow keys"
                  onPointerDown={(e) => {
                    e.currentTarget.setPointerCapture(e.pointerId);
                    setDrag({ id: widget.id, over: null, before: true });
                  }}
                  onKeyDown={(e) => gripKeys(e, widget.id)}
                >
                  <GripVerticalIcon className="size-4" />
                </button>
                <span className="min-w-0 flex-1 truncate text-sm font-medium">{title}</span>
                {/* A one-column widget's bar keeps its room for the title; the size menu says the size. */}
                {widget.w > 1 && (
                  <span className="text-xs text-muted-foreground tabular-nums">
                    {widget.w}×{widget.h}
                  </span>
                )}
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`Move ${title} up`}
                  disabled={index === 0}
                  onClick={() => onChange(moveWidget(layout, widget.id, -1))}
                >
                  <ArrowUpIcon />
                </Button>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`Move ${title} down`}
                  disabled={index === layout.widgets.length - 1}
                  onClick={() => onChange(moveWidget(layout, widget.id, 1))}
                >
                  <ArrowDownIcon />
                </Button>
                {(widget.kind === "chart" || widget.kind === "services") && (
                  <Popover>
                    <PopoverTrigger asChild>
                      <Button variant="ghost" size="icon-sm" aria-label={`Settings of ${title}`}>
                        <Settings2Icon />
                      </Button>
                    </PopoverTrigger>
                    <PopoverContent align="end" className="w-80">
                      <WidgetSettings
                        widget={widget}
                        onChange={(change) => onChange(updateWidget(layout, widget.id, change))}
                      />
                    </PopoverContent>
                  </Popover>
                )}
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="icon-sm" aria-label={`Size of ${title}`}>
                      <MoveDiagonal2Icon />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuLabel>Width</DropdownMenuLabel>
                    <DropdownMenuRadioGroup
                      value={String(widget.w)}
                      onValueChange={(v) => onChange(resizeWidget(layout, widget.id, Number(v), widget.h))}
                    >
                      {WIDTHS.map((o) => (
                        <DropdownMenuRadioItem key={o.w} value={String(o.w)}>
                          {o.label}
                        </DropdownMenuRadioItem>
                      ))}
                    </DropdownMenuRadioGroup>
                    <DropdownMenuSeparator />
                    <DropdownMenuLabel>Height</DropdownMenuLabel>
                    <DropdownMenuRadioGroup
                      value={String(widget.h)}
                      onValueChange={(v) => onChange(resizeWidget(layout, widget.id, widget.w, Number(v)))}
                    >
                      {Array.from({ length: MAX_ROWS }, (_, i) => i + 1).map((h) => (
                        <DropdownMenuRadioItem key={h} value={String(h)}>
                          {h} {h === 1 ? "row" : "rows"}
                        </DropdownMenuRadioItem>
                      ))}
                    </DropdownMenuRadioGroup>
                  </DropdownMenuContent>
                </DropdownMenu>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`Remove ${title}`}
                  onClick={() => onChange(removeWidget(layout, widget.id))}
                >
                  <XIcon />
                </Button>
              </div>
            )}
            <div
              className={cn("@container min-h-0 flex-1 overflow-auto", editing && "pointer-events-none select-none")}
              inert={editing}
            >
              {renderWidget(widget, contentHeight)}
            </div>
            {editing && (
              <button
                type="button"
                className="absolute right-0.5 bottom-0.5 flex size-6 cursor-nwse-resize touch-none items-center justify-center rounded-sm bg-background/80 text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                aria-label={`Resize ${title}: drag, or press the arrow keys (now ${widget.w} columns by ${widget.h} rows)`}
                title="Drag to resize, or press the arrow keys"
                onPointerDown={(e) => {
                  e.currentTarget.setPointerCapture(e.pointerId);
                  setResizing({ id: widget.id, x: e.clientX, y: e.clientY, start: { w: widget.w, h: widget.h } });
                }}
                onKeyDown={(e) => cornerKeys(e, widget)}
              >
                <MoveDiagonal2Icon className="size-3.5" />
              </button>
            )}
          </section>
        );
      })}
    </div>
  );
}
