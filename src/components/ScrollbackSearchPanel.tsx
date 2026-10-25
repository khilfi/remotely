// QL-18: search every open terminal's scrollback at once, from a panel under the terminals (the toolbar's button,
// Ctrl+Shift+G, or the palette). Results are grouped by tab, each match a line of its output with the match marked;
// clicking one shows that tab and pane, scrolls to the line and highlights the match. Each search reads every
// terminal's buffer once (as the user types, after a pause, or with Enter or Search again), never on every write, so
// the results are those of when it ran. While presenting (FD-03) the masked terminals on screen are searched, so the
// lines shown never hold a real host. Caps and invalid regular expressions are said in the panel (scrollback-search.ts).

import { useEffect, useRef, useState } from "react";
import { CaseSensitiveIcon, RefreshCwIcon, RegexIcon, TextSearchIcon, XIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Toggle } from "@/components/ui/toggle";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  compileSearch,
  groupByTab,
  longLinesText,
  summaryText,
  type LineHit,
  type PaneResult,
  type SearchOptions,
  type SearchSummary,
} from "@/lib/scrollback-search";
import type { PaneSession } from "@/lib/terminal-session";
import { cn } from "@/lib/utils";

/** How long typing pauses before the terminals are searched. */
const TYPING_PAUSE_MS = 300;

/** A pane to search, with where it is. */
export interface SearchPane {
  tabKey: string;
  /** The tab's title. */
  title: string;
  pane: PaneSession;
  /** The pane's own name, shown when its tab is split. */
  name: string;
  /** Its tab holds several panes. */
  split: boolean;
}

interface Props {
  /** Every pane of every tab, in tab order. */
  panes: SearchPane[];
  /** Changes when the input should take the focus (the shortcut, the palette). */
  focus: number;
  onReveal: (target: SearchPane, hit: LineHit) => void;
  onClose: () => void;
}

interface Done {
  summary: SearchSummary;
  /** The panes searched, by key, to reveal in. */
  panes: Map<string, SearchPane>;
}

const hitKey = (paneKey: string, hit: LineHit) => `${paneKey}:${hit.row}:${hit.start}`;

export function ScrollbackSearchPanel({ panes, focus, onReveal, onClose }: Props) {
  const [query, setQuery] = useState("");
  const [options, setOptions] = useState<SearchOptions>({ caseSensitive: false, regex: false });
  const [done, setDone] = useState<Done | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const timer = useRef<number | null>(null);
  // The panes as they are now, for a search that runs after a pause.
  const latest = useRef(panes);
  useEffect(() => {
    latest.current = panes;
  });

  useEffect(() => {
    input.current?.focus();
    input.current?.select();
  }, [focus]);
  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    },
    [],
  );

  function run(text = query, opts = options) {
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = null;
    const compiled = compileSearch(text, opts);
    const targets = latest.current;
    setSelected(null);
    if (!compiled) {
      targets.forEach((t) => t.pane.endScrollbackSearch());
      setDone(null);
      setError(null);
      return;
    }
    if (!compiled.ok) {
      setError(compiled.error);
      return;
    }
    setError(null);
    const results: PaneResult[] = targets.map((t) => ({
      tabKey: t.tabKey,
      title: t.title,
      paneKey: t.pane.key,
      paneName: t.split ? t.name : "",
      ...t.pane.scanScrollback(compiled.pattern),
    }));
    setDone({ summary: groupByTab(results), panes: new Map(targets.map((t) => [t.pane.key, t])) });
  }

  function later(text: string, opts: SearchOptions) {
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => run(text, opts), TYPING_PAUSE_MS);
  }

  function setOption(change: Partial<SearchOptions>) {
    const next = { ...options, ...change };
    setOptions(next);
    run(query, next);
  }

  const summary = done?.summary ?? null;
  const longLines = summary ? longLinesText(summary) : null;

  return (
    <section className="flex h-full min-h-0 flex-col rounded-lg border" aria-label="Search all terminals">
      <div className="flex flex-wrap items-center gap-1 border-b px-2 py-1">
        <TextSearchIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
        <span className="mr-1 text-sm font-medium">Search all terminals</span>
        <Input
          ref={input}
          aria-label="Search every terminal's scrollback"
          placeholder={options.regex ? "Regular expression" : "Text"}
          className="h-7 w-56 min-w-24 shrink text-sm"
          value={query}
          onChange={(e) => {
            const text = e.currentTarget.value;
            setQuery(text);
            later(text, options);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              run();
            } else if (e.key === "Escape") {
              e.preventDefault();
              onClose();
            }
          }}
        />
        <Toggle
          size="sm"
          aria-label="Match case"
          title="Match case"
          pressed={options.caseSensitive}
          onPressedChange={(v) => setOption({ caseSensitive: v })}
        >
          <CaseSensitiveIcon />
        </Toggle>
        <Toggle
          size="sm"
          aria-label="Regular expression"
          title="Regular expression"
          pressed={options.regex}
          onPressedChange={(v) => setOption({ regex: v })}
        >
          <RegexIcon />
        </Toggle>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label="Search again" onClick={() => run()} disabled={!query}>
              <RefreshCwIcon />
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            Search again: the results are from when you searched, output since is not in them
          </TooltipContent>
        </Tooltip>
        <Button
          variant="ghost"
          size="icon-sm"
          className="ml-auto"
          aria-label="Close the search (Esc)"
          onClick={onClose}
        >
          <XIcon />
        </Button>
      </div>
      <div className="grid gap-0.5 border-b px-3 py-1 text-xs" aria-live="polite">
        {error ? (
          <span className="text-destructive" role="alert">
            {error}
          </span>
        ) : summary ? (
          <span className={cn(summary.capped ? "text-tier-medium" : "text-muted-foreground")}>
            {summaryText(summary)}
          </span>
        ) : (
          <span className="text-muted-foreground">
            Type to search the scrollback of every open terminal{panes.length > 0 ? ` (${panes.length})` : ""}.
            Ctrl+Shift+F searches one terminal.
          </span>
        )}
        {longLines && !error && <span className="text-muted-foreground">{longLines}</span>}
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="grid gap-2 p-2">
          {summary?.groups.map((group) => (
            <div key={group.tabKey} className="grid gap-0.5">
              <div className="flex items-center gap-2 px-1 text-sm font-medium">
                <span className="truncate">{group.title}</span>
                <Badge variant="secondary" className="tabular-nums">
                  {group.count}
                  {group.capped ? "+" : ""}
                </Badge>
              </div>
              {group.panes.map((pane) => (
                <div key={pane.paneKey} className="grid">
                  {pane.paneName && <span className="px-1 text-xs text-muted-foreground">{pane.paneName}</span>}
                  {pane.hits.map((hit) => {
                    const key = hitKey(pane.paneKey, hit);
                    const target = done?.panes.get(pane.paneKey);
                    return (
                      <button
                        key={key}
                        type="button"
                        className={cn(
                          "block w-full truncate rounded-sm px-2 py-0.5 text-left font-mono text-xs whitespace-pre hover:bg-muted",
                          selected === key && "bg-accent",
                        )}
                        title="Show it in its terminal"
                        onClick={() => {
                          if (!target) return;
                          setSelected(key);
                          onReveal(target, hit);
                        }}
                      >
                        {hit.cutBefore && <span className="text-muted-foreground">…</span>}
                        {hit.before}
                        <mark className="rounded-sm bg-amber-300/80 text-foreground dark:bg-amber-500/50">
                          {hit.shown}
                        </mark>
                        {hit.after}
                        {hit.cutAfter && <span className="text-muted-foreground">…</span>}
                      </button>
                    );
                  })}
                </div>
              ))}
            </div>
          ))}
        </div>
      </ScrollArea>
    </section>
  );
}
