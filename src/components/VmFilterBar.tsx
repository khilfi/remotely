// VM-02: narrows the VM list by text, tag and power state, and keeps named filters. The core does the
// matching (`vm_list` with a filter), so the CLI and bulk-run target picker (BX-01) match the same way.

import { BookmarkIcon, ChevronDownIcon, SearchIcon, TagIcon, XIcon, ZapIcon } from "lucide-react";
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
import { Input } from "@/components/ui/input";
import type { PowerState, SavedFilter, Tag, VmFilter } from "@/lib/api";

export const POWER_STATES: { value: PowerState; label: string }[] = [
  { value: "running", label: "Running" },
  { value: "not_running", label: "Off" },
  { value: "suspended", label: "Suspended" },
  { value: "paused", label: "Paused" },
  { value: "unknown", label: "Unknown" },
];

export function isEmptyFilter(f: VmFilter) {
  return (
    !f.text?.trim() &&
    !f.tags?.length &&
    !f.powerStates?.length &&
    !f.environments?.length &&
    (f.protected === undefined || f.protected === null)
  );
}

function toggle<T>(list: T[] | undefined, value: T): T[] {
  const current = list ?? [];
  return current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
}

interface Props {
  filter: VmFilter;
  onChange: (filter: VmFilter) => void;
  tags: Tag[];
  savedFilters: SavedFilter[];
  /** Shows the saved filter's VMs and selects them. */
  onApplySaved: (saved: SavedFilter) => void;
  onSaveCurrent: () => void;
  onDeleteSaved: (saved: SavedFilter) => void;
}

export function VmFilterBar({
  filter,
  onChange,
  tags,
  savedFilters,
  onApplySaved,
  onSaveCurrent,
  onDeleteSaved,
}: Props) {
  const tagCount = filter.tags?.length ?? 0;
  const stateCount = filter.powerStates?.length ?? 0;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="relative w-64">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          aria-label="Search VMs"
          placeholder="Name, path, OS, IP or tag"
          className="pl-8"
          spellCheck={false}
          value={filter.text ?? ""}
          onChange={(e) => onChange({ ...filter, text: e.currentTarget.value })}
        />
      </div>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline">
            <TagIcon data-icon="inline-start" />
            Tags
            {tagCount > 0 && <Badge variant="secondary">{tagCount}</Badge>}
            <ChevronDownIcon data-icon="inline-end" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-56">
          <DropdownMenuLabel>Show VMs with any of</DropdownMenuLabel>
          {tags.length === 0 && <DropdownMenuItem disabled>No tags yet</DropdownMenuItem>}
          {tags.map((t) => (
            <DropdownMenuCheckboxItem
              key={t.id}
              checked={filter.tags?.some((x) => x.toLowerCase() === t.name.toLowerCase()) ?? false}
              onCheckedChange={() => onChange({ ...filter, tags: toggle(filter.tags, t.name) })}
              onSelect={(e) => e.preventDefault()}
            >
              {t.name}
              <DropdownMenuShortcut>{t.vmCount}</DropdownMenuShortcut>
            </DropdownMenuCheckboxItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline">
            <ZapIcon data-icon="inline-start" />
            State
            {stateCount > 0 && <Badge variant="secondary">{stateCount}</Badge>}
            <ChevronDownIcon data-icon="inline-end" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-44">
          {POWER_STATES.map((s) => (
            <DropdownMenuCheckboxItem
              key={s.value}
              checked={filter.powerStates?.includes(s.value) ?? false}
              onCheckedChange={() => onChange({ ...filter, powerStates: toggle(filter.powerStates, s.value) })}
              onSelect={(e) => e.preventDefault()}
            >
              {s.label}
            </DropdownMenuCheckboxItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline">
            <BookmarkIcon data-icon="inline-start" />
            Saved filters
            <ChevronDownIcon data-icon="inline-end" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-60">
          <DropdownMenuLabel>Show and select</DropdownMenuLabel>
          {savedFilters.length === 0 && <DropdownMenuItem disabled>No saved filters yet</DropdownMenuItem>}
          {savedFilters.map((f) => (
            <DropdownMenuItem key={f.id} onSelect={() => onApplySaved(f)}>
              {f.name}
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          <DropdownMenuItem disabled={isEmptyFilter(filter)} onSelect={onSaveCurrent}>
            Save the current filter…
          </DropdownMenuItem>
          {savedFilters.length > 0 && (
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>Delete</DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                {savedFilters.map((f) => (
                  <DropdownMenuItem key={f.id} variant="destructive" onSelect={() => onDeleteSaved(f)}>
                    {f.name}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuSubContent>
            </DropdownMenuSub>
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      {!isEmptyFilter(filter) && (
        <Button variant="ghost" onClick={() => onChange({})}>
          <XIcon data-icon="inline-start" />
          Clear filter
        </Button>
      )}
    </div>
  );
}
