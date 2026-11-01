// VM-02: narrows the VM list by text, tag, power state, (VM-18) hypervisor and environment, and keeps named filters.
// The core does the matching (`vm_list` with a filter), so the CLI and bulk-run target picker (BX-01) match the same
// way. UX-02: one search box and one Filter menu, with the saved filters inside it, instead of four buttons.

import { BookmarkIcon, FilterIcon, SearchIcon, Trash2Icon, XIcon } from "lucide-react";
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
import type { Environment, PowerState, SavedFilter, Tag, VmFilter } from "@/lib/api";
import { HYPERVISORS } from "@/lib/hypervisors";
import { activeFilterCount } from "@/lib/vm-page";

export const POWER_STATES: { value: PowerState; label: string }[] = [
  { value: "running", label: "Running" },
  { value: "not_running", label: "Off" },
  { value: "suspended", label: "Suspended" },
  { value: "paused", label: "Paused" },
  { value: "unknown", label: "Unknown" },
];

const ENVIRONMENTS: { value: Environment; label: string }[] = [
  { value: "prod", label: "Prod" },
  { value: "staging", label: "Staging" },
  { value: "lab", label: "Lab" },
  { value: "none", label: "None" },
];

export function isEmptyFilter(f: VmFilter) {
  return !f.text?.trim() && activeFilterCount(f) === 0;
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
  /** QL-26: only the starred VMs (the window's own filter; the core's list is filtered here). */
  starredOnly: boolean;
  onStarredOnly: (on: boolean) => void;
}

export function VmFilterBar({
  filter,
  onChange,
  tags,
  savedFilters,
  onApplySaved,
  onSaveCurrent,
  onDeleteSaved,
  starredOnly,
  onStarredOnly,
}: Props) {
  const count = activeFilterCount(filter) + (starredOnly ? 1 : 0);
  const keepOpen = (e: Event) => e.preventDefault();

  return (
    <>
      <div className="relative w-56 min-w-40">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          aria-label="Search VMs"
          placeholder="Search VMs"
          title="Name, path, OS, IP address or tag"
          className="pl-8"
          spellCheck={false}
          value={filter.text ?? ""}
          onChange={(e) => onChange({ ...filter, text: e.currentTarget.value })}
        />
      </div>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" aria-label={count > 0 ? `Filter, ${count} on` : "Filter"}>
            <FilterIcon data-icon="inline-start" />
            Filter
            {count > 0 && <Badge variant="secondary">{count}</Badge>}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-56">
          <DropdownMenuCheckboxItem checked={starredOnly} onCheckedChange={onStarredOnly} onSelect={keepOpen}>
            Starred only
          </DropdownMenuCheckboxItem>
          <DropdownMenuSub>
            <DropdownMenuSubTrigger>
              State
              {(filter.powerStates?.length ?? 0) > 0 && (
                <DropdownMenuShortcut>{filter.powerStates?.length}</DropdownMenuShortcut>
              )}
            </DropdownMenuSubTrigger>
            <DropdownMenuSubContent className="w-44">
              {POWER_STATES.map((s) => (
                <DropdownMenuCheckboxItem
                  key={s.value}
                  checked={filter.powerStates?.includes(s.value) ?? false}
                  onCheckedChange={() => onChange({ ...filter, powerStates: toggle(filter.powerStates, s.value) })}
                  onSelect={keepOpen}
                >
                  {s.label}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuSubContent>
          </DropdownMenuSub>
          <DropdownMenuSub>
            <DropdownMenuSubTrigger>
              Tags
              {(filter.tags?.length ?? 0) > 0 && <DropdownMenuShortcut>{filter.tags?.length}</DropdownMenuShortcut>}
            </DropdownMenuSubTrigger>
            <DropdownMenuSubContent className="w-56">
              {tags.length === 0 && <DropdownMenuItem disabled>No tags yet</DropdownMenuItem>}
              {tags.map((t) => (
                <DropdownMenuCheckboxItem
                  key={t.id}
                  checked={filter.tags?.some((x) => x.toLowerCase() === t.name.toLowerCase()) ?? false}
                  onCheckedChange={() => onChange({ ...filter, tags: toggle(filter.tags, t.name) })}
                  onSelect={keepOpen}
                >
                  {t.name}
                  <DropdownMenuShortcut>{t.vmCount}</DropdownMenuShortcut>
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuSubContent>
          </DropdownMenuSub>
          <DropdownMenuSub>
            <DropdownMenuSubTrigger>
              Environment
              {(filter.environments?.length ?? 0) > 0 && (
                <DropdownMenuShortcut>{filter.environments?.length}</DropdownMenuShortcut>
              )}
            </DropdownMenuSubTrigger>
            <DropdownMenuSubContent className="w-44">
              {ENVIRONMENTS.map((env) => (
                <DropdownMenuCheckboxItem
                  key={env.value}
                  checked={filter.environments?.includes(env.value) ?? false}
                  onCheckedChange={() => onChange({ ...filter, environments: toggle(filter.environments, env.value) })}
                  onSelect={keepOpen}
                >
                  {env.label}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuSubContent>
          </DropdownMenuSub>
          <DropdownMenuSub>
            <DropdownMenuSubTrigger>
              Hypervisor
              {(filter.hypervisors?.length ?? 0) > 0 && (
                <DropdownMenuShortcut>{filter.hypervisors?.length}</DropdownMenuShortcut>
              )}
            </DropdownMenuSubTrigger>
            <DropdownMenuSubContent className="w-52">
              {HYPERVISORS.map((h) => (
                <DropdownMenuCheckboxItem
                  key={h.value}
                  checked={filter.hypervisors?.includes(h.value) ?? false}
                  onCheckedChange={() => onChange({ ...filter, hypervisors: toggle(filter.hypervisors, h.value) })}
                  onSelect={keepOpen}
                >
                  {h.label}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuSubContent>
          </DropdownMenuSub>

          <DropdownMenuSeparator />
          <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">Saved filters</DropdownMenuLabel>
          {savedFilters.map((f) => (
            <DropdownMenuItem key={f.id} onSelect={() => onApplySaved(f)} title="Show and select its VMs">
              <BookmarkIcon />
              {f.name}
            </DropdownMenuItem>
          ))}
          {!isEmptyFilter(filter) && <DropdownMenuItem onSelect={onSaveCurrent}>Save this filter…</DropdownMenuItem>}
          {savedFilters.length === 0 && isEmptyFilter(filter) && (
            <DropdownMenuItem disabled>Set a filter to save it</DropdownMenuItem>
          )}
          {savedFilters.length > 0 && (
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>
                <Trash2Icon />
                Delete a saved filter
              </DropdownMenuSubTrigger>
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
        <Button variant="ghost" size="sm" onClick={() => onChange({})}>
          <XIcon data-icon="inline-start" />
          Clear
        </Button>
      )}
    </>
  );
}
