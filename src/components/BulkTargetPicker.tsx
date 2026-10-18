// BX-01 target picker for the Bulk run page: saved sessions, VMs (reached through the session linked to
// each), tags and saved VM filters. The core turns the picks into hosts, each session once, and lists
// the picked VMs no session reaches: commands reach a VM over SSH, and running them through VMware
// Tools without SSH (VM-09) comes in a later version.

import { useEffect, useMemo, useState } from "react";
import { FilterIcon, ListTreeIcon, SearchIcon, ServerIcon, ShieldIcon, TagIcon, TriangleAlertIcon } from "lucide-react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  api,
  errorMessage,
  type ResolvedTargets,
  type SavedFilter,
  type SessionRecord,
  type Tag,
  type TargetPicks,
  type VmRecord,
} from "@/lib/api";
import { plural } from "@/lib/format";
import { EnvBadge } from "./Badges";

interface Props {
  /** True while the page is shown, so the lists are read again when the user comes back. */
  active: boolean;
  picks: TargetPicks;
  onPicksChange: (picks: TargetPicks) => void;
  /** The hosts the picks reach, as the core resolved them. */
  resolved: ResolvedTargets | null;
  onOpenSessions: () => void;
}

type Kind = "sessionIds" | "vmPaths" | "tags" | "filterIds";

function toggle(list: string[] | undefined, value: string, on: boolean) {
  const rest = (list ?? []).filter((v) => v !== value);
  return on ? [...rest, value] : rest;
}

function matches(needle: string, ...fields: (string | null | undefined)[]) {
  const n = needle.trim().toLowerCase();
  return !n || fields.some((f) => f?.toLowerCase().includes(n));
}

function sessionAddress(s: SessionRecord) {
  return `${s.username ? `${s.username}@` : ""}${s.host}:${s.port}`;
}

export function BulkTargetPicker({ active, picks, onPicksChange, resolved, onOpenSessions }: Props) {
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [vms, setVms] = useState<VmRecord[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [filters, setFilters] = useState<SavedFilter[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [text, setText] = useState("");

  useEffect(() => {
    if (!active) return;
    let stale = false;
    Promise.all([api.sessions(), api.vmList(), api.tags(), api.savedFilters()]).then(
      ([s, v, t, f]) => {
        if (stale) return;
        setSessions(s);
        setVms(v);
        setTags(t);
        setFilters(f);
        setError(null);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [active]);

  // Which session each VM is reached through: the first linked one by name, as the core picks it.
  const linked = useMemo(() => {
    const byVm = new Map<string, SessionRecord[]>();
    for (const s of sessions) {
      if (s.vmId) byVm.set(s.vmId, [...(byVm.get(s.vmId) ?? []), s]);
    }
    return byVm;
  }, [sessions]);

  const set = (kind: Kind, value: string, on: boolean) =>
    onPicksChange({ ...picks, [kind]: toggle(picks[kind], value, on) });
  const has = (kind: Kind, value: string) => (picks[kind] ?? []).includes(value);
  const shownSessions = sessions.filter((s) => matches(text, s.name, s.host, s.username, ...s.tags));
  const shownVms = vms.filter((v) => matches(text, v.displayName, v.vmxPath, v.ipAddress, ...v.tags));
  const shownTags = tags.filter((t) => matches(text, t.name));
  const shownFilters = filters.filter((f) => matches(text, f.name));
  const picked = (kind: Kind) => (picks[kind] ?? []).length;
  const anyPicked = (["sessionIds", "vmPaths", "tags", "filterIds"] as Kind[]).some((k) => picked(k) > 0);
  const hosts = resolved?.hosts ?? [];
  const skipped = hosts.filter((h) => h.protected);
  const prod = hosts.filter((h) => h.environment === "prod" && !h.protected);
  const without = resolved?.vmsWithoutSession ?? [];

  function countBadge(kind: Kind) {
    const n = picked(kind);
    return n > 0 ? (
      <Badge variant="secondary" className="ml-1 h-4 min-w-4 px-1 text-[10px] tabular-nums">
        {n}
      </Badge>
    ) : null;
  }

  return (
    <div className="grid gap-3">
      <Tabs defaultValue="sessions" className="gap-3">
        <TabsList className="w-full">
          <TabsTrigger value="sessions">
            <ListTreeIcon />
            Sessions
            {countBadge("sessionIds")}
          </TabsTrigger>
          <TabsTrigger value="vms">
            <ServerIcon />
            VMs
            {countBadge("vmPaths")}
          </TabsTrigger>
          <TabsTrigger value="tags">
            <TagIcon />
            Tags
            {countBadge("tags")}
          </TabsTrigger>
          <TabsTrigger value="filters">
            <FilterIcon />
            Filters
            {countBadge("filterIds")}
          </TabsTrigger>
        </TabsList>

        <div className="relative">
          <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            className="pl-8"
            placeholder="Search"
            aria-label="Search the list"
            value={text}
            onChange={(e) => setText(e.currentTarget.value)}
          />
        </div>

        <TabsContent value="sessions">
          <PickList empty={sessions.length === 0 ? "No saved sessions yet." : "No session matches."}>
            {shownSessions.map((s) => (
              <PickRow
                key={s.id}
                id={`pick-session-${s.id}`}
                checked={has("sessionIds", s.id)}
                onChange={(on) => set("sessionIds", s.id, on)}
                title={s.name}
                detail={sessionAddress(s)}
                mono
                extra={
                  <>
                    {s.protected && <ShieldIcon className="size-3.5 text-muted-foreground" aria-label="Protected" />}
                    <EnvBadge env={s.environment} />
                  </>
                }
              />
            ))}
          </PickList>
        </TabsContent>

        <TabsContent value="vms">
          <PickList empty={vms.length === 0 ? "No VMs found yet. Refresh the VM list." : "No VM matches."}>
            {shownVms.map((v) => {
              const via = linked.get(v.id);
              return (
                <PickRow
                  key={v.id}
                  id={`pick-vm-${v.id}`}
                  checked={has("vmPaths", v.vmxPath)}
                  onChange={(on) => set("vmPaths", v.vmxPath, on)}
                  title={v.displayName}
                  detail={
                    via ? (
                      `through ${via[0].name}${via.length > 1 ? ` (+${via.length - 1} more linked)` : ""}`
                    ) : (
                      <span className="text-tier-medium">No linked session: can&apos;t run commands yet</span>
                    )
                  }
                  extra={<EnvBadge env={v.environment} />}
                />
              );
            })}
          </PickList>
        </TabsContent>

        <TabsContent value="tags">
          <PickList empty={tags.length === 0 ? "No tags yet." : "No tag matches."}>
            {shownTags.map((t) => (
              <PickRow
                key={t.id}
                id={`pick-tag-${t.id}`}
                checked={has("tags", t.name)}
                onChange={(on) => set("tags", t.name, on)}
                title={t.name}
                detail={[t.sessionCount && plural(t.sessionCount, "session"), t.vmCount && plural(t.vmCount, "VM")]
                  .filter(Boolean)
                  .join(", ")}
              />
            ))}
          </PickList>
        </TabsContent>

        <TabsContent value="filters">
          <PickList
            empty={
              filters.length === 0
                ? "No saved filters yet. Save one on the Virtual machines page."
                : "No filter matches."
            }
          >
            {shownFilters.map((f) => (
              <PickRow
                key={f.id}
                id={`pick-filter-${f.id}`}
                checked={has("filterIds", f.id)}
                onChange={(on) => set("filterIds", f.id, on)}
                title={f.name}
                detail="Saved VM filter"
              />
            ))}
          </PickList>
        </TabsContent>
      </Tabs>

      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-medium">{plural(hosts.length - skipped.length, "host")}</span>
        {skipped.length > 0 && (
          <Badge variant="outline" className="font-normal">
            {skipped.length} protected, skipped
          </Badge>
        )}
        {prod.length > 0 && (
          <Badge variant="outline" className="border-env-prod/50 font-normal text-env-prod">
            {prod.length} Prod
          </Badge>
        )}
        {anyPicked && (
          <Button variant="ghost" size="sm" className="ml-auto" onClick={() => onPicksChange({})}>
            Clear
          </Button>
        )}
      </div>

      {without.length > 0 && (
        <Alert>
          <TriangleAlertIcon className="text-tier-medium" />
          <AlertTitle>
            {plural(without.length, "VM")} can&apos;t run commands yet: {without.map((v) => v.name).join(", ")}
          </AlertTitle>
          <AlertDescription>
            Commands reach a VM over SSH, through a session linked to it: edit a session and choose the VM it reaches.
            Running commands through VMware Tools without SSH comes in a later version (VM-09).
          </AlertDescription>
          <AlertAction>
            <Button size="sm" variant="outline" onClick={onOpenSessions}>
              Sessions
            </Button>
          </AlertAction>
        </Alert>
      )}
      {resolved?.notes.map((note) => (
        <p key={note} className="text-xs text-muted-foreground">
          {note}
        </p>
      ))}
    </div>
  );
}

function PickList({ children, empty }: { children: React.ReactNode[]; empty: string }) {
  return (
    <ScrollArea className="h-56 rounded-md border">
      {children.length === 0 ? (
        <p className="p-4 text-center text-sm text-muted-foreground">{empty}</p>
      ) : (
        <ul className="divide-y">{children}</ul>
      )}
    </ScrollArea>
  );
}

function PickRow({
  id,
  checked,
  onChange,
  title,
  detail,
  mono,
  extra,
}: {
  id: string;
  checked: boolean;
  onChange: (on: boolean) => void;
  title: string;
  detail?: React.ReactNode;
  mono?: boolean;
  extra?: React.ReactNode;
}) {
  return (
    <li className="flex items-center gap-3 px-3 py-2">
      <Checkbox id={id} checked={checked} onCheckedChange={(v) => onChange(v === true)} />
      <Label htmlFor={id} className="grid min-w-0 flex-1 gap-0.5 font-normal">
        <span className="truncate text-sm font-medium">{title}</span>
        {detail && (
          <span
            className={
              mono ? "truncate font-mono text-xs text-muted-foreground" : "truncate text-xs text-muted-foreground"
            }
          >
            {detail}
          </span>
        )}
      </Label>
      {extra && <span className="flex shrink-0 items-center gap-1.5">{extra}</span>}
    </li>
  );
}
