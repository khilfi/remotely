// BX-01 target picker, UX-16 (0.9.0 H2) the one picker for every bulk job: Compare hosts, the SS-09 key push, support
// bundles, the Files page's push and fetch, and the Ansible inventory. It picks saved sessions, VMs (reached through
// the session linked to each), tags, saved VM filters and saved groups (QL-19's MultiExec groups, a read of their
// sessions). The core turns the picks into hosts, each session once, and lists the picked VMs no session reaches:
// commands reach a VM over SSH, and running them through VMware Tools without SSH (VM-09) comes in a later version.
// A4, H11: a VM linked only automatically (by the address its guest reports, which a hostile guest can make up) is
// reached once the user confirms the link.
// UX-16 `compact`: one summary line ("12 hosts: 6 picked tabs, folder 'Web', tag 'db'") with Change…, which opens the
// tabs below it; Compare hosts uses it, filled with the picked tabs and the tree's picks (lib/bulk-picks.ts).
// SS-12: only SSH sessions are listed for a key push, which goes over SSH; BX-13: a support bundle lists WinRM
// sessions too (`winrm`). The core leaves out any other kind a tag or group brings in, saying so. F6's Ansible inventory
// picks with `purpose="export"`: nothing runs, so WinRM sessions are listed too, protected hosts are counted (they go
// in, in their own group) and nothing picked is every SSH and WinRM session.

import { useEffect, useMemo, useState } from "react";
import {
  FilterIcon,
  LayersIcon,
  LinkIcon,
  ListTreeIcon,
  SearchIcon,
  ServerIcon,
  ShieldIcon,
  TagIcon,
  TriangleAlertIcon,
} from "lucide-react";
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
  type MultiExecGroup,
  type ResolvedTargets,
  type SavedFilter,
  type SessionFolder,
  type SessionRecord,
  type Tag,
  type TargetPicks,
  type VmRecord,
} from "@/lib/api";
import {
  anyPicks,
  leftOutText,
  picksParts,
  picksSummary,
  togglePick,
  type PickKind,
  type TabsPart,
} from "@/lib/bulk-picks";
import { plural } from "@/lib/format";
import { memberNames } from "@/lib/multiexec-groups";
import { kindOf } from "@/lib/session-kinds";
import { EnvBadge } from "./Badges";

interface Props {
  /** True while the page is shown, so the lists are read again when the user comes back. */
  active: boolean;
  picks: TargetPicks;
  onPicksChange: (picks: TargetPicks) => void;
  /** The hosts the picks reach, as the core resolved them. */
  resolved: ResolvedTargets | null;
  onOpenSessions: () => void;
  /** BX-13: WinRM sessions are hosts too (a support bundle); off for the key push. */
  winrm?: boolean;
  /**
   * What the hosts are for: commands run on them (the default: protected hosts are skipped), or an export (F6's
   * Ansible inventory: protected hosts go in, in their own group, and nothing picked is every SSH session).
   */
  purpose?: "run" | "export";
  /**
   * UX-16: one summary line with Change… instead of the tabs (Compare hosts). `tabs` are the picked tabs the summary
   * counts (picked on the tab row, not here).
   */
  compact?: { tabs: TabsPart };
  /** The page shows the core's notes itself (Compare hosts' alert). */
  hideNotes?: boolean;
  /** Changes when the lists should be read again (Compare hosts: a group changed in Manage groups). */
  refresh?: string;
}

function matches(needle: string, ...fields: (string | null | undefined)[]) {
  const n = needle.trim().toLowerCase();
  return !n || fields.some((f) => f?.toLowerCase().includes(n));
}

function sessionAddress(s: SessionRecord) {
  return `${s.username ? `${s.username}@` : ""}${s.host}:${s.port}`;
}

/** UX-16: five tabs in a side panel (Compare hosts): narrower than 28rem, smaller tabs and no icons (`@max-md`). */
const NARROW_TAB = "h-7 @max-md:px-0.5 @max-md:text-xs";

export function BulkTargetPicker({
  active,
  picks,
  onPicksChange,
  resolved,
  onOpenSessions,
  winrm = false,
  purpose = "run",
  compact,
  hideNotes = false,
  refresh = "",
}: Props) {
  const exporting = purpose === "export";
  const [allSessions, setSessions] = useState<SessionRecord[]>([]);
  // An export (the Ansible inventory) and a support bundle (BX-13) also take WinRM sessions; the key push goes over SSH.
  const withWinrm = winrm || exporting;
  const sessions = useMemo(
    () =>
      allSessions.filter((s) => {
        const protocol = kindOf(s).protocol;
        return protocol === "ssh" || (withWinrm && protocol === "winrm");
      }),
    [allSessions, withWinrm],
  );
  const otherKinds = allSessions.length - sessions.length;
  const [vms, setVms] = useState<VmRecord[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [filters, setFilters] = useState<SavedFilter[]>([]);
  const [groups, setGroups] = useState<MultiExecGroup[]>([]);
  const [folders, setFolders] = useState<SessionFolder[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [reload, setReload] = useState(0);
  const [confirming, setConfirming] = useState<string | null>(null);
  /** UX-16: compact mode's tabs, opened with Change…. */
  const [changing, setChanging] = useState(false);
  const isCompact = compact !== undefined;

  useEffect(() => {
    if (!active) return;
    let stale = false;
    Promise.all([
      api.sessions(),
      api.vmList(),
      api.tags(),
      api.savedFilters(),
      api.multiExecGroups(),
      // The summary names whole folders the tree picked.
      isCompact ? api.sessionFolders() : Promise.resolve([] as SessionFolder[]),
    ]).then(
      ([s, v, t, f, g, folderList]) => {
        if (stale) return;
        setSessions(s);
        setVms(v);
        setTags(t);
        setFilters(f);
        setGroups(g);
        setFolders(folderList);
        setError(null);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [active, reload, isCompact, refresh]);

  // Which session each VM is reached through: the first linked one by name, as the core picks it. A4, H11: only a
  // link the user chose or confirmed; an automatic one waits for a confirm.
  const [linked, autoLinked] = useMemo(() => {
    const confirmed = new Map<string, SessionRecord[]>();
    const automatic = new Map<string, SessionRecord[]>();
    for (const s of sessions) {
      if (!s.vmId) continue;
      const into = s.vmLink === "auto" ? automatic : confirmed;
      into.set(s.vmId, [...(into.get(s.vmId) ?? []), s]);
    }
    return [confirmed, automatic];
  }, [sessions]);

  async function confirmLink(sessionId: string) {
    setConfirming(sessionId);
    try {
      await api.confirmSessionVmLink(sessionId);
      setError(null);
      setReload((n) => n + 1);
      // The core resolves the picks again, now through the confirmed link.
      onPicksChange({ ...picks });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setConfirming(null);
    }
  }

  const set = (kind: PickKind, value: string, on: boolean) => onPicksChange(togglePick(picks, kind, value, on));
  const has = (kind: PickKind, value: string) => (picks[kind] ?? []).includes(value);
  const shownSessions = sessions.filter((s) => matches(text, s.name, s.host, s.username, ...s.tags));
  const shownVms = vms.filter((v) => matches(text, v.displayName, v.vmxPath, v.ipAddress, ...v.tags));
  const shownTags = tags.filter((t) => matches(text, t.name));
  const shownFilters = filters.filter((f) => matches(text, f.name));
  const shownGroups = groups.filter((g) => matches(text, g.name, ...g.members.map((m) => m.name)));
  // A group whose sessions this job doesn't take (a WinRM group under the key push or the Files push, SSH only) would
  // reach no host: it shows, but can't be picked, and says why.
  const reachable = useMemo(() => new Set(sessions.map((s) => s.id)), [sessions]);
  const groupReason = (g: MultiExecGroup) =>
    g.members.length > 0 && !g.members.some((m) => reachable.has(m.sessionId))
      ? withWinrm
        ? "None of its sessions is an SSH or WinRM session"
        : "Its sessions are WinRM sessions: this works over SSH only"
      : null;
  const picked = (kind: PickKind) => (picks[kind] ?? []).length;
  const anyPicked = anyPicks(picks);
  const hosts = resolved?.hosts ?? [];
  const skipped = hosts.filter((h) => h.protected);
  const prod = hosts.filter((h) => h.environment === "prod" && !h.protected);
  const without = resolved?.vmsWithoutSession ?? [];
  const unconfirmed = resolved?.vmsUnconfirmed ?? [];
  const hostCount = exporting ? hosts.length : hosts.length - skipped.length;

  function countBadge(kind: PickKind) {
    const n = picked(kind);
    return n > 0 ? (
      <Badge variant="secondary" className="ml-1 h-4 min-w-4 px-1 text-[10px] tabular-nums">
        {n}
      </Badge>
    ) : null;
  }

  const badges = (
    <>
      {skipped.length > 0 && (
        <Badge variant="outline" className="font-normal">
          {exporting ? `${skipped.length} protected` : `${skipped.length} protected, skipped`}
        </Badge>
      )}
      {prod.length > 0 && (
        <Badge variant="outline" className="border-env-prod/50 font-normal text-env-prod">
          {prod.length} Prod
        </Badge>
      )}
    </>
  );

  const leftOut = compact?.tabs.leftOut ?? 0;
  const summary = compact && (
    <div className="flex min-w-0 flex-wrap items-center gap-2 text-sm">
      <span className="grid min-w-0 flex-1 gap-0.5">
        <span className="font-medium break-words" title={hosts.map((h) => h.name).join(", ")}>
          {picksSummary(hostCount, picksParts(picks, compact.tabs, { sessions, folders, vms, filters, groups }))}
        </span>
        {leftOut > 0 && <span className="text-xs text-muted-foreground">{leftOutText(leftOut)}</span>}
      </span>
      {badges}
      <Button
        variant={changing ? "ghost" : "outline"}
        size="sm"
        aria-expanded={changing}
        onClick={() => setChanging((open) => !open)}
      >
        {changing ? "Done" : "Change…"}
      </Button>
    </div>
  );

  return (
    <div className="@container grid min-w-0 grid-cols-1 gap-3">
      {summary}
      {(!isCompact || changing) && (
        <>
          <Tabs defaultValue="sessions" className="gap-3">
            <TabsList className="w-full flex-wrap group-data-horizontal/tabs:h-auto">
              <TabsTrigger value="sessions" className={NARROW_TAB}>
                <ListTreeIcon className="@max-md:hidden" />
                Sessions
                {countBadge("sessionIds")}
              </TabsTrigger>
              <TabsTrigger value="vms" className={NARROW_TAB}>
                <ServerIcon className="@max-md:hidden" />
                VMs
                {countBadge("vmPaths")}
              </TabsTrigger>
              <TabsTrigger value="tags" className={NARROW_TAB}>
                <TagIcon className="@max-md:hidden" />
                Tags
                {countBadge("tags")}
              </TabsTrigger>
              <TabsTrigger value="filters" className={NARROW_TAB}>
                <FilterIcon className="@max-md:hidden" />
                Filters
                {countBadge("filterIds")}
              </TabsTrigger>
              <TabsTrigger value="groups" className={NARROW_TAB}>
                <LayersIcon className="@max-md:hidden" />
                Groups
                {countBadge("groupIds")}
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
              <PickList
                empty={
                  sessions.length > 0
                    ? "No session matches."
                    : otherKinds > 0
                      ? withWinrm
                        ? "No SSH or WinRM sessions yet."
                        : "No SSH sessions yet."
                      : "No saved sessions yet."
                }
              >
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
                        {s.protected && (
                          <ShieldIcon className="size-3.5 text-muted-foreground" aria-label="Protected" />
                        )}
                        <EnvBadge env={s.environment} />
                      </>
                    }
                  />
                ))}
              </PickList>
              {otherKinds > 0 && (
                <p className="mt-2 text-xs text-muted-foreground">
                  {exporting
                    ? `${plural(otherKinds, "remote desktop, VNC, Telnet or serial session")} not listed: the inventory takes SSH and WinRM sessions.`
                    : winrm
                      ? `${plural(otherKinds, "remote desktop, VNC, Telnet or serial session")} not listed: this works over SSH and WinRM only.`
                      : `${plural(otherKinds, "session")} of other kinds not listed: this works over SSH only.`}
                </p>
              )}
            </TabsContent>

            <TabsContent value="vms">
              <PickList empty={vms.length === 0 ? "No VMs found yet. Refresh the VM list." : "No VM matches."}>
                {shownVms.map((v) => {
                  const via = linked.get(v.id);
                  const auto = autoLinked.get(v.id);
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
                        ) : auto ? (
                          <span className="text-tier-medium">
                            Linked automatically to {auto[0].name}: confirm the link to run on it
                          </span>
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

            <TabsContent value="groups">
              <PickList
                empty={
                  groups.length === 0
                    ? "No saved groups yet. Save picked tabs as a group on the Terminal page."
                    : "No group matches."
                }
              >
                {shownGroups.map((g) => {
                  const reason = groupReason(g);
                  const checked = has("groupIds", g.id);
                  return (
                    <PickRow
                      key={g.id}
                      id={`pick-group-${g.id}`}
                      checked={checked}
                      // A picked one can still be taken out.
                      disabled={reason !== null && !checked}
                      onChange={(on) => set("groupIds", g.id, on)}
                      title={g.name}
                      detail={
                        g.members.length === 0 ? (
                          <span className="text-tier-medium">No sessions left: edit it in Manage groups</span>
                        ) : reason ? (
                          <span className="text-tier-medium">{reason}</span>
                        ) : (
                          `${plural(g.members.length, "session")}: ${memberNames(g.members)}`
                        )
                      }
                    />
                  );
                })}
              </PickList>
            </TabsContent>
          </Tabs>

          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}

          <div className="flex flex-wrap items-center gap-2 text-sm">
            {isCompact ? null : exporting && !anyPicked ? (
              <span className="text-muted-foreground">Nothing picked, so every SSH and WinRM session goes in</span>
            ) : (
              <span className="font-medium">{plural(hostCount, "host")}</span>
            )}
            {!isCompact && badges}
            {anyPicked && (
              <Button
                variant="ghost"
                size="sm"
                className="ml-auto"
                onClick={() => onPicksChange({ winrm: picks.winrm, terminalIds: picks.terminalIds })}
              >
                {isCompact ? "Clear these picks" : "Clear"}
              </Button>
            )}
          </div>
        </>
      )}
      {isCompact && !changing && error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}

      {without.length > 0 && (
        <Alert>
          <TriangleAlertIcon className="text-tier-medium" />
          <AlertTitle>
            {plural(without.length, "VM")} {exporting ? "left out" : "can't run commands yet"}:{" "}
            {without.map((v) => v.name).join(", ")}
          </AlertTitle>
          <AlertDescription>
            {exporting
              ? "A VM goes in through a session linked to it: edit a session and choose the VM it reaches."
              : "Commands reach a VM over SSH, through a session linked to it: edit a session and choose the VM it reaches."}
          </AlertDescription>
          <AlertAction>
            <Button size="sm" variant="outline" onClick={onOpenSessions}>
              Sessions
            </Button>
          </AlertAction>
        </Alert>
      )}
      {unconfirmed.length > 0 && (
        <Alert>
          <LinkIcon className="text-tier-medium" />
          <AlertTitle>
            {plural(unconfirmed.length, "VM")} linked only automatically, so {exporting ? "left out" : "not reached"}{" "}
            yet
          </AlertTitle>
          <AlertDescription>
            <p>
              These links follow the IP address each guest reports about itself, and a guest can report any address,
              even a production server&apos;s. Confirm a link once you know the session is that VM&apos;s own.
            </p>
            <ul className="mt-2 grid gap-1.5">
              {unconfirmed.map((u) => (
                <li key={u.vmxPath} className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{u.name}</span>
                  <span className="text-muted-foreground">through {u.sessionName}</span>
                  <span className="font-mono text-xs text-muted-foreground" data-mask="address">
                    {u.address}
                  </span>
                  <Button
                    size="sm"
                    variant="outline"
                    className="ml-auto h-7"
                    disabled={confirming !== null}
                    onClick={() => void confirmLink(u.sessionId)}
                  >
                    Confirm link
                  </Button>
                </li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
      {!hideNotes &&
        resolved?.notes.map((note) => (
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
  disabled = false,
}: {
  id: string;
  checked: boolean;
  onChange: (on: boolean) => void;
  title: string;
  detail?: React.ReactNode;
  mono?: boolean;
  extra?: React.ReactNode;
  /** QL-08: can't be picked; `detail` says why. */
  disabled?: boolean;
}) {
  return (
    <li className="flex items-center gap-3 px-3 py-2">
      <Checkbox id={id} checked={checked} disabled={disabled} onCheckedChange={(v) => onChange(v === true)} />
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
