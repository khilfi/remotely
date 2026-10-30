// MO-16, MO-14: a watched SSH host's services on the dashboard: failed ones first, then the running ones. Read once a
// minute while the dashboard shows and the window is visible (usePoll), on the dashboard's kept connection to the host
// only: it never logs in on its own, so a host that is not watched reads nothing and says to watch it (UX-03: with the
// page's Watch hosts, the one place to watch a host).

import { useState } from "react";
import { ServerCogIcon } from "lucide-react";
import { Input } from "@/components/ui/input";
import { usePoll } from "@/hooks/use-poll";
import { errorMessage } from "@/lib/api";
import { dashboardApi, type ServicesRead } from "@/lib/dashboard-api";
import { cn } from "@/lib/utils";

/** How often the widget reads the host's services. */
export const SERVICES_POLL_MS = 60_000;

const MANAGER: Record<string, string> = { systemd: "systemd", openRc: "OpenRC", sysV: "SysV init", unknown: "" };

export function ServicesWidget({
  sessionId,
  name,
  live,
}: {
  /** The host, or null until one is chosen (Customize). */
  sessionId: string | null;
  name: string | null;
  live: boolean;
}) {
  const [read, setRead] = useState<{ id: string; read: ServicesRead } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  usePoll(
    async (stillLive) => {
      if (!sessionId) return;
      try {
        const answer = await dashboardApi.services(sessionId);
        if (!stillLive()) return;
        setRead({ id: sessionId, read: answer });
        setError(null);
      } catch (err) {
        if (stillLive()) setError(errorMessage(err));
        throw err;
      }
    },
    { enabled: live && sessionId !== null, resetKey: sessionId ?? "", intervalMs: SERVICES_POLL_MS },
  );

  const current = read && read.id === sessionId ? read.read : null;
  const body = () => {
    if (!sessionId) {
      return <p className="text-xs text-muted-foreground">Choose a host in Customize.</p>;
    }
    if (error && !current) return <p className="text-xs text-destructive">{error}</p>;
    if (!current) return <p className="text-xs text-muted-foreground">Reading the services…</p>;
    if (current.state === "notConnected") {
      return current.watched ? (
        <p className="text-xs text-muted-foreground">
          Waiting for the dashboard&apos;s connection to {name ?? "the host"}. The services show once it answers.
        </p>
      ) : (
        <p className="text-xs text-muted-foreground">
          Not watched: watch {name ?? "the host"} with Watch hosts to see its services.
        </p>
      );
    }
    const { report } = current;
    const needle = filter.trim().toLowerCase();
    const match = (s: { name: string; description: string | null }) =>
      !needle || s.name.toLowerCase().includes(needle) || (s.description ?? "").toLowerCase().includes(needle);
    const rows = [
      ...report.failed.filter(match).map((s) => ({ ...s, failed: true })),
      ...report.running.filter(match).map((s) => ({ ...s, failed: false })),
    ];
    return (
      <div className="flex min-h-0 flex-1 flex-col gap-2">
        <div className="flex flex-wrap items-center gap-x-2 text-xs whitespace-nowrap text-muted-foreground">
          <span className={cn(report.failed.length > 0 && "font-medium text-status-critical")}>
            {report.failed.length} failed
          </span>
          <span>{report.running.length} running</span>
          {MANAGER[report.serviceManager] && <span>{MANAGER[report.serviceManager]}</span>}
          <span className="ml-auto tabular-nums" title="Read every minute while the dashboard shows">
            {new Date(report.collectedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
          </span>
        </div>
        <Input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter services"
          aria-label="Filter services"
          className="h-7 text-xs"
        />
        <ul className="min-h-0 flex-1 overflow-auto text-xs">
          {rows.map((s) => (
            <li
              key={`${s.failed}-${s.name}`}
              className="flex items-baseline gap-2 py-0.5"
              title={s.description ?? undefined}
            >
              <span
                className={cn("size-2 shrink-0 rounded-full", s.failed ? "bg-status-critical" : "bg-success")}
                aria-label={s.failed ? "Failed" : "Running"}
              />
              <span className={cn("truncate font-mono", s.failed && "text-status-critical")}>{s.name}</span>
            </li>
          ))}
          {rows.length === 0 && <li className="text-muted-foreground">No service matches.</li>}
        </ul>
        {error && <p className="text-xs text-destructive">{error}</p>}
      </div>
    );
  };

  return (
    <section
      aria-label={name ? `Services of ${name}` : "Services"}
      className="flex h-full min-h-0 flex-col rounded-lg border bg-card p-3"
    >
      <div className="mb-2 flex items-center gap-2">
        <ServerCogIcon className="size-4 text-muted-foreground" />
        <span className="truncate text-sm font-medium">{name ? `Services of ${name}` : "Services"}</span>
      </div>
      {body()}
    </section>
  );
}
