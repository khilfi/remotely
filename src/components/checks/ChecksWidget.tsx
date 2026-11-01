// MO-08 on MO-16's grid: how many health checks are up, failing and down, and the ones that need a look (down first),
// each opening its history on the Checks tab. Read when the dashboard shows and after each run, never while hidden.

import { useEffect, useState } from "react";
import { CheckCircle2Icon, HeartPulseIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { CheckStatusBadge } from "@/components/checks/CheckBits";
import { checksApi, type ChecksOverview } from "@/lib/checks-api";
import { needingLook } from "@/lib/checks";
import { requestLink } from "@/lib/links";

export function ChecksWidget({ live }: { live: boolean }) {
  const [overview, setOverview] = useState<ChecksOverview | null>(null);

  useEffect(() => {
    if (!live) return;
    let stopped = false;
    let timer: number | undefined;
    const read = () =>
      checksApi.overview("24h").then(
        (o) => {
          if (!stopped) setOverview(o);
        },
        () => undefined,
      );
    void read();
    const unlisten = checksApi.onEvent(() => {
      if (timer !== undefined) return;
      timer = window.setTimeout(() => {
        timer = undefined;
        void read();
      }, 1000);
    });
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      void unlisten.then((stop) => stop());
    };
  }, [live]);

  if (!overview) return <p className="text-sm text-muted-foreground">Reading the checks…</p>;
  const s = overview.summary;
  if (s.total === 0) {
    return (
      <div className="flex h-full flex-col items-start justify-center gap-2 text-sm text-muted-foreground">
        <p>No health checks yet.</p>
        <Button variant="outline" size="sm" onClick={() => requestLink({ kind: "checks" })}>
          <HeartPulseIcon data-icon="inline-start" />
          Open the checks
        </Button>
      </div>
    );
  }
  const look = needingLook(overview.rows);
  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
        <span>
          <span className="font-medium tabular-nums">{s.up}</span> up
        </span>
        <span className={s.failing > 0 ? "text-status-warning" : "text-muted-foreground"}>
          <span className="font-medium tabular-nums">{s.failing}</span> failing
        </span>
        <span className={s.down > 0 ? "text-status-critical" : "text-muted-foreground"}>
          <span className="font-medium tabular-nums">{s.down}</span> down
        </span>
        {s.paused > 0 && (
          <span className="text-muted-foreground">
            <span className="tabular-nums">{s.paused}</span> paused
          </span>
        )}
      </div>
      {look.length === 0 ? (
        <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
          <CheckCircle2Icon className="size-4 text-success" />
          Every check is up.
        </p>
      ) : (
        <ul className="min-h-0 flex-1 overflow-y-auto">
          {look.map((row) => (
            <li key={row.check.id}>
              <button
                type="button"
                className="flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-accent"
                onClick={() => requestLink({ kind: "checks", checkId: row.check.id })}
              >
                <CheckStatusBadge status={row.status} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{row.check.name}</span>
                  {row.last && <span className="block truncate text-xs text-muted-foreground">{row.last.detail}</span>}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
