// UX-19 (0.9.0 H4): the sessions the dashboard watches (MO-02) and how often it reads them, for Monitor ▸. Read when
// a menu opens (`enabled`), as the palette reads them each time it opens: never in the background. `watch` starts or
// stops watching (audited by the core, a read: no approval) and reads again.

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api, errorMessage } from "@/lib/api";

export interface Watched {
  /** null until read. */
  watched: Set<string> | null;
  /** Seconds between two reads of a watched host (Settings, Dashboard). */
  intervalSecs: number;
  watch: (sessionId: string, on: boolean) => Promise<void>;
}

export function useWatched(enabled: boolean): Watched {
  const [watched, setWatched] = useState<Set<string> | null>(null);
  const [intervalSecs, setIntervalSecs] = useState(5);

  const read = useCallback(
    () =>
      api.metricsOverview().then(
        (o) => {
          setWatched(new Set(o.rows.flatMap((r) => (r.watchedSession ? [r.watchedSession] : []))));
          if (o.cost.guestIntervalSecs > 0) setIntervalSecs(o.cost.guestIntervalSecs);
        },
        // Unread, it offers to watch: watching a watched session again changes nothing.
        () => setWatched(new Set()),
      ),
    [],
  );

  useEffect(() => {
    if (enabled) void read();
  }, [enabled, read]);

  const watch = useCallback(async (sessionId: string, on: boolean) => {
    try {
      const now = await api.metricsWatch(sessionId, on);
      setWatched(new Set(now));
      toast.success(
        on ? "Watching it on the dashboard. The first reading arrives within a round." : "Stopped watching",
      );
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }, []);

  return { watched, intervalSecs, watch };
}
