// UX-19 (0.9.0 H4): the sessions the dashboard watches (MO-02) and how often it reads them, for Monitor ▸ and the
// palette. Read when a menu or the palette opens (`enabled`), never in the background, from `metrics_watched`: the
// whole list, since the overview's rows name one watched session per VM, however many of its sessions are watched.
// `watch` starts or stops watching (audited by the core, a read: no approval) and keeps the list it returns.

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api, errorMessage } from "@/lib/api";
import { watchedFrom } from "@/lib/monitor";

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

  useEffect(() => {
    if (!enabled) return;
    let stale = false;
    api.metricsWatched().then(
      (hosts) => {
        if (stale) return;
        const read = watchedFrom(hosts);
        setWatched(read.watched);
        setIntervalSecs(read.intervalSecs);
      },
      // Unread, it offers to watch: watching a watched session again changes nothing.
      () => {
        if (!stale) setWatched(new Set());
      },
    );
    return () => {
      stale = true;
    };
  }, [enabled]);

  const watch = useCallback(async (sessionId: string, on: boolean) => {
    try {
      setWatched(new Set(await api.metricsWatch(sessionId, on)));
      toast.success(
        on ? "Watching it on the dashboard. The first reading arrives within a round." : "Stopped watching",
      );
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }, []);

  return { watched, intervalSecs, watch };
}
