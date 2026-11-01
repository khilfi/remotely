// 0.7.0 F6: an export that may read every SSH host first (the inventory to Excel, the handover pack): the run's id,
// how many hosts are done (`reports://progress`), and the cancel. Closing the dialog cancels a run still going (the
// core then writes nothing), so its Cancel button stays on while the hosts are read.

import { useEffect, useRef, useState } from "react";
import { reportsApi, type ReadProgress } from "@/lib/reports-api";

function newRunId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}`;
  }
}

export interface ExportRun {
  busy: boolean;
  /** Hosts done of those asked, once the reads began. */
  progress: ReadProgress | null;
  /** Runs `work` under a new id. */
  run: <T>(work: (run: string) => Promise<T>) => Promise<T>;
}

export function useExportRun(): ExportRun {
  const current = useRef<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<ReadProgress | null>(null);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let gone = false;
    void reportsApi
      .onProgress((event) => {
        if (event.run === current.current) setProgress({ done: event.done, total: event.total });
      })
      .then((stop) => {
        if (gone) stop();
        else unlisten = stop;
      });
    return () => {
      gone = true;
      unlisten?.();
      // The dialog closed (Cancel, Esc, a click outside) while its hosts were read: they stop, nothing is written.
      if (current.current) void reportsApi.cancel(current.current).catch(() => undefined);
    };
  }, []);

  async function run<T>(work: (run: string) => Promise<T>): Promise<T> {
    const id = newRunId();
    current.current = id;
    setBusy(true);
    setProgress(null);
    try {
      return await work(id);
    } finally {
      if (current.current === id) {
        current.current = null;
        setBusy(false);
      }
    }
  }

  return { busy, progress, run };
}
