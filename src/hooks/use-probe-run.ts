// FD-09: one Toolbox run at a time per tool: an id for its `toolbox://progress` events, what has come so far, the
// result or the error, and Stop.

import { useCallback, useEffect, useRef, useState } from "react";
import { errorMessage } from "@/lib/api";
import { toolboxApi, type ProbeProgress } from "@/lib/toolbox-api";

export interface ProbeRun<T> {
  running: boolean;
  progress: ProbeProgress[];
  result: T | null;
  error: string | null;
  start: (work: (run: string) => Promise<T>) => Promise<void>;
  stop: () => void;
  clear: () => void;
}

function newRunId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2)}`;
  }
}

export function useProbeRun<T>(): ProbeRun<T> {
  const current = useRef<string | null>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<ProbeProgress[]>([]);
  const [result, setResult] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    let gone = false;
    void toolboxApi
      .onProgress((event) => {
        if (event.run === current.current) setProgress((list) => [...list, event.progress].slice(-500));
      })
      .then((stop) => {
        if (gone) stop();
        else unlisten = stop;
      });
    return () => {
      gone = true;
      unlisten?.();
      // A run still going when the page goes away stops.
      if (current.current) void toolboxApi.cancel(current.current).catch(() => undefined);
    };
  }, []);

  const start = useCallback(async (work: (run: string) => Promise<T>) => {
    const run = newRunId();
    if (current.current) void toolboxApi.cancel(current.current).catch(() => undefined);
    current.current = run;
    setRunning(true);
    setProgress([]);
    setResult(null);
    setError(null);
    try {
      const done = await work(run);
      if (current.current === run) setResult(done);
    } catch (err) {
      if (current.current === run) setError(errorMessage(err));
    } finally {
      if (current.current === run) {
        current.current = null;
        setRunning(false);
      }
    }
  }, []);

  const stop = useCallback(() => {
    if (current.current) void toolboxApi.cancel(current.current).catch(() => undefined);
  }, []);

  const clear = useCallback(() => {
    setProgress([]);
    setResult(null);
    setError(null);
  }, []);

  return { running, progress, result, error, start, stop, clear };
}
