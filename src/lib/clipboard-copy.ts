// QL-05: a terminal's selection goes to the clipboard through the core, which scrubs the terminal's secrets from it,
// and the shell, which keeps it out of Windows' clipboard history and cloud clipboard; never through the browser's
// clipboard API. Each copy is an IPC call that finishes in its own time, so copies go one at a time, and of those
// made while one is on its way only the newest is kept: the clipboard always ends up with the last selection. Pure,
// tested in clipboard-copy.test.ts.

/**
 * Sends values one at a time, in the order they came; of the values that come while one is being sent, only the
 * newest is sent after it. A failed send goes to `onError` and the next one still goes.
 */
export function latestOnly<T>(send: (value: T) => Promise<void>, onError: (err: unknown) => void): (value: T) => void {
  let busy = false;
  let waiting: { value: T } | null = null;
  const next = () => {
    if (busy || waiting === null) return;
    const { value } = waiting;
    waiting = null;
    busy = true;
    let sent: Promise<void>;
    try {
      sent = send(value);
    } catch (err) {
      sent = Promise.reject(err);
    }
    void sent.catch(onError).finally(() => {
      busy = false;
      next();
    });
  };
  return (value: T) => {
    waiting = { value };
    next();
  };
}
