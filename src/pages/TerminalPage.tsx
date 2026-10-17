// Terminal panel (SS-03 plumbing): xterm.js wired to the core over IPC. Until SSH lands the core
// hands out a loopback shell, so nothing typed here leaves the machine.

import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { api, errorMessage } from "@/lib/api";
import type { ResolvedTheme } from "@/lib/theme";

const MONO = "'Cascadia Mono', 'Cascadia Code', Consolas, monospace";

// In code rather than CSS variables: React runs this page's effects before the app flips the `dark`
// class, so reading CSS variables on a theme change would pick up the old colours.
const PALETTE = {
  light: { background: "#fafafa", foreground: "#1f1f1f", cursor: "#1f1f1f", selectionBackground: "#0000002e" },
  dark: { background: "#0c0c0d", foreground: "#e4e4e7", cursor: "#e4e4e7", selectionBackground: "#ffffff38" },
} as const;

interface Props {
  /** The page stays mounted while hidden so the session survives; refit when it shows again. */
  active: boolean;
  theme: ResolvedTheme;
}

export function TerminalPage({ active, theme }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const term = new Terminal({
      fontFamily: MONO,
      fontSize: 13,
      cursorBlink: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host);
    termRef.current = term;
    fitRef.current = fit;

    let id: string | null = null;
    let closed = false;
    const subscriptions = [
      term.onData((data) => {
        if (id) void api.terminalWrite(id, data);
      }),
      term.onResize(({ cols, rows }) => {
        if (id) void api.terminalResize(id, cols, rows);
      }),
    ];
    api
      .terminalOpen((data) => term.write(data))
      .then((opened) => {
        if (closed) {
          void api.terminalClose(opened);
          return;
        }
        id = opened;
        void api.terminalResize(opened, term.cols, term.rows);
      })
      .catch((err) => term.write(`\r\nCould not open the terminal: ${errorMessage(err)}\r\n`));

    const observer = new ResizeObserver(() => {
      if (host.offsetWidth > 0) fit.fit();
    });
    observer.observe(host);

    return () => {
      closed = true;
      observer.disconnect();
      subscriptions.forEach((s) => s.dispose());
      if (id) void api.terminalClose(id);
      term.dispose();
      termRef.current = null;
    };
  }, []);

  // Runs after the terminal is created on mount, and on every theme change.
  useEffect(() => {
    if (termRef.current) termRef.current.options.theme = PALETTE[theme];
  }, [theme]);

  useEffect(() => {
    if (!active) return;
    fitRef.current?.fit();
    termRef.current?.focus();
  }, [active]);

  return (
    <div className="flex h-full flex-col gap-3">
      <p className="text-sm text-muted-foreground">
        Loopback shell: SSH sessions arrive with SS-03. What you type is echoed locally and sent nowhere.
      </p>
      <div
        ref={hostRef}
        className="terminal-host min-h-60 flex-1 overflow-hidden rounded-lg border p-2"
        style={{ background: PALETTE[theme].background }}
      />
    </div>
  );
}
