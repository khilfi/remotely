// Dark and light themes (FD-01). QL-11: the top bar's Dark mode switch picks dark or light; "Follow Windows" in
// Settings, General lets Windows decide instead (the default), and using the switch turns it off. While Windows
// decides, the switch shows the theme in effect. The choice is remembered per machine. This module is the one place
// that sets the `dark` class on <html>; the pure helpers are tested in theme.test.ts.

import { useSyncExternalStore } from "react";

export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

const STORAGE_KEY = "remotely.theme";

/** The theme shown for a preference, given whether Windows is dark. */
export function resolveTheme(preference: ThemePreference, systemDark: boolean): ResolvedTheme {
  return preference === "system" ? (systemDark ? "dark" : "light") : preference;
}

/** QL-11: the preference once the Dark mode switch is set: a fixed theme, so Windows no longer decides. */
export function afterDarkSwitch(dark: boolean): ThemePreference {
  return dark ? "dark" : "light";
}

/** QL-11: the preference once "Follow Windows" is set. Turning it off keeps the theme on screen. */
export function afterFollowWindows(follow: boolean, preference: ThemePreference, systemDark: boolean): ThemePreference {
  return follow ? "system" : resolveTheme(preference, systemDark);
}

function readPreference(): ThemePreference {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "light" || saved === "dark" || saved === "system") return saved;
  } catch {
    // Storage can be unavailable; fall back to the system theme.
  }
  return "system";
}

interface ThemeState {
  preference: ThemePreference;
  systemDark: boolean;
}

let state: ThemeState | null = null;
const listeners = new Set<() => void>();

/** shadcn/ui switches its colour tokens on the `dark` class (src/styles.css). */
function apply({ preference, systemDark }: ThemeState) {
  const resolved = resolveTheme(preference, systemDark);
  const root = document.documentElement;
  root.classList.toggle("dark", resolved === "dark");
  root.style.colorScheme = resolved;
}

/** The theme state, read and applied on first use, following Windows' setting from then on. */
function current(): ThemeState {
  if (state) return state;
  const query = window.matchMedia("(prefers-color-scheme: dark)");
  state = { preference: readPreference(), systemDark: query.matches };
  query.addEventListener("change", (e) => update({ systemDark: e.matches }));
  apply(state);
  return state;
}

function update(change: Partial<ThemeState>) {
  const next = { ...current(), ...change };
  state = next;
  try {
    localStorage.setItem(STORAGE_KEY, next.preference);
  } catch {
    // Not persisted; still applied for this session.
  }
  apply(next);
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function useTheme() {
  const { preference, systemDark } = useSyncExternalStore(subscribe, current);
  return {
    preference,
    /** The theme on screen. */
    resolved: resolveTheme(preference, systemDark),
    /** QL-11: Windows decides the theme. */
    followWindows: preference === "system",
    /** QL-11: the top bar's switch; Windows no longer decides. */
    setDark: (dark: boolean) => update({ preference: afterDarkSwitch(dark) }),
    /** QL-11: Settings, General. */
    setFollowWindows: (follow: boolean) =>
      update({ preference: afterFollowWindows(follow, current().preference, current().systemDark) }),
  };
}
