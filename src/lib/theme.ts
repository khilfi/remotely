// Dark and light themes (FD-01). "system" follows Windows; the choice is remembered per machine.

import { useEffect, useState } from "react";

export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

const STORAGE_KEY = "remotely.theme";
const darkQuery = () => window.matchMedia("(prefers-color-scheme: dark)");

function readPreference(): ThemePreference {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "light" || saved === "dark" || saved === "system") return saved;
  } catch {
    // Storage can be unavailable; fall back to the system theme.
  }
  return "system";
}

export function useTheme() {
  const [preference, setPreference] = useState<ThemePreference>(readPreference);
  const [systemDark, setSystemDark] = useState(() => darkQuery().matches);

  useEffect(() => {
    const query = darkQuery();
    const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, preference);
    } catch {
      // Not persisted; still applied for this session.
    }
  }, [preference]);

  const resolved: ResolvedTheme = preference === "system" ? (systemDark ? "dark" : "light") : preference;

  // shadcn/ui switches its colour tokens on the `dark` class (src/styles.css).
  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle("dark", resolved === "dark");
    root.style.colorScheme = resolved;
  }, [resolved]);

  return { preference, setPreference, resolved };
}
