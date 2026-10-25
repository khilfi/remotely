// QL-24 density: comfortable (the default, shadcn's own spacing) or compact. Applied through the tokens, not one-off
// CSS: `data-density` on <html> sets Tailwind's `--spacing` (every padding, gap, height and margin utility is a
// multiple of it, shadcn's components included) and shadcn's `--radius` (styles.css, "QL-24 density"). Text sizes stay
// the same, so compact fits more rows without getting harder to read; terminals keep their own font size. Remembered
// per machine, like the theme (theme.ts). Pure helpers are tested in density.test.ts.

import { useSyncExternalStore } from "react";

export type Density = "comfortable" | "compact";

export const DENSITIES: { value: Density; label: string; hint: string }[] = [
  { value: "comfortable", label: "Comfortable", hint: "The default spacing." },
  { value: "compact", label: "Compact", hint: "Tighter spacing: more rows of VMs, sessions and jobs on screen." },
];

const STORAGE_KEY = "remotely.density";

/** A stored value, or the default for anything else. */
export function parseDensity(value: string | null | undefined): Density {
  return value === "compact" ? "compact" : "comfortable";
}

function read(): Density {
  try {
    return parseDensity(localStorage.getItem(STORAGE_KEY));
  } catch {
    return "comfortable";
  }
}

let current: Density | null = null;
const listeners = new Set<() => void>();

function apply(density: Density) {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.density = density;
}

function get(): Density {
  if (current === null) {
    current = read();
    apply(current);
  }
  return current;
}

export function setDensity(density: Density) {
  current = density;
  try {
    localStorage.setItem(STORAGE_KEY, density);
  } catch {
    // Not kept; still applied for this run.
  }
  apply(density);
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Applies the saved density at start (main.tsx), before the first paint. */
export function applySavedDensity() {
  get();
}

export function useDensity(): [Density, (density: Density) => void] {
  return [useSyncExternalStore(subscribe, get), setDensity];
}
