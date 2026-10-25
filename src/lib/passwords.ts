// SS-04, FD-07: how the meter under a new vault password or export passphrase reads the core's strength score
// (zxcvbn's 0 to 4). The core's own check decides when the form is submitted; this only shows it.

/** The same levels as the dashboard's meters (`Level` in metrics.ts), so `Meter` draws it. */
export type StrengthLevel = "ok" | "warning" | "critical";

/** A word for each score, 0 to 4. */
export const STRENGTH_LABEL = ["Very weak", "Weak", "Fair", "Good", "Strong"] as const;

export interface StrengthView {
  /** How full the meter is, 0 to 100: a quarter a point, a sliver at 0. */
  percent: number;
  /** Red or amber while the core would refuse it, green once it takes it. */
  level: StrengthLevel;
  label: (typeof STRENGTH_LABEL)[number];
}

export function strengthView(score: number, acceptable: boolean): StrengthView {
  const s = Math.max(0, Math.min(4, Math.round(Number.isFinite(score) ? score : 0)));
  return {
    percent: s === 0 ? 5 : s * 25,
    level: acceptable ? "ok" : s >= 2 ? "warning" : "critical",
    label: STRENGTH_LABEL[s],
  };
}
