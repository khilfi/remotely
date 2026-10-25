// MO-02, MO-03: a VM row's charts put its host side (read every 5 s) and its guest (read every 5 to 60 s, Settings,
// Dashboard) on one time line, so the guest series has no value at the times only the host side was read. uPlot breaks
// a line at `null` and joins over `undefined`: short runs of missing guest readings become `undefined`, so the guest's
// line stays a line, while a longer gap (the host stopped answering) still shows as one. Tested in chart-gaps.test.ts.

/**
 * `values` (one per time in `times`, Unix milliseconds) with each run of nulls between two readings at most `maxGapMs`
 * apart turned into `undefined`. Longer runs, and nulls before the first or after the last reading, stay `null`.
 */
export function joinShortGaps(
  times: number[],
  values: (number | null)[],
  maxGapMs: number,
): (number | null | undefined)[] {
  const out: (number | null | undefined)[] = [...values];
  let last = -1;
  for (let i = 0; i < values.length; i++) {
    if (values[i] === null) continue;
    if (last >= 0 && i - last > 1 && times[i] - times[last] <= maxGapMs) {
      for (let j = last + 1; j < i; j++) out[j] = undefined;
    }
    last = i;
  }
  return out;
}

/** The longest run joined for a guest polled every `intervalSecs`: one missed reading still shows as a gap. */
export function guestGapMs(intervalSecs: number): number {
  return Math.max(intervalSecs, 5) * 1500;
}
