// Small text formatters shared by pages.

/** "1 session", "3 sessions"; a consonant and y takes "ies" ("2 entries", but "2 keys"). */
export function plural(n: number, word: string) {
  if (n === 1) return `${n} ${word}`;
  return `${n} ${/[^aeiou]y$/i.test(word) ? `${word.slice(0, -1)}ies` : `${word}s`}`;
}

/** "3 h 12 min", "4 min", "2 d 5 h". */
export function formatDuration(secs: number) {
  const minutes = Math.floor(secs / 60);
  if (minutes < 1) return `${Math.max(0, Math.floor(secs))} s`;
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return minutes % 60 ? `${hours} h ${minutes % 60} min` : `${hours} h`;
  const days = Math.floor(hours / 24);
  return hours % 24 ? `${days} d ${hours % 24} h` : `${days} d`;
}

/** "today", "yesterday", "45 days ago". */
export function formatAge(days: number | null) {
  if (days === null) return "unknown age";
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  return `${days} days ago`;
}

export function formatWhen(ts: string | null) {
  return ts ? new Date(ts).toLocaleString() : "—";
}
