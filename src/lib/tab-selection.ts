// Several terminal tabs picked at once (SS-11 bulk output; MultiExec and Compare in P6 use the same
// selection). Click picks one tab, Ctrl+click adds or removes a tab, Shift+click picks a range.
// Pure functions over tab keys, so any page can hold the selection in its own state.

export interface TabSelection {
  /** Picked tab keys. One or none means "the current tab" for actions. */
  keys: string[];
  /** Where a Shift+click range starts. */
  anchor: string | null;
}

export const NO_SELECTION: TabSelection = { keys: [], anchor: null };

/** What a click on a tab does to the selection. `order` is every tab key, left to right. */
export function clickTab(
  selection: TabSelection,
  key: string,
  order: string[],
  modifiers: { ctrl: boolean; shift: boolean },
): TabSelection {
  if (modifiers.shift) {
    const from = order.indexOf(selection.anchor ?? key);
    const to = order.indexOf(key);
    if (from < 0 || to < 0) return { keys: [key], anchor: key };
    const [a, b] = from <= to ? [from, to] : [to, from];
    return { keys: order.slice(a, b + 1), anchor: selection.anchor ?? key };
  }
  if (modifiers.ctrl) {
    const has = selection.keys.includes(key);
    // The first Ctrl+click keeps the tab that was current, so it and the new one are picked.
    const base =
      selection.keys.length === 0 && selection.anchor && selection.anchor !== key ? [selection.anchor] : selection.keys;
    const keys = has ? base.filter((k) => k !== key) : [...base, key];
    return { keys: order.filter((k) => keys.includes(k)), anchor: key };
  }
  return { keys: [], anchor: key };
}

/** Drops keys of tabs that closed. */
export function pruneSelection(selection: TabSelection, order: string[]): TabSelection {
  const keys = selection.keys.filter((k) => order.includes(k));
  const anchor = selection.anchor && order.includes(selection.anchor) ? selection.anchor : null;
  if (keys.length === selection.keys.length && anchor === selection.anchor) return selection;
  return { keys, anchor };
}

/** Two or more tabs picked: actions apply to all of them. */
export function isMulti(selection: TabSelection) {
  return selection.keys.length > 1;
}
