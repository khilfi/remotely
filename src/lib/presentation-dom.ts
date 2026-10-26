// FD-03: masks what the window shows while presenting, at the DOM. Every text node, and the attributes that show text
// (title, aria-label, placeholder, alt, the terminal's drop label), goes through the masker in presentation.ts, whether
// React rendered it, a toast or tooltip showed it in a portal, or the core built it in Rust (errors, approval
// summaries, audit text). One place, so no page can forget it.
//
// A MutationObserver masks new and changed text in the microtask after the change, which runs before the browser
// paints: a page, dialog or toast never shows a real value first. The real text is kept per node (in memory, next to
// the node) and put back when presenting stops; React keeps writing real text, which is masked again as it lands.
// Adjacent text nodes are masked together, so `{user}@{host}` in JSX is still seen as user@host. A value the masker
// learns later (from an answer that arrived after the text) is masked in what is on screen already: the values learnt
// in one go are gathered, and in the next microtask (still before paint) only the text and attributes that mention one
// of them are masked again (presentation-rescan.ts), not the whole window.
//
// Not rewritten:
// - Terminals (`data-presentation-skip`): each pane masks its output stream itself (terminal-session.ts).
// - Inputs and text areas: their value is what the user edits and saves. Those marked `data-mask` show dots while
//   presenting, and so does any other one whose value holds something to mask (checked as it appears and as it is
//   typed into).

import { masker, type MaskKind, type Replacement } from "@/lib/presentation";
import { LearnedBatch, mentionsAny } from "@/lib/presentation-rescan";

const SKIP = "[data-presentation-skip]";
/** Attributes whose text the user can see (a tooltip, a placeholder, the drop label's CSS `content`). */
const TEXT_ATTRIBUTES = ["title", "aria-label", "aria-description", "placeholder", "alt", "data-drop"];
/** Elements whose text children are not shown, or are a form's value. */
const NO_TEXT = new Set(["SCRIPT", "STYLE", "TEXTAREA", "NOSCRIPT", "TEMPLATE"]);
const TEXT_INPUTS = new Set(["text", "search", "url", "email", "tel", ""]);
/** Set on an unmarked input whose value holds something to mask; styles.css shows it as dots. */
export const HIDDEN_VALUE = "data-presentation-hidden";

type Kept = { real: string; shown: string };
const texts = new WeakMap<Text, Kept>();
const attributes = new WeakMap<Element, Map<string, Kept>>();

let observer: MutationObserver | null = null;
let stopListening: (() => void) | null = null;
/** Values learnt since the last rescan of what is on screen. */
const learnt = new LearnedBatch();

/**
 * React sets an input's value as a property, which no event or mutation reports, so the inputs' `value` setter is
 * wrapped once, before React's first render (it keeps the setter it finds when an input mounts): while masking, each
 * new value is checked like a typed one. The value itself is set unchanged.
 */
function watchValues() {
  if (typeof window === "undefined") return;
  for (const proto of [HTMLInputElement.prototype, HTMLTextAreaElement.prototype]) {
    const own = Object.getOwnPropertyDescriptor(proto, "value");
    const set = own?.set;
    if (!own || !set) continue;
    Object.defineProperty(proto, "value", {
      ...own,
      set(this: HTMLInputElement | HTMLTextAreaElement, value: string) {
        set.call(this, value);
        if (observer) checkInput(this);
      },
    });
  }
}
watchValues();

/** Masks the whole window now, then everything that appears or changes, until `stopDomMasking`. */
export function startDomMasking() {
  if (observer || typeof document === "undefined") return;
  observer = new MutationObserver(onMutations);
  maskTree(document.body);
  observer.observe(document.body, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: TEXT_ATTRIBUTES,
  });
  // A value learnt from an answer that arrived later is masked in what is on screen already.
  const unlisten = masker.onChange((learned) => {
    if (learnt.add(learned)) queueMicrotask(rescan);
  });
  document.addEventListener("input", onInput, true);
  stopListening = () => {
    unlisten();
    document.removeEventListener("input", onInput, true);
  };
}

/** Puts every real text back. */
export function stopDomMasking() {
  if (!observer) return;
  observer.disconnect();
  observer = null;
  stopListening?.();
  stopListening = null;
  restoreTree(document.body);
}

/** Masks again the text, attributes and inputs on screen that mention a value learnt since the last rescan. */
function rescan() {
  const mentions = mentionsAny(learnt.take());
  if (!observer || !mentions) return;
  const body = document.body;
  // Text: each element holding text is looked at once, its runs of text nodes cut as `maskChildren` cuts them.
  const looked = new Set<Element>();
  const parents: Element[] = [];
  const walker = document.createTreeWalker(body, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
    acceptNode: (node) => {
      if (node instanceof Element) {
        if (node.matches(SKIP)) return NodeFilter.FILTER_REJECT;
        return NO_TEXT.has(node.tagName) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_SKIP;
      }
      return NodeFilter.FILTER_ACCEPT;
    },
  });
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const parent = node.parentElement;
    if (!parent || looked.has(parent)) continue;
    looked.add(parent);
    if (textRuns(parent).some(mentions)) parents.push(parent);
  }
  for (const el of parents) maskChildren(el);
  // Attributes that show text, and inputs whose value may now hold something to mask.
  for (const el of body.querySelectorAll(TEXT_ATTRIBUTES.map((name) => `[${name}]`).join(","))) {
    if (el.closest(SKIP)) continue;
    for (const name of TEXT_ATTRIBUTES) {
      const value = el.getAttribute(name);
      if (value === null) continue;
      const before = attributes.get(el)?.get(name);
      if (mentions(before && value === before.shown ? before.real : value)) maskAttribute(el, name);
    }
  }
  for (const el of body.querySelectorAll("input, textarea")) {
    const value = (el as HTMLInputElement | HTMLTextAreaElement).value;
    if (mentions(value) && !el.closest(SKIP)) checkInput(el);
  }
}

function onInput(event: Event) {
  if (event.target instanceof Element) checkInput(event.target);
}

function onMutations(records: MutationRecord[]) {
  const parents = new Set<Element>();
  const added: Element[] = [];
  const changedAttributes: [Element, string][] = [];
  for (const r of records) {
    if (r.type === "characterData") {
      const parent = r.target.parentElement;
      if (parent) parents.add(parent);
    } else if (r.type === "childList") {
      if (r.target instanceof Element) parents.add(r.target);
      r.addedNodes.forEach((n) => {
        if (n instanceof Element) added.push(n);
      });
    } else if (r.type === "attributes" && r.attributeName && r.target instanceof Element) {
      changedAttributes.push([r.target, r.attributeName]);
    }
  }
  for (const el of added) if (el.isConnected) maskTree(el);
  for (const el of parents) if (el.isConnected && !el.closest(SKIP)) maskChildren(el);
  for (const [el, name] of changedAttributes) if (el.isConnected && !el.closest(SKIP)) maskAttribute(el, name);
}

function maskTree(root: Element) {
  if (root.closest(SKIP)) return;
  visit(root);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT, {
    acceptNode: (node) => ((node as Element).matches(SKIP) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT),
  });
  for (let node = walker.nextNode(); node; node = walker.nextNode()) visit(node as Element);
}

function visit(el: Element) {
  maskChildren(el);
  for (const name of TEXT_ATTRIBUTES) if (el.hasAttribute(name)) maskAttribute(el, name);
  checkInput(el);
}

/** The kind of value an element marked `data-mask` holds. */
function fieldKind(el: Element): MaskKind | "address" | null {
  const kind = el.closest("[data-mask]")?.getAttribute("data-mask");
  return kind === "host" ||
    kind === "ip" ||
    kind === "user" ||
    kind === "mac" ||
    kind === "workspace" ||
    kind === "address"
    ? kind
    : null;
}

function maskChildren(el: Element) {
  if (NO_TEXT.has(el.tagName)) return;
  const kind = fieldKind(el);
  let run: Text[] = [];
  for (let node = el.firstChild; node; node = node.nextSibling) {
    if (node.nodeType === Node.TEXT_NODE) run.push(node as Text);
    else if (node.nodeType !== Node.COMMENT_NODE) {
      maskRun(run, kind);
      run = [];
    }
  }
  maskRun(run, kind);
}

/** The real text of each run of text nodes `maskChildren` masks as one (comments don't end a run; elements do). */
function textRuns(el: Element): string[] {
  const runs: string[] = [];
  let run: string | null = null;
  for (let node = el.firstChild; node; node = node.nextSibling) {
    if (node.nodeType === Node.TEXT_NODE) run = (run ?? "") + realText(node as Text);
    else if (node.nodeType !== Node.COMMENT_NODE && run !== null) {
      runs.push(run);
      run = null;
    }
  }
  if (run !== null) runs.push(run);
  return runs;
}

function realText(node: Text): string {
  const kept = texts.get(node);
  return kept && node.data === kept.shown ? kept.real : node.data;
}

/** Text nodes side by side, masked as one text and shown spread over the same nodes. */
function maskRun(nodes: Text[], kind: MaskKind | "address" | null) {
  if (nodes.length === 0) return;
  const reals = nodes.map(realText);
  const joined = reals.join("");
  const reps = kind ? fieldReplacements(kind, joined) : masker.ranges(joined);
  let offset = 0;
  nodes.forEach((node, i) => {
    const real = reals[i] ?? "";
    const start = offset;
    const end = offset + real.length;
    offset = end;
    let shown = "";
    let at = start;
    for (const r of reps) {
      if (r.end <= start || r.start >= end) continue;
      if (r.start >= start) shown += joined.slice(at, r.start) + r.text;
      at = Math.max(at, Math.min(r.end, end));
    }
    shown += joined.slice(at, end);
    show(node, real, shown);
  });
}

/** A marked element's text is one value: masked whole, whatever it looks like. */
function fieldReplacements(kind: MaskKind | "address", text: string): Replacement[] {
  const trimmed = text.trim();
  if (trimmed === "") return [];
  const masked = masker.field(kind, trimmed);
  if (masked === trimmed) return [];
  const start = text.indexOf(trimmed);
  return [{ start, end: start + trimmed.length, kind: kind === "address" ? "host" : kind, text: masked }];
}

function show(node: Text, real: string, shown: string) {
  if (shown === real) {
    if (texts.delete(node) && node.data !== real) node.data = real;
    return;
  }
  texts.set(node, { real, shown });
  if (node.data !== shown) node.data = shown;
}

function maskAttribute(el: Element, name: string) {
  const value = el.getAttribute(name);
  const kept = attributes.get(el);
  if (value === null) {
    kept?.delete(name);
    return;
  }
  const before = kept?.get(name);
  const real = before && value === before.shown ? before.real : value;
  const shown = masker.text(real);
  if (shown === real) {
    if (kept?.delete(name) && value !== real) el.setAttribute(name, real);
    return;
  }
  const map = kept ?? new Map<string, Kept>();
  map.set(name, { real, shown });
  attributes.set(el, map);
  if (value !== shown) el.setAttribute(name, shown);
}

function checkInput(el: Element) {
  const field =
    el instanceof HTMLTextAreaElement || (el instanceof HTMLInputElement && TEXT_INPUTS.has(el.type)) ? el : null;
  if (!field || field.hasAttribute("data-mask")) return;
  const hide = field.value !== "" && masker.text(field.value) !== field.value;
  if (hide) field.setAttribute(HIDDEN_VALUE, "");
  else field.removeAttribute(HIDDEN_VALUE);
}

function restoreTree(root: Element) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
    acceptNode: (node) =>
      node instanceof Element && node.matches(SKIP) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT,
  });
  for (let node: Node | null = root; node; node = walker.nextNode()) {
    if (node instanceof Text) {
      const kept = texts.get(node);
      if (kept) {
        if (node.data === kept.shown) node.data = kept.real;
        texts.delete(node);
      }
    } else if (node instanceof Element) {
      const kept = attributes.get(node);
      if (kept) {
        for (const [name, k] of kept) if (node.getAttribute(name) === k.shown) node.setAttribute(name, k.real);
        attributes.delete(node);
      }
      node.removeAttribute(HIDDEN_VALUE);
    }
  }
}
