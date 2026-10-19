// FD-03: masks what the window shows while presenting, at the DOM. Every text node, and the attributes that show text
// (title, aria-label, placeholder, alt, the terminal's drop label), goes through the masker in presentation.ts, whether
// React rendered it, a toast or tooltip showed it in a portal, or the core built it in Rust (errors, approval
// summaries, audit text). One place, so no page can forget it.
//
// A MutationObserver masks new and changed text in the microtask after the change, which runs before the browser
// paints: a page, dialog or toast never shows a real value first. The real text is kept per node (in memory, next to
// the node) and put back when presenting stops; React keeps writing real text, which is masked again as it lands.
// Adjacent text nodes are masked together, so `{user}@{host}` in JSX is still seen as user@host.
//
// Not rewritten:
// - Terminals (`data-presentation-skip`): each pane masks its output stream itself (terminal-session.ts).
// - Inputs and text areas: their value is what the user edits and saves. Those marked `data-mask` show dots while
//   presenting, and so does any other one whose value holds something to mask (checked as it appears and as it is
//   typed into).

import { masker, type MaskKind, type Replacement } from "@/lib/presentation";

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
let rescanQueued = false;

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
  const unlisten = masker.onChange(queueRescan);
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

function queueRescan() {
  if (rescanQueued) return;
  rescanQueued = true;
  queueMicrotask(() => {
    rescanQueued = false;
    if (observer) maskTree(document.body);
  });
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
  return kind === "host" || kind === "ip" || kind === "user" || kind === "address" ? kind : null;
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
