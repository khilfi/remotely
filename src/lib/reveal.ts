// R10: shows an element a link asked for (a session's row, a settings card, a catalogue row) by scrolling only the
// nearest scrolling area it is in. `scrollIntoView` would also scroll the window's fixed layout, whose outer boxes
// clip their overflow but can still be scrolled, pushing the top bar and the status bar out of place.

/** The nearest ancestor that scrolls vertically, or null. */
function scroller(el: Element): HTMLElement | null {
  for (let node = el.parentElement; node; node = node.parentElement) {
    const overflow = getComputedStyle(node).overflowY;
    if ((overflow === "auto" || overflow === "scroll") && node.scrollHeight > node.clientHeight) return node;
  }
  return null;
}

/** Scrolls the element's own scrolling area so the element is in view: near the top, or centred. */
export function reveal(el: Element | null, where: "top" | "center" = "center") {
  if (!el) return;
  const area = scroller(el);
  if (!area) return;
  const box = el.getBoundingClientRect();
  const view = area.getBoundingClientRect();
  const offset = where === "top" ? box.top - view.top - 16 : box.top - view.top - (view.height - box.height) / 2;
  area.scrollTo({ top: area.scrollTop + offset, behavior: "smooth" });
}
