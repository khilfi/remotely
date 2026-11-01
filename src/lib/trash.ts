// QL-27 the trash in the window, as pure functions (tested in trash.test.ts): each kind's name, a restore's message,
// and the Undo a delete's toast offers.

import type { RestoreReport, TrashKind } from "./comfort-api.ts";

const KIND_LABELS: Record<TrashKind, string> = {
  session: "Session",
  command: "Favourite command",
  size: "Size",
  image: "Image",
  template: "Launch template",
  stack: "Stack",
};

export function trashKindLabel(kind: TrashKind): string {
  return KIND_LABELS[kind];
}

/** "Restored 'web01'", with what was left out or renamed as the description. */
export function restoredMessage(report: RestoreReport): { title: string; description?: string } {
  const title = `Restored '${report.name}'`;
  if (report.notes.length === 0) return { title };
  const description = report.notes.map((n) => n.charAt(0).toUpperCase() + n.slice(1)).join(". ");
  return { title, description: /[.!?]$/.test(description) ? description : `${description}.` };
}

/** What a delete's toast says: the item went to the trash for 30 days. */
export function deletedMessage(name: string): { title: string; description: string } {
  return { title: `Deleted '${name}'`, description: "It is in the trash for 30 days." };
}
