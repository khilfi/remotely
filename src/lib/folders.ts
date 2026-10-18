// The session folder tree (SS-01), flattened in display order.

import type { SessionFolder } from "@/lib/api";

export interface FolderRow {
  folder: SessionFolder;
  depth: number;
}

/** Folders in tree order (each right after its parent), with how deep each one is. */
export function flattenFolders(folders: SessionFolder[]): FolderRow[] {
  const children = new Map<string | null, SessionFolder[]>();
  for (const f of folders) {
    const siblings = children.get(f.parentId) ?? [];
    siblings.push(f);
    children.set(f.parentId, siblings);
  }
  const out: FolderRow[] = [];
  const visit = (parent: string | null, depth: number) => {
    const list = (children.get(parent) ?? []).sort(
      (a, b) => a.sortOrder - b.sortOrder || a.name.localeCompare(b.name, undefined, { sensitivity: "base" }),
    );
    for (const folder of list) {
      out.push({ folder, depth });
      visit(folder.id, depth + 1);
    }
  };
  visit(null, 0);
  return out;
}

/** The folder and every folder under it. */
export function subtree(folders: SessionFolder[], root: string): Set<string> {
  const found = new Set([root]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const f of folders) {
      if (f.parentId && found.has(f.parentId) && !found.has(f.id)) {
        found.add(f.id);
        grew = true;
      }
    }
  }
  return found;
}

/** "Customer A / Site 1". */
export function folderPath(folders: SessionFolder[], id: string | null): string {
  const byId = new Map(folders.map((f) => [f.id, f]));
  const parts: string[] = [];
  let current = id ? byId.get(id) : undefined;
  while (current && parts.length < 32) {
    parts.unshift(current.name);
    current = current.parentId ? byId.get(current.parentId) : undefined;
  }
  return parts.join(" / ");
}
