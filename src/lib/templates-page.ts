// UX-07 for the Templates page: its tabs in the order a first deploy takes them, the tab it opens on (the first step
// that isn't done), and each tab's one primary action with why it is off. Pure, tested in templates-page.test.ts.

/** UX-08: "disks" is Disk images, the Image tools page until 0.6.0. */
export type TemplatesTab = "sizes" | "images" | "templates" | "stacks" | "disks";

/** In the order a first deploy goes: where the OS comes from, how big, both together, then several together. */
export const TEMPLATE_TABS: readonly { id: TemplatesTab; label: string }[] = [
  { id: "images", label: "Images" },
  { id: "sizes", label: "Sizes" },
  { id: "templates", label: "Launch templates" },
  { id: "stacks", label: "Stacks" },
  { id: "disks", label: "Disk images" },
];

/**
 * The tab the page opens on: Images until there is one, then Launch templates (sizes are built in, so that step is
 * always done, and stacks are optional), where Deploy is.
 */
export function openingTab(counts: { images: number; templates: number }): TemplatesTab {
  if (counts.images === 0) return "images";
  return "templates";
}

/** Why "New launch template" is off, or null. */
export function newTemplateReason(readOnly: string | null, images: number): string | null {
  return readOnly ?? (images === 0 ? "Add an image first: a launch template starts from one" : null);
}

/** Why "New stack" is off, or null. */
export function newStackReason(readOnly: string | null, templates: number): string | null {
  return readOnly ?? (templates === 0 ? "Make a launch template first: a stack deploys them in order" : null);
}
