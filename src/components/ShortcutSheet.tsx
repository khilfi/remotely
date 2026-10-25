// QL-24: the keyboard shortcut sheet (Ctrl+/; Ctrl+Shift+/ from a terminal, and the palette's "Keyboard shortcuts").
// It lists every shortcut from lib/shortcuts.ts, with the pages' own from App's PAGES, and filters as you type.

import { useState } from "react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Kbd } from "@/components/ui/kbd";
import { filterShortcuts, shortcutGroups } from "@/lib/shortcuts";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pages: readonly { label: string; shortcut: string }[];
}

export function ShortcutSheet({ open, onOpenChange, pages }: Props) {
  const [text, setText] = useState("");
  const groups = filterShortcuts(shortcutGroups(pages), text);
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) setText("");
        onOpenChange(next);
      }}
    >
      <DialogContent className="max-h-[85vh] overflow-hidden sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Keyboard shortcuts</DialogTitle>
          <DialogDescription>
            Every key Remotely answers to. Inside a terminal, the shell keeps the rest.
          </DialogDescription>
        </DialogHeader>
        <Input
          placeholder="Filter: a key or what it does"
          aria-label="Filter the shortcuts"
          value={text}
          onChange={(e) => setText(e.currentTarget.value)}
          autoFocus
        />
        <div className="-mx-1 min-h-0 overflow-auto px-1">
          <div className="gap-x-8 md:columns-2">
            {groups.map((group) => (
              <section key={group.title} aria-label={group.title} className="mb-5 break-inside-avoid">
                <h3 className="mb-2 text-xs font-medium text-muted-foreground">{group.title}</h3>
                <dl className="grid gap-1.5">
                  {group.shortcuts.map((s) => (
                    <div key={`${s.keys}:${s.what}`} className="flex items-baseline justify-between gap-3">
                      <dt className="text-sm">{s.what}</dt>
                      <dd className="flex shrink-0 flex-wrap justify-end gap-1">
                        {s.keys.split(" / ").map((k) => (
                          <Kbd key={k}>{k}</Kbd>
                        ))}
                      </dd>
                    </div>
                  ))}
                </dl>
              </section>
            ))}
            {groups.length === 0 && <p className="text-sm text-muted-foreground">No shortcut has that.</p>}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
