// FD-06: the note of a session, VM or folder, in a sheet App hosts once (opened by a `{ kind: "note" }` link from the
// Sessions page, a VM's details, the palette or a search result). The core renders the markdown: raw HTML and images
// show as text, and links carry no address, so clicking one goes through here: a web address opens after a confirm
// that shows it, an app link through the app's own navigation. A code block's "Send to terminal" pastes it into the
// open terminal, which asks before a paste with a line break and never presses Enter. A note that looks like it holds a
// secret says so and points to the vault. Saving is audited without the text and refused while presenting.

import { useCallback, useEffect, useRef, useState } from "react";
import { PencilIcon, ShieldAlertIcon } from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { EmptyState } from "@/components/EmptyState";
import { HelpTip } from "@/components/HelpTip";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage } from "@/lib/api";
import { comfortApi, type Note, type NoteKind, type RenderedNote } from "@/lib/comfort-api";
import { requestLink } from "@/lib/links";
import { sendNoteCode } from "@/lib/note-send";
import { noteAbout, noteLinkAction, noteLinkTitle } from "@/lib/notes";

export interface NoteSheetTarget {
  kind: NoteKind;
  key: string;
  /** What it is about, when the opener knows (a note not written yet has no title in the core). */
  title?: string;
}

interface Props {
  target: NoteSheetTarget | null;
  onClose: () => void;
}

/** The core's HTML, with each link's tooltip and each code block's "Send to terminal". */
function RenderedBody({
  rendered,
  onLink,
  onSend,
}: {
  rendered: RenderedNote;
  onLink: (index: number) => void;
  onSend: (index: number) => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const root = box.current;
    if (!root) return;
    for (const a of root.querySelectorAll<HTMLElement>("[data-note-link]")) {
      const link = rendered.links[Number(a.dataset.noteLink)];
      if (link) a.title = noteLinkTitle(link);
    }
    for (const pre of root.querySelectorAll<HTMLElement>("pre[data-note-code]")) {
      if (pre.querySelector("[data-note-send]")) continue;
      const button = document.createElement("button");
      button.type = "button";
      button.className = "note-send";
      button.dataset.noteSend = pre.dataset.noteCode ?? "";
      button.textContent = "Send to terminal";
      pre.appendChild(button);
    }
  }, [rendered]);
  return (
    <div
      ref={box}
      className="note-body"
      // The core made this HTML: raw HTML in a note is text, links carry no address, nothing in it can run.
      dangerouslySetInnerHTML={{ __html: rendered.html }}
      onClick={(e) => {
        const target = e.target as HTMLElement;
        const send = target.closest<HTMLElement>("[data-note-send]");
        if (send) {
          e.preventDefault();
          onSend(Number(send.dataset.noteSend));
          return;
        }
        const link = target.closest<HTMLElement>("[data-note-link]");
        if (link) {
          e.preventDefault();
          onLink(Number(link.dataset.noteLink));
        }
      }}
      onKeyDown={(e) => {
        const link = (e.target as HTMLElement).closest<HTMLElement>("[data-note-link]");
        if (link && (e.key === "Enter" || e.key === " ")) {
          e.preventDefault();
          onLink(Number(link.dataset.noteLink));
        }
      }}
    />
  );
}

export function NoteSheet({ target, onClose }: Props) {
  const [note, setNote] = useState<Note | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [rendered, setRendered] = useState<RenderedNote | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [handover, setHandover] = useState(false);
  const [preview, setPreview] = useState<RenderedNote | null>(null);
  const [tab, setTab] = useState("write");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [web, setWeb] = useState<string | null>(null);
  const readOnly = useReadOnlyReason();

  const show = useCallback((found: Note | null) => {
    setNote(found);
    setHandover(found?.handover ?? false);
    setLoaded(true);
    if (found) {
      comfortApi.renderNote(found.body).then(setRendered, (err) => setError(errorMessage(err)));
    } else {
      setRendered(null);
    }
  }, []);

  // App mounts the sheet afresh for each target (its key), so it starts empty here.
  useEffect(() => {
    if (!target) return;
    comfortApi.note({ kind: target.kind, key: target.key }).then(show, (err) => {
      setError(errorMessage(err));
      setLoaded(true);
    });
  }, [target, show]);

  // The preview, while writing.
  useEffect(() => {
    if (!editing || tab !== "preview") return;
    const timer = window.setTimeout(() => {
      comfortApi.renderNote(draft).then(setPreview, (err) => setError(errorMessage(err)));
    }, 150);
    return () => window.clearTimeout(timer);
  }, [editing, tab, draft]);

  if (!target) return null;
  const title = note?.title ?? target.title ?? "";
  const about = title ? noteAbout(target.kind, title) : "";
  const looksSecret = editing ? (preview?.looksSecret ?? note?.looksSecret ?? false) : (note?.looksSecret ?? false);

  function startEditing() {
    setDraft(note?.body ?? "");
    setHandover(note?.handover ?? false);
    setPreview(null);
    setTab("write");
    setError(null);
    setEditing(true);
  }

  async function save() {
    if (!target) return;
    setSaving(true);
    setError(null);
    try {
      const saved = await comfortApi.saveNote({ kind: target.kind, key: target.key }, { body: draft, handover });
      show(saved);
      setEditing(false);
      toast.success(saved ? "Note saved" : "Note deleted");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  async function markHandover(on: boolean) {
    if (!target || !note) return;
    try {
      show(await comfortApi.setNoteHandover({ kind: target.kind, key: target.key }, on));
      if (on && note.looksSecret) toast.warning("Its secret-looking part goes into the handover pack as [redacted]");
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  function openLink(source: RenderedNote, index: number) {
    const link = source.links[index];
    if (!link) return;
    const action = noteLinkAction(link);
    if ("web" in action) setWeb(action.web);
    else if ("open" in action) {
      onClose();
      requestLink(action.open);
    } else toast.info(action.none);
  }

  function sendCode(source: RenderedNote, index: number) {
    const code = source.codeBlocks[index];
    if (code === undefined) return;
    onClose();
    requestLink({ kind: "page", page: "terminal" });
    // The Terminal page shows first, so its paste confirm shows on it.
    window.setTimeout(() => {
      if (!sendNoteCode(code)) toast.info("Open a terminal first, then send it");
    }, 50);
  }

  return (
    <Sheet open onOpenChange={(open) => !open && !saving && onClose()}>
      <SheetContent className="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-1">
            Note
            <HelpTip topic="notes" />
          </SheetTitle>
          <SheetDescription>{about ? `About ${about}` : " "}</SheetDescription>
        </SheetHeader>
        <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-auto px-4 pb-4">
          {looksSecret && (
            <Alert>
              <ShieldAlertIcon />
              <AlertTitle>This looks like it holds a secret</AlertTitle>
              <AlertDescription>
                <span>
                  Keep passwords and keys in the vault, and link them here by name.{" "}
                  <Button
                    variant="link"
                    className="h-auto p-0"
                    onClick={() => {
                      onClose();
                      requestLink({ kind: "vault" });
                    }}
                  >
                    Open the vault
                  </Button>
                </span>
              </AlertDescription>
            </Alert>
          )}
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          {!editing && loaded && !note && (
            <EmptyState
              icon={PencilIcon}
              title="No note yet"
              description="Write down what the next person needs to know: how to reach it, quirks, runbooks."
              help="notes"
              action={
                <WhyDisabled reason={readOnly}>
                  <Button disabled={readOnly !== null} onClick={startEditing}>
                    <PencilIcon data-icon="inline-start" />
                    Write a note
                  </Button>
                </WhyDisabled>
              }
            />
          )}
          {!editing && note && rendered && (
            <RenderedBody
              rendered={rendered}
              onLink={(i) => openLink(rendered, i)}
              onSend={(i) => sendCode(rendered, i)}
            />
          )}
          {editing && (
            <Tabs value={tab} onValueChange={setTab} className="min-h-0 flex-1">
              <TabsList>
                <TabsTrigger value="write">Write</TabsTrigger>
                <TabsTrigger value="preview">Preview</TabsTrigger>
              </TabsList>
              <TabsContent value="write" className="min-h-0">
                <Textarea
                  aria-label="Note"
                  data-presentation-hidden
                  className="min-h-80 font-mono text-sm"
                  value={draft}
                  autoFocus
                  placeholder={"# How to reach it\n\nMarkdown: **bold**, - lists, | tables |, ```code```."}
                  onChange={(e) => setDraft(e.currentTarget.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                      e.preventDefault();
                      void save();
                    }
                  }}
                />
              </TabsContent>
              <TabsContent value="preview">
                {preview ? (
                  <RenderedBody
                    rendered={preview}
                    onLink={(i) => openLink(preview, i)}
                    onSend={(i) => sendCode(preview, i)}
                  />
                ) : (
                  <p className="text-sm text-muted-foreground">…</p>
                )}
              </TabsContent>
            </Tabs>
          )}
        </div>
        {(note || editing) && (
          <SheetFooter className="flex-row flex-wrap items-center justify-between gap-2 border-t">
            <div className="flex items-center gap-2">
              <WhyDisabled reason={readOnly}>
                <Switch
                  id="note-handover"
                  checked={handover}
                  disabled={readOnly !== null || saving}
                  onCheckedChange={(on) => (editing ? setHandover(on) : void markHandover(on))}
                />
              </WhyDisabled>
              <Label htmlFor="note-handover" className="font-normal">
                Include in the handover pack
              </Label>
            </div>
            {handover && looksSecret && (
              <p className="order-last w-full text-xs text-tier-high" role="status">
                The handover pack shows what looks like a secret as [redacted]. Keep it in the vault instead.
              </p>
            )}
            {editing ? (
              <div className="flex items-center gap-2">
                <Button variant="outline" disabled={saving} onClick={() => setEditing(false)}>
                  Cancel
                </Button>
                <Button disabled={saving} onClick={() => void save()}>
                  {saving ? "Saving…" : draft.trim() === "" && note ? "Delete note" : "Save"}
                </Button>
              </div>
            ) : (
              <WhyDisabled reason={readOnly}>
                <Button disabled={readOnly !== null} onClick={startEditing}>
                  <PencilIcon data-icon="inline-start" />
                  Edit
                </Button>
              </WhyDisabled>
            )}
          </SheetFooter>
        )}
      </SheetContent>
      <AlertDialog open={web !== null} onOpenChange={(open) => !open && setWeb(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Open this address in your browser?</AlertDialogTitle>
            <AlertDialogDescription className="font-mono break-all text-foreground">{web}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                const url = web;
                setWeb(null);
                if (url) comfortApi.openNoteLink(url).catch((err: unknown) => toast.error(errorMessage(err)));
              }}
            >
              Open
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Sheet>
  );
}
