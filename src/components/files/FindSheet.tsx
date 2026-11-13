// SS-14 (0.8.0 G3): find files on the host: `find` under the folder shown, for names matching a pattern (a read, no
// approval). Each hit opens its folder in the host pane, or shows its preview or SHA-256 there.

import { useState, type FormEvent } from "react";
import { FileIcon, FolderIcon, FolderOpenIcon, LinkIcon, SearchIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { DropdownMenuItem } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { HelpTip } from "@/components/HelpTip";
import { RowMenu } from "@/components/RowMenu";
import { errorMessage } from "@/lib/api";
import { plural } from "@/lib/format";
import { filesPageApi, type FindHit, type FindResult } from "@/lib/files-page-api";
import { formatSize } from "@/lib/transfers";

interface Props {
  terminalId: string;
  folder: string;
  asRoot: boolean;
  onOpenFolder: (folder: string) => void;
  onPreview: (hit: FindHit) => void;
  onChecksum: (hit: FindHit) => void;
  onClose: () => void;
}

function folderOf(path: string) {
  const at = path.lastIndexOf("/");
  return at <= 0 ? "/" : path.slice(0, at);
}

export function FindSheet({ terminalId, folder, asRoot, onOpenFolder, onPreview, onChecksum, onClose }: Props) {
  const [pattern, setPattern] = useState("");
  const [ignoreCase, setIgnoreCase] = useState(true);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<FindResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function find(ev: FormEvent) {
    ev.preventDefault();
    if (!pattern.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await filesPageApi.find(terminalId, { folder, pattern: pattern.trim(), ignoreCase, asRoot }));
    } catch (err) {
      setError(errorMessage(err));
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  const notes: string[] = [];
  if (result?.timedOut) notes.push("it stopped at its time limit; this is what it found by then");
  if (result?.more) notes.push("there are more than are shown");
  if (result && result.unreadable > 0) notes.push(`${plural(result.unreadable, "folder")} couldn't be read`);
  if (result?.pathsOnly) notes.push("the host's find gives names only");

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-xl">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-1">
            Find files
            <HelpTip topic="files.find" />
          </SheetTitle>
          <SheetDescription className="truncate">
            Under <span className="font-mono">{folder}</span>
            {asRoot ? ", as root" : ""}
          </SheetDescription>
        </SheetHeader>
        <form className="grid gap-2 px-4" onSubmit={find}>
          <div className="flex gap-2">
            <Input
              aria-label="Name pattern"
              placeholder="A name or a pattern, such as *.conf"
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              spellCheck={false}
              autoFocus
            />
            <Button type="submit" disabled={busy || !pattern.trim()}>
              <SearchIcon data-icon="inline-start" />
              {busy ? "Finding…" : "Find"}
            </Button>
          </div>
          <div className="flex items-center gap-2">
            <Checkbox id="find-any-case" checked={ignoreCase} onCheckedChange={(v) => setIgnoreCase(v === true)} />
            <Label htmlFor="find-any-case" className="font-normal">
              Any letter case
            </Label>
          </div>
        </form>
        <div className="grid min-h-0 flex-1 gap-2 overflow-hidden px-4 pb-4">
          {error && <p className="text-sm text-destructive">{error}</p>}
          {result && (
            <p className="text-xs text-muted-foreground">
              {plural(result.hits.length, "result")}
              {notes.length > 0 && `: ${notes.join("; ")}`}.
            </p>
          )}
          {result && result.hits.length > 0 && (
            <ul className="min-h-0 divide-y overflow-auto rounded-md border text-xs">
              {result.hits.map((hit) => (
                <li key={hit.path} className="group flex items-center gap-2 px-2 py-1">
                  {hit.kind === "folder" ? (
                    <FolderIcon className="size-3.5 shrink-0 text-primary" aria-label="Folder" />
                  ) : (
                    <FileIcon className="size-3.5 shrink-0 text-muted-foreground" aria-label="File" />
                  )}
                  <button
                    type="button"
                    className="min-w-0 flex-1 truncate text-left font-mono hover:underline"
                    title="Open its folder"
                    onClick={() => onOpenFolder(hit.kind === "folder" ? hit.path : folderOf(hit.path))}
                  >
                    {hit.shown}
                  </button>
                  {hit.link && <LinkIcon className="size-3 shrink-0 text-muted-foreground" aria-label="Link" />}
                  {hit.size !== null && hit.kind === "file" && (
                    <span className="shrink-0 text-muted-foreground tabular-nums">{formatSize(hit.size)}</span>
                  )}
                  <RowMenu label={hit.shown} className="opacity-0 group-hover:opacity-100 focus-visible:opacity-100">
                    <DropdownMenuItem
                      onSelect={() => onOpenFolder(hit.kind === "folder" ? hit.path : folderOf(hit.path))}
                    >
                      <FolderOpenIcon />
                      {hit.kind === "folder" ? "Open" : "Open its folder"}
                    </DropdownMenuItem>
                    {hit.kind !== "folder" && (
                      <>
                        <DropdownMenuItem onSelect={() => onPreview(hit)}>Preview</DropdownMenuItem>
                        <DropdownMenuItem onSelect={() => onChecksum(hit)}>SHA-256 checksum</DropdownMenuItem>
                      </>
                    )}
                  </RowMenu>
                </li>
              ))}
            </ul>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
