// BX-03: the line diff between two output groups of a bulk run, computed in the core from each group's
// sample host. Lines only on the left are red with "-", lines only on the right green with "+".

import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { api, errorMessage, type DiffLine, type OutputDiff, type OutputGroup } from "@/lib/api";
import { plural } from "@/lib/format";
import { cn } from "@/lib/utils";

interface Props {
  jobId: string;
  groups: OutputGroup[];
  ignoreTrailingWhitespace: boolean;
  /** The groups to compare first, by label. */
  left: string;
  right: string;
  onClose: () => void;
}

function groupText(g: OutputGroup) {
  const what = g.kind === "error" ? (g.errorCode ?? "error") : `exit ${g.exitCode ?? "?"}`;
  return `${g.label}: ${plural(g.hosts.length, "host")}, ${what}`;
}

export function OutputDiffDialog({ jobId, groups, ignoreTrailingWhitespace, left, right, onClose }: Props) {
  const [a, setA] = useState(left);
  const [b, setB] = useState(right);
  const [diff, setDiff] = useState<{ key: string; diff: OutputDiff } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const leftSample = groups.find((g) => g.label === a)?.sample;
  const rightSample = groups.find((g) => g.label === b)?.sample;
  const key = `${leftSample}|${rightSample}|${ignoreTrailingWhitespace}`;

  useEffect(() => {
    if (!leftSample || !rightSample) return;
    let stale = false;
    api.bulkDiff(jobId, leftSample, rightSample, { ignoreTrailingWhitespace }).then(
      (d) => {
        if (stale) return;
        setDiff({ key, diff: d });
        setError(null);
      },
      (err) => {
        if (!stale) setError(errorMessage(err));
      },
    );
    return () => {
      stale = true;
    };
  }, [jobId, leftSample, rightSample, ignoreTrailingWhitespace, key]);

  const shown = diff?.key === key ? diff.diff : null;
  const changed = shown ? [...shown.stdout, ...shown.stderr].filter((l) => l.kind !== "same").length : 0;

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>Compare groups</DialogTitle>
          <DialogDescription>
            Each group&apos;s output is shown by one of its hosts.
            {ignoreTrailingWhitespace && " Trailing whitespace is ignored."}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 sm:grid-cols-2">
          {[
            { id: "diff-left", label: "Left (-)", value: a, set: setA },
            { id: "diff-right", label: "Right (+)", value: b, set: setB },
          ].map((side) => (
            <div key={side.id} className="grid gap-1.5">
              <Label htmlFor={side.id}>{side.label}</Label>
              <Select value={side.value} onValueChange={side.set}>
                <SelectTrigger id={side.id} className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {groups.map((g) => (
                    <SelectItem key={g.label} value={g.label}>
                      {groupText(g)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ))}
        </div>
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        {!shown && !error && <Skeleton className="h-40" />}
        {shown && (
          <div className="grid gap-3">
            <p className="text-sm text-muted-foreground">
              {changed === 0
                ? "The outputs are the same; the groups differ in exit code or cause."
                : `${plural(changed, "line")} differ between ${shown.left} (exit ${shown.leftExitCode ?? "–"}) and ${shown.right} (exit ${shown.rightExitCode ?? "–"}).`}
            </p>
            <DiffBlock title="stdout" lines={shown.stdout} />
            {shown.stderr.length > 0 && <DiffBlock title="stderr" lines={shown.stderr} />}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

const PREFIX: Record<DiffLine["kind"], string> = { same: " ", removed: "-", added: "+" };

function DiffBlock({ title, lines }: { title: string; lines: DiffLine[] }) {
  return (
    <div className="grid gap-1">
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-muted-foreground">{title}</span>
        {lines.length === 0 && (
          <Badge variant="outline" className="font-normal">
            empty on both sides
          </Badge>
        )}
      </div>
      {lines.length > 0 && (
        <pre className="max-h-[45svh] overflow-auto rounded-md border font-mono text-xs leading-5">
          {lines.map((line, i) => (
            <div
              key={i}
              className={cn(
                "px-3 whitespace-pre-wrap",
                line.kind === "removed" && "bg-destructive/10 text-destructive",
                line.kind === "added" && "bg-success/10 text-success",
              )}
            >
              <span className="mr-2 select-none opacity-60">{PREFIX[line.kind]}</span>
              {line.text || " "}
            </div>
          ))}
        </pre>
      )}
    </div>
  );
}
