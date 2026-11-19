// UX-14 (0.9.0 H1): Settings' Files card: what double-clicking a file does, in the Terminal's Files here and on the
// Files page alike (one setting for both; a terminal editor on the host by default). When that can't be done (the host
// has no editor Remotely knows, a link, the read-only lock), a double-click previews the file instead. The setting is
// kept with the terminal settings in the core (audited like them), and saved through saveTerminalSettings so it never
// puts back what the Terminal card changed. UX-10: it saves at once, with "Saved" and Undo in the header.

import { useEffect, useState } from "react";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { HelpTip } from "@/components/HelpTip";
import { SaveStatus, useSaveStatus } from "@/components/SaveStatus";
import { saveTerminalSettings } from "@/components/TerminalSettingsCard";
import { api, errorMessage, type FileDoubleClick } from "@/lib/api";

const DOUBLE_CLICK: { value: FileDoubleClick; label: string }[] = [
  { value: "terminalEditor", label: "Edit it in the terminal, on the host" },
  { value: "thisPc", label: "Edit it on this PC" },
];

export function FilesSettingsCard() {
  const [value, setValue] = useState<FileDoubleClick | null>(null);
  const [error, setError] = useState<string | null>(null);
  const status = useSaveStatus();

  useEffect(() => {
    api.terminalSettings().then(
      (s) => setValue(s.fileDoubleClick ?? "terminalEditor"),
      (err) => setError(errorMessage(err)),
    );
  }, []);

  if (!value) return error ? <p className="text-sm text-destructive">{error}</p> : null;

  function save(next: FileDoubleClick) {
    const before = value ?? "terminalEditor";
    const apply = (to: FileDoubleClick) =>
      saveTerminalSettings({ fileDoubleClick: to }).then((saved) =>
        setValue(saved.fileDoubleClick ?? "terminalEditor"),
      );
    void status.run(
      () => apply(next),
      () => apply(before),
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Files</CardTitle>
        <CardDescription>Files here, beside a terminal, and the Files page.</CardDescription>
        <CardAction>
          <SaveStatus status={status} />
        </CardAction>
      </CardHeader>
      <CardContent>
        <div className="grid gap-2 sm:max-w-sm">
          <span className="flex items-center gap-1">
            <Label htmlFor="file-double-click">Double-clicking a file</Label>
            <HelpTip topic="filesEditing" />
          </span>
          <Select value={value} onValueChange={(v) => save(v as FileDoubleClick)}>
            <SelectTrigger id="file-double-click" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {DOUBLE_CLICK.map((d) => (
                <SelectItem key={d.value} value={d.value}>
                  {d.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </CardContent>
    </Card>
  );
}
