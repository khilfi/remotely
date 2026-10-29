// CV-03: Settings' card for qemu-img, which converts qcow2 and VHDX images when the owner installed QEMU for Windows.
// Remotely never ships it (GPL-licensed): empty finds it (REMOTELY_QEMU_IMG, then QEMU's default folder). Saving is
// audited and refused by the read-only lock in the core.

import { useEffect, useState } from "react";
import { ExternalLinkIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useReadOnlyReason } from "@/components/Presentation";
import { HelpTip } from "@/components/HelpTip";
import { api, errorMessage } from "@/lib/api";
import { convertApi } from "@/lib/convert-api";

/** QEMU's download page (the core opens only this one). */
const QEMU_DOWNLOAD = "https://www.qemu.org/download/#windows";

export function QemuImgCard() {
  const readOnly = useReadOnlyReason();
  const [path, setPath] = useState("");
  const [inUse, setInUse] = useState<string | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    let stopped = false;
    api.settings().then(
      (s) => {
        if (stopped) return;
        setPath(s.qemuImgPathSaved ?? "");
        setInUse(s.qemuImgPathInUse);
      },
      () => {},
    );
    return () => {
      stopped = true;
    };
  }, []);

  async function save(next: string | null) {
    try {
      const s = await convertApi.setQemuImgPath(next);
      setPath(s.qemuImgPathSaved ?? "");
      setInUse(s.qemuImgPathInUse);
      setMessage({
        ok: s.qemuImgPathInUse !== null,
        text: s.qemuImgPathInUse ? `Using ${s.qemuImgPathInUse}` : "qemu-img.exe was not found",
      });
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Conversion tools
          <HelpTip topic="qemuImg" />
        </CardTitle>
        <CardDescription>
          qemu-img converts qcow2 and VHDX. Leave the path empty to find it automatically.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-2">
        <Label htmlFor="qemu-img-path">qemu-img.exe path</Label>
        <Input
          id="qemu-img-path"
          className="font-mono"
          placeholder="Found automatically"
          spellCheck={false}
          value={path}
          onChange={(e) => setPath(e.currentTarget.value)}
        />
        <p className="text-sm text-muted-foreground">
          In use: <span className="font-mono">{inUse ?? "not installed"}</span>
        </p>
        {message && (
          <p className={message.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
            {message.text}
          </p>
        )}
      </CardContent>
      <CardFooter className="flex-wrap gap-2">
        <WhyDisabled reason={readOnly}>
          <Button disabled={readOnly !== null} onClick={() => void save(path)}>
            Save
          </Button>
        </WhyDisabled>
        <WhyDisabled reason={readOnly}>
          <Button variant="outline" disabled={readOnly !== null} onClick={() => void save(null)}>
            Find automatically
          </Button>
        </WhyDisabled>
        <Button variant="ghost" onClick={() => void convertApi.openQemuSite(QEMU_DOWNLOAD)}>
          <ExternalLinkIcon data-icon="inline-start" />
          QEMU&apos;s download page
        </Button>
      </CardFooter>
    </Card>
  );
}
