// Settings: the vmrun.exe path (configurable, never hard-coded). The theme switch is in the top bar.

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, errorMessage, type Settings } from "@/lib/api";

interface Props {
  /** Called after the vmrun path changes, so the sidebar status updates. */
  onChanged: () => void;
}

export function SettingsPage({ onChanged }: Props) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [path, setPath] = useState("");
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    api.settings().then(
      (s) => {
        setSettings(s);
        setPath(s.vmrunPathSaved ?? "");
      },
      (err) => setMessage({ ok: false, text: errorMessage(err) }),
    );
  }, []);

  async function save(next: string | null) {
    try {
      const s = await api.setVmrunPath(next);
      setSettings(s);
      setPath(s.vmrunPathSaved ?? "");
      setMessage({
        ok: s.vmrunPathInUse !== null,
        text: s.vmrunPathInUse ? `Using ${s.vmrunPathInUse}` : "vmrun.exe was not found",
      });
      onChanged();
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    }
  }

  return (
    <Card className="max-w-3xl">
      <CardHeader>
        <CardTitle>VMware Workstation</CardTitle>
        <CardDescription>
          Every VM action runs through vmrun.exe. Leave the path empty to find it automatically: the registry first,
          then the default install folders.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-2">
        <Label htmlFor="vmrun-path">vmrun.exe path</Label>
        <Input
          id="vmrun-path"
          className="font-mono"
          placeholder="Found automatically"
          spellCheck={false}
          value={path}
          onChange={(e) => setPath(e.currentTarget.value)}
        />
        <p className="text-sm text-muted-foreground">
          In use: <span className="font-mono">{settings?.vmrunPathInUse ?? "not found"}</span>
        </p>
        {message && (
          <p className={message.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
            {message.text}
          </p>
        )}
      </CardContent>
      <CardFooter className="gap-2">
        <Button onClick={() => void save(path)}>Save</Button>
        <Button variant="outline" onClick={() => void save(null)}>
          Find automatically
        </Button>
      </CardFooter>
    </Card>
  );
}
