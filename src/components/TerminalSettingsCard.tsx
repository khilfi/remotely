// SS-03 terminal settings: keep-alive, auto-reconnect and copy-on-select. Saved in the core and audited;
// they apply to terminals opened from then on.

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api, errorMessage, type TerminalSettings } from "@/lib/api";

export function TerminalSettingsCard() {
  const [settings, setSettings] = useState<TerminalSettings | null>(null);
  const [keepalive, setKeepalive] = useState("");
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    api.terminalSettings().then(
      (s) => {
        setSettings(s);
        setKeepalive(String(s.keepaliveSecs));
      },
      (err) => setMessage({ ok: false, text: errorMessage(err) }),
    );
  }, []);

  async function save(next: TerminalSettings) {
    try {
      const saved = await api.setTerminalSettings(next);
      setSettings(saved);
      setKeepalive(String(saved.keepaliveSecs));
      setMessage({ ok: true, text: "Saved. Applies to terminals opened from now on." });
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    }
  }

  if (!settings) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Terminal</CardTitle>
        <CardDescription>
          Keep-alives stop idle connections from being dropped by firewalls and VPNs, and notice a dead link. A dropped
          connection reconnects by itself, with growing pauses, up to 10 times.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-2">
          <Label htmlFor="keepalive">Keep-alive every (seconds, 0 for off)</Label>
          <Input
            id="keepalive"
            className="max-w-32"
            inputMode="numeric"
            value={keepalive}
            onChange={(e) => setKeepalive(e.currentTarget.value)}
          />
        </div>
        <div className="flex items-center gap-3">
          <Switch
            id="auto-reconnect"
            checked={settings.autoReconnect}
            onCheckedChange={(autoReconnect) => void save({ ...settings, autoReconnect })}
          />
          <Label htmlFor="auto-reconnect" className="font-normal">
            Reconnect by itself after a dropped connection
          </Label>
        </div>
        <div className="flex items-center gap-3">
          <Switch
            id="copy-on-select"
            checked={settings.copyOnSelect}
            onCheckedChange={(copyOnSelect) => void save({ ...settings, copyOnSelect })}
          />
          <Label htmlFor="copy-on-select" className="font-normal">
            Copy text as soon as it is selected (like PuTTY)
          </Label>
        </div>
        {message && (
          <p className={message.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
            {message.text}
          </p>
        )}
      </CardContent>
      <CardFooter>
        <Button
          variant="outline"
          disabled={keepalive === String(settings.keepaliveSecs)}
          onClick={() => void save({ ...settings, keepaliveSecs: Number(keepalive) })}
        >
          Save keep-alive
        </Button>
      </CardFooter>
    </Card>
  );
}
