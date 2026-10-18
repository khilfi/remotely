// SS-03, QL-04 and QL-05 terminal settings: keep-alive, auto-reconnect, copy-on-select, font size,
// scrollback and the session tree's reachability checks. Saved in the core and audited. Connection
// settings apply to terminals opened from then on; font size and scrollback to open ones too.

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api, errorMessage, type ReachabilityMode, type TerminalSettings } from "@/lib/api";

const REACHABILITY: { value: ReachabilityMode; label: string }[] = [
  { value: "auto", label: "On, unless there are more than 200 sessions" },
  { value: "on", label: "On" },
  { value: "off", label: "Off" },
];

/** The number fields, as typed. */
interface Draft {
  keepalive: string;
  fontSize: string;
  scrollback: string;
  reachabilitySecs: string;
}

function draftOf(s: TerminalSettings): Draft {
  return {
    keepalive: String(s.keepaliveSecs),
    fontSize: String(s.fontSize),
    scrollback: String(s.scrollback),
    reachabilitySecs: String(s.reachabilitySecs),
  };
}

export function TerminalSettingsCard() {
  const [settings, setSettings] = useState<TerminalSettings | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    api.terminalSettings().then(
      (s) => {
        setSettings(s);
        setDraft(draftOf(s));
      },
      (err) => setMessage({ ok: false, text: errorMessage(err) }),
    );
  }, []);

  async function save(next: TerminalSettings) {
    try {
      const saved = await api.setTerminalSettings(next);
      setSettings(saved);
      setDraft(draftOf(saved));
      setMessage({ ok: true, text: "Saved." });
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    }
  }

  if (!settings || !draft) return null;
  const changed = JSON.stringify(draft) !== JSON.stringify(draftOf(settings));
  const field = (key: keyof Draft, id: string, label: string, hint?: string) => (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        className="max-w-32"
        inputMode="numeric"
        value={draft[key]}
        onChange={(e) => setDraft({ ...draft, [key]: e.currentTarget.value })}
      />
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );

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
        <div className="grid gap-4 sm:grid-cols-2">
          {field("keepalive", "keepalive", "Keep-alive every (seconds, 0 for off)")}
          {field("fontSize", "font-size", "Font size (8 to 32)")}
          {field(
            "scrollback",
            "scrollback",
            "Scrollback lines (1000 to 100000)",
            "Lines each terminal keeps to scroll back through, copy, search and save.",
          )}
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
        <div className="grid gap-4 border-t pt-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="reachability">Reachability dots in the session tree</Label>
            <Select
              value={settings.reachability}
              onValueChange={(v) => void save({ ...settings, reachability: v as ReachabilityMode })}
            >
              <SelectTrigger id="reachability" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {REACHABILITY.map((r) => (
                  <SelectItem key={r.value} value={r.value}>
                    {r.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              A TCP connection to each shown session's port, opened and closed at once: no login. Sessions in closed
              groups are not checked.
            </p>
          </div>
          {field("reachabilitySecs", "reachability-secs", "Check every (seconds, 15 to 3600)")}
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
          disabled={!changed}
          onClick={() =>
            void save({
              ...settings,
              keepaliveSecs: Number(draft.keepalive),
              fontSize: Number(draft.fontSize),
              scrollback: Number(draft.scrollback),
              reachabilitySecs: Number(draft.reachabilitySecs),
            })
          }
        >
          Save
        </Button>
      </CardFooter>
    </Card>
  );
}
