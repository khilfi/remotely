// SS-03, QL-04, QL-05 and QL-07 terminal settings: keep-alive, auto-reconnect, copy-on-select, font size,
// scrollback, the session tree's reachability checks, and notifications when a command finishes while the user is
// away (a background tab, another page, or Remotely not in front): commands longer than N seconds, or any command
// whatever its length. A MultiExec line notifies once for all its terminals. Saved in the core and audited.
// Connection settings apply to terminals opened from then on; font size, scrollback and notifications to open ones
// too.

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api, errorMessage, type NotifyWhen, type ReachabilityMode, type TerminalSettings } from "@/lib/api";

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
  notifyAfter: string;
  notifyQuiet: string;
}

function draftOf(s: TerminalSettings): Draft {
  return {
    keepalive: String(s.keepaliveSecs),
    fontSize: String(s.fontSize),
    scrollback: String(s.scrollback),
    reachabilitySecs: String(s.reachabilitySecs),
    notifyAfter: String(s.notifyAfterSecs),
    notifyQuiet: String(s.notifyQuietSecs),
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
        <div className="grid gap-4 border-t pt-4">
          <div className="flex items-center gap-3">
            <Switch
              id="notify-finished"
              checked={settings.notifyFinished}
              onCheckedChange={(notifyFinished) => void save({ ...settings, notifyFinished })}
            />
            <Label htmlFor="notify-finished" className="font-normal">
              Notify when a command finishes while I&apos;m away
            </Label>
          </div>
          <RadioGroup
            value={settings.notifyWhen}
            onValueChange={(v) => void save({ ...settings, notifyWhen: v as NotifyWhen })}
            disabled={!settings.notifyFinished}
            className="gap-3 pl-12"
            aria-label="Which commands notify"
          >
            <div className="flex flex-wrap items-center gap-3">
              <RadioGroupItem id="notify-long" value="long" />
              <Label htmlFor="notify-long" className="font-normal">
                Commands longer than
              </Label>
              <Input
                id="notify-after"
                aria-label="Seconds, 5 to 3600"
                className="w-24"
                inputMode="numeric"
                disabled={!settings.notifyFinished || settings.notifyWhen !== "long"}
                value={draft.notifyAfter}
                onChange={(e) => setDraft({ ...draft, notifyAfter: e.currentTarget.value })}
              />
              <span className="text-sm text-muted-foreground">seconds (5 to 3600), from Enter to the prompt</span>
            </div>
            <div className="flex items-center gap-3">
              <RadioGroupItem id="notify-any" value="any" />
              <Label htmlFor="notify-any" className="font-normal">
                Any command that finishes while I&apos;m away, whatever its length
              </Label>
            </div>
          </RadioGroup>
          <div className="grid gap-4 sm:grid-cols-2">
            {field(
              "notifyQuiet",
              "notify-quiet",
              "Or when it goes quiet for (seconds, 0 for never)",
              "For prompts Remotely doesn't recognise, or a command waiting for an answer: no output for this long ends it.",
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Away means the tab isn&apos;t on screen (another tab or page) or Remotely isn&apos;t the window in front. A
            line sent with MultiExec notifies once, when all its terminals are done. The bell in the terminal toolbar
            turns notifications off for one tab.
          </p>
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
              notifyAfterSecs: Number(draft.notifyAfter),
              notifyQuietSecs: Number(draft.notifyQuiet),
            })
          }
        >
          Save
        </Button>
      </CardFooter>
    </Card>
  );
}
