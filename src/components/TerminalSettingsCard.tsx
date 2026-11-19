// SS-03, QL-04, QL-05 and QL-07 terminal settings: keep-alive, auto-reconnect, copy-on-select, asking before a
// multi-line paste, font size, scrollback, the session tree's reachability checks (each shows in the host's sshd log,
// which their "?" says), and notifications when a command finishes while the user is away (a background tab, another
// page, or Remotely not in front): commands longer than N seconds, or any command whatever its length. A MultiExec
// line notifies once for all its terminals. Saved in the core and audited. Connection settings apply to terminals
// opened from then on; font size, scrollback, the paste question and notifications to open ones too.
//
// UX-10: every field saves at once (a number on Enter or when you leave it), with "Saved" and Undo in the header;
// the longer explanations are behind "?". UX-14 (0.9.0 H1): what double-clicking a file does is FilesSettingsCard's,
// for Files here and the Files page alike; both cards save through saveTerminalSettings.

import { useEffect, useState } from "react";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { HelpTip } from "@/components/HelpTip";
import { NumberSetting, SaveStatus, useSaveStatus } from "@/components/SaveStatus";
import { api, errorMessage, type NotifyWhen, type ReachabilityMode, type TerminalSettings } from "@/lib/api";
import type { HelpKey } from "@/lib/help";

const REACHABILITY: { value: ReachabilityMode; label: string }[] = [
  { value: "auto", label: "On, unless there are more than 200 sessions" },
  { value: "on", label: "On" },
  { value: "off", label: "Off" },
];

/**
 * UX-14 (0.9.0 H1): the terminal settings are saved whole, and two cards edit them (Terminal, and Files' double-click),
 * so a change goes onto the settings as the core has them now: one card's save never puts back what the other changed.
 */
export async function saveTerminalSettings(change: Partial<TerminalSettings>): Promise<TerminalSettings> {
  const now = await api.terminalSettings();
  return api.setTerminalSettings({ ...now, ...change });
}

/** What Undo puts back: the changed settings' values before the change, and nothing else. */
export function undoOf(before: TerminalSettings, change: Partial<TerminalSettings>): Partial<TerminalSettings> {
  const keys = Object.keys(change) as (keyof TerminalSettings)[];
  return Object.fromEntries(keys.map((key) => [key, before[key]])) as Partial<TerminalSettings>;
}

export function TerminalSettingsCard() {
  const [settings, setSettings] = useState<TerminalSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const status = useSaveStatus();
  // The notify-after seconds, as typed (inside a radio row, so not a NumberSetting).
  const [notifyAfter, setNotifyAfter] = useState("");

  useEffect(() => {
    api.terminalSettings().then(
      (s) => {
        setSettings(s);
        setNotifyAfter(String(s.notifyAfterSecs));
      },
      (err) => setError(errorMessage(err)),
    );
  }, []);

  if (!settings) return error ? <p className="text-sm text-destructive">{error}</p> : null;
  const s = settings;

  /** Saves a change, with Undo back to what those settings were before it. */
  function save(change: Partial<TerminalSettings>) {
    void status.run(
      () =>
        saveTerminalSettings(change).then((saved) => {
          setSettings(saved);
          setNotifyAfter(String(saved.notifyAfterSecs));
        }),
      () =>
        saveTerminalSettings(undoOf(s, change)).then((saved) => {
          setSettings(saved);
          setNotifyAfter(String(saved.notifyAfterSecs));
        }),
    );
  }

  const toggle = (id: string, key: keyof TerminalSettings, label: string, help?: HelpKey) => (
    <div className="flex items-center gap-3">
      <Switch id={id} checked={Boolean(s[key])} onCheckedChange={(on) => save({ [key]: on })} />
      <Label htmlFor={id} className="font-normal">
        {label}
      </Label>
      {help && <HelpTip topic={help} />}
    </div>
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>Terminal</CardTitle>
        <CardDescription>Connections, copy and paste, and notifications.</CardDescription>
        <CardAction>
          <SaveStatus status={status} />
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-5">
        <div className="grid gap-4 sm:grid-cols-3">
          <NumberSetting
            id="keepalive"
            label="Keep-alive (0 for off)"
            suffix="seconds"
            min={0}
            max={3600}
            value={s.keepaliveSecs}
            onCommit={(keepaliveSecs) => save({ keepaliveSecs })}
          />
          <NumberSetting
            id="font-size"
            label="Font size"
            min={8}
            max={32}
            value={s.fontSize}
            onCommit={(fontSize) => save({ fontSize })}
          />
          <NumberSetting
            id="scrollback"
            label="Scrollback"
            suffix="lines"
            min={1000}
            max={100000}
            value={s.scrollback}
            onCommit={(scrollback) => save({ scrollback })}
          />
        </div>
        <div className="grid gap-3">
          {toggle("auto-reconnect", "autoReconnect", "Reconnect by itself after a dropped connection")}
          {toggle("copy-on-select", "copyOnSelect", "Copy text as soon as it is selected")}
          {toggle(
            "confirm-multiline-paste",
            "confirmMultilinePaste",
            "Ask before pasting several lines",
            "pasteConfirm",
          )}
          {toggle("prompt-hook", "promptHook", "Follow the shell's folder in bash and zsh", "promptHook")}
        </div>

        <div className="grid gap-4 border-t pt-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <span className="flex items-center gap-1">
              <Label htmlFor="reachability">Reachability dots in the session tree</Label>
              <HelpTip topic="reachabilityChecks" />
            </span>
            <Select value={s.reachability} onValueChange={(v) => save({ reachability: v as ReachabilityMode })}>
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
          </div>
          <NumberSetting
            id="reachability-secs"
            label="Check every"
            suffix="seconds"
            min={15}
            max={3600}
            value={s.reachabilitySecs}
            disabled={s.reachability === "off"}
            onCommit={(reachabilitySecs) => save({ reachabilitySecs })}
          />
        </div>

        <div className="grid gap-4 border-t pt-4">
          {toggle("notify-finished", "notifyFinished", "Notify when a command finishes while I'm away", "notifyAway")}
          <RadioGroup
            value={s.notifyWhen}
            onValueChange={(v) => save({ notifyWhen: v as NotifyWhen })}
            disabled={!s.notifyFinished}
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
                disabled={!s.notifyFinished || s.notifyWhen !== "long"}
                value={notifyAfter}
                onChange={(e) => setNotifyAfter(e.currentTarget.value)}
                onBlur={() => {
                  const next = Number(notifyAfter.trim());
                  if (notifyAfter.trim() === "" || !Number.isFinite(next)) setNotifyAfter(String(s.notifyAfterSecs));
                  else if (next !== s.notifyAfterSecs) save({ notifyAfterSecs: next });
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") e.currentTarget.blur();
                }}
              />
              <span className="text-sm text-muted-foreground">seconds</span>
            </div>
            <div className="flex items-center gap-3">
              <RadioGroupItem id="notify-any" value="any" />
              <Label htmlFor="notify-any" className="font-normal">
                Any command, whatever its length
              </Label>
            </div>
          </RadioGroup>
          <div className="pl-12">
            <NumberSetting
              id="notify-quiet"
              label="Or when it goes quiet for"
              suffix="seconds (0 for never)"
              min={0}
              max={3600}
              value={s.notifyQuietSecs}
              disabled={!s.notifyFinished}
              onCommit={(notifyQuietSecs) => save({ notifyQuietSecs })}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
