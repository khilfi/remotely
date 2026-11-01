// SS-12: the session editor's fields of each kind but SSH, under Advanced: remote desktop's screen and what it shares,
// VNC's view only, Telnet's line ending, a serial line's speed, framing, flow control, line ending and local echo. And
// the serial session's COM port, which takes the host's place (the ports Windows has now are offered to pick).

import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { RefreshButton } from "@/components/RefreshButton";
import { api, errorMessage, type ComPort, type LineEnding, type SessionKind } from "@/lib/api";
import {
  FLOW_CHOICES,
  LINE_ENDING_CHOICES,
  PARITY_CHOICES,
  SERIAL_SPEEDS,
  STOP_BIT_CHOICES,
} from "@/lib/session-kinds";

function Check({
  id,
  label,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (on: boolean) => void;
}) {
  return (
    <div className="flex items-center gap-2">
      <Checkbox id={id} checked={checked} onCheckedChange={(v) => onChange(v === true)} />
      <Label htmlFor={id} className="font-normal">
        {label}
      </Label>
    </div>
  );
}

function LineEndingField({ value, onChange }: { value: LineEnding; onChange: (v: LineEnding) => void }) {
  return (
    <div className="grid content-start gap-2">
      <Label>Enter sends</Label>
      <ToggleGroup
        type="single"
        variant="outline"
        size="sm"
        className="justify-self-start"
        value={value}
        onValueChange={(v) => v && onChange(v as LineEnding)}
      >
        {LINE_ENDING_CHOICES.map((c) => (
          <ToggleGroupItem key={c.value} value={c.value}>
            {c.label}
          </ToggleGroupItem>
        ))}
      </ToggleGroup>
    </div>
  );
}

export function SessionKindFields({
  kind,
  onChange,
  problem,
}: {
  kind: SessionKind;
  onChange: (kind: SessionKind) => void;
  /** What the fields refuse, shown under them. */
  problem: string | null;
}) {
  const problemLine = problem && (
    <p className="text-xs text-destructive" role="alert">
      {problem}
    </p>
  );
  switch (kind.protocol) {
    case "ssh":
      return null;
    case "rdp": {
      const screen = kind.screen;
      const mode = screen.mode;
      return (
        <div className="grid gap-3">
          <div className="grid gap-2">
            <Label>Screen</Label>
            <ToggleGroup
              type="single"
              variant="outline"
              size="sm"
              className="flex-wrap justify-self-start"
              value={mode}
              onValueChange={(v) => {
                if (v === "full" || v === "allMonitors") onChange({ ...kind, screen: { mode: v } });
                if (v === "window") onChange({ ...kind, screen: { mode: "window", width: 1600, height: 900 } });
              }}
            >
              <ToggleGroupItem value="full">Full screen</ToggleGroupItem>
              <ToggleGroupItem value="allMonitors">All monitors</ToggleGroupItem>
              <ToggleGroupItem value="window">Window</ToggleGroupItem>
            </ToggleGroup>
            {screen.mode === "window" && (
              <div className="flex items-center gap-2">
                <Input
                  aria-label="Width in pixels"
                  inputMode="numeric"
                  className="w-24"
                  value={String(screen.width)}
                  onChange={(e) =>
                    onChange({ ...kind, screen: { ...screen, width: Number(e.currentTarget.value) || 0 } })
                  }
                />
                <span className="text-muted-foreground">×</span>
                <Input
                  aria-label="Height in pixels"
                  inputMode="numeric"
                  className="w-24"
                  value={String(screen.height)}
                  onChange={(e) =>
                    onChange({ ...kind, screen: { ...screen, height: Number(e.currentTarget.value) || 0 } })
                  }
                />
              </div>
            )}
          </div>
          <div className="grid gap-2">
            <Label>Share with the remote desktop</Label>
            <div className="flex flex-wrap gap-x-5 gap-y-2">
              <Check
                id="rdp-clipboard"
                label="Clipboard"
                checked={kind.clipboard}
                onChange={(clipboard) => onChange({ ...kind, clipboard })}
              />
              <Check
                id="rdp-drives"
                label="Drives"
                checked={kind.drives}
                onChange={(drives) => onChange({ ...kind, drives })}
              />
              <Check
                id="rdp-printers"
                label="Printers"
                checked={kind.printers}
                onChange={(printers) => onChange({ ...kind, printers })}
              />
              <Check
                id="rdp-audio"
                label="Sound"
                checked={kind.audio}
                onChange={(audio) => onChange({ ...kind, audio })}
              />
            </div>
          </div>
          <Check
            id="rdp-admin"
            label="Admin session (the server's console)"
            checked={kind.admin}
            onChange={(admin) => onChange({ ...kind, admin })}
          />
          {problemLine}
        </div>
      );
    }
    case "vnc":
      return (
        <Check
          id="vnc-view-only"
          label="View only: send no keys or mouse moves"
          checked={kind.viewOnly}
          onChange={(viewOnly) => onChange({ ...kind, viewOnly })}
        />
      );
    case "telnet":
      return <LineEndingField value={kind.lineEnding} onChange={(lineEnding) => onChange({ ...kind, lineEnding })} />;
    case "serial":
      return (
        <div className="grid gap-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid content-start gap-2">
              <Label htmlFor="serial-speed">Speed (bits per second)</Label>
              <Input
                id="serial-speed"
                inputMode="numeric"
                list="serial-speeds"
                className="font-mono"
                value={String(kind.speed)}
                onChange={(e) => onChange({ ...kind, speed: Number(e.currentTarget.value) || 0 })}
              />
              <datalist id="serial-speeds">
                {SERIAL_SPEEDS.map((s) => (
                  <option key={s} value={s} />
                ))}
              </datalist>
            </div>
            <div className="grid content-start gap-2">
              <Label htmlFor="serial-data-bits">Data bits</Label>
              <Select value={String(kind.dataBits)} onValueChange={(v) => onChange({ ...kind, dataBits: Number(v) })}>
                <SelectTrigger id="serial-data-bits" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {[8, 7, 6, 5].map((b) => (
                    <SelectItem key={b} value={String(b)}>
                      {b}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid content-start gap-2">
              <Label htmlFor="serial-parity">Parity</Label>
              <Select value={kind.parity} onValueChange={(v) => onChange({ ...kind, parity: v as typeof kind.parity })}>
                <SelectTrigger id="serial-parity" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PARITY_CHOICES.map((p) => (
                    <SelectItem key={p.value} value={p.value}>
                      {p.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid content-start gap-2">
              <Label htmlFor="serial-stop-bits">Stop bits</Label>
              <Select
                value={kind.stopBits}
                onValueChange={(v) => onChange({ ...kind, stopBits: v as typeof kind.stopBits })}
              >
                <SelectTrigger id="serial-stop-bits" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {STOP_BIT_CHOICES.map((s) => (
                    <SelectItem key={s.value} value={s.value}>
                      {s.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid content-start gap-2">
              <Label htmlFor="serial-flow">Flow control</Label>
              <Select
                value={kind.flowControl}
                onValueChange={(v) => onChange({ ...kind, flowControl: v as typeof kind.flowControl })}
              >
                <SelectTrigger id="serial-flow" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {FLOW_CHOICES.map((f) => (
                    <SelectItem key={f.value} value={f.value}>
                      {f.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <LineEndingField value={kind.lineEnding} onChange={(lineEnding) => onChange({ ...kind, lineEnding })} />
          </div>
          <Check
            id="serial-echo"
            label="Local echo: show what is typed, for devices that don't"
            checked={kind.localEcho}
            onChange={(localEcho) => onChange({ ...kind, localEcho })}
          />
          {problemLine}
        </div>
      );
  }
}

/** A serial session's COM port, with the ports Windows has now to pick from. */
export function SerialPortField({
  value,
  onChange,
  autoFocus,
}: {
  value: string;
  onChange: (port: string) => void;
  autoFocus?: boolean;
}) {
  const [ports, setPorts] = useState<ComPort[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** Bumped by Refresh to read the ports again. */
  const [reads, setReads] = useState(0);

  useEffect(() => {
    let live = true;
    api.serialPorts().then(
      (found) => {
        if (!live) return;
        setPorts(found);
        setError(null);
      },
      (err) => {
        if (!live) return;
        setPorts([]);
        setError(errorMessage(err));
      },
    );
    return () => {
      live = false;
    };
  }, [reads]);

  const missing = value.trim() !== "" && ports !== null && !ports.some((p) => p.name === value.trim().toUpperCase());
  return (
    <div className="grid gap-2">
      <Label htmlFor="session-com-port">COM port</Label>
      <div className="flex items-center gap-2">
        <Input
          id="session-com-port"
          autoFocus={autoFocus}
          autoComplete="off"
          spellCheck={false}
          className="w-40 font-mono"
          placeholder="COM3"
          value={value}
          onChange={(e) => onChange(e.currentTarget.value)}
        />
        <RefreshButton onClick={() => setReads((n) => n + 1)} />
        <div className="flex flex-wrap gap-1">
          {(ports ?? []).map((p) => (
            <Badge key={p.name} asChild variant={p.name === value.trim().toUpperCase() ? "default" : "outline"}>
              <button type="button" title={p.device} onClick={() => onChange(p.name)}>
                {p.name}
              </button>
            </Badge>
          ))}
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        {error ??
          (ports === null
            ? "Looking for COM ports…"
            : ports.length === 0
              ? "No COM port is plugged in now; type the one it will have."
              : missing
                ? "That port isn't plugged in now."
                : "A COM port opens in one tab at a time.")}
      </p>
    </div>
  );
}
