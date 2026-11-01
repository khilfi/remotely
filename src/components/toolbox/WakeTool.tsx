// FD-09: the Toolbox's Wake up tab: a Wake-on-LAN magic packet for a MAC (from the VM's hardware, the VM a session is
// linked to, or typed), sent from an adapter of this PC to its subnet broadcast, or to an address typed in. Sending is
// a command on the bus: Low, Medium for a Prod target, audited, and refused by the read-only lock.

import { useEffect, useState } from "react";
import { PowerIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { HelpTip } from "@/components/HelpTip";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type SubmitOutcome, type TargetRef, type WakeSpec } from "@/lib/api";
import { normalizeMac, wakeAddress, type ToolTarget } from "@/lib/toolbox";
import { toolboxApi, type WakeOptions } from "@/lib/toolbox-api";
import type { Incoming } from "./ProbeTools";
import { Field, RunError, TargetField, useRecent } from "./TargetField";

/** "Send from": an adapter by its address, or an address typed in. */
const TYPED = "typed";

function targetRef(target: ToolTarget): TargetRef {
  switch (target.kind) {
    case "session":
      return { kind: "session", sessionId: target.sessionId };
    case "vm":
      return { kind: "vm", vmxPath: target.vmKey };
    case "address":
      return { kind: "app" };
  }
}

export function WakeTool({
  incoming,
  shown,
  onSubmitted,
}: {
  incoming: Incoming | null;
  /** The tab shows: only then are the adapters and MACs read. */
  shown: boolean;
  onSubmitted: (outcome: SubmitOutcome) => void;
}) {
  const [target, setTarget] = useState<ToolTarget>(incoming?.target ?? { kind: "address", host: "" });
  const [handled, setHandled] = useState(incoming?.n ?? 0);
  const [mac, setMac] = useState("");
  if (incoming && incoming.n !== handled) {
    setHandled(incoming.n);
    setTarget(incoming.target);
    setMac("");
  }
  const [recent, remember] = useRecent("wake");
  const [options, setOptions] = useState<WakeOptions | null>(null);
  const [from, setFrom] = useState<string>("");
  const [address, setAddress] = useState("");
  const [port, setPort] = useState("9");
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const readOnly = useReadOnlyReason();

  const ref = target.kind === "address" ? null : targetRef(target);
  const refKey = JSON.stringify(ref);
  useEffect(() => {
    if (!shown) return;
    let gone = false;
    toolboxApi.wakeOptions(ref).then(
      (found) => {
        if (gone) return;
        setOptions(found);
        setFrom((current) => current || found.adapters[0]?.address || TYPED);
        if (found.macs.length > 0) setMac((current) => current || found.macs[0].mac);
      },
      (err) => {
        if (!gone) setError(errorMessage(err));
      },
    );
    return () => {
      gone = true;
    };
    // `ref` is rebuilt each render; its JSON says when it changed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refKey, shown]);

  const normalized = normalizeMac(mac);
  const typedAddress = from === TYPED ? wakeAddress(address) : null;
  const portNumber = Number(port);
  const reason =
    readOnly ??
    (!normalized
      ? "Type the machine's MAC address"
      : from === TYPED && !typedAddress
        ? "Type the address to send to, like 192.0.2.255"
        : !Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535
          ? "Type a port from 1 to 65535"
          : null);

  const wake = async () => {
    if (reason || !normalized) return;
    const destination: WakeSpec["destination"] =
      from === TYPED ? { kind: "address", address: typedAddress ?? "" } : { kind: "adapter", address: from };
    setSending(true);
    setError(null);
    try {
      remember(normalized);
      onSubmitted(
        await api.submit({
          type: "wakeOnLan",
          targets: [targetRef(target)],
          wake: { mac: normalized, destination, port: portNumber },
        }),
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="flex max-w-3xl flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Machine" htmlFor="wake-target">
          {target.kind === "address" ? (
            <p id="wake-target" className="flex h-9 items-center text-sm text-muted-foreground">
              None: the MAC alone (Wake up on a session or VM row fills it in)
            </p>
          ) : (
            <TargetField
              id="wake-target"
              target={target}
              onChange={(t) => {
                setTarget(t);
                setMac("");
              }}
              onSubmit={() => void wake()}
              recent={[]}
            />
          )}
        </Field>
        <Field label="MAC address" htmlFor="wake-mac">
          <Input
            id="wake-mac"
            data-mask="mac"
            list="wake-mac-known"
            autoComplete="off"
            spellCheck={false}
            placeholder="aa:bb:cc:dd:ee:ff"
            value={mac}
            onChange={(e) => setMac(e.target.value)}
          />
          <datalist id="wake-mac-known">
            {[...(options?.macs.map((m) => m.mac) ?? []), ...recent].map((v, i) => (
              <option key={`${v}-${i}`} value={v} />
            ))}
          </datalist>
          {options && options.macs.length > 0 && (
            <p className="text-xs text-muted-foreground">
              {options.macs.find((m) => m.mac === normalized)?.source ?? "Typed in"}
            </p>
          )}
        </Field>
        <Field label="Send from" htmlFor="wake-from">
          <Select value={from} onValueChange={setFrom}>
            <SelectTrigger id="wake-from" className="w-full">
              <SelectValue placeholder="Choose an adapter" />
            </SelectTrigger>
            <SelectContent>
              {options?.adapters.map((a) => (
                <SelectItem key={a.address} value={a.address}>
                  {a.name} · {a.address}/{a.prefix} to {a.broadcast}
                </SelectItem>
              ))}
              <SelectItem value={TYPED}>An address I type</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <div className="grid grid-cols-[minmax(0,1fr)_5rem] gap-3">
          <Field label="Send to" htmlFor="wake-address">
            <Input
              id="wake-address"
              data-mask="ip"
              autoComplete="off"
              spellCheck={false}
              placeholder={from === TYPED ? "192.0.2.255" : "The adapter's broadcast"}
              disabled={from !== TYPED}
              value={from === TYPED ? address : (options?.adapters.find((a) => a.address === from)?.broadcast ?? "")}
              onChange={(e) => setAddress(e.target.value)}
            />
          </Field>
          <Field label="Port" htmlFor="wake-port">
            <Input id="wake-port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} />
          </Field>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <WhyDisabled reason={sending ? null : reason}>
          <Button onClick={() => void wake()} disabled={sending || reason !== null}>
            <PowerIcon data-icon="inline-start" />
            Wake up
          </Button>
        </WhyDisabled>
        <HelpTip topic="toolbox.wake" />
      </div>
      <RunError error={error} />
    </div>
  );
}
