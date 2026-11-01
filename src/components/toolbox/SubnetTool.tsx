// FD-09: the Toolbox's Subnet calculator, worked out in the window as you type (nothing is sent anywhere).

import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table";
import { calculate, countText, split, MAX_SPLIT_LISTED } from "@/lib/subnet";
import { Field, useRecent } from "./TargetField";

export function SubnetTool() {
  const [text, setText] = useState("");
  const [into, setInto] = useState("");
  const [recent, remember] = useRecent("subnet");
  const result = text.trim() ? calculate(text) : null;
  const info = result?.ok ? result.info : null;
  const prefix = Number(into);
  const parts = info && into.trim() && Number.isInteger(prefix) ? split(info, prefix) : null;
  const rows: [string, string][] = info
    ? [
        ["Network", info.cidr],
        ...(info.mask ? ([["Mask", info.mask]] as [string, string][]) : []),
        ...(info.wildcard ? ([["Wildcard", info.wildcard]] as [string, string][]) : []),
        ...(info.broadcast ? ([["Broadcast", info.broadcast]] as [string, string][]) : []),
        [info.family === 4 ? "First host" : "First address", info.first],
        [info.family === 4 ? "Last host" : "Last address", info.last],
        [info.family === 4 ? "Hosts" : "Addresses", countText(info.hosts)],
        ...(info.family === 4 && info.hosts !== info.addresses
          ? ([["Addresses", countText(info.addresses)]] as [string, string][])
          : []),
      ]
    : [];
  return (
    <div className="flex max-w-3xl flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_10rem]">
        <Field label="Address and prefix" htmlFor="subnet-cidr">
          <Input
            id="subnet-cidr"
            list="subnet-cidr-recent"
            autoComplete="off"
            spellCheck={false}
            placeholder="192.0.2.0/24 or 2001:db8::/48"
            value={text}
            onChange={(e) => setText(e.target.value)}
            onBlur={() => {
              if (info) remember(text);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && info) remember(text);
            }}
          />
          <datalist id="subnet-cidr-recent">
            {recent.map((v) => (
              <option key={v} value={v} />
            ))}
          </datalist>
        </Field>
        <Field label="Split into /" htmlFor="subnet-split">
          <Input
            id="subnet-split"
            inputMode="numeric"
            placeholder={info ? String(Math.min(info.prefix + 2, info.family === 4 ? 32 : 128)) : ""}
            value={into}
            disabled={!info}
            onChange={(e) => setInto(e.target.value)}
          />
        </Field>
      </div>
      {result && !result.ok && (
        <p className="text-sm text-destructive" role="alert">
          {result.error}
        </p>
      )}
      {info && (
        <div className="rounded-lg border">
          <Table>
            <TableBody>
              {rows.map(([label, value]) => (
                <TableRow key={label}>
                  <TableCell className="w-40 text-muted-foreground">{label}</TableCell>
                  <TableCell className="font-mono text-xs break-all whitespace-normal">{value}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {parts && !parts.ok && <p className="text-sm text-destructive">{parts.error}</p>}
      {parts && parts.ok && (
        <div className="grid gap-2">
          <p className="text-sm">
            {countText(parts.total)} subnets
            {parts.listedAll ? "" : `; the first ${MAX_SPLIT_LISTED} are listed`}
          </p>
          <div className="grid max-h-80 grid-cols-[repeat(auto-fill,minmax(12rem,1fr))] gap-x-4 gap-y-1 overflow-y-auto rounded-lg border p-3 font-mono text-xs">
            {parts.subnets.map((s) => (
              <span key={s}>{s}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
