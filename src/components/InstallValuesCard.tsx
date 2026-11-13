// VM-29, VM-32: the Deploy dialog's part for a template with an install config: where the VMs' addresses come from
// (typed per VM, or an address pool), a row per VM for the config's placeholders ({{ip}} and its own variables),
// rows pasted from a spreadsheet, the install's time limit, and each VM's file as it will be, secrets masked.

import { useEffect, useState } from "react";
import { ClipboardPasteIcon, EyeIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { HelpTip } from "@/components/HelpTip";
import { errorMessage, type VmInstall } from "@/lib/api";
import type { AddressPool } from "@/lib/address-pools-api";
import { installConfigsApi, type InstallConfig } from "@/lib/install-configs-api";
import { parseRows, rowVariables, usesPlaceholder } from "@/lib/unattended";

const NO_POOL = "none";

interface Props {
  config: InstallConfig;
  /** The VMs the deploy names, in order. */
  names: string[];
  rows: VmInstall[];
  onRows: (rows: VmInstall[]) => void;
  /** The pools that fit the deploy's network. */
  pools: AddressPool[];
  poolId: string | null;
  onPool: (id: string | null) => void;
  minutesText: string;
  onMinutes: (text: string) => void;
  /** The template's name, for `{{template}}` in the preview. */
  templateName: string;
}

export function InstallValuesCard({
  config,
  names,
  rows,
  onRows,
  pools,
  poolId,
  onPool,
  minutesText,
  onMinutes,
  templateName,
}: Props) {
  const variables = rowVariables(config);
  const usesIp = usesPlaceholder(config.body, "ip");
  const typedIp = usesIp && !poolId;
  const [pasting, setPasting] = useState(false);
  const [pasteText, setPasteText] = useState("");
  const [pasteError, setPasteError] = useState<string | null>(null);
  const [previewed, setPreviewed] = useState<number | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);

  const row = (i: number): VmInstall => rows[i] ?? { ip: null, values: {} };
  const setRow = (i: number, next: VmInstall) => {
    const out = names.map((_, n) => (n === i ? next : row(n)));
    onRows(out);
  };

  // The previewed VM's file, masked by the core, as its row changes.
  const previewKey = previewed === null ? null : JSON.stringify([previewed, row(previewed), names[previewed]]);
  useEffect(() => {
    if (previewed === null || previewKey === null) return;
    let stopped = false;
    const r = row(previewed);
    installConfigsApi
      .preview(config, {
        hostname: names[previewed] ?? null,
        ip: r.ip ?? null,
        n: previewed + 1,
        template: templateName,
        values: r.values,
      })
      .then(
        (text) => {
          if (stopped) return;
          setPreview(text);
          setPreviewError(null);
        },
        (err) => !stopped && setPreviewError(errorMessage(err)),
      );
    return () => {
      stopped = true;
    };
    // The key holds what the preview depends on.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [previewKey, config]);

  function paste() {
    const parsed = parseRows(
      pasteText,
      variables.map((v) => v.name),
    );
    if (parsed.error) {
      setPasteError(parsed.error);
      return;
    }
    onRows(names.map((_, i) => parsed.rows[i] ?? row(i)));
    setPasting(false);
    setPasteText("");
    setPasteError(null);
  }

  return (
    <section className="grid gap-3 rounded-md border p-3" aria-label="Unattended install">
      <div className="flex items-center gap-1 text-sm font-medium">
        Unattended install from &apos;{config.name}&apos;
        <HelpTip topic="deploy.unattended" />
      </div>
      <div className="grid grid-cols-[1fr_10rem] gap-3">
        <div className="grid gap-2">
          <Label htmlFor="deploy-pool">Addresses</Label>
          <Select value={poolId ?? NO_POOL} onValueChange={(v) => onPool(v === NO_POOL ? null : v)}>
            <SelectTrigger id="deploy-pool" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={NO_POOL}>
                {usesIp ? "Typed for each VM below" : "As the install config sets them"}
              </SelectItem>
              {pools.map((p) => (
                <SelectItem key={p.id} value={p.id} disabled={!usesIp}>
                  From the pool {p.name} ({p.free} free)
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {!usesIp && pools.length > 0 && (
            <p className="text-xs text-muted-foreground">
              The config doesn&apos;t use {"{{ip}}"}, so a pool&apos;s addresses would go nowhere.
            </p>
          )}
        </div>
        <div className="grid gap-2">
          <Label htmlFor="deploy-install-minutes">Time limit (minutes)</Label>
          <Input
            id="deploy-install-minutes"
            inputMode="numeric"
            value={minutesText}
            onChange={(e) => onMinutes(e.currentTarget.value)}
          />
        </div>
      </div>

      {(typedIp || variables.length > 0) && (
        <div className="grid gap-2">
          <div className="flex items-center justify-between">
            <span className="text-sm">Values per VM</span>
            <Button variant="ghost" size="sm" onClick={() => setPasting((p) => !p)}>
              <ClipboardPasteIcon data-icon="inline-start" />
              Paste rows
            </Button>
          </div>
          {pasting && (
            <div className="grid gap-2">
              <Label htmlFor="deploy-paste">
                A header line ({["ip", ...variables.map((v) => v.name)].join(", ")}), then a line per VM
              </Label>
              <Textarea
                id="deploy-paste"
                className="font-mono text-xs"
                rows={4}
                value={pasteText}
                onChange={(e) => setPasteText(e.currentTarget.value)}
              />
              {pasteError && (
                <p className="text-xs text-destructive" role="alert">
                  {pasteError}
                </p>
              )}
              <div>
                <Button variant="outline" size="sm" onClick={paste}>
                  Fill the rows
                </Button>
              </div>
            </div>
          )}
          <div className="max-h-64 overflow-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>VM</TableHead>
                  {typedIp && <TableHead>IP address</TableHead>}
                  {variables.map((v) => (
                    <TableHead key={v.name} className="font-mono">
                      {v.name}
                    </TableHead>
                  ))}
                  <TableHead className="w-10">
                    <span className="sr-only">Preview</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {names.map((name, i) => (
                  <TableRow key={name}>
                    <TableCell className="font-medium">{name}</TableCell>
                    {typedIp && (
                      <TableCell>
                        <Input
                          aria-label={`IP address of ${name}`}
                          data-mask="ip"
                          className="h-8 font-mono"
                          value={row(i).ip ?? ""}
                          onChange={(e) => setRow(i, { ...row(i), ip: e.currentTarget.value })}
                        />
                      </TableCell>
                    )}
                    {variables.map((v) => (
                      <TableCell key={v.name}>
                        <Input
                          aria-label={`${v.name} of ${name}`}
                          className="h-8 font-mono"
                          placeholder={v.fallback ?? ""}
                          value={row(i).values[v.name] ?? ""}
                          onChange={(e) =>
                            setRow(i, { ...row(i), values: { ...row(i).values, [v.name]: e.currentTarget.value } })
                          }
                        />
                      </TableCell>
                    ))}
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={`Preview ${name}'s file`}
                        title={`Preview ${name}'s file`}
                        onClick={() => setPreviewed((p) => (p === i ? null : i))}
                      >
                        <EyeIcon />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      )}
      {!typedIp && variables.length === 0 && names.length > 0 && (
        <div>
          <Button variant="ghost" size="sm" onClick={() => setPreviewed((p) => (p === 0 ? null : 0))}>
            <EyeIcon data-icon="inline-start" />
            Preview {names[0]}&apos;s file
          </Button>
        </div>
      )}
      {previewed !== null && (
        <div className="grid gap-1">
          <span className="text-xs text-muted-foreground">
            {names[previewed]}&apos;s {config.kind === "unattend" ? "autounattend.xml" : "answer file"}, secrets masked
          </span>
          {previewError ? (
            <p className="text-xs text-destructive">{previewError}</p>
          ) : (
            <pre className="max-h-64 overflow-auto rounded-md bg-muted p-2 font-mono text-xs whitespace-pre-wrap">
              {preview ?? "…"}
            </pre>
          )}
        </div>
      )}
    </section>
  );
}
