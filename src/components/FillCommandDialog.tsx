// BX-08: asks for a command's {{variables}} before it is pasted, with the defaults filled in and the finished command
// shown. The core fills them in (and refuses a value with a line break, which would press Enter halfway). "Paste"
// leaves the command at the prompt; "Paste and run" also presses Enter.

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RiskBadge } from "@/components/Badges";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type CommandRisk, type CommandVariable } from "@/lib/api";
import { namesAHost } from "@/lib/presentation";

interface Props {
  name: string;
  command: string;
  variables: CommandVariable[];
  risk: CommandRisk;
  /** Where it goes, e.g. the terminal's name. */
  target: string;
  /** Shift+click: running is the first choice. */
  run: boolean;
  onSend: (filled: string, enter: boolean) => void;
  onClose: () => void;
}

export function FillCommandDialog({ name, command, variables, risk, target, run, onSend, onClose }: Props) {
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(variables.map((v) => [v.name, v.default ?? ""])),
  );
  const [filled, setFilled] = useState<{ text: string } | { error: string } | null>(null);

  useEffect(() => {
    let current = true;
    api.commandFill(command, values).then(
      (text) => current && setFilled({ text }),
      (err) => current && setFilled({ error: errorMessage(err) }),
    );
    return () => {
      current = false;
    };
  }, [command, values]);

  /** Filled again from the values as they are now: the preview may lag behind the last keystroke. */
  async function send(enter: boolean) {
    try {
      const text = await api.commandFill(command, values);
      onSend(text, enter);
      onClose();
    } catch (err) {
      setFilled({ error: errorMessage(err) });
    }
  }

  const ready = !(filled && "error" in filled);
  // QL-08: the fill's own problem says why the buttons wait.
  const notReady = filled && "error" in filled ? filled.error : null;
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{name}</DialogTitle>
          <DialogDescription>Fill in the values, then paste the command into {target}.</DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            void send(run);
          }}
        >
          {variables.map((v, i) => (
            <div key={v.name} className="grid gap-2">
              <Label htmlFor={`variable-${v.name}`} className="font-mono">
                {v.name}
              </Label>
              <Input
                id={`variable-${v.name}`}
                // FD-03: a host, address or user shows as dots while presenting.
                data-mask={namesAHost(v.name) ? "host" : undefined}
                value={values[v.name] ?? ""}
                placeholder={v.default ? `Default: ${v.default}` : undefined}
                autoFocus={i === 0}
                spellCheck={false}
                onChange={(e) => setValues({ ...values, [v.name]: e.currentTarget.value })}
              />
            </div>
          ))}
          <div className="grid gap-1.5">
            <div className="flex items-center justify-between gap-2 text-sm font-medium">
              Command
              <RiskBadge risk={risk} />
            </div>
            {filled && "error" in filled ? (
              <p className="text-sm text-destructive" role="alert">
                {filled.error}
              </p>
            ) : (
              <pre className="max-h-40 overflow-auto rounded-md border bg-muted/50 px-3 py-2 font-mono text-xs break-all whitespace-pre-wrap">
                {filled?.text ?? command}
              </pre>
            )}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <WhyDisabled reason={notReady}>
              <Button
                type={run ? "button" : "submit"}
                variant={run ? "outline" : "default"}
                disabled={!ready}
                onClick={run ? () => void send(false) : undefined}
              >
                Paste
              </Button>
            </WhyDisabled>
            <WhyDisabled reason={notReady}>
              <Button
                type={run ? "submit" : "button"}
                variant={run ? "default" : "outline"}
                disabled={!ready}
                onClick={run ? undefined : () => void send(true)}
              >
                Paste and run
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
