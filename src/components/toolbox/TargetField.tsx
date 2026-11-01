// FD-09: what a Toolbox tool is pointed at: a session or VM handed over from its row (shown by name, with a way back
// to typing), or a host typed in, with the tool's last inputs offered as you type.

import { useCallback, useState, type ReactNode } from "react";
import { XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { recentInputs, rememberInput, type ToolboxTool, type ToolTarget } from "@/lib/toolbox";

/** The tool's last inputs, and a way to add one. */
export function useRecent(tool: ToolboxTool): [string[], (input: string) => void] {
  const [recent, setRecent] = useState(() => recentInputs(tool));
  const remember = useCallback((input: string) => setRecent(rememberInput(tool, input)), [tool]);
  return [recent, remember];
}

interface Props {
  id: string;
  target: ToolTarget;
  onChange: (target: ToolTarget) => void;
  /** Enter in the field. */
  onSubmit: () => void;
  recent: string[];
  placeholder?: string;
  disabled?: boolean;
}

export function TargetField({ id, target, onChange, onSubmit, recent, placeholder, disabled }: Props) {
  if (target.kind !== "address") {
    return (
      <div className="flex h-9 min-w-0 items-center gap-2 rounded-md border px-3 text-sm" id={id}>
        <span className="min-w-0 truncate font-medium">{target.label}</span>
        <span className="shrink-0 text-muted-foreground">{target.kind === "session" ? "Session" : "VM"}</span>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              className="ml-auto"
              aria-label="Type a host instead"
              disabled={disabled}
              onClick={() => onChange({ kind: "address", host: "" })}
            >
              <XIcon />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Type a host instead</TooltipContent>
        </Tooltip>
      </div>
    );
  }
  return (
    <>
      <Input
        id={id}
        data-mask="host"
        list={`${id}-recent`}
        autoComplete="off"
        spellCheck={false}
        placeholder={placeholder ?? "Host name or IP address"}
        value={target.host}
        disabled={disabled}
        onChange={(e) => onChange({ kind: "address", host: e.target.value })}
        onKeyDown={(e) => {
          if (e.key === "Enter") onSubmit();
        }}
      />
      <datalist id={`${id}-recent`}>
        {recent.map((value) => (
          <option key={value} value={value} />
        ))}
      </datalist>
    </>
  );
}

/** A labelled field in a tool's form. */
export function Field({
  label,
  htmlFor,
  children,
  className,
}: {
  label: string;
  htmlFor: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={className ?? "grid gap-1.5"}>
      <label htmlFor={htmlFor} className="text-sm font-medium">
        {label}
      </label>
      {children}
    </div>
  );
}

/** A run's error, as the tool shows it. */
export function RunError({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <p className="text-sm text-destructive" role="alert">
      {error}
    </p>
  );
}
