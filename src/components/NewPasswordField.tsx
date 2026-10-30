// SS-04, FD-07: the field for a new vault password or export passphrase. Under it, a strength meter with the
// core's hint (the form scores the value with usePasswordStrength; the core's check on submit decides).
// Generate fills in six random words the core made up and shows them so they can be written down, except while
// presenting (FD-03), when the field stays dots. The value lives only in the form's state and goes to the core
// once, on submit.

import { useState, type ReactNode } from "react";
import { toast } from "sonner";
import { EyeIcon, EyeOffIcon, WandSparklesIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from "@/components/ui/input-group";
import { Label } from "@/components/ui/label";
import { Meter } from "@/components/MetricBits";
import { usePresentation } from "@/components/Presentation";
import { api, errorMessage, type PasswordStrength } from "@/lib/api";
import { strengthView } from "@/lib/passwords";
import { cn } from "@/lib/utils";

interface Props {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  /** Generate filled in a passphrase: the form puts it in its "Type it again" field too. */
  onGenerated: (value: string) => void;
  /** The core's score for the value (usePasswordStrength); null while it is empty or being scored. */
  strength: PasswordStrength | null;
  /** Shown under an empty field. */
  description?: ReactNode;
  /** "password" or "passphrase", for screen readers. */
  noun?: string;
  disabled?: boolean;
  className?: string;
}

export function NewPasswordField({
  id,
  label,
  value,
  onChange,
  onGenerated,
  strength,
  description,
  noun = "password",
  disabled,
  className,
}: Props) {
  const presenting = usePresentation().presenting;
  const [revealed, setRevealed] = useState(false);
  const [generated, setGenerated] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function generate() {
    setBusy(true);
    try {
      const phrase = await api.passphraseGenerate();
      setGenerated(phrase);
      setRevealed(true);
      onChange(phrase);
      onGenerated(phrase);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const visible = revealed && !presenting;
  const fromGenerate = generated !== null && value === generated;
  const view = strength ? strengthView(strength.score, strength.acceptable) : null;

  return (
    <div className={cn("grid gap-2", className)}>
      <Label htmlFor={id}>{label}</Label>
      <div className="flex gap-2">
        <InputGroup>
          <InputGroupInput
            id={id}
            type={visible ? "text" : "password"}
            autoComplete="new-password"
            spellCheck={false}
            value={value}
            disabled={disabled}
            onChange={(e) => onChange(e.currentTarget.value)}
            aria-invalid={(strength !== null && !strength.acceptable) || undefined}
            aria-describedby={`${id}-hint`}
          />
          <InputGroupAddon align="inline-end">
            <InputGroupButton
              size="icon-xs"
              aria-label={visible ? `Hide the ${noun}` : `Show the ${noun}`}
              title={presenting ? "Hidden while presenting" : undefined}
              disabled={disabled || presenting}
              onClick={() => setRevealed((r) => !r)}
            >
              {visible ? <EyeOffIcon /> : <EyeIcon />}
            </InputGroupButton>
          </InputGroupAddon>
        </InputGroup>
        <Button type="button" variant="outline" disabled={disabled || busy} onClick={() => void generate()}>
          <WandSparklesIcon data-icon="inline-start" />
          Generate
        </Button>
      </div>
      <div id={`${id}-hint`} className="grid gap-1" aria-live="polite">
        {value && view && strength ? (
          <>
            <div className="flex items-center gap-2">
              <Meter
                pct={view.percent}
                level={view.level}
                label={`How hard the ${noun} is to guess`}
                className="w-32"
              />
              <span className="text-xs text-muted-foreground">{view.label}</span>
            </div>
            {/* UX-04: the core's hint only when it says more than the meter's word ("Strong."). */}
            {strength.hint.replace(/\.$/, "").toLowerCase() !== view.label.toLowerCase() && (
              <p className={strength.acceptable ? "text-sm text-muted-foreground" : "text-sm text-destructive"}>
                {strength.hint}
              </p>
            )}
          </>
        ) : (
          !value && description && <p className="text-sm text-muted-foreground">{description}</p>
        )}
        {fromGenerate && (
          <p className="text-sm text-muted-foreground">
            {presenting
              ? "Generated and hidden while presenting. Stop presenting to see it and write it down."
              : "Write it down or keep it in your password manager: it can't be recovered."}
          </p>
        )}
      </div>
    </div>
  );
}
