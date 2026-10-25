// SS-04, FD-07: the core's strength score for a new vault password or export passphrase, asked again on every change.
// Null while the value is empty or its score hasn't come back; an answer for an older value is dropped. The form
// enables its submit button on `acceptable`, and the core checks again on submit, which decides.

import { useEffect, useState } from "react";
import { api, type PasswordStrength } from "@/lib/api";

export function usePasswordStrength(value: string): PasswordStrength | null {
  const [scored, setScored] = useState<{ value: string; strength: PasswordStrength } | null>(null);
  useEffect(() => {
    if (!value) return;
    let current = true;
    api.passwordStrength(value).then(
      (strength) => {
        if (current) setScored({ value, strength });
      },
      () => {
        // No score: the meter stays empty and the form's submit button off; nothing else to do.
      },
    );
    return () => {
      current = false;
    };
  }, [value]);
  return value && scored?.value === value ? scored.strength : null;
}
