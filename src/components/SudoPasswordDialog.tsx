// SS-14: browsing as root, sudo asks for a password and the session saves none (a key or agent login): one from the
// vault, given to sudo, never typed or shown. BX-07's choice; the core asks for the vault password first when it
// would go somewhere new (rule 7).

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
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, type SecretMeta } from "@/lib/api";

export function SudoPasswordDialog({
  terminal,
  onPick,
  onCancel,
}: {
  /** How the terminal is named. */
  terminal: string;
  onPick: (secretId: string) => void;
  onCancel: () => void;
}) {
  const [secrets, setSecrets] = useState<SecretMeta[] | null>(null);
  const [picked, setPicked] = useState("");
  useEffect(() => {
    let stale = false;
    api.secrets().then(
      (all) => {
        if (!stale) setSecrets(all.filter((s) => s.kind === "password"));
      },
      () => {
        if (!stale) setSecrets([]);
      },
    );
    return () => {
      stale = true;
    };
  }, []);
  const none = secrets !== null && secrets.length === 0;
  const why = none ? "Add sudo's password on the Vault page first" : !picked ? "Choose a password first" : null;
  return (
    <Dialog open onOpenChange={(open) => !open && onCancel()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Choose sudo&apos;s password</DialogTitle>
          <DialogDescription>
            sudo on <span data-mask="host">{terminal}</span> asks for a password to browse as root.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-1.5">
          <Label htmlFor="root-sudo-password">Password from the vault</Label>
          <Select value={picked} onValueChange={setPicked} disabled={!secrets || none}>
            <SelectTrigger id="root-sudo-password" className="w-full">
              <SelectValue placeholder={none ? "No passwords in the vault" : "Choose a password"} />
            </SelectTrigger>
            <SelectContent>
              {(secrets ?? []).map((s) => (
                <SelectItem key={s.id} value={s.id}>
                  {s.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">Given to sudo, never typed or shown.</p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <WhyDisabled reason={why}>
            <Button disabled={why !== null} onClick={() => onPick(picked)}>
              Browse as root
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
