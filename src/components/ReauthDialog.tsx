// SS-04, AP-06: the vault password, asked again for a step that needs it (see lib/reauth.ts): a vault password sent
// to a host where no saved session sends it yet, one typed with no prompt showing, looser approval rules, an import
// that uses passwords already in the vault. App renders it once; call sites use `withVaultPassword`.

import { useEffect, useState } from "react";
import { ShieldAlertIcon } from "lucide-react";
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
import { setReauthHost, type ReauthPrompt } from "@/lib/reauth-prompt";

export function ReauthDialog() {
  const [prompt, setPrompt] = useState<ReauthPrompt | null>(null);
  const [password, setPassword] = useState("");

  useEffect(() => {
    setReauthHost((next) => {
      setPassword("");
      setPrompt((open) => {
        // A second request while one is open: the first one is cancelled.
        open?.answer(null);
        return next;
      });
    });
    return () => setReauthHost(null);
  }, []);

  function answer(value: string | null) {
    prompt?.answer(value);
    setPrompt(null);
    setPassword("");
  }

  return (
    <Dialog open={prompt !== null} onOpenChange={(open) => !open && answer(null)}>
      <DialogContent className="sm:max-w-md">
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (password) answer(password);
          }}
        >
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlertIcon className="size-5 text-amber-600 dark:text-amber-400" aria-hidden />
              Enter the vault password
            </DialogTitle>
            <DialogDescription>{prompt?.reason}</DialogDescription>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            The vault password confirms it is you, however the vault was unlocked. It also covers the next 5 minutes,
            and for a saved session the answer counts from then on.
          </p>
          <div className="grid gap-2">
            <Label htmlFor="reauth-password">Vault password</Label>
            <Input
              id="reauth-password"
              type="password"
              autoFocus
              autoComplete="off"
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
              aria-invalid={prompt?.problem ? true : undefined}
            />
            {prompt?.problem && (
              <p className="text-sm text-destructive" role="alert">
                {prompt.problem}
              </p>
            )}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => answer(null)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!password}>
              Continue
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
