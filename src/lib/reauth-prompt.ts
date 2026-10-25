// SS-04, AP-06: the one vault password dialog (ReauthDialog, rendered once by App) and the helper call sites use:
//   await withVaultPassword((password) => api.updateSession(id, input, password))

import { withReauth, type AskPassword } from "./reauth";

export interface ReauthPrompt {
  reason: string;
  problem: string | null;
  answer: (password: string | null) => void;
}

let show: ((prompt: ReauthPrompt) => void) | null = null;

/** ReauthDialog registers itself here; `null` when it unmounts. */
export function setReauthHost(host: ((prompt: ReauthPrompt) => void) | null) {
  show = host;
}

export const askVaultPassword: AskPassword = (reason, problem) =>
  new Promise((resolve) => {
    if (!show) {
      resolve(null);
      return;
    }
    show({ reason, problem, answer: resolve });
  });

/** Runs `call`, asking for the vault password when the core needs it (code `reauth_required`). */
export function withVaultPassword<T>(call: (vaultPassword?: string) => Promise<T>): Promise<T> {
  return withReauth(call, askVaultPassword);
}
