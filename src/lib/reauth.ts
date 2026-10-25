// SS-04, AP-06: some steps need the vault password again: sending a vault password to a host where no saved session
// sends it yet (a session, a quick connection, a container host's sudo, typing it into a terminal), typing one with
// no prompt showing, loosening the approval rules, an import that uses passwords already in the vault. The core
// answers such a request with `reauth_required` and the reason; the UI asks for the password and sends the same
// request again with it. Pure, so it is tested with Node's test runner (`npm test`).

export const REAUTH_REQUIRED = "reauth_required";
export const WRONG_VAULT_PASSWORD = "wrong_vault_password";

/** Asks the user for the vault password; `null` when they cancel. `problem` says why the last answer failed. */
export type AskPassword = (reason: string, problem: string | null) => Promise<string | null>;

/** The user closed the vault password dialog, so nothing was done. */
export class ReauthCancelled extends Error {
  constructor() {
    super("Not done: the vault password was not entered.");
    this.name = "ReauthCancelled";
  }
}

export function isReauthCancelled(err: unknown): boolean {
  return err instanceof ReauthCancelled;
}

function codeOf(err: unknown): string | undefined {
  return err && typeof err === "object" && "code" in err ? String((err as { code: unknown }).code) : undefined;
}

function messageOf(err: unknown): string {
  if (typeof err === "string") return err;
  if (err && typeof err === "object" && "message" in err) return String((err as { message: unknown }).message);
  return "The vault password is needed for this.";
}

/** "this would send…": the core's reason, with a capital and without "Enter the vault password to go ahead". */
export function reauthReason(message: string): string {
  const text = message.replace(/\.?\s*Enter the vault password to go ahead\.?$/i, "").trim();
  if (!text) return "This needs the vault password.";
  const sentence = text.charAt(0).toUpperCase() + text.slice(1);
  return /[.!?]$/.test(sentence) ? sentence : `${sentence}.`;
}

/**
 * Runs `call` without the vault password; when the core asks for it, asks the user and runs `call` again with
 * it, as often as the password is wrong. Throws {@link ReauthCancelled} when the user cancels, and any other error
 * as it comes.
 */
export async function withReauth<T>(call: (vaultPassword?: string) => Promise<T>, ask: AskPassword): Promise<T> {
  try {
    return await call(undefined);
  } catch (err) {
    if (codeOf(err) !== REAUTH_REQUIRED) throw err;
    let reason = reauthReason(messageOf(err));
    let problem: string | null = null;
    for (;;) {
      const password = await ask(reason, problem);
      if (password === null) throw new ReauthCancelled();
      try {
        return await call(password);
      } catch (again) {
        const code = codeOf(again);
        if (code === WRONG_VAULT_PASSWORD) {
          problem = "That is not the vault password.";
        } else if (code === REAUTH_REQUIRED) {
          reason = reauthReason(messageOf(again));
          problem = null;
        } else {
          throw again;
        }
      }
    }
  }
}

/** SS-04: how often the window tells the core the user is active, so the vault's idle lock starts again. */
export const ACTIVITY_PING_MS = 20_000;

/** Whether input at `now` should tell the core, given the last time it did. */
export function shouldPingActivity(last: number | null, now: number): boolean {
  return last === null || now - last >= ACTIVITY_PING_MS;
}
