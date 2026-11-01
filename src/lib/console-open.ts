// SS-12: opening an RDP or VNC session's window, from the Terminal page or the Sessions page: the core starts mstsc
// or the VNC viewer (each asks for the password); the toast says what opened. While presenting, a remote desktop's
// window isn't masked (presentation mode hides what Remotely shows, not other programs' windows), so it says so.

import { toast } from "sonner";
import { api, errorMessage, type SessionKind } from "./api.ts";

/** The notice while presenting, before a remote desktop opens (a window or a tunnel tab). */
export function warnUnmasked(kind: SessionKind, presenting: boolean) {
  if (kind.protocol === "rdp" && presenting) {
    toast.warning("The remote desktop window isn't masked", {
      description: "Presentation mode hides what Remotely shows, not other programs' windows.",
    });
  }
}

/** Opens the window of a session with no jump host. */
export function openSessionWindow(session: { id: string; name: string; kind: SessionKind }, presenting: boolean) {
  warnUnmasked(session.kind, presenting);
  api.consoleOpenWindow(session.id).then(
    (opened) =>
      toast.success(
        opened.protocol === "rdp"
          ? `Opened the remote desktop of '${session.name}'`
          : `Opened '${session.name}' in the VNC viewer`,
        {
          description:
            opened.protocol === "rdp"
              ? "Remote Desktop Connection asks for the password."
              : "The viewer asks for the password. Many VNC servers don't encrypt.",
        },
      ),
    (err) => toast.error(errorMessage(err)),
  );
}
