// AP-05, UX-21 (0.9.0): Reports ▸ Audit log (CSV)… in Activity's "⋯" and the palette: the shell's save dialog, then the
// core writes the CSV (secrets redacted, audited). One function, so both say the same.

import { toast } from "sonner";
import { api, errorMessage } from "@/lib/api";
import { plural } from "@/lib/format";

/** True when a file was written; false when the dialog was cancelled or the export failed (a toast says why). */
export async function exportAuditLog(): Promise<boolean> {
  try {
    const report = await api.exportAudit();
    if (!report) return false;
    const redacted = report.redacted
      ? ` ${plural(report.redacted, "row")} had something that looked like a secret, replaced by [redacted].`
      : "";
    toast.success(`Exported ${plural(report.entries, "entry")}`, {
      description: `${report.path}.${redacted}`,
      duration: 8000,
    });
    return true;
  } catch (err) {
    toast.error(`Could not export the audit log: ${errorMessage(err)}`);
    return false;
  }
}
