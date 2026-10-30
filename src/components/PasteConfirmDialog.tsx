// QL-05: asks before a paste that holds a line break goes into a terminal (TerminalSettings.confirmMultilinePaste):
// how many lines, the first few, whether the shell holds pasted text (bracketed paste), and with MultiExec on how many
// terminals it goes to. Cancel has the focus, so a key pressed by mistake pastes nothing. FD-03 masks the preview like
// any other text on the page (the dialog is not inside a terminal).

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { plural } from "@/lib/format";
import type { PastePreview } from "@/lib/paste";

interface Props {
  preview: PastePreview;
  /** The shell asked for bracketed paste, so it holds pasted text until Enter. */
  bracketed: boolean;
  /** SS-10: the terminals MultiExec sends it to; null when MultiExec is not on for this terminal. */
  multiExecTerminals: number | null;
  onAnswer: (paste: boolean) => void;
}

export function PasteConfirmDialog({ preview, bracketed, multiExecTerminals, onAnswer }: Props) {
  const { lines, shown, more, endsWithBreak } = preview;
  return (
    <AlertDialog open onOpenChange={(open) => !open && onAnswer(false)}>
      <AlertDialogContent className="data-[size=default]:sm:max-w-lg">
        <AlertDialogHeader>
          <AlertDialogTitle>Paste {plural(lines, "line")}?</AlertDialogTitle>
          <AlertDialogDescription>
            {multiExecTerminals !== null && (
              <>Type in all tabs is on: this goes to {plural(multiExecTerminals, "terminal")}. </>
            )}
            {bracketed
              ? "The shell asked for bracketed paste, so it should wait for Enter before it runs anything."
              : "The shell did not ask for bracketed paste, so each line break runs the line before it."}
            {endsWithBreak && " The text ends with a line break, which presses Enter."}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <pre className="max-h-48 overflow-auto rounded-md bg-muted p-2 font-mono text-xs whitespace-pre">
          {shown.join("\n")}
        </pre>
        {more > 0 && <p className="-mt-2 text-xs text-muted-foreground">…and {plural(more, "more line")}.</p>}
        <p className="text-xs text-muted-foreground">Settings, Terminal can turn this question off.</p>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={() => onAnswer(true)}>Paste</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
