// QL-15: a page that throws while drawing shows what broke and a way back, instead of a blank window. One around
// each page, so the others keep working, and one around the whole app.
//
// "Reload this page" draws the page again from scratch. The page that crashed has unmounted by then, which closes
// what it had open (the Terminal page closes its terminals in the core). "Reload Remotely" (the whole app) reloads the
// window; the core then closes the terminals, tunnels and approvals the old page had (see `page_loaded` in lib.rs).
//
// The error text goes through presentation masking (FD-03) before it shows, and to the app's log shortened and with
// secrets redacted (`ui_error`).

import { Component, Fragment, type ErrorInfo, type ReactNode } from "react";
import { OctagonAlertIcon, RotateCcwIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { maskedOutside } from "@/lib/presentation-state";
import { describeError } from "@/lib/ui-errors";

interface Props {
  /** Names the page in the message and the log, e.g. "Terminal". */
  name: string;
  /** The whole app: reloading means reloading the window. */
  root?: boolean;
  children: ReactNode;
}

interface State {
  error: string | null;
  /** Bumped by "Reload this page", so the page mounts afresh. */
  attempt: number;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, attempt: 0 };

  static getDerivedStateFromError(error: unknown): Partial<State> {
    return { error: describeError(error) };
  }

  componentDidCatch(error: unknown, info: ErrorInfo) {
    console.error(`${this.props.name} crashed`, error);
    api.uiError(this.props.name, describeError(error), info.componentStack ?? null).catch(() => undefined);
  }

  private reload = () => {
    if (this.props.root) {
      window.location.reload();
      return;
    }
    this.setState((s) => ({ error: null, attempt: s.attempt + 1 }));
  };

  render() {
    const { error, attempt } = this.state;
    if (error === null) return <Fragment key={attempt}>{this.props.children}</Fragment>;
    const { name, root } = this.props;
    return (
      <div className={root ? "grid h-svh place-items-center p-6" : "p-6"}>
        <Alert variant="destructive" className="max-w-2xl">
          <OctagonAlertIcon />
          <AlertTitle>{root ? "Remotely ran into a problem" : `The ${name} page ran into a problem`}</AlertTitle>
          <AlertDescription className="grid gap-3">
            <p className="break-words">{maskedOutside(error)}</p>
            <p>
              {root
                ? "Reloading closes the terminals and tunnels that were open, and cancels approvals still waiting. Jobs that are running go on."
                : "The other pages still work. Reloading this one closes what it had open."}{" "}
              The app's log has the details (Settings, About).
            </p>
            <div>
              <Button size="sm" variant="outline" onClick={this.reload}>
                <RotateCcwIcon />
                {root ? "Reload Remotely" : "Reload this page"}
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      </div>
    );
  }
}
