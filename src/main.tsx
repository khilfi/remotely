import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { primeMasker } from "@/components/Presentation";
import { api } from "@/lib/api";
import { applySavedDensity } from "@/lib/density";
import { setPresentationView } from "@/lib/presentation-state";
import { isBrowserKey } from "@/lib/ui-errors";
import "@xterm/xterm/css/xterm.css";
import "./styles.css";

// QL-15: a release build has no reload or developer-tool keys (WebView2's are off on the Rust side too). A reload
// would leave terminals, tunnels and approvals in the core with nothing showing them.
if (import.meta.env.PROD) {
  window.addEventListener(
    "keydown",
    (e) => {
      if (isBrowserKey(e)) e.preventDefault();
    },
    { capture: true },
  );
}

// FD-03: whether the app is presenting is known before anything shows, and what to mask is learnt first, so the first
// paint is already masked. When the setting can't be read, the app presents (fail closed).
async function start() {
  // QL-24: the saved density applies before the first paint.
  applySavedDensity();
  let presentation = { enabled: true, readOnly: true };
  try {
    presentation = await api.presentation();
  } catch (err) {
    console.warn("presentation mode unknown; presenting", err);
  }
  setPresentationView({ presenting: presentation.enabled, readOnly: presentation.readOnly });
  if (presentation.enabled) await primeMasker();
  else void primeMasker();

  ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <ErrorBoundary name="Remotely" root>
        <App />
      </ErrorBoundary>
    </React.StrictMode>,
  );
}

void start();
