import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { primeMasker } from "@/components/Presentation";
import { api } from "@/lib/api";
import { setPresentationView } from "@/lib/presentation-state";
import "@xterm/xterm/css/xterm.css";
import "./styles.css";

// FD-03: whether the app is presenting is known before anything shows, and what to mask is learnt first, so the first
// paint is already masked. When the setting can't be read, the app presents (fail closed).
async function start() {
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
      <App />
    </React.StrictMode>,
  );
}

void start();
