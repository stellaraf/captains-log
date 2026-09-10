import { createRoot } from "react-dom/client";
import { initializeAuth } from "./api";
import { App } from "./App";
import "@fontsource-variable/open-sans";
import "@fontsource-variable/fira-code";
import "./style.css";
const root = createRoot(document.getElementById("root")!);
root.render(
  <div className="boot">
    <img
      className="boot-logo"
      src="/brand/stellar-icon-gradient.png"
      alt="Stellar"
    />
    <h1>Captain’s Log</h1>
    <p>Connecting to your appliance…</p>
  </div>,
);
initializeAuth()
  .then((config) => root.render(<App config={config} />))
  .catch(() =>
    root.render(
      <div className="boot">
        <img
          className="boot-logo"
          src="/brand/stellar-icon-gradient.png"
          alt="Stellar"
        />
        <h1>Unable to connect</h1>
        <p>
          The API or identity provider could not be reached. Check appliance
          configuration and retry.
        </p>
        <button onClick={() => location.reload()}>Retry connection</button>
        <small>Authentication is required to access Captain’s Log.</small>
      </div>,
    ),
  );
