"use strict";
// Everything is built with createElement and textContent, so nothing from the server can inject markup.
(async () => {
  const root = document.getElementById("app");
  const r = await fetch("/api/health", { credentials: "same-origin" });
  root.replaceChildren();
  const h = document.createElement("h1");
  h.textContent = "mcpgate admin";
  const p = document.createElement("p");
  p.textContent = r.ok ? "Connected." : "The admin service is not reachable.";
  root.append(h, p);
})();
