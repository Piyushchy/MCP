"use strict";
// Everything is built with createElement and textContent, so nothing from the server can inject markup.
const root = document.getElementById("app");
let csrf = "";

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
  n.append(...kids);
  return n;
}

async function api(path, method = "GET", data) {
  const headers = {};
  if (data !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && csrf) headers["x-csrf-token"] = csrf;
  const r = await fetch(path, { method, headers, credentials: "same-origin", body: data === undefined ? undefined : JSON.stringify(data) });
  let body = {};
  try { body = await r.json(); } catch (e) { /* not JSON */ }
  return { ok: r.ok, status: r.status, body };
}

function field(label, name, type = "password", extra = {}) {
  const id = "f-" + name;
  return el("div", { class: "field" }, el("label", { for: id }, label), el("input", { id, name, type, autocomplete: type === "password" ? "off" : "on", required: "", ...extra }));
}

function form(title, intro, fields, button, onSubmit) {
  const msg = el("p", { class: "msg", role: "alert" });
  const f = el("form", { class: "card" }, el("h2", {}, title), intro ? el("p", { class: "muted" }, intro) : "", ...fields, el("button", { type: "submit" }, button), msg);
  f.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    msg.textContent = "";
    const values = Object.fromEntries(new FormData(f));
    const err = await onSubmit(values);
    if (err) msg.textContent = err;
    f.querySelectorAll("input[type=password]").forEach((i) => { i.value = ""; });
  });
  return f;
}

function page(...kids) {
  root.replaceChildren(el("h1", {}, "mcpgate admin"), ...kids);
}

async function after(r) {
  if (!r.ok) return r.body.error || "Something went wrong.";
  await render();
  return "";
}

async function render() {
  const { body: s } = await api("/api/session");
  csrf = s.csrf || "";
  if (s.state === "setup") {
    page(form("Set up", "Enter the setup code printed in the terminal where mcpgate runs (or run: mcpgate ui-code), then choose an admin passphrase.",
      [field("Setup code", "code", "text", { autocomplete: "off", spellcheck: "false" }), field("New passphrase (12+ characters)", "passphrase", "password", { minlength: "12" }), field("Repeat passphrase", "again")],
      "Create admin passphrase", async (v) => (v.passphrase !== v.again ? "The two passphrases do not match." : after(await api("/api/setup", "POST", { code: v.code, passphrase: v.passphrase })))));
  } else if (s.state === "login") {
    page(form("Sign in", "", [field("Admin passphrase", "passphrase")], "Sign in", async (v) => after(await api("/api/login", "POST", { passphrase: v.passphrase }))));
  } else {
    const out = el("button", { type: "button" }, "Sign out");
    out.addEventListener("click", async () => { await api("/api/logout", "POST", {}); csrf = ""; await render(); });
    page(el("p", {}, "You are signed in."), out,
      form("Change passphrase", "", [field("Current passphrase", "current"), field("New passphrase (12+ characters)", "new", "password", { minlength: "12" })], "Change",
        async (v) => after(await api("/api/passphrase", "POST", { current: v.current, new: v.new }))));
  }
}

render().catch(() => page(el("p", {}, "The admin service is not reachable.")));
