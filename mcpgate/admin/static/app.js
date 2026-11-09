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

// Ask for the admin passphrase again (dangerous actions). Resolves true when the server accepted it.
function stepUp(reason) {
  return new Promise((resolve) => {
    const dlg = el("dialog", { class: "card", "aria-labelledby": "su-title" });
    const msg = el("p", { class: "msg", role: "alert" });
    const f = el("form", { method: "dialog" }, el("h2", { id: "su-title" }, "Confirm it is you"), el("p", { class: "muted" }, reason),
      field("Admin passphrase", "passphrase"), el("div", { class: "row" }, el("button", { type: "submit" }, "Confirm"), el("button", { type: "button", class: "plain", id: "su-cancel" }, "Cancel")), msg);
    dlg.append(f);
    document.body.append(dlg);
    let done = false;
    const finish = (v) => { if (!done) { done = true; dlg.close(); dlg.remove(); resolve(v); } };
    f.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const r = await api("/api/stepup", "POST", { passphrase: new FormData(f).get("passphrase") });
      if (r.ok) finish(true); else { msg.textContent = r.body.error || "That did not work."; f.querySelector("input").value = ""; }
    });
    f.querySelector("#su-cancel").addEventListener("click", () => finish(false));
    dlg.addEventListener("cancel", () => finish(false));
    dlg.showModal();
    f.querySelector("input").focus();
  });
}

// Run an action; if the server asks for a fresh passphrase, ask once and retry.
async function act(path, data = {}) {
  let r = await api(path, "POST", data);
  if (r.status === 403 && r.body.stepup && (await stepUp(r.body.error))) r = await api(path, "POST", data);
  return r;
}

const STATE_LABEL = { connected: "Connected", idle: "Idle (starts when used)", error: "Error", disabled: "Disabled" };

const notes = {};   // the last message per backend, kept across refreshes

function backendCard(b, reload) {
  const last = notes[b.name] || { t: "", bad: false };
  const note = el("p", { class: last.bad ? "msg" : "note", role: "status" }, last.t);
  const say = (t, bad = false) => { notes[b.name] = { t, bad }; note.textContent = t; note.className = bad ? "msg" : "note"; };
  const btn = (label, fn, cls = "plain") => {
    const x = el("button", { type: "button", class: cls }, label);
    x.addEventListener("click", async () => { x.disabled = true; try { await fn(); } finally { x.disabled = false; } });
    return x;
  };
  const buttons = [];
  if (!b.readonly) {
    buttons.push(btn(b.enabled ? "Disable" : "Enable", async () => {
      const r = await act(`/api/backends/${b.name}/${b.enabled ? "disable" : "enable"}`);
      if (r.ok) { say(""); reload(); } else say(r.body.error || "Failed.", true);
    }));
  }
  buttons.push(btn("Test connection", async () => {
    say("Testing…");
    const r = await act(`/api/backends/${b.name}/test`);
    if (!r.ok) return say(r.body.error || "Failed.", true);
    say(r.body.ok ? `Works: ${r.body.tools} tools (${r.body.visible} visible to the model).` : `Failed: ${r.body.error}`, !r.body.ok);
    reload();
  }));
  if (b.enabled) buttons.push(btn("Restart", async () => { say("Restarting…"); const r = await act(`/api/backends/${b.name}/restart`); if (r.ok) { say(""); reload(); } else say(r.body.error || "Failed.", true); }));
  if (!b.readonly) {
    buttons.push(btn("Remove", async () => {
      const imp = await api(`/api/backends/${b.name}/impact`);
      let text = `Remove "${b.name}"?`;
      if (imp.body.has_policy) text += "\nIts saved tool rules will be deleted.";
      const names = imp.body.secrets_only_used_here || [];
      if (names.length) text += `\nSecrets only it uses: ${names.join(", ")}. Delete them too? (OK = delete them, Cancel = keep them)`;
      if (!window.confirm(`${text}\n\nContinue?`)) return;
      let deleteSecrets = false;
      if (names.length) deleteSecrets = window.confirm(`Also delete the secret(s) ${names.join(", ")}?`);
      const r = await act(`/api/backends/${b.name}/remove`, { confirm: true, delete_secrets: deleteSecrets });
      if (r.ok) { delete notes[b.name]; reload(); } else say(r.body.error || "Failed.", true);
    }, "danger"));
  }
  const meta = [b.transport, b.source, b.target].filter(Boolean).join(" · ");
  const tools = b.tools_visible === null ? "tools: not loaded yet" : `tools: ${b.tools_visible} visible${b.tools_hidden ? `, ${b.tools_hidden} hidden` : ""}`;
  const secrets = b.secrets.length ? "secrets: " + b.secrets.map((x) => `${x.name} (${x.set ? "set" : "NOT set"})`).join(", ") : "";
  return el("article", { class: "card backend", "data-name": b.name },
    el("h3", {}, b.name, " ", el("span", { class: "pill " + b.state }, STATE_LABEL[b.state])),
    b.description ? el("p", {}, b.description) : "",
    el("p", { class: "muted" }, meta), el("p", { class: "muted" }, tools + (secrets ? " · " + secrets : "")),
    b.path ? el("p", { class: "muted" }, "File: " + b.path + " (drop-in, managed as a file)") : "",
    b.error ? el("p", { class: "msg" }, b.error) : "",
    el("div", { class: "row" }, ...buttons), note);
}

async function backendsSection() {
  const box = el("section", { "aria-labelledby": "bk" }, el("h2", { id: "bk" }, "Backends"));
  async function load() {
    const r = await api("/api/backends");
    if (!r.ok) { box.replaceChildren(el("h2", { id: "bk" }, "Backends"), el("p", { class: "msg" }, "Could not load backends.")); return; }
    const kids = [el("h2", { id: "bk" }, "Backends")];
    if (r.body.config_error) kids.push(el("p", { class: "msg", role: "alert" }, "The config file has an error, so the last good settings are still running: " + r.body.config_error));
    if (!r.body.backends.length) kids.push(el("p", { class: "muted" }, "No backends yet."));
    for (const b of r.body.backends) kids.push(backendCard(b, load));
    box.replaceChildren(...kids);
  }
  await load();
  return box;
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
    page(el("p", {}, "You are signed in."), out, await backendsSection(),
      form("Change passphrase", "", [field("Current passphrase", "current"), field("New passphrase (12+ characters)", "new", "password", { minlength: "12" })], "Change",
        async (v) => after(await api("/api/passphrase", "POST", { current: v.current, new: v.new }))));
  }
}

render().catch(() => page(el("p", {}, "The admin service is not reachable.")));
