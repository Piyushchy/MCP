"use strict";
// Everything is built with createElement and textContent, so nothing from the server can inject markup.
const root = document.getElementById("app");
let csrf = "";

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) n.setAttribute(k, v);
  n.append(...kids);
  return n;
}

async function api(path, method = "GET", data) {
  const headers = {};
  if (data !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && csrf) headers["x-csrf-token"] = csrf;
  let r;
  try {
    r = await fetch(path, { method, headers, credentials: "same-origin", body: data === undefined ? undefined : JSON.stringify(data) });
  } catch (e) {
    return { ok: false, status: 0, body: { error: "Cannot reach mcpgate. Check that it is running (mcpgate service status), then try again." } };
  }
  let body = {};
  try { body = await r.json(); } catch (e) { /* not JSON */ }
  if (r.status === 401 && !QUIET_401.has(path) && !expiring) {
    expiring = true;
    csrf = "";
    render().finally(() => { expiring = false; });
    return { ok: false, status: 401, body: { error: "Your session ended. Sign in again." } };
  }
  return { ok: r.ok, status: r.status, body };
}
const QUIET_401 = new Set(["/api/login", "/api/setup", "/api/session", "/api/passphrase"]);
let expiring = false;

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

let viewTitle = "mcpgate admin";

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
const openPolicy = {};   // which permission panels are open, kept across refreshes
const openEdit = {};     // which edit panels are open

const STATE_NAMES = { allow: "Allowed", confirm: "Needs my approval", block: "Blocked" };
const DELETES = /(^|_)(delete|remove|drop|destroy|wipe|purge|erase|clear|truncate)(_|$)/i;

// Per-tool permissions. Everything from the backend (names, descriptions) is shown with textContent only.
function policyPanel(b, reloadList) {
  const box = el("div", { class: "policy" });
  let saved = null;            // payload for the saved rules
  let view = null;             // payload with the pending changes applied (server-computed)
  let pending = {};            // tool -> wanted state
  let removed = { allow: [], deny: [], confirm: [] };
  const msg = el("p", { class: "msg", role: "alert" });

  const dirty = () => Object.keys(pending).length > 0 || removed.allow.length + removed.deny.length + removed.confirm.length > 0;

  async function refresh() {
    if (!dirty()) { view = saved; return draw(); }
    const r = await api(`/api/backends/${b.name}/policy/preview`, "POST", { changes: pending, remove: removed });
    if (!r.ok) { msg.textContent = r.body.error || "That did not work."; return; }
    msg.textContent = "";
    view = r.body;
    draw();
  }

  function setState(tool, st) {
    const base = saved.tools.find((t) => t.name === tool).state;
    if (st === base) delete pending[tool]; else pending[tool] = st;
    refresh();
  }

  function chips(list, title, key, editable) {
    if (!list.length) return null;
    const row = el("div", { class: "chips" }, el("span", { class: "label" }, title + ": "));
    for (const pat of list) {
      const gone = removed[key].includes(pat);
      const chip = el("span", { class: "chip" + (gone ? " gone" : "") }, el("code", {}, pat));
      if (editable) {
        const x = el("button", { type: "button", class: "plain tiny", "aria-label": (gone ? "Keep " : "Remove ") + title + " pattern " + pat }, gone ? "undo" : "×");
        x.addEventListener("click", () => { removed[key] = gone ? removed[key].filter((q) => q !== pat) : [...removed[key], pat]; refresh(); });
        chip.append(x);
      }
      row.append(chip);
    }
    return row;
  }

  function draw() {
    const kids = [];
    const rules = saved.rules;
    const edit = saved.editable;
    if (!saved.editable) kids.push(el("p", { class: "msg", role: "status" }, saved.why));
    if (!saved.loaded && b.enabled) {
      const go = el("button", { type: "button" }, "Load tools");
      go.addEventListener("click", async () => { go.disabled = true; const r = await act(`/api/backends/${b.name}/policy/load`); saved = r.body; view = saved; pending = {}; removed = { allow: [], deny: [], confirm: [] }; draw(); });
      kids.push(go);
    }
    const ruleBox = el("div", { class: "rules" },
      chips(rules.allow.length === 1 && rules.allow[0] === "*" ? [] : rules.allow, "Only allow", "allow", edit) || "",
      chips(rules.deny, "Block", "deny", edit) || "", chips(rules.confirm, "Needs approval", "confirm", edit) || "");
    if (ruleBox.children.length) kids.push(el("p", { class: "muted" }, "Rules written by hand are kept as they are. Remove one only if it gets in the way."), ruleBox);
    if (saved.tools.length) {
      const bulk = el("div", { class: "row" });
      const bulkBtn = (label, fn) => { const x = el("button", { type: "button", class: "plain" }, label); x.addEventListener("click", fn); bulk.append(x); };
      if (edit) {
        bulkBtn("Block everything that deletes", () => { for (const t of view.tools) if ((DELETES.test(t.name) || t.destructive) && t.options.block === null) pending[t.name] = "block"; refresh(); });
        bulkBtn("Approval for everything not read-only", () => { for (const t of view.tools) if (!t.read_only && t.state === "allow" && t.options.confirm === null) pending[t.name] = "confirm"; refresh(); });
        bulkBtn("Allow everything that only reads", () => { for (const t of view.tools) if (t.read_only && t.state !== "allow" && t.options.allow === null) pending[t.name] = "allow"; refresh(); });
      }
      kids.push(bulk);
      const list = el("div", { class: "tools" });
      view.tools.forEach((t, i) => {
        const changed = t.name in pending;
        const radios = ["allow", "confirm", "block"].map((st) => {
          const id = `p-${b.name}-${i}-${st}`;
          const input = el("input", { type: "radio", id, name: `p-${b.name}-${i}`, value: st });
          input.checked = t.state === st;
          input.disabled = !edit || (t.options[st] !== null && t.state !== st);
          if (t.options[st]) input.title = t.options[st];
          input.addEventListener("change", () => setState(t.name, st));
          return el("label", { class: "radio", for: id, title: t.options[st] || "" }, input, " " + STATE_NAMES[st]);
        });
        list.append(el("div", { class: "tool" + (changed ? " changed" : "") },
          el("div", {}, el("strong", {}, t.name), " ", t.read_only ? el("span", { class: "pill" }, "read-only") : "", t.destructive ? el("span", { class: "pill error" }, "destructive") : "", changed ? el("span", { class: "pill" }, "changed") : ""),
          t.description ? el("div", { class: "muted small" }, t.description) : "", t.reason ? el("div", { class: "muted small" }, t.reason) : "",
          el("div", { class: "radios", role: "radiogroup", "aria-label": "Permission for " + t.name }, ...radios)));
      });
      kids.push(list);
      const names = (xs) => (xs.length ? xs.join(", ") : "none");
      kids.push(el("div", { class: "card summary" }, el("strong", {}, `The model will see ${view.model_sees.length} of ${view.tools.length} tools`),
        el("p", { class: "muted small" }, "Needs your approval: " + names(view.needs_approval)), el("p", { class: "muted small" }, "Hidden from the model: " + names(view.hidden))));
      if (edit) {
        const save = el("button", { type: "button" }, "Save permissions");
        save.disabled = !dirty();
        save.addEventListener("click", async () => {
          save.disabled = true;
          const r = await act(`/api/backends/${b.name}/policy/save`, { changes: pending, remove: removed });
          if (!r.ok) { msg.textContent = r.body.error || "Failed."; save.disabled = false; return; }
          saved = view = r.body; pending = {}; removed = { allow: [], deny: [], confirm: [] }; msg.textContent = ""; draw(); reloadList();
        });
        const discard = el("button", { type: "button", class: "plain" }, "Discard changes");
        discard.disabled = !dirty();
        discard.addEventListener("click", () => { pending = {}; removed = { allow: [], deny: [], confirm: [] }; msg.textContent = ""; refresh(); });
        kids.push(el("div", { class: "row" }, save, discard));
      }
    }
    kids.push(msg);
    box.replaceChildren(...kids);
  }

  (async () => { const r = await api(`/api/backends/${b.name}/policy`); saved = view = r.body; draw(); })();
  return box;
}

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
    say(r.body.ok ? `Works: ${r.body.tools} tools (${r.body.visible} visible to the model).` : `Failed: ${r.body.error}${r.body.hint ? " " + r.body.hint : ""}`, !r.body.ok);
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
  if (b.auth === "oauth") buttons.unshift(...signInButtons(b, btn, say, reload));
  const editBox = el("div", {});
  if (!b.readonly) {
    buttons.unshift(btn("Edit", async () => {
      if (editBox.firstChild) { editBox.replaceChildren(); delete openEdit[b.name]; return; }
      openEdit[b.name] = true;
      editBox.replaceChildren(editPanel(b, reload));
    }));
    if (openEdit[b.name]) editBox.replaceChildren(editPanel(b, reload));
  }
  const panelBox = el("div", {});
  const perm = btn("Permissions", async () => {
    if (panelBox.firstChild) { panelBox.replaceChildren(); delete openPolicy[b.name]; return; }
    openPolicy[b.name] = true;
    panelBox.replaceChildren(policyPanel(b, reload));
  });
  buttons.push(perm);
  if (openPolicy[b.name]) panelBox.replaceChildren(policyPanel(b, reload));
  const meta = [b.transport, b.source, b.target].filter(Boolean).join(" · ");
  const tools = b.tools_visible === null ? "tools: not loaded yet" : `tools: ${b.tools_visible} visible${b.tools_hidden ? `, ${b.tools_hidden} hidden` : ""}`;
  const missing = b.secrets.filter((x) => !x.set).map((x) => x.name);
  const secrets = missing.length ? "missing credential: " + missing.join(", ") + ". Use Edit to add it." : "";
  return el("article", { class: "card backend", "data-name": b.name },
    el("h3", {}, b.name, " ", el("span", { class: "pill " + b.state }, STATE_LABEL[b.state])),
    b.description ? el("p", {}, b.description) : "",
    el("p", { class: "muted" }, meta), el("p", { class: "muted" }, tools + (secrets ? " · " + secrets : "")),
    b.path ? el("p", { class: "muted" }, "File: " + b.path + " (drop-in, managed as a file)") : "",
    b.auth === "oauth" ? el("p", { class: "muted" }, "Sign-in: " + (b.signed_in ? "signed in" : b.signing_in ? "waiting for you to finish in the other tab" : "not signed in")) : "",
    b.error ? el("p", { class: "msg" }, b.error, b.error_hint ? el("br") : "", b.error_hint ? el("span", { class: "muted" }, b.error_hint) : "") : "",
    el("div", { class: "row" }, ...buttons), note, editBox, panelBox);
}


// ---- signing in to a backend with an account --------------------------------------------------------------
// Some servers (Notion, Linear, Colab ...) have no token to paste: they send you to their own page to log in. mcpgate
// starts that, opens the page, then polls until the sign-in has finished. The login token never reaches this page.
function signInButtons(b, btn, say, reload) {
  const out = [];
  out.push(btn(b.signed_in ? "Sign in again" : "Sign in", async () => {
    say("Starting sign-in…");
    const r = await act(`/api/backends/${b.name}/signin`);
    if (!r.ok) return say(r.body.error || "Could not start sign-in.", true);
    if (r.body.already) { say("Already signed in."); return reload(); }
    const link = el("a", { href: r.body.url, target: "_blank", rel: "noopener noreferrer" }, "Open the sign-in page");
    const note = document.querySelector(`article[data-name="${b.name}"] p[role=status]`);
    if (note) { note.className = "note"; note.replaceChildren("Finish signing in in the new tab. If nothing opened, ", link, ". It returns to ", el("code", {}, r.body.redirect_uri), " on this computer, so over SSH forward that same port."); }
    window.open(r.body.url, "_blank", "noopener,noreferrer");
    for (let i = 0; i < 150; i++) {
      await new Promise((ok) => setTimeout(ok, 2000));
      const l = await api("/api/backends");
      const me = l.ok && (l.body.backends || []).find((x) => x.name === b.name);
      if (me && me.signed_in) { say("Signed in."); return reload(); }
      if (me && !me.signing_in && i > 2) break;
    }
    say("Sign-in did not finish. Press Sign in to try again.", true);
  }));
  if (b.signed_in) out.push(btn("Sign out", async () => {
    if (!window.confirm(`Sign out of "${b.name}"? mcpgate forgets the stored login.`)) return;
    const r = await act(`/api/backends/${b.name}/signout`);
    if (r.ok) { say(""); reload(); } else say(r.body.error || "Failed.", true);
  }, "danger"));
  return out;
}

// ---- credentials, editing a backend ---------------------------------------------------------------
// A credential is something mcpgate uses to sign in to a backend (a GitHub token, an API key). The page can store or
// replace one, and says whether one is stored, but can never show it again.
function credentialRow(c, label, afterSave, note) {
  const input = el("input", { type: "password", autocomplete: "new-password", spellcheck: "false", id: "cred-" + c.name,
    placeholder: c.set ? "Paste a new value to replace the stored one" : "Paste the value here" });
  const save = el("button", { type: "button" }, c.set ? "Replace" : "Save");
  save.disabled = true;
  input.addEventListener("input", () => { save.disabled = !input.value.trim(); });
  const msg = el("p", { class: "note", role: "status" }, note || "");
  save.addEventListener("click", async () => {
    save.disabled = true;
    const r = await act("/api/secrets/" + encodeURIComponent(c.name), { value: input.value });
    input.value = "";
    if (r.ok) { msg.className = "note"; msg.textContent = r.body.restarted.length ? "Saved. " + r.body.restarted.join(", ") + " restarted with the new value." : "Saved."; afterSave(); }
    else { msg.className = "msg"; msg.textContent = r.body.error || "Could not save. Try again."; save.disabled = false; }
  });
  return el("div", { class: "cred" },
    el("label", { for: "cred-" + c.name }, label || c.name, " ", el("span", { class: "pill " + (c.set ? "connected" : "error") }, c.set ? "Stored" : "Missing")),
    el("div", { class: "inline" }, input, save), msg);
}

let presetLabels = null;
async function labelsForSecrets() {
  if (presetLabels) return presetLabels;
  const r = await api("/api/presets");
  presetLabels = {};
  if (r.ok) for (const p of r.body.presets) for (const f of p.fields) presetLabels[f.secret_name] = f.label;
  return presetLabels;
}

function editRows(title, nameLabel, initial) {
  const list = el("div", { class: "rows" });
  const rows = [];
  function addRow(item) {
    const name = el("input", { type: "text", "aria-label": nameLabel + " name", autocomplete: "off", spellcheck: "false", placeholder: nameLabel, value: item.name || "" });
    const gone = el("button", { type: "button", class: "plain tiny", "aria-label": "Remove this " + nameLabel.toLowerCase() }, "Remove");
    let rec;
    let row;
    if (item.secret) {
      row = el("div", { class: "row3 keep" }, name, el("span", { class: "muted" }, "Stored secret. Replace it under Credentials."), gone);
      rec = { name, ref: item.secret, row };
    } else {
      const value = el("input", { type: "text", "aria-label": nameLabel + " value", autocomplete: "off", spellcheck: "false", placeholder: "value", value: item.value || "" });
      const box = el("input", { type: "checkbox", "aria-label": "store this value as a secret" });
      box.addEventListener("change", () => { value.type = box.checked ? "password" : "text"; });
      row = el("div", { class: "row3" }, name, value, el("label", { class: "check" }, box, " secret"), gone);
      rec = { name, value, box, row };
    }
    gone.addEventListener("click", () => { row.remove(); rows.splice(rows.indexOf(rec), 1); });
    rows.push(rec);
    list.append(row);
  }
  for (const it of initial) addRow(it);
  const more = el("button", { type: "button", class: "plain" }, "Add " + nameLabel.toLowerCase());
  more.addEventListener("click", () => addRow({}));
  return { node: el("div", { class: "field" }, el("p", { class: "label" }, title), list, more),
    get: () => rows.filter((r) => r.name.value.trim()).map((r) => r.ref ? { name: r.name.value.trim(), secret: r.ref } : { name: r.name.value.trim(), value: r.value.value, secret: r.box.checked }) };
}

function editPanel(b, reload) {
  const box = el("div", { class: "edit" }, el("p", { class: "muted" }, "Loading…"));
  (async () => {
    const r = await api(`/api/backends/${b.name}/edit`);
    if (!r.ok) { box.replaceChildren(el("p", { class: "msg", role: "alert" }, r.body.error || "Could not load the settings.")); return; }
    const v = r.body;
    const labels = await labelsForSecrets();
    const parts = [];
    if (v.secrets.length) {
      parts.push(el("div", { class: "block" }, el("h4", {}, "Credentials"),
        el("p", { class: "muted" }, "What mcpgate uses to sign in to this backend. They are stored on this computer and never shown again; paste a new value to replace one."),
        ...v.secrets.map((c) => credentialRow(c, labels[c.name] ? `${labels[c.name]} (${c.name})` : c.name, reload))));
    }
    const msg = el("p", { class: "msg", role: "alert" });
    const done = el("p", { class: "note", role: "status" });
    const f = el("form", { class: "block" }, el("h4", {}, "Settings"));
    const text = (label, name, value, extra = {}) => field(label, name + "-" + b.name, "text", { name, value: value || "", autocomplete: "off", required: null, ...extra });
    f.append(text("Description", "description", v.description));
    let headers = null, env = null, authBox = null;
    if (!v.preset) {
      if (v.runs_program) {
        f.append(text("Command", "command", v.command, { required: "" }));
        const args = el("textarea", { name: "args", id: "f-args-" + b.name, rows: "3", spellcheck: "false", autocomplete: "off" }, v.args.join("\n"));
        f.append(el("div", { class: "field" }, el("label", { for: "f-args-" + b.name }, "Arguments (one per line)"), args));
        f.append(text("Working folder (optional)", "cwd", v.cwd));
        env = editRows("Environment values", "Variable", v.env);
        f.append(env.node);
      } else {
        f.append(text("Address (URL)", "url", v.url, { required: "" }));
        headers = editRows("Request headers (for example Authorization)", "Header", v.headers);
        f.append(headers.node);
        authBox = el("input", { type: "checkbox", id: "f-auth-" + b.name, name: "auth" });
        authBox.checked = v.auth === "oauth";
        f.append(el("div", { class: "field check" }, authBox, el("label", { for: "f-auth-" + b.name }, "This server needs me to sign in with an account (no token)")));
      }
      f.append(text("Start timeout, seconds", "start_timeout", String(v.start_timeout), { inputmode: "numeric" }));
    }
    const save = el("button", { type: "submit" }, "Save changes");
    f.append(el("div", { class: "row" }, save), msg, done);
    f.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      msg.textContent = ""; done.textContent = "";
      const fd = new FormData(f);
      const data = { description: fd.get("description") };
      if (!v.preset) {
        data.start_timeout = Number(fd.get("start_timeout")) || undefined;
        if (v.runs_program) { data.command = fd.get("command"); data.args = String(fd.get("args")).split("\n").map((x) => x.trim()).filter(Boolean); data.cwd = fd.get("cwd"); data.env = env.get(); }
        else { data.url = fd.get("url"); data.headers = headers.get(); data.auth = authBox.checked ? "oauth" : ""; }
      }
      save.disabled = true;
      const res = await act(`/api/backends/${b.name}/edit`, data);
      save.disabled = false;
      if (!res.ok) { msg.textContent = res.body.error || "Could not save. Check the values and try again."; return; }
      done.textContent = "Saved.";
      notes[b.name] = { t: "Saved.", bad: false };
      reload();
    });
    parts.push(f);
    box.replaceChildren(...parts);
  })();
  return box;
}

// ---- the credentials page ---------------------------------------------------------------------------
async function secretsSection() {
  const box = el("section", { "aria-labelledby": "sec" });
  async function load() {
    const r = await api("/api/secrets");
    const kids = [el("h2", { id: "sec", tabindex: "-1" }, "Credentials"),
      el("p", { class: "muted" }, "The tokens and keys mcpgate uses to sign in to your backends, such as a GitHub token. They are stored on this computer in a private file and are never shown again; you can only replace or delete them. (Tokens, on the Tokens page, are the opposite direction: what apps use to reach mcpgate.)")];
    if (!r.ok) { kids.push(el("p", { class: "msg", role: "alert" }, r.body.error || "Could not load the credentials. Reload the page.")); box.replaceChildren(...kids); return; }
    if (!r.body.secrets.length) kids.push(el("p", { class: "muted" }, "Nothing is stored yet. Add a backend that needs a token and it appears here."));
    for (const c of r.body.secrets) {
      const del = el("button", { type: "button", class: "danger" }, "Delete");
      del.addEventListener("click", async () => {
        const used = c.used_by.length ? ` ${c.used_by.join(", ")} will stop working until you store a new one.` : "";
        if (!window.confirm(`Delete ${c.name}?${used}`)) return;
        const d = await act("/api/secrets/" + encodeURIComponent(c.name) + "/delete", { confirm: true });
        if (d.ok) load(); else window.alert(d.body.error || "Could not delete it.");
      });
      kids.push(el("div", { class: "card wide cred-card" },
        credentialRow(c, c.name, load),
        el("p", { class: "muted small" }, (c.used_by.length ? "Used by: " + c.used_by.join(", ") + "." : "Not used by any backend right now.") + (c.updated ? ` Last changed ${ago(c.updated)}.` : "")),
        c.set ? del : ""));
    }
    const name = el("input", { id: "new-secret-name", type: "text", autocomplete: "off", spellcheck: "false", placeholder: "MY_API_KEY", pattern: "[A-Za-z_][A-Za-z0-9_]*" });
    const value = el("input", { id: "new-secret-value", type: "password", autocomplete: "new-password", spellcheck: "false" });
    const msg = el("p", { class: "note", role: "status" });
    const add = el("form", { class: "card wide" }, el("h3", {}, "Add a credential"),
      el("p", { class: "muted" }, "For a backend whose settings refer to it as ${NAME}. Most of the time the Backends page sets these up for you."),
      el("div", { class: "field" }, el("label", { for: "new-secret-name" }, "Name (letters, digits, underscore)"), name),
      el("div", { class: "field" }, el("label", { for: "new-secret-value" }, "Value"), value), el("button", { type: "submit" }, "Store"), msg);
    add.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const r2 = await act("/api/secrets/" + encodeURIComponent(name.value.trim()), { value: value.value });
      value.value = "";
      if (r2.ok) { await load(); } else { msg.className = "msg"; msg.textContent = r2.body.error || "Could not store it."; }
    });
    kids.push(add);
    box.replaceChildren(...kids);
  }
  await load();
  return box;
}

async function backendsSection() {
  const box = el("section", { "aria-labelledby": "bk" }, el("h2", { id: "bk" }, "Backends"));
  async function load() {
    const r = await api("/api/backends");
    if (!r.ok) { box.replaceChildren(el("h2", { id: "bk" }, "Backends"), el("p", { class: "msg", role: "alert" }, "Could not load backends. Reload the page; if it keeps failing, run mcpgate doctor.")); return; }
    const kids = [el("h2", { id: "bk" }, "Backends")];
    if (r.body.config_error) kids.push(el("p", { class: "msg", role: "alert" }, "The config file has an error, so the last good settings are still running: " + r.body.config_error));
    if (!r.body.backends.length) kids.push(el("p", { class: "muted" }, "No backends yet. Add one in the \"Add a backend\" section below, or open the setup guide in Settings."));
    for (const b of r.body.backends) kids.push(backendCard(b, load));
    box.replaceChildren(...kids);
  }
  await load();
  box.reload = load;
  return box;
}

// ---- adding a backend -------------------------------------------------------------------------
function rowsEditor(title, nameLabel) {
  const list = el("div", { class: "rows" });
  const rows = [];
  function addRow() {
    const name = el("input", { type: "text", "aria-label": nameLabel + " name", autocomplete: "off", spellcheck: "false", placeholder: nameLabel });
    const value = el("input", { type: "text", "aria-label": nameLabel + " value", autocomplete: "off", spellcheck: "false", placeholder: "value" });
    const box = el("input", { type: "checkbox", "aria-label": "this value is secret" });
    box.addEventListener("change", () => { value.type = box.checked ? "password" : "text"; });
    const row = el("div", { class: "row3" }, name, value, el("label", { class: "check" }, box, " secret"));
    rows.push({ name, value, box, row });
    list.append(row);
  }
  addRow();
  const more = el("button", { type: "button", class: "plain" }, "Add another");
  more.addEventListener("click", addRow);
  return { node: el("div", { class: "field" }, el("p", { class: "label" }, title), list, more),
    get: () => rows.filter((r) => r.name.value.trim()).map((r) => ({ name: r.name.value.trim(), value: r.value.value, secret: r.box.checked })) };
}

function textField(label, name, extra = {}) { return field(label, name, "text", { autocomplete: "off", ...extra }); }

async function addSection(reloadList, goSettings, onAdded) {
  const box = el("section", { "aria-labelledby": "add" });
  const { body: info } = await api("/api/presets");
  let current = null;
  const out = el("div", {});

  function show(...kids) { out.replaceChildren(...kids); }
  const choose = el("div", { class: "choices" });
  const pick = (label, fn, desc) => {
    const b = el("button", { type: "button", class: "choice" }, el("strong", {}, label), el("span", { class: "muted" }, desc || ""));
    b.addEventListener("click", () => { for (const x of choose.children) x.removeAttribute("aria-pressed"); b.setAttribute("aria-pressed", "true"); fn(); });
    choose.append(b);
  };

  function reviewScreen(payload, formNode, onError) {
    const msg = el("p", { class: "msg", role: "alert" });
    const done = el("p", { class: "note", role: "status" });
    const lines = [];
    return async () => {
      msg.textContent = "";
      const r = await api("/api/backends/preview", "POST", payload());
      if (!r.ok) { onError(r.body.error || "That did not work."); return false; }
      const v = r.body;
      lines.length = 0;
      lines.push(v.runs_program ? "This runs a program on this computer:" : "This connects to:", "  " + v.target);
      if (v.cwd) lines.push("Working folder: " + v.cwd);
      for (const h of v.headers) lines.push(`Header ${h.name}: ${h.value}`);
      for (const e of v.env) lines.push(`Environment ${e.name}=${e.value}`);
      for (const x of v.secrets) lines.push(x.action === "store" ? `Secret ${x.name}: will be stored (write-only)` : `Secret ${x.name}: already stored, will be reused`);
      lines.push(`Name: ${v.name}`);
      const pre = el("pre", { class: "review", tabindex: "0" }, lines.join("\n"));
      const add = el("button", { type: "button" }, "Add backend");
      const back = el("button", { type: "button", class: "plain" }, "Back");
      back.addEventListener("click", () => show(formNode));
      add.addEventListener("click", async () => {
        add.disabled = true; done.textContent = "Adding…";
        const res = await act("/api/backends/add", { ...payload(), confirm: true });
        if (!res.ok) { done.textContent = ""; msg.textContent = res.body.error || "That did not work."; add.disabled = false; return; }
        done.textContent = "Added. Testing the connection…";
        reloadList();
        const t = await act(`/api/backends/${res.body.backend.name}/test`);
        done.textContent = t.body.ok ? `Works: ${t.body.tools} tools found${t.body.names.length ? ": " + t.body.names.slice(0, 12).join(", ") + (t.body.names.length > 12 ? ", …" : "") : ""}.` : `Added, but the connection failed: ${t.body.error || "unknown error"}${t.body.hint ? " " + t.body.hint : ""}`;
        reloadList();
        if (onAdded) onAdded(res.body.backend.name, t.body);
        back.remove(); add.remove();
      });
      show(el("div", { class: "card" }, el("h3", {}, "Review"), el("p", { class: "muted" }, "This is exactly what will be saved."), pre, el("div", { class: "row" }, add, back), msg, done));
      return true;
    };
  }

  function presetForm(p) {
    const fields = [textField("Name", "name", { value: p.name })];
    for (const f of p.fields) fields.push(field(f.label + (f.already_set ? " (already stored: leave empty to keep it)" : ""), "v_" + f.id, "password", { required: f.already_set ? null : "" }), el("p", { class: "muted" }, f.help));
    const msg = el("p", { class: "msg", role: "alert" });
    const f = el("form", { class: "card" }, el("h3", {}, p.title), el("p", { class: "muted" }, p.description),
      p.runs_program ? el("p", { class: "muted" }, "This one runs a program on this computer, so you will be asked for your passphrase when you add it.") : "", ...fields.map((n) => n),
      el("button", { type: "submit" }, "Review"), msg);
    const payload = () => { const fd = new FormData(f); const values = {}; for (const x of p.fields) values[x.id] = fd.get("v_" + x.id) || ""; return { kind: "preset", preset: p.id, name: fd.get("name"), values }; };
    f.addEventListener("submit", async (ev) => { ev.preventDefault(); msg.textContent = ""; await reviewScreen(payload, f, (t) => { msg.textContent = t; })(); });
    return f;
  }

  function remoteForm() {
    const headers = rowsEditor("Headers (for example Authorization). Tick “secret” for anything private.", "Header");
    const sel = el("select", { name: "transport", id: "f-transport" }, el("option", { value: "http" }, "HTTP (streamable)"), el("option", { value: "sse" }, "SSE"));
    const msg = el("p", { class: "msg", role: "alert" });
    const signin = el("input", { type: "checkbox", id: "f-auth", name: "auth" });
    const f = el("form", { class: "card" }, el("h3", {}, "Remote MCP server"), el("p", { class: "muted" }, "Any MCP server reachable by a web address. It must be https, except localhost."),
      textField("Name", "name"), el("div", { class: "field" }, el("label", { for: "f-transport" }, "Transport"), sel), textField("Address (URL)", "url", { placeholder: "https://example.com/mcp" }),
      textField("Description (optional)", "description", { required: null }), textField("Start timeout, seconds", "start_timeout", { value: "30", inputmode: "numeric" }),
      el("div", { class: "field check" }, signin, el("label", { for: "f-auth" }, "This server needs me to sign in with an account (no token)")),
      el("p", { class: "muted" }, "Tick this for services that ask you to log in or approve access in a browser. After adding it, press Sign in on its card."),
      headers.node, el("button", { type: "submit" }, "Review"), msg);
    const payload = () => { const fd = new FormData(f); return { kind: "remote", name: fd.get("name"), transport: fd.get("transport"), url: fd.get("url"), description: fd.get("description"), start_timeout: Number(fd.get("start_timeout")) || undefined, headers: headers.get(), auth: signin.checked ? "oauth" : "" }; };
    f.addEventListener("submit", async (ev) => { ev.preventDefault(); msg.textContent = ""; await reviewScreen(payload, f, (t) => { msg.textContent = t; })(); });
    return f;
  }

  function commandForm() {
    if (!info.custom_commands) {
      const go = el("button", { type: "button", class: "plain" }, "Open settings");
      go.addEventListener("click", goSettings);
      return el("div", { class: "card" }, el("h3", {}, "Custom command"), el("p", {}, "Programs on this computer are switched off in Settings. Turning them on lets you add a backend that starts a program here; each one asks for your admin passphrase."), go);
    }
    const env = rowsEditor("Environment values. Tick “secret” for anything private.", "Variable");
    const msg = el("p", { class: "msg", role: "alert" });
    const args = el("textarea", { name: "args", id: "f-args", rows: "3", spellcheck: "false", autocomplete: "off" });
    const f = el("form", { class: "card" }, el("h3", {}, "Custom command"), el("p", { class: "muted" }, "Runs a program on this computer as your user, started when the gateway needs it."),
      textField("Name", "name"), textField("Command", "command", { placeholder: "npx" }), el("div", { class: "field" }, el("label", { for: "f-args" }, "Arguments (one per line)"), args),
      env.node, textField("Working folder (optional)", "cwd", { required: null }), textField("Description (optional)", "description", { required: null }), textField("Start timeout, seconds", "start_timeout", { value: "30", inputmode: "numeric" }),
      el("button", { type: "submit" }, "Review"), msg);
    const payload = () => { const fd = new FormData(f); return { kind: "command", name: fd.get("name"), command: fd.get("command"), args: String(fd.get("args")).split("\n").map((x) => x.trim()).filter(Boolean), cwd: fd.get("cwd"), description: fd.get("description"), start_timeout: Number(fd.get("start_timeout")) || undefined, env: env.get() }; };
    f.addEventListener("submit", async (ev) => { ev.preventDefault(); msg.textContent = ""; await reviewScreen(payload, f, (t) => { msg.textContent = t; })(); });
    return f;
  }

  for (const p of info.presets) pick(p.title, () => show(presetForm(p)), p.description);
  pick("Remote server (URL)", () => show(remoteForm()), "Any MCP server reachable by a web address, with a token or header if it needs one.");
  pick("Custom command", () => show(commandForm()), "Start a program on this computer, such as npx or uvx.");
  box.append(el("h2", { id: "add" }, "Add a backend"), el("p", { class: "muted" }, "Pick what to connect. Tokens you enter go to a private store on this computer, never into the config file."), choose, out);
  return box;
}

async function settingsSection(reloadAll, openGuide) {
  const box = el("section", { "aria-labelledby": "set" });
  async function load() {
    const { body: s } = await api("/api/settings");
    const msg = el("p", { class: "msg", role: "alert" });
    const guide = el("button", { type: "button", class: "plain" }, "Open the setup guide");
    guide.addEventListener("click", () => openGuide());
    const kids = [el("h2", { id: "set" }, "Settings"), el("h3", {}, "Setup guide"),
      el("p", { class: "muted" }, "Step by step: add a first backend, test it, and connect a client."), guide, el("h3", {}, "Programs on this computer"),
      el("p", {}, s.custom_commands ? "On: you can add a backend that starts a program on this computer (a custom command). Each one asks for your admin passphrase again." : "Off: only presets and remote servers can be added.")];
    const sw = el("button", { type: "button", class: s.custom_commands ? "plain" : "" }, s.custom_commands ? "Turn off" : "Turn on");
    sw.addEventListener("click", async () => {
      const r = await act("/api/settings/custom-commands", { enabled: !s.custom_commands });
      if (r.ok) { await load(); reloadAll(); } else msg.textContent = r.body.error || "Failed.";
    });
    kids.push(sw, msg);
    box.replaceChildren(...kids);
  }
  await load();
  return box;
}

// ---- approvals inbox ----------------------------------------------------------------------------
let pollTimer = null;

async function overviewSection(approvals) {
  const box = el("section", { "aria-labelledby": "ov" }, el("h2", { id: "ov", tabindex: "-1" }, "Overview"));
  const [bk, rm] = await Promise.all([api("/api/backends"), api("/api/remote")]);
  const list = bk.ok ? bk.body.backends : [];
  const up = list.filter((b) => b.state === "connected").length;
  const bad = list.filter((b) => b.state === "error").length;
  const r = rm.ok ? rm.body : null;
  const remoteReady = !!(r && r.settings.public_url && r.settings.oauth_enabled && r.passphrase.set);
  const remoteText = remoteReady ? "On" : (r && r.settings.public_url ? "Needs a passphrase" : "Off");
  const apps = r ? r.clients.length : 0;
  const tile = (href, label, value, hint) => el("a", { class: "tile", href }, el("span", { class: "tile-label" }, label), el("strong", { class: "tile-value" }, value), el("span", { class: "muted small" }, hint));
  box.append(el("p", { class: "muted" }, "Your gateway gives Claude one door to all your backends. This page shows where things stand and what to do next."),
    el("div", { class: "tiles" },
      tile("#/backends", "Backends", `${up} of ${list.length} connected`, bad ? `${bad} with a problem` : "Add or change them"),
      tile("#/approvals", "Waiting for you", String(approvals.count || 0), "Calls that need your approval"),
      tile("#/remote", "Remote access", remoteText, "For claude.ai from anywhere"),
      tile("#/tokens", "Signed-in apps", String(apps), "Tokens and passphrases")));
  const step = (done, title, body, href, action) => el("li", { class: done ? "step done" : "step" },
    el("div", {}, el("strong", {}, (done ? "Done: " : "") + title), el("p", { class: "muted" }, body)),
    el("a", { class: "button", href }, action));
  box.append(el("h3", {}, "Get started"), el("ol", { class: "steps" },
    step(list.length > 0, "Register a backend", "A backend is a tool server such as GitHub or Google Colab. Pick a preset, paste its token, and test it.", "#/backends", list.length ? "Add another" : "Add a backend"),
    step(false, "Choose what Claude may do", "Open a backend and set each tool to allowed, needs approval, or hidden. Deleting and writing tools are good ones to ask about.", "#/backends", "Open backends"),
    step(remoteReady, "Connect claude.ai", "Add your public address, set an approval passphrase, and check the connection.", "#/remote", "Set up remote access"),
    step(apps > 0, "Add it in claude.ai", "Add a custom connector with your address, then sign in with the approval passphrase. Usage and tokens are explained on the Tokens page.", "#/tokens", "How to connect")));
  box.append(el("h3", {}, "On this computer"), el("p", { class: "muted" }, "Claude Code and Claude Desktop on this machine need no tunnel or token:"), codeBlock("claude mcp add mcpgate -- mcpgate serve"));
  return box;
}

async function approvalsSection() {
  const box = el("section", { id: "approvals", "aria-labelledby": "ap" });
  const badge = el("a", { href: "#/approvals", class: "badge", "aria-label": "Approvals waiting" }, "Approvals: 0");
  const live = el("p", { class: "sr", "aria-live": "polite" });
  let sig = "";
  let lastCount = 0;

  async function decide(id, action, data, note) {
    const r = await api(`/api/approvals/${id}/${action}`, "POST", data || {});
    if (!r.ok) note.textContent = r.body.error || "That did not work.";
    await refresh();
  }

  function card(p) {
    const note = el("p", { class: "msg", role: "alert" });
    const when = el("span", { class: "muted small", "data-id": p.id }, "");
    when.textContent = `asked ${p.requested_ago}s ago · expires in ${p.expires_in}s`;
    const once = el("button", { type: "button" }, "Approve once");
    once.addEventListener("click", () => decide(p.id, "approve", {}, note));
    const sel = el("select", { "aria-label": "Approve this exact call for a while" }, el("option", { value: "" }, "Approve for…"),
      el("option", { value: "5" }, "5 minutes"), el("option", { value: "15" }, "15 minutes"), el("option", { value: "60" }, "1 hour"));
    sel.addEventListener("change", () => { if (sel.value) decide(p.id, "approve", { minutes: Number(sel.value) }, note); });
    const deny = el("button", { type: "button", class: "danger" }, "Deny");
    deny.addEventListener("click", () => decide(p.id, "deny", {}, note));
    return el("article", { class: "card pending", "data-id": p.id },
      el("h3", {}, p.tool), when,
      el("p", { class: "muted small" }, "The model asked to run this with exactly these arguments (secret-looking values are hidden):"),
      el("pre", { class: "review", tabindex: "0" }, p.args + (p.args_cut ? "\n… (cut for display)" : "")),
      el("div", { class: "row" }, once, sel, deny), note);
  }

  function draw(d) {
    const kids = [el("h2", { id: "ap" }, "Approvals")];
    if (!d.available) kids.push(el("p", { class: "muted" }, "Risky tools are approved here when mcpgate runs as the service (mcpgate serve --service)."));
    else if (!d.pending.length) kids.push(el("p", { class: "muted" }, "Nothing is waiting for you."));
    for (const p of d.pending) kids.push(card(p));
    if (d.recent.length) {
      kids.push(el("details", {}, el("summary", {}, "Recent decisions"),
        el("ul", {}, ...d.recent.map((h) => el("li", {}, `${h.tool}: ${h.state}${h.minutes ? ` for ${h.minutes} min` : ""} (${h.ago}s ago)`)))));
    }
    box.replaceChildren(...kids);
  }

  async function refresh() {
    const r = await api("/api/approvals");
    if (!r.ok) return;
    const d = r.body;
    const next = d.pending.map((p) => p.id).join(",") + "|" + d.recent.map((h) => h.id + h.state).join(",");
    if (next !== sig) { sig = next; draw(d); }
    else for (const p of d.pending) {   // only the countdowns change; leave forms and focus alone
      const w = box.querySelector(`span[data-id="${p.id}"]`);
      if (w) w.textContent = `asked ${p.requested_ago}s ago · expires in ${p.expires_in}s`;
    }
    badge.textContent = `Approvals: ${d.count}`;
    badge.classList.toggle("alert", d.count > 0);
    document.title = (d.count ? `(${d.count}) ` : "") + viewTitle + " · mcpgate admin";
    if (d.count > lastCount) live.textContent = `${d.count} approval${d.count > 1 ? "s" : ""} waiting`;
    lastCount = d.count;
  }
  await refresh();
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => { if (!document.hidden) refresh(); }, 3000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  Object.defineProperty(box, "count", { get: () => lastCount });
  box.badge = badge;
  box.live = live;
  return box;
}

// ---- remote access ------------------------------------------------------------------------------
function copyButton(text, label = "Copy") {
  const b = el("button", { type: "button", class: "plain" }, label);
  b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(text); b.textContent = "Copied"; } catch (e) { b.textContent = "Select and copy by hand"; }
    setTimeout(() => { b.textContent = label; }, 2000);
  });
  return b;
}

function codeBlock(text) {
  return el("div", { class: "codewrap" }, el("pre", { class: "code" }, text), copyButton(text));
}

function ago(ts) {
  if (!ts) return "never";
  const m = Math.max(0, Math.round((Date.now() / 1000 - ts) / 60));
  if (m < 1) return "just now";
  if (m < 90) return m + " min ago";
  if (m < 60 * 36) return Math.round(m / 60) + " h ago";
  return Math.round(m / 1440) + " days ago";
}

async function remoteSection(part = "remote") {
  const box = el("section", { "aria-labelledby": part === "tokens" ? "tok" : "rem" });
  let token = "";          // shown once, then dropped
  let checkResult = null;
  const notes = {};
  async function load() {
    const { body: st } = await api("/api/remote");
    const refresh = async () => { await load(); };
    const say = (key, text, bad) => { notes[key] = { text, bad }; };
    const note = (key) => { const n = notes[key]; return el("p", { class: n && n.bad ? "msg" : "note", role: n && n.bad ? "alert" : "status" }, n ? n.text : ""); };
    const pieces = {};

    if (st.restart.required) {
      const b = el("button", { type: "button" }, "Restart now");
      b.addEventListener("click", async () => {
        const r = await act("/api/remote/restart");
        say("restart", r.ok ? "Restarting. This page reconnects in a few seconds; reload it if it does not." : (r.body.error || "Could not restart. Run mcpgate service status to see why."), !r.ok);
        await refresh();
      });
      pieces.banner = (el("div", { class: "banner", role: "status" }, el("p", {}, "Saved changes will apply after the service restarts." +
        (st.restart.supervised ? "" : " It is not running under a service manager, so stop it with Ctrl+C and start it again yourself.")),
        st.restart.supervised ? b : "", note("restart")));
    }

    // address and options
    const url = el("input", { id: "r-url", name: "public_url", type: "text", autocomplete: "off", spellcheck: "false", placeholder: "https://your-machine.your-tailnet.ts.net", value: st.settings.public_url });
    const port = el("input", { id: "r-port", name: "port", type: "number", min: "1024", max: "65535", value: String(st.settings.port) });
    const hosts = el("input", { id: "r-hosts", name: "allow_hosts", type: "text", autocomplete: "off", value: st.settings.allow_hosts.join(", ") });
    const oauth = el("input", { id: "r-oauth", name: "oauth_enabled", type: "checkbox" });
    oauth.checked = st.settings.oauth_enabled;
    const sf = el("form", { class: "card" }, el("h3", {}, "Address"),
      el("div", { class: "field" }, el("label", { for: "r-url" }, "Public address (https, no path)"), url),
      el("div", { class: "field" }, el("label", { for: "r-port" }, "Local port the tunnel points at"), port),
      el("div", { class: "field" }, el("label", { for: "r-hosts" }, "Extra allowed host names (optional, comma separated)"), hosts),
      el("div", { class: "field check" }, oauth, el("label", { for: "r-oauth" }, "Let apps sign in with the approval passphrase (claude.ai)")),
      el("button", { type: "submit" }, "Save"), note("settings"));
    sf.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const r = await api("/api/remote/settings", "POST", {
        public_url: url.value.trim(), port: Number(port.value),
        allow_hosts: hosts.value.split(",").map((x) => x.trim()).filter(Boolean), oauth_enabled: oauth.checked });
      say("settings", r.ok ? "Saved." : (r.body.error || "Could not save. Check the values and try again."), !r.ok);
      await refresh();
    });
    pieces.address = sf;

    // approval passphrase
    const pw = el("input", { id: "r-pw", name: "passphrase", type: "password", autocomplete: "new-password", minlength: "12", required: "" });
    const keep = el("input", { id: "r-keep", name: "keep", type: "checkbox" });
    keep.checked = true;
    const pf = el("form", { class: "card" }, el("h3", {}, "Approval passphrase"),
      el("p", { class: "muted" }, st.passphrase.from_env ? "A passphrase is also set in the environment and takes priority." :
        (st.passphrase.set ? "A passphrase is set. It is never shown again; set a new one to change it." : "Not set yet. Apps cannot sign in until you set one.")),
      el("div", { class: "field" }, el("label", { for: "r-pw" }, "New passphrase (12+ characters)"), pw),
      el("div", { class: "field check" }, keep, el("label", { for: "r-keep" }, "Keep apps that are already signed in")),
      el("button", { type: "submit" }, st.passphrase.set ? "Change passphrase" : "Set passphrase"), note("pass"));
    pf.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const r = await act("/api/remote/passphrase", { passphrase: pw.value, keep_sessions: keep.checked });
      pw.value = "";
      say("pass", r.ok ? "Passphrase saved." : (r.body.error || "Could not save. Check the values and try again."), !r.ok);
      await refresh();
    });
    pieces.pass = pf;

    // access token
    const tk = [el("h3", {}, "Access token"),
      el("p", { class: "muted" }, st.token.from_env ? "A token is also set in the environment." :
        (st.token.set ? "A token is set. It cannot be shown again; create a new one to replace it." : "For tools that cannot do the sign-in flow. Optional."))];
    if (token) {
      tk.push(el("p", { class: "note", role: "status" }, "Copy this token now. It will not be shown again."), codeBlock(token));
    }
    const make = el("button", { type: "button" }, st.token.set ? "Create a new token" : "Create token");
    make.addEventListener("click", async () => {
      const r = await act("/api/remote/token");
      if (r.ok) { token = r.body.token; } else say("token", r.body.error || "Could not create a token. Try again; if it keeps failing, run mcpgate doctor.", true);
      await refresh();
    });
    tk.push(make);
    if (st.token.set) {
      const rm = el("button", { type: "button", class: "danger" }, "Remove token");
      rm.addEventListener("click", async () => { if (!window.confirm("Remove the access token? Anything using it stops working until you create a new one.")) return; token = ""; await act("/api/remote/token/remove"); await refresh(); });
      tk.push(rm);
    }
    tk.push(note("token"));
    pieces.token = el("div", { class: "card" }, ...tk);

    // connection check
    const chk = el("button", { type: "button" }, "Check connection");
    chk.disabled = !st.settings.public_url;
    chk.addEventListener("click", async () => {
      chk.disabled = true;
      const r = await api("/api/remote/check", "POST", {});
      checkResult = r.ok ? r.body : null;
      say("check", r.ok ? "" : (r.body.error || "The check failed. Try again in a moment."), !r.ok);
      await refresh();
    });
    const list = el("ul", { class: "checks" });
    if (checkResult) {
      for (const c of checkResult.results) {
        list.append(el("li", { class: c.ok === true ? "pass" : c.ok === false ? "fail" : "warn" },
          el("strong", {}, (c.ok === true ? "OK: " : c.ok === false ? "Problem: " : "Note: ") + c.name), " " + c.detail, c.advice ? el("div", { class: "muted" }, c.advice) : ""));
      }
    }
    pieces.check = el("div", { class: "card" }, el("h3", {}, "Connection check"),
      el("p", { class: "muted" }, "Contacts your saved public address from here and reports what an outside app would see."), chk, note("check"), list);

    // instructions
    const ins = st.instructions;
    const how = [el("h3", {}, "How to connect"), el("p", {}, "Connector address for claude.ai:"), codeBlock(ins.connector_url)];
    for (const key of ["tailscale", "cloudflare"]) {
      const g = ins[key];
      how.push(el("h4", {}, g.title), el("p", { class: "muted" }, g.intro));
      for (const c of g.commands) how.push(codeBlock(c));
    }
    how.push(el("h4", {}, "In claude.ai"), el("ol", {}, ...ins.claude.map((t) => el("li", {}, t))));
    pieces.how = el("details", { class: "card" }, el("summary", {}, "Show setup instructions"), ...how);

    // signed-in apps
    const apps = [el("h3", {}, "Signed-in apps")];
    if (!st.clients.length) apps.push(el("p", { class: "muted" }, "No apps are signed in."));
    for (const c of st.clients) {
      const mine = st.sessions.filter((x) => x.client_id === c.client_id);
      const rm = el("button", { type: "button", class: "danger" }, "Remove app");
      rm.addEventListener("click", async () => { if (!window.confirm(`Remove ${c.name}? It will be signed out and must be approved again to reconnect.`)) return; await act("/api/remote/clients/" + encodeURIComponent(c.client_id) + "/remove"); await refresh(); });
      const row = el("div", { class: "approval" }, el("strong", {}, c.name), el("span", { class: "muted" }, ` ${mine.length} signed in, last used ${ago(c.last_used)} `), rm);
      for (const x of mine) {
        const so = el("button", { type: "button", class: "plain" }, "Sign out");
        so.addEventListener("click", async () => { await act("/api/remote/sessions/" + encodeURIComponent(x.id) + "/signout"); await refresh(); });
        row.append(el("div", {}, `Session started ${ago(x.created)}, last used ${ago(x.last_used)} `, so));
      }
      apps.push(row);
    }
    if (st.clients.length) {
      const all = el("button", { type: "button", class: "danger" }, "Sign out everywhere");
      all.addEventListener("click", async () => { if (!window.confirm("Sign every app out? Each one has to be approved again.")) return; await act("/api/remote/signout-all"); await refresh(); });
      apps.push(all);
    }
    pieces.apps = el("div", { class: "card" }, ...apps);

    const url0 = st.settings.public_url ? st.instructions.connector_url : "https://YOUR-ADDRESS/mcp";
    const explain = [
      el("div", { class: "card wide" }, el("h3", {}, "Which secret is which?"),
        el("dl", { class: "defs" },
          el("dt", {}, "Admin passphrase"), el("dd", {}, "Signs you in to this admin page. It never leaves this computer. Change it in Settings."),
          el("dt", {}, "Approval passphrase"), el("dd", {}, "What you type on the sign-in page that claude.ai (or another app that supports sign-in) opens when you add the connector. The app never sees it."),
          el("dt", {}, "Access token"), el("dd", {}, "A long random string for tools that cannot do the sign-in step. The tool sends it with every request. It is shown once when you create it and stored only as a hash."))),
      el("div", { class: "card wide" }, el("h3", {}, "How to use them"),
        el("p", {}, el("strong", {}, "claude.ai or the Claude app. "), "Add a custom connector with this address, then type the approval passphrase when asked:"), codeBlock(url0),
        el("p", {}, el("strong", {}, "Claude Code on another computer, with a token:")), codeBlock(`claude mcp add --transport http mcpgate ${url0} --header "Authorization: Bearer YOUR_TOKEN"`),
        el("p", {}, el("strong", {}, "Any other tool. "), "Send the header ", el("code", {}, "Authorization: Bearer YOUR_TOKEN"), " to that address."),
        el("p", {}, el("strong", {}, "On this computer "), "you need no token and no tunnel:"), codeBlock("claude mcp add mcpgate -- mcpgate serve"),
        st.settings.public_url ? "" : el("p", { class: "muted" }, "Remote use needs a public address first: set it on the Remote access page."))];
    if (part === "tokens") {
      box.replaceChildren(el("h2", { id: "tok", tabindex: "-1" }, "Tokens and sign-in"),
        el("p", { class: "muted" }, "What an app needs to be allowed in to mcpgate, and how to use it. (The keys mcpgate uses to reach your backends, such as a GitHub token, are on the Credentials page.)"), ...explain,
        ...[pieces.banner, pieces.pass, pieces.token, pieces.apps].filter(Boolean));
    } else {
      box.replaceChildren(el("h2", { id: "rem", tabindex: "-1" }, "Remote access"),
        el("p", { class: "muted" }, "Lets claude.ai and other apps outside this computer reach your gateway through a tunnel. This admin page itself is never exposed. Passphrases and tokens are on the Tokens page."),
        ...[pieces.banner, pieces.address, pieces.check, pieces.how].filter(Boolean));
    }
  }
  await load();
  return box;
}

// ---- audit log ----------------------------------------------------------------------------------
const WHEN = { "": "All time", "3600": "Last hour", "86400": "Last 24 hours", "604800": "Last 7 days" };
const KIND = { "": "Everything", call: "Tool calls", admin: "Admin actions", approval: "Approvals" };

function select(id, label, options, value = "") {
  const sel = el("select", { id, name: id });
  for (const [v, t] of options) { const o = el("option", { value: v }, t); if (v === value) o.selected = true; sel.append(o); }
  return el("div", { class: "field" }, el("label", { for: id }, label), sel);
}

function bytesText(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB"; }

function auditRow(e) {
  const what = e.event ? e.event.replace(/_/g, " ") : (e.tool || "?");
  const status = e.event ? "" : (e.status || "");
  const sum = el("summary", {}, el("time", { datetime: new Date(e.ts * 1000).toISOString() }, new Date(e.ts * 1000).toLocaleString()), " ",
    el("strong", {}, what), status ? el("span", { class: "tag " + (status === "ok" || status === "cached" ? "good" : "bad") }, " " + status) : "",
    typeof e.ms === "number" ? el("span", { class: "muted" }, " " + e.ms + " ms") : "");
  return el("details", { class: "logrow" }, sum, el("pre", { class: "code" }, JSON.stringify(e, null, 2)));
}

async function auditSection() {
  const box = el("section", { "aria-labelledby": "aud" });
  const f = { backend: "", tool: "", status: "", kind: "", q: "", when: "" };
  let entries = [], next = null, meta = null, loading = false, note = "";
  const list = el("div", { class: "loglist", "aria-live": "polite" });
  const more = el("button", { type: "button", class: "plain" }, "Show older");
  const info = el("p", { class: "muted" });

  function query(cursor) {
    const q = new URLSearchParams({ limit: "100" });
    for (const k of ["backend", "tool", "status", "kind", "q"]) if (f[k]) q.set(k, f[k]);
    if (f.when) q.set("since", String(Math.floor(Date.now() / 1000) - Number(f.when)));
    if (cursor) q.set("cursor", cursor);
    return "/api/audit?" + q.toString();
  }
  function paint() {
    list.replaceChildren(...(entries.length ? entries.map(auditRow) : [el("p", { class: "muted" }, loading ? "Loading…" : "Nothing matches.")]));
    more.hidden = !next;
    more.textContent = meta && meta.scanned >= 100000 ? "Keep searching older entries" : "Show older";
    info.textContent = note || (meta ? `${meta.files.length} file(s), ${bytesText(meta.files.reduce((a, x) => a + x.bytes, 0))} on disk.` : "");
  }
  async function load(more_) {
    if (loading) return;
    loading = true; note = "";
    const r = await api(query(more_ ? next : null));
    loading = false;
    if (!r.ok) { note = r.body.error || "Could not read the log. Reload the page, or check that the log folder is readable."; paint(); return; }
    meta = r.body;
    if (meta.stale) note = "The log was rotated while you were reading. Refresh to start again.";
    entries = more_ ? entries.concat(meta.entries) : meta.entries;
    next = meta.next;
    paint();
    if (!more_) buildHead();
  }
  more.addEventListener("click", () => load(true));

  const head = el("div", {});
  function buildHead() {
    const s = meta.settings;
    const fields = [
      select("a-kind", "Show", Object.entries(KIND), f.kind),
      el("div", { class: "field" }, el("label", { for: "a-backend" }, "Backend (exact name)"), el("input", { id: "a-backend", type: "text", list: "a-backends", autocomplete: "off", value: f.backend }),
        el("datalist", { id: "a-backends" }, ...meta.backends.map((b) => el("option", { value: b })))),
      select("a-status", "Result", [["", "Any"], ...meta.statuses.map((x) => [x, x])], f.status),
      select("a-when", "Time", Object.entries(WHEN), f.when),
      el("div", { class: "field" }, el("label", { for: "a-tool" }, "Tool contains"), el("input", { id: "a-tool", type: "text", autocomplete: "off", value: f.tool })),
      el("div", { class: "field" }, el("label", { for: "a-q" }, "Search"), el("input", { id: "a-q", type: "search", autocomplete: "off", value: f.q })),
    ];
    const form_ = el("form", { class: "filters" }, ...fields, el("button", { type: "submit" }, "Apply"));
    form_.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      f.kind = form_.querySelector("#a-kind").value; f.backend = form_.querySelector("#a-backend").value.trim();
      f.status = form_.querySelector("#a-status").value; f.when = form_.querySelector("#a-when").value;
      f.tool = form_.querySelector("#a-tool").value.trim(); f.q = form_.querySelector("#a-q").value.trim();
      await load(false);
    });
    const refresh = el("button", { type: "button", class: "plain" }, "Refresh");
    refresh.addEventListener("click", () => load(false));
    const dl = el("a", { href: "/api/audit/download", download: "mcpgate-audit.jsonl", class: "button plain" }, "Download all");

    const on = el("input", { id: "a-on", type: "checkbox" }); on.checked = s.enabled;
    const mb = el("input", { id: "a-mb", type: "number", min: "1", max: "1000", value: String(s.max_mb) });
    const keep = el("input", { id: "a-keep", type: "number", min: "1", max: "50", value: String(s.keep) });
    const msg = el("p", { class: "note", role: "status" });
    const sf = el("form", { class: "card" }, el("h3", {}, "Log settings"),
      el("div", { class: "field check" }, on, el("label", { for: "a-on" }, "Record tool calls and admin actions")),
      el("div", { class: "field" }, el("label", { for: "a-mb" }, "Start a new file at this size (MB)"), mb),
      el("div", { class: "field" }, el("label", { for: "a-keep" }, "Old files to keep"), keep),
      el("p", { class: "muted" }, "Secrets, passphrases and tokens are never written to the log. When the oldest kept file is full it is deleted."),
      el("button", { type: "submit" }, "Save"), msg);
    sf.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const r = await api("/api/audit/settings", "POST", { enabled: on.checked, max_mb: Number(mb.value), keep: Number(keep.value) });
      msg.className = r.ok ? "note" : "msg";
      msg.textContent = r.ok ? "Saved." : (r.body.error || "Could not save. Check the values and try again.");
      if (r.ok) await load(false);
    });
    head.replaceChildren(el("div", { class: "row" }, refresh, dl), form_, el("details", {}, el("summary", {}, "Log settings"), sf));
  }

  box.append(el("h2", { id: "aud" }, "Activity log"),
    el("p", { class: "muted" }, "Every tool call and every admin action, newest first. Open a row for the full record."), head, info, list, more);
  paint();
  await load(false);
  return box;
}

// ---- first-run setup guide ----------------------------------------------------------------------
let wizardOpen = false;
let wizardAuto = true;     // open it by itself once per page load, on a fresh install only

const WIZ_STEPS = ["Admin passphrase", "Add a backend", "Test it", "Connect a client", "Summary"];

async function wizardSection(close) {
  const { body: first } = await api("/api/wizard");
  const box = el("section", { class: "card", "aria-labelledby": "wiz" });
  let step = first.has_backend ? 3 : 2;
  let target = "";        // the backend being tested in step 3
  let lastTest = null;

  async function skip() { await act("/api/wizard", { done: true }); await close(); }

  function frame(...kids) {
    const nav = el("ol", { class: "steps" }, ...WIZ_STEPS.map((t, i) => el("li", { class: i + 1 === step ? "current" : i + 1 < step ? "done" : "", "aria-current": i + 1 === step ? "step" : null }, `${i + 1}. ${t}`)));
    const sk = el("button", { type: "button", class: "plain" }, "Skip setup for now");
    sk.addEventListener("click", skip);
    box.replaceChildren(el("h2", { id: "wiz" }, "Set up mcpgate"), nav, ...kids, el("div", { class: "row" }, sk,
      el("span", { class: "muted" }, "You can come back to this from Settings.")));
  }

  function next(n) { step = n; draw(); }

  async function draw() {
    if (step === 2) return stepAdd();
    if (step === 3) return stepTest();
    if (step === 4) return stepConnect();
    return stepSummary();
  }

  async function stepAdd() {
    const skipStep = el("button", { type: "button", class: "plain" }, "I already have backends, continue");
    skipStep.addEventListener("click", () => next(first.has_backend ? 3 : 4));
    const add = await addSection(() => {}, () => close(), (name, t) => { target = name; lastTest = t; next(3); });
    frame(el("p", {}, "Pick something to connect. Passwords and tokens go into a password field and are stored write-only."), add, skipStep);
  }

  async function stepTest() {
    if (!target) {
      const { body } = await api("/api/backends");
      const usable = body.backends.filter((b) => b.enabled);
      if (!usable.length) { frame(el("p", {}, "There is no enabled backend to test yet."), backTo(2)); return; }
      target = usable[0].name;
    }
    const out = el("div", { "aria-live": "polite" });
    const again = el("button", { type: "button" }, "Test again");
    const cont = el("button", { type: "button", class: "plain" }, "Continue");
    const undo = el("button", { type: "button", class: "danger" }, "Remove it and start over");
    const paint = (t) => {
      if (!t) { out.replaceChildren(el("p", {}, "Testing…")); return; }
      if (t.ok) {
        out.replaceChildren(el("p", { class: "note" }, `It works: ${t.tools} tool${t.tools === 1 ? "" : "s"} found${t.hidden ? `, ${t.hidden} hidden by permissions` : ""}.`),
          t.names.length ? el("ul", { class: "toolnames" }, ...t.names.slice(0, 50).map((n) => el("li", {}, n))) : "");
      } else {
        out.replaceChildren(el("p", { class: "msg", role: "alert" }, "The connection did not work: " + (t.error || "unknown error")), t.hint ? el("p", {}, t.hint) : "",
          t.detail ? el("details", {}, el("summary", {}, "Technical detail"), el("pre", { class: "code" }, t.detail)) : "");
      }
    };
    const run = async () => {
      again.disabled = true; paint(null);
      const r = await act(`/api/backends/${encodeURIComponent(target)}/test`);
      lastTest = r.ok ? r.body : { ok: false, error: r.body.error || "The test could not run." };
      paint(lastTest); again.disabled = false;
    };
    again.addEventListener("click", run);
    cont.addEventListener("click", () => next(4));
    undo.addEventListener("click", async () => {
      if (!window.confirm(`Remove “${target}” and its stored secrets, and start over?`)) return;
      const r = await act(`/api/backends/${encodeURIComponent(target)}/remove`, { confirm: true, delete_secrets: true });
      if (!r.ok) { out.replaceChildren(el("p", { class: "msg", role: "alert" }, r.body.error || "Could not remove it. Reload the page and try again.")); return; }
      target = ""; lastTest = null; next(2);
    });
    frame(el("p", {}, `Testing “${target}”.`), out, el("div", { class: "row" }, again, cont, undo));
    if (lastTest) paint(lastTest); else await run();
  }

  function backTo(n) {
    const b = el("button", { type: "button", class: "plain" }, "Back");
    b.addEventListener("click", () => next(n));
    return b;
  }

  async function stepConnect() {
    const { body: w } = await api("/api/wizard");
    const remote = el("button", { type: "button" }, "Set up remote access");
    remote.addEventListener("click", async () => { await act("/api/wizard", { done: true }); await close("rem"); });
    const go = el("button", { type: "button" }, "Continue");
    go.addEventListener("click", () => next(5));
    frame(el("p", {}, "How will your AI apps reach mcpgate?"),
      el("div", { class: "card" }, el("h3", {}, "This computer only"),
        el("p", { class: "muted" }, "For Claude Code and other apps on this computer. Run this once in a terminal:"), codeBlock(w.connect.command),
        el("p", { class: "muted" }, "Or paste this into the app's MCP settings:"), codeBlock(w.connect.json)),
      el("div", { class: "card" }, el("h3", {}, "From claude.ai"), el("p", { class: "muted" }, "Needs a public address and a sign-in passphrase. The next page walks you through it."), remote),
      el("div", { class: "row" }, backTo(3), go));
  }

  async function stepSummary() {
    const { body: w } = await api("/api/wizard");
    const s = w.summary;
    const done = el("button", { type: "button" }, "Finish");
    done.addEventListener("click", async () => { await act("/api/wizard", { done: true }); await close(); });
    const li = (...t) => el("li", {}, ...t);
    frame(el("h3", {}, "Protected"), el("ul", {},
      li(`The admin page listens on ${s.admin.address} only, so only this computer can reach it.`),
      li("Admin passphrase: set."),
      ...s.backends.map((b) => li(`${b.name} (${b.transport}${b.enabled ? "" : ", disabled"}): ` +
        (b.secrets.length ? b.secrets.map((x) => `${x.name} ${x.set ? "set" : "NOT set"}`).join(", ") + "; " : "") +
        `${b.needs_approval} rule${b.needs_approval === 1 ? "" : "s"} needing your approval, ${b.blocked} blocked.`)),
      li(s.approvals ? "Risky calls wait for you in the Approvals inbox." : "Approvals inbox is active when you run the background service."),
      li(s.audit ? "Every call and admin action is logged." : "The activity log is off.")),
      el("h3", {}, "Exposed"), el("ul", {}, li(s.remote.exposed ? `Reachable from outside${s.remote.public_url ? " at " + s.remote.public_url : ""}${s.remote.signs_in ? ", with sign-in" : ""}${s.remote.token ? ", and by access token" : ""}.` : "Nothing is exposed outside this computer.")),
      el("div", { class: "row" }, backTo(4), done));
  }

  await draw();
  return box;
}

async function after(r) {
  if (!r.ok) return r.body.error || "Something went wrong. Reload the page and try again.";
  await render();
  return "";
}

async function render() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  const { status: sessionStatus, body: s } = await api("/api/session");
  if (sessionStatus !== 200) {
    const again = el("button", { type: "button" }, "Try again");
    again.addEventListener("click", () => render());
    page(el("section", { class: "card", "aria-labelledby": "off" }, el("h2", { id: "off" }, "Cannot reach mcpgate"),
      el("p", {}, "The page could not talk to the gateway. It may be restarting or stopped."),
      el("p", { class: "muted" }, "Check it with: mcpgate service status. Start it with: mcpgate service install."), again));
    return;
  }
  csrf = s.csrf || "";
  if (s.state === "setup") {
    page(form("Set up", "Enter the setup code printed in the terminal where mcpgate runs (or run: mcpgate ui-code), then choose an admin passphrase.",
      [field("Setup code", "code", "text", { autocomplete: "off", spellcheck: "false" }), field("New passphrase (12+ characters)", "passphrase", "password", { minlength: "12" }), field("Repeat passphrase", "again")],
      "Create admin passphrase", async (v) => (v.passphrase !== v.again ? "The two passphrases do not match." : after(await api("/api/setup", "POST", { code: v.code, passphrase: v.passphrase })))));
  } else if (s.state === "login") {
    page(form("Sign in", "", [field("Admin passphrase", "passphrase")], "Sign in", async (v) => after(await api("/api/login", "POST", { passphrase: v.passphrase }))));
  } else {
    const out = el("button", { type: "button", class: "plain" }, "Sign out");
    out.addEventListener("click", async () => { await api("/api/logout", "POST", {}); csrf = ""; viewTitle = "mcpgate admin"; document.title = "mcpgate admin"; location.hash = ""; await render(); });
    const { body: wz } = await api("/api/wizard");
    if (wizardAuto && !wz.done && !wz.has_backend) wizardOpen = true;
    wizardAuto = false;
    if (wizardOpen) {
      const closeWizard = async (scrollTo) => { wizardOpen = false; if (scrollTo) location.hash = ROUTE_OF[scrollTo] || ""; await render(); };
      page(el("p", {}, "You are signed in."), out, await wizardSection(closeWizard));
      return;
    }
    await shell(out);
  }
}

// ---- dashboard shell: a side menu and one page at a time ---------------------------------------
const ROUTES = [
  ["overview", "Overview"], ["backends", "Backends"], ["secrets", "Credentials"], ["approvals", "Approvals"],
  ["remote", "Remote access"], ["tokens", "Tokens"], ["activity", "Activity"], ["settings", "Settings"]];
const ROUTE_OF = { bk: "#/backends", sec: "#/secrets", rem: "#/remote", tok: "#/tokens", set: "#/settings", ap: "#/approvals" };

async function shell(out) {
  const approvals = await approvalsSection();
  const links = ROUTES.map(([key, label]) => el("li", {}, el("a", { href: "#/" + key, "data-route": key }, label)));
  const nav = el("nav", { "aria-label": "Main menu" }, el("ul", {}, ...links));
  const view = el("div", { class: "view" });
  const side = el("div", { class: "side" }, nav, el("div", { class: "who" }, approvals.badge, approvals.live, out));
  const frame = el("div", { class: "shell" }, side, view);
  root.replaceChildren(el("h1", {}, "mcpgate admin"), frame);

  let current = 0;
  const builders = {
    overview: () => overviewSection(approvals),
    backends: async () => {
      const bk = await backendsSection();
      const add = await addSection(() => bk.reload(), () => { location.hash = "#/settings"; });
      return [bk, add];
    },
    secrets: () => secretsSection(),
    approvals: async () => approvals,
    remote: () => remoteSection("remote"),
    tokens: () => remoteSection("tokens"),
    activity: () => auditSection(),
    settings: async () => {
      const settings = await settingsSection(() => render(), () => { wizardOpen = true; render(); });
      return [settings, form("Change passphrase", "", [field("Current passphrase", "current"), field("New passphrase (12+ characters)", "new", "password", { minlength: "12" })], "Change",
        async (v) => after(await api("/api/passphrase", "POST", { current: v.current, new: v.new })))];
    },
  };
  async function show() {
    const key = (location.hash.match(/^#\/([a-z]+)/) || [])[1];
    const name = builders[key] ? key : "overview";
    const mine = ++current;
    for (const a of nav.querySelectorAll("a")) { if (a.dataset.route === name) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); }
    viewTitle = ROUTES.find(([k]) => k === name)[1];
    document.title = viewTitle + " · mcpgate admin";
    view.setAttribute("aria-busy", "true");
    let built;
    try { built = await builders[name](); } catch (e) { built = el("p", { class: "msg", role: "alert" }, "Could not load this page. Reload it, or run mcpgate doctor."); }
    if (mine !== current) return;  // the person moved on while this was loading
    view.replaceChildren(...[].concat(built));
    view.removeAttribute("aria-busy");
    const h = view.querySelector("h2");
    if (h) { h.setAttribute("tabindex", "-1"); if (shown) h.focus({ preventScroll: true }); }
    shown = true;
    window.scrollTo(0, 0);
  }
  let shown = false;
  if (routeListener) window.removeEventListener("hashchange", routeListener);
  routeListener = () => show();
  window.addEventListener("hashchange", routeListener);
  await show();
}
let routeListener = null;

render().catch(() => page(el("p", {}, "The admin service is not reachable.")));
