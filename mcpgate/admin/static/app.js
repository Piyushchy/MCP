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
const openPolicy = {};   // which permission panels are open, kept across refreshes

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
  const secrets = b.secrets.length ? "secrets: " + b.secrets.map((x) => `${x.name} (${x.set ? "set" : "NOT set"})`).join(", ") : "";
  return el("article", { class: "card backend", "data-name": b.name },
    el("h3", {}, b.name, " ", el("span", { class: "pill " + b.state }, STATE_LABEL[b.state])),
    b.description ? el("p", {}, b.description) : "",
    el("p", { class: "muted" }, meta), el("p", { class: "muted" }, tools + (secrets ? " · " + secrets : "")),
    b.path ? el("p", { class: "muted" }, "File: " + b.path + " (drop-in, managed as a file)") : "",
    b.error ? el("p", { class: "msg" }, b.error) : "",
    el("div", { class: "row" }, ...buttons), note, panelBox);
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

async function addSection(reloadList, goSettings) {
  const box = el("section", { "aria-labelledby": "add" });
  const { body: info } = await api("/api/presets");
  let current = null;
  const out = el("div", {});

  function show(...kids) { out.replaceChildren(...kids); }
  const choose = el("div", { class: "row" });
  const pick = (label, fn) => { const b = el("button", { type: "button", class: "plain" }, label); b.addEventListener("click", fn); choose.append(b); };

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
        done.textContent = t.body.ok ? `Works: ${t.body.tools} tools found${t.body.names.length ? ": " + t.body.names.slice(0, 12).join(", ") + (t.body.names.length > 12 ? ", …" : "") : ""}.` : `Added, but the connection failed: ${t.body.error || "unknown error"}`;
        reloadList();
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
    const f = el("form", { class: "card" }, el("h3", {}, "Remote MCP server"), el("p", { class: "muted" }, "Any MCP server reachable by a web address. It must be https, except localhost."),
      textField("Name", "name"), el("div", { class: "field" }, el("label", { for: "f-transport" }, "Transport"), sel), textField("Address (URL)", "url", { placeholder: "https://example.com/mcp" }),
      textField("Description (optional)", "description", { required: null }), textField("Start timeout, seconds", "start_timeout", { value: "30", inputmode: "numeric" }), headers.node,
      el("button", { type: "submit" }, "Review"), msg);
    const payload = () => { const fd = new FormData(f); return { kind: "remote", name: fd.get("name"), transport: fd.get("transport"), url: fd.get("url"), description: fd.get("description"), start_timeout: Number(fd.get("start_timeout")) || undefined, headers: headers.get() }; };
    f.addEventListener("submit", async (ev) => { ev.preventDefault(); msg.textContent = ""; await reviewScreen(payload, f, (t) => { msg.textContent = t; })(); });
    return f;
  }

  function commandForm() {
    if (!info.custom_commands) {
      const go = el("button", { type: "button", class: "plain" }, "Open settings");
      go.addEventListener("click", goSettings);
      return el("div", { class: "card" }, el("h3", {}, "Custom command"), el("p", {}, "Custom commands are switched off. Turning them on lets whoever controls this page run programs on this computer as you, so it asks for your passphrase and a typed confirmation."), go);
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

  for (const p of info.presets) pick(p.title, () => show(presetForm(p)));
  pick("Remote server (URL)", () => show(remoteForm()));
  pick("Custom command", () => show(commandForm()));
  box.append(el("h2", { id: "add" }, "Add a backend"), el("p", { class: "muted" }, "Pick what to connect. Tokens go to a write-only store, never into the config file."), choose, out);
  return box;
}

async function settingsSection(reloadAll) {
  const box = el("section", { "aria-labelledby": "set" });
  async function load() {
    const { body: s } = await api("/api/settings");
    const msg = el("p", { class: "msg", role: "alert" });
    const kids = [el("h2", { id: "set" }, "Settings"), el("h3", {}, "Custom commands"),
      el("p", {}, s.custom_commands ? "On: this page can add and enable programs that run on this computer." : "Off: this page can only add presets and remote servers.")];
    if (s.custom_commands) {
      const off = el("button", { type: "button", class: "plain" }, "Turn off");
      off.addEventListener("click", async () => { const r = await act("/api/settings/custom-commands", { enabled: false }); if (r.ok) { await load(); reloadAll(); } else msg.textContent = r.body.error || "Failed."; });
      kids.push(off);
    } else {
      const f = el("form", { class: "card" }, el("p", {}, "Turning this on lets whoever controls this page run programs on this computer as you. Only do it if you need a server that is not a preset."),
        field("Type ALLOW PROGRAMS to confirm", "confirm", "text", { autocomplete: "off", spellcheck: "false" }), el("button", { type: "submit" }, "Turn on"), msg);
      f.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const r = await act("/api/settings/custom-commands", { enabled: true, confirm: new FormData(f).get("confirm") });
        if (r.ok) { await load(); reloadAll(); } else msg.textContent = r.body.error || "Failed.";
      });
      kids.push(f);
    }
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
    const bk = await backendsSection();
    const settings = await settingsSection(() => render());
    const add = await addSection(() => bk.reload(), () => settings.scrollIntoView());
    page(el("p", {}, "You are signed in."), out, bk, add, settings,
      form("Change passphrase", "", [field("Current passphrase", "current"), field("New passphrase (12+ characters)", "new", "password", { minlength: "12" })], "Change",
        async (v) => after(await api("/api/passphrase", "POST", { current: v.current, new: v.new }))));
  }
}

render().catch(() => page(el("p", {}, "The admin service is not reachable.")));
